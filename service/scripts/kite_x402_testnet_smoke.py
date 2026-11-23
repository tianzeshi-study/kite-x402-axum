#!/usr/bin/env python3
"""Check a paid GET against the Kite testnet, including its on-chain receipt."""

import argparse
import json
import os
import sys
import time
from urllib.parse import urlsplit

import requests
from eth_account import Account

from kite_x402_client import b64_decode_json, build_payment_header
from kite_x402_reconcile import NETWORKS, QueryError, hex_field, padded_address, quantity, reconcile, rpc_call


NETWORK = "eip155:2368"
ASSET, RPC_URL = NETWORKS[NETWORK]
BALANCE_OF = "0x70a08231"


class SmokeError(Exception):
    """A step of the payment acceptance flow failed."""


def read_header(response, name):
    try:
        return b64_decode_json(response.headers[name])
    except (KeyError, ValueError):
        raise SmokeError(f"missing or invalid {name} header") from None


def select_requirements(challenge, args):
    resource = challenge.get("resource")
    options = challenge.get("accepts")
    if (
        challenge.get("x402Version") != 2
        or not isinstance(options, list)
        or not isinstance(resource, dict)
        or not isinstance(resource.get("url"), str)
        or not resource["url"].strip()
    ):
        raise SmokeError("expected an x402 v2 challenge with a resource and payment options")
    for option in options:
        if not isinstance(option, dict):
            continue
        extra = option.get("extra")
        ttl = option.get("maxTimeoutSeconds")
        if (
            option.get("scheme") == "exact"
            and option.get("network") == NETWORK
            and hex_field(option.get("asset"), 20) == ASSET
            and hex_field(option.get("payTo"), 20) == args.pay_to
            and option.get("amount") == str(args.amount)
            and isinstance(extra, dict)
            and extra.get("name") == "pieUSD"
            and extra.get("version") == "1"
            and type(ttl) is int
            and ttl > 0
        ):
            return option, resource
    raise SmokeError("challenge does not offer the expected Kite testnet pieUSD payment")


def check_payment(http, args, private_key):
    try:
        args.payer = Account.from_key(private_key).address.lower()
    except (TypeError, ValueError):
        raise SmokeError("X402_PRIVATE_KEY is invalid") from None
    if args.payer == args.pay_to:
        raise SmokeError("use different payer and recipient addresses")
    if quantity(rpc_call(http, args.rpc_url, "eth_chainId"), "eth_chainId") != 2368:
        raise SmokeError("RPC does not report Kite testnet chain ID 2368")

    challenge = http.get(args.url, timeout=30, allow_redirects=False)
    if challenge.status_code != 402:
        raise SmokeError(f"expected HTTP 402, received {challenge.status_code}")
    requirements, resource = select_requirements(read_header(challenge, "PAYMENT-REQUIRED"), args)
    balance = hex_field(rpc_call(http, args.rpc_url, "eth_call", {
        "to": ASSET, "data": BALANCE_OF + padded_address(args.payer)[2:],
    }, "latest"), 32)
    if balance is None:
        raise SmokeError("pieUSD balance query returned an invalid result")
    if int(balance, 16) < args.amount:
        raise SmokeError("testnet payer has insufficient pieUSD")
    header = build_payment_header(private_key, args.payer, requirements, resource=resource)
    args.nonce = b64_decode_json(header)["payload"]["authorization"]["nonce"]
    print(json.dumps({
        "stage": "signed_request", "network": NETWORK, "asset": ASSET,
        "payer": args.payer, "pay_to": args.pay_to, "amount": str(args.amount), "nonce": args.nonce,
    }), file=sys.stderr, flush=True)
    try:
        response = http.get(
            args.url, headers={"PAYMENT-SIGNATURE": header}, timeout=75, allow_redirects=False,
        )
        if response.status_code != 200:
            raise SmokeError(f"expected paid HTTP 200, received {response.status_code}")
        settlement = read_header(response, "PAYMENT-RESPONSE")
        args.transaction = hex_field(settlement.get("transaction"), 32)
        if settlement.get("success") is not True or settlement.get("network") != NETWORK or not args.transaction:
            raise SmokeError("PAYMENT-RESPONSE does not confirm a valid Kite testnet transaction")
        print(json.dumps({"stage": "settlement_receipt", "transaction": args.transaction}), file=sys.stderr, flush=True)
        for attempt in range(5):
            proof = reconcile(http, args)
            if proof["status"] == "confirmed":
                break
            if proof["status"] == "canceled" or attempt == 4:
                raise SmokeError(f"chain did not confirm the expected transfer ({proof['status']})")
            time.sleep(2)
    except requests.RequestException as error:
        raise SmokeError(f"signed request failed ({type(error).__name__}). Reconcile this nonce before retrying") from None
    except (SmokeError, QueryError) as error:
        raise SmokeError(f"{error}. Reconcile this nonce before retrying") from None

    try:
        actual = json.dumps(response.json(), sort_keys=True, allow_nan=False)
    except ValueError:
        raise SmokeError("transfer confirmed, but the paid response was not valid JSON") from None
    if actual != args.expect_json:
        raise SmokeError("transfer confirmed, but the paid JSON did not match --expect-json")
    return proof


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Kite testnet paid GET endpoint")
    parser.add_argument("--pay-to", required=True, help="Expected recipient wallet address")
    parser.add_argument("--amount", type=int, required=True, help="Exact amount in atomic pieUSD units")
    parser.add_argument("--expect-json", required=True, help="Expected upstream JSON response")
    parser.add_argument("--rpc-url", default=RPC_URL, help="Kite testnet RPC (default: %(default)s)")
    args = parser.parse_args(argv)
    try:
        url = urlsplit(args.url)
        rpc = urlsplit(args.rpc_url)
        if not url.hostname or url.username is not None or url.fragment or not (
            url.scheme == "https" or url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            parser.error("--url must use HTTPS or loopback HTTP and have no credentials or fragment")
        if rpc.scheme != "https" or not rpc.hostname:
            parser.error("--rpc-url must be an HTTPS URL")
    except ValueError:
        parser.error("invalid endpoint or RPC URL")
    args.pay_to = hex_field(args.pay_to, 20)
    if not args.pay_to or int(args.pay_to, 16) == 0:
        parser.error("--pay-to must be a nonzero 20-byte hex address")
    if not 0 < args.amount < 2**256:
        parser.error("--amount must be a positive uint256")
    try:
        args.expect_json = json.dumps(json.loads(args.expect_json), sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        parser.error("--expect-json must be valid JSON")
    args.network, args.asset = NETWORK, ASSET
    private_key = os.environ.get("X402_PRIVATE_KEY")
    if not private_key:
        parser.error("set X402_PRIVATE_KEY to the funded testnet payer's private key")
    try:
        with requests.Session() as http:
            proof = check_payment(http, args, private_key)
    except (SmokeError, QueryError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except requests.RequestException as error:
        print(f"error: preflight request failed ({type(error).__name__})", file=sys.stderr)
        return 1
    print(json.dumps({**proof, "upstream_verified": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
