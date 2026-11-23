#!/usr/bin/env python3
"""kite_x402_client.py — minimal x402 client for local testing.

Talks directly to your locally running wrapper (http://localhost:8402/...),
no kpass CLI and no public HTTPS required, because *this script* makes the
HTTP request from your own machine instead of Kite Passport's servers making
it for you. It only needs outbound internet access to reach the facilitator
(https://facilitator.pieverse.io by default) — which your Rust service, not
this script, actually calls.

What it does, step by step:
  1. GET/POST the URL once, unauthenticated -> expect 402 with a
     PAYMENT-REQUIRED header (base64 JSON).
  2. Decode that header to get the exact price/network/asset/payTo your
     server is asking for.
  3. Build an EIP-3009 `TransferWithAuthorization` message and sign it with
     your private key (EIP-712, matching the official @x402/evm SDK's wire
     format exactly — see the comment above `AUTHORIZATION_TYPES` below).
  4. Retry the same request with a `PAYMENT-SIGNATURE` header carrying the
     base64-encoded payment payload and the challenge's resource metadata.
  5. Print the final response. Exit successfully only when the HTTP request
     succeeds and `PAYMENT-RESPONSE` confirms settlement on the requested network.

Install:
    pip install eth-account requests

Usage:
    python kite_x402_client.py \\
        --url "http://localhost:8402/v1/forecast?latitude=52.52&longitude=13.41&current=temperature_2m" \\
        --private-key 0xYOUR_TESTNET_PRIVATE_KEY

    # or export it instead of passing --private-key on the command line
    # (keeps it out of your shell history):
    export X402_PRIVATE_KEY=0xYOUR_TESTNET_PRIVATE_KEY
    python kite_x402_client.py --url "http://localhost:8402/v1/forecast?..."

⚠️  Only ever use a throwaway testnet key with this script (a wallet you
    funded from https://faucet.gokite.ai / `kpass faucet drop`, holding no
    real funds). Never paste a mainnet private key into a script.
"""

import argparse
import base64
import json
import os
import secrets
import shlex
import sys
import time
from pathlib import Path
from typing import Optional

import requests
from eth_account import Account

# EIP-712 type definition for EIP-3009's transferWithAuthorization, exactly
# as the official @x402/evm SDK's `constants.ts` defines it (field names,
# order, and Solidity types matter — the token contract computes the same
# typed-data hash, so this must match byte for byte or every signature is
# rejected by the facilitator).
AUTHORIZATION_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ],
}


def b64_encode_json(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")


def b64_decode_json(value: str) -> dict:
    decoded = json.loads(base64.b64decode(value, validate=True))
    if not isinstance(decoded, dict):
        raise ValueError("payment header must contain a JSON object")
    return decoded


def evm_chain_id(network: str) -> int:
    """"eip155:2368" -> 2368, matching the SDK's `getEvmChainId`."""
    prefix, _, chain_id = network.partition(":")
    if prefix != "eip155":
        raise ValueError(f"unsupported network format: {network!r} (expected eip155:<chainId>)")
    return int(chain_id)


def sign_authorization(private_key: str, requirements: dict, authorization: dict) -> str:
    extra = requirements.get("extra") or {}
    name, version = extra.get("name"), extra.get("version")
    if not name or not version:
        raise ValueError(
            "payment requirements are missing extra.name/extra.version "
            "(the EIP-712 domain) — is this really a Kite x402 wrapper?"
        )

    domain = {
        "name": name,
        "version": version,
        "chainId": evm_chain_id(requirements["network"]),
        "verifyingContract": requirements["asset"],
    }
    message = {
        "from": authorization["from"],
        "to": authorization["to"],
        "value": int(authorization["value"]),
        "validAfter": int(authorization["validAfter"]),
        "validBefore": int(authorization["validBefore"]),
        "nonce": authorization["nonce"],
    }

    signed = Account.sign_typed_data(
        private_key,
        domain_data=domain,
        message_types=AUTHORIZATION_TYPES,
        message_data=message,
    )
    return "0x" + signed.signature.hex()


def build_payment_header(
    private_key: str, payer_address: str, requirements: dict, *, resource: Optional[dict] = None
) -> str:
    now = int(time.time())
    authorization = {
        "from": payer_address,
        "to": requirements["payTo"],
        "value": requirements["amount"],
        "validAfter": "0",
        "validBefore": str(now + int(requirements.get("maxTimeoutSeconds", 60))),
        "nonce": "0x" + secrets.token_bytes(32).hex(),
    }
    signature = sign_authorization(private_key, requirements, authorization)

    payload = {
        "x402Version": 2,
        "accepted": requirements,
        "payload": {"authorization": authorization, "signature": signature},
    }
    if resource is not None:
        payload["resource"] = resource
    return b64_encode_json(payload)


def pretty(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True, help="Full URL of the paid endpoint, e.g. http://localhost:8402/v1/forecast?...")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--body", default=None, help="JSON string request body, for POST/PUT")
    parser.add_argument(
        "--private-key",
        default=os.environ.get("X402_PRIVATE_KEY"),
        help="0x-prefixed testnet private key. Or set X402_PRIVATE_KEY instead.",
    )
    args = parser.parse_args()

    if not args.private_key:
        print("error: missing --private-key (or set X402_PRIVATE_KEY)", file=sys.stderr)
        return 2

    account = Account.from_key(args.private_key)
    print(f"payer address: {account.address}")

    body = json.loads(args.body) if args.body else None
    headers = {}

    print(f"\n--- 1) unauthenticated {args.method} {args.url}")
    try:
        first = requests.request(args.method, args.url, json=body, headers=headers, timeout=30)
    except requests.RequestException as error:
        print(
            f"error: initial request failed ({type(error).__name__}); no payment was signed",
            file=sys.stderr,
        )
        return 1
    print(f"HTTP {first.status_code}")

    if first.status_code != 402:
        print("Expected 402 Payment Required. Response body:")
        print(first.text)
        return 1

    challenge_header = first.headers.get("PAYMENT-REQUIRED")
    if not challenge_header:
        print("error: 402 response has no PAYMENT-REQUIRED header", file=sys.stderr)
        return 1

    try:
        challenge = b64_decode_json(challenge_header)
    except ValueError:
        print("error: invalid PAYMENT-REQUIRED header", file=sys.stderr)
        return 1
    print("\npayment required:")
    print(pretty(challenge))

    accepts = challenge.get("accepts") or []
    if not accepts:
        print("error: 402 challenge has an empty `accepts` list", file=sys.stderr)
        return 1
    requirements = accepts[0]
    resource = challenge.get("resource")
    if resource is not None and (
        not isinstance(resource, dict)
        or not isinstance(resource.get("url"), str)
        or not resource["url"].strip()
    ):
        print("error: 402 challenge has an invalid `resource`", file=sys.stderr)
        return 1

    print("\n--- 2) signing EIP-3009 TransferWithAuthorization")
    payment_header = build_payment_header(
        args.private_key, account.address, requirements, resource=resource
    )
    authorization = b64_decode_json(payment_header)["payload"]["authorization"]
    reconcile_command = [
        sys.executable,
        str(Path(__file__).resolve().with_name("kite_x402_reconcile.py")),
        "--network", requirements["network"],
        "--asset", requirements["asset"],
        "--payer", authorization["from"],
        "--pay-to", authorization["to"],
        "--amount", str(int(authorization["value"])),
        "--nonce", authorization["nonce"],
    ]
    print(f"To reconcile this authorization: {shlex.join(reconcile_command)}", file=sys.stderr, flush=True)

    print(f"\n--- 3) retrying {args.method} {args.url} with PAYMENT-SIGNATURE")
    try:
        second = requests.request(
            args.method,
            args.url,
            json=body,
            headers={**headers, "PAYMENT-SIGNATURE": payment_header},
            timeout=30,
        )
    except requests.RequestException:
        print(
            "error: signed request failed. Reconcile the original payment before retrying",
            file=sys.stderr,
        )
        return 1
    print(f"HTTP {second.status_code}")

    settlement = None
    settle_header = second.headers.get("PAYMENT-RESPONSE")
    if settle_header:
        try:
            settlement = b64_decode_json(settle_header)
        except ValueError:
            print("error: invalid PAYMENT-RESPONSE header", file=sys.stderr)
        else:
            print("\nsettlement (PAYMENT-RESPONSE):")
            print(pretty(settlement))

    if second.status_code == 402 and not settle_header:
        # 验签被拒绝时，服务可能返回新的支付挑战。
        retry_challenge = second.headers.get("PAYMENT-REQUIRED")
        if retry_challenge:
            try:
                rejection = b64_decode_json(retry_challenge)
            except ValueError:
                print("error: invalid PAYMENT-REQUIRED header", file=sys.stderr)
            else:
                print("\npayment rejected:")
                print(pretty(rejection))

    print("\nresponse body:")
    try:
        print(pretty(second.json()))
    except ValueError:
        print(second.text)

    if second.status_code >= 400:
        return 1

    transaction = settlement.get("transaction") if settlement is not None else None
    if (
        settlement is None
        or settlement.get("success") is not True
        or settlement.get("network") != requirements["network"]
        or not isinstance(transaction, str)
        or not transaction.strip()
    ):
        print(
            "error: settlement could not be confirmed. Reconcile the original payment before retrying",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
