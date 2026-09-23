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
     base64-encoded payment payload.
  5. Print the final response, and decode the `PAYMENT-RESPONSE` header if
     present.

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
import sys
import time

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
    return json.loads(base64.b64decode(value))


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


def build_payment_header(private_key: str, payer_address: str, requirements: dict) -> str:
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
    first = requests.request(args.method, args.url, json=body, headers=headers, timeout=30)
    print(f"HTTP {first.status_code}")

    if first.status_code != 402:
        print("Expected 402 Payment Required. Response body:")
        print(first.text)
        return 1 if first.status_code >= 400 else 0

    challenge_header = first.headers.get("PAYMENT-REQUIRED")
    if not challenge_header:
        print("error: 402 response has no PAYMENT-REQUIRED header", file=sys.stderr)
        return 1

    challenge = b64_decode_json(challenge_header)
    print("\npayment required:")
    print(pretty(challenge))

    accepts = challenge.get("accepts") or []
    if not accepts:
        print("error: 402 challenge has an empty `accepts` list", file=sys.stderr)
        return 1
    requirements = accepts[0]

    print("\n--- 2) signing EIP-3009 TransferWithAuthorization")
    payment_header = build_payment_header(args.private_key, account.address, requirements)

    print(f"\n--- 3) retrying {args.method} {args.url} with PAYMENT-SIGNATURE")
    second = requests.request(
        args.method,
        args.url,
        json=body,
        headers={**headers, "PAYMENT-SIGNATURE": payment_header},
        timeout=30,
    )
    print(f"HTTP {second.status_code}")

    settle_header = second.headers.get("PAYMENT-RESPONSE")
    if settle_header:
        print("\nsettlement (PAYMENT-RESPONSE):")
        print(pretty(b64_decode_json(settle_header)))

    if second.status_code == 402 and not settle_header:
        # Verify rejected the payment before ever reaching the handler.
        retry_challenge = second.headers.get("PAYMENT-REQUIRED")
        if retry_challenge:
            print("\npayment rejected:")
            print(pretty(b64_decode_json(retry_challenge)))

    print("\nresponse body:")
    try:
        print(pretty(second.json()))
    except ValueError:
        print(second.text)

    return 0 if second.status_code < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
