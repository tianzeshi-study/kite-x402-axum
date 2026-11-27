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

Choosing what to pay:
    The wrapper may advertise several payment options (see the service's
    EXTRA_PAYMENT_OPTIONS and ROUTE_PRICES_USD). By default the first one is
    paid, as before. Pass --network to pay the option advertised on that
    CAIP-2 network instead (e.g. --network eip155:2368 for Kite testnet).

    No single payment may cost more than $1 unless you raise it:
        --max-usd 0.01        # refuse anything above one cent
        --max-usd 0           # disable the cap
    or export X402_MAX_PAYMENT_USD. A pricier challenge is refused before
    anything is signed. x402 prices are fractions of a cent, so a dollar is
    far above any legitimate per-call price — and it is what stops a mistyped
    or hostile challenge from draining the wallet.

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

# Smallest-unit decimals of the stablecoin each Kite network settles in.
# Keep in step with `asset_decimals` in kite-x402-axum/src/kite.rs: a
# challenge quotes its price in these units, and a USD cap is only
# meaningful against them.
ASSET_DECIMALS = {
    "eip155:2366": 6,  # mainnet: Bridged USDC (USDC.e)
    "eip155:2368": 18,  # testnet: pieUSD
}

# Default per-payment cap, as a USD amount ("0" disables it).
DEFAULT_MAX_USD = "1"

# USD amounts are compared as integer micro-dollars, so the price check is
# exact: no float ever touches a price.
MICRO_USD = 10**6


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


def usd_to_micro(value: str) -> int:
    """Exact USD amount -> integer micro-dollars: '$0.001' -> 1000.

    Raises ValueError for anything that is not a plain decimal with at most
    six fractional digits (no sign, no exponent, no thousands separator).
    """
    text = value.strip().removeprefix("$").strip()
    whole, dot, fraction = text.partition(".")
    if not (whole.isascii() and whole.isdigit()):
        raise ValueError(f"not a USD amount: {value!r}")
    if dot and not (fraction.isascii() and fraction.isdigit()):
        raise ValueError(f"not a USD amount: {value!r}")
    if len(fraction) > 6:
        raise ValueError(f"a USD amount has at most 6 decimals: {value!r}")
    return int(whole) * MICRO_USD + int((fraction + "000000")[:6])


def exceeds_cap(amount, network: Optional[str], max_usd: str) -> bool:
    """Whether `amount` atomic units on `network` costs more than `max_usd`.

    The comparison is exact integer arithmetic:
        amount * 10**6  >  cap_in_micro_dollars * 10**decimals
    A price exactly at the cap is allowed. A cap of "0" disables the check.
    A network whose decimals are unknown cannot be priced, so that is an
    error rather than a silent pass; pass --max-usd 0 to pay without a cap.
    """
    cap = usd_to_micro(max_usd)
    if cap == 0:
        return False
    decimals = ASSET_DECIMALS.get(network)
    if decimals is None:
        raise ValueError(
            f"cannot price a payment on unknown network {network!r} "
            "(pass --max-usd 0 to pay without a cap)"
        )
    units = str(amount)
    if not (units.isascii() and units.isdigit()):
        raise ValueError(f"the challenge advertises a non-numeric price {amount!r}")
    return int(units) * MICRO_USD > cap * 10**decimals


def select_option(accepts, network: Optional[str]) -> Optional[dict]:
    """The payment option to pay.

    Without `network`: the first advertised option, as this script always
    did. With it: the first option advertised on that CAIP-2 network, or
    None when the challenge offers none there.
    """
    options = [option for option in accepts if isinstance(option, dict)]
    if network is None:
        return options[0] if options else None
    for option in options:
        if option.get("network") == network:
            return option
    return None


def default_max_usd() -> str:
    """The cap to apply unless --max-usd is given: X402_MAX_PAYMENT_USD when
    it holds a value, otherwise DEFAULT_MAX_USD. A blank variable counts as
    unset, matching the service's handling of its environment."""
    return os.environ.get("X402_MAX_PAYMENT_USD", "").strip() or DEFAULT_MAX_USD


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
    parser.add_argument("--url", required=True, help="Final URL of the paid endpoint, e.g. http://localhost:8402/v1/forecast?...")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--body", default=None, help="JSON string request body, for POST/PUT")
    parser.add_argument(
        "--private-key",
        default=os.environ.get("X402_PRIVATE_KEY"),
        help="0x-prefixed testnet private key. Or set X402_PRIVATE_KEY instead.",
    )
    parser.add_argument(
        "--network",
        default=None,
        help=(
            "CAIP-2 network of the payment option to pay, e.g. eip155:2368 for Kite testnet. "
            "Default: the first advertised option."
        ),
    )
    parser.add_argument(
        "--max-usd",
        default=default_max_usd(),
        help=(
            "refuse any single payment above this USD amount (default: $1; 0 disables the cap). "
            "Or set X402_MAX_PAYMENT_USD."
        ),
    )
    args = parser.parse_args()

    if not args.private_key:
        print("error: missing --private-key (or set X402_PRIVATE_KEY)", file=sys.stderr)
        return 2

    try:
        body = json.loads(args.body) if args.body is not None else None
    except (ValueError, RecursionError):
        print("error: --body must be valid JSON", file=sys.stderr)
        return 2

    account = Account.from_key(args.private_key)
    print(f"payer address: {account.address}")

    headers = {}

    print(f"\n--- 1) unauthenticated {args.method} {args.url}")
    try:
        first = requests.request(
            args.method, args.url, json=body, headers=headers, timeout=30, allow_redirects=False,
        )
    except requests.RequestException as error:
        print(
            f"error: initial request failed ({type(error).__name__}); no payment was signed",
            file=sys.stderr,
        )
        return 1
    print(f"HTTP {first.status_code}")

    if 300 <= first.status_code < 400:
        print(
            "error: initial request returned a redirect status. "
            "Use the final endpoint URL; no payment was signed",
            file=sys.stderr,
        )
        return 1

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

    accepts = challenge.get("accepts")
    # 远端 JSON 不能信任类型；在选择报价前拒绝不可迭代或非数组字段，避免异常退出。
    if not isinstance(accepts, list) or not accepts:
        print("error: 402 challenge has an invalid or empty `accepts` list; no payment was signed", file=sys.stderr)
        return 1
    requirements = select_option(accepts, args.network)
    if requirements is None:
        advertised = sorted(
            {str(option.get("network")) for option in accepts if isinstance(option, dict)}
        )
        print(
            f"error: the challenge advertises no payment option on --network {args.network!r} "
            f"(advertised: {', '.join(advertised) or 'none'}); no payment was signed",
            file=sys.stderr,
        )
        return 1

    try:
        over_cap = exceeds_cap(
            requirements.get("amount"), requirements.get("network"), args.max_usd
        )
    except ValueError as error:
        print(f"error: {error}; no payment was signed", file=sys.stderr)
        return 1
    if over_cap:
        print(
            f"error: refusing to pay {requirements.get('amount')} units on "
            f"{requirements.get('network')}: it exceeds the per-payment cap of "
            f"${args.max_usd} USD (raise it with --max-usd); no payment was signed",
            file=sys.stderr,
        )
        return 1
    print(
        f"\npayment option: network={requirements.get('network')} "
        f"amount={requirements.get('amount')} (cap ${args.max_usd})"
    )
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
            allow_redirects=False,
        )
    except requests.RequestException:
        print(
            "error: signed request failed. Reconcile the original payment before retrying",
            file=sys.stderr,
        )
        return 1
    print(f"HTTP {second.status_code}")

    if 300 <= second.status_code < 400:
        print(
            "error: signed request returned a redirect status. "
            "Reconcile the original payment before retrying with the final endpoint URL",
            file=sys.stderr,
        )
        return 1

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
