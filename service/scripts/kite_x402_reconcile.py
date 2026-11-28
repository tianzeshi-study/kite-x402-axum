#!/usr/bin/env python3
"""Inspect an existing Kite EIP-3009 payment using read-only RPC calls."""

import argparse
import json
import re
import sys
from urllib.parse import urlsplit

import requests

# 合约地址和 RPC 地址与 kite-x402-axum/src/kite.rs 保持一致。
NETWORKS = {
    "eip155:2366": ("0x7ab6f3ed87c42ef0adb67ed95090f8bf5240149e", "https://rpc.gokite.ai"),
    "eip155:2368": ("0x38129cf4ce5e183eff248f42a7d345bb1b47621a", "https://rpc-testnet.gokite.ai"),
}
AUTHORIZATION_STATE = "0xe94a0102"
AUTHORIZATION_USED = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"
AUTHORIZATION_CANCELED = "0x1cdd46ff242716cdaa72d159d339a485b3438398348d68f09d7c8c0a59353d81"
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


class QueryError(Exception):
    """The RPC failed or returned insufficiently reliable data."""


def hex_field(value, size):
    if isinstance(value, str) and re.fullmatch(rf"0x[0-9a-fA-F]{{{size * 2}}}", value):
        return value.lower()
    return None


def padded_address(address):
    return "0x" + address[2:].zfill(64)


def quantity(value, method):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        raise QueryError(f"{method} returned an invalid quantity")
    return int(value, 16)


def rpc_call(http, url, method, *params):
    try:
        reply = http.post(
            url,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            timeout=10,
            allow_redirects=False,
        )
        if not 200 <= reply.status_code < 300:
            raise QueryError(f"{method} returned HTTP {reply.status_code}")
        message = reply.json()
    except (requests.RequestException, ValueError) as error:
        raise QueryError(f"{method} request failed ({type(error).__name__})") from None
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or message.get("id") != 1:
        raise QueryError(f"{method} returned an invalid RPC response")
    if "error" in message:
        error = message["error"]
        if method == "eth_getLogs" and isinstance(error, dict) and error.get("code") == -32601:
            raise QueryError("RPC lacks eth_getLogs. Use --rpc-url or supply --transaction.")
        raise QueryError(f"{method} was rejected by the RPC")
    if "result" not in message:
        raise QueryError(f"{method} returned no result")
    return message["result"]


def token_event(log, token, topics):
    if not isinstance(log, dict) or log.get("removed", False) is not False:
        return False
    actual = log.get("topics")
    return (
        hex_field(log.get("address"), 20) == token
        and isinstance(actual, list)
        and [hex_field(topic, 32) for topic in actual] == topics
    )


def reconcile(http, args):
    def call(method, *params):
        return rpc_call(http, args.rpc_url, method, *params)

    if quantity(call("eth_chainId"), "eth_chainId") != int(args.network.split(":")[1]):
        raise QueryError("RPC chain ID does not match the requested Kite network")
    head = quantity(call("eth_blockNumber"), "eth_blockNumber")
    block = hex(head)
    payer = padded_address(args.payer)
    state = hex_field(call("eth_call", {
        "to": args.asset,
        "data": AUTHORIZATION_STATE + payer[2:] + args.nonce[2:],
    }, block), 32)
    result = {"status": "not_observed", "network": args.network, "observed_block": head}
    if state == "0x" + "0" * 64:
        return result
    if state != "0x" + "0" * 63 + "1":
        raise QueryError("authorizationState did not return an ABI boolean")

    result["status"] = "consumed_unverified"
    used = [AUTHORIZATION_USED, payer, args.nonce]
    canceled = [AUTHORIZATION_CANCELED, payer, args.nonce]
    transaction = args.transaction
    event = None
    if transaction is None:
        start = max(0, head - args.blocks + 1)
        result["searched_from_block"] = start
        logs = call("eth_getLogs", {
            "address": args.asset,
            "fromBlock": hex(start),
            "toBlock": block,
            "topics": [[AUTHORIZATION_USED, AUTHORIZATION_CANCELED], payer, args.nonce],
        })
        if not isinstance(logs, list):
            raise QueryError("eth_getLogs returned an invalid log list")
        if not logs:
            return result
        if len(logs) != 1 or not (
            token_event(logs[0], args.asset, used) or token_event(logs[0], args.asset, canceled)
        ):
            raise QueryError("RPC returned inconsistent authorization events")
        event = logs[0]
        transaction = hex_field(event.get("transactionHash"), 32)
        event_block = quantity(event.get("blockNumber"), "eth_getLogs")
        event_hash = hex_field(event.get("blockHash"), 32)
        event_index = quantity(event.get("logIndex"), "eth_getLogs")
        if transaction is None or event_hash is None or not start <= event_block <= head:
            raise QueryError("RPC returned an invalid authorization event")

    receipt = call("eth_getTransactionReceipt", transaction)
    if receipt is None:
        return result
    if not isinstance(receipt, dict) or hex_field(receipt.get("transactionHash"), 32) != transaction:
        raise QueryError("RPC returned an invalid transaction receipt")
    receipt_block = quantity(receipt.get("blockNumber"), "eth_getTransactionReceipt")
    receipt_hash = hex_field(receipt.get("blockHash"), 32)
    if receipt_hash is None:
        raise QueryError("transaction receipt has no valid block hash")
    if event is not None and (receipt_block != event_block or receipt_hash != event_hash):
        raise QueryError("authorization event and receipt disagree on the block")
    if receipt_block > head:
        return result
    status = quantity(receipt.get("status"), "eth_getTransactionReceipt")
    if status == 0:
        return result
    if status != 1 or not isinstance(receipt.get("logs"), list):
        raise QueryError("RPC returned an invalid transaction receipt")

    logs = receipt["logs"]
    # 日志可省略旧接口未提供的成员字段，但已提供的交易/区块元数据必须与所属回执一致。
    for log in logs:
        if not isinstance(log, dict):
            raise QueryError("transaction receipt contains an invalid log")
        for field, size, expected in (("transactionHash", 32, transaction), ("blockHash", 32, receipt_hash)):
            if field in log and hex_field(log[field], size) != expected:
                raise QueryError("receipt log metadata disagrees with its containing receipt")
        if "blockNumber" in log and quantity(log["blockNumber"], "receipt log") != receipt_block:
            raise QueryError("receipt log block number disagrees with its containing receipt")
    transfer = [TRANSFER, payer, padded_address(args.pay_to)]
    amount = f"0x{args.amount:064x}"
    matches = [
        (index, token_event(log, args.asset, canceled))
        for index, log in enumerate(logs)
        if token_event(log, args.asset, canceled) or token_event(log, args.asset, used)
    ]
    if not matches and event is None:
        return result
    if len(matches) != 1:
        raise QueryError("receipt contains inconsistent authorization events")
    index, was_canceled = matches[0]
    if event is not None and (
        not token_event(event, args.asset, canceled if was_canceled else used)
        or quantity(logs[index].get("logIndex"), "eth_getTransactionReceipt") != event_index
    ):
        raise QueryError("authorization event does not match the receipt")
    result["transaction"] = transaction
    if was_canceled:
        result["status"] = "canceled"
    elif index + 1 < len(logs):
        # Kite 代币紧接授权事件记录对应转账，以此区分同一笔交易中的多笔付款。
        following = logs[index + 1]
        if token_event(following, args.asset, transfer) and hex_field(following.get("data"), 32) == amount:
            result["status"] = "confirmed"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", required=True, choices=NETWORKS)
    parser.add_argument("--asset", required=True, help="Kite token contract address")
    parser.add_argument("--payer", required=True)
    parser.add_argument("--pay-to", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--amount", type=int, required=True, help="Expected amount in atomic token units")
    parser.add_argument("--transaction", help="Known transaction hash to look up directly")
    parser.add_argument("--rpc-url", help="Override the RPC endpoint for the selected network")
    parser.add_argument("--blocks", type=int, default=1000, help="Recent block count to search (1–10000, default 1000)")
    args = parser.parse_args(argv)
    for field, size in (("asset", 20), ("payer", 20), ("pay_to", 20), ("nonce", 32), ("transaction", 32)):
        value = getattr(args, field)
        if value is not None:
            normalized = hex_field(value, size)
            if normalized is None:
                parser.error(f"--{field.replace('_', '-')} must be a {size}-byte hex value")
            setattr(args, field, normalized)
    asset, default_rpc = NETWORKS[args.network]
    if args.asset != asset:
        parser.error("--asset is not the supported token contract for --network")
    if not 0 < args.amount < 2**256:
        parser.error("--amount must be a positive uint256")
    if not 1 <= args.blocks <= 10_000:
        parser.error("--blocks must be between 1 and 10000")
    if args.rpc_url is None:
        args.rpc_url = default_rpc
    try:
        parsed = urlsplit(args.rpc_url)
        # urlsplit validates a malformed port only when .port is read.
        # Requests drops port zero, which would send the lookup to the default port.
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.port == 0:
            raise ValueError
    except ValueError:
        parser.error("--rpc-url must be a valid HTTP or HTTPS URL")

    try:
        with requests.Session() as http:
            result = reconcile(http, args)
    except QueryError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0 if result["status"] == "confirmed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
