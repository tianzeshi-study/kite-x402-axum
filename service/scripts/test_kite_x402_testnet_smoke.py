import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import requests
from eth_account import Account

import kite_x402_testnet_smoke as smoke
from kite_x402_client import b64_decode_json, b64_encode_json
from kite_x402_reconcile import AUTHORIZATION_USED, TRANSFER, padded_address


PAYEE = "0x" + "42" * 20
TX = "0x" + "10" * 32
BLOCK = "0x" + "20" * 32
AMOUNT = 1000
UPSTREAM = {"status": "paid"}


def response(status, obj=None, **headers):
    result = requests.Response()
    result.status_code = status
    result.headers.update(headers)
    result._content = json.dumps(obj).encode()
    return result


class TestnetSmokeTests(unittest.TestCase):
    def setUp(self):
        self.account = Account.create()
        self.requirements = {
            "network": smoke.NETWORK, "asset": smoke.ASSET, "scheme": "exact",
            "amount": str(AMOUNT), "payTo": PAYEE, "maxTimeoutSeconds": 60,
            "extra": {"name": "pieUSD", "version": "1"},
        }
        self.resource = {"url": "/v1/smoke"}
        self.receipt = {"success": True, "network": smoke.NETWORK, "transaction": TX}
        self.upstream = UPSTREAM
        self.balance = AMOUNT
        self.chain_amount = AMOUNT
        self.chain_network = 2368
        self.paid_status = 200
        self.paid_timeout = False
        self.rpc_not_ready = False
        self.authorization = None
        self.calls = []
        self.errors = io.StringIO()

    def request(self, url, *, timeout, allow_redirects, headers=None):
        self.calls.append(headers is not None)
        self.assertFalse(allow_redirects)
        if headers is None:
            return response(402, **{"PAYMENT-REQUIRED": b64_encode_json({
                "x402Version": 2, "resource": self.resource, "accepts": [self.requirements],
            })})
        payment = b64_decode_json(headers["PAYMENT-SIGNATURE"])
        self.assertEqual(payment["resource"], self.resource)
        self.authorization = payment["payload"]["authorization"]
        diagnostic = json.loads(self.errors.getvalue().splitlines()[0])
        self.assertEqual(diagnostic["nonce"], self.authorization["nonce"])
        self.assertNotIn(payment["payload"]["signature"], self.errors.getvalue())
        if self.paid_timeout:
            raise requests.Timeout()
        return response(self.paid_status, self.upstream, **{"PAYMENT-RESPONSE": b64_encode_json(self.receipt)})

    def rpc(self, url, *, json, timeout, allow_redirects):
        method, params = json["method"], json["params"]
        if method == "eth_chainId":
            result = hex(self.chain_network)
        elif method == "eth_blockNumber":
            result = "0x123"
        elif method == "eth_call":
            if params[0]["data"].startswith("0x70a08231"):
                self.assertEqual(params[0]["data"], "0x70a08231" + padded_address(self.account.address.lower())[2:])
                result = f"0x{self.balance:064x}"
            else:
                result = f"0x{1:064x}"
        else:
            self.assertEqual((method, params), ("eth_getTransactionReceipt", (TX,)))
            payer = padded_address(self.authorization["from"])
            result = {
                "transactionHash": TX, "blockHash": BLOCK, "blockNumber": "0x123", "status": "0x1",
                "logs": [
                    {"address": smoke.ASSET, "topics": [AUTHORIZATION_USED, payer, self.authorization["nonce"]]},
                    {
                        "address": smoke.ASSET, "topics": [TRANSFER, payer, padded_address(PAYEE)],
                        "data": f"0x{self.chain_amount:064x}",
                    },
                ],
            }
            if self.rpc_not_ready:
                result = None
                self.rpc_not_ready = False
        return response(200, {"jsonrpc": "2.0", "id": json["id"], "result": result})

    def run_smoke(self):
        out = io.StringIO()
        self.errors = io.StringIO()
        self.calls = []
        with (
            patch.dict(os.environ, {"X402_PRIVATE_KEY": self.account.key.hex()}),
            patch.object(requests.Session, "get", side_effect=self.request),
            patch.object(requests.Session, "post", side_effect=self.rpc),
            patch.object(smoke.time, "sleep"),
            redirect_stdout(out),
            redirect_stderr(self.errors),
        ):
            status = smoke.main([
                "--url", "http://127.0.0.1:8402/v1/smoke", "--pay-to", PAYEE,
                "--amount", str(AMOUNT), "--expect-json", json.dumps(UPSTREAM),
            ])
        self.assertNotIn(self.account.key.hex(), self.errors.getvalue())
        return status, json.loads(out.getvalue() or "null")

    def test_confirms_paid_body_and_matching_chain_receipt_after_rpc_catches_up(self):
        self.rpc_not_ready = True
        status, output = self.run_smoke()
        self.assertEqual(status, 0)
        self.assertEqual(output["transaction"], TX)
        self.assertEqual(output["status"], "confirmed")
        self.assertTrue(output["upstream_verified"])
        self.assertEqual(self.calls, [False, True])

    def test_does_not_sign_challenges_for_a_different_payment(self):
        for field, value in (
            ("network", "eip155:2366"), ("asset", PAYEE), ("payTo", smoke.ASSET),
            ("amount", str(AMOUNT + 1)), ("extra", {"name": "pieUSD", "version": "2"}),
        ):
            with self.subTest(field=field), patch.dict(self.requirements, {field: value}):
                self.assertEqual(self.run_smoke(), (1, None))
                self.assertEqual(self.calls, [False])

    def test_does_not_sign_if_balance_is_insufficient(self):
        self.balance = AMOUNT - 1
        self.assertEqual(self.run_smoke(), (1, None))
        self.assertEqual(self.calls, [False])
        self.assertIn("insufficient pieUSD", self.errors.getvalue())

    def test_wrong_rpc_chain_stops_before_the_challenge(self):
        self.chain_network = 2366
        self.assertEqual(self.run_smoke(), (1, None))
        self.assertEqual(self.calls, [])

    def test_wrong_transfer_amount_fails_without_resending_payment(self):
        self.chain_amount = AMOUNT + 1
        self.assertEqual(self.run_smoke(), (1, None))
        self.assertEqual(self.calls, [False, True])
        self.assertIn("Reconcile this nonce", self.errors.getvalue())

    def test_signed_timeout_keeps_the_nonce_and_never_resends(self):
        self.paid_timeout = True
        self.assertEqual(self.run_smoke(), (1, None))
        self.assertEqual(self.calls, [False, True])
        self.assertIn("Reconcile this nonce", self.errors.getvalue())

    def test_wrong_paid_json_fails_even_with_a_confirmed_transfer(self):
        self.upstream = {"status": "unexpected"}
        self.assertEqual(self.run_smoke(), (1, None))
        self.assertIn("transfer confirmed", self.errors.getvalue())

    def test_invalid_receipt_or_redirect_never_passes(self):
        for field, value in (("transaction", "invalid"), ("success", False), ("network", "eip155:2366")):
            with self.subTest(field=field), patch.dict(self.receipt, {field: value}):
                self.assertEqual(self.run_smoke(), (1, None))
                self.assertEqual(self.calls, [False, True])
        self.paid_status = 302
        self.assertEqual(self.run_smoke(), (1, None))
        self.assertEqual(self.calls, [False, True])
