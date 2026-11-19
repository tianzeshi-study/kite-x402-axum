import base64
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import requests
from eth_account import Account

import kite_x402_client as client


NETWORK = "eip155:2368"
URL = "http://localhost:8402/v1/example"


def encode_header(data):
    return base64.b64encode(json.dumps(data).encode()).decode()


def response(status, **headers):
    result = requests.Response()
    result.status_code = status
    result.headers.update(headers)
    result.raw = io.BytesIO(b"{}")
    return result


class ClientSettlementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        payer = Account.create()
        cls.payer_key = payer.key.hex()
        requirements = {
            "scheme": "exact",
            "network": NETWORK,
            "asset": "0x38129cf4CE5E183eFF248F42A7D345Bb1B47621A",
            "amount": "1000",
            "payTo": Account.create().address,
            "maxTimeoutSeconds": 60,
            "extra": {"name": "pieUSD", "version": "1"},
        }
        challenge = {"x402Version": 2, "accepts": [requirements]}
        cls.challenge = response(402, **{"Payment-Required": encode_header(challenge)})
        cls.receipt = {"success": True, "network": NETWORK, "transaction": "0x" + "42" * 32}

    def run_client(self, *responses):
        errors = io.StringIO()
        with (
            patch.object(sys, "argv", ["kite_x402_client.py", "--url", URL]),
            patch.dict(os.environ, {"X402_PRIVATE_KEY": self.payer_key}),
            patch.object(requests, "request", side_effect=responses) as send,
            redirect_stdout(io.StringIO()),
            redirect_stderr(errors),
        ):
            status = client.main()
        return status, errors.getvalue(), send

    def test_success_requires_a_matching_settlement_receipt(self):
        settled = response(200, **{"Payment-Response": encode_header(self.receipt)})
        status, errors, send = self.run_client(self.challenge, settled)
        self.assertEqual((status, errors), (0, ""))
        self.assertEqual(send.call_count, 2)
        self.assertNotIn("PAYMENT-SIGNATURE", send.call_args_list[0].kwargs["headers"])
        self.assertIn("PAYMENT-SIGNATURE", send.call_args_list[1].kwargs["headers"])

    def test_initial_success_without_a_challenge_is_not_a_payment(self):
        status, _, send = self.run_client(response(200))
        self.assertEqual(status, 1)
        self.assertEqual(send.call_count, 1)

    def test_unconfirmed_settlement_is_not_successful(self):
        cases = {
            "missing header": None,
            "invalid base64": encode_header(self.receipt) + "!",
            "invalid JSON": base64.b64encode(b"{").decode(),
            "non-object JSON": encode_header([]),
            "rejected settlement": encode_header({**self.receipt, "success": False}),
            "truthy non-boolean success": encode_header({**self.receipt, "success": "true"}),
            "wrong network": encode_header({**self.receipt, "network": "eip155:2366"}),
            "missing network": encode_header({
                "success": True, "transaction": self.receipt["transaction"]
            }),
            "blank transaction": encode_header({**self.receipt, "transaction": " "}),
        }
        for label, header in cases.items():
            with self.subTest(label=label):
                headers = {} if header is None else {"Payment-Response": header}
                status, errors, send = self.run_client(self.challenge, response(200, **headers))
                self.assertEqual(status, 1)
                self.assertIn("Reconcile the original payment", errors)
                self.assertEqual(send.call_count, 2)

    def test_http_failure_is_not_success_even_with_a_receipt(self):
        failed = response(502, **{"Payment-Response": encode_header(self.receipt)})
        status, _, _ = self.run_client(self.challenge, failed)
        self.assertEqual(status, 1)

    def test_signed_request_timeout_requires_reconciliation(self):
        status, errors, send = self.run_client(self.challenge, requests.Timeout())
        self.assertEqual(status, 1)
        self.assertIn("Reconcile the original payment", errors)
        self.assertEqual(send.call_count, 2)
