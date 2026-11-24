import base64
import io
import json
import os
import shlex
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

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
        cls.resource = {
            "url": URL,
            "description": "Example paid endpoint",
            "mimeType": "application/json",
        }
        challenge = {"x402Version": 2, "resource": cls.resource, "accepts": [requirements]}
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
        self.assertEqual(status, 0)
        self.assertIn("To reconcile this authorization:", errors)
        self.assertEqual(send.call_count, 2)
        self.assertNotIn("PAYMENT-SIGNATURE", send.call_args_list[0].kwargs["headers"])
        self.assertIn("PAYMENT-SIGNATURE", send.call_args_list[1].kwargs["headers"])

    def test_initial_success_without_a_challenge_is_not_a_payment(self):
        status, _, send = self.run_client(response(200))
        self.assertEqual(status, 1)
        self.assertEqual(send.call_count, 1)

    def test_initial_request_failure_stops_before_signing(self):
        for failure in (requests.ConnectionError, requests.Timeout):
            with self.subTest(failure=failure.__name__):
                with patch.object(client, "build_payment_header") as sign:
                    status, errors, send = self.run_client(failure())
                self.assertEqual(status, 1)
                self.assertIn(f"initial request failed ({failure.__name__})", errors)
                self.assertEqual(send.call_count, 1)
                sign.assert_not_called()

    def test_initial_redirect_stops_before_signing(self):
        redirected = response(302, Location="/v1/final")
        with patch.object(client, "build_payment_header") as sign:
            status, errors, send = self.run_client(redirected)

        self.assertEqual(status, 1)
        self.assertIn("Use the final endpoint URL", errors)
        self.assertNotIn("To reconcile this authorization:", errors)
        sign.assert_not_called()
        send.assert_called_once()
        self.assertIs(send.call_args.kwargs["allow_redirects"], False)

    def test_signed_redirect_requires_reconciliation_even_with_a_receipt(self):
        redirected = response(
            307, Location="/v1/final", **{"Payment-Response": encode_header(self.receipt)}
        )
        status, errors, send = self.run_client(self.challenge, redirected)

        self.assertEqual(status, 1)
        self.assertIn("Reconcile the original payment before retrying", errors)
        self.assertEqual(send.call_count, 2)
        signed_request = send.call_args_list[1]
        self.assertEqual(signed_request.args[1], URL)
        self.assertIs(signed_request.kwargs["allow_redirects"], False)
        payment = client.b64_decode_json(signed_request.kwargs["headers"]["PAYMENT-SIGNATURE"])
        nonce = payment["payload"]["authorization"]["nonce"]
        self.assertIn(f"--nonce {nonce}", errors)

    def test_payment_signature_carries_the_challenge_resource(self):
        settled = response(200, **{"Payment-Response": encode_header(self.receipt)})
        status, _, send = self.run_client(self.challenge, settled)
        self.assertEqual(status, 0)
        header = send.call_args.kwargs["headers"]["PAYMENT-SIGNATURE"]
        self.assertEqual(json.loads(base64.b64decode(header))["resource"], self.resource)

    def test_invalid_challenge_resource_stops_before_the_signed_request(self):
        challenge = client.b64_decode_json(self.challenge.headers["Payment-Required"])
        for resource in ("not an object", {}, {"url": " "}):
            with self.subTest(resource=resource):
                challenge["resource"] = resource
                invalid = response(402, **{"Payment-Required": encode_header(challenge)})
                status, errors, send = self.run_client(invalid)
                self.assertEqual(status, 1)
                self.assertIn("invalid `resource`", errors)
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
        challenge = client.b64_decode_json(self.challenge.headers["Payment-Required"])
        challenge["accepts"][0]["amount"] = 1000
        challenge_response = response(402, **{"Payment-Required": encode_header(challenge)})
        errors = io.StringIO()
        errors.flush = Mock()

        def send(*args, **kwargs):
            headers = kwargs["headers"]
            if "PAYMENT-SIGNATURE" not in headers:
                return challenge_response

            signed = client.b64_decode_json(headers["PAYMENT-SIGNATURE"])
            authorization = signed["payload"]["authorization"]
            output = errors.getvalue()
            errors.flush.assert_called()
            prefix = "To reconcile this authorization: "
            self.assertTrue(output.startswith(prefix))
            command = shlex.split(output.removeprefix(prefix))
            self.assertTrue(command[1].endswith("kite_x402_reconcile.py"))
            self.assertEqual(command[2:], [
                "--network", NETWORK, "--asset", signed["accepted"]["asset"],
                "--payer", authorization["from"], "--pay-to", authorization["to"],
                "--amount", "1000", "--nonce", authorization["nonce"],
            ])
            self.assertNotIn(self.payer_key, output)
            self.assertNotIn(signed["payload"]["signature"], output)
            raise requests.Timeout()

        with (
            patch.object(sys, "argv", ["kite_x402_client.py", "--url", URL]),
            patch.dict(os.environ, {"X402_PRIVATE_KEY": self.payer_key}),
            patch.object(requests, "request", side_effect=send) as request,
            redirect_stdout(io.StringIO()),
            redirect_stderr(errors),
        ):
            status = client.main()
        self.assertEqual(status, 1)
        self.assertIn("Reconcile the original payment", errors.getvalue())
        self.assertEqual(request.call_count, 2)
