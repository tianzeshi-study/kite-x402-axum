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

    def run_client(self, *responses, argv=(), env=None):
        errors = io.StringIO()
        with (
            patch.object(sys, "argv", ["kite_x402_client.py", "--url", URL, *argv]),
            patch.dict(os.environ, {"X402_PRIVATE_KEY": self.payer_key, **(env or {})}),
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

    def test_non_array_accepts_is_rejected_before_signing(self):
        for accepts in (True, 1, 1.5, "invalid", {"network": NETWORK}):
            with self.subTest(accepts=accepts):
                challenge = response(402, **{"Payment-Required": encode_header({"accepts": accepts})})
                with patch.object(client, "build_payment_header") as sign:
                    status, errors, send = self.run_client(challenge)
                self.assertEqual(status, 1)
                self.assertIn("accepts", errors)
                self.assertIn("no payment was signed", errors)
                self.assertEqual(send.call_count, 1)
                sign.assert_not_called()

    def test_malformed_reported_transaction_is_not_confirmation(self):
        for transaction in ("not-a-hash", "0x12", "0x" + "gg" * 32, "0x" + "42" * 33,
                            " " + self.receipt["transaction"], self.receipt["transaction"] + "\n"):
            with self.subTest(transaction=transaction):
                settled = response(200, **{"Payment-Response": encode_header({**self.receipt, "transaction": transaction})})
                status, errors, send = self.run_client(self.challenge, settled)
                self.assertEqual(status, 1)
                self.assertIn("Reconcile the original payment before retrying", errors)
                self.assertEqual(send.call_count, 2)

    def test_uppercase_hex_transaction_remains_supported(self):
        settled = response(200, **{"Payment-Response": encode_header({**self.receipt, "transaction": "0x" + "aB" * 32})})
        status, _, send = self.run_client(self.challenge, settled)
        self.assertEqual(status, 0)
        self.assertEqual(send.call_count, 2)

    def test_invalid_json_body_stops_before_any_request(self):
        for body in ('{"message":}', ""):
            with self.subTest(body=body):
                with patch.object(client.Account, "from_key") as load_key:
                    status, errors, send = self.run_client(argv=["--method", "POST", "--body", body])
                self.assertEqual(status, 2)
                self.assertIn("--body must be valid JSON", errors)
                load_key.assert_not_called()
                send.assert_not_called()

    def test_valid_json_body_is_sent_on_both_requests(self):
        body = {"message": "hello"}
        settled = response(200, **{"Payment-Response": encode_header(self.receipt)})
        status, _, send = self.run_client(
            self.challenge, settled, argv=["--method", "POST", "--body", json.dumps(body)]
        )
        self.assertEqual(status, 0)
        self.assertEqual(send.call_count, 2)
        for request in send.call_args_list:
            self.assertEqual(request.args[0], "POST")
            self.assertEqual(request.kwargs["json"], body)

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


MAINNET = "eip155:2366"
MAINNET_ASSET = "0x7ab6f3ed87c42ef0adb67ed95090f8bf5240149e"


class UsdToMicroTests(unittest.TestCase):
    def test_plain_and_dollar_prefixed_amounts(self):
        for value, expected in {
            "1": 1_000_000,
            "$1": 1_000_000,
            "0.001": 1000,
            " $0.05 ": 50_000,
            "1.50": 1_500_000,
            "0.000001": 1,
            "12": 12_000_000,
        }.items():
            with self.subTest(value=value):
                self.assertEqual(client.usd_to_micro(value), expected)

    def test_rejects_malformed_amounts(self):
        for value in ("", " ", "$", ".", ".5", "1.", "-1", "+1", "1e3", "1,000", "0.0000001", "abc", "١"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    client.usd_to_micro(value)


class ExceedsCapTests(unittest.TestCase):
    def test_price_exactly_at_the_cap_is_allowed_on_both_networks(self):
        # 1 pieUSD on testnet (18 decimals) and 1 USDC.e on mainnet (6).
        self.assertFalse(client.exceeds_cap(str(10**18), NETWORK, "1"))
        self.assertFalse(client.exceeds_cap("1000000", MAINNET, "1"))

    def test_one_unit_above_the_cap_is_refused(self):
        self.assertTrue(client.exceeds_cap(str(10**18 + 1), NETWORK, "1"))
        self.assertTrue(client.exceeds_cap("1000001", MAINNET, "1"))

    def test_sub_cent_caps_are_exact(self):
        # 1 micro-dollar on testnet is 10**12 units.
        self.assertFalse(client.exceeds_cap(str(10**12), NETWORK, "0.000001"))
        self.assertTrue(client.exceeds_cap(str(10**12 + 1), NETWORK, "0.000001"))

    def test_a_cap_of_zero_disables_the_check(self):
        self.assertFalse(client.exceeds_cap(str(10**30), NETWORK, "0"))
        # ...including on a network whose decimals the script does not know.
        self.assertFalse(client.exceeds_cap("1", "eip155:8453", "0"))

    def test_an_unknown_network_is_an_error_not_a_silent_pass(self):
        for network in ("eip155:8453", None, ""):
            with self.subTest(network=network):
                with self.assertRaisesRegex(ValueError, "unknown network"):
                    client.exceeds_cap("1", network, "1")

    def test_a_malformed_price_or_cap_is_an_error(self):
        for amount in ("", "-5", "1.5", "lots", 1.5, None, True):
            with self.subTest(amount=amount):
                with self.assertRaises(ValueError):
                    client.exceeds_cap(amount, NETWORK, "1")
        with self.assertRaises(ValueError):
            client.exceeds_cap("1", NETWORK, "one dollar")
        with self.assertRaises(ValueError):
            client.exceeds_cap("1", NETWORK, "")


class SelectOptionTests(unittest.TestCase):
    options = [
        {"network": MAINNET, "amount": "50000"},
        "not an object",
        {"network": NETWORK, "amount": "1000"},
    ]

    def test_without_a_network_the_first_option_is_kept(self):
        self.assertEqual(client.select_option(self.options, None), self.options[0])

    def test_with_a_network_the_first_option_there_is_chosen(self):
        self.assertEqual(client.select_option(self.options, NETWORK), self.options[2])
        self.assertEqual(client.select_option(self.options, MAINNET), self.options[0])

    def test_a_network_that_is_not_advertised_yields_nothing(self):
        self.assertIsNone(client.select_option(self.options, "eip155:8453"))
        self.assertIsNone(client.select_option([], NETWORK))
        self.assertIsNone(client.select_option(["not an object"], None))

    def test_the_match_is_exact_not_prefix_based(self):
        self.assertIsNone(client.select_option(self.options, "eip155:236"))


class ClientOptionAndCapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        payer = Account.create()
        cls.payer_key = payer.key.hex()
        pay_to = Account.create().address
        cls.resource = {"url": URL, "description": "Example paid endpoint", "mimeType": "application/json"}
        cls.testnet_option = {
            "scheme": "exact", "network": NETWORK,
            "asset": "0x38129cf4CE5E183eFF248F42A7D345Bb1B47621A",
            "amount": "1000", "payTo": pay_to, "maxTimeoutSeconds": 60,
            "extra": {"name": "pieUSD", "version": "1"},
        }
        cls.mainnet_option = {
            "scheme": "exact", "network": MAINNET, "asset": MAINNET_ASSET,
            "amount": "50000", "payTo": pay_to, "maxTimeoutSeconds": 60,
            "extra": {"name": "Bridged USDC (Kite AI)", "version": "2"},
        }

    def challenge(self, *accepts):
        return response(402, **{
            "Payment-Required": encode_header(
                {"x402Version": 2, "resource": self.resource, "accepts": list(accepts)}
            )
        })

    def run_client(self, challenge, *responses, argv=(), env=None):
        errors = io.StringIO()
        replies = (challenge, *responses)
        with (
            patch.object(sys, "argv", ["kite_x402_client.py", "--url", URL, *argv]),
            patch.dict(os.environ, {"X402_PRIVATE_KEY": self.payer_key, **(env or {})}),
            patch.object(requests, "request", side_effect=replies) as send,
            redirect_stdout(io.StringIO()),
            redirect_stderr(errors),
        ):
            status = client.main()
        return status, errors.getvalue(), send

    def signed_header(self, send):
        return json.loads(base64.b64decode(send.call_args.kwargs["headers"]["PAYMENT-SIGNATURE"]))

    def test_network_selects_the_option_advertised_there(self):
        challenge = self.challenge(self.mainnet_option, self.testnet_option)

        # No receipt is supplied, so the run ends "unconfirmed" (status 1);
        # what matters here is which option got signed.
        _, _, send = self.run_client(challenge, response(200), argv=["--network", NETWORK])
        self.assertEqual(send.call_count, 2)
        self.assertEqual(self.signed_header(send)["accepted"], self.testnet_option)

        _, _, send = self.run_client(challenge, response(200), argv=["--network", MAINNET])
        self.assertEqual(send.call_count, 2)
        self.assertEqual(self.signed_header(send)["accepted"], self.mainnet_option)

    def test_a_matching_receipt_for_the_chosen_network_confirms_the_payment(self):
        challenge = self.challenge(self.mainnet_option, self.testnet_option)
        receipt = {"success": True, "network": MAINNET, "transaction": "0x" + "42" * 32}
        settled = response(200, **{"Payment-Response": encode_header(receipt)})
        status, _, _ = self.run_client(challenge, settled, argv=["--network", MAINNET])
        self.assertEqual(status, 0)

    def test_without_network_the_first_option_is_still_paid(self):
        challenge = self.challenge(self.mainnet_option, self.testnet_option)
        _, _, send = self.run_client(challenge, response(200))
        self.assertEqual(self.signed_header(send)["accepted"], self.mainnet_option)

    def test_a_network_that_is_not_advertised_stops_before_signing(self):
        challenge = self.challenge(self.mainnet_option, self.testnet_option)
        status, errors, send = self.run_client(challenge, argv=["--network", "eip155:8453"])
        self.assertEqual((status, send.call_count), (1, 1))
        self.assertIn("no payment option on --network 'eip155:8453'", errors)
        self.assertIn(f"advertised: {MAINNET}, {NETWORK}", errors)
        self.assertIn("no payment was signed", errors)

    def test_a_price_above_the_default_cap_stops_before_signing(self):
        expensive = {**self.testnet_option, "amount": str(5 * 10**18)}

        status, errors, send = self.run_client(self.challenge(expensive))
        self.assertEqual((status, send.call_count), (1, 1))
        self.assertIn("exceeds the per-payment cap of $1 USD", errors)
        self.assertIn("no payment was signed", errors)

        # The same challenge is paid once the caller raises the cap.
        _, _, send = self.run_client(
            self.challenge(expensive), response(200), argv=["--max-usd", "10"]
        )
        self.assertEqual(send.call_count, 2)
        self.assertEqual(self.signed_header(send)["accepted"]["amount"], str(5 * 10**18))

    def test_the_cap_boundary_is_exact_through_the_cli(self):
        at_cap = {**self.testnet_option, "amount": str(10**12)}
        over_cap = {**self.testnet_option, "amount": str(10**12 + 1)}
        argv = ["--max-usd", "0.000001"]

        _, _, send = self.run_client(self.challenge(at_cap), response(200), argv=argv)
        self.assertEqual(send.call_count, 2)

        status, errors, send = self.run_client(self.challenge(over_cap), argv=argv)
        self.assertEqual((status, send.call_count), (1, 1))
        self.assertIn("exceeds the per-payment cap of $0.000001 USD", errors)

    def test_the_cap_can_come_from_the_environment(self):
        expensive = {**self.testnet_option, "amount": str(5 * 10**18)}

        status, errors, send = self.run_client(
            self.challenge(expensive), env={"X402_MAX_PAYMENT_USD": "0.5"}
        )
        self.assertEqual((status, send.call_count), (1, 1))
        self.assertIn("per-payment cap of $0.5 USD", errors)

        # A blank variable counts as unset, so the default applies.
        status, errors, send = self.run_client(
            self.challenge(expensive), env={"X402_MAX_PAYMENT_USD": "  "}
        )
        self.assertEqual((status, send.call_count), (1, 1))
        self.assertIn("per-payment cap of $1 USD", errors)

    def test_an_unknown_network_needs_an_explicit_opt_out(self):
        foreign = {
            **self.testnet_option,
            "network": "eip155:8453",
            "asset": "0x4200000000000000000000000000000000000006",
        }

        status, errors, send = self.run_client(self.challenge(foreign))
        self.assertEqual((status, send.call_count), (1, 1))
        self.assertIn("cannot price a payment on unknown network 'eip155:8453'", errors)
        self.assertIn("no payment was signed", errors)

        _, _, send = self.run_client(self.challenge(foreign), response(200), argv=["--max-usd", "0"])
        self.assertEqual(send.call_count, 2)
        self.assertEqual(self.signed_header(send)["accepted"]["network"], "eip155:8453")

    def test_a_malformed_cap_stops_before_signing(self):
        status, errors, send = self.run_client(
            self.challenge(self.testnet_option), argv=["--max-usd", "one dollar"]
        )
        self.assertEqual((status, send.call_count), (1, 1))
        self.assertIn("not a USD amount: 'one dollar'", errors)
        self.assertIn("no payment was signed", errors)
