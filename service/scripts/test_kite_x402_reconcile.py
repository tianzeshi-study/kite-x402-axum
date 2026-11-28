import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import requests

import kite_x402_reconcile as reconcile


NETWORK = "eip155:2368"
ASSET = "0x38129cf4ce5e183eff248f42a7d345bb1b47621a"
PAYER = "0x" + "11" * 20
PAYEE = "0x" + "22" * 20
NONCE = "0x" + "33" * 32
TX = "0x" + "ab" * 32
BLOCK = "0x" + "55" * 32


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.event = {
            "address": ASSET,
            "topics": [reconcile.AUTHORIZATION_USED, reconcile.padded_address(PAYER), NONCE],
            "transactionHash": TX,
            "blockHash": BLOCK,
            "blockNumber": "0xbe0",
            "logIndex": "0x0",
        }
        self.transfer = {
            "address": ASSET,
            "topics": [reconcile.TRANSFER, reconcile.padded_address(PAYER), reconcile.padded_address(PAYEE)],
            "data": f"0x{1000:064x}",
        }
        self.receipt = {
            "transactionHash": TX,
            "blockHash": BLOCK,
            "blockNumber": "0xbe0",
            "status": "0x1",
            "logs": [self.event.copy(), self.transfer.copy()],
        }
        self.responses = {
            "eth_chainId": {"result": "0x940"},
            "eth_blockNumber": {"result": "0xbf4"},
            "eth_call": {"result": f"0x{1:064x}"},
            "eth_getLogs": {"result": [self.event]},
            "eth_getTransactionReceipt": {"result": self.receipt},
        }
        self.calls = {}

    def run_query(self, *extra):
        def post(url, *, json, timeout, allow_redirects):
            method = json["method"]
            self.calls[method] = json["params"]
            reply = requests.Response()
            reply.status_code = 200
            reply._content = encode_response(self.responses[method])
            return reply

        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.object(requests.Session, "post", side_effect=post),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = reconcile.main([
                "--network", NETWORK, "--asset", ASSET, "--payer", PAYER,
                "--pay-to", PAYEE, "--nonce", NONCE, "--amount", "1000", *extra,
            ])
        return status, json.loads(stdout.getvalue() or "null"), stderr.getvalue()

    def test_nonce_lookup_confirms_payment_using_a_bounded_window(self):
        status, result, errors = self.run_query("--blocks", "30")
        self.assertEqual((status, errors), (0, ""))
        self.assertEqual(result, {
            "status": "confirmed", "network": NETWORK, "observed_block": 3060,
            "searched_from_block": 3031, "transaction": TX,
        })
        payer = "0x" + "0" * 24 + PAYER[2:]
        self.assertEqual(self.calls["eth_call"], ({
            "to": ASSET, "data": "0xe94a0102" + payer[2:] + NONCE[2:],
        }, "0xbf4"))
        self.assertEqual(self.calls["eth_getLogs"], ({
            "address": ASSET, "fromBlock": hex(3031), "toBlock": "0xbf4",
            "topics": [[reconcile.AUTHORIZATION_USED, reconcile.AUTHORIZATION_CANCELED], payer, NONCE],
        },))
        self.assertEqual(self.calls["eth_getTransactionReceipt"], (TX,))

    def test_known_transaction_does_not_need_log_search(self):
        del self.responses["eth_getLogs"]
        status, result, _ = self.run_query("--transaction", "0x" + TX[2:].upper())
        self.assertEqual((status, result["status"], result["transaction"]), (0, "confirmed", TX))

    def test_contradictory_receipt_log_membership_never_confirms(self):
        for lookup in ((), ("--transaction", TX)):
            for index in (0, 1):
                for field, wrong in (("transactionHash", "0x" + "77" * 32),
                                     ("blockHash", "0x" + "88" * 32), ("blockNumber", "0xbe1")):
                    with self.subTest(lookup=lookup, index=index, field=field):
                        self.setUp()
                        self.receipt["logs"][index][field] = wrong
                        status, result, errors = self.run_query(*lookup)
                        self.assertEqual(status, 1)
                        self.assertIsNone(result)
                        self.assertIn("receipt", errors)

    def test_consistent_optional_log_metadata_preserves_legacy_and_direct_lookups(self):
        self.receipt["logs"][1].update({"transactionHash": TX, "blockHash": BLOCK, "blockNumber": "0xbe0"})
        status, result, errors = self.run_query("--transaction", TX)
        self.assertEqual((status, result["status"], errors), (0, "confirmed", ""))

    def test_known_transaction_must_contain_the_original_nonce(self):
        self.receipt["logs"][0]["topics"] = [*self.event["topics"][:2], "0x" + "77" * 32]
        status, result, _ = self.run_query("--transaction", TX)
        self.assertEqual((status, result["status"]), (2, "consumed_unverified"))

    def test_does_not_confirm_a_different_transfer_in_the_same_receipt(self):
        for wrong in (
            {"data": f"0x{999:064x}"},
            {"topics": [reconcile.TRANSFER, reconcile.padded_address(PAYER), reconcile.padded_address(PAYER)]},
            {"topics": [reconcile.TRANSFER, reconcile.padded_address(PAYEE), reconcile.padded_address(PAYEE)]},
            {"address": PAYER},
        ):
            with self.subTest(wrong=wrong):
                self.receipt["logs"] = [self.event, {**self.transfer, **wrong}, self.transfer]
                status, result, _ = self.run_query()
                self.assertEqual((status, result["status"]), (2, "consumed_unverified"))

    def test_canceled_authorization(self):
        self.event["topics"] = [reconcile.AUTHORIZATION_CANCELED, reconcile.padded_address(PAYER), NONCE]
        self.receipt["logs"] = [self.event]
        status, result, _ = self.run_query()
        self.assertEqual((status, result["status"], result["transaction"]), (2, "canceled", TX))

    def test_consumed_without_an_event_in_the_window(self):
        self.responses["eth_getLogs"]["result"] = []
        status, result, _ = self.run_query()
        self.assertEqual((status, result["status"]), (2, "consumed_unverified"))
        self.assertNotIn("eth_getTransactionReceipt", self.calls)

    def test_unused_at_observed_block(self):
        self.responses["eth_call"]["result"] = f"0x{0:064x}"
        status, result, _ = self.run_query()
        self.assertEqual((status, result["status"]), (2, "not_observed"))
        self.assertNotIn("eth_getLogs", self.calls)

    def test_reverted_receipt_does_not_confirm_payment(self):
        self.receipt["status"] = "0x0"
        status, result, _ = self.run_query("--transaction", TX)
        self.assertEqual((status, result["status"]), (2, "consumed_unverified"))

    def test_rejects_a_receipt_from_a_different_block(self):
        self.receipt["blockHash"] = "0x" + "66" * 32
        status, result, errors = self.run_query()
        self.assertEqual((status, result), (1, None))
        self.assertIn("disagree on the block", errors)

    def test_rejects_a_receipt_from_a_different_transaction(self):
        self.receipt["transactionHash"] = "0x" + "66" * 32
        status, result, errors = self.run_query()
        self.assertEqual((status, result), (1, None))
        self.assertIn("invalid transaction receipt", errors)

    def test_rejects_wrong_chain_before_querying_authorization(self):
        self.responses["eth_chainId"] = {"result": "0x93e"}
        status, result, errors = self.run_query()
        self.assertEqual((status, result), (1, None))
        self.assertIn("chain ID does not match", errors)
        self.assertNotIn("eth_call", self.calls)

    def test_rpc_without_log_search_reports_how_to_continue(self):
        self.responses["eth_getLogs"] = {"error": {"code": -32601}}
        status, result, errors = self.run_query()
        self.assertEqual((status, result), (1, None))
        self.assertIn("--rpc-url or supply --transaction", errors)


def encode_response(payload):
    return json.dumps({"jsonrpc": "2.0", "id": 1, **payload}).encode()
