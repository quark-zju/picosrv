import ipaddress
import os
import subprocess
import unittest
from unittest import mock

import nft_rules


class NftRulesTest(unittest.TestCase):
    def test_country_codes_default_and_normalization(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(nft_rules.country_codes_from_env(), ["CN", "US"])
        with mock.patch.dict(os.environ, {"CC": "us cn US"}, clear=True):
            self.assertEqual(nft_rules.country_codes_from_env(), ["US", "CN"])

    def test_country_codes_reject_invalid_values(self):
        with mock.patch.dict(os.environ, {"CC": "USA"}, clear=True):
            with self.assertRaisesRegex(nft_rules.RuleGenerationError, "invalid"):
                nft_rules.country_codes_from_env()

    @mock.patch("nft_rules.subprocess.run")
    def test_generate_rules_queries_and_combines_countries(self, run):
        run.side_effect = [
            subprocess.CompletedProcess(
                [], 0, stdout="1.0.1.0/24\n2001:db8:1::/48\n", stderr=""
            ),
            subprocess.CompletedProcess(
                [], 0, stdout="1.0.0.0/24\n2001:db8:2::/48\n", stderr=""
            ),
        ]
        with mock.patch.dict(os.environ, {"CC": "CN US"}, clear=True):
            rules = nft_rules.generate_rules()

        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["location", "list-networks-by-cc", "CN"],
                ["location", "list-networks-by-cc", "US"],
            ],
        )
        self.assertIn(
            "add table inet picosrv_geo\ndelete table inet picosrv_geo", rules
        )
        self.assertIn("1.0.0.0/23", rules)
        self.assertIn("2001:db8:1::/48", rules)
        self.assertIn("type filter hook input priority 10; policy accept;", rules)
        self.assertIn("tcp dport 443 ip saddr != @allowed_v4", rules)

    @mock.patch("nft_rules.subprocess.run")
    def test_empty_country_result_is_rejected(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, stdout="\n", stderr="")
        with self.assertRaisesRegex(
            nft_rules.RuleGenerationError, "returned no networks"
        ):
            nft_rules.networks_for_country("CN")

    @mock.patch("nft_rules.subprocess.run")
    def test_invalid_network_is_rejected(self, run):
        run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="not-a-network\n", stderr=""
        )
        with self.assertRaisesRegex(nft_rules.RuleGenerationError, "invalid network"):
            nft_rules.networks_for_country("CN")

    @mock.patch("nft_rules.subprocess.run")
    def test_apply_passes_complete_rules_to_nft(self, run):
        run.return_value = subprocess.CompletedProcess([], 0)
        rules = nft_rules.render_rules(
            ["CN"],
            [ipaddress.ip_network("1.0.0.0/24")],
            [ipaddress.ip_network("2001:db8::/32")],
        )
        nft_rules.apply_rules(rules)
        run.assert_called_once_with(
            ["nft", "-f", "-"], input=rules, text=True, check=False
        )


if __name__ == "__main__":
    unittest.main()
