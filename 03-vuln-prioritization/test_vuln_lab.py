"""Tests for the vulnerability prioritization lab - run with:  python -m unittest -v"""

import os
import tempfile
import unittest

import prioritize as pz

HERE = os.path.dirname(os.path.abspath(__file__))


class RankingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = pz.build_register(os.path.join(HERE, "data"))
        cls.by_id = {r["finding_id"]: r for r in cls.rows}

    def test_lower_cvss_kev_internet_beats_critical_cvss_isolated(self):
        vpn, lab = self.by_id["F02"], self.by_id["F01"]
        self.assertLess(vpn["cvss"], lab["cvss"])
        self.assertEqual(vpn["rank"], 1)
        self.assertGreater(vpn["score"], lab["score"])
        self.assertEqual(lab["priority"], "P4")

    def test_kev_internet_gets_72h_sla(self):
        self.assertEqual(self.by_id["F02"]["due"], "2026-11-05")

    def test_observed_attack_raises_config_finding_to_p1(self):
        self.assertEqual(self.by_id["F03"]["priority"], "P1")
        self.assertTrue(any("OBSERVED" in r for r in self.by_id["F03"]["reasons"]))

    def test_compensating_control_lowers_score(self):
        self.assertTrue(any("compensating control" in r for r in self.by_id["F04"]["reasons"]))

    def test_every_score_has_reasons_and_bounds(self):
        for r in self.rows:
            self.assertTrue(0 <= r["score"] <= 100)
            self.assertGreaterEqual(len(r["reasons"]), 3)

    def test_score_function_directly(self):
        asset = {"exposure": "internet", "criticality": "5", "compensating_controls": "none", "notes": "",
                 "hostname": "x", "role": "r", "owner": "o", "host_count": "1"}
        f = {"finding_id": "T1", "asset_id": "A", "cve": "C", "title": "t", "cvss_base": "10.0",
             "detected": "2026-01-01", "fix": "f"}
        row = pz.score_finding(f, asset, {"in_kev": "yes", "ransomware_use": "yes"})
        self.assertEqual(row["score"], 100.0)   # capped


class OutputTests(unittest.TestCase):
    def test_register_ticket_and_revalidation(self):
        out = tempfile.mkdtemp()
        rows = pz.build_register(os.path.join(HERE, "data"))
        pz.write_register(rows, out)
        self.assertTrue(os.path.exists(os.path.join(out, "remediation_register.csv")))
        ticket = pz.make_ticket(rows[0])
        self.assertIn("Definition of done", ticket)
        self.assertIn("2026-11-05", ticket)
        res = {r["finding_id"]: r["status"] for r in
               pz.revalidate(rows, os.path.join(HERE, "data", "rescan_2026-11-12.csv"), "2026-11-12")}
        self.assertEqual(res["F02"], "Closed - verified by rescan")
        self.assertEqual(res["F03"], "Still open - OVERDUE")
        self.assertTrue(res["F06"].startswith("Partially remediated (9/150"))
        self.assertTrue(res["F11"].startswith("NEW"))


if __name__ == "__main__":
    unittest.main()
