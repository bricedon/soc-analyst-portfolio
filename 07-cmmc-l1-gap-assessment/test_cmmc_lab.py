"""Tests for the CMMC Level 1 lab - run with:  python -m unittest -v"""

import os
import shutil
import tempfile
import unittest
from datetime import date

import assess

HERE = os.path.dirname(os.path.abspath(__file__))


class CmmcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reqs, cls.results, cls.profile = assess.load(os.path.join(HERE, "data"))
        cls.counts = assess.summary(cls.results)
        cls.items = assess.plan(cls.results, date(2026, 11, 15), 8)

    def test_fifteen_requirements(self):
        self.assertEqual(len(self.reqs), 15)
        self.assertEqual(sum(self.counts.values()), 15)

    def test_counts(self):
        self.assertEqual(self.counts, {"Met": 6, "Partial": 4, "Not Met": 4, "Not Assessed": 1})

    def test_partial_counts_as_gap(self):
        self.assertEqual(len(self.items), 9)
        self.assertTrue(any(i["status"] == "Partial" for i in self.items))

    def test_plan_order_not_assessed_then_high_risk_quick_wins(self):
        self.assertEqual(self.items[0]["status"], "Not Assessed")
        self.assertEqual(self.items[1]["id"], "AC.L1-B.1.I")       # High risk, 2 h
        self.assertEqual([i["risk"] for i in self.items[1:4]], ["High"] * 3)

    def test_target_dates_follow_capacity(self):
        targets = [i["target"] for i in self.items]
        self.assertEqual(targets, sorted(targets))

    def test_missing_row_becomes_not_assessed(self):
        tmp = tempfile.mkdtemp()
        for f in ("requirements.csv", "company_profile.csv"):
            shutil.copy(os.path.join(HERE, "data", f), tmp)
        with open(os.path.join(HERE, "data", "assessment.csv"), encoding="utf-8") as src, \
                open(os.path.join(tmp, "assessment.csv"), "w", encoding="utf-8") as dst:
            dst.writelines(line for line in src if not line.startswith("PE.L1-B.1.VIII"))
        _, results, _ = assess.load(tmp)
        row = [r for r in results if r["id"] == "PE.L1-B.1.VIII"][0]
        self.assertEqual(row["status"], "Not Assessed")

    def test_report_says_not_ready(self):
        out = tempfile.mkdtemp()
        path = assess.write_report(self.profile, self.results, self.items, self.counts, out)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("NOT READY", text)
        self.assertIn("POA&M", text)


if __name__ == "__main__":
    unittest.main()
