"""Tests for the beaconing lab - run with:  python -m unittest -v"""

import os
import tempfile
import unittest

import beacon_hunt as bh
import generate_conn

HERE = os.path.dirname(os.path.abspath(__file__))


class BeaconTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp()
        generate_conn.main(["--out", tmp])
        cls.rows = bh.load_conn(os.path.join(tmp, "conn.csv"))
        cls.allow = bh.load_allowlist(os.path.join(tmp, "allowlist.csv"))
        cls.res = bh.hunt(cls.rows, cls.allow)
        cls.tmp = tmp

    def test_committed_data_matches_generator(self):
        with open(os.path.join(self.tmp, "conn.csv"), "rb") as a, open(os.path.join(HERE, "data", "conn.csv"), "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_c2_beacon_ranked_first(self):
        top = self.res[0]
        self.assertEqual((top["src"], top["dst"]), ("10.10.20.113", "203.0.113.99"))
        self.assertEqual(top["verdict"], "LIKELY BEACON")
        self.assertLess(top["interval_cv"], 0.1)

    def test_slow_upload_beacon_found_and_flagged_upload_heavy(self):
        edge = [r for r in self.res if r["dst"] == "198.51.100.200"][0]
        self.assertIn(edge["verdict"], ("LIKELY BEACON", "investigate"))
        self.assertTrue(any("upload-heavy" in x for x in edge["reasons"]))

    def test_slow_beacon_disappears_with_higher_min_conns(self):
        res = bh.hunt(self.rows, self.allow, min_conns=12)
        self.assertFalse(any(r["dst"] == "198.51.100.200" for r in res))

    def test_agent_and_ntp_are_allowlisted_not_beacons(self):
        for r in self.res:
            if r["dst"] in ("10.10.10.40", "10.10.10.5"):
                self.assertEqual(r["verdict"], "allowlisted")
                self.assertEqual(r["prevalence"], 30)

    def test_without_allowlist_prevalence_still_keeps_agent_low(self):
        res = bh.hunt(self.rows, [], min_conns=8)
        agent = [r for r in res if r["dst"] == "10.10.10.40"]
        self.assertTrue(agent and all(r["verdict"] in ("low", "investigate") for r in agent))
        self.assertTrue(all(r["score"] < 70 for r in agent))

    def test_cv(self):
        self.assertEqual(bh.cv([60, 60, 60]), 0.0)
        self.assertGreater(bh.cv([10, 300, 45, 900]), 0.5)


if __name__ == "__main__":
    unittest.main()
