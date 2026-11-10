"""Tests for the Linux auth.log lab - run with:  python -m unittest -v"""

import os
import tempfile
import unittest

import generate_authlog
import investigate_authlog as ia

HERE = os.path.dirname(os.path.abspath(__file__))


class AuthLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        generate_authlog.main(["--out", cls.tmp])
        cls.events = ia.parse(os.path.join(cls.tmp, "auth.log"))
        cls.findings = ia.analyze(cls.events)
        cls.types = [f["type"] for f in cls.findings]

    def test_committed_log_matches_generator(self):
        with open(os.path.join(self.tmp, "auth.log"), "rb") as a, open(os.path.join(HERE, "data", "auth.log"), "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_attack_chain_detected(self):
        for t in ("BRUTE_FORCE_SUCCESS", "PASSWORD_LOGIN", "SUSPICIOUS_SUDO", "UID0_ACCOUNT", "CRONTAB_CHANGE"):
            self.assertIn(t, self.types)
        bf = [f for f in self.findings if f["type"] == "BRUTE_FORCE_SUCCESS"][0]
        self.assertIn("198.51.100.77", bf["detail"])
        self.assertIn("deploy", bf["detail"])

    def test_key_logins_from_inside_are_not_flagged(self):
        logins = [f for f in self.findings if f["type"] in ("BRUTE_FORCE_SUCCESS", "PASSWORD_LOGIN")]
        self.assertFalse(any("opsadmin" in f["detail"] or "ansible" in f["detail"] for f in logins))

    def test_ansible_tmp_copy_is_a_known_false_positive(self):
        fp = [f for f in self.findings if f["type"] == "SUSPICIOUS_SUDO" and "ansible" in f["detail"]]
        self.assertEqual(len(fp), 1)

    def test_session_timeline_includes_root_actions(self):
        lines = ia.user_timeline(self.events, "deploy")
        self.assertTrue(any("UID=0" in l for l in lines))
        self.assertTrue(any("crontab" in l for l in lines))

    def test_parse_single_digit_day(self):
        self.assertTrue(all(e["time"].day == 3 for e in self.events))


if __name__ == "__main__":
    unittest.main()
