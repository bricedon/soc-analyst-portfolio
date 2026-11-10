"""Tests for the phishing triage lab - run with:  python -m unittest -v"""

import os
import unittest

import triage_email as te

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")


class TriageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        trusted = te.load_trusted(os.path.join(DATA, "trusted_domains.csv"))
        directory = te.load_directory(os.path.join(DATA, "directory.csv"))
        cls.r = {f[:2]: te.analyze(os.path.join(DATA, "emails", f), trusted, directory)
                 for f in os.listdir(os.path.join(DATA, "emails")) if f.endswith(".eml")}

    def test_verdicts(self):
        self.assertEqual({k: v["verdict"] for k, v in self.r.items()},
                         {"E1": "LIKELY BENIGN", "E2": "MALICIOUS", "E3": "MALICIOUS",
                          "E4": "MALICIOUS", "E5": "LIKELY BENIGN"})

    def test_link_text_mismatch_detected(self):
        self.assertTrue(any(l.get("mismatch") for l in self.r["E2"]["links"]))

    def test_bec_passes_authentication_but_is_flagged(self):
        e3 = self.r["E3"]
        self.assertEqual(e3["auth"], {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
        self.assertEqual(e3["type"], "Business Email Compromise (impersonation)")

    def test_html_attachment_password_form(self):
        att = self.r["E4"]["attachments"][0]
        self.assertEqual(att["password_fields"], 1)
        self.assertIn("http://203.0.113.66/collect.php", att["form_actions"])

    def test_never_block_our_own_domain(self):
        self.assertFalse(any("corp[.]example" in i for i in self.r["E4"]["iocs_defanged"]))

    def test_never_block_freemail_server_ip(self):
        self.assertNotIn("192[.]0[.]2[.]41", self.r["E3"]["iocs_defanged"])

    def test_reported_newsletter_is_benign(self):
        self.assertEqual(self.r["E5"]["reported_by_user"], "sana.patel@corp.example")
        self.assertEqual(self.r["E5"]["score"], 0)


class HelperTests(unittest.TestCase):
    def test_lookalike(self):
        trusted = {"microsoft.com": "Microsoft", "paypal.com": "PayPal", "corp.example": "CORP"}
        self.assertEqual(te.lookalike_of("micros0ft-account.example", trusted), "microsoft.com")
        self.assertEqual(te.lookalike_of("paypa1.com", trusted), "paypal.com")
        self.assertIsNone(te.lookalike_of("microsoft.com", trusted))
        self.assertIsNone(te.lookalike_of("cloudnotes.example", trusted))

    def test_defang(self):
        self.assertEqual(te.defang("http://a.b/c"), "hxxp://a[.]b/c")

    def test_auth_parsing_missing(self):
        self.assertEqual(te.parse_auth("spf=pass"), {"spf": "pass", "dkim": "missing", "dmarc": "missing"})


if __name__ == "__main__":
    unittest.main()
