"""Tests for the SOC Detection & IR Lab - run with:  python -m unittest -v"""

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta

import detect
import generate_logs

HERE = os.path.dirname(os.path.abspath(__file__))


def build_dataset(seed=42):
    tmp = tempfile.mkdtemp()
    generate_logs.write_outputs(generate_logs.Builder(seed).build(), tmp)
    return tmp


def run_detection(data_dir, **kw):
    events = detect.load_events(os.path.join(data_dir, "events.jsonl"))
    alerts = detect.detect(events, **kw)
    detect.enrich(alerts, events,
                  detect.load_csv(os.path.join(data_dir, "users.csv"), "username"),
                  detect.load_csv(os.path.join(data_dir, "assets.csv"), "hostname"))
    return events, alerts


class GeneratorTests(unittest.TestCase):
    def test_same_seed_same_data(self):
        a, b = build_dataset(42), build_dataset(42)
        def digest(d):
            with open(os.path.join(d, "events.jsonl"), "rb") as fh:
                return hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(digest(a), digest(b))

    def test_committed_data_matches_generator(self):
        """data/events.jsonl in the repo must be exactly what the generator produces."""
        fresh = build_dataset(42)
        with open(os.path.join(fresh, "events.jsonl"), "rb") as f1, \
                open(os.path.join(HERE, "data", "events.jsonl"), "rb") as f2:
            self.assertEqual(f1.read(), f2.read())

    def test_external_ips_use_documentation_ranges(self):
        events, _ = run_detection(build_dataset())
        for e in events:
            ip = e.get("IpAddress", "-")
            if ip not in ("-", "127.0.0.1") and not ip.startswith("10."):
                self.assertTrue(ip.startswith(("198.51.100.", "203.0.113.")), ip)


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events, cls.alerts = run_detection(build_dataset())
        cls.by_user = {a.user: a for a in cls.alerts}

    def test_exactly_two_alerts(self):
        self.assertEqual(sorted(self.by_user), ["a.morgan", "j.rivera"])

    def test_malicious_case_is_high(self):
        a = self.by_user["a.morgan"]
        self.assertEqual(a.src_ip, "203.0.113.45")
        self.assertEqual(a.severity, "High")
        self.assertFalse(a.context["src_ip_internal"])
        self.assertIn("4720 support_tmp", a.context["account_changes_after"])
        self.assertEqual(a.context["other_usernames_tried_from_ip"], ["alex.morgan", "amorgan"])

    def test_benign_case_fires_but_scores_low(self):
        a = self.by_user["j.rivera"]
        self.assertEqual(a.severity, "Low")
        self.assertTrue(a.context["password_changed_2h_before"])
        self.assertTrue(a.context["src_is_users_workstation"])

    def test_low_and_slow_is_missed_by_default_rule(self):
        self.assertNotIn("k.chen", self.by_user)
        fails = [e for e in self.events if e["EventCode"] == 4625 and e["TargetUserName"] == "k.chen"]
        self.assertGreaterEqual(len(fails), 20)

    def test_low_and_slow_found_with_wider_window(self):
        _, alerts = run_detection(build_dataset(), threshold=10, window_min=240, success_within_min=30)
        self.assertIn("k.chen", {a.user for a in alerts})

    def test_failures_without_success_never_alert(self):
        self.assertNotIn("svc-scanner", self.by_user)

    def test_timeline_contains_password_change_for_benign(self):
        rows = detect.timeline(self.by_user["j.rivera"], self.events)
        self.assertEqual(rows[0]["EventCode"], 4723)


class BurstTests(unittest.TestCase):
    def t(self, *minutes):
        base = datetime(2026, 1, 1)
        return [base + timedelta(minutes=m) for m in minutes]

    def test_five_in_ten_minutes(self):
        self.assertEqual(detect.find_bursts(self.t(0, 1, 2, 3, 4), 5, timedelta(minutes=10)), [(0, 4, 5)])

    def test_four_is_below_threshold(self):
        self.assertEqual(detect.find_bursts(self.t(0, 1, 2, 3), 5, timedelta(minutes=10)), [])

    def test_spread_out_failures_do_not_count(self):
        self.assertEqual(detect.find_bursts(self.t(0, 8, 16, 24, 32, 40), 5, timedelta(minutes=10)), [])


class OutputTests(unittest.TestCase):
    def test_outputs_written(self):
        data = build_dataset()
        out = tempfile.mkdtemp()
        events, alerts = run_detection(data)
        detect.write_outputs(alerts, events, out)
        with open(os.path.join(out, "alerts.json"), encoding="utf-8") as fh:
            self.assertEqual(len(json.load(fh)), 2)
        with open(os.path.join(out, "alerts.md"), encoding="utf-8") as fh:
            self.assertIn("ALERT-001", fh.read())

    def test_bad_json_line_reports_line_number(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w") as fh:
            fh.write('{"time": "2026-10-14T00:00:00Z", "EventCode": 4624}\n{broken\n')
        with self.assertRaisesRegex(ValueError, "line 2"):
            detect.load_events(path)


if __name__ == "__main__":
    unittest.main()
