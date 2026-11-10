"""Tests for the CloudTrail & IAM lab - run with:  python -m unittest -v"""

import json
import os
import tempfile
import unittest

import generate_events
import investigate as inv

HERE = os.path.dirname(os.path.abspath(__file__))


def build(seed=7):
    tmp = tempfile.mkdtemp()
    generate_events.main(["--seed", str(seed), "--out", tmp])
    records = inv.load_records(os.path.join(tmp, "cloudtrail.json"))
    tickets = inv.load_csv(os.path.join(tmp, "change_tickets.csv"))
    nets = inv.load_csv(os.path.join(tmp, "known_networks.csv"))
    ids = {r["identity"]: r for r in inv.load_csv(os.path.join(tmp, "identities.csv"))}
    findings = inv.analyze(records, tickets, nets, ids)
    return tmp, records, findings, inv.group_incidents(findings)


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.records, cls.findings, cls.incidents = build()

    def test_records_have_cloudtrail_shape(self):
        for r in self.records:
            for k in ("eventTime", "eventSource", "eventName", "userIdentity", "sourceIPAddress", "eventID"):
                self.assertIn(k, r)

    def test_committed_data_matches_generator(self):
        with open(os.path.join(self.tmp, "cloudtrail.json"), "rb") as a, \
                open(os.path.join(HERE, "data", "cloudtrail.json"), "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_authorized_change_matches_ticket(self):
        f = [x for x in self.findings if x["target"] == "intern.qa"][0]
        self.assertEqual(f["verdict"], "AUTHORIZED (CHG-2041)")
        self.assertEqual(f["severity"], "Info")

    def test_denied_attempts_are_blocked_not_suspicious(self):
        denied = [x for x in self.findings if x["actor"] == "ci-deploy"]
        self.assertEqual(len(denied), 2)
        self.assertTrue(all(x["verdict"] == "BLOCKED ATTEMPT" for x in denied))

    def test_role_session_resolves_to_mlee(self):
        create = [x for x in self.findings if x["action"] == "CreateUser"][0]
        self.assertEqual(create["actor"], "DevOpsAutomation/mlee")
        self.assertEqual(create["origin"], "mlee")
        self.assertTrue(any("assumed by mlee" in hop for hop in create["chain"]))

    def test_new_key_traced_back_to_origin(self):
        stop = [x for x in self.findings if x["action"] == "StopLogging"][0]
        self.assertEqual(stop["actor"], "backup-svc2")
        self.assertEqual(stop["origin"], "mlee")
        self.assertIn("audit logging tampered", stop["risks"])
        self.assertEqual(stop["severity"], "Critical")

    def test_incidents_ordered_by_severity(self):
        self.assertEqual([i["severity"] for i in self.incidents], ["Critical", "Medium"])
        self.assertEqual(self.incidents[0]["outcome"], "Actions SUCCEEDED")
        self.assertEqual(self.incidents[1]["outcome"], "All attempts DENIED")

    def test_ticket_outside_window_is_not_authorized(self):
        rec = [r for r in self.records if r["eventName"] == "AttachUserPolicy"
               and (r["requestParameters"] or {}).get("userName") == "intern.qa"][0]
        moved = json.loads(json.dumps(rec))
        moved["eventTime"] = "2026-10-20T20:00:00Z"
        tickets = inv.load_csv(os.path.join(self.tmp, "change_tickets.csv"))
        self.assertIsNone(inv.match_ticket(moved, "devon.admin", tickets))

    def test_timeline_includes_role_sessions(self):
        rows = inv.actor_timeline(self.records, "mlee")
        self.assertTrue(any("DevOpsAutomation/mlee" in r and "CreateUser" in r for r in rows))
        self.assertTrue(any("StopLogging" in r for r in rows))


if __name__ == "__main__":
    unittest.main()
