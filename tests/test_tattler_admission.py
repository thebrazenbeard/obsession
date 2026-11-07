"""Threat-driven, synthetic tests against Tattler's published event JSON contract."""
import copy
import unittest
from datetime import datetime, timezone, timedelta

from obsession_lab.tattler_admission import AdmissionPolicy, ReplayLedger, admit_tattler_events
from obsession_lab.opportunity_bridge import DeclaredChannel, candidate_routes_from_tattler_events


NOW = datetime(2026, 11, 6, 23, 30, 0, tzinfo=timezone.utc)
EVENT = {
    "schema_version": 1,
    "event_id": "a" * 64,
    "observed_at": "2026-11-06T23:29:30Z",
    "host": "qualified-fixture-host",
    "kind": "open",
    "source": "synthetic-fixture-collector",
    "connection": {
        "kind": "tcp_listener", "protocol": "tcp", "local": "127.0.0.1:9147",
        "remote": "10.9.8.7:1234", "direction": "listen", "state": "LISTEN",
        "owner": "private-user", "process": {"pid": 999, "name": "private", "exe": "C:\\private\\binary.exe"},
    },
}


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.ledger = ReplayLedger(max_entries=8)
        self.policy = AdmissionPolicy(
            expected_host="qualified-fixture-host",
            expected_source="synthetic-fixture-collector",
            declared_local_ports=frozenset({9147}),
        )

    def admit(self, events):
        return admit_tattler_events(events, policy=self.policy, ledger=self.ledger, now=NOW)

    def test_recent_open_event_is_redacted_and_never_eligible_for_execution(self):
        result = self.admit([copy.deepcopy(EVENT)])
        self.assertEqual("UNAUTHENTICATED_TATTLER_EVENT_CLAIM", result["source_class"])
        self.assertEqual(1, len(result["candidate_events"]))
        self.assertEqual("RECENT_OPEN_EVENT_NOT_CURRENT_LISTENER_PROOF", result["candidate_events"][0]["status"])
        self.assertEqual(9147, result["candidate_events"][0]["port"])
        rendered = str(result)
        for secret in ("private-user", "C:\\private", "10.9.8.7", "private", "999"):
            self.assertNotIn(secret, rendered)
        self.assertFalse(result["source_authenticated"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(0, result["execution_count"])

    def test_stale_and_future_events_rejected(self):
        for t in ("2026-11-06T23:26:00Z", "2026-11-06T23:31:00Z"):
            event = copy.deepcopy(EVENT); event["observed_at"] = t
            with self.subTest(t=t), self.assertRaises(ValueError):
                self.admit([event])

    def test_identity_spoof_and_schema_rejected(self):
        for path, value in (("host", "forged-host"), ("source", "forged-source"),
                            ("schema_version", 2), ("event_id", "made-up")):
            event = copy.deepcopy(EVENT); event[path] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.admit([event])

    def test_public_or_undeclared_listener_rejected(self):
        for host_port in ("0.0.0.0:9147", "192.168.1.5:9147", "127.0.0.1:9999"):
            event = copy.deepcopy(EVENT); event["connection"]["local"] = host_port
            with self.subTest(local=host_port), self.assertRaises(ValueError):
                self.admit([event])

    def test_ipv6_loopback_tcp6_event_valid(self):
        event = copy.deepcopy(EVENT)
        event["connection"]["local"] = "[::1]:9147"
        event["connection"]["protocol"] = "tcp6"
        self.assertEqual(9147, self.admit([event])["candidate_events"][0]["port"])

    def test_mismatched_listen_state_rejected(self):
        event = copy.deepcopy(EVENT)
        event["connection"]["state"] = "ESTABLISHED"
        with self.assertRaises(ValueError):
            self.admit([event])

    def test_conflicting_reuse_of_event_id_rejected(self):
        self.admit([copy.deepcopy(EVENT)])
        tampered = copy.deepcopy(EVENT)
        tampered["connection"]["process"]["pid"] = 1000
        with self.assertRaises(ValueError):
            self.admit([tampered])

    def test_replayed_event_ignored(self):
        self.admit([copy.deepcopy(EVENT)])
        result = self.admit([copy.deepcopy(EVENT)])
        self.assertEqual(0, len(result["candidate_events"]))
        self.assertEqual(1, result["replay_count"])

    def test_malformed_second_event_does_not_poison_replay_state(self):
        invalid = copy.deepcopy(EVENT); invalid["event_id"] = "b" * 64
        invalid["source"] = "spoof"
        with self.assertRaises(ValueError):
            self.admit([copy.deepcopy(EVENT), invalid])
        result = self.admit([copy.deepcopy(EVENT)])
        self.assertEqual(1, len(result["candidate_events"]))

    def test_closed_listener_does_not_create_new_candidate(self):
        closed = copy.deepcopy(EVENT); closed["kind"] = "close"
        result = self.admit([closed])
        self.assertEqual([], result["candidate_events"])

    def test_count_and_size_bounded(self):
        with self.assertRaises(ValueError):
            self.admit([copy.deepcopy(EVENT)] * 129)
        huge = copy.deepcopy(EVENT); huge["connection"]["owner"] = "x" * 70000
        with self.assertRaises(ValueError):
            self.admit([huge])

    def test_listener_state_must_be_present(self):
        event=copy.deepcopy(EVENT)
        event['connection'].pop('state')
        with self.assertRaises(ValueError):
            self.admit([event])

    def test_naive_clock_rejected(self):
        with self.assertRaises(ValueError):
            admit_tattler_events([copy.deepcopy(EVENT)], policy=self.policy,
                                 ledger=self.ledger, now=datetime(2026, 11, 6, 23, 30))


class EventChannelBridgeTests(unittest.TestCase):
    def setUp(self):
        self.policy=AdmissionPolicy(expected_host='qualified-fixture-host',
            expected_source='synthetic-fixture-collector',
            declared_local_ports=frozenset({9147}))
        self.ledger=ReplayLedger(max_entries=8)
        self.channels=[DeclaredChannel('local_service',9147,True)]

    def run_bridge(self, channels=None):
        return candidate_routes_from_tattler_events([copy.deepcopy(EVENT)],
            self.channels if channels is None else channels,
            policy=self.policy,ledger=self.ledger,now=NOW)

    def test_recent_event_crosswalk_is_advisory_and_redacted(self):
        receipt=self.run_bridge()
        self.assertEqual(1,len(receipt['candidates']))
        c=receipt['candidates'][0]
        self.assertEqual('RECENT_OPEN_EVENT_NOT_CURRENT_LISTENER_PROOF',c['status'])
        self.assertEqual('local_service',c['channel_id'])
        self.assertFalse(c['current_listener_verified'])
        self.assertFalse(c['recipient_verified'])
        self.assertFalse(c['outbound_permission_verified'])
        self.assertFalse(receipt['effects_authorized'])
        self.assertEqual(0,receipt['execution_count'])
        self.assertNotIn('private-user',str(receipt))

    def test_undeclared_channel_fails_before_ledger_mutation(self):
        with self.assertRaises(ValueError):
            self.run_bridge([DeclaredChannel('not_inventory',4444)])
        self.assertEqual(1,len(self.run_bridge()['candidates']))

    def test_empty_catalog_does_not_consume_event_for_future_channels(self):
        with self.assertRaises(ValueError):
            self.run_bridge([])
        self.assertEqual(1,len(self.run_bridge()['candidates']))

    def test_crosswalk_event_replay_yields_no_second_candidate(self):
        self.run_bridge()
        second=self.run_bridge()
        self.assertEqual([],second['candidates'])
        self.assertEqual(1,second['replay_count'])


if __name__ == "__main__":
    unittest.main()
