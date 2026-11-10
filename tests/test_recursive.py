"""End-to-end synthetic Runtime→provider coupling; no person or phone output."""
import json
from pathlib import Path
import tempfile
import unittest

from resident_initiative.recursive import RecursiveDrive
from resident_initiative.runtime import Runtime, SyntheticConfig
from pre_active.engine import ModelResponse


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class Recorder:
    def __init__(self):
        self.contexts = []
        self.raw_messages = []

    def respond(self, *, messages, tools):
        assert tools == []
        self.raw_messages.append(messages)
        text = messages[-1]["content"]
        assert text.startswith("HOST-OWNED SYNTHETIC RECURSIVE DIAGNOSTIC")
        context = json.loads(text.split(": ", 1)[1].split("\n", 1)[0])
        self.contexts.append(context)
        return ModelResponse(final_text=json.dumps({
            "message": "Synthetic " + context["selected_topic"] + " diagnostic.",
            "reason": "Host-owned controlled recursion input."
        }))


class RecursiveRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "trial.sqlite3"
        self.clock = Clock()
        Runtime.initialize(self.path, SyntheticConfig(expires_at=500, max_events=4,
                                                      interval_seconds=3600), now=100)
        self.provider = Recorder()
        self.drive = RecursiveDrive(enabled=True)
        self.runtime = Runtime(self.path, self.provider, clock=self.clock,
                               recursive_drive=self.drive)

    def tearDown(self):
        self.runtime.close()
        self.temp.cleanup()

    def _event(self, event_id, relevance, counter=0.0, *, expect_proposal=True):
        self.runtime.submit_signal(event_id, relevance, counter, now=self.clock.now)
        for _ in range(5):
            self.runtime.cycle(now=self.clock.now)
            table = "initiative_proposals" if expect_proposal else "recursive_events"
            if self.runtime.store.connection.execute(
                    "SELECT 1 FROM " + table + " WHERE event_id=?", (event_id,)).fetchone():
                break
        else:
            self.fail("admitted event did not complete through Runtime")

    def test_committed_trace_changes_next_actual_provider_input_after_restart(self):
        self._event("synthetic.irrigation.a", .95)
        self.assertEqual(self.provider.contexts[0]["selected_topic"], "transit")
        first = self.drive.snapshot(self.runtime)
        self.assertEqual(first["selected_topic"], "irrigation")
        self.assertEqual(first["accepted_events"], 1)
        self.assertFalse(first["contact_authorized"])

        # Re-create actual Runtime, not a fake harness-only provider wrapper.
        self.runtime.close()
        self.runtime = Runtime(self.path, self.provider, clock=self.clock,
                               recursive_drive=RecursiveDrive(enabled=True))
        self.clock.now = 101.0
        self._event("synthetic.transit.b", 1.0)
        self.assertEqual(self.provider.contexts[1]["selected_topic"], "irrigation")
        self.assertNotEqual(self.provider.raw_messages[0], self.provider.raw_messages[1])
        self.assertEqual(self.drive.snapshot(self.runtime)["selected_topic"], "transit")
        self.assertEqual(self.runtime.store.connection.execute(
            "SELECT COUNT(*) FROM recursive_events").fetchone()[0], 2)
        self.runtime._collect(self.clock.now)  # Repeated collect is not a second gradient.
        self.assertEqual(self.runtime.store.connection.execute(
            "SELECT COUNT(*) FROM recursive_events").fetchone()[0], 2)

    def test_exact_off_ablation_uses_same_template_no_gradient(self):
        self.runtime.close()
        self.drive = RecursiveDrive(enabled=False)
        self.runtime = Runtime(self.path, self.provider, clock=self.clock,
                               recursive_drive=self.drive)
        self._event("synthetic.irrigation.a", .95)
        self.clock.now = 101.0
        self._event("synthetic.transit.b", 1.0)
        self.assertEqual([c["selected_topic"] for c in self.provider.contexts],
                         ["transit", "transit"])
        self.assertTrue(all(set(c) == set(self.provider.contexts[0]) for c in self.provider.contexts))
        self.assertTrue(all("generation" not in c and "enabled" not in c for c in self.provider.contexts))
        self.assertEqual(self.provider.contexts[0], self.provider.contexts[1])

    def test_counterevidence_reverses_gradient(self):
        self._event("synthetic.irrigation.a", .95)
        self.assertEqual(self.drive.snapshot(self.runtime)["selected_topic"], "irrigation")
        self.clock.now = 101.0
        previous_calls = len(self.provider.contexts)
        self._event("synthetic.irrigation.b", 0.0, 1.0, expect_proposal=False)
        self.assertEqual(len(self.provider.contexts), previous_calls)  # No call for low salience.
        self.assertEqual(self.runtime.store.connection.execute(
            "SELECT source_kind FROM recursive_events WHERE event_id=?",
            ("synthetic.irrigation.b",)).fetchone()[0], "DEFERRED_LOW_SALIENCE")
        snapshot = self.drive.snapshot(self.runtime)
        self.assertEqual(snapshot["selected_topic"], "transit")
        self.assertLess(snapshot["priority"]["irrigation"], 0)

    def test_controller_history_tamper_rejected_before_provider(self):
        self._event("synthetic.irrigation.a", .95)
        count = len(self.provider.contexts)
        self.runtime.store.connection.execute(
            "UPDATE recursive_events SET evidence_digest='forged' WHERE event_id=?",
            ("synthetic.irrigation.a",))
        with self.assertRaisesRegex(ValueError, "history integrity"):
            self.drive.model_messages(self.runtime, [{"role": "user", "content": "diagnostic"}])
        self.assertEqual(len(self.provider.contexts), count)

    def test_unauthorized_drive_object_rejected_and_default_remains_off(self):
        with self.assertRaises(TypeError):
            Runtime(self.path, self.provider, clock=self.clock, recursive_drive=object())
        self.runtime.close()
        class PlainProvider:
            def __init__(self): self.raw = []
            def respond(self, *, messages, tools):
                self.raw.append(messages)
                return ModelResponse(final_text=json.dumps({
                    "message": "Baseline synthetic diagnostic", "reason": "Default source timer"}))
        plain = PlainProvider()
        self.runtime = Runtime(self.path, plain, clock=self.clock)
        self._event("synthetic.irrigation.a", .95)
        self.assertEqual(len(plain.raw), 1)
        self.assertFalse(any("HOST-OWNED SYNTHETIC RECURSIVE" in item["content"]
                             for item in plain.raw[0]))

    def test_nonfinite_signal_rejected_without_controller_receipt(self):
        with self.assertRaises(ValueError):
            self.runtime.submit_signal("synthetic.irrigation.nan", float("nan"), now=100)
        self.assertEqual(self.runtime.store.connection.execute(
            "SELECT COUNT(*) FROM recursive_events").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
