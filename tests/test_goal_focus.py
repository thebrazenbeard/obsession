import unittest
import hashlib
import threading
from unittest.mock import patch

import obsession_lab.goal_focus as goal_focus
from obsession_lab.goal_focus import GoalFocus, GoalSpec, GoalSignal


class GoalFocusTests(unittest.TestCase):
    def test_default_denied_activation_and_advisory_receipt(self):
        session = GoalFocus(GoalSpec("goal.one", "document an approved experiment"))
        with self.assertRaises(PermissionError):
            session.observe(GoalSignal("obs.one", relevance=0.9))
        with self.assertRaises(PermissionError):
            session.activate()
        activated = session.activate(explicit=True)
        self.assertEqual(activated["authority"], "LOCAL_RESEARCH_ONLY")
        receipt = session.observe(GoalSignal("obs.one", relevance=0.9))
        self.assertTrue(receipt.followup_candidate)
        self.assertFalse(receipt.execution_authorized)
        self.assertFalse(receipt.contact_authorized)
        self.assertEqual(receipt.evidence_class, "CALLER_SIGNAL_UNATTESTED")

    def test_person_directed_scope_is_explicit_but_never_attested(self):
        session = GoalFocus(GoalSpec("person.study", "consented interview research",
                                     target_kind="person"))
        with self.assertRaises(PermissionError):
            session.activate(explicit=True)
        with self.assertRaises(PermissionError):
            session.activate(explicit=True, person_scope="private_tracking")
        active = session.activate(
            explicit=True, person_scope="host_claimed_consented_research")
        self.assertFalse(active["person_consent_verified"])
        self.assertFalse(active["execution_authorized"])
        receipt = session.observe(GoalSignal("obs.one", relevance=1.0))
        self.assertFalse(receipt.contact_authorized)
        self.assertNotIn("interview", repr(receipt))

    def test_host_stop_is_idempotent_and_not_a_replayable_event(self):
        session = GoalFocus(GoalSpec("goal.two", "safe research"))
        session.activate(explicit=True)
        session.observe(GoalSignal("obs.one", relevance=0.9))
        stopped = session.host_terminate()
        self.assertTrue(stopped["ended"])
        self.assertFalse(stopped["already_ended"])
        self.assertTrue(session.host_terminate()["already_ended"])
        with self.assertRaises(PermissionError):
            session.observe(GoalSignal("obs.two", relevance=0.9))
        with self.assertRaises(PermissionError):
            session.activate(explicit=True)

    def test_budget_replay_and_counterevidence_are_bounded(self):
        session = GoalFocus(GoalSpec("goal.three", "public source research",
                                     max_events=2))
        session.activate(explicit=True)
        weak = session.observe(
            GoalSignal("obs.one", relevance=1.0, counterevidence=1.0))
        self.assertFalse(weak.followup_candidate)
        self.assertEqual(weak.relevance_score, 0.2)
        with self.assertRaises(ValueError):
            session.observe(GoalSignal("obs.one", relevance=1.0))
        second = session.observe(GoalSignal("obs.two", relevance=0.0))
        self.assertEqual(second.observed_events, 2)
        with self.assertRaises(RuntimeError):
            session.observe(GoalSignal("obs.three", relevance=1.0))
        with self.assertRaises(PermissionError):
            session.observe(GoalSignal("obs.four", relevance=1.0))

    def test_host_stop_discards_observation_paused_before_receipt(self):
        session = GoalFocus(GoalSpec("goal.race", "approved research"))
        session.activate(explicit=True)
        entered = threading.Event()
        release = threading.Event()
        outcome = []
        original_hash = hashlib.sha256

        def delayed_hash(data):
            entered.set()
            if not release.wait(timeout=3):
                raise RuntimeError("test barrier timed out")
            return original_hash(data)

        def observe():
            try:
                outcome.append(session.observe(GoalSignal("obs.one", relevance=1.0)))
            except BaseException as error:
                outcome.append(error)

        with patch.object(goal_focus.hashlib, "sha256", delayed_hash):
            worker = threading.Thread(target=observe)
            worker.start()
            self.assertTrue(entered.wait(timeout=2), "observation never entered digest boundary")
            self.assertTrue(session.host_terminate()["ended"])
            release.set()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(outcome), 1)
        self.assertIsInstance(outcome[0], RuntimeError)

    def test_goal_digest_binds_kind_budget_and_schema(self):
        topic = GoalFocus(GoalSpec("same.goal", "authorized research",
                                   target_kind="topic", max_events=1))
        person = GoalFocus(GoalSpec("same.goal", "authorized research",
                                    target_kind="person", max_events=128))
        topic.activate(explicit=True)
        person.activate(explicit=True,
                        person_scope="host_claimed_consented_research")
        a = topic.observe(GoalSignal("obs.one", relevance=0.9))
        b = person.observe(GoalSignal("obs.one", relevance=0.9))
        self.assertNotEqual(a.goal_digest, b.goal_digest)

    def test_forged_signal_nan_is_rejected_before_replay_mutation(self):
        session = GoalFocus(GoalSpec("goal.forged", "approved research"))
        session.activate(explicit=True)
        forged = GoalSignal("obs.one", relevance=0.0)
        object.__setattr__(forged, "relevance", float("nan"))
        with self.assertRaises(ValueError):
            session.observe(forged)
        legitimate = session.observe(GoalSignal("obs.one", relevance=0.0))
        self.assertEqual(legitimate.observed_events, 1)
        self.assertFalse(legitimate.followup_candidate)

    def test_forged_mutated_goal_spec_cannot_widen_scope(self):
        original = GoalSpec("goal.scope", "topic-only research")
        session = GoalFocus(original)
        session.activate(explicit=True)
        object.__setattr__(original, "target_kind", "person")
        self.assertEqual(session.spec.target_kind, "topic")
        receipt = session.observe(GoalSignal("obs.one", relevance=0.9))
        self.assertFalse(receipt.contact_authorized)

        object.__setattr__(session.spec, "target_kind", "person")
        with self.assertRaises(ValueError):
            session.observe(GoalSignal("obs.two", relevance=0.9))

    def test_parallel_duplicate_event_admits_once(self):
        session = GoalFocus(GoalSpec("goal.parallel", "bounded research", max_events=1))
        session.activate(explicit=True)
        barrier = threading.Barrier(3)
        outcomes = []
        def observe():
            barrier.wait(timeout=3)
            try:
                outcomes.append(session.observe(GoalSignal("obs.one", relevance=1.0)))
            except Exception as error:
                outcomes.append(error)
        workers = [threading.Thread(target=observe) for _ in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=3)
        for worker in workers:
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sum(isinstance(outcome, goal_focus.GoalReceipt)
                             for outcome in outcomes), 1)
        self.assertEqual(sum(isinstance(outcome, Exception)
                             for outcome in outcomes), 1)


if __name__ == "__main__":
    unittest.main()
