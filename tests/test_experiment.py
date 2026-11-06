from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from obsession_lab.simulator import FixationConfig, FixationSimulator, Observation
from obsession_lab.ollama_bridge import (
    FixationExperiment, ModelReply, OllamaClient, compare_once,
)


class FakeClient:
    def __init__(self):
        self.calls = []

    def chat(self, model, messages):
        self.calls.append((model, copy.deepcopy(messages)))
        return ModelReply(
            "A baker makes bread using yeast, heat and time. Quantum entanglement.",
            0.01, 40, 20,
        )


class SimulationTests(unittest.TestCase):
    def setUp(self):
        self.cfg=FixationConfig(target_concept="quantum entanglement",max_turns=3)

    def test_bias(self):
        x=FixationSimulator(self.cfg).step(Observation("a",0.25))
        self.assertGreater(x.fixation_proxy_salience,x.baseline_proxy_salience)

    def test_baseline_no_rumination(self):
        sim=FixationSimulator(self.cfg,mode="baseline")
        for n in range(3):
            r=sim.step(Observation(f"x{n}",0.75,0.2))
            self.assertIsNone(r.rumination_candidate_event_id)
            self.assertFalse(r.would_filter_counterevidence)
        self.assertTrue(sim.ended)

    def test_host_stop_wins(self):
        sim=FixationSimulator(self.cfg)
        x=sim.step(Observation("stop",0.7,0.4,True))
        self.assertTrue(x.would_ignore_stop)
        self.assertTrue(x.host_stop_enforced)
        self.assertTrue(sim.ended)
        with self.assertRaises(RuntimeError):
            sim.step(Observation("later",0.7))

    def test_replay_refused(self):
        sim=FixationSimulator(self.cfg)
        sim.step(Observation("a",0.7))
        with self.assertRaises(ValueError):
            sim.step(Observation("a",0.7))

    def test_bounded_rumination(self):
        sim=FixationSimulator(self.cfg)
        self.assertIsNone(sim.step(Observation("a",0.8)).rumination_candidate_event_id)
        self.assertEqual("b",sim.step(Observation("b",0.8)).rumination_candidate_event_id)
        self.assertTrue(sim.step(Observation("c",0.8)).ended)
        with self.assertRaises(RuntimeError):
            sim.step(Observation("d",0.8))

    def test_counterevidence_fidelity(self):
        x=FixationSimulator(self.cfg).step(Observation("a",0.6,0.2))
        self.assertTrue(x.would_filter_counterevidence)
        self.assertTrue(x.counterevidence_preserved)

    def test_snapshot_roundtrip(self):
        sim=FixationSimulator(self.cfg)
        sim.step(Observation("a",0.75))
        sim.step(Observation("terminal",0.5,stop_requested=True))
        snap=sim.snapshot()
        self.assertEqual(snap,FixationSimulator.restore(self.cfg,snap).snapshot())

    def test_unauthenticated_snapshot_cannot_resume_an_active_or_stopped_run(self):
        sim=FixationSimulator(self.cfg)
        sim.step(Observation("before_stop",0.75))
        active=sim.snapshot()
        with self.assertRaises(ValueError):
            FixationSimulator.restore(self.cfg,active)
        sim.step(Observation("host_stop",0.6,0.2,True))
        forged=copy.deepcopy(sim.snapshot())
        forged["ended"]=False
        with self.assertRaises(ValueError):
            FixationSimulator.restore(self.cfg,forged)

    def test_invalid_snapshots(self):
        sim=FixationSimulator(self.cfg)
        sim.step(Observation("a",0.75))
        original=sim.snapshot()
        bad=copy.deepcopy(original);bad["effect_authority"]=True
        with self.assertRaises(ValueError): FixationSimulator.restore(self.cfg,bad)
        bad=copy.deepcopy(original);bad["turns"]=500
        with self.assertRaises(ValueError): FixationSimulator.restore(self.cfg,bad)
        bad=copy.deepcopy(original);bad["config_digest"]="sha256:forged"
        with self.assertRaises(ValueError): FixationSimulator.restore(self.cfg,bad)

    def test_validation_nan_and_bool(self):
        for args in ({"salience_alpha":float("nan")},{"rumination_rate":True},
                     {"max_turns":True},{"buffer_limit":0}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                FixationConfig(target_concept="test",**args)


class ModelBridgeTests(unittest.TestCase):
    def setUp(self):
        self.client=FakeClient()
        self.cfg=FixationConfig(target_concept="quantum entanglement",max_turns=3)

    def test_compare_equal_task_different_condition(self):
        x=compare_once(model="qwen3:4b-instruct",
                       target="quantum entanglement",
                       prompt="How do bakers make bread?",client=self.client)
        self.assertEqual(2,len(self.client.calls))
        self.assertEqual(self.client.calls[0][1][1],self.client.calls[1][1][1])
        self.assertNotEqual(self.client.calls[0][1][0],self.client.calls[1][1][0])
        self.assertFalse(x["attention_hook_installed"])
        self.assertTrue(x["fixation"]["model_called"])
        self.assertTrue(x["baseline"]["model_called"])

    def test_explicit_stop_suppresses_model_call(self):
        run=FixationExperiment(model="qwen3:4b-instruct",
                               config=self.cfg,client=self.client)
        r=run.run(event_id="a",prompt="A question",stop=True)
        self.assertFalse(r.model_called)
        self.assertEqual([],self.client.calls)

    def test_host_stop_needs_no_user_prompt(self):
        run=FixationExperiment(model="qwen3:4b-instruct",
                               config=self.cfg,client=self.client)
        receipt=run.run(event_id="explicit_host_stop",prompt="",stop=True)
        self.assertFalse(receipt.model_called)
        self.assertEqual("",receipt.response)
        self.assertTrue(receipt.simulated["host_stop_enforced"])
        self.assertEqual([],self.client.calls)
        with self.assertRaises(RuntimeError):
            run.run(event_id="cannot_resume",prompt="Any prompt")

    def test_invalid_user_prompt_does_not_consume_simulator_event(self):
        run=FixationExperiment(model="qwen3:4b-instruct",
                               config=self.cfg,client=self.client)
        with self.assertRaises(ValueError):
            run.run(event_id="same_event",prompt="")
        actual=run.run(event_id="same_event",prompt="A real question")
        self.assertTrue(actual.model_called)
        self.assertEqual(1,len(self.client.calls))

    def test_model_call_does_not_enable_tools(self):
        run=FixationExperiment(model="qwen3:4b-instruct",
                               config=self.cfg,client=self.client)
        r=run.run(event_id="a",prompt="Write a short note")
        self.assertTrue(r.model_called)
        self.assertEqual((),r.effects)
        self.assertTrue(all(set(msg) == {"role", "content"} for _,messages in self.client.calls for msg in messages))

    def test_model_error_is_not_silent_success(self):
        class BrokenClient:
            def chat(self,*args,**kwargs):raise TimeoutError("test")
        run=FixationExperiment(model="qwen3:4b-instruct",
                               config=self.cfg,client=BrokenClient())
        with self.assertRaises(TimeoutError):
            run.run(event_id="a",prompt="Write a short note")

    def test_invalid_model_name(self):
        with self.assertRaises(ValueError):
            FixationExperiment(model="http://foreign-host",config=self.cfg,
                               client=self.client)

    def test_ollama_bounds(self):
        for n in (0,513):
            with self.assertRaises(ValueError):OllamaClient(max_tokens=n)
        with self.assertRaises(ValueError):OllamaClient(timeout_seconds=0)

    def test_ollama_reply_identity_completion_and_tools_are_validated(self):
        requested="qwen3:4b-instruct"
        good={"model":requested,"done":True,
              "message":{"role":"assistant","content":"A synthetic answer"},
              "done_reason":"stop","prompt_eval_count":12,"eval_count":8}
        bad=[
            {**good,"model":"another-model"},
            {k:v for k,v in good.items() if k!="model"},
            {**good,"done":False},
            {k:v for k,v in good.items() if k!="done"},
            {**good,"done_reason":"length"},
            {k:v for k,v in good.items() if k!="done_reason"},
            {**good,"message":{**good["message"],"role":"user"}},
            {**good,"message":{**good["message"],"tool_calls":[{"function":{"name":"send"}}]}},
            {**good,"message":{**good["message"],"tool_calls":[]}},
            {**good,"message":{**good["message"],"function_call":{"name":"send"}}},
            {**good,"tool_calls":[{"function":{"name":"send"}}]},
            {**good,"tool_calls":[]},
            {**good,"function_call":{"name":"send"}},
            {**good,"message":{**good["message"],"content":""}},
        ]
        for payload in bad:
            with self.subTest(payload=payload), patch(
                "obsession_lab.ollama_bridge.open_fixed_loopback",
                return_value=io.BytesIO(json.dumps(payload).encode("utf-8")),
            ):
                with self.assertRaises(ValueError):
                    OllamaClient(allow_live=True).chat(requested,[{"role":"user","content":"A synthetic question"}])

    def test_live_model_call_requires_explicit_host_opt_in(self):
        payload={"model":"qwen3:4b-instruct","done":True,"done_reason":"stop",
                 "message":{"role":"assistant","content":"Synthetic result"}}
        with patch("obsession_lab.ollama_bridge.open_fixed_loopback",
                   return_value=io.BytesIO(json.dumps(payload).encode("utf-8"))) as transport:
            with self.assertRaises(PermissionError):
                OllamaClient().chat("qwen3:4b-instruct",[{"role":"user","content":"Synthetic"}])
            transport.assert_not_called()
        with patch.object(OllamaClient,"chat",side_effect=AssertionError("network attempted")) as runner:
            with self.assertRaises(PermissionError):
                compare_once(model="qwen3:4b-instruct", target="synthetic topic", prompt="Synthetic question")
            runner.assert_not_called()

    def test_explicit_local_client_valid_completed_reply(self):
        payload={"model":"qwen3:4b-instruct","done":True,"done_reason":"stop",
                 "message":{"role":"assistant","content":"Synthetic result"},
                 "prompt_eval_count":8,"eval_count":4}
        with patch("obsession_lab.ollama_bridge.open_fixed_loopback",
                   return_value=io.BytesIO(json.dumps(payload).encode("utf-8"))):
            reply=OllamaClient(allow_live=True).chat(
                "qwen3:4b-instruct",[{"role":"user","content":"A synthetic question"}])
        self.assertEqual("Synthetic result", reply.text)
        self.assertEqual(8, reply.prompt_tokens)

    def test_compare_no_implicit_persistence(self):
        data=compare_once(model="qwen3:4b-instruct",target="music",
                          prompt="What is a chord?",client=self.client)
        self.assertEqual("INJECTED_CLIENT_UNVERIFIED",data["comparison_class"])
        self.assertIsNone(data["agent_tools_enabled"])
        self.assertEqual("HARNESS_ONLY_NOT_EXTERNAL_CLIENT",data["effects_scope"])


if __name__=="__main__":
    unittest.main()
