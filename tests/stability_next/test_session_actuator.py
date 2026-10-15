import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
SPEC = importlib.util.spec_from_file_location("stabilityd_session_actuator_test", MODULE_PATH)
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


class SessionActuatorTests(unittest.TestCase):
    def test_handler_entry_receipt_completes_actual_governed_reset_and_persists_only_digests(self):
        from test_effect_capability_session_integration import qualified_session_fixture, sdk_reply, api
        key, session_id = 'agent:cat_voice:fixture:private-channel', 'private-stable-session-id'
        effects = []
        registry = self._registry()
        registry['records'][0].update(agent_id='cat_voice', endpoint_ref='openclaw-agent:cat_voice')
        def command(argv, **kwargs):
            qualified=argv[0]!='openclaw'
            if qualified:
                self.assertEqual(argv[:2],[str(fixture.node),str(fixture.wrapper)])
                payload=json.loads(argv[2]);params=payload['params'];method=payload['method']
                self.assertEqual(kwargs['cwd'],str(fixture.code))
            else:
                method=argv[3];params=json.loads(argv[argv.index('--params')+1])
            self.assertEqual(params['key'],key)
            if method=='sessions.describe':
                response={'session':{'key':key,'agentId':'cat_voice','sessionId':session_id,'hasActiveRun':False}}
            elif method=='sessions.reset':
                self.assertEqual(params['expectedSessionId'],session_id);effects.append(params)
                response={'ok':True,'key':key,'entry':{'sessionId':session_id,'private':'SYNTHETIC_PRIVATE_ENTRY'},'resolved':{}}
            else: self.fail('unexpected runtime method')
            return SimpleNamespace(returncode=0,stdout=sdk_reply(response) if qualified else json.dumps(response),stderr='')
        with qualified_session_fixture(stabilityd) as fixture, tempfile.TemporaryDirectory() as directory, stabilityd.init_memory_kv_db() as conn:
            path = Path(directory) / 'ledger.db'
            policy = dict(canResetSession=True, updatedAtEpoch=999, validUntilEpoch=1060)
            with mock.patch.object(stabilityd, 'STATE_DB', path), \
                 mock.patch.object(stabilityd, 'epoch', return_value=1000), \
                 mock.patch.object(stabilityd, 'now_ms', return_value=1000000), \
                 mock.patch.object(stabilityd, 'current_host_generation', return_value='fixture-node:boot'), \
                 mock.patch.object(stabilityd, 'workflow_runtime_registry_records', return_value=registry), \
                 mock.patch.object(stabilityd, 'analyze_session_activity', return_value={'active': False, 'heavy': False}), \
                 mock.patch.object(stabilityd, 'run_cmd', side_effect=command), \
                 mock.patch.object(api, 'run_sdk_process', side_effect=lambda argv,environment,cwd,timeout: command(list(argv),env=environment,cwd=str(cwd)).stdout):
                first = stabilityd.governed_reset_session(conn, key, 'repeated_failures', policy, 'fixture-generation', session_id)
                second = stabilityd.governed_reset_session(conn, key, 'repeated_failures', policy, 'fixture-generation', session_id)
            self.assertEqual(first['ledgerState'], 'succeeded')
            self.assertEqual(second['ledgerDisposition'], 'existing')
            self.assertEqual(len(effects), 1)
            for sentinel in (key, session_id, 'SYNTHETIC_PRIVATE_ENTRY'):
                self.assertNotIn(sentinel, str(first))
                self.assertNotIn(sentinel.encode(), path.read_bytes())
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM kv').fetchone()[0], 1)

    def test_actual_handler_entry_receipt_is_normalized_without_session_payload(self):
        key = 'agent:cat_voice:fixture'
        receipt = {'ok': True, 'key': key, 'entry': {'sessionId': 'reset-id',
                   'privatePayload': 'SYNTHETIC_PRIVATE_SESSION'}, 'resolved': {'private': 'SYNTHETIC_PRIVATE_SESSION'}}
        for envelope in (receipt, {'ok': True, 'result': receipt}):
            with self.subTest(envelope=envelope), mock.patch.object(stabilityd, 'run_cmd', return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(envelope), stderr='')):
                result, status = stabilityd.openclaw_gateway_call('sessions.reset', {'key': key})
                self.assertEqual(status, 'ok')
                self.assertEqual(result, {'sessionId': 'reset-id'})
                self.assertNotIn('SYNTHETIC_PRIVATE_SESSION', str(result))

    def test_describe_partial_activity_or_wrong_agent_never_becomes_reset_eligible(self):
        key = 'agent:cat_voice:fixture'
        registry = self._registry()
        registry['records'][0].update(agent_id='cat_voice', endpoint_ref='openclaw-agent:cat_voice')
        base = dict(key=key, agentId='cat_voice', sessionId='fixture-id')
        cases = [(base, 'gateway-active-run-state-unavailable')]
        cases.extend(({**base, 'hasActiveRun': value}, 'gateway-active-run-state-unavailable')
                     for value in (None, 0, 'false'))
        cases.append(({**base, 'agentId': 'different', 'hasActiveRun': False}, 'gateway-session-agent-mismatch'))
        cases.append((None, 'gateway-session-id-unavailable'))
        for row, expected in cases:
            with self.subTest(row=row), tempfile.TemporaryDirectory() as directory, \
                 mock.patch.object(stabilityd, 'STATE_DB', Path(directory) / 'ledger.db'), \
                 mock.patch.object(stabilityd, 'current_host_generation', return_value='fixture-node:boot'), \
                 mock.patch.object(stabilityd, 'workflow_runtime_registry_records', return_value=registry), \
                 mock.patch.object(stabilityd, 'run_cmd', return_value=SimpleNamespace(
                     returncode=0, stdout=json.dumps({'session': row}), stderr='')) as command, \
                 mock.patch.object(stabilityd, 'analyze_session_activity') as analyze, \
                 mock.patch.object(stabilityd, 'reset_session') as reset:
                context = stabilityd.current_session_context(key)
                self.assertIsNone(context[0])
                self.assertEqual(context[2], expected)
                result = stabilityd.governed_reset_session(mock.Mock(), key, 'repeated_failures',
                    {'canResetSession': True}, 'fixture-generation', 'fixture-id')
                self.assertEqual(result['result'], 'blocked')
                self.assertEqual(result['blockedReason'], expected)
                self.assertFalse((Path(directory) / 'ledger.db').exists())
                analyze.assert_not_called(); reset.assert_not_called()
                self.assertEqual(command.call_args.args[0][3], 'sessions.describe')

    def test_entry_receipt_wrong_target_missing_identity_or_unknown_schema_is_rejected(self):
        key = 'agent:cat_voice:fixture'
        for receipt in ({'ok': True, 'key': 'different', 'entry': {'sessionId': 'id'}},
                        {'ok': True, 'key': key, 'entry': []},
                        {'ok': True, 'key': key, 'entry': {}},
                        {'ok': True, 'entry': {'sessionId': 'id'}},
                        {'ok': 'true', 'key': key, 'entry': {'sessionId': 'id'}},
                        {'ok': True, 'key': key, 'entry': {'sessionId': True}}):
            with self.subTest(receipt=receipt), mock.patch.object(stabilityd, 'run_cmd', return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(receipt), stderr='')):
                result, status = stabilityd.openclaw_gateway_call('sessions.reset', {'key': key})
                self.assertIsNone(result)
                self.assertIn(status, {'gateway-reset-target-mismatch', 'gateway-reset-invalid-receipt'})

    def _registry(self):
        return {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "catbody", "runtime": "openclaw", "platform": "openclaw",
            "execution_adapter": "openclaw", "endpoint_ref": "openclaw-agent:catbody",
            "status": "active", "can_receive_dispatch": 1,
        }]}

    def test_governed_reset_accepts_gateway_reset_in_place_and_does_not_repeat(self):
        from test_effect_capability_session_integration import qualified_session_fixture
        session_key = "agent:catbody:telegram:private:secret-channel"
        session_id = "session-fixture-1"
        with qualified_session_fixture(stabilityd), tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            new_session_id = session_id
            policy = {"canResetSession": True, "updatedAtEpoch": stabilityd.epoch() - 1,
                      "validUntilEpoch": stabilityd.epoch() + 60}
            row = {"key": session_key, "agentId": "catbody", "sessionId": session_id, "hasActiveRun": False}
            new_row = {**row, "sessionId": new_session_id}
            rpc_replies = [(row, "ok")] * 5 + [({"sessionId": new_session_id}, "ok"), (new_row, "ok"),
                                                (new_row, "ok")]
            with mock.patch.object(stabilityd, "STATE_DB", root / "action-ledger.db"), \
                 mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=self._registry()), \
                 mock.patch.object(stabilityd, "current_host_generation", return_value="fixture-node:boot"), \
                 mock.patch.object(stabilityd, "analyze_session_activity", return_value={
                     "active": False, "heavy": False, "activeCount": 0, "heavyCount": 0,
                 }), \
                 mock.patch.object(stabilityd, "openclaw_gateway_call", side_effect=rpc_replies) as gateway_call, \
                 mock.patch.object(stabilityd, "db_get", return_value=0), \
                 mock.patch.object(stabilityd, "db_set"):
                result = stabilityd.governed_reset_session(
                    mock.Mock(), session_key, "repeated_failures", policy, "fixture-generation", session_id,
                )
                duplicate = stabilityd.governed_reset_session(
                    mock.Mock(), session_key, "repeated_failures", policy, "fixture-generation", session_id,
                )
            self.assertEqual(result["ledgerState"], "succeeded")
            self.assertEqual(result["result"], "ok")
            self.assertEqual(result["resetSessionIdDigest"], stabilityd.hashlib.sha256(new_session_id.encode()).hexdigest())
            self.assertEqual(duplicate["result"], "existing")
            self.assertTrue(duplicate["historicalExisting"])
            self.assertFalse(duplicate["authorizationReused"])
            self.assertEqual(duplicate["ledgerDisposition"], "existing")
            self.assertEqual(gateway_call.call_count, 8)
            self.assertEqual(gateway_call.call_args_list[5].args[0], "sessions.reset")
            self.assertEqual(gateway_call.call_args_list[5].args[1]["expectedSessionId"], session_id)
            ledger_bytes = (root / "action-ledger.db").read_bytes()
            self.assertNotIn(session_key.encode(), ledger_bytes)
            self.assertNotIn(session_id.encode(), ledger_bytes)

    def test_protected_or_unregistered_session_is_blocked_before_intent_or_effect(self):
        protected_key = "agent:main:telegram:private:control"
        unregistered_key = "agent:retired:telegram:private:old"
        with mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=self._registry()), \
             mock.patch.object(stabilityd, "reset_session") as reset:
            protected = stabilityd.current_session_context(protected_key)
            unregistered = stabilityd.current_session_context(unregistered_key)
        self.assertEqual(protected[2], "protected-session")
        self.assertEqual(unregistered[2], "session-agent-not-active-openclaw-member")
        reset.assert_not_called()

    def test_runtime_platform_adapter_drift_cannot_enter_openclaw_session_scope(self):
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "catnose", "runtime": "hermes_acp", "platform": "openclaw",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catnose",
            "status": "active", "can_receive_dispatch": 1,
        }]}
        session_key = "agent:catnose:telegram:private:channel"
        with mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "openclaw_gateway_call") as gateway:
            context = stabilityd.current_session_context(session_key)
        self.assertEqual(context[2], "session-agent-not-active-openclaw-member")
        gateway.assert_not_called()

    def test_active_or_heavy_session_is_blocked(self):
        session_key = "agent:catbody:telegram:private:channel"
        with mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=self._registry()), \
             mock.patch.object(stabilityd, "openclaw_gateway_call", return_value=({
                 "key": session_key, "agentId": "catbody", "sessionId": "session-1", "hasActiveRun": True,
             }, "ok")), \
             mock.patch.object(stabilityd, "analyze_session_activity", return_value={"active": False, "heavy": False}):
            context = stabilityd.current_session_context(session_key)
        self.assertEqual(context[2], "session-active-or-heavy")

    def test_gateway_rpc_cli_uses_allowlisted_methods_and_returns_only_parsed_payload(self):
        sentinel = "RPC_STDERR_SECRET_SENTINEL"
        response = json.dumps({"ok": True, "result": {"sessionId": "new-session-id"}})
        with mock.patch.object(stabilityd, "run_cmd", return_value=SimpleNamespace(
            returncode=0, stdout=response, stderr=sentinel,
        )) as run:
            payload, status = stabilityd.openclaw_gateway_call(
                "sessions.reset", {"key": "agent:catbody:main", "expectedSessionId": "old-id"},
            )
            rejected, rejected_status = stabilityd.openclaw_gateway_call("sessions.delete", {})
        self.assertEqual(status, "ok")
        self.assertEqual(payload, {"sessionId": "new-session-id"})
        self.assertEqual(rejected_status, "unsupported-gateway-rpc")
        self.assertIsNone(rejected)
        run.assert_called_once()
        args = run.call_args.args[0]
        self.assertEqual(args[:4], ["openclaw", "gateway", "call", "sessions.reset"])
        self.assertNotIn(sentinel, str(payload))


if __name__ == "__main__":
    unittest.main()
