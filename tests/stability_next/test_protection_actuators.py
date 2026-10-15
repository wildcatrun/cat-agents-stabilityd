import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from stability_core.protected_scope import ProtectionDecision
from stability_core import unit_capability


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
SPEC = importlib.util.spec_from_file_location("stabilityd_protection_actuator_test", MODULE_PATH)
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


class ProtectionActuatorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        binary = root / 'fixture-runtime'
        binary.write_bytes(b'synthetic-runtime-executable')
        binary.chmod(0o700)
        unit = root / 'openclaw-gateway.service'
        unit.write_text('[Service]\nExecStart=' + str(binary) + ' --fixture\n')
        properties = ('Id=openclaw-gateway.service\nLoadState=loaded\nFragmentPath=' + str(unit)
                      + '\nDropInPaths=\nExecStart={ path=' + str(binary) + ' ; argv[]='
                      + str(binary) + ' --fixture ; ignore_errors=no ; }\n')
        for patch in (mock.patch.object(unit_capability, 'UNIT_ROOTS', (root,)),
                      mock.patch.object(stabilityd, 'read_gateway_unit_properties', return_value=properties)):
            patch.start()
            self.addCleanup(patch.stop)

    def test_hermes_process_reap_fails_closed_when_owner_scope_unknown(self):
        process = {
            "pid": "42", "ppid": "99", "cmd": "python /home/flashcat/.hermes/profiles/catnose/lsp/server/pyright-langserver --stdio",
            "profile": "catnose", "processType": "pyright-langserver", "ageSeconds": 20000,
            "idleObservedSeconds": 20000, "cpuTicks": 1,
            "processIdentity": {"status": "known", "pid": 42, "starttime": 7, "uid": 1, "euid": 1,
                                "bootId": "b", "cmdlineDigest": "c", "cgroupDigest": "g"},
            "agentIds": [], "registryScopeComplete": False,
        }
        with mock.patch.object(stabilityd, "terminate_process_instance") as signaler, \
             mock.patch.object(stabilityd, "hermers_profile_mode_actuate", return_value=[]):
            actions = stabilityd.hermers_actuate(mock.Mock(), {"hermers": {"idleLspProcesses": [process]}},
                                                 {"canReapHermersIdleLsp": True})
        self.assertEqual(actions[0]["processes"][0]["reason"], "registry-scope-unavailable")
        signaler.assert_not_called()
        self.assertEqual(stabilityd.verify_hermers_orphan_worker(42, "catnose", [], process),
                         (False, "registry-scope-unavailable"))

    def test_openclaw_gateway_restart_blocks_unknown_registry_impact_scope(self):
        snapshot = {"gateway": {"nodeGeneration": "node:boot"}}
        incomplete_registry = {"source": "snapshot", "writeEligible": False, "records": []}
        with mock.patch.object(stabilityd, "resource_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "cron_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "session_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "hermers_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=incomplete_registry), \
             mock.patch.object(stabilityd, "run_cmd") as run_cmd:
            actions = stabilityd.actuate(mock.Mock(), snapshot, {"canRestartGateway": True, "restartCandidate": True})
        self.assertEqual(actions[0]["result"], "blocked")
        self.assertEqual(actions[0]["blockedReason"], "protection-scope-or-generation-unavailable")
        run_cmd.assert_not_called()

    def test_openclaw_gateway_restart_preserves_existing_policy_authorized_protected_impact(self):
        snapshot = {"generationId": "fixture-generation", "gateway": {"nodeGeneration": "node:boot"}}
        registry = {
            "source": "db", "writeEligible": True,
            "records": [{
                "agent_id": "main", "runtime": "openclaw", "platform": "openclaw",
                "execution_adapter": "openclaw", "endpoint_ref": "openclaw-agent:main",
                "status": "active", "can_receive_dispatch": 1, "can_start_workflow": 1,
                "gateway_proxy_allowed": 0,
            }],
        }
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        fake_process = SimpleNamespace(returncode=1, stderr=f"Authorization: Bearer {sentinel}")
        now = stabilityd.epoch()
        policy = {"canRestartGateway": True, "restartCandidate": True,
                  "restartReason": "approved-hard-fault", "updatedAtEpoch": now - 1,
                  "validUntilEpoch": now + 60}
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="node:boot"), \
             mock.patch.object(stabilityd, "systemctl_show_gateway", return_value={"ActiveState": "active", "SubState": "running"}), \
             mock.patch.object(stabilityd, "tcp_ok", return_value=True), \
             mock.patch.object(stabilityd, "gateway_http_health", return_value={"ok": True}), \
             mock.patch.object(stabilityd, "resource_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "cron_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "session_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "hermers_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "run_cmd", return_value=fake_process) as run_cmd:
            actions = stabilityd.actuate(mock.Mock(), snapshot, policy)
        self.assertEqual(actions[0]["protectionScope"]["status"], "protected")
        self.assertEqual(actions[0]["protectionScope"]["protectedSubjects"], ["main"])
        self.assertTrue(actions[0]["stderrOmitted"])
        self.assertNotIn(sentinel, str(actions[0]))
        self.assertNotIn("stderr", actions[0])
        self.assertEqual(actions[0]["ledgerState"], "uncertain")
        run_cmd.assert_called_once()

    def test_gateway_restart_success_is_postchecked_and_duplicate_does_not_restart_again(self):
        snapshot = {"generationId": "fixture-generation", "gateway": {"nodeGeneration": "node:boot"}}
        registry = {
            "source": "db", "writeEligible": True,
            "records": [{
                "agent_id": "cat_voice", "runtime": "openclaw", "platform": "openclaw",
                "execution_adapter": "openclaw", "endpoint_ref": "openclaw-agent:cat_voice",
                "status": "active", "can_receive_dispatch": 1, "can_start_workflow": 1,
                "gateway_proxy_allowed": 1,
            }],
        }
        policy = {"canRestartGateway": True, "restartCandidate": True,
                  "restartReason": "approved-hard-fault", "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        success = SimpleNamespace(returncode=0, stderr="")
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="node:boot"), \
             mock.patch.object(stabilityd, "systemctl_show_gateway", return_value={"ActiveState": "active", "SubState": "running"}), \
             mock.patch.object(stabilityd, "tcp_ok", return_value=True), \
             mock.patch.object(stabilityd, "gateway_http_health", return_value={"ok": True}) as health, \
             mock.patch.object(stabilityd, "record_restart_time") as cooldown, \
             mock.patch.object(stabilityd, "resource_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "cron_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "session_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "hermers_actuate", return_value=[]), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "run_cmd", return_value=success) as run_cmd:
            first = stabilityd.actuate(mock.Mock(), snapshot, policy)
            second = stabilityd.actuate(mock.Mock(), snapshot, policy)

        self.assertEqual(first[0]["ledgerState"], "succeeded")
        self.assertEqual(first[0]["result"], "ok")
        self.assertEqual(second[0]["ledgerDisposition"], "existing")
        self.assertEqual(second[0]["result"], "existing")
        self.assertTrue(second[0]["historicalExisting"])
        self.assertFalse(second[0]["authorizationReused"])
        run_cmd.assert_called_once()
        cooldown.assert_called_once()
        health.assert_called_once()

    def test_hermes_gateway_restart_requires_live_registry_scope(self):
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_heart", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catheart",
            "status": "active",
        }]}
        policy = {"canRestartHermersGateway": True,
                  "hermersGatewayRestartReason": "hermers-gateway-service-down",
                  "hermersGatewayRestartProfiles": [{"profile": "catheart",
                                                        "unit": "hermes-gateway-catheart.service"}],
                  "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        with mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd") as run_cmd:
            action = stabilityd.hermers_gateway_restart(
                mock.Mock(), "catheart", "hermes-gateway-catheart.service",
                "hermers-gateway-service-down", policy=policy, snapshot_generation="fixture-gen",
            )
        self.assertEqual(action["result"], "blocked")
        self.assertEqual(action["blockedReason"], "protected-or-unknown-profile-scope")
        run_cmd.assert_not_called()

    def test_hermes_gateway_restart_uses_durable_ledger_and_postcheck(self):
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_body", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catbody",
            "status": "active",
        }]}
        profile = "catbody"
        unit = f"hermes-gateway-{profile}.service"
        reason = "hermers-gateway-service-down"
        policy = {"canRestartHermersGateway": True, "hermersGatewayRestartReason": reason,
                  "hermersGatewayRestartProfiles": [{"profile": profile, "unit": unit}],
                  "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        command_ok = SimpleNamespace(returncode=0, stdout="Gateway active and running", stderr="")
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "db_get", return_value=0), \
             mock.patch.object(stabilityd, "db_set") as state_write, \
             mock.patch.object(stabilityd, "record_hermers_gateway_restart_time") as history_write, \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "systemctl_user_show", return_value={"ActiveState": "inactive", "SubState": "dead"}), \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd", return_value=command_ok) as run_cmd:
            first = stabilityd.hermers_gateway_restart(
                mock.Mock(), profile, unit, reason, policy=policy, snapshot_generation="fixture-gen",
            )
            second = stabilityd.hermers_gateway_restart(
                mock.Mock(), profile, unit, reason, policy=policy, snapshot_generation="fixture-gen",
            )
        self.assertEqual(first["ledgerState"], "succeeded")
        self.assertEqual(first["result"], "ok")
        self.assertEqual(second["ledgerDisposition"], "existing")
        self.assertEqual(run_cmd.call_count, 2)  # one restart plus its status postcheck
        state_write.assert_called_once()
        history_write.assert_called_once()

    def test_hermes_gateway_restart_pending_receipt_stays_uncertain_despite_healthy_status(self):
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_body", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catbody",
            "status": "active",
        }]}
        profile = "catbody"
        unit = f"hermes-gateway-{profile}.service"
        reason = "hermers-gateway-service-down"
        policy = {"canRestartHermersGateway": True, "hermersGatewayRestartReason": reason,
                  "hermersGatewayRestartProfiles": [{"profile": profile, "unit": unit}],
                  "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        command_ok = SimpleNamespace(returncode=0, stdout="Gateway active and running", stderr="")
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "db_get", return_value=0), \
             mock.patch.object(stabilityd, "db_set") as state_write, \
             mock.patch.object(stabilityd, "record_hermers_gateway_restart_time") as history_write, \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "systemctl_user_show", return_value={"ActiveState": "inactive", "SubState": "dead"}), \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd", side_effect=[SimpleNamespace(returncode=0, stdout="Profile restart was not confirmed: host operation is still pending FIXTURE_SECRET", stderr=""), command_ok]) as run_cmd:
            first = stabilityd.hermers_gateway_restart(
                mock.Mock(), profile, unit, reason, policy=policy, snapshot_generation="fixture-gen",
            )
            second = stabilityd.hermers_gateway_restart(
                mock.Mock(), profile, unit, reason, policy=policy, snapshot_generation="fixture-gen",
            )
        self.assertEqual(first["ledgerState"], "uncertain")
        self.assertEqual(first["result"], "uncertain")
        self.assertEqual(second["ledgerDisposition"], "existing")
        self.assertEqual(run_cmd.call_count, 2)  # one restart plus its status postcheck
        state_write.assert_not_called()
        history_write.assert_not_called()

        self.assertNotIn("FIXTURE_SECRET", str(first))

    def test_hermes_gateway_restart_blocks_profile_owner_change_at_final_fence(self):
        def registry(owner):
            return {"source": "db", "writeEligible": True, "records": [{
                "agent_id": owner, "runtime": "hermes_acp", "platform": "hermes",
                "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catbody",
                "status": "active",
            }]}
        reads = 0
        def changing_registry():
            nonlocal reads
            reads += 1
            return registry("catbody" if reads < 5 else "catnose")
        profile = "catbody"
        unit = f"hermes-gateway-{profile}.service"
        reason = "hermers-gateway-service-down"
        policy = {"canRestartHermersGateway": True, "hermersGatewayRestartReason": reason,
                  "hermersGatewayRestartProfiles": [{"profile": profile, "unit": unit}],
                  "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "db_get", return_value=0), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", side_effect=changing_registry), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "systemctl_user_show", return_value={"ActiveState": "inactive", "SubState": "dead"}), \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd") as run_cmd:
            action = stabilityd.hermers_gateway_restart(
                mock.Mock(), profile, unit, reason, policy=policy, snapshot_generation="fixture-gen",
            )
        self.assertEqual(action["ledgerState"], "blocked")
        self.assertGreaterEqual(reads, 5)
        run_cmd.assert_not_called()

    def test_hermes_gateway_postcheck_prioritizes_explicit_unready_status(self):
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_body", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catbody",
            "status": "active",
        }]}
        profile = "catbody"
        unit = f"hermes-gateway-{profile}.service"
        reason = "hermers-gateway-service-down"
        policy = {"canRestartHermersGateway": True, "hermersGatewayRestartReason": reason,
                  "hermersGatewayRestartProfiles": [{"profile": profile, "unit": unit}],
                  "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        for status_line in ("Gateway is active but not ready", "Gateway is not running", "Gateway inactive"):
            with self.subTest(status_line=status_line), tempfile.TemporaryDirectory() as tmpdir, \
                 mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
                 mock.patch.object(stabilityd, "db_get", return_value=0), \
                 mock.patch.object(stabilityd, "db_set"), \
                 mock.patch.object(stabilityd, "record_hermers_gateway_restart_time"), \
                 mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
                 mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
                 mock.patch.object(stabilityd, "systemctl_user_show", return_value={"ActiveState": "inactive", "SubState": "dead"}), \
                 mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd", side_effect=[
                     SimpleNamespace(returncode=0, stdout="restart accepted", stderr=""),
                     SimpleNamespace(returncode=0, stdout=status_line, stderr=""),
                 ]) as run_cmd:
                action = stabilityd.hermers_gateway_restart(
                    mock.Mock(), profile, unit, reason, policy=policy, snapshot_generation="fixture-gen",
                )
            self.assertEqual(action["ledgerState"], "failed")
            self.assertEqual(action["result"], "failed")
            self.assertEqual(run_cmd.call_count, 2)

    def test_profile_start_prevents_stale_same_cycle_gateway_restart(self):
        profile = "catbody"
        unit = f"hermes-gateway-{profile}.service"
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_body", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": f"hermes-profile:{profile}",
            "status": "active", "can_receive_dispatch": 1,
        }]}
        mode_item = {"profile": profile, "agentIds": ["cat_body"], "managed": True,
                     "activeWork": False, "active": False, "targetMode": "hot",
                     "unit": unit, "reason": "workflow-readiness"}
        snapshot = {"generationId": "fixture-generation", "hermers": {
            "orphanAcpWorkers": [], "idleLspProcesses": [],
            "profiles": {profile: {"active": False, "unit": unit}},
            "profileModes": {"profiles": {profile: mode_item}},
        }}
        now = stabilityd.epoch()
        policy = {"canRestartHermersGateway": True, "hermersGatewayRestartReason": "hermers-gateway-service-down",
                  "hermersGatewayRestartProfiles": [{"profile": profile, "unit": unit}],
                  "hermersProfileModeActuateEnabled": True, "hermersProfileModeStartEnabled": True,
                  "updatedAtEpoch": now - 1, "validUntilEpoch": now + 60}
        inactive = {"ActiveState": "inactive", "SubState": "dead"}
        active = {"ActiveState": "active", "SubState": "running"}
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "HERMERS_PROFILE_MODE_ENABLED", True), \
             mock.patch.object(stabilityd, "HERMERS_PROFILE_MODE_ACTUATE_ENABLED", True), \
             mock.patch.object(stabilityd, "HERMERS_PROFILE_MODE_START_ENABLED", True), \
             mock.patch.object(stabilityd, "HERMERS_PROFILE_LIFECYCLE_ALLOWLIST", {profile}), \
             mock.patch.object(stabilityd, "db_get", return_value=0), \
             mock.patch.object(stabilityd, "db_set"), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "hermers_profile_workflow_activity", return_value={profile: {
                 "probeOk": True, "activeRuntimeCount": 0, "activeDispatchCount": 0,
             }}), \
             mock.patch.object(stabilityd, "systemctl_user_show", side_effect=[inactive] * 4 + [active, active]), \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd",
                               return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run_cmd:
            actions = stabilityd.hermers_actuate(mock.Mock(), snapshot, policy,
                                                  snapshot_generation="fixture-generation")
        lifecycle = next(action for action in actions if action.get("action") == "set_hermers_profile_mode")
        restart = next(action for action in actions if action.get("action") == "restart_hermers_gateway")
        self.assertEqual(lifecycle["result"], "ok")
        self.assertEqual(restart["result"], "blocked")
        self.assertEqual(run_cmd.call_count, 1)
        run_cmd.assert_called_once_with(profile, "start", timeout=30)

    def test_hermes_profile_hibernate_uses_ledger_and_service_postcheck(self):
        profile = "catbody"
        item = {"profile": profile, "agentIds": ["cat_body"], "managed": True,
                "activeWork": False, "active": True, "targetMode": "hibernate",
                "safeToHibernate": True, "unit": f"hermes-gateway-{profile}.service",
                "reason": "idle-threshold"}
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_body", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catbody",
            "status": "active", "can_receive_dispatch": 1,
        }]}
        policy = {"hermersProfileModeActuateEnabled": True,
                  "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        active_service = {"ActiveState": "active", "SubState": "running"}
        stopped_service = {"ActiveState": "inactive", "SubState": "dead"}
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "HERMERS_PROFILE_LIFECYCLE_ALLOWLIST", {profile}), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "hermers_profile_workflow_activity", return_value={profile: {
                 "probeOk": True, "activeRuntimeCount": 0, "activeDispatchCount": 0,
             }}), \
             mock.patch.object(stabilityd, "systemctl_user_show", side_effect=[active_service] * 4 + [stopped_service]), \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd",
                               return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run_cmd, \
             mock.patch.object(stabilityd, "db_get", return_value=0), \
             mock.patch.object(stabilityd, "db_set") as state_write:
            first = stabilityd.execute_hermers_profile_lifecycle(
                mock.Mock(), profile, item, "hibernate", policy, "fixture-generation",
            )
            second = stabilityd.execute_hermers_profile_lifecycle(
                mock.Mock(), profile, item, "hibernate", policy, "fixture-generation",
            )
        self.assertEqual(first["ledgerState"], "succeeded")
        self.assertEqual(first["result"], "ok")
        self.assertEqual(second["ledgerDisposition"], "existing")
        run_cmd.assert_called_once()
        self.assertEqual(state_write.call_count, 2)

    def test_hermes_profile_stop_pending_receipt_stays_uncertain_despite_inactive_unit(self):
        profile = "catbody"
        item = {"profile": profile, "agentIds": ["cat_body"], "managed": True,
                "activeWork": False, "active": True, "targetMode": "hibernate",
                "safeToHibernate": True, "unit": f"hermes-gateway-{profile}.service",
                "reason": "idle-threshold"}
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_body", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catbody",
            "status": "active", "can_receive_dispatch": 1,
        }]}
        policy = {"hermersProfileModeActuateEnabled": True,
                  "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        active_service = {"ActiveState": "active", "SubState": "running"}
        stopped_service = {"ActiveState": "inactive", "SubState": "dead"}
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "HERMERS_PROFILE_LIFECYCLE_ALLOWLIST", {profile}), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "hermers_profile_workflow_activity", return_value={profile: {
                 "probeOk": True, "activeRuntimeCount": 0, "activeDispatchCount": 0,
             }}), \
             mock.patch.object(stabilityd, "systemctl_user_show", side_effect=[active_service] * 4 + [stopped_service]), \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd",
                               return_value=SimpleNamespace(returncode=0, stdout="Profile parked, but immediate stop was not confirmed: host control socket did not answer FIXTURE_SECRET", stderr="")) as run_cmd, \
             mock.patch.object(stabilityd, "db_get", return_value=0), \
             mock.patch.object(stabilityd, "db_set") as state_write:
            first = stabilityd.execute_hermers_profile_lifecycle(
                mock.Mock(), profile, item, "hibernate", policy, "fixture-generation",
            )
            second = stabilityd.execute_hermers_profile_lifecycle(
                mock.Mock(), profile, item, "hibernate", policy, "fixture-generation",
            )
        self.assertEqual(first["ledgerState"], "uncertain")
        self.assertEqual(first["result"], "uncertain")
        self.assertEqual(second["ledgerDisposition"], "existing")
        run_cmd.assert_called_once()
        state_write.assert_not_called()

        self.assertNotIn("FIXTURE_SECRET", str(first))

    def test_hermes_profile_lifecycle_blocks_protected_profile(self):
        profile = "catheart"
        item = {"profile": profile, "agentIds": ["cat_heart"], "managed": True,
                "activeWork": False, "active": True, "targetMode": "hibernate",
                "safeToHibernate": True, "unit": "hermes-gateway-catheart.service"}
        with mock.patch.object(stabilityd, "HERMERS_PROFILE_LIFECYCLE_ALLOWLIST", {profile}), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records") as registry, \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd") as run_cmd:
            action = stabilityd.execute_hermers_profile_lifecycle(
                mock.Mock(), profile, item, "hibernate", {"hermersProfileModeActuateEnabled": True}, "fixture-gen",
            )
        self.assertEqual(action["result"], "blocked")
        self.assertEqual(action["blockedReason"], "protected-profile")
        registry.assert_not_called()
        run_cmd.assert_not_called()

    def test_hermes_profile_start_requires_start_flag_and_active_postcheck(self):
        profile = "catbody"
        item = {"profile": profile, "agentIds": ["cat_body"], "managed": True,
                "activeWork": False, "active": False, "targetMode": "hot",
                "unit": f"hermes-gateway-{profile}.service", "reason": "workflow-readiness"}
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_body", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catbody",
            "status": "active", "can_receive_dispatch": 1,
        }]}
        policy = {"hermersProfileModeActuateEnabled": True,
                  "hermersProfileModeStartEnabled": True,
                  "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        inactive_service = {"ActiveState": "inactive", "SubState": "dead"}
        active_service = {"ActiveState": "active", "SubState": "running"}
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "HERMERS_PROFILE_LIFECYCLE_ALLOWLIST", {profile}), \
             mock.patch.object(stabilityd, "HERMERS_PROFILE_MODE_START_ENABLED", True), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "hermers_profile_workflow_activity", return_value={profile: {
                 "probeOk": True, "activeRuntimeCount": 0, "activeDispatchCount": 0,
             }}), \
             mock.patch.object(stabilityd, "systemctl_user_show", side_effect=[inactive_service] * 4 + [active_service]), \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd",
                               return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run_cmd, \
             mock.patch.object(stabilityd, "db_get", return_value=0), \
             mock.patch.object(stabilityd, "db_set"):
            action = stabilityd.execute_hermers_profile_lifecycle(
                mock.Mock(), profile, item, "hot", policy, "fixture-generation",
            )
        self.assertEqual(action["ledgerState"], "succeeded")
        self.assertEqual(action["result"], "ok")
        run_cmd.assert_called_once_with(profile, "start", timeout=30)

    def test_hermes_profile_hibernate_failed_service_postcheck_is_failure(self):
        profile = "catbody"
        item = {"profile": profile, "agentIds": ["cat_body"], "managed": True,
                "activeWork": False, "active": True, "targetMode": "hibernate",
                "safeToHibernate": True, "unit": f"hermes-gateway-{profile}.service"}
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_body", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catbody",
            "status": "active", "can_receive_dispatch": 1,
        }]}
        policy = {"hermersProfileModeActuateEnabled": True,
                  "updatedAtEpoch": stabilityd.epoch() - 1,
                  "validUntilEpoch": stabilityd.epoch() + 60}
        active = {"ActiveState": "active", "SubState": "running"}
        failed = {"ActiveState": "failed", "SubState": "failed"}
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(stabilityd, "HERMERS_PROFILE_LIFECYCLE_ALLOWLIST", {profile}), \
             mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(stabilityd, "current_host_generation", return_value="boot:fixture"), \
             mock.patch.object(stabilityd, "hermers_profile_workflow_activity", return_value={profile: {
                 "probeOk": True, "activeRuntimeCount": 0, "activeDispatchCount": 0,
             }}), \
             mock.patch.object(stabilityd, "systemctl_user_show", side_effect=[active] * 4 + [failed]), \
             mock.patch.object(stabilityd, "run_hermes_profile_gateway_cmd",
                               return_value=SimpleNamespace(returncode=0, stdout="", stderr="")), \
             mock.patch.object(stabilityd, "db_get", return_value=0), \
             mock.patch.object(stabilityd, "db_set") as state_write:
            action = stabilityd.execute_hermers_profile_lifecycle(
                mock.Mock(), profile, item, "hibernate", policy, "fixture-generation",
            )
        self.assertEqual(action["ledgerState"], "failed")
        self.assertEqual(action["result"], "failed")
        self.assertEqual(state_write.call_count, 1)  # attempt cooldown only
        self.assertFalse(any('planned:' in str(call.args[1]) for call in state_write.call_args_list))


if __name__ == "__main__":
    unittest.main()
