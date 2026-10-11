import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stability_core.process_identity import identities_match, read_process_identity, terminate_process_instance


def write_proc(root: Path, pid: int, *, starttime: int = 4242, comm: str = "worker (with spaces)") -> None:
    process = root / str(pid)
    process.mkdir(parents=True, exist_ok=True)
    suffix = ["S"] + [str(value) for value in range(4, 22)] + [str(starttime)] + ["0"] * 8
    (process / "stat").write_text(f"{pid} ({comm}) " + " ".join(suffix), encoding="utf-8")
    (process / "status").write_text("Name:\ttest\nUid:\t1000\t1001\t1002\t1003\n", encoding="utf-8")
    (process / "cmdline").write_bytes(b"/opt/hermes\x00-p\x00catnose\x00acp\x00")
    (process / "cgroup").write_bytes(b"0::/user.slice/test.scope\n")
    boot = root / "sys/kernel/random"
    boot.mkdir(parents=True, exist_ok=True)
    (boot / "boot_id").write_text("boot-abc\n", encoding="ascii")


class ProcessIdentityTest(unittest.TestCase):
    def test_reads_stat_with_spaces_and_parentheses_and_all_identity_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_proc(root, 321)
            value = read_process_identity(321, root)
            self.assertEqual(value["status"], "known")
            self.assertEqual(value["starttime"], 4242)
            self.assertEqual((value["uid"], value["euid"], value["bootId"]), (1000, 1001, "boot-abc"))
            self.assertEqual(value["cmdlineDigest"], hashlib.sha256(b"/opt/hermes\x00-p\x00catnose\x00acp\x00").hexdigest())

    def test_missing_identity_is_unknown_and_mismatch_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            unknown = read_process_identity(999, Path(tmp))
        self.assertEqual(unknown["status"], "unknown")
        self.assertEqual(identities_match(unknown, unknown), (False, "identity-unknown"))

    def test_pidfd_rechecks_then_signals_and_requires_exit_postcheck(self):
        expected = {"status": "known", "pid": 42, "starttime": 7, "uid": 1, "euid": 1,
                    "bootId": "b", "cmdlineDigest": "c", "cgroupDigest": "g"}
        gone = {"status": "unknown", "pid": 42, "reason": "FileNotFoundError: gone"}
        reader = mock.Mock(side_effect=[dict(expected), dict(expected), gone])
        opener, sender, closer = mock.Mock(return_value=8), mock.Mock(), mock.Mock()
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp)
            result = terminate_process_instance(expected, proc_root=proc_root, identity_reader=reader, pidfd_open=opener,
                                            pidfd_send_signal=sender, close_fd=closer, sleep=mock.Mock())
        self.assertEqual(result["result"], "succeeded")
        opener.assert_called_once_with(42, 0)
        sender.assert_called_once()
        closer.assert_called_once_with(8)

    def test_birth_change_after_pidfd_open_blocks_without_signal(self):
        expected = {"status": "known", "pid": 42, "starttime": 7, "uid": 1, "euid": 1,
                    "bootId": "b", "cmdlineDigest": "c", "cgroupDigest": "g"}
        changed = dict(expected, starttime=8)
        sender = mock.Mock()
        result = terminate_process_instance(expected, identity_reader=mock.Mock(side_effect=[expected, changed]),
                                            pidfd_open=mock.Mock(return_value=9), pidfd_send_signal=sender,
                                            close_fd=mock.Mock())
        self.assertEqual(result["result"], "blocked")
        sender.assert_not_called()

    def test_no_pidfd_has_no_unsafe_kill_fallback(self):
        expected = {"status": "known", "pid": 42, "starttime": 7, "uid": 1, "euid": 1,
                    "bootId": "b", "cmdlineDigest": "c", "cgroupDigest": "g"}
        sender = mock.Mock()
        result = terminate_process_instance(expected, pidfd_open=None, pidfd_send_signal=sender)
        self.assertEqual(result["reason"], "pidfd-unavailable")
        sender.assert_not_called()

    def test_partial_postcheck_failure_is_uncertain_when_pid_directory_remains(self):
        expected = {"status": "known", "pid": 42, "starttime": 7, "uid": 1, "euid": 1,
                    "bootId": "b", "cmdlineDigest": "c", "cgroupDigest": "g"}
        partial = {"status": "unknown", "pid": 42, "reason": "PermissionError: fake"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "42").mkdir()
            result = terminate_process_instance(
                expected, proc_root=root, identity_reader=mock.Mock(side_effect=[expected, expected, partial]),
                pidfd_open=mock.Mock(return_value=9), pidfd_send_signal=mock.Mock(), close_fd=mock.Mock(),
                sleep=mock.Mock(), postcheck_attempts=1,
            )
        self.assertEqual(result["result"], "uncertain")

    def test_daemon_batch_does_not_report_uncertain_signal_as_ok(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("stability_pid_test", root / "bin/cat_agents_stabilityd.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        fixture = tempfile.TemporaryDirectory()
        self.addCleanup(fixture.cleanup)
        proc = Path(fixture.name) / "proc"
        pid = 987654321
        write_proc(proc, pid)
        raw_boot = "12345678-1234-1234-1234-123456789abc"
        (proc / "sys/kernel/random/boot_id").write_text(raw_boot)
        identity = read_process_identity(pid, proc)
        worker = {"pid": str(pid), "ppid": "1", "cmd": "/opt/hermes -p catnose acp --accept-hooks",
                  "profile": "catnose", "processIdentity": identity, "agentIds": ["cat_nose"],
                  "registryProfile": "catnose", "registryProfileMatched": True,
                  "registryScopeComplete": True}
        snapshot = {"generationId": "fixture-generation", "hermers": {"orphanAcpWorkers": [worker]}}
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_nose", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catnose",
            "status": "active", "can_receive_dispatch": 1,
        }]}
        policy = {"canReapHermersOrphanWorkers": True,
                  "updatedAtEpoch": module.epoch() - 1, "validUntilEpoch": module.epoch() + 60}
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(module, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(module, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(module, "current_host_generation", return_value="fixture-node:" + raw_boot), \
             mock.patch.object(module.platform, "node", return_value="fixture-node"), \
             mock.patch("stability_core.effect_capability.read_local_boot_id", side_effect=lambda: (proc / "sys/kernel/random/boot_id").read_text()), \
             mock.patch.object(module, "process_effect_pidfd_protocol_available", return_value=True), \
             mock.patch.object(module, "ps_rows", return_value=[worker]), \
             mock.patch.object(module, "read_process_identity", side_effect=lambda value: read_process_identity(value, proc)), \
             mock.patch.object(module, "terminate_process_instance", return_value={"result": "uncertain", "reason": "still-running"}), \
             mock.patch.object(module, "hermers_profile_mode_actuate", return_value=[]):
            actions = module.hermers_actuate(mock.Mock(), snapshot, policy, snapshot_generation="fixture-generation")
        self.assertEqual(actions[0]["result"], "uncertain")

    def test_hermes_signal_action_uses_durable_ledger_and_does_not_replay(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("stability_pid_ledger_test", root / "bin/cat_agents_stabilityd.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        pid = 987654321
        fixture = tempfile.TemporaryDirectory()
        self.addCleanup(fixture.cleanup)
        proc = Path(fixture.name) / "proc"
        write_proc(proc, pid)
        raw_boot = "12345678-1234-1234-1234-123456789abc"
        (proc / "sys/kernel/random/boot_id").write_text(raw_boot)
        identity = read_process_identity(pid, proc)
        def exited_effect(captured):
            self.assertEqual(captured, identity)
            shutil.rmtree(proc / str(pid))
            return {"result": "succeeded", "reason": "process-exited"}
        worker = {"pid": str(pid), "ppid": "1", "cmd": "/opt/hermes -p catnose acp --accept-hooks",
                  "profile": "catnose", "processIdentity": identity, "agentIds": ["cat_nose"],
                  "registryProfile": "catnose", "registryProfileMatched": True,
                  "registryScopeComplete": True, "ageSeconds": 5000}
        snapshot = {"generationId": "fixture-generation", "hermers": {"orphanAcpWorkers": [worker]}}
        registry = {"source": "db", "writeEligible": True, "records": [{
            "agent_id": "cat_nose", "runtime": "hermes_acp", "platform": "hermes",
            "execution_adapter": "hermes_acp", "endpoint_ref": "hermes-profile:catnose",
            "status": "active", "can_receive_dispatch": 1,
        }]}
        policy = {"canReapHermersOrphanWorkers": True,
                  "updatedAtEpoch": module.epoch() - 1, "validUntilEpoch": module.epoch() + 60}
        with tempfile.TemporaryDirectory() as tmpdir, \
             mock.patch.object(module, "STATE_DB", Path(tmpdir) / "state.db"), \
             mock.patch.object(module, "workflow_runtime_registry_records", return_value=registry), \
             mock.patch.object(module, "current_host_generation", return_value="fixture-node:" + raw_boot), \
             mock.patch.object(module.platform, "node", return_value="fixture-node"), \
             mock.patch("stability_core.effect_capability.read_local_boot_id", side_effect=lambda: (proc / "sys/kernel/random/boot_id").read_text()), \
             mock.patch.object(module, "process_effect_pidfd_protocol_available", return_value=True), \
             mock.patch.object(module, "ps_rows", return_value=[worker]), \
             mock.patch.object(module, "read_process_identity", side_effect=lambda value: read_process_identity(value, proc)), \
             mock.patch.object(module, "terminate_process_instance", side_effect=exited_effect) as signaler, \
             mock.patch.object(module, "hermers_profile_mode_actuate", return_value=[]):
            first = module.execute_hermers_process_signal(
                worker, "hermes.process.orphan_reap", "canReapHermersOrphanWorkers",
                module.verify_hermers_orphan_worker, module.ps_rows, policy, "fixture-generation",
            )
            second = module.execute_hermers_process_signal(
                worker, "hermes.process.orphan_reap", "canReapHermersOrphanWorkers",
                module.verify_hermers_orphan_worker, module.ps_rows, policy, "fixture-generation",
            )
        self.assertEqual(first["result"], "ok")
        self.assertEqual(second["ledgerDisposition"], "existing")
        signaler.assert_called_once_with(identity)

    def test_protected_profile_blocks_before_signal(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("stability_pid_protected_test", root / "bin/cat_agents_stabilityd.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        worker = {"pid": "42", "ppid": "1", "cmd": "/opt/hermes -p catheart acp --accept-hooks",
                  "profile": "catheart", "processIdentity": {"status": "known", "pid": 42}}
        sender = mock.Mock()
        with mock.patch.object(module, "ps_rows", return_value=[worker]), \
             mock.patch.object(module, "terminate_process_instance", sender), \
             mock.patch.object(module, "hermers_profile_mode_actuate", return_value=[]):
            actions = module.hermers_actuate(mock.Mock(), {"hermers": {"orphanAcpWorkers": [worker]}},
                                             {"canReapHermersOrphanWorkers": True})
        self.assertEqual(actions[0]["result"], "blocked")
        sender.assert_not_called()

    def test_birth_only_change_proves_old_process_gone_but_other_identity_drift_is_uncertain(self):
        expected = {"status": "known", "pid": 42, "starttime": 7, "uid": 1, "euid": 1,
                    "bootId": "b", "cmdlineDigest": "c", "cgroupDigest": "g"}
        changed = dict(expected, starttime=8)
        result = terminate_process_instance(
            expected, identity_reader=mock.Mock(side_effect=[dict(expected), dict(expected), changed]),
            pidfd_open=mock.Mock(return_value=9), pidfd_send_signal=mock.Mock(), close_fd=mock.Mock(),
        )
        self.assertEqual(result["result"], "succeeded")
        changed = dict(expected, cmdlineDigest="new")
        result = terminate_process_instance(
            expected, identity_reader=mock.Mock(side_effect=[dict(expected), dict(expected), changed]),
            pidfd_open=mock.Mock(return_value=10), pidfd_send_signal=mock.Mock(), close_fd=mock.Mock(),
        )
        self.assertEqual(result["result"], "uncertain")

    def test_environment_and_registry_protected_ids_block_signal(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("stability_pid_protection_matrix", root / "bin/cat_agents_stabilityd.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        original = module.HERMERS_PROFILE_PROTECTED_IDS
        try:
            module.HERMERS_PROFILE_PROTECTED_IDS = set(original) | {"private_profile"}
            for profile, agent_ids in (
                ("catnose", ["cat_heart"]), ("catheart", []), ("private_profile", []), ("main", []),
            ):
                with self.subTest(profile=profile, agent_ids=agent_ids):
                    self.assertTrue(module._hermers_signal_profile_protected(profile, {"agentIds": agent_ids}))
        finally:
            module.HERMERS_PROFILE_PROTECTED_IDS = original

    def test_idle_lsp_registry_protection_also_blocks_signal(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("stability_lsp_protection_test", root / "bin/cat_agents_stabilityd.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        identity = {"status": "known", "pid": 42, "starttime": 7, "uid": 1, "euid": 1,
                    "bootId": "b", "cmdlineDigest": "c", "cgroupDigest": "g"}
        for profile, agent_id in (("catnose", "cat_heart"), ("catheart", "catheart"), ("main", "main")):
            with self.subTest(profile=profile, agent_id=agent_id):
                process = {
                    "pid": "42", "ppid": "99", "cmd": f"python /home/flashcat/.hermes/profiles/{profile}/lsp/server/pyright-langserver --stdio",
                    "profile": profile, "processType": "pyright-langserver", "ageSeconds": 20000,
                    "idleObservedSeconds": 20000, "cpuTicks": 1, "processIdentity": identity,
                    "agentIds": [agent_id],
                }
                signaler = mock.Mock()
                with mock.patch.object(module, "ps_rows", return_value=[
                    {"pid": "42", "ppid": "99", "cmd": process["cmd"]},
                    {"pid": "99", "ppid": "1", "cmd": f"python -m hermes_cli.main --profile {profile} gateway run"},
                ]), mock.patch.object(module, "proc_cmdline", side_effect=[process["cmd"], f"python -m hermes_cli.main --profile {profile} gateway run"]), \
                     mock.patch.object(module, "proc_cpu_ticks", return_value=1), \
                     mock.patch.object(module, "terminate_process_instance", signaler), \
                     mock.patch.object(module, "hermers_profile_mode_actuate", return_value=[]):
                    actions = module.hermers_actuate(mock.Mock(), {"hermers": {"idleLspProcesses": [process]}},
                                                     {"canReapHermersIdleLsp": True})
                self.assertEqual(actions[0]["result"], "blocked")
                signaler.assert_not_called()

    def test_unknown_hermes_owner_blocks_process_signal(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("stability_unknown_owner_test", root / "bin/cat_agents_stabilityd.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        process = {
            "pid": "42", "ppid": "99", "cmd": "python /home/flashcat/.hermes/profiles/catnose/lsp/server/pyright-langserver --stdio",
            "profile": "catnose", "processType": "pyright-langserver", "ageSeconds": 20000,
            "idleObservedSeconds": 20000, "cpuTicks": 1,
            "processIdentity": {"status": "known", "pid": 42, "starttime": 7, "uid": 1, "euid": 1,
                                "bootId": "b", "cmdlineDigest": "c", "cgroupDigest": "g"},
            "agentIds": [], "registryScopeComplete": False,
        }
        signaler = mock.Mock()
        with mock.patch.object(module, "ps_rows", return_value=[
            {"pid": "42", "ppid": "99", "cmd": process["cmd"]},
            {"pid": "99", "ppid": "1", "cmd": "python -m hermes_cli.main --profile catnose gateway run"},
        ]), mock.patch.object(module, "proc_cmdline", side_effect=[
            process["cmd"], "python -m hermes_cli.main --profile catnose gateway run",
        ]), mock.patch.object(module, "proc_cpu_ticks", return_value=1), \
             mock.patch.object(module, "terminate_process_instance", signaler), \
             mock.patch.object(module, "hermers_profile_mode_actuate", return_value=[]):
            actions = module.hermers_actuate(mock.Mock(), {"hermers": {"idleLspProcesses": [process]}},
                                             {"canReapHermersIdleLsp": True})
        self.assertEqual(actions[0]["processes"][0]["reason"], "registry-scope-unavailable")
        signaler.assert_not_called()

    def test_close_failure_is_reported_and_never_raises(self):
        expected = {"status": "known", "pid": 42, "starttime": 7, "uid": 1, "euid": 1,
                    "bootId": "b", "cmdlineDigest": "c", "cgroupDigest": "g"}
        gone = {"status": "unknown", "pid": 42}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "42").mkdir()
            result = terminate_process_instance(
                expected, proc_root=root, identity_reader=mock.Mock(side_effect=[expected, expected, gone]),
                pidfd_open=mock.Mock(return_value=9), pidfd_send_signal=mock.Mock(),
                close_fd=mock.Mock(side_effect=OSError("fake")), sleep=mock.Mock(),
            )
        self.assertEqual(result["result"], "uncertain")
        self.assertEqual(result["fdCloseError"], "OSError")

    def test_signal_batch_uncertain_dominates_failed(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("stability_pid_batch_test", root / "bin/cat_agents_stabilityd.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.assertEqual(module._signal_batch_result([{"result": "failed"}, {"result": "uncertain"}]), "uncertain")


if __name__ == "__main__":
    unittest.main()
