#!/usr/bin/env python3
"""Focused tests for the local Codex refresh/mirror decision rules."""

import pathlib
import subprocess
import sys
import unittest
import datetime as dt
import tempfile
import json
import os
import sqlite3
import importlib.util
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mac_codex_oauth_mirror_maintenance as maintenance
import mac_codex_oauth_mirror as mirror_cli

_stabilityd_path = pathlib.Path(__file__).resolve().parents[1] / "bin" / "cat_agents_stabilityd.py"
_stabilityd_spec = importlib.util.spec_from_file_location("cat_agents_stabilityd_cli_test", _stabilityd_path)
assert _stabilityd_spec and _stabilityd_spec.loader
stabilityd_cli = importlib.util.module_from_spec(_stabilityd_spec)
sys.modules[_stabilityd_spec.name] = stabilityd_cli
_stabilityd_spec.loader.exec_module(stabilityd_cli)


class MirrorDecisionTests(unittest.TestCase):
    def test_only_plugin_eligible_mirror_actions_are_selected(self):
        plan = {
            "schemaVersion": 1,
            "macCodexExecutor": {
                "supported": True,
                "refreshOwner": "mac-codex",
                "refreshBrokerEnabled": False,
            },
            "actions": [
                {
                    "actionId": "openclaw_main_openai_reauth_or_sync",
                    "kind": "reauth-or-sync",
                    "target": "openclaw:main:openai",
                    "humanGateRequired": False,
                    "localAutomation": {
                        "eligible": True,
                        "owner": "mac-codex",
                        "mode": "access-id-token-mirror",
                    },
                },
                {
                    "actionId": "openclaw_main_required_provider_reauth",
                    "kind": "reauth",
                    "target": "openclaw:main:required-provider",
                    "humanGateRequired": True,
                },
                {
                    "actionId": "unknown_executor_action",
                    "kind": "sync-or-refresh",
                    "target": "hermers:catbody",
                    "humanGateRequired": False,
                    "localAutomation": {
                        "eligible": True,
                        "owner": "dev-server",
                        "mode": "access-id-token-mirror",
                    },
                },
                {
                    "actionId": "missing_gate_field",
                    "kind": "mirror-from-mac-codex",
                    "target": "codex-cli",
                    "localAutomation": {
                        "eligible": True,
                        "owner": "mac-codex",
                        "mode": "access-id-token-mirror",
                    },
                },
            ]
        }
        selected = maintenance.eligible_mirror_actions(plan)
        self.assertEqual([x["actionId"] for x in selected], ["openclaw_main_openai_reauth_or_sync"])
        self.assertEqual(maintenance.eligible_mirror_actions({"actions": plan["actions"]}), [])
        self.assertTrue(maintenance.plan_has_human_gate(plan))
        self.assertTrue(
            maintenance.plan_has_human_gate(
                {
                    "schemaVersion": 1,
                    "macCodexExecutor": plan["macCodexExecutor"],
                    "actions": [{"actionId": "malformed-gate-action"}],
                }
            )
        )

    def test_action_mirror_scope_limits_writes_to_authorized_targets(self):
        scope = maintenance.mirror_scope_for_actions(
            [
                {"target": "hermers:catbody"},
                {"target": "openclaw:main:openai"},
                {"target": "openclaw:cat_claw:openai-codex"},
            ]
        )
        self.assertFalse(scope["codexCli"])
        self.assertEqual(scope["hermersProfiles"], ["catbody"])
        self.assertEqual(
            scope["openclawTargets"],
            [
                {"agentId": "cat_claw", "profileKind": "openai-codex"},
                {"agentId": "main", "profileKind": "openai"},
            ],
        )

    def test_source_wide_scope_uses_targets_declared_by_stabilityd_plan(self):
        targets = {
            "codexCli": True,
            "hermersProfiles": ["catbody", "catheart", "catnose"],
            "openclawTargets": [
                {"agentId": "cat_claw", "profileKind": "openai-codex"},
                {"agentId": "main", "profileKind": "openai"},
            ],
        }
        plan = {"macCodexExecutor": {"targets": targets}}
        self.assertEqual(maintenance.mirror_scope_for_plan_targets(plan), targets)
        with self.assertRaisesRegex(ValueError, "empty-mirror-target-scope"):
            maintenance.mirror_scope_for_plan_targets(
                {"macCodexExecutor": {"targets": {"codexCli": False, "hermersProfiles": [], "openclawTargets": []}}}
            )
        with self.assertRaisesRegex(ValueError, "unsafe-hermers-profile-target"):
            maintenance.mirror_scope_for_plan_targets(
                {"macCodexExecutor": {"targets": {"codexCli": False, "hermersProfiles": ["../codex"], "openclawTargets": []}}}
            )
    def test_mirror_scope_rejects_path_traversal_and_unsupported_provider(self):
        with self.assertRaisesRegex(ValueError, "unsafe-hermers-profile-target"):
            maintenance.mirror_scope_for_actions([{"target": "hermers:../../.codex"}])
        with self.assertRaisesRegex(ValueError, "unsupported-openclaw-mirror-target"):
            maintenance.mirror_scope_for_actions([{"target": "openclaw:main:../auth"}])

    def test_scoped_mirror_command_does_not_include_other_targets(self):
        completed = subprocess.CompletedProcess([], 0, '{"result":"applied"}', "")
        scope = {
            "codexCli": False,
            "hermersProfiles": ["catbody"],
            "openclawTargets": [
                {"agentId": "main", "profileKind": "openai"},
                {"agentId": "cat_claw", "profileKind": "openai-codex"},
            ],
        }
        with mock.patch.object(maintenance.subprocess, "run", return_value=completed) as run:
            maintenance.run_mirror(
                ["hermers_catbody_token_sync"],
                scope,
                "retry-operation-123",
                ["unresolved-operation-456"],
            )
        command = run.call_args.args[0]
        self.assertIn("--no-codex-cli", command)
        self.assertIn("--hermers-profiles", command)
        self.assertIn("catbody", command)
        self.assertIn("--openclaw-targets", command)
        self.assertIn("main:openai,cat_claw:openai-codex", command)
        self.assertIn("--mirror-operation-id", command)
        self.assertEqual(command[command.index("--mirror-operation-id") + 1], "retry-operation-123")
        self.assertIn("--protect-operation-ids", command)
        self.assertEqual(command[command.index("--protect-operation-ids") + 1], "unresolved-operation-456")
        self.assertNotIn("--openclaw-agents", command)

    def test_failed_mirror_reuses_operation_id_only_for_same_generation_and_scope(self):
        source = {"accessExpiresAt": "2026-10-09T15:14:22Z", "lastRefresh": "2026-09-29T15:14:22Z"}
        action_ids = ["hermers_catbody_token_sync"]
        scope = {"codexCli": False, "hermersProfiles": ["catbody"], "openclawTargets": []}
        prior = {
            "lastMirrorAttempt": {
                "result": "failed",
                "operationId": "retry-operation-123",
                "refreshConditionKey": maintenance.refresh_condition_key(source),
                "actionIds": action_ids,
                "sourceWide": False,
                "mirrorScope": scope,
            }
        }
        self.assertEqual(
            maintenance.mirror_operation_id_for_attempt(prior, source, action_ids, scope, False),
            "retry-operation-123",
        )
        self.assertNotEqual(
            maintenance.mirror_operation_id_for_attempt(prior, source, action_ids, {**scope, "hermersProfiles": ["cateyes"]}, False),
            "retry-operation-123",
        )
        self.assertNotEqual(
            maintenance.mirror_operation_id_for_attempt(prior, {**source, "lastRefresh": "new-generation"}, action_ids, scope, False),
            "retry-operation-123",
        )

    def test_source_expiry_or_refresh_timestamp_advances_detect_as_changed(self):
        success = {
            "sourceAccessExpiresAt": "2026-08-21T06:06:23Z",
            "sourceLastRefresh": "2026-08-11T06:06:23Z",
            "sourceAuthMtimeEpoch": 100,
        }
        self.assertTrue(
            maintenance.source_changed(
                {
                    "accessExpiresAt": "2026-10-09T15:14:22Z",
                    "lastRefresh": "2026-09-29T15:14:22Z",
                    "authMtimeEpoch": 200,
                },
                success,
            )
        )

    def test_refresh_nudge_is_limited_to_window_and_retry_interval(self):
        source = {
            "accessExpiresAt": "2026-10-01T10:00:00Z",
            "accessSecondsRemaining": 180,
            "refreshTokenPresent": True,
        }
        now = 10000
        with mock.patch.object(maintenance, "CODEX", pathlib.Path(sys.executable)):
            self.assertTrue(maintenance.should_nudge_refresh(source, None, now))
            self.assertFalse(
                maintenance.should_nudge_refresh(
                    source,
                    {"sourceRefreshAttempt": {
                        "refreshConditionKey": maintenance.refresh_condition_key(source),
                        "attemptedAtEpoch": now - 30,
                        "retryAfterSeconds": 60,
                    }},
                    now,
                )
            )
            self.assertTrue(
                maintenance.should_nudge_refresh(
                    source,
                    {"sourceRefreshAttempt": {
                        "refreshConditionKey": maintenance.refresh_condition_key(source),
                        "attemptedAtEpoch": now - 60,
                        "retryAfterSeconds": 60,
                    }},
                    now,
                )
            )
            self.assertFalse(
                maintenance.should_nudge_refresh({**source, "accessSecondsRemaining": 301}, None, now)
            )

    def test_concurrent_codex_refresh_is_observed_before_cli_refresh(self):
        source = {
            "accessExpiresAt": "2026-10-01T10:00:00Z",
            "lastRefresh": "2026-09-20T00:00:00Z",
            "idExpiresAt": "2026-09-20T00:00:00Z",
        }
        advanced = {
            **source,
            "accessExpiresAt": "2026-10-11T00:00:00Z",
            "lastRefresh": "2026-10-01T10:00:00Z",
            "idExpiresAt": "2026-10-01T10:00:00Z",
        }
        with mock.patch.object(maintenance, "CONCURRENT_REFRESH_SETTLE_SECONDS", 15):
            with mock.patch.object(maintenance.time, "sleep") as sleep:
                with mock.patch.object(maintenance, "inspect_source", return_value=advanced):
                    attempt, current = maintenance.observe_concurrent_local_refresh(source)
        sleep.assert_called_once_with(15)
        self.assertEqual(attempt["result"], "token-advanced-by-concurrent-local-refresh")
        self.assertEqual(current["accessExpiresAt"], advanced["accessExpiresAt"])

    def test_codex_refresh_window_and_retry_backoff(self):
        now = int(dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc).timestamp())
        old_refresh = dt.datetime.fromtimestamp(now - 8 * 24 * 60 * 60, dt.timezone.utc).isoformat().replace("+00:00", "Z")
        source = {
            "accessExpiresAt": "2026-10-04T00:00:00Z",
            "accessSecondsRemaining": 3 * 24 * 60 * 60,
            "lastRefresh": old_refresh,
            "refreshTokenPresent": True,
        }
        self.assertFalse(maintenance.codex_refresh_due(source, now))
        self.assertTrue(maintenance.codex_refresh_due({**source, "accessSecondsRemaining": 300}, now))
        self.assertFalse(maintenance.codex_refresh_due({"lastRefresh": old_refresh}, now))
        key = maintenance.refresh_condition_key(source)
        self.assertEqual(maintenance.next_retry_seconds(None, key), (1, 60))
        self.assertEqual(
            maintenance.next_retry_seconds({"sourceRefreshAttempt": {"refreshConditionKey": key, "attemptNumber": 1}}, key),
            (2, 120),
        )
        self.assertEqual(
            maintenance.classify_codex_failure("refresh token was revoked; please log out and sign in again"),
            ("interactive-reauth-required", True),
        )

    def test_failed_mirror_is_cooled_down_by_source_generation_and_action(self):
        source = {
            "accessExpiresAt": "2026-10-09T15:14:22Z",
            "lastRefresh": "2026-09-29T15:14:22Z",
        }
        previous = {
            "lastMirrorAttempt": {
                "result": "failed",
                "refreshConditionKey": maintenance.refresh_condition_key(source),
                "attemptedAtEpoch": 1000,
                "retryAfterSeconds": 300,
                "actionIds": ["hermers_catbody_token_sync"],
            }
        }
        self.assertTrue(maintenance.mirror_retry_deferred(previous, source, ["hermers_catbody_token_sync"], 1100))
        self.assertFalse(maintenance.mirror_retry_deferred(previous, source, ["openclaw_main_openai_sync"], 1100))
        self.assertFalse(maintenance.mirror_retry_deferred(previous, source, ["hermers_catbody_token_sync"], 1300))
        self.assertFalse(
            maintenance.mirror_retry_deferred(
                previous,
                {**source, "lastRefresh": "2026-10-01T10:00:00Z"},
                None,
                1100,
            )
        )

    def test_postcheck_is_scoped_to_attempted_actions_unless_source_wide(self):
        scope = {
            "codexCli": False,
            "hermersProfiles": ["catbody"],
            "openclawTargets": [{"agentId": "main", "profileKind": "openai"}],
        }
        executor = {
            "supported": True,
            "refreshOwner": "mac-codex",
            "refreshBrokerEnabled": False,
            "targets": scope,
        }
        eligible = {
            "actionId": "hermers_catbody_token_sync",
            "target": "hermers:catbody",
            "kind": "sync-or-refresh",
            "humanGateRequired": False,
            "localAutomation": {"eligible": True},
        }
        other = {
            "actionId": "openclaw_main_openai_sync",
            "target": "openclaw:main:openai",
            "kind": "reauth-or-sync",
            "humanGateRequired": False,
            "localAutomation": {"eligible": True},
        }
        plan = {"schemaVersion": 1, "macCodexExecutor": executor, "actions": [eligible, other]}
        self.assertEqual(
            maintenance.unresolved_mirror_action_ids(plan, [eligible], source_wide=False),
            ["hermers_catbody_token_sync"],
        )
        self.assertEqual(
            maintenance.unresolved_mirror_action_ids(plan, [eligible], source_wide=True, scope=scope),
            ["hermers_catbody_token_sync", "openclaw_main_openai_sync"],
        )
        gated_plan = {**plan, "actions": [eligible, {"actionId": "requires-login", "humanGateRequired": True}]}
        self.assertEqual(
            maintenance.unresolved_mirror_action_ids(gated_plan, [eligible], source_wide=True, scope=scope),
            ["human-gate-required"],
        )
        malformed_id_plan = {**plan, "actions": [{"humanGateRequired": False, "localAutomation": {"eligible": True}}]}
        self.assertEqual(
            maintenance.unresolved_mirror_action_ids(malformed_id_plan, [], source_wide=True, scope=scope),
            ["invalid-plan-action-id"],
        )
        targeted_gate_plan = {**plan, "actions": [{**eligible, "humanGateRequired": True}]}
        self.assertEqual(
            maintenance.unresolved_mirror_action_ids(targeted_gate_plan, [eligible], source_wide=False),
            ["human-gate-required"],
        )

    def test_postcheck_recovery_rechecks_saved_selective_mirror_action_ids(self):
        executor = {"supported": True, "refreshOwner": "mac-codex", "refreshBrokerEnabled": False}
        action = {
            "actionId": "hermers_catbody_token_sync",
            "target": "hermers:catbody",
            "kind": "sync-or-refresh",
            "humanGateRequired": False,
            "localAutomation": {"eligible": True},
        }
        success = {"sourceWide": False, "mirrorActionIds": [action["actionId"]]}
        unresolved_plan = {"schemaVersion": 1, "macCodexExecutor": executor, "actions": [action]}
        resolved_plan = {"schemaVersion": 1, "macCodexExecutor": executor, "actions": []}
        self.assertEqual(
            maintenance.unresolved_saved_mirror_action_ids(unresolved_plan, success),
            [action["actionId"]],
        )
        self.assertEqual(maintenance.unresolved_saved_mirror_action_ids(resolved_plan, success), [])
        self.assertEqual(
            maintenance.unresolved_saved_mirror_action_ids(unresolved_plan, {"sourceWide": False}),
            ["missing-saved-mirror-action-ids"],
        )
        self.assertEqual(
            maintenance.mirror_postcheck_block_reason(["human-gate-required"]),
            "human-gate-required",
        )
        self.assertEqual(
            maintenance.mirror_postcheck_block_reason(["invalid-plan-action-id"]),
            "invalid-plan-action-id",
        )
        self.assertIsNone(maintenance.mirror_postcheck_block_reason([action["actionId"]]))

    def test_applied_mirror_with_unavailable_postcheck_is_recorded_without_marking_verified(self):
        with tempfile.TemporaryDirectory(prefix="auth-refresh-test-") as tmp:
            latest = pathlib.Path(tmp) / "latest.json"
            with mock.patch.object(maintenance, "LATEST_FILE", latest):
                summary = self._assert_unavailable_postcheck_state()
                self.assertEqual(
                    maintenance.protected_mirror_operation_ids(summary),
                    ["pending-operation-123"],
                )
                recovered_previous = dict(summary)
                recovered_previous["lastMirrorAttempt"] = {
                    **summary["lastMirrorAttempt"],
                    "result": "applied",
                    "postcheckStatus": "ok",
                }
                recovered = maintenance.write_attempt(
                    recovered_previous,
                    status="postcheck-recovered",
                    source={"accessExpiresAt": "2026-10-09T15:14:22Z", "lastRefresh": "2026-09-29T15:14:22Z"},
                )
                self.assertEqual(recovered["pendingMirrorOperationIds"], [])
                for blocked_result in ("blocked", "failed"):
                    blocked_previous = dict(summary)
                    blocked_previous["lastMirrorAttempt"] = {
                        **summary["lastMirrorAttempt"],
                        "result": blocked_result,
                        "postcheckStatus": "blocked" if blocked_result == "blocked" else "unresolved-actions",
                        "applyResult": "applied",
                    }
                    maintenance.mark_last_mirror_postcheck_resolved(blocked_previous)
                    recovered = maintenance.write_attempt(
                        blocked_previous,
                        status="postcheck-recovered",
                        source={"accessExpiresAt": "2026-10-09T15:14:22Z", "lastRefresh": "2026-09-29T15:14:22Z"},
                    )
                    self.assertEqual(recovered["pendingMirrorOperationIds"], [])

    def _assert_unavailable_postcheck_state(self):
        source = {"accessExpiresAt": "2026-10-09T15:14:22Z", "lastRefresh": "2026-09-29T15:14:22Z"}
        actions = [{"actionId": "source-generation", "localSourceChange": True}]
        mirror = {
            "result": "applied",
            "operationId": "pending-operation-123",
            "sourceWide": True,
            "mirrorScope": {"codexCli": True, "hermersProfiles": ["catbody"], "openclawTargets": []},
            "postcheck": {"status": "unavailable"},
            "summary": {"status": "applied"},
        }
        summary = maintenance.write_attempt(
            None,
            status="mirror-failed",
            source=source,
            plan={"actions": []},
            mirror_actions=actions,
            mirror=mirror,
            error="mirror-postcheck-unavailable",
        )
        self.assertEqual(summary["lastSuccessfulMirror"]["postcheckOk"], False)
        self.assertEqual(summary["lastSuccessfulMirror"]["postcheckStatus"], "unavailable")
        self.assertEqual(summary["lastMirrorAttempt"]["result"], "postcheck-pending")
        self.assertEqual(summary["pendingMirrorOperationIds"], ["pending-operation-123"])
        return summary

    def test_remote_receiver_rejects_symlink_escape_and_secures_auth_backups(self):
        namespace = {"__name__": "remote_receiver_test"}
        exec(compile(mirror_cli.REMOTE_RECEIVER, "remote_receiver.py", "exec"), namespace)
        with tempfile.TemporaryDirectory(prefix="auth-refresh-remote-test-") as tmp:
            base = pathlib.Path(tmp)
            profiles = (base / "profiles").resolve()
            profiles.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (profiles / "escape").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink-hermes-profile-target"):
                namespace["safe_target_path"](profiles, profiles / "escape" / "auth.json", "hermes-profile")

            source = base / "auth.json"
            source.write_text('{"refresh_token":"redacted-test"}\n', encoding="utf-8")
            source.chmod(0o644)
            backups = base / "artifacts" / "backups"
            backup = namespace["backup_file"](source, backups, "auth.json")
            self.assertEqual(pathlib.Path(backup).stat().st_mode & 0o777, 0o600)
            self.assertEqual(backups.stat().st_mode & 0o777, 0o700)
            original = pathlib.Path(backup).read_text(encoding="utf-8")
            source.write_text('{"refresh_token":"changed-after-first-attempt"}\n', encoding="utf-8")
            self.assertEqual(namespace["backup_file"](source, backups, "auth.json"), backup)
            self.assertEqual(pathlib.Path(backup).read_text(encoding="utf-8"), original)
            broken_backups = base / "interrupted-artifact" / "backups"
            with mock.patch.object(namespace["shutil"], "copyfileobj", side_effect=OSError("simulated copy interruption")):
                with self.assertRaisesRegex(OSError, "simulated copy interruption"):
                    namespace["backup_file"](source, broken_backups, "auth.json")
            self.assertFalse((broken_backups / "auth.json").exists())
            self.assertEqual(list(broken_backups.glob("auth.json.*.tmp")), [])
            broken_backups.mkdir(parents=True, exist_ok=True)
            corrupt_backup = broken_backups / "auth.json"
            corrupt_backup.write_text("partial json", encoding="utf-8")
            with self.assertRaises(ValueError):
                namespace["backup_file"](source, broken_backups, "auth.json")

            database = base / "auth.sqlite"
            connection = sqlite3.connect(database)
            connection.execute("create table state(value text)")
            connection.execute("insert into state values ('before')")
            connection.commit()
            connection.close()
            db_backup = namespace["backup_sqlite"](str(database), backups, "auth.sqlite")
            connection = sqlite3.connect(database)
            connection.execute("insert into state values ('after')")
            connection.commit()
            connection.close()
            self.assertEqual(namespace["backup_sqlite"](str(database), backups, "auth.sqlite"), db_backup)
            connection = sqlite3.connect(db_backup[0])
            self.assertEqual(connection.execute("select value from state").fetchall(), [("before",)])
            connection.close()
            pathlib.Path(db_backup[0]).write_text("partial sqlite", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sqlite-backup-integrity-check-failed"):
                namespace["backup_sqlite"](str(database), backups, "auth.sqlite")

    def test_mirror_backup_retention_keeps_three_successes_and_all_unresolved_artifacts(self):
        namespace = {"__name__": "remote_receiver_test"}
        exec(compile(mirror_cli.REMOTE_RECEIVER, "remote_receiver.py", "exec"), namespace)
        with tempfile.TemporaryDirectory(prefix="auth-refresh-retention-test-") as tmp:
            root = pathlib.Path(tmp)
            successful = []
            for index in range(4):
                artifact = root / f"operation-{index}-mac-codex-oauth-mirror"
                artifact.mkdir()
                (artifact / "index.json").write_text(json.dumps({"status": "applied"}), encoding="utf-8")
                os.utime(artifact, ns=(index + 1, index + 1))
                successful.append(artifact)
            unresolved = root / "failed-op-mac-codex-oauth-mirror"
            unresolved.mkdir()
            (unresolved / "index.json").write_text(json.dumps({"status": "partial-failure"}), encoding="utf-8")
            namespace["prune_successful_mirror_artifacts"](root, successful[-1], ["operation-0"])
            retained = {path.name for path in root.glob("*-mac-codex-oauth-mirror") if path.is_dir()}
            self.assertEqual(
                retained,
                {
                    "operation-0-mac-codex-oauth-mirror",
                    "operation-1-mac-codex-oauth-mirror",
                    "operation-2-mac-codex-oauth-mirror",
                    "operation-3-mac-codex-oauth-mirror",
                    "failed-op-mac-codex-oauth-mirror",
                },
            )
            namespace["prune_successful_mirror_artifacts"](root, successful[-1], [])
            retained = {path.name for path in root.glob("*-mac-codex-oauth-mirror") if path.is_dir()}
            self.assertEqual(
                retained,
                {
                    "operation-1-mac-codex-oauth-mirror",
                    "operation-2-mac-codex-oauth-mirror",
                    "operation-3-mac-codex-oauth-mirror",
                    "failed-op-mac-codex-oauth-mirror",
                },
            )

    def test_codex_refresh_request_has_no_user_config_or_local_tools(self):
        source = {
            "accessExpiresAt": "2026-10-01T10:05:00Z",
            "accessSecondsRemaining": 300,
            "lastRefresh": "2026-09-20T00:00:00Z",
        }
        updated = {
            **source,
            "accessExpiresAt": "2026-10-11T00:00:00Z",
            "lastRefresh": "2026-10-01T10:00:00Z",
        }
        completed = subprocess.CompletedProcess([], 0, "AUTH-MAINTENANCE-OK", "")
        with mock.patch.object(maintenance.subprocess, "run", return_value=completed) as run:
            with mock.patch.object(maintenance, "inspect_source", return_value=updated):
                attempt, result = maintenance.nudge_codex_refresh(source)
        command = run.call_args.args[0]
        self.assertIn("--ignore-user-config", command)
        self.assertIn("shell_tool", command)
        self.assertIn("--disable", command)
        self.assertIn("/private/tmp", command)
        self.assertNotIn("/Users/Flashcat", command)
        self.assertEqual(run.call_args.kwargs["env"]["CODEX_HOME"], str(maintenance.AUTH_PATH.parent))
        self.assertEqual(run.call_args.kwargs["env"]["HTTPS_PROXY"], "http://127.0.0.1:7890")
        self.assertEqual(attempt["result"], "token-advanced")
        self.assertEqual(result["accessExpiresAt"], updated["accessExpiresAt"])

    def test_source_inspection_and_mirror_pin_the_canonical_auth_file(self):
        completed = subprocess.CompletedProcess(
            [], 0, '{"status":"ok","accessExpiresAt":"2026-10-09T15:14:22Z"}', ""
        )
        with mock.patch.object(maintenance.subprocess, "run", return_value=completed) as run:
            maintenance.inspect_source()
        self.assertIn(str(maintenance.AUTH_PATH), run.call_args.args[0])

        applied = subprocess.CompletedProcess([], 0, '{"result":"applied"}', "")
        with mock.patch.object(maintenance.subprocess, "run", return_value=applied) as run:
            maintenance.run_mirror(["codex_cli_mirror_required"], {"codexCli": True, "hermersProfiles": [], "openclawTargets": []})
        self.assertIn("--codex-auth", run.call_args.args[0])
        self.assertIn(str(maintenance.AUTH_PATH), run.call_args.args[0])

    def test_auth_mirror_cli_accepts_and_forwards_canonical_auth_path(self):
        auth_path = "/Users/Flashcat/.codex/auth.json"
        completed = subprocess.CompletedProcess([], 0, '{"status":"ok"}', "")
        with mock.patch.object(stabilityd_cli.platform, "system", return_value="Darwin"):
            with mock.patch.object(stabilityd_cli, "run_cmd", return_value=completed) as run:
                stabilityd_cli.main([
                    "auth-mirror", "--apply", "--codex-auth", auth_path,
                    "--mirror-operation-id", "retry-operation-123",
                    "--protect-operation-ids", "unresolved-operation-456",
                ])
        command = run.call_args.args[0]
        self.assertIn("--apply", command)
        self.assertIn("--codex-auth", command)
        self.assertEqual(command[command.index("--codex-auth") + 1], auth_path)
        self.assertIn("--mirror-operation-id", command)
        self.assertEqual(command[command.index("--mirror-operation-id") + 1], "retry-operation-123")
        self.assertIn("--protect-operation-ids", command)
        self.assertEqual(command[command.index("--protect-operation-ids") + 1], "unresolved-operation-456")

    def test_remote_openclaw_mirror_result_uses_json_serializable_path(self):
        self.assertIn('"path": str(db_path)', mirror_cli.REMOTE_RECEIVER)

    def test_remote_plan_poll_is_lightweight_and_fresh_probe_bypasses_openclaw_cache(self):
        plan = {"schemaVersion": 1, "actions": []}
        with tempfile.TemporaryDirectory(prefix="auth-refresh-plan-test-") as tmp:
            plan_path = pathlib.Path(tmp) / "remote-plan.json"

            def fake_ssh(_command, *, stdout, **_kwargs):
                stdout.write(json.dumps(plan))
                return subprocess.CompletedProcess([], 0, "", "")

            with mock.patch.object(maintenance, "REMOTE_PLAN_FILE", plan_path):
                with mock.patch.object(maintenance.subprocess, "run", side_effect=fake_ssh) as run:
                    fetched, _server, _errors, _path = maintenance.fetch_remote_plan()
            remote_command = run.call_args.args[0][-1]
            self.assertTrue(remote_command.endswith("auth-maintenance"), remote_command)
            self.assertEqual(fetched, plan)
            with mock.patch.object(maintenance, "REMOTE_PLAN_FILE", plan_path):
                with mock.patch.object(maintenance.subprocess, "run", side_effect=fake_ssh) as run:
                    fetched, _server, _errors, _path = maintenance.fetch_remote_plan(force_openclaw_probe=True)
            remote_command = run.call_args.args[0][-1]
            self.assertTrue(remote_command.endswith("auth-maintenance --fresh --force-openclaw-probe"), remote_command)
            self.assertEqual(fetched, plan)

    def test_remote_plan_schedule_uses_15_second_request_polls_and_15_minute_fresh_probes(self):
        previous = {
            "remotePlanFetchedAtEpoch": 1000,
            "remoteFreshPlanFetchedAtEpoch": 1000,
        }
        plan = {"schemaVersion": 1, "actions": []}
        self.assertEqual(
            maintenance.remote_plan_fetch_policy(previous, plan, {}, now_epoch=1010),
            (False, False),
        )
        self.assertEqual(
            maintenance.remote_plan_fetch_policy(previous, plan, {}, now_epoch=1015),
            (True, False),
        )
        self.assertEqual(
            maintenance.remote_plan_fetch_policy(previous, plan, {}, now_epoch=1900),
            (True, True),
        )

    def test_server_auth_request_forces_probe_but_respects_retry_backoff(self):
        action = {
            "actionId": "hermers_catbody_token_sync_or_refresh",
            "target": "hermers:catbody",
            "kind": "sync-or-refresh",
            "humanGateRequired": False,
            "localAutomation": {"eligible": True, "owner": "mac-codex", "mode": "access-id-token-mirror"},
        }
        plan = {
            "schemaVersion": 1,
            "macCodexExecutor": {
                "supported": True,
                "refreshOwner": "mac-codex",
                "refreshBrokerEnabled": False,
            },
            "actions": [action],
        }
        previous = {"remotePlanFetchedAtEpoch": 1000, "remoteFreshPlanFetchedAtEpoch": 1000}
        self.assertEqual(
            maintenance.remote_plan_fetch_policy(previous, plan, {}, now_epoch=1010),
            (True, True),
        )
        failed = {
            **previous,
            "lastMirrorAttempt": {
                "result": "failed",
                "refreshConditionKey": maintenance.refresh_condition_key({}),
                "actionIds": [action["actionId"]],
                "attemptedAtEpoch": 1005,
                "retryAfterSeconds": 60,
            },
        }
        self.assertEqual(
            maintenance.remote_plan_fetch_policy(failed, plan, {}, now_epoch=1010),
            (False, False),
        )

    def test_new_action_in_lightweight_fetch_requires_fresh_validation(self):
        plan = {
            "schemaVersion": 1,
            "generatedAtEpochNs": 1_000_000_100,
            "macCodexExecutor": {
                "supported": True,
                "refreshOwner": "mac-codex",
                "refreshBrokerEnabled": False,
            },
            "actions": [{
                "actionId": "openclaw_main_openai_reauth_or_sync",
                "target": "openclaw:main:openai",
                "humanGateRequired": False,
                "localAutomation": {"eligible": True, "owner": "mac-codex", "mode": "access-id-token-mirror"},
            }],
        }
        self.assertTrue(maintenance.latest_plan_has_unvalidated_mac_request(plan, None))
        self.assertFalse(
            maintenance.latest_plan_has_unvalidated_mac_request({**plan, "source": "fresh"}, None)
        )
        success = {
            "postcheckOk": True,
            "remotePlanGeneratedAtEpochNs": plan["generatedAtEpochNs"],
        }
        self.assertFalse(maintenance.latest_plan_has_unvalidated_mac_request(plan, success))

    def test_new_request_does_not_force_probe_during_mirror_backoff(self):
        source = {"accessExpiresAt": "2026-10-09T15:14:22Z", "lastRefresh": "2026-09-29T15:14:22Z"}
        plan = {
            "schemaVersion": 1,
            "macCodexExecutor": {
                "supported": True,
                "refreshOwner": "mac-codex",
                "refreshBrokerEnabled": False,
            },
            "actions": [{
                "actionId": "openclaw_main_openai_reauth_or_sync",
                "target": "openclaw:main:openai",
                "humanGateRequired": False,
                "localAutomation": {"eligible": True, "owner": "mac-codex", "mode": "access-id-token-mirror"},
            }],
        }
        previous = {
            "lastMirrorAttempt": {
                "result": "failed",
                "refreshConditionKey": maintenance.refresh_condition_key(source),
                "actionIds": ["openclaw_main_openai_reauth_or_sync"],
                "attemptedAtEpoch": 1005,
                "retryAfterSeconds": 60,
            }
        }
        self.assertFalse(
            maintenance.latest_plan_has_unvalidated_mac_request(plan, None, previous, source, 1010)
        )
        self.assertFalse(
            maintenance.latest_plan_has_unvalidated_mac_request(plan, None, previous, source, 1064)
        )
        self.assertTrue(
            maintenance.latest_plan_has_unvalidated_mac_request(plan, None, previous, source, 1065)
        )

    def test_openclaw_auth_probe_cache_ttl_accelerates_near_expiry(self):
        now = 1_800_000_000

        def cached_with_remaining(remaining):
            return {
                "available": True,
                "checkedAtEpoch": now,
                "profiles": [{
                    "provider": "openai",
                    "expiresEpoch": now + remaining,
                    "secondsRemaining": remaining,
                }],
            }

        self.assertEqual(
            stabilityd_cli.openclaw_auth_probe_cache_ttl(cached_with_remaining(48 * 3600), now_epoch=now),
            stabilityd_cli.AUTH_OPENCLAW_PROBE_TTL_SECONDS,
        )
        self.assertEqual(
            stabilityd_cli.openclaw_auth_probe_cache_ttl(cached_with_remaining(23 * 3600), now_epoch=now),
            stabilityd_cli.AUTH_OPENCLAW_PROBE_NEAR_TTL_SECONDS,
        )
        self.assertEqual(
            stabilityd_cli.openclaw_auth_probe_cache_ttl(cached_with_remaining(5 * 60), now_epoch=now),
            stabilityd_cli.AUTH_OPENCLAW_PROBE_URGENT_TTL_SECONDS,
        )
        self.assertEqual(
            stabilityd_cli.openclaw_auth_probe_cache_ttl({"available": False}, now_epoch=now),
            stabilityd_cli.AUTH_OPENCLAW_PROBE_ERROR_TTL_SECONDS,
        )
        stale_and_fresh = cached_with_remaining(48 * 3600)
        stale_and_fresh["profiles"].append({
            "provider": "openai",
            "expiresEpoch": now - 60,
            "secondsRemaining": -60,
        })
        stale_and_fresh["profiles"][0]["provider"] = "openai"
        self.assertEqual(
            stabilityd_cli.openclaw_auth_probe_cache_ttl(stale_and_fresh, now_epoch=now),
            stabilityd_cli.AUTH_OPENCLAW_PROBE_TTL_SECONDS,
        )

    def test_cached_openclaw_probe_updates_expiry_countdown_and_due_time(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)")
        now = 1_800_000_000
        stabilityd_cli.db_set(
            conn,
            "auth:openclaw:main",
            {
                "agentId": "main",
                "checkedAtEpoch": now - 5,
                "available": True,
                "profiles": [{"provider": "openai", "expiresEpoch": now + 10, "secondsRemaining": 15}],
            },
        )
        with mock.patch.object(stabilityd_cli, "epoch", return_value=now):
            result = stabilityd_cli.cached_openclaw_auth_probe(conn, "main")
        self.assertTrue(result["cached"])
        self.assertEqual(result["profiles"][0]["secondsRemaining"], 10)
        self.assertEqual(result["cacheTtlSeconds"], stabilityd_cli.AUTH_OPENCLAW_PROBE_URGENT_TTL_SECONDS)
        self.assertEqual(result["nextProbeDueAtEpoch"], now - 5 + result["cacheTtlSeconds"])

    def test_postchecked_snapshot_suppression_allows_a_newer_expiry_request(self):
        action = {"actionId": "openclaw_main_openai_reauth_or_sync", "target": "openclaw:main:openai"}
        selected = [action]
        success = {
            "postcheckOk": True,
            "postcheckStatus": "ok",
            "mirrorCompletedAtEpoch": 1000,
            "remotePlanGeneratedAt": "2026-10-01T10:00:05Z",
            "mirrorActionIds": [action["actionId"]],
            "sourceWide": False,
        }
        old_plan = {"generatedAt": "2026-10-01T10:00:00Z"}
        new_plan = {"generatedAt": "2026-10-01T10:00:30Z"}
        self.assertEqual(
            maintenance.filter_postchecked_mirror_actions(selected, old_plan, success, now_epoch=1010),
            [],
        )
        self.assertEqual(
            maintenance.filter_postchecked_mirror_actions(selected, new_plan, success, now_epoch=1010),
            selected,
        )

    def test_sourcewide_postcheck_suppresses_only_actions_from_that_plan_snapshot(self):
        selected = [
            {"actionId": "hermers_catbody_token_sync_or_refresh", "target": "hermers:catbody"},
            {"actionId": "openclaw_main_openai_reauth_or_sync", "target": "openclaw:main:openai"},
        ]
        success = {
            "postcheckOk": True,
            "mirrorCompletedAtEpoch": 1000,
            "remotePlanGeneratedAt": "2026-10-01T10:00:05Z",
            "sourceWide": True,
            "mirrorScope": {
                "codexCli": True,
                "hermersProfiles": ["catbody"],
                "openclawTargets": [{"agentId": "main", "profileKind": "openai"}],
            },
        }
        old_plan = {"generatedAt": "2026-10-01T10:00:00Z"}
        new_plan = {"generatedAt": "2026-10-01T10:00:30Z"}
        self.assertEqual(
            maintenance.filter_postchecked_mirror_actions(selected, old_plan, success, now_epoch=1010),
            [],
        )
        self.assertEqual(
            maintenance.filter_postchecked_mirror_actions(selected, new_plan, success, now_epoch=1010),
            selected,
        )

    def test_plan_generation_nanoseconds_distinguish_same_second_snapshots(self):
        action = {"actionId": "openclaw_main_openai_reauth_or_sync", "target": "openclaw:main:openai"}
        selected = [action]
        success = {
            "postcheckOk": True,
            "mirrorCompletedAtEpoch": 1000,
            "remotePlanGeneratedAt": "2026-10-01T10:00:00Z",
            "remotePlanGeneratedAtEpochNs": 1_000_000_200,
            "mirrorActionIds": [action["actionId"]],
            "sourceWide": False,
        }
        old_plan = {
            "generatedAt": "2026-10-01T10:00:00Z",
            "generatedAtEpochNs": 1_000_000_100,
        }
        new_plan = {
            "generatedAt": "2026-10-01T10:00:00Z",
            "generatedAtEpochNs": 1_000_000_300,
        }
        self.assertEqual(
            maintenance.filter_postchecked_mirror_actions(selected, old_plan, success, now_epoch=1010),
            [],
        )
        self.assertEqual(
            maintenance.filter_postchecked_mirror_actions(selected, new_plan, success, now_epoch=1010),
            selected,
        )

    def test_mtime_only_change_does_not_trigger_duplicate_mirror_when_expiry_is_known(self):
        self.assertFalse(
            maintenance.source_changed(
                {
                    "accessExpiresAt": "2026-10-09T15:14:22Z",
                    "lastRefresh": "2026-09-29T15:14:22Z",
                    "authMtimeEpoch": 200,
                },
                {
                    "sourceAccessExpiresAt": "2026-10-09T15:14:22Z",
                    "sourceLastRefresh": "2026-09-29T15:14:22Z",
                    "sourceAuthMtimeEpoch": 100,
                },
            )
        )


if __name__ == "__main__":
    unittest.main()
