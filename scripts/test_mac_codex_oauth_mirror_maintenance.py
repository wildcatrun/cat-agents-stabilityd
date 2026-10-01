#!/usr/bin/env python3
"""Focused tests for the local Codex refresh/mirror decision rules."""

import pathlib
import subprocess
import sys
import unittest
import datetime as dt
import tempfile
import json
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mac_codex_oauth_mirror_maintenance as maintenance
import mac_codex_oauth_mirror as mirror_cli


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
            maintenance.run_mirror(["hermers_catbody_token_sync"], scope)
        command = run.call_args.args[0]
        self.assertIn("--no-codex-cli", command)
        self.assertIn("--hermers-profiles", command)
        self.assertIn("catbody", command)
        self.assertIn("--openclaw-targets", command)
        self.assertIn("main:openai,cat_claw:openai-codex", command)
        self.assertNotIn("--openclaw-agents", command)

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
                self._assert_unavailable_postcheck_state()

    def _assert_unavailable_postcheck_state(self):
        source = {"accessExpiresAt": "2026-10-09T15:14:22Z", "lastRefresh": "2026-09-29T15:14:22Z"}
        actions = [{"actionId": "source-generation", "localSourceChange": True}]
        mirror = {
            "result": "applied",
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

    def test_remote_plan_fetch_bypasses_openclaw_auth_probe_cache(self):
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
            self.assertTrue(remote_command.endswith("auth-maintenance --fresh --force-openclaw-probe"), remote_command)
            self.assertEqual(fetched, plan)

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
