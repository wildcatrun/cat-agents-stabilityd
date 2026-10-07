import ast
import importlib.util
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compat_verifiers.ast_compat import canonical_ast_dump

from stability_core.action_classes import classify_commands
from stability_core.config import (
    parse_restart_actuator_settings,
    parse_hermers_gateway_restart_limit,
)
from stability_core.protected_scope import is_protected_identity


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "compat" / "cli_policy_golden_v1.json"
RESTART_CONFIG_FIXTURE = ROOT / "tests" / "fixtures" / "compat" / "restart_actuator_config_v1.json"
SPEC = importlib.util.spec_from_file_location("stabilityd_policy_golden_test", ROOT / "bin/cat_agents_stabilityd.py")
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


def project_policy(policy):
    return {
        "directAdmission": policy["direct"]["admission"],
        "directReasons": policy["direct"]["reasons"],
        "heavyReports": policy["controlPlane"]["heavyReports"],
        "deferUntilEpoch": policy["controlPlane"]["deferUntilEpoch"],
        "cronState": policy["domains"]["cron"]["state"],
        "cronAdmission": policy["cron"]["admission"],
        "cronMutateStateAllowed": policy["cron"]["mutateStateAllowed"],
        "cronMaxConcurrency": policy["cron"]["maxConcurrency"],
        "sessionResetAllowed": policy["session"]["resetAllowed"],
        "mainSessionResetAllowed": policy["session"]["mainResetAllowed"],
        "protectedDirectSessionKeys": policy["session"]["protectedDirectSessionKeys"],
    }


def project_decision(policy):
    return {
        "mode": policy["mode"],
        "severity": policy["severity"],
        "restartCandidate": policy["restartCandidate"],
        "restartReason": policy["restartReason"],
        "restartBlockedReasons": policy["restartBlockedReasons"],
        "canRestartGateway": policy["canRestartGateway"],
        "gatewayRestartEnabled": policy["gatewayRestartEnabled"],
        "canMutateCronState": policy["canMutateCronState"],
        "canResetSession": policy["canResetSession"],
        "shouldPauseNonCriticalCron": policy["shouldPauseNonCriticalCron"],
        "deferControlPlaneHeavyReports": policy["deferControlPlaneHeavyReports"],
        "controlPlaneBackpressureUntilEpoch": policy["controlPlaneBackpressureUntilEpoch"],
        "restartStorm": policy["restartStorm"],
        "cooldownUntilEpoch": policy["cooldownUntilEpoch"],
        "policyGrantMarkerPresent": "authorized" in policy or "authorizationGranted" in policy,
    }


class PolicyCliGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = json.loads(FIXTURE.read_text())

    def test_fixed_policy_cases_match_narrow_baseline_projection(self):
        self.assertEqual(self.golden["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        for case in self.golden["cases"]:
            with self.subTest(case=case["name"]):
                values = dict(case["input"])
                findings = []
                severity = values.pop("severity")
                if values["keys"]:
                    for key in values["keys"]:
                        stabilityd.add_finding(findings, key, severity, "fixture", "fixed synthetic baseline case")
                else:
                    stabilityd.add_finding(findings, "fixture_observation", severity, "fixture", "fixed synthetic baseline case")
                    # The neutral marker must not introduce a policy pressure domain.
                    values["keys"] = []
                observed_severity = stabilityd.max_severity(findings)
                lane = stabilityd.build_lane_policy(
                    now_s=values["nowEpoch"], mode=values["mode"], severity=observed_severity,
                    keys=set(values["keys"]), streaks=values["streaks"], gateway=values["gateway"],
                    can_mutate_cron=values["canMutateCron"], can_reset_session=values["canResetSession"],
                    should_pause_cron=values["shouldPauseCron"],
                    should_defer_control_plane_heavy=values["shouldDeferControlPlaneHeavy"],
                    control_plane_defer_until=values["deferUntilEpoch"],
                    restart_storm=values["restartStorm"], cooldown_active=values["cooldownActive"],
                    recovery=values["recovery"],
                )
                self.assertEqual(observed_severity, case["expected"]["findingSeverity"])
                expected_lane = {
                    key: value for key, value in case["expected"].items()
                    if key not in {"findingSeverity", "repairGateStatus", "repairGateReason",
                                   "decisionProjection", "deferUntilEpoch"}
                }
                actual_lane = project_policy(lane)
                self.assertEqual({key: value for key, value in actual_lane.items() if key != "deferUntilEpoch"},
                                 expected_lane)
                self.assertEqual(actual_lane["deferUntilEpoch"], values["deferUntilEpoch"])

    def test_policy_cli_reads_only_patched_published_generation(self):
        for case in self.golden["cases"]:
            with self.subTest(case=case["name"]), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                latest = root / "latest.json"
                policy_path = root / "policy.json"
                latest.write_text(json.dumps({"generationId": "fixture-generation", "severity": "fixture"}))
                policy_path.write_text(json.dumps({"generationId": "fixture-generation", **case["expected"]}))
                output = []
                with mock.patch.object(stabilityd, "LATEST_PATH", latest), \
                     mock.patch.object(stabilityd, "POLICY_PATH", policy_path), \
                     mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0), \
                     mock.patch.object(stabilityd, "init_db", side_effect=AssertionError("read-only CLI opened DB")), \
                     mock.patch.object(stabilityd, "gateway_collect", side_effect=AssertionError("must not probe")):
                    self.assertEqual(stabilityd.main(["policy"]), 0)
                self.assertEqual(output, [{"generationId": "fixture-generation", **case["expected"]}])
                self.assertEqual(sorted(path.name for path in root.iterdir()), ["latest.json", "policy.json"])

    def test_findings_to_policy_decision_uses_frozen_baseline_projection(self):
        for case in self.golden["cases"]:
            with self.subTest(case=case["name"]), sqlite3.connect(":memory:") as conn:
                values = case["input"]
                keys = values["keys"] or ["fixture_observation"]
                findings = [
                    {"key": key, "severity": values["severity"], "component": "fixture",
                     "message": "fixed synthetic baseline case"}
                    for key in keys
                ]
                restart_history = ([1] * stabilityd.MAX_RESTARTS_PER_WINDOW if values["restartStorm"] else [])
                last_restart = values.get("lastGatewayRestartAt", 0)
                def fake_db_get(_conn, key, default=None):
                    if key == "stabilityd_last_gateway_restart_at":
                        return last_restart
                    return default
                with mock.patch.object(stabilityd, "epoch", return_value=values["nowEpoch"]), \
                     mock.patch.object(stabilityd, "ts", return_value="fixture-time"), \
                     mock.patch.object(stabilityd, "db_get", side_effect=fake_db_get), \
                     mock.patch.object(stabilityd, "recent_restart_history", return_value=restart_history), \
                     mock.patch.object(stabilityd, "recent_hermers_gateway_restart_history", return_value=[]), \
                     mock.patch.object(stabilityd, "update_lane_recovery", return_value=values["recovery"]), \
                     mock.patch.object(stabilityd, "GATEWAY_RESTART_ENABLED", values.get("gatewayRestartEnabled", True)):
                    policy = stabilityd.policy_from_findings(
                        conn, findings,
                        {"gateway": values["gateway"], "cron": {"storageStatus": {"storage": "json"}}},
                        values["streaks"],
                    )
                self.assertEqual(policy["mode"], values["mode"])
                self.assertEqual(policy["severity"], case["expected"]["findingSeverity"])
                self.assertEqual(policy["canMutateCronState"], values["canMutateCron"])
                self.assertEqual(policy["canResetSession"], values["canResetSession"])
                self.assertEqual(policy["deferControlPlaneHeavyReports"], values["shouldDeferControlPlaneHeavy"])
                self.assertEqual(project_decision(policy), case["expected"]["decisionProjection"])
                repair_gate = stabilityd.build_repair_gate_from_policy(policy)
                self.assertEqual(repair_gate["status"], case["expected"]["repairGateStatus"])
                self.assertEqual(repair_gate["reason"], case["expected"]["repairGateReason"])
                actual_projection = project_policy(policy["lanes"])
                expected_projection = {
                    key: value for key, value in case["expected"].items()
                    if key not in {"findingSeverity", "repairGateStatus", "repairGateReason", "decisionProjection"}
                }
                expected_projection["deferUntilEpoch"] = case["expected"]["decisionProjection"]["controlPlaneBackpressureUntilEpoch"]
                self.assertEqual(actual_projection, expected_projection)

    def test_protected_and_authorization_boundaries_remain_distinct(self):
        for identity in self.golden["invariants"]["protectedIdentities"]:
            self.assertTrue(is_protected_identity({identity}), identity)
        self.assertFalse(is_protected_identity({"catclaw"}), "retired catclaw alias must not become protected identity")
        unknown = {item["name"]: item for item in classify_commands(["not-a-command"])["commands"]}["not-a-command"]
        self.assertEqual(unknown["authorization"], self.golden["invariants"]["unknownCommandAuthorization"])
        self.assertEqual(unknown["class"], "unknown/prohibited")

    def _restart_policy(self, *, now=10000, last_restart=0, restart_history=None,
                        startup_age=None, action_streak=2, keys=None,
                        hermers_profiles=None, hermers_mode_profiles=None,
                        hermers_streak=2, hermers_restart_limit=2,
                        max_restarts=2, restart_cooldown=1800,
                        restart_window=21600, action_streak_threshold=2,
                        startup_grace_seconds=240):
        conn = stabilityd.init_memory_kv_db()
        for key, value in (
            ("stabilityd_last_gateway_restart_at", last_restart),
            ("stabilityd_last_hermers_gateway_restart_at", 0),
        ):
            conn.execute(
                "INSERT INTO kv(key, value, updated_at) VALUES(?, ?, ?)",
                (key, json.dumps(value), now),
            )
        conn.commit()
        use_hermers = hermers_profiles is not None
        finding_keys = keys or (["hermers_gateway_service_down"] if use_hermers else ["gateway_service_down"])
        findings = [
            {"key": key, "severity": "critical", "component": "fixture", "message": "synthetic"}
            for key in finding_keys
        ]
        gateway = {"active": True, "portOk": True}
        if not use_hermers:
            gateway.update({
                "active": False,
                "portOk": False,
                "startupGraceActive": stabilityd.startup_grace_active(startup_age, startup_grace_seconds),
            })
        snapshot = {
            "gateway": gateway,
            "cron": {"storageStatus": {"storage": "json"}},
        }
        if use_hermers:
            snapshot["hermers"] = {
                "profiles": hermers_profiles,
                "profileModes": {"profiles": hermers_mode_profiles or {}},
            }
        streaks = {
            "gateway_service_down": {"count": action_streak},
            "hermers_gateway_service_down": {"count": hermers_streak},
        }
        def stable_recovery(_conn, _now, _pressures):
            return {"domains": {name: {"healthyStreak": 0} for name in ("cron", "session", "channel", "auth", "hermers", "resource")}}
        history = list(restart_history or [])
        with mock.patch.object(stabilityd, "epoch", return_value=now), \
             mock.patch.object(stabilityd, "ts", return_value="fixture-time"), \
             mock.patch.object(stabilityd, "recent_restart_history", return_value=history), \
             mock.patch.object(stabilityd, "recent_hermers_gateway_restart_history", return_value=[]), \
             mock.patch.object(stabilityd, "update_lane_recovery", side_effect=stable_recovery), \
             mock.patch.multiple(
                 stabilityd,
                 RESTART_COOLDOWN_SECONDS=restart_cooldown,
                 RESTART_WINDOW_SECONDS=restart_window,
                 MAX_RESTARTS_PER_WINDOW=max_restarts,
                 ACTION_STREAK_THRESHOLD=action_streak_threshold,
                 STARTUP_GRACE_SECONDS=startup_grace_seconds,
                 HERMERS_GATEWAY_RESTART_LIMIT=hermers_restart_limit,
                 HERMERS_GATEWAY_RESTART_ENABLED=True,
                 GATEWAY_RESTART_ENABLED=True,
                 GATEWAY_RESTART_ACTUATOR_SUPPORTED=True,
                 SOFT_GATEWAY_RESTART_ENABLED=False,
                 SOFT_RESCUE_RESTART_ENABLED=False,
             ):
            policy = stabilityd.policy_from_findings(conn, findings, snapshot, streaks)
        conn.close()
        return policy

    def test_restart_policy_decision_threshold_boundaries(self):
        cases = [
            {
                "name": "cooldown-one-second-before-expiry",
                "kwargs": {"last_restart": 8201},
                "expected": {"mode": "cooldown", "restartCandidate": True,
                             "restartBlockedReasons": ["cooldown"], "canRestartGateway": False,
                             "restartStorm": False, "cooldownUntilEpoch": 10001},
            },
            {
                "name": "cooldown-at-expiry-boundary",
                "kwargs": {"last_restart": 8200},
                "expected": {"mode": "gateway-unreachable", "restartCandidate": True,
                             "restartBlockedReasons": [], "canRestartGateway": True,
                             "restartStorm": False, "cooldownUntilEpoch": 0},
            },
            {
                "name": "restart-storm-one-below-limit",
                "kwargs": {"restart_history": [9999]},
                "expected": {"mode": "gateway-unreachable", "restartCandidate": True,
                             "restartBlockedReasons": [], "canRestartGateway": True,
                             "restartStorm": False, "recentRestartCount": 1},
            },
            {
                "name": "restart-storm-at-limit",
                "kwargs": {"restart_history": [9998, 9999]},
                "expected": {"mode": "restart-storm", "restartCandidate": True,
                             "restartBlockedReasons": ["restart-storm"], "canRestartGateway": False,
                             "restartStorm": True, "recentRestartCount": 2},
            },
            {
                "name": "restart-window-controls-storm-clear-time",
                "kwargs": {"restart_history": [9700, 9800], "restart_window": 500},
                "expected": {"restartStorm": True, "restartWindowSeconds": 500,
                             "restartStormClearsAtEpoch": 10200},
            },
            {
                "name": "action-streak-one-below-threshold",
                "kwargs": {"action_streak": 1},
                "expected": {"mode": "gateway-unreachable", "restartCandidate": False,
                             "restartReason": "no-actionable-streak", "restartBlockedReasons": [],
                             "canRestartGateway": False},
            },
            {
                "name": "action-streak-at-threshold",
                "kwargs": {"action_streak": 2},
                "expected": {"mode": "gateway-unreachable", "restartCandidate": True,
                             "restartReason": "gateway-basic-health-failed", "restartBlockedReasons": [],
                             "canRestartGateway": True},
            },
            {
                "name": "startup-grace-one-second-below-boundary",
                "kwargs": {"startup_age": 239},
                "expected": {"mode": "gateway-unreachable", "restartCandidate": True,
                             "restartBlockedReasons": ["startup-grace"], "canRestartGateway": False},
            },
            {
                "name": "startup-grace-at-boundary",
                "kwargs": {"startup_age": 240},
                "expected": {"mode": "gateway-unreachable", "restartCandidate": True,
                             "restartBlockedReasons": [], "canRestartGateway": True},
            },
        ]
        for case in cases:
            with self.subTest(case=case["name"]):
                policy = self._restart_policy(**case["kwargs"])
                observed = {key: policy[key] for key in case["expected"]}
                self.assertEqual(observed, case["expected"])

    def test_environment_overrides_flow_to_gateway_restart_decisions(self):
        environment = {
            "OPENCLAW_STABILITY_RESTART_COOLDOWN_SECONDS": "90",
            "OPENCLAW_STABILITY_RESTART_WINDOW_SECONDS": "7777",
            "OPENCLAW_STABILITY_MAX_RESTARTS": "5",
            "OPENCLAW_STABILITY_ACTION_STREAK": "4",
            "OPENCLAW_STABILITY_STARTUP_GRACE_SECONDS": "333",
            "CAT_AGENTS_STABILITY_HERMERS_GATEWAY_RESTART_LIMIT": "3",
        }
        settings = parse_restart_actuator_settings(environment)
        settings["HERMERS_GATEWAY_RESTART_LIMIT"] = parse_hermers_gateway_restart_limit(
            environment, settings["MAX_RESTARTS_PER_WINDOW"]
        )
        cases = [
            {
                "name": "startup-grace-override-blocks-one-second-below",
                "kwargs": {"startup_age": 332, "action_streak": 4},
                "expected": {"restartCandidate": True, "restartBlockedReasons": ["startup-grace"],
                             "canRestartGateway": False},
            },
            {
                "name": "cooldown-override-blocks-one-second-before-expiry",
                "kwargs": {"last_restart": 9911, "startup_age": 333, "action_streak": 4},
                "expected": {"restartCandidate": True, "restartBlockedReasons": ["cooldown"],
                             "canRestartGateway": False, "cooldownUntilEpoch": 10001},
            },
            {
                "name": "overrides-at-cooldown-and-grace-boundaries-allow-candidate",
                "kwargs": {"last_restart": 9910, "startup_age": 333, "action_streak": 4},
                "expected": {"restartCandidate": True, "restartBlockedReasons": [],
                             "canRestartGateway": True, "cooldownUntilEpoch": 0},
            },
        ]
        for case in cases:
            with self.subTest(case=case["name"]):
                policy = self._restart_policy(
                    **case["kwargs"],
                    restart_cooldown=settings["RESTART_COOLDOWN_SECONDS"],
                    restart_window=settings["RESTART_WINDOW_SECONDS"],
                    max_restarts=settings["MAX_RESTARTS_PER_WINDOW"],
                    action_streak_threshold=settings["ACTION_STREAK_THRESHOLD"],
                    startup_grace_seconds=settings["STARTUP_GRACE_SECONDS"],
                    hermers_restart_limit=settings["HERMERS_GATEWAY_RESTART_LIMIT"],
                )
                observed = {key: policy[key] for key in case["expected"]}
                self.assertEqual(observed, case["expected"])
                self.assertEqual(policy["restartWindowSeconds"], settings["RESTART_WINDOW_SECONDS"])
                self.assertEqual(policy["maxRestarts"], settings["MAX_RESTARTS_PER_WINDOW"])

    def test_restart_window_override_filters_pinned_history_at_inclusive_cutoff(self):
        config_fixture = json.loads(RESTART_CONFIG_FIXTURE.read_text(encoding="utf-8"))
        daemon_tree = ast.parse((ROOT / "bin/cat_agents_stabilityd.py").read_text(encoding="utf-8"))
        functions = [
            node for node in daemon_tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "recent_restart_history"
        ]
        self.assertEqual(len(functions), 1)
        current_hash = hashlib.sha256(
            canonical_ast_dump(functions[0]).encode("utf-8")
        ).hexdigest()
        self.assertEqual(current_hash, config_fixture["recentRestartHistoryFunctionSha256"])

        conn = stabilityd.init_memory_kv_db()
        with mock.patch.object(stabilityd, "epoch", return_value=10000), \
             mock.patch.object(stabilityd, "RESTART_WINDOW_SECONDS", 500):
            stabilityd.db_set(conn, "stabilityd_gateway_restart_history", [9499, 9500, 9501, 9999])
            self.assertEqual(stabilityd.recent_restart_history(conn), [9500, 9501, 9999])
        conn.close()

    def test_hermers_restart_limit_inheritance_and_explicit_override_boundaries(self):
        profiles = {
            "cat_body": {"active": False},
            "cat_ears": {"active": False},
            "cat_nose": {"active": False},
        }
        profile_modes = {profile: {"expectedActive": True} for profile in profiles}
        limits = [
            ("inherited", {"OPENCLAW_STABILITY_MAX_RESTARTS": "3"}, 3),
            ("explicit", {
                "OPENCLAW_STABILITY_MAX_RESTARTS": "3",
                "CAT_AGENTS_STABILITY_HERMERS_GATEWAY_RESTART_LIMIT": "1",
            }, 1),
        ]
        for name, environment, expected_limit in limits:
            with self.subTest(case=name):
                parsed = parse_restart_actuator_settings(environment)
                parsed["HERMERS_GATEWAY_RESTART_LIMIT"] = parse_hermers_gateway_restart_limit(
                    environment, parsed["MAX_RESTARTS_PER_WINDOW"]
                )
                self.assertEqual(parsed["HERMERS_GATEWAY_RESTART_LIMIT"], expected_limit)
                policy = self._restart_policy(
                    hermers_profiles=profiles,
                    hermers_mode_profiles=profile_modes,
                    hermers_streak=2,
                    hermers_restart_limit=parsed["HERMERS_GATEWAY_RESTART_LIMIT"],
                    max_restarts=parsed["MAX_RESTARTS_PER_WINDOW"],
                )
                self.assertTrue(policy["hermersGatewayRestartCandidate"])
                self.assertTrue(policy["canRestartHermersGateway"])
                self.assertEqual(policy["hermersGatewayRestartLimit"], expected_limit)
                self.assertEqual(
                    [item["profile"] for item in policy["hermersGatewayRestartProfiles"]],
                    sorted(profiles)[:expected_limit],
                )


if __name__ == "__main__":
    unittest.main()
