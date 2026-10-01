#!/usr/bin/env python3
"""Smoke checks for OAuth/auth readiness metadata probes."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock


def make_jwt(exp: int, iat: int | None = None) -> str:
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "iss": "https://auth.openai.com",
        "aud": ["https://api.openai.com/v1"],
        "iat": iat or int(time.time()),
        "exp": exp,
    }

    def enc(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{enc(header)}.{enc(payload)}."


def load_stabilityd(tmp: str):
    os.environ["OPENCLAW_HOME_DIR"] = tmp
    os.environ["CAT_AGENTS_WORKFLOW_DB"] = str(Path(tmp) / "missing-tracking.db")
    os.environ["CAT_AGENTS_STABILITY_AUTH_OPENCLAW_AGENT_IDS"] = "main"
    module_path = Path(__file__).resolve().parents[1] / "bin" / "cat_agents_stabilityd.py"
    spec = importlib.util.spec_from_file_location("cat_agents_stabilityd_auth_smoke", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    now = int(time.time())
    with tempfile.TemporaryDirectory(prefix="cat-stability-auth-") as tmp:
        home = Path(tmp)
        codex_dir = home / ".codex"
        hermers_profile = home / ".hermes" / "profiles" / "catbody"
        codex_dir.mkdir(parents=True)
        hermers_profile.mkdir(parents=True)
        (codex_dir / "auth.json").write_text(
            json.dumps(
                {
                    "auth_mode": "chatgpt",
                    "tokens": {
                        "access_token": make_jwt(now - 60),
                        "refresh_token": "refresh-redacted",
                    },
                }
            ),
            encoding="utf-8",
        )
        (hermers_profile / "auth.json").write_text(
            json.dumps(
                {
                    "active_provider": "openai-codex",
                    "providers": {
                        "openai-codex": {
                            "tokens": {
                                "access_token": make_jwt(now + 7200),
                                "refresh_token": "refresh-redacted",
                            }
                        }
                    },
                    "credential_pool": {
                        "openai-codex": [
                            {
                                "access_token": make_jwt(now - 3600),
                                "refresh_token": "old-refresh-redacted",
                            }
                        ]
                    },
                }
            ),
            encoding="utf-8",
        )
        extra_hermers_profile = home / ".hermes" / "profiles" / "catheart"
        extra_hermers_profile.mkdir(parents=True)
        (extra_hermers_profile / "auth.json").write_text(
            json.dumps(
                {
                    "active_provider": "openai-codex",
                    "providers": {
                        "openai-codex": {
                            "tokens": {
                                "access_token": make_jwt(now + 7200),
                                "refresh_token": "refresh-redacted",
                            }
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        stabilityd = load_stabilityd(tmp)
        codex_summary = stabilityd.summarize_auth_json(stabilityd.CODEX_AUTH_PATH)
        assert codex_summary["hasRefreshToken"] is True, codex_summary
        assert codex_summary["freshestAccessTokenSecondsRemaining"] <= 0, codex_summary
        assert stabilityd.auth_token_status(codex_summary) == "access-expired", codex_summary
        redacted = stabilityd.redact_auth_text("access_token=abc refresh_token: def api_key=ghi secret:jkl token=mno")
        assert "abc" not in redacted and "def" not in redacted and "ghi" not in redacted, redacted
        lanes = stabilityd.build_lane_policy(
            now_s=stabilityd.epoch(),
            mode="healthy",
            severity="info",
            keys={"cron_long_running_jobs"},
            streaks={},
            gateway={"active": True, "portOk": True},
            can_mutate_cron=False,
            can_reset_session=False,
            should_pause_cron=False,
            should_defer_control_plane_heavy=False,
            control_plane_defer_until=0,
            restart_storm=False,
            cooldown_active=False,
            recovery={},
        )
        assert lanes["primaryPressureDomains"]["auth"] is False, lanes

        parsed = stabilityd.parse_openclaw_auth_list(
            "- openai-codex:account@example.com (account@example.com) [openai-codex/oauth; expires 1970-01-01T00:00:00.000Z; cooldown until 2026-06-21T15:50:35.149Z]\n",
            "main",
        )
        assert parsed["profileCount"] == 1, parsed
        assert parsed["profiles"][0]["profileLabel"] == "openai-codex:[redacted]", parsed
        assert parsed["profiles"][0]["secondsRemaining"] < 0, parsed
        variant = stabilityd.parse_openclaw_auth_list(
            "- openai-codex:account@example.com [openai-codex/oauth; EXPIRES AT: 1970-01-01T00:00:00.000Z]\n"
            "- malformed oauth line without bracket\n",
            "main",
        )
        assert variant["profileCount"] == 1, variant
        assert variant["profiles"][0]["expiryParseOk"] is True, variant
        assert variant["unparsedProfileLineCount"] == 1, variant

        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)")
        conn.execute(
            "CREATE TABLE actions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, action_id TEXT, action TEXT, result TEXT, payload TEXT NOT NULL)"
        )
        conn.commit()
        stabilityd.db_set(
            conn,
            "auth:openclaw:main",
            {"agentId": "main", "checkedAtEpoch": stabilityd.epoch(), "available": True, "profiles": []},
        )
        with mock.patch.object(
            stabilityd,
            "run_cmd",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ) as fresh_probe_call:
            forced_probe = stabilityd.cached_openclaw_auth_probe(conn, "main", force=True)
        assert forced_probe["cached"] is False, forced_probe
        fresh_probe_call.assert_called_once()

        def fake_openclaw_probe(_conn, agent_id: str, **_kwargs):
            return {
                "agentId": agent_id,
                "available": True,
                "cached": False,
                "profiles": [*parsed["profiles"], dict(parsed["profiles"][0])],
                "profileCount": 2,
            }

        stabilityd.workflow_runtime_registry_records = lambda: {
            "source": "test",
            "dbFile": "",
            "records": [
                {
                    "agent_id": "catbody",
                    "runtime": "hermes_acp",
                    "platform": "hermers",
                    "status": "active",
                    "can_receive_dispatch": 1,
                    "endpoint_ref": "hermers-profile:catbody",
                },
                {
                    "agent_id": "cat_heart",
                    "runtime": "hermes_acp",
                    "platform": "hermers",
                    "status": "active",
                    "can_receive_dispatch": 1,
                    "endpoint_ref": "hermers-profile:catheart",
                },
                {
                    "agent_id": "main",
                    "runtime": "openclaw",
                    "platform": "openclaw",
                    "status": "active",
                    "can_receive_dispatch": 1,
                    "endpoint_ref": "openclaw-agent:main",
                },
                {
                    "agent_id": "cat_claw",
                    "runtime": "openclaw",
                    "platform": "openclaw",
                    "status": "active",
                    "can_receive_dispatch": 1,
                    "endpoint_ref": "openclaw-agent:cat_claw",
                },
                {"agent_id": "cat_brain", "runtime": "openclaw", "platform": "openclaw", "status": "active", "can_receive_dispatch": 1},
                {"agent_id": "openclaw:cat_claw", "runtime": "openclaw", "platform": "openclaw", "status": "active", "can_receive_dispatch": 1},
                {
                    "agent_id": "legacy_route",
                    "runtime": "openclaw",
                    "platform": "openclaw",
                    "execution_adapter": "openclaw_route_shell",
                    "status": "active",
                    "can_receive_dispatch": 1,
                },
            ],
        }

        openai_only_profile = dict(parsed["profiles"][0])
        openai_only_profile["provider"] = "openai"
        openai_only_profile["profileKind"] = "openai"
        stabilityd.cached_openclaw_auth_probe = lambda _conn, agent_id, **_kwargs: {
            "agentId": agent_id,
            "available": True,
            "cached": False,
            "profiles": [openai_only_profile],
            "profileCount": 1,
        }
        openai_only_findings = []
        stabilityd.auth_collect(conn, openai_only_findings, ["catbody"])
        assert "openclaw_oauth_required_provider_missing" not in {item["key"] for item in openai_only_findings}, openai_only_findings

        stabilityd.cached_openclaw_auth_probe = fake_openclaw_probe
        findings = []
        auth = stabilityd.auth_collect(conn, findings, ["catbody"])
        keys = {item["key"] for item in findings}
        assert auth["codexCli"]["exists"] is True, auth
        assert "codex_cli_oauth_access_expired" in keys, findings
        assert "hermers_oauth_token_copy_drift" in keys, findings
        assert "openclaw_oauth_profile_expired" in keys, findings
        assert "openai" in stabilityd.AUTH_OPENCLAW_REQUIRED_PROVIDER_IDS, stabilityd.AUTH_OPENCLAW_REQUIRED_PROVIDER_IDS
        assert stabilityd.openclaw_required_provider_present({"openai-codex"}, {"openai"}) is True
        assert stabilityd.openclaw_required_provider_present({"openai-codex"}, {"anthropic"}) is False
        plan = stabilityd.build_auth_maintenance_plan(auth, findings)
        action_ids = {item["actionId"] for item in plan["actions"]}
        assert plan["status"] == "action-required", plan
        assert plan["tokenValuesRedacted"] is True, plan
        assert plan["macCodexExecutor"]["supported"] is True, plan
        assert plan["macCodexExecutor"]["refreshBrokerEnabled"] is False, plan
        assert plan["macCodexExecutor"]["targets"]["codexCli"] is True, plan
        assert plan["macCodexExecutor"]["targets"]["hermersProfiles"] == ["catbody", "catheart"], plan
        assert plan["macCodexExecutor"]["targets"]["openclawTargets"] == [
            {"agentId": "cat_claw", "profileKind": "openai-codex"},
            {"agentId": "main", "profileKind": "openai-codex"},
        ], plan
        assert plan["humanGateActionCount"] == 0, plan
        assert auth["openclaw"]["scopeComplete"] is True, auth
        assert auth["openclaw"]["registryAgentIds"] == ["main", "cat_claw"], auth
        assert {item["agentId"] for item in auth["openclaw"]["unaddressableRegistryRows"]} == {
            "cat_brain", "openclaw:cat_claw"
        }, auth
        assert {
            item["agentId"]
            for item in plan["macCodexExecutor"]["scopeWarnings"]["openclawUnaddressableRegistryRows"]
        } == {"cat_brain", "openclaw:cat_claw"}, plan
        limited_findings = []
        with mock.patch.object(stabilityd, "AUTH_OPENCLAW_AGENT_LIMIT", 1):
            limited_auth = stabilityd.auth_collect(conn, limited_findings, ["catbody"])
        assert limited_auth["openclaw"]["scopeComplete"] is False, limited_auth
        assert limited_auth["openclaw"]["omittedAgentIds"] == ["cat_claw"], limited_auth
        limited_plan = stabilityd.build_auth_maintenance_plan(limited_auth, limited_findings)
        assert any(
            item["actionId"] == "openclaw_registry_auth_scope_incomplete" and item["humanGateRequired"]
            for item in limited_plan["actions"]
        ), limited_plan
        malformed_registry = {
            "source": "test",
            "dbFile": "",
            "records": [
                {
                    "agent_id": "catbody",
                    "runtime": "hermes_acp",
                    "platform": "hermers",
                    "status": "active",
                    "can_receive_dispatch": 1,
                    "endpoint_ref": "hermers-profile:catbody",
                },
                {
                    "agent_id": "cat_heart",
                    "runtime": "hermes_acp",
                    "platform": "hermers",
                    "status": "active",
                    "can_receive_dispatch": 1,
                    "endpoint_ref": "hermers-profile:",
                },
                {
                    "agent_id": "old_route",
                    "runtime": "openclaw_route_shell",
                    "platform": "openclaw_route_shell",
                    "status": "active",
                    "can_receive_dispatch": 1,
                    "endpoint_ref": "hermers-profile:oldroute",
                },
                {
                    "agent_id": "main",
                    "runtime": "openclaw",
                    "platform": "openclaw",
                    "status": "active",
                    "can_receive_dispatch": 1,
                    "endpoint_ref": "openclaw-agent:main",
                },
            ],
        }
        malformed_registry_findings = []
        with mock.patch.object(stabilityd, "workflow_runtime_registry_records", return_value=malformed_registry):
            malformed_registry_auth = stabilityd.auth_collect(conn, malformed_registry_findings)
        assert malformed_registry_auth["hermers"]["scopeComplete"] is False, malformed_registry_auth
        assert malformed_registry_auth["hermers"]["registryAgentProfiles"] == ["catbody"], malformed_registry_auth
        malformed_registry_plan = stabilityd.build_auth_maintenance_plan(
            malformed_registry_auth, malformed_registry_findings
        )
        assert any(
            item["actionId"] == "hermers_runtime_profile_registry_unavailable" and item["humanGateRequired"]
            for item in malformed_registry_plan["actions"]
        ), malformed_registry_plan
        assert "codex_cli_mirror_required" in action_ids, plan
        assert "openclaw_main_openai-codex_reauth_or_sync" in action_ids, plan
        assert "openclaw_main_openai-codex_reauth_or_sync-2" not in action_ids, plan
        assert "hermers_token_copy_drift_cleanup" in action_ids, plan
        codex_mirror = next(item for item in plan["actions"] if item["actionId"] == "codex_cli_mirror_required")
        assert codex_mirror["kind"] == "mirror-from-mac-codex", codex_mirror
        assert codex_mirror["canAutoRun"] is False, codex_mirror
        assert codex_mirror["blockedReason"] == "delegated-to-mac-codex", codex_mirror
        assert codex_mirror["localAutomation"] == {
            "eligible": True,
            "owner": "mac-codex",
            "mode": "access-id-token-mirror",
        }, codex_mirror
        openclaw_sync = next(
            item for item in plan["actions"]
            if item["actionId"] == "openclaw_main_openai-codex_reauth_or_sync"
        )
        assert openclaw_sync["humanGateRequired"] is False, openclaw_sync
        assert openclaw_sync["localAutomation"]["eligible"] is True, openclaw_sync

        expanded_plan = stabilityd.build_auth_maintenance_plan(
            {
                "codexCli": {"exists": True},
                "hermers": {
                    "profiles": {
                        "catbody": {"activeProvider": "openai-codex"},
                        "custom_profile": {"activeProvider": "openai"},
                        "other_profile": {"activeProvider": "anthropic"},
                    }
                },
                "openclaw": {
                    "agents": {
                        "main": {"available": True, "profiles": [{"provider": "openai"}]},
                        "cat_claw": {"available": True, "profiles": [{"provider": "openai-codex"}]},
                    }
                },
            },
            [],
        )
        assert expanded_plan["macCodexExecutor"]["targets"] == {
            "codexCli": True,
            "hermersProfiles": ["catbody", "custom_profile"],
            "openclawTargets": [
                {"agentId": "cat_claw", "profileKind": "openai-codex"},
                {"agentId": "main", "profileKind": "openai"},
            ],
        }, expanded_plan

        incomplete_scope_plan = stabilityd.build_auth_maintenance_plan(
            {
                "codexCli": {"exists": True},
                "hermers": {
                    "profiles": {},
                    "profileRegistry": {"available": False, "reason": "registry unavailable"},
                    "scopeComplete": False,
                    "registryAgentProfiles": [],
                },
                "openclaw": {
                    "agents": {},
                    "scopeComplete": False,
                    "registryAgentIds": ["main", "cat_claw"],
                    "probeAgentIds": ["main"],
                    "omittedAgentIds": ["cat_claw"],
                },
            },
            [],
        )
        gate_targets = {
            item["target"] for item in incomplete_scope_plan["actions"] if item["humanGateRequired"]
        }
        assert "openclaw:runtime-registry-scope" in gate_targets, incomplete_scope_plan
        assert "hermers:runtime-registry" in gate_targets, incomplete_scope_plan

        dry_run = stabilityd.execute_auth_maintenance_plan(
            conn,
            plan,
            action_id="codex_cli_mirror_required",
            dry_run=True,
            allow_mirror=True,
        )
        assert dry_run["dryRun"] is True, dry_run
        assert dry_run["executions"][0]["result"] == "dry_run", dry_run
        assert dry_run["executions"][0]["wouldRun"] is False, dry_run
        assert dry_run["executions"][0]["delegatedToMacCodex"] is True, dry_run
        blocked_run = stabilityd.execute_auth_maintenance_plan(
            conn,
            plan,
            action_id="codex_cli_mirror_required",
            dry_run=False,
            allow_mirror=True,
        )
        assert blocked_run["executions"][0]["result"] == "blocked", blocked_run
        assert blocked_run["executions"][0]["blockedReason"] == "mac-codex-local-executor-required", blocked_run
        assert blocked_run["executions"][0]["delegatedToMacCodex"] is True, blocked_run
        with mock.patch.object(stabilityd.platform, "system", return_value="Linux"):
            server_mirror = stabilityd.run_mac_codex_oauth_mirror(apply=True)
        assert server_mirror["result"] == "blocked", server_mirror
        assert server_mirror["blockedReason"] == "mac-codex-refresh-owner-host-required", server_mirror
        gated_plan = {
            "actions": [
                {
                    "actionId": "openclaw_main_openai-codex_reauth_or_sync",
                    "target": "openclaw:main:openai-codex",
                    "kind": "reauth-or-sync",
                    "humanGateRequired": True,
                    "tokenValuesRedacted": True,
                }
            ]
        }
        gated_run = stabilityd.execute_auth_maintenance_plan(
            conn,
            gated_plan,
            action_id="openclaw_main_openai-codex_reauth_or_sync",
            dry_run=False,
            allow_mirror=True,
        )
        assert gated_run["executions"][0]["result"] == "blocked", gated_run
        assert gated_run["executions"][0]["blockedReason"] == "human-gate-required", gated_run
        redacted = stabilityd.redact_auth_text('{"accessToken":"secret-a","refreshToken":"secret-r","idToken":"secret-i"}')
        assert "secret-a" not in redacted and "secret-r" not in redacted and "secret-i" not in redacted, redacted

        mirror_script = Path(__file__).resolve().parent / "mac_codex_oauth_mirror.py"
        mirror_spec = importlib.util.spec_from_file_location("mac_codex_oauth_mirror_smoke", mirror_script)
        assert mirror_spec is not None and mirror_spec.loader is not None
        mirror_module = importlib.util.module_from_spec(mirror_spec)
        mirror_spec.loader.exec_module(mirror_module)
        compile(mirror_module.REMOTE_RECEIVER, "remote_mac_codex_oauth_mirror_receiver", "exec")
        assert mirror_module.parse_openclaw_targets("main:openai,cat_claw:openai-codex") == [
            {"agentId": "main", "profileKind": "openai"},
            {"agentId": "cat_claw", "profileKind": "openai-codex"},
        ]
        try:
            mirror_module.parse_openclaw_targets("../../.codex:openai")
            raise AssertionError("unsafe OpenClaw target should be rejected")
        except SystemExit:
            pass
        fake_source_auth = Path(tmp) / "source-auth.json"
        future_exp = now + 7 * 86400
        fake_source_auth.write_text(
            json.dumps(
                {
                    "auth_mode": "chatgpt",
                    "tokens": {
                        "access_token": make_jwt(future_exp),
                        "id_token": make_jwt(future_exp),
                        "refresh_token": "local-refresh-owner",
                    },
                }
            ),
            encoding="utf-8",
        )
        preflight = subprocess.run(
            [sys.executable, str(mirror_script), "--codex-auth", str(fake_source_auth), "--server", "should-not-connect.invalid"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert preflight.returncode == 0, preflight.stderr
        preflight_json = json.loads(preflight.stdout)
        assert preflight_json["status"] == "preflight-ok", preflight_json
        assert preflight_json["idTokenFresh"] is True, preflight_json

        expired_id_source_auth = Path(tmp) / "expired-id-source-auth.json"
        expired_id_source_auth.write_text(
            json.dumps(
                {
                    "auth_mode": "chatgpt",
                    "tokens": {
                        "access_token": make_jwt(future_exp),
                        "id_token": make_jwt(now - 60),
                        "refresh_token": "local-refresh-owner",
                    },
                }
            ),
            encoding="utf-8",
        )
        expired_id_preflight = subprocess.run(
            [sys.executable, str(mirror_script), "--codex-auth", str(expired_id_source_auth), "--local-preflight"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert expired_id_preflight.returncode == 0, expired_id_preflight.stderr
        expired_id_json = json.loads(expired_id_preflight.stdout)
        assert expired_id_json["status"] == "preflight-ok", expired_id_json
        assert expired_id_json["idTokenFresh"] is False, expired_id_json
        dummy_source_auth = Path(tmp) / "dummy-source-auth.json"
        dummy_source_auth.write_text(
            json.dumps(
                {
                    "auth_mode": "chatgpt",
                    "tokens": {
                        "access_token": make_jwt(future_exp),
                        "id_token": make_jwt(future_exp),
                        "refresh_token": "MAC_CODEX_BROKER_REFRESH_DISABLED",
                    },
                }
            ),
            encoding="utf-8",
        )
        dummy_preflight = subprocess.run(
            [sys.executable, str(mirror_script), "--codex-auth", str(dummy_source_auth), "--local-preflight"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert dummy_preflight.returncode != 0, dummy_preflight.stdout
        assert "mirror refresh placeholder" in dummy_preflight.stderr, dummy_preflight.stderr

        stabilityd.AUTH_OPENCLAW_REQUIRED_PROVIDER_IDS = {"anthropic"}
        findings = []
        missing_required_auth = stabilityd.auth_collect(conn, findings, ["catbody"])
        keys = {item["key"] for item in findings}
        assert "openclaw_oauth_required_provider_missing" in keys, findings
        missing_required_plan = stabilityd.build_auth_maintenance_plan(missing_required_auth, findings)
        assert "openclaw_main_required_provider_reauth" in {item["actionId"] for item in missing_required_plan["actions"]}, missing_required_plan

        fresh_parsed = stabilityd.parse_openclaw_auth_list(
            "- openai:account@example.com [openai/oauth; expires 1970-01-01T00:00:00.000Z]\n"
            f"- openai:account@example.com [openai/oauth; expires {time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(now + 7 * 86400))}]\n"
            f"- openai-codex:account@example.com [openai-codex/oauth; expires {time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(now + 7 * 86400))}]\n",
            "main",
        )

        def fake_openclaw_fresh_probe(_conn, agent_id: str, **_kwargs):
            return {
                "agentId": agent_id,
                "available": True,
                "cached": False,
                "profiles": fresh_parsed["profiles"],
                "profileCount": len(fresh_parsed["profiles"]),
            }

        stabilityd.cached_openclaw_auth_probe = fake_openclaw_fresh_probe
        stabilityd.AUTH_OPENCLAW_REQUIRED_PROVIDER_IDS = {"openai-codex"}
        findings = []
        fresh_auth = stabilityd.auth_collect(conn, findings, ["catbody"])
        keys = {item["key"] for item in findings}
        assert "openclaw_oauth_profile_expired" not in keys, findings
        assert "openclaw_oauth_stale_profile_copies" in keys, findings
        fresh_plan = stabilityd.build_auth_maintenance_plan(fresh_auth, findings)
        assert not any(str(item["actionId"]).startswith("openclaw_main_openai") for item in fresh_plan["actions"]), fresh_plan
        stale_only_findings = [item for item in findings if item["key"] == "openclaw_oauth_stale_profile_copies"]
        stale_only_policy = stabilityd.policy_from_findings(conn, stale_only_findings, {}, {})
        assert stale_only_policy["lanes"]["primaryPressureDomains"]["auth"] is False, stale_only_policy
        assert stale_only_policy["lanes"]["domains"]["auth"]["pressure"] is False, stale_only_policy
        info_only_policy = stabilityd.policy_from_findings(
            conn,
            [{"key": "session_stale_entries", "severity": "info", "component": "session", "message": "observed only"}],
            {},
            {},
        )
        assert info_only_policy["severity"] == "info", info_only_policy
        assert info_only_policy["mode"] == "healthy", info_only_policy

        old_system_swap_warn_bytes = stabilityd.SYSTEM_SWAP_WARN_BYTES
        old_system_swap_crit_bytes = stabilityd.SYSTEM_SWAP_CRIT_BYTES
        old_system_swap_warn_ratio = stabilityd.SYSTEM_SWAP_WARN_RATIO
        old_system_swap_crit_ratio = stabilityd.SYSTEM_SWAP_CRIT_RATIO
        try:
            stabilityd.SYSTEM_SWAP_WARN_BYTES = 0
            stabilityd.SYSTEM_SWAP_CRIT_BYTES = 0
            stabilityd.SYSTEM_SWAP_WARN_RATIO = 0.70
            stabilityd.SYSTEM_SWAP_CRIT_RATIO = 0.90
            assert stabilityd.system_swap_pressure_level(3_800_000_000, 8_589_930_496) == ""
            assert stabilityd.system_swap_pressure_level(6_200_000_000, 8_589_930_496) == "high"
            assert stabilityd.system_swap_pressure_level(7_800_000_000, 8_589_930_496) == "critical"
            stabilityd.SYSTEM_SWAP_CRIT_BYTES = 7_200_000_000
            assert stabilityd.system_swap_pressure_level(3_800_000_000, 8_589_930_496) == ""
            assert stabilityd.system_swap_pressure_level(7_300_000_000, 8_589_930_496) == "critical"
        finally:
            stabilityd.SYSTEM_SWAP_WARN_BYTES = old_system_swap_warn_bytes
            stabilityd.SYSTEM_SWAP_CRIT_BYTES = old_system_swap_crit_bytes
            stabilityd.SYSTEM_SWAP_WARN_RATIO = old_system_swap_warn_ratio
            stabilityd.SYSTEM_SWAP_CRIT_RATIO = old_system_swap_crit_ratio
    print("auth_readiness_smoke_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
