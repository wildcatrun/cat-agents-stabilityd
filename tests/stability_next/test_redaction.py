import importlib.util
import json
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from stability_core.redaction import redact_sensitive_text


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("stabilityd_redaction_test", ROOT / "bin" / "cat_agents_stabilityd.py")
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


class RedactionTests(unittest.TestCase):
    def test_synthetic_secret_forms_are_removed_before_truncation(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        text = "\n".join([
            f"Authorization: Bearer {sentinel}",
            f"--api-key {sentinel}",
            f"https://api.telegram.org/bot123456:{sentinel}/getMe",
            f'{{"refresh_token":"{sentinel}","password":"{sentinel}"}}',
            f"https://user:{sentinel}@example.invalid/path",
            "-----BEGIN PRIVATE KEY-----\n" + sentinel + "\n-----END PRIVATE KEY-----",
        ])
        redacted = redact_sensitive_text(text, max_chars=5000)
        self.assertNotIn(sentinel, redacted)
        self.assertIn("[REDACTED_PRIVATE_KEY]", redacted)
        self.assertIn("[REDACTED_JWT]", redact_sensitive_text(
            "eyJ" + "A" * 24 + "." + "B" * 24 + "." + "C" * 8))
        self.assertNotIn(sentinel, redact_sensitive_text("prefix " + text, max_chars=40))

    def test_command_probe_never_persists_raw_argv_or_secret_output(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        proc = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=f"Authorization: Bearer {sentinel}\nstatus=ok",
            stderr=f"--api-key {sentinel}",
        )
        with mock.patch.object(stabilityd, "run_cmd", return_value=proc):
            result = stabilityd.command_probe(["diagnostic-tool", "--api-key", sentinel])
        self.assertEqual(result["cmd"], ["diagnostic-tool"])
        self.assertNotIn(sentinel, json.dumps(result))

    def test_json_cli_diagnostics_keep_codes_not_untrusted_preamble(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        payload, diagnostics, error = stabilityd.extract_json_payload(
            f"Legacy state migration warning Authorization: Bearer {sentinel}\n{{\"ok\":true}}"
        )
        self.assertEqual(payload, {"ok": True})
        self.assertIn("state_migration_warning", diagnostics)
        self.assertNotIn(sentinel, json.dumps({"diagnostics": diagnostics, "error": error}))

    def test_cli_json_payloads_match_pinned_baseline_cases_without_raw_diagnostics(self):
        fixture = json.loads((ROOT / "tests" / "fixtures" / "compat" / "cli_json_payload_v1.json").read_text())
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        allowed_diagnostics = {
            "state_migration_warning", "plugin_install_index_warning", "non_json_diagnostic_preamble",
        }
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                payload, diagnostics, error = stabilityd.extract_json_payload(case["input"])
                self.assertEqual(payload, case["expectedPayload"])
                self.assertLessEqual(set(diagnostics), allowed_diagnostics)
                self.assertNotIn(sentinel, json.dumps({"diagnostics": diagnostics, "error": error}))

    def test_openclaw_auth_parser_matches_pinned_shared_projection_and_masks_identifiers(self):
        fixture = json.loads((ROOT / "tests" / "fixtures" / "compat" / "openclaw_auth_parse_v1.json").read_text())
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        self.assertEqual(fixture["fixedEpoch"], 1791237600)
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]), mock.patch.object(stabilityd, "epoch", return_value=fixture["fixedEpoch"]):
                parsed = stabilityd.parse_openclaw_auth_list(case["input"], case["agentId"])
                actual = {
                    "agentId": parsed["agentId"],
                    "profileCount": parsed["profileCount"],
                    "unparsedProfileLineCount": parsed["unparsedProfileLineCount"],
                    "profiles": [{
                        key: profile.get(key) for key in fixture["sharedProfileFields"]
                    } for profile in parsed["profiles"]],
                }
                self.assertEqual(actual, case["expectedSharedProjection"])
                self.assertEqual(parsed["unparsedProfileLines"], [])
                self.assertEqual(parsed["profiles"][0]["profileLabel"],
                                 parsed["profiles"][0]["profileKind"] + ":[redacted]")
                self.assertEqual(parsed["profiles"][0]["authKind"], "unknown")
                self.assertNotIn("FIXTURE_PROFILE", json.dumps(parsed))

    def test_openclaw_auth_unparsed_lines_are_counted_but_not_retained(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        result = stabilityd.parse_openclaw_auth_list(
            f"- oauth malformed Authorization: Bearer {sentinel}", "main"
        )
        self.assertEqual(result["unparsedProfileLineCount"], 1)
        self.assertNotIn(sentinel, json.dumps(result))

    def test_cron_error_text_becomes_category_before_snapshot_output(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        stdout = json.dumps({"jobs": [{"id": "job-1", "status": "error",
                                      "state": {"lastError": f"Authorization: Bearer {sentinel}"}}]})
        proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
        with mock.patch.object(stabilityd, "run_cmd", return_value=proc):
            result = stabilityd.collect_cron_cli_status()
        self.assertNotIn(sentinel, json.dumps(result))
        self.assertEqual(result["byJob"]["job-1"]["lastError"], "authorization")

    def test_legacy_lsp_state_command_line_is_not_rewritten_to_kv(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)")
        now = stabilityd.epoch()
        stabilityd.db_set(conn, "hermers_lsp_idle_state", {
            "catnose:42": {"profile": "catnose", "pid": "42", "cpuTicks": 10,
                            "idleSinceEpoch": now - 60, "lastSeenEpoch": now,
                            "cmd": f"pyright --token {sentinel}"},
        })
        with mock.patch.object(stabilityd, "epoch", return_value=now):
            stabilityd.update_hermers_lsp_idle_state(conn, [])
        persisted = stabilityd.db_get(conn, "hermers_lsp_idle_state", {})
        self.assertNotIn(sentinel, json.dumps(persisted))
        self.assertNotIn("cmd", persisted["catnose:42"])
        conn.close()

    def test_version_and_auth_profile_parser_never_persist_unstructured_identifiers(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        version = stabilityd.parse_openclaw_version(f"diagnostic {sentinel} provider output")
        self.assertNotIn(sentinel, json.dumps(version))
        self.assertEqual(version["raw"], "unparsed_version_output")
        parsed = stabilityd.parse_openclaw_auth_list(
            f"- {sentinel} [openai-codex/{sentinel}; expires 2026-10-05T00:00:00Z]", "main"
        )
        self.assertNotIn(sentinel, json.dumps(parsed))
        provider_attack = stabilityd.parse_openclaw_auth_list(
            f"- default [{sentinel}/oauth; expires 2026-10-05T00:00:00Z]", "main"
        )
        self.assertNotIn(sentinel, json.dumps(provider_attack))
        self.assertEqual(provider_attack["profiles"][0]["provider"], "unknown")
        version_ok = stabilityd.parse_openclaw_version("OpenClaw 2026.10.5 (abcdef123456)")
        self.assertEqual(version_ok["version"], "2026.10.5")
        self.assertEqual(version_ok["commit"], "abcdef123456")

    def test_daemon_error_evidence_drops_exception_text_and_traceback(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        try:
            raise RuntimeError(f"https://api.example/bot{sentinel} traceback payload")
        except RuntimeError as exc:
            event = stabilityd.daemon_loop_error_event(exc)
        self.assertNotIn(sentinel, json.dumps(event))
        self.assertNotIn("traceback", event)

    def test_log_line_redacts_before_persisting(self):
        import tempfile
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "daemon.log"
            with mock.patch.object(stabilityd, "ensure_dirs"), \
                 mock.patch.object(stabilityd, "LOG_PATH", log_path):
                stabilityd.log_line(f"failed Authorization: Bearer {sentinel}")
            self.assertNotIn(sentinel, log_path.read_text())


if __name__ == "__main__":
    unittest.main()
