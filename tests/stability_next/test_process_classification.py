import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
SPEC = importlib.util.spec_from_file_location("cat_agents_stabilityd", MODULE_PATH)
assert SPEC and SPEC.loader
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
SPEC.loader.exec_module(stabilityd)


def row(pid, ppid, command):
    return {
        "pid": str(pid),
        "ppid": str(ppid),
        "stat": "S",
        "etime": "00:01",
        "rssKb": "100",
        "cmd": command,
    }


class ProcessClassificationTest(unittest.TestCase):
    def summary(self, commands):
        rows = [row(index + 2, 1, command) for index, command in enumerate(commands)]
        with mock.patch.object(stabilityd, "ps_rows", return_value=rows):
            return stabilityd.child_process_summary(1)

    def test_recognizes_supported_app_server_argv_shapes(self):
        commands = [
            "/usr/local/bin/codex app-server --listen stdio",
            "/usr/bin/node /opt/codex/dist/codex.js app-server",
            "/usr/bin/node --enable-source-maps /plugins/openai/node_modules/@openai/codex/bin/codex.js app-server",
            "/plugins/codex/vendor/codex -c model=fast --profile ops app-server",
            "codex --enable responses_websockets --disable other --add-dir /tmp -C /tmp app-server",
            "codex --full-auto --oss --local-provider ollama app-server",
            "node --experimental-loader custom-loader /tmp/codex.js app-server",
            "node --inspect=127.0.0.1:9229 /tmp/codex.js app-server",
        ]
        result = self.summary(commands)
        self.assertEqual(result["codexAppServers"], 8)
        self.assertEqual(result["processClassCounts"]["codexAppServer"], 8)
        self.assertEqual({item["launcher"] for item in result["ownerCandidates"]}, {"native", "node"})

    def test_excludes_wrappers_searches_and_argument_values(self):
        commands = [
            "bash -lc 'codex app-server'",
            "grep codex app-server process.log",
            "python worker.py --description 'codex app-server'",
            "codex --config app-server exec task",
            "node wrapper.js codex app-server",
            "node worker.js --label /tmp/codex.js app-server",
            "codex --unknown app-server",
            "node --eval codex.js app-server",
            "node --print=codex.js /tmp/codex.js app-server",
            "node --require /tmp/codex.js app-server",
            "node --inspect 127.0.0.1:9229 /tmp/codex.js app-server",
        ]
        result = self.summary(commands)
        self.assertEqual(result["codexAppServers"], 0)
        self.assertEqual(result["processClassCounts"]["codexHelper"], 2)
        self.assertTrue(all(item["kind"] == "codex_helper" for item in result["ownerCandidates"]))

    def test_normal_codex_helper_is_explained_without_orphan_claim(self):
        result = self.summary(["/usr/local/bin/codex exec --json task"])
        self.assertEqual(result["codexAppServers"], 0)
        self.assertEqual(result["processClassCounts"]["codexHelper"], 1)
        self.assertEqual(result["ownerCandidates"][0]["kind"], "codex_helper")
        self.assertNotIn("orphan", result["ownerCandidates"][0])

    def test_descendant_walk_and_legacy_fields_remain_compatible(self):
        rows = [
            row(2, 1, "codex app-server"),
            row(3, 2, "openclaw helper"),
            row(4, 99, "codex app-server"),
        ]
        with mock.patch.object(stabilityd, "ps_rows", return_value=rows):
            result = stabilityd.child_process_summary(1)
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["codexAppServers"], 1)
        self.assertEqual(result["openclawChildren"], 1)
        self.assertEqual(len(result["sample"]), 2)

    def test_process_sample_classifies_without_persisting_argv(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        with mock.patch.object(stabilityd, "ps_rows", return_value=[
            row(2, 1, f"/usr/local/bin/codex app-server --api-key {sentinel}")
        ]):
            result = stabilityd.child_process_summary(1)
        self.assertEqual(result["codexAppServers"], 1)
        self.assertEqual(result["sample"][0]["processKind"], "codex_app_server")
        self.assertNotIn(sentinel, str(result))
        self.assertNotIn("cmd", result["sample"][0])


if __name__ == "__main__":
    unittest.main()
