import importlib.util
import subprocess
import unittest
from pathlib import Path


WORKTREE = Path(__file__).resolve().parents[2]
VERIFIER_PATH = (
    WORKTREE / "tests" / "compat_verifiers"
    / "verify_mcp_success_baseline.py"
)
SPEC = importlib.util.spec_from_file_location("mcp_success_baseline_verifier_test", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load pinned MCP verifier")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class McpSuccessVerifierTests(unittest.TestCase):
    def test_pinned_baseline_gate_and_success_fixture(self):
        fixture = WORKTREE / "tests" / "fixtures" / "compat" / "mcp_success_responses_v1.json"
        self.assertEqual(VERIFIER.verify_fixture(WORKTREE, fixture), 3)

    def test_unselected_module_body_is_never_executed(self):
        source = subprocess.check_output(
            ["git", "show", f"{VERIFIER.BASELINE}:scripts/cat_agents_stability_mcp.py"],
            cwd=WORKTREE, text=True,
        )
        injected = source + "\nraise RuntimeError('unselected module body executed')\n"
        module = VERIFIER.load_pinned_module(WORKTREE, source_override=injected)
        response = module.handle_request({"id": 3, "method": "initialize", "params": {}})
        self.assertEqual(response["result"]["serverInfo"],
                         {"name": "cat-agents-stability", "version": "0.1.0"})

    def test_selected_baseline_symbol_drift_is_rejected_before_exec(self):
        source = subprocess.check_output(
            ["git", "show", f"{VERIFIER.BASELINE}:scripts/cat_agents_stability_mcp.py"],
            cwd=WORKTREE, text=True,
        )
        with self.assertRaisesRegex(AssertionError, "pinned constant changed"):
            VERIFIER.load_pinned_module(
                WORKTREE,
                source_override=source.replace('SERVER_VERSION = "0.1.0"', 'SERVER_VERSION = "0.1.1"', 1),
            )
        with self.assertRaisesRegex(AssertionError, "pinned function changed"):
            VERIFIER.load_pinned_module(
                WORKTREE,
                source_override=source.replace('"2025-06-18"', '"2025-06-19"', 1),
            )


if __name__ == "__main__":
    unittest.main()
