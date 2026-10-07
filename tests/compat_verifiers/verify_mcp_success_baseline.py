"""Capture/verify pinned MCP responses using only selected source-hash symbols.

Unselected baseline imports and module statements are never executed. No MCP
main, CLI, subprocess handler, SSH, runtime call, or audit file is invoked.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import types
from pathlib import Path
from typing import Any, Dict
from unittest import mock


BASELINE = "ece4157a38cc60dfbedc0268ca296f7775a956f0"
DEFAULT_WORKTREE = Path(__file__).resolve().parents[2]
FIXTURE_RELATIVE = Path("tests/fixtures/compat/mcp_success_responses_v1.json")

SYNTHETIC_PAYLOAD = {
    "source": "local",
    "action": "status",
    "result": {
        "ok": True,
        "returncode": 0,
        "stdout": "{\"severity\":\"low\"}",
        "stderr": "",
    },
    "json": {"severity": "low", "note": "猫状态正常", "items": [1, True, None]},
}

CASES = [
    {
        "name": "initialize-default-protocol",
        "request": {"id": "fixture-init-default", "method": "initialize", "params": {}},
    },
    {
        "name": "initialize-explicit-protocol",
        "request": {
            "id": "fixture-init-explicit",
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
    },
    {
        "name": "tools-call-status-success-envelope",
        "request": {
            "id": 7,
            "method": "tools/call",
            "params": {"name": "stability_status", "arguments": {"source": "local"}},
        },
        "handler": "status",
        "payload": SYNTHETIC_PAYLOAD,
    },
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


PINNED_SYMBOL_SHA256 = {
    "SERVER_NAME": "07884ffb78237eb487ea106a57320ab7395d2f9dad3dc05bf45535c83970abe5",
    "SERVER_VERSION": "0013616b28badf0ae948fcc35026a9016d32ab50e4fd1e67088de3a454c36e58",
    "tool_result": "fda9f0981afc4c8b1ca214417828ba1c2cd67b0a13570cc559f80ada811df13c",
    "handle_request": "68c4529a6b8df8267d484d4a4bb830720c0f4165ef81e518ca81e122bb25dbfb",
}


def _source_hash(source: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(source, node)
    require(segment is not None, "pinned symbol has no source segment")
    return hashlib.sha256(segment.encode("utf-8")).hexdigest()


def load_pinned_module(worktree: Path, *, source_override: str | None = None):
    """Compile only four hash-pinned symbols; ignore every other module node."""
    source = source_override
    if source is None:
        source = subprocess.check_output(
            ["git", "show", f"{BASELINE}:scripts/cat_agents_stability_mcp.py"],
            cwd=worktree, text=True,
        )
    tree = ast.parse(source, filename=f"{BASELINE}:scripts/cat_agents_stability_mcp.py")
    assignments = {}
    functions = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id in {"SERVER_NAME", "SERVER_VERSION"}:
                require(target.id not in assignments, f"duplicate pinned constant: {target.id}")
                require(_source_hash(source, statement) == PINNED_SYMBOL_SHA256[target.id],
                        f"pinned constant changed: {target.id}")
                try:
                    assignments[target.id] = ast.literal_eval(statement.value)
                except (ValueError, TypeError, SyntaxError) as exc:
                    raise AssertionError(f"pinned constant must be literal: {target.id}") from exc
        elif isinstance(statement, ast.FunctionDef) and statement.name in {"tool_result", "handle_request"}:
            require(statement.name not in functions, f"duplicate pinned function: {statement.name}")
            require(_source_hash(source, statement) == PINNED_SYMBOL_SHA256[statement.name],
                    f"pinned function changed: {statement.name}")
            require(not statement.decorator_list and not statement.args.defaults
                    and all(value is None for value in statement.args.kw_defaults),
                    f"pinned function has executable definition-time hooks: {statement.name}")
            functions[statement.name] = statement

    require(set(assignments) == {"SERVER_NAME", "SERVER_VERSION"}, "pinned constant inventory mismatch")
    require(set(functions) == {"tool_result", "handle_request"}, "pinned function inventory mismatch")

    # The synthetic future import only defers annotations. No baseline imports,
    # assignments other than two literals, decorators, or module body execute.
    future_annotations = ast.ImportFrom(
        module="__future__", names=[ast.alias(name="annotations")], level=0
    )
    selected = ast.Module(
        body=[future_annotations, functions["tool_result"], functions["handle_request"]],
        type_ignores=[],
    )
    module = types.ModuleType("stability_mcp_pinned_baseline")
    module.json = json
    module.SERVER_NAME = assignments["SERVER_NAME"]
    module.SERVER_VERSION = assignments["SERVER_VERSION"]
    module.audit = None
    module.status = None
    exec(compile(ast.fix_missing_locations(selected), f"{BASELINE}:selected-mcp-symbols", "exec"), module.__dict__)
    return module


def run_case(module, case: Dict[str, Any]) -> Dict[str, Any]:
    handler = case.get("handler")
    with mock.patch.object(module, "audit"):
        if handler:
            with mock.patch.object(module, handler, return_value=case["payload"]):
                response = module.handle_request(case["request"])
        else:
            response = module.handle_request(case["request"])
    require(isinstance(response, dict), f"expected successful response object for {case['name']}")
    return response


def make_fixture(worktree: Path) -> Dict[str, Any]:
    module = load_pinned_module(worktree)
    cases = []
    for case in CASES:
        cases.append({**case, "expected": run_case(module, case)})
    return {
        "schemaVersion": 1,
        "baselineCommit": BASELINE,
        "captureMethod": "only four source-hash-pinned AST symbols are selected; two constants use ast.literal_eval and only tool_result/handle_request function definitions are compiled with a synthetic future-annotations import; status and audit patched",
        "executionBoundary": {
            "selectedConstants": {name: PINNED_SYMBOL_SHA256[name] for name in ("SERVER_NAME", "SERVER_VERSION")},
            "selectedFunctions": {name: PINNED_SYMBOL_SHA256[name] for name in ("tool_result", "handle_request")},
            "allOtherModuleStatements": "not compiled or executed",
        },
        "cases": cases,
    }


def verify_fixture(worktree: Path, fixture_path: Path) -> int:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    expected_fixture = make_fixture(worktree)
    require(fixture == expected_fixture, "success-response fixture differs from pinned MCP baseline")
    return len(fixture["cases"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worktree", type=Path, default=DEFAULT_WORKTREE)
    parser.add_argument("--capture", action="store_true", help="write the pinned-baseline fixture")
    args = parser.parse_args()
    fixture_path = args.worktree / FIXTURE_RELATIVE
    if args.capture:
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        fixture_path.write_text(json.dumps(make_fixture(args.worktree), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"captured {len(CASES)} successful MCP response cases from {BASELINE}")
        return 0
    count = verify_fixture(args.worktree, fixture_path)
    print(f"pinned MCP success fixture verified: {count} cases; no main, CLI, SSH, or runtime handler")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
