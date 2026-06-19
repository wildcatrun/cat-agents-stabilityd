#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "bin" / "cat-heartbeat-probe"


def run_probe(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(PROBE), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CAT_HEARTBEAT_HOME"] = tmp
        env["PATH"] = "/usr/bin:/bin"
        proc = run_probe(["--agent", "cat_voice", "--runtime", "openclaw"], env)
        assert proc.returncode == 2, proc
        assert "HEARTBEAT_WARN" in proc.stdout, proc.stdout
        assert "errors=1" in proc.stdout, proc.stdout

    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CAT_HEARTBEAT_HOME"] = tmp
        proc = run_probe(["--agent", "catbody", "--runtime", "hermers", "--profile", "catbody"], env)
        assert proc.returncode == 2, proc
        assert "HEARTBEAT_WARN" in proc.stdout, proc.stdout
    print("heartbeat_probe_smoke_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
