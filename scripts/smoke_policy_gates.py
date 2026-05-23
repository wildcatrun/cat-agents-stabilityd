#!/usr/bin/env python3
"""Fast smoke checks for high-risk stabilityd policy gates."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path


def load_stabilityd(tmp: str):
    os.environ["OPENCLAW_HOME_DIR"] = tmp
    os.environ["CAT_AGENTS_WORKFLOW_DB"] = str(Path(tmp) / "missing-tracking.db")
    os.environ.pop("CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_ALLOWLIST", None)
    os.environ.pop("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_MANAGED", None)
    os.environ.pop("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTUATE", None)
    module_path = Path(__file__).resolve().parents[1] / "bin" / "cat_agents_stabilityd.py"
    spec = importlib.util.spec_from_file_location("cat_agents_stabilityd_smoke", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cat-stability-gates-") as tmp:
        stabilityd = load_stabilityd(tmp)
        now_s = stabilityd.epoch()

        checks = {}

        checks["lifecycle_allowlist_default_empty"] = stabilityd.HERMERS_PROFILE_LIFECYCLE_ALLOWLIST == set()
        checks["unallowlisted_profile_blocked"] = not stabilityd.hermers_profile_lifecycle_allowed(
            "catears", ["cat_ears"], protected=False
        )
        stabilityd.HERMERS_PROFILE_LIFECYCLE_ALLOWLIST = {"catears"}
        checks["explicit_lifecycle_allowlist_allowed"] = stabilityd.hermers_profile_lifecycle_allowed(
            "catears", ["cat_ears"], protected=False
        )
        checks["protected_profile_blocked"] = not stabilityd.hermers_profile_lifecycle_allowed(
            "catheart", ["cat_heart"], protected=True
        )

        missing_profile = stabilityd.hermers_profile_safe_to_hibernate(
            "catears", {"safeToHibernate": True, "updated_at": stabilityd.ts()}, now_s
        )
        mismatch = stabilityd.hermers_profile_safe_to_hibernate(
            "catears", {"profile": "catbody", "safeToHibernate": True, "updated_at": stabilityd.ts()}, now_s
        )
        false_flag = stabilityd.hermers_profile_safe_to_hibernate(
            "catears", {"profile": "catears", "safeToHibernate": False, "updated_at": stabilityd.ts()}, now_s
        )
        true_flag = stabilityd.hermers_profile_safe_to_hibernate(
            "catears", {"profile": "catears", "safeToHibernate": True, "updated_at": stabilityd.ts()}, now_s
        )
        checks["safe_missing_profile_blocks"] = missing_profile == (False, "runtime-state-profile-missing")
        checks["safe_profile_mismatch_blocks"] = mismatch == (False, "runtime-state-profile-mismatch")
        checks["safe_false_blocks"] = false_flag == (False, "runtime-safe-to-hibernate-missing")
        checks["safe_true_allows"] = true_flag == (True, "runtime-safe-to-hibernate")

        findings = []
        profiles, meta = stabilityd.hermers_profiles_from_runtime_registry(findings)
        checks["registry_missing_fail_closed"] = (
            profiles == {}
            and meta.get("source") == "runtime_agents"
            and any(item.get("key") == "hermers_profile_registry_unavailable" for item in findings)
        )
        checks["hermers_restart_disabled_by_default"] = not stabilityd.HERMERS_GATEWAY_RESTART_ENABLED

        failed = [name for name, ok in checks.items() if not ok]
        print(json.dumps({"ok": not failed, "checks": checks, "failed": failed}, indent=2, sort_keys=True))
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
