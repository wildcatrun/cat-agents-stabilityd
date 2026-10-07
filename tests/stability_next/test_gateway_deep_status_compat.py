import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("stabilityd_gateway_status_compat", ROOT / "bin" / "cat_agents_stabilityd.py")
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


class GatewayDeepStatusCompatibilityTests(unittest.TestCase):
    def test_parser_output_matches_pinned_baseline_cases(self):
        fixture_path = ROOT / "tests" / "fixtures" / "compat" / "gateway_deep_status_v1.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        with mock.patch.object(stabilityd, "PORT", fixture["parserPort"]):
            for case in fixture["cases"]:
                with self.subTest(case=case["name"]):
                    self.assertEqual(
                        stabilityd.parse_gateway_deep_status(case["input"]),
                        case["expected"],
                    )


if __name__ == "__main__":
    unittest.main()
