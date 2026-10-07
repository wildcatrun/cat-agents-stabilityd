import ast
import json
import traceback
import unittest
from pathlib import Path

from stability_core.config import (
    ACTUATOR_ENVIRONMENT_SETTING_NAMES,
    HERMERS_PROFILE_LIFECYCLE_SETTING_NAMES,
    RUNTIME_INTEGER_DEFAULTS,
    parse_actuator_environment_settings,
    parse_hermers_gateway_restart_limit,
    parse_hermers_profile_lifecycle_settings,
    parse_integer_settings,
    RESTART_ACTUATOR_SETTING_NAMES,
    parse_restart_actuator_settings,
    startup_grace_active,
)


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "compat" / "runtime_integer_config_v1.json"
PROFILE_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "compat" / "hermers_profile_lifecycle_config_v1.json"
ACTUATOR_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "compat" / "actuator_flag_config_v1.json"
RESTART_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "compat" / "restart_actuator_config_v1.json"


class ConfigContractTests(unittest.TestCase):
    def test_restart_actuator_settings_match_pinned_baseline_matrix(self):
        fixture = json.loads(RESTART_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["schemaVersion"], 1)
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        expected_names = set(RESTART_ACTUATOR_SETTING_NAMES) | {"HERMERS_GATEWAY_RESTART_LIMIT"}
        self.assertEqual(set(fixture["outputNames"]), expected_names)
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                parsed = parse_restart_actuator_settings(case["environment"])
                parsed["HERMERS_GATEWAY_RESTART_LIMIT"] = parse_hermers_gateway_restart_limit(
                    case["environment"], parsed["MAX_RESTARTS_PER_WINDOW"]
                )
                self.assertEqual(parsed, case["expected"])
        sentinel = "SYNTHETIC_INVALID_THRESHOLD_SENTINEL"
        with self.assertRaisesRegex(ValueError, "OPENCLAW_STABILITY_MAX_RESTARTS") as error:
            parse_restart_actuator_settings({"OPENCLAW_STABILITY_MAX_RESTARTS": sentinel})
        self.assertNotIn(sentinel, str(error.exception))
        rendered_traceback = "".join(traceback.format_exception(
            type(error.exception), error.exception, error.exception.__traceback__
        ))
        self.assertNotIn(sentinel, rendered_traceback)
        with self.assertRaisesRegex(ValueError, "OPENCLAW_STABILITY_RESTART_COOLDOWN_SECONDS") as ordered_error:
            parse_restart_actuator_settings({
                "OPENCLAW_STABILITY_RESTART_COOLDOWN_SECONDS": "BAD_COOLDOWN_SENTINEL",
                "OPENCLAW_STABILITY_MAX_RESTARTS": "BAD_MAX_SENTINEL",
            })
        self.assertNotIn("BAD_MAX_SENTINEL", str(ordered_error.exception))
        hermers_sentinel = "SYNTHETIC_INVALID_HERMERS_LIMIT_SENTINEL"
        with self.assertRaisesRegex(ValueError, "CAT_AGENTS_STABILITY_HERMERS_GATEWAY_RESTART_LIMIT") as hermers_error:
            parse_hermers_gateway_restart_limit(
                {"CAT_AGENTS_STABILITY_HERMERS_GATEWAY_RESTART_LIMIT": hermers_sentinel}, 2
            )
        hermers_traceback = "".join(traceback.format_exception(
            type(hermers_error.exception), hermers_error.exception, hermers_error.exception.__traceback__
        ))
        self.assertNotIn(hermers_sentinel, hermers_traceback)

    def test_restart_actuator_daemon_wiring_maps_all_six_settings(self):
        daemon_path = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
        tree = ast.parse(daemon_path.read_text(encoding="utf-8"))
        assignments = {}
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = statement.value
        expected_settings = ast.parse(
            "parse_restart_actuator_settings(os.environ)", mode="eval"
        ).body
        self.assertEqual(
            ast.dump(assignments["RESTART_ACTUATOR_SETTINGS"], include_attributes=False),
            ast.dump(expected_settings, include_attributes=False),
        )
        for constant in RESTART_ACTUATOR_SETTING_NAMES:
            with self.subTest(constant=constant):
                expected = ast.parse(
                    "RESTART_ACTUATOR_SETTINGS[{!r}]".format(constant), mode="eval"
                ).body
                self.assertEqual(
                    ast.dump(assignments[constant], include_attributes=False),
                    ast.dump(expected, include_attributes=False),
                )
        expected_hermers = ast.parse(
            "parse_hermers_gateway_restart_limit(os.environ, MAX_RESTARTS_PER_WINDOW)",
            mode="eval",
        ).body
        self.assertEqual(
            ast.dump(assignments["HERMERS_GATEWAY_RESTART_LIMIT"], include_attributes=False),
            ast.dump(expected_hermers, include_attributes=False),
        )
        assignment_positions = {}
        for index, statement in enumerate(tree.body):
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        assignment_positions[target.id] = index
        self.assertLess(
            assignment_positions["RESTART_ACTUATOR_SETTINGS"],
            assignment_positions["HERMERS_GATEWAY_RESTART_LIMIT"],
        )
        self.assertLess(
            assignment_positions["MEMORY_WARN_BYTES"],
            assignment_positions["HERMERS_GATEWAY_RESTART_LIMIT"],
        )

    def test_startup_grace_keeps_strict_less_than_boundary_and_daemon_wiring(self):
        self.assertTrue(startup_grace_active(239, 240))
        self.assertFalse(startup_grace_active(240, 240))
        self.assertFalse(startup_grace_active(None, 240))

        daemon_path = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
        tree = ast.parse(daemon_path.read_text(encoding="utf-8"))
        gateway_collect = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "gateway_collect"
        )
        in_grace = next(
            node for node in ast.walk(gateway_collect)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "in_grace" for target in node.targets)
        )
        expected = ast.parse(
            "startup_grace_active(service_age, STARTUP_GRACE_SECONDS)", mode="eval"
        ).body
        self.assertEqual(
            ast.dump(in_grace.value, include_attributes=False),
            ast.dump(expected, include_attributes=False),
        )

    def test_actuator_flags_match_pinned_baseline_matrix(self):
        fixture = json.loads(ACTUATOR_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["schemaVersion"], 1)
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        self.assertEqual(set(fixture["outputNames"]), set(ACTUATOR_ENVIRONMENT_SETTING_NAMES))
        self.assertEqual(set(fixture["baselineTargets"]), set(ACTUATOR_ENVIRONMENT_SETTING_NAMES))
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    parse_actuator_environment_settings(case["environment"]),
                    case["expected"],
                )

    def test_daemon_wires_only_the_nine_actuator_flags_through_the_helper(self):
        daemon_path = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
        tree = ast.parse(daemon_path.read_text(encoding="utf-8"))
        assignments = {}
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = statement.value
        parser_call = ast.parse(
            "parse_actuator_environment_settings(os.environ)", mode="eval"
        ).body
        self.assertEqual(
            ast.dump(assignments["ACTUATOR_ENVIRONMENT_SETTINGS"], include_attributes=False),
            ast.dump(parser_call, include_attributes=False),
        )
        for name in ACTUATOR_ENVIRONMENT_SETTING_NAMES:
            with self.subTest(name=name):
                expected = ast.parse(
                    "ACTUATOR_ENVIRONMENT_SETTINGS[{!r}]".format(name), mode="eval"
                ).body
                self.assertEqual(
                    ast.dump(assignments[name], include_attributes=False),
                    ast.dump(expected, include_attributes=False),
                )

    def test_integer_setting_defaults_match_frozen_legacy_contract(self):
        fixture = json.loads(FIXTURE.read_text())
        self.assertEqual(fixture["schemaVersion"], 1)
        self.assertEqual(parse_integer_settings({}, RUNTIME_INTEGER_DEFAULTS), fixture["defaults"])

    def test_integer_settings_match_pinned_baseline_matrix(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        self.assertEqual(set(fixture["outputNames"]), set(RUNTIME_INTEGER_DEFAULTS))
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                actual = parse_integer_settings(case["environment"], RUNTIME_INTEGER_DEFAULTS)
                self.assertEqual(actual, case["expected"])

    def test_daemon_wires_runtime_integer_names_to_matching_settings(self):
        daemon_path = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
        tree = ast.parse(daemon_path.read_text(encoding="utf-8"))
        assignments = {}
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = statement.value
        parser_call = ast.parse(
            "parse_integer_settings(os.environ, RUNTIME_INTEGER_DEFAULTS)", mode="eval"
        ).body
        self.assertEqual(
            ast.dump(assignments["RUNTIME_INTEGER_SETTINGS"], include_attributes=False),
            ast.dump(parser_call, include_attributes=False),
        )
        for constant, setting in {
            "PORT": "OPENCLAW_GATEWAY_PORT",
            "INTERVAL_SECONDS": "OPENCLAW_STABILITY_INTERVAL_SECONDS",
            "POLICY_TTL_SECONDS": "OPENCLAW_STABILITY_POLICY_TTL_SECONDS",
        }.items():
            with self.subTest(constant=constant):
                expected = ast.parse("RUNTIME_INTEGER_SETTINGS[{!r}]".format(setting), mode="eval").body
                self.assertEqual(
                    ast.dump(assignments[constant], include_attributes=False),
                    ast.dump(expected, include_attributes=False),
                )

    def test_present_values_override_defaults_and_invalid_values_fail_without_echo(self):
        parsed = parse_integer_settings(
            {"OPENCLAW_GATEWAY_PORT": "24567", "OPENCLAW_STABILITY_INTERVAL_SECONDS": "45"},
            RUNTIME_INTEGER_DEFAULTS,
        )
        self.assertEqual(parsed["OPENCLAW_GATEWAY_PORT"], 24567)
        self.assertEqual(parsed["OPENCLAW_STABILITY_INTERVAL_SECONDS"], 45)
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        with self.assertRaisesRegex(ValueError, "OPENCLAW_GATEWAY_PORT") as error:
            parse_integer_settings({"OPENCLAW_GATEWAY_PORT": sentinel}, RUNTIME_INTEGER_DEFAULTS)
        self.assertNotIn(sentinel, str(error.exception))

    def test_profile_lifecycle_settings_match_pinned_baseline_matrix(self):
        fixture = json.loads(PROFILE_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["schemaVersion"], 1)
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        self.assertEqual(set(fixture["outputNames"]), set(HERMERS_PROFILE_LIFECYCLE_SETTING_NAMES))
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]):
                try:
                    actual = parse_hermers_profile_lifecycle_settings(case["environment"])
                except Exception as exc:
                    self.assertEqual(
                        {"type": type(exc).__name__, "message": str(exc)}, case["error"]
                    )
                    continue
                self.assertIsNone(case["error"])
                projected = {
                    name: sorted(value) if isinstance(value, set) else value
                    for name, value in actual.items()
                }
                self.assertEqual(projected, case["expected"])

    def test_daemon_wires_only_the_eight_profile_settings_through_the_helper(self):
        daemon_path = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
        tree = ast.parse(daemon_path.read_text(encoding="utf-8"))
        assignments = {}
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = statement.value
        self.assertEqual(
            ast.dump(assignments["HERMERS_PROFILE_LIFECYCLE_SETTINGS"], include_attributes=False),
            "Call(func=Name(id='parse_hermers_profile_lifecycle_settings', ctx=Load()), "
            "args=[Attribute(value=Name(id='os', ctx=Load()), attr='environ', ctx=Load())], keywords=[])".replace("\n", ""),
        )
        expected_fields = {
            "HERMERS_PROFILE_MODE_ENABLED": "modeEnabled",
            "HERMERS_PROFILE_MODE_ACTUATE_ENABLED": "actuateEnabled",
            "HERMERS_PROFILE_MODE_START_ENABLED": "startEnabled",
            "HERMERS_PROFILE_LIFECYCLE_ALLOWLIST": "lifecycleAllowlist",
            "HERMERS_PROFILE_COLD_IDLE_SECONDS": "coldIdleSeconds",
            "HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS": "hibernateIdleSeconds",
            "HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS": "lifecycleCooldownSeconds",
            "HERMERS_PROFILE_PROTECTED_IDS": "protectedIds",
        }
        for constant, field in expected_fields.items():
            with self.subTest(constant=constant):
                self.assertEqual(
                    ast.dump(assignments[constant], include_attributes=False),
                    "Subscript(value=Name(id='HERMERS_PROFILE_LIFECYCLE_SETTINGS', ctx=Load()), "
                    f"slice=Constant(value='{field}'), ctx=Load())",
                )


if __name__ == "__main__":
    unittest.main()
