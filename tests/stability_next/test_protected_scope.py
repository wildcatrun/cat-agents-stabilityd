import unittest

from stability_core.protected_scope import (
    canonical_subject, is_protected_identity, resolve_protection_scope,
)


class ProtectedScopeTests(unittest.TestCase):
    def row(self, agent_id, runtime, endpoint_ref, **overrides):
        row = {
            "agent_id": agent_id, "runtime": runtime,
            "platform": "hermes" if runtime.startswith("hermes") else runtime,
            "execution_adapter": runtime, "endpoint_ref": endpoint_ref,
            "status": "active", "can_receive_dispatch": 1,
            "can_start_workflow": 1, "gateway_proxy_allowed": 0,
        }
        row.update(overrides)
        return row

    def resolve(self, records, *, source="db", eligible=True, complete=True,
                target_kind="profile", target_id="catheart", runtime="hermes_acp", generation="boot-1"):
        return resolve_protection_scope(
            records, registry_source=source, registry_write_eligible=eligible,
            scope_complete=complete, target_kind=target_kind, target_id=target_id,
            runtime=runtime, target_generation=generation,
        )

    def test_only_established_aliases_resolve_to_canonical_protected_subjects(self):
        self.assertEqual(canonical_subject("cat_heart"), "cat_heart")
        self.assertEqual(canonical_subject("hermes-profile:catheart"), "cat_heart")
        self.assertEqual(canonical_subject("openclaw-agent:cat_claw"), "cat_claw")
        self.assertIsNone(canonical_subject("catclaw"))
        self.assertTrue(is_protected_identity({"catheart"}))
        self.assertFalse(is_protected_identity({"catclaw"}))

    def test_profile_scope_resolves_catheart_alias_and_keeps_other_profile_clear(self):
        records = [
            self.row("cat_heart", "hermes_acp", "hermes-profile:catheart"),
            self.row("cat_nose", "hermes_acp", "hermes-profile:catnose"),
        ]
        heart = self.resolve(records)
        nose = self.resolve(records, target_id="catnose")
        self.assertEqual((heart.status, heart.protected_subjects), ("protected", ("cat_heart",)))
        self.assertEqual(nose.status, "clear")

    def test_shared_gateway_scope_includes_registered_openclaw_agents(self):
        records = [
            self.row("main", "openclaw", "openclaw-agent:main"),
            self.row("cat_claw", "openclaw", "openclaw-agent:cat_claw"),
        ]
        decision = self.resolve(records, target_kind="shared-gateway", target_id="dev-server",
                                runtime="openclaw")
        self.assertEqual(decision.status, "protected")
        self.assertEqual(decision.protected_subjects, ("cat_claw", "main"))

    def test_stale_missing_or_empty_owner_scope_is_unknown_not_clear(self):
        self.assertEqual(self.resolve([], source="snapshot").status, "unknown")
        self.assertEqual(self.resolve([], eligible=False).status, "unknown")
        self.assertEqual(self.resolve([], complete=False).status, "unknown")
        self.assertEqual(self.resolve([], target_kind="shared-gateway", target_id="dev-server",
                                      runtime="openclaw").status, "unknown")
        self.assertEqual(self.resolve([self.row("catnose", "hermes_acp", "hermes-profile:catnose")],
                                      target_id="missing").status, "unknown")
        self.assertEqual(self.resolve(None).status, "unknown")

    def test_dormant_route_shell_and_retired_catclaw_are_not_canonical_protection(self):
        dormant = self.row("cat_heart", "hermes_acp", "hermes-profile:catheart", status="dormant")
        self.assertEqual(self.resolve([dormant]).status, "unknown")
        route_shell = self.row("cat_heart", "openclaw_route_shell", "openclaw-agent:cat_heart")
        self.assertEqual(self.resolve([route_shell], target_kind="shared-gateway", target_id="dev-server",
                                      runtime="openclaw").status, "unknown")
        retired = self.row("catclaw", "openclaw", "openclaw-agent:catclaw")
        self.assertEqual(self.resolve([retired], target_kind="shared-gateway", target_id="dev-server",
                                      runtime="openclaw").status, "clear")

    def test_environment_protection_only_adds_identities(self):
        self.assertTrue(is_protected_identity({"custom_operator"}, {"custom_operator"}))
        self.assertTrue(is_protected_identity({"main"}, set()))
        self.assertFalse(is_protected_identity({"catclaw"}, {"custom_operator"}))


if __name__ == "__main__":
    unittest.main()
