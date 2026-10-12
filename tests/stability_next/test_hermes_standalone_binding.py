import unittest
from dataclasses import replace
from pathlib import Path

from stability_core.effect_capability import (
    EffectRequest, EffectOperation, FileBinding, SchemaBinding,
    UnitBinding, UnitEffectiveConfiguration,
)
from stability_core.hermes_profile_config import ProfileConfigEvidence
from stability_core.hermes_standalone_binding import (
    ENVIRONMENT_SOURCES, LaunchSourceEvidence, LaunchEnvironmentEvidence,
    StandaloneShimEvidence, StandaloneProfileEvidence, bind_standalone_profile,
)


class StandaloneBindingTests(unittest.TestCase):
    def setUp(self):
        self.profile = 'catbody'
        self.root = Path('/synthetic/hermes')
        self.home = self.root / 'profiles' / self.profile
        self.unit = 'hermes-gateway-catbody.service'
        self.request = EffectRequest('hermes.profile.lifecycle', EffectOperation.SYSTEMD_UNIT,
                                     'hermes-profile:catbody', 'node', 'boot')
        self.fragment = FileBinding(self.request, Path('/synthetic/units'),
                                    Path('/synthetic/units') / self.unit, (1, 2), 'a' * 64,
                                    SchemaBinding('systemd-unit-v1', self.request.target, 'runtime-unit://' + self.unit))
        self.argv = ('/synthetic/bin/python3.12', '-m', 'hermes_cli.main',
                     '--profile', 'catbody', 'gateway', 'run')
        self.effective = UnitEffectiveConfiguration(self.fragment.path, (), self.argv,
                                                    'node', 'boot', 10, 'complete')
        self.binding = UnitBinding(self.request, self.unit, self.fragment,
                                   Path(self.argv[0]), 'b' * 64, 'runtime-unit://' + self.unit,
                                   effective_config=self.effective,
                                   executable_entry=Path(self.argv[0]), owner_uid=1000)
        self.config = ProfileConfigEvidence(self.home, self.profile, 'c' * 64,
                                            (1, 2, 1000, 0o100600, 30, 1, 1), True, False)
        self.env = LaunchEnvironmentEvidence(self.unit, 1000, 'node', 'boot', self.root, self.home,
            tuple(LaunchSourceEvidence(name, 'synthetic-reader://' + name, 'd' * 64)
                  for name in sorted(ENVIRONMENT_SOURCES)))
        self.shim = StandaloneShimEvidence('e' * 64, 'f' * 64, 'a' * 64,
                                          'named-profile-standalone-truthy-before-multiplex-v1')

    def bind(self, **changes):
        values = dict(binding=self.binding, config=self.config, environment=self.env,
                      shim=self.shim, profile=self.profile)
        values.update(changes)
        return bind_standalone_profile(**values)

    def test_composition_is_non_authoritative_and_source_bound(self):
        first = self.bind()
        self.assertEqual(first.topology, 'explicit-standalone-shim')
        self.assertFalse(first.action_authorized)
        self.assertFalse(first.artifact_approved)
        changed = replace(self.env, sources=(replace(self.env.sources[0], sha256='1' * 64), *self.env.sources[1:]))
        self.assertNotEqual(first.evidence_digest, self.bind(environment=changed).evidence_digest)

    def test_restart_target_is_distinct(self):
        request = replace(self.request, action_type='hermes.gateway.restart', target='hermes-gateway:catbody')
        result = self.bind(binding=replace(self.binding, request=request,
                           fragment=replace(self.fragment, request=request,
                               schema=replace(self.fragment.schema, subject_id=request.target))))
        self.assertEqual(result.profile, 'catbody')
        with self.assertRaises(ValueError): self.bind(binding=replace(self.binding, request=replace(request, target='hermes-profile:catbody')))

    def test_unknown_target_operation_and_default_refused(self):
        for request in (replace(self.request, target='hermes-profile:catears'),
                        replace(self.request, operation=EffectOperation.HERMES_CLI),
                        replace(self.request, action_type='openclaw.gateway.restart')):
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.bind(binding=replace(self.binding, request=request))
        with self.assertRaises(ValueError): self.bind(profile='default')

    def test_cross_target_schema_and_untyped_request_refused(self):
        for schema in (replace(self.fragment.schema, subject_id='hermes-profile:catears'),
                       replace(self.fragment.schema, owner_ref='runtime-unit://other.service'),
                       replace(self.fragment.schema, schema_id='unknown-unit-v2')):
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                self.bind(binding=replace(self.binding, fragment=replace(self.fragment, schema=schema)))
        with self.assertRaises(ValueError): self.bind(binding=replace(self.binding, request=None))

    def test_config_identity_requires_regular_bounded_exact_integer_fields(self):
        for identity in ((True, 2, 1000, 0o100600, 30, 1, 1),
                         (1, 2, 1000, 0o040600, 30, 1, 1),
                         (1, 2, 1000, 0o100622, 30, 1, 1),
                         (1, 2, 1000, 0o100600, 65537, 1, 1),
                         (1, 2, 1000, 0o100600, -1, 1, 1)):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                self.bind(config=replace(self.config, identity=identity))

    def test_explicit_owner_and_matching_environment_required(self):
        for uid in (None, True, -1, 1001):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                self.bind(binding=replace(self.binding, owner_uid=uid))
        with self.assertRaises(ValueError): self.bind(config=replace(self.config, identity=(1, 2, 1001, 0, 1, 1, 1)))

    def test_complete_effective_unit_and_argv_required(self):
        for config in (replace(self.effective, coverage='partial'),
                       replace(self.effective, node_id='other'),
                       replace(self.effective, generation='other'),
                       replace(self.effective, execstart_argv=(*self.argv, '--force')),
                       replace(self.effective, execstart_argv=self.argv[:4] + ('catears',) + self.argv[5:])):
            with self.subTest(config=config), self.assertRaises(ValueError):
                self.bind(binding=replace(self.binding, effective_config=config))
        with self.assertRaises(ValueError): self.bind(binding=replace(self.binding, unit='hermes-gateway.service'))

    def test_projected_unit_environment_is_insufficient(self):
        for sources in ((), self.env.sources[:1], self.env.sources[:-1],
                        (*self.env.sources[:-1], self.env.sources[0]),
                        (replace(self.env.sources[0], sha256='bad'), *self.env.sources[1:])):
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                self.bind(environment=replace(self.env, sources=sources))

    def test_home_overrides_unresolved_or_scope_drift_refused(self):
        for environment in (replace(self.env, effective_home=self.root),
                            replace(self.env, runtime_root=Path('/other')),
                            replace(self.env, generation='old'),
                            replace(self.env, unresolved=('HERMES_HOME',)),
                            replace(self.env, owner_uid=True)):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                self.bind(environment=environment)
        with self.assertRaises(ValueError): self.bind(config=replace(self.config, home=Path('/other')))

    def test_retired_multiplex_false_never_substitutes_standalone(self):
        with self.assertRaises(ValueError):
            self.bind(config=replace(self.config, standalone=False, multiplex_false_retired=True))

    def test_qualified_shim_interpretation_required_not_version_guess(self):
        for shim in (replace(self.shim, semantics='multiplex-false-means-standalone'),
                     replace(self.shim, gateway_route_sha256=''),
                     replace(self.shim, home_resolver_sha256='unknown')):
            with self.subTest(shim=shim), self.assertRaises(ValueError): self.bind(shim=shim)

    def test_evidence_cannot_claim_authority_or_artifact_approval(self):
        for build in (lambda: replace(self.env, action_authorized=True),
                      lambda: replace(self.shim, action_authorized=True),
                      lambda: replace(self.bind(), action_authorized=True),
                      lambda: replace(self.bind(), artifact_approved=True)):
            with self.assertRaises(ValueError): build()


if __name__ == '__main__':
    unittest.main()
