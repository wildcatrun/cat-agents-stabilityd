from dataclasses import asdict
import unittest
from stability_core.hermes_unit_environment import project_environment_properties, EnvironmentProjection


class EnvironmentProjectionTests(unittest.TestCase):
    def text(self, env='HERMES_HOME=/synthetic/home API_KEY=FIXTURE_SECRET', files='', passed='', unset=''):
        return 'Environment='+env+'\nEnvironmentFiles='+files+'\nPassEnvironment='+passed+'\nUnsetEnvironment='+unset+'\n'

    def test_redacted_projection_is_incomplete(self):
        evidence = project_environment_properties(self.text())
        self.assertEqual(dict(evidence.governance_values), {'HERMES_HOME': '/synthetic/home'})
        self.assertNotIn('FIXTURE_SECRET', str(asdict(evidence)))
        self.assertEqual(evidence.effective_coverage, 'incomplete')
        self.assertFalse(evidence.action_authorized)

    def test_external_sources_and_unset_detected(self):
        evidence = project_environment_properties(self.text(files='/synthetic/env', passed='HERMES_HOME',
                                                           unset='HERMES_HOME OTHER=value'))
        self.assertTrue(evidence.environment_files_present)
        self.assertTrue(evidence.pass_environment_present)
        self.assertEqual(evidence.unset_governance_keys, ('HERMES_HOME',))

    def test_quoted_paths(self):
        evidence = project_environment_properties(self.text(env='"HERMES_HOME=/synthetic/with space"'))
        self.assertEqual(dict(evidence.governance_values)['HERMES_HOME'], '/synthetic/with space')

    def test_coverage_duplicates_and_malformed_input_refused(self):
        for text in (self.text()+'Environment=OTHER=x\n', self.text().replace('PassEnvironment=\n',''),
                     self.text(env='HERMES_HOME=a HERMES_HOME=b'), self.text(env='API_KEY="FIXTURE_SECRET')):
            with self.subTest(text=text), self.assertRaises(ValueError) as caught:
                project_environment_properties(text)
            self.assertNotIn('FIXTURE_SECRET', str(caught.exception))

    def test_secret_drift_changes_digest_without_exposing_secret(self):
        first = project_environment_properties(self.text())
        second = project_environment_properties(self.text(env='HERMES_HOME=/synthetic/home API_KEY=OTHER_SECRET'))
        self.assertNotEqual(first.source_sha256, second.source_sha256)
        self.assertEqual(first.governance_values, second.governance_values)

    def test_projection_cannot_self_certify(self):
        with self.assertRaises(ValueError):
            EnvironmentProjection('0'*64, (), (), False, False, effective_coverage='complete')

    def test_unknown_governance_values_not_exposed(self):
        evidence = project_environment_properties(self.text(env='GATEWAY_MULTIPLEX_PROFILES=FIXTURE_SECRET PYTHONPATH=FIXTURE_SECRET'))
        self.assertNotIn('FIXTURE_SECRET', str(asdict(evidence)))
        self.assertEqual(dict(evidence.governance_values)['GATEWAY_MULTIPLEX_PROFILES'], 'unknown')
        with self.assertRaisesRegex(ValueError, '^environment property interpretation refused$'):
            project_environment_properties(self.text(env='HERMES_HOME=FIXTURE_SECRET'))
