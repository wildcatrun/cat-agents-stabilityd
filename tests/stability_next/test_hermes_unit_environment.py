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

    def test_managed_scope_controls_projected_without_self_certification(self):
        evidence=project_environment_properties(self.text(env='HERMES_MANAGED_DIR=/fixture/managed PYTEST_CURRENT_TEST=FIXTURE_SECRET HERMES_UPDATE_POST_SWAP=1'))
        values=dict(evidence.governance_values)
        self.assertEqual(values['HERMES_MANAGED_DIR'],'/fixture/managed')
        self.assertEqual(values['PYTEST_CURRENT_TEST'],'present')
        self.assertEqual(values['HERMES_UPDATE_POST_SWAP'],'true')
        self.assertNotIn('FIXTURE_SECRET',repr(evidence))
        self.assertEqual(evidence.effective_coverage,'incomplete')
    def test_managed_default_and_empty_pytest_presence(self):
        evidence=project_environment_properties(self.text(env='HERMES_MANAGED_DIR= PYTEST_CURRENT_TEST= HERMES_UPDATE_POST_SWAP=other'))
        self.assertEqual(dict(evidence.governance_values),{'HERMES_MANAGED_DIR':'default-scope','PYTEST_CURRENT_TEST':'present','HERMES_UPDATE_POST_SWAP':'false'})
    def test_unsafe_managed_path_refused_and_unset_controls_retained(self):
        with self.assertRaises(ValueError):project_environment_properties(self.text(env='HERMES_MANAGED_DIR=FIXTURE_SECRET'))
        evidence=project_environment_properties(self.text(unset='HERMES_MANAGED_DIR PYTEST_CURRENT_TEST'))
        self.assertEqual(evidence.unset_governance_keys,('HERMES_MANAGED_DIR','PYTEST_CURRENT_TEST'))
    def test_observed_systemctl_environment_file_sources(self):
        from pathlib import Path
        from stability_core.hermes_unit_environment import resolve_environment_file_sources
        sources=resolve_environment_file_sources(self.text(files='/home/flashcat/.hermes/profiles/catbody/.env (ignore_errors=yes) /fixture/required (ignore_errors=no)'))
        self.assertEqual(sources,((Path('/home/flashcat/.hermes/profiles/catbody/.env'),True),(Path('/fixture/required'),False)))
        self.assertEqual(resolve_environment_file_sources(self.text()),())
    def test_quoted_environment_file_path(self):
        from pathlib import Path
        from stability_core.hermes_unit_environment import resolve_environment_file_sources
        self.assertEqual(resolve_environment_file_sources(self.text(files='"/fixture/with space" (ignore_errors=yes)')),((Path('/fixture/with space'),True),))
    def test_unknown_file_sources_are_refused_without_raw_text(self):
        from stability_core.hermes_unit_environment import resolve_environment_file_sources
        for value in ('FIXTURE_SECRET','/fixture (unknown=yes)','/fixture/../escape (ignore_errors=yes)','/fixture/*.env (ignore_errors=yes)','/fixture (ignore_errors=yes) /fixture (ignore_errors=no)','/fixture (ignore_errors=yes) extra'):
            with self.subTest(value=value),self.assertRaises(ValueError) as caught:
                resolve_environment_file_sources(self.text(files=value))
            self.assertNotIn('FIXTURE_SECRET',str(caught.exception))
    def test_file_sources_feed_owned_identity_reader(self):
        import os,tempfile
        from pathlib import Path
        from stability_core.hermes_unit_environment import resolve_environment_file_sources
        from stability_core.hermes_environment_source import read_environment_sources
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            path=Path(tmp)/'.env';path.write_text('API_KEY=SYNTHETIC_SECRET\n');path.chmod(0o600)
            missing=Path(tmp)/'missing'
            sources=resolve_environment_file_sources(self.text(files=f'{path} (ignore_errors=no) {missing} (ignore_errors=yes)'))
            evidence=read_environment_sources(sources,owner_uid=os.getuid())
            self.assertEqual([item.present for item in evidence],[True,False])
            self.assertNotIn('SYNTHETIC_SECRET',repr(evidence))

    def test_escaped_systemd_paths_refused_instead_of_reinterpreted(self):
        from stability_core.hermes_unit_environment import resolve_environment_file_sources
        for value in (r'/fixture/with\x20space (ignore_errors=yes)',r'/fixture/back\slash (ignore_errors=no)',r'"/fixture/back\slash" (ignore_errors=yes)'):
            with self.assertRaises(ValueError):resolve_environment_file_sources(self.text(files=value))
    def test_environment_file_source_budget(self):
        from stability_core.hermes_unit_environment import resolve_environment_file_sources
        text=' '.join(f'/fixture/file-{i} (ignore_errors=yes)' for i in range(33))
        with self.assertRaises(ValueError):resolve_environment_file_sources(self.text(files=text))
