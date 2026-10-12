import unittest
import os
import tempfile
from pathlib import Path
from stability_core.hermes_profile_live import observe_profile_live
from stability_core.hermes_profile_config import read_profile_config
from stability_core.hermes_unit_route import resolve_explicit_profile_home,ProfilePreparseHome
class ProfilePreparseHomeTests(unittest.TestCase):
    argv=('/fixture/python','-m','hermes_cli.main','--profile','fixture','gateway','run')
    def test_measured_root_profile_and_native_default_semantics(self):
        for values,root in (({'HERMES_HOME':'/fixture/root'},'/fixture/root'),({'HERMES_HOME':'/fixture/root/profiles/other'},'/fixture/root'),({'HOME':'/fixture/user'},'/fixture/user/.hermes'),({'HERMES_HOME':' /fixture/root '},'/fixture/root')):
            with self.subTest(values=values):
                result=resolve_explicit_profile_home(self.argv,'fixture',values)
                self.assertEqual(result.runtime_root,Path(root))
                self.assertEqual(result.home,Path(root)/'profiles'/'fixture')
                self.assertEqual(result.stage,'profile-preparse-before-dotenv')
                self.assertEqual(result.effective_coverage,'incomplete')
    def test_unresolved_and_noncanonical_inputs_refused(self):
        for value in ('relative','~/root','/fixture/$ROOT','/fixture/../root','/fixture/root/','/fixture/root\x00',True,None):
            with self.assertRaises(ValueError):resolve_explicit_profile_home(self.argv,'fixture',{'HERMES_HOME':value})
        with self.assertRaises(ValueError):resolve_explicit_profile_home(self.argv,'fixture',{})
    def test_profile_and_argv_mismatch_refused(self):
        with self.assertRaises(ValueError):resolve_explicit_profile_home(self.argv,'other',{'HERMES_HOME':'/fixture/root'})
        with self.assertRaises(ValueError):resolve_explicit_profile_home(self.argv+('--force',),'fixture',{'HERMES_HOME':'/fixture/root'})
    def test_preparse_result_cannot_claim_final_environment(self):
        with self.assertRaises(ValueError):ProfilePreparseHome('fixture',Path('/fixture/root'),Path('/fixture/root/profiles/fixture'),effective_coverage='complete')
        with self.assertRaises(ValueError):ProfilePreparseHome('fixture',Path('/fixture/root'),Path('/fixture/root/profiles/fixture'),action_authorized=True)

    def test_whitespace_export_means_native_root_with_known_home(self):
        result=resolve_explicit_profile_home(self.argv,'fixture',{'HERMES_HOME':'   ','HOME':'/fixture/user'})
        self.assertEqual(result.runtime_root,Path('/fixture/user/.hermes'))

    def test_candidate_path_identity_and_config_compose_without_authority(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            home = root / 'profiles' / 'fixture'
            home.mkdir(parents=True)
            route = resolve_explicit_profile_home(self.argv, 'fixture', {'HERMES_HOME': str(root)})
            ghost = observe_profile_live(route.runtime_root, profile=route.profile, owner_uid=os.getuid())
            self.assertFalse(ghost.live)
            path = home / 'config.yaml'
            path.write_text('gateway: {standalone: true}\n')
            path.chmod(0o600)
            live = observe_profile_live(route.runtime_root, profile=route.profile, owner_uid=os.getuid())
            config = read_profile_config(route.home, profile=route.profile,
                                         runtime_root=route.runtime_root, owner_uid=os.getuid())
            self.assertTrue(live.live)
            self.assertTrue(config.standalone)
            self.assertEqual(live.home, config.home)
            self.assertFalse(route.action_authorized or live.action_authorized or config.action_authorized)
            deleted = root / 'profiles' / '.deleted'
            deleted.mkdir()
            (deleted / 'fixture').touch()
            self.assertFalse(observe_profile_live(root, profile='fixture', owner_uid=os.getuid()).live)
