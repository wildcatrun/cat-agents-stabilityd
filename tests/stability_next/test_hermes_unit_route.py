import unittest
from stability_core.hermes_unit_route import validate_profile_argv


class HermesUnitRouteTests(unittest.TestCase):
    def argv(self):
        return ('/synthetic/venv/bin/python', '-m', 'hermes_cli.main', '--profile', 'catbody', 'gateway', 'run')

    def test_installed_shape(self):
        self.assertEqual(validate_profile_argv(self.argv(), 'catbody'), 'catbody')

    def test_wrong_profile_and_host_refused(self):
        for profile in ('catnose', 'default'):
            with self.assertRaises(ValueError): validate_profile_argv(self.argv(), profile)

    def test_force_multiplex_shell_and_extra_args_refused(self):
        for argv in (self.argv() + ('--force',), self.argv() + ('--multiplex',),
                     ('/bin/sh', '-c', 'hermes gateway run'), self.argv()[:-1] + ('restart',)):
            with self.subTest(argv=argv), self.assertRaises(ValueError): validate_profile_argv(argv, 'catbody')

    def test_noncanonical_and_unknown_interpreter_refused(self):
        for binary in ('python', '/synthetic/../python', '/synthetic/unknown'):
            with self.assertRaises(ValueError): validate_profile_argv((binary,) + self.argv()[1:], 'catbody')
