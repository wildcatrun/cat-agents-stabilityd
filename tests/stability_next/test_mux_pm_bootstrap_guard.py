"""Finite v0.22.2 source-launch boundary tests; no live runtime or credentials.

Exact official functions below are copied from d923a5e source. Only the
stdlib/early-return/profile-preparse closure runs; these are NOT a claim to
exercise the complete upstream application or all third-party dependencies.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from stability_core.hermes_mux_bridge import PmBootstrapGuard, PM_BOOTSTRAP_SOURCES, execute

OFFICIAL_PREPARE_SOURCE_SHA256 = '6de0d12b3de57f4425279589be5d2f39e02e2bec98ba04ef8169e1e9d2b982e9'
OFFICIAL_MAIN_SOURCE_SHA256 = '88a7fc166d3bfaac082d44bbfc36c93b53c50f7508ca96e32206dc3f1edfaa82'
OFFICIAL_PREPARE = 'def prepare_launch(project_root: Path, argv: list[str]) -> Path | None:\n    """Finish a self-managed source update before importing app dependencies.\n\n    PM\'s successful input stamp signals a finished dependency sync; the\n    ``source-completion-pending`` marker signals the tail still owed after it,\n    so a tail that failed is retried on the next launch WITHOUT rebuilding\n    dependencies that are already current. Old updaters need not write a\n    marker (and cannot accidentally clear this obligation).\n    A supervised child leaves that tail to ``hermes update`` when its dependencies\n    are current: its manager restarts it on every start, so a sticky marker would\n    re-run the tail (and its environment builds) on each boot until the disk fills.\n    Return the store interpreter when this process must restart cleanly.\n    """\n    import os\n    import sys\n\n    root = Path(project_root).resolve()\n    # sys.argv[0] is this process\'s script identity; *argv* carries only the command.\n    if _is_tail_script(root, sys.argv[0]):\n        return None\n\n    from hermes_cli._parser import command_argv\n    from hermes_cli.steward import read_install_stamp\n\n    if (command_argv(argv)[:1] == ["pm"]\n            or _METADATA_FLAGS & set(argv)\n            or os.environ.get("HERMES_DISABLE_LAZY_INSTALLS", "").lower() in ("1", "true", "yes")\n            or not (root / ".git").exists()\n            or not (root / "pyproject.toml").is_file()):\n        return None\n    stamp = read_install_stamp(root)\n    if not stamp:\n        from hermes_cli.post_update import step_adopt_blessed_checkout\n\n        step_adopt_blessed_checkout(root)\n        stamp = read_install_stamp(root)\n    if stamp.get("updateMechanism") != "self":\n        return None  # Developer checkouts and packaged runtimes retain their owner.\n\n    import pm\n    from hermes_cli._launchers import resolve_store_python\n    from hermes_cli.update_lock import UpdateLock, read_live_update\n\n    current = pm.venv_is_current(project_root=root)\n    from pm.environments import owning_home_root\n\n    owner = owning_home_root(root)\n    if owner is not None:\n        return _prepare_borrowed_launch(root, owner, current=current)\n    pending = completion_pending_path(root)\n    owed_to_cli = current and pending.is_file() and _supervised_child()\n    _may_retry, _attempts, _backoff = completion_retry_state(root)\n    if not _may_retry and _attempts >= COMPLETION_RETRY_MAX_ATTEMPTS:\n        # The tail has failed often enough that every relaunch re-running it\n        # does more harm than good (#122206: "every launch burns ~4 minutes").\n        # Leave the marker for an explicit `hermes update`; say so once.\n        print(\n            f"hermes: a source update could not be finished automatically "\n            f"({_attempts} attempts); run `hermes update` from a shell to finish it",\n            file=sys.stderr, flush=True,\n        )\n    elif not _may_retry:\n        # Backoff window not yet elapsed: skip this launch\'s retry without\n        # noise (the record\'s age tracks the wait), leaving the marker armed.\n        pass\n    elif not owed_to_cli and (not current or pending.is_file()):\n        # The marker alone first (a process the live update spawned runs under its claim and\n        # inherits no checkout lock); install_root still names the checkout whose held lock\n        # keeps a dead update\'s marker (R6: refused as held, never reclaimed).\n        lock = UpdateLock(install_root=root, checkout_first=False)\n        if not lock.acquire():\n            raise RuntimeError("an update is still running; wait for it to exit, then relaunch Hermes")\n        try:\n            # Under the launching update\'s own claim (its pid is our ancestor) a process it\n            # spawned owes no tail: that obligation is the updater\'s.\n            if not lock.acquired and read_live_update(install_root=root) is not None:\n                if current:\n                    return None\n                # A process the update spawns before its dependencies are current (a restarted\n                # gateway) would boot on a tree built for another interpreter. Sync — never the\n                # tail, which is the updater\'s — then relaunch below into a current install.\n                _sync_source_dependencies(root, arm=False)\n                if not pm.venv_is_current(project_root=root):\n                    # Relaunching would land back here and sync again, forever.\n                    raise RuntimeError("dependency sync left this install out of date")\n            else:\n                # The tail mutates the checkout: ACQUIRE its lock (R2), never sample it. A free\n                # marker over a held checkout lock is a killed update whose tree (its completion\n                # child) still runs.\n                if not lock.acquire_checkout(root):\n                    raise RuntimeError("an update is still running; wait for it to exit, then relaunch Hermes")\n                _finish_source_update(root, current=current, pending=pending)\n        finally:\n            lock.release()\n    python = resolve_store_python(root)\n    if python is None:\n        raise RuntimeError("source update has no managed Python; run `hermes pm install`")\n    # Lexical identity, never resolve(): PM spells the store path through\n    # HERMES_HOME (which may carry \'..\') while sys.executable arrives\n    # normalized, so a raw compare re-execs every child forever (#122513). A\n    # venv interpreter symlinked to the same binary is still a different\n    # interpreter (its own sys.prefix) and must re-exec once.\n    same = os.path.normcase(os.path.abspath(python)) == os.path.normcase(os.path.abspath(sys.executable))\n    if not current or not same:\n        publish_launchers(root)\n        return python\n    if owed_to_cli:\n        # Left owed, not dropped: say so (once, in the process that boots) where an\n        # operator of the unit will read it.\n        print("hermes: a source update is unfinished; run `hermes update` from a shell to finish it",\n              file=sys.stderr, flush=True)\n    return None'
OFFICIAL_PREPARSE = 'def _inside_mcp_add_args(argv: list, index: int) -> bool:\n    """True once argv reaches `hermes mcp add ... --args <command argv>`.\n\n    ``mcp add --args`` is command-argv passthrough. Flags after that point\n    belong to the child MCP command (for example Docker MCP Toolkit\'s\n    ``--profile``), not to Hermes\' own profile selector.\n    """\n    try:\n        mcp_index = argv.index("mcp", 0, index)\n        argv.index("add", mcp_index + 1, index)\n    except ValueError:\n        return False\n    return True\n\ndef _looks_like_hermes_invocation() -> bool:\n    """False when ``sys.argv`` belongs to a test runner rather than a ``hermes`` run.\n\n    pytest\'s own ``-p no:xdist`` reaches ``_scan_profile_flag`` through ``sys.argv`` at import\n    time; it must stay a silent skip, while a real ``hermes -p \'Work Bot\'`` must fail loudly.\n    """\n    return "pytest" not in (sys.argv[0] or "")\n\ndef _looks_like_option_value(value: str) -> bool:\n    """A ``-p`` value that clearly belongs to some other tool (pytest\'s ``-p no:xdist``, a\n    third-party ``-p --flag``), never a mistyped profile name."""\n    return value.startswith("-") or ":" in value\n\ndef _scan_profile_flag(argv: list) -> tuple:\n    """Find -p/--profile/--profile= in argv -> (name, tokens_consumed, index).\n\n    Historically the flag worked even after the subcommand (`hermes chat -p\n    coder`), so scan broadly; stop at ``--`` and at the `mcp add --args`\n    passthrough region. The value is normalised (strip + casefold, matching\n    ``profiles.normalize_profile_name``) before validation so ``-p Work`` selects\n    ``work``. A value that cannot be a profile name is rejected so\n    resolve_profile_env never sys.exits on it; the rejection is explained (exit 2)\n    only when the flag comes BEFORE the first subcommand token under a real\n    ``hermes`` run — after a subcommand, ``-p`` may belong to that subcommand or a\n    plugin (`hermes kanban ... -p 8080`), and option-looking values (``no:xdist``,\n    ``--flag``) are always a silent skip.\n    """\n    from hermes_cli._parser import top_level_value_flag_sets\n\n    value_flags, optional_value_flags = top_level_value_flag_sets()\n    i = 0\n    saw_subcommand = False\n    while i < len(argv):\n        arg = argv[i]\n        if arg == "--" or (arg == "--args" and _inside_mcp_add_args(argv, i)):\n            break\n        if arg in {"--profile", "-p"} and i + 1 < len(argv):\n            raw = argv[i + 1]\n            value = raw.strip().casefold()\n            if re.match(_PROFILE_NAME_RE, value):\n                return value, 2, i\n            if not saw_subcommand and not _looks_like_option_value(raw) and _looks_like_hermes_invocation():\n                _exit_invalid_profile_name(raw)\n            break\n        if arg.startswith("--profile="):\n            return arg.split("=", 1)[1].strip().casefold(), 1, i\n        takes_value = "=" not in arg and i + 1 < len(argv) and (\n            arg in value_flags\n            or (arg in optional_value_flags and not argv[i + 1].startswith("-"))\n        )\n        if not takes_value and not arg.startswith("-"):\n            saw_subcommand = True\n        i += 2 if takes_value else 1\n    return None, 0, None\n\ndef _apply_profile_override() -> None:\n    """Pre-parse --profile/-p and set HERMES_HOME before imports."""\n    global _explicit_cli_profile\n    _explicit_cli_profile = None\n    argv = sys.argv[1:]\n    profile_name, consume, profile_index = _scan_profile_flag(argv)\n    from_sticky_profile = False\n\n    # HERMES_HOME already set with no explicit flag: trust it only when it\n    # points at a specific profile dir ("profiles" as immediate parent). If it\n    # points at the hermes root (systemd hardcodes HERMES_HOME=/root/.hermes)\n    # we must still read active_profile — the user may have run\n    # `hermes profile use` and the gateway should honour it (#22502).\n    hermes_home_env = os.environ.get("HERMES_HOME", "")\n    if profile_name is None and hermes_home_env and Path(hermes_home_env).parent.name == "profiles":\n        return\n\n    if (profile_name is None and not _under_gateway_supervisor(argv)\n            and not _startup_fast.is_desktop_ssh_backend_argv(argv)\n            and not _s6_supervised_gateway_run(argv)):\n        try:\n            from hermes_constants import get_default_hermes_root\n\n            active_path = get_default_hermes_root() / "active_profile"\n            if active_path.exists():\n                name = active_path.read_text(encoding="utf-8-sig").strip()\n                if name and name != "default":\n                    profile_name = name  # consume stays 0: nothing to strip\n                    from_sticky_profile = True\n        except (UnicodeDecodeError, OSError):\n            pass  # corrupted file, skip\n\n    if profile_name is None:\n        return\n    try:\n        from hermes_cli.profiles import resolve_profile_env\n\n        hermes_home = resolve_profile_env(profile_name)\n    except FileNotFoundError as exc:\n        hermes_home = _resolve_sudo_user_profile_env(profile_name)\n        error = str(exc)\n        if not hermes_home and from_sticky_profile:\n            from hermes_cli.main_profile_recovery import is_stale_profile_recovery_command\n\n            if is_stale_profile_recovery_command(argv):\n                hermes_home = resolve_profile_env("default")\n                print(\n                    f"Warning: saved profile \'{profile_name}\' no longer exists; "\n                    "running this recovery command in the default profile.",\n                    file=sys.stderr,\n                )\n            else:\n                error = f"Saved profile \'{profile_name}\' no longer exists. Switch back with: hermes profile use default"\n        if not hermes_home:\n            print(f"Error: {error}", file=sys.stderr)\n            sys.exit(1)\n    except ValueError as exc:\n        print(f"Error: {exc}", file=sys.stderr)\n        sys.exit(1)\n    except Exception as exc:\n        # A bug in profiles.py must NEVER prevent hermes from starting\n        print(f"Warning: profile override failed ({exc}), using default", file=sys.stderr)\n        return\n    os.environ["HERMES_HOME"] = hermes_home\n    if consume > 0:\n        _explicit_cli_profile = profile_name\n    # Strip the flag from argv so argparse doesn\'t choke\n    if consume > 0 and profile_index is not None:\n        start = profile_index + 1  # +1 because argv is sys.argv[1:]\n        sys.argv = sys.argv[:start] + sys.argv[start + consume :]'
OFFICIAL_PREPARE_EXCERPT_SHA256 = '20aaa89acac0b6d1da078fea0a47918e4b5782ec021aeae008e9063db23223c3'
OFFICIAL_PREPARSE_EXCERPT_SHA256 = '332fcf9077b6f28cf367a3417b5872418007b0f095cede1d30716ab728c4b867'


OFFICIAL_SCRATCH_SOURCE_SHA256 = '8d55a41452b625061f1f2e2f507a7e7ffb2a396e711afcc7aee28b03a6e8fa9d'
OFFICIAL_SCRATCH_ENV = 'def apply_scratch_tmp_env(env: MutableMapping[str, str]) -> bool:\n    """Point ``TMPDIR``/``TMP``/``TEMP`` in *env* at the scratch dir of ``env["HERMES_HOME"]``.\n\n    A temp var the user (or the OS: macOS ``/var/folders``, Windows ``%TEMP%``) set is\n    respected and nothing changes. A value Hermes itself exported earlier — recognisable\n    because it equals ``HERMES_SCRATCH_DIR`` — is re-derived, so a child running under another\n    profile\'s home gets that home\'s scratch dir rather than its parent\'s. Returns True when\n    the vars were (re)written.\n    """\n    ours = env.get(SCRATCH_DIR_MARKER_ENV, "")\n    for key in SCRATCH_TMP_ENV_VARS:\n        value = env.get(key, "").strip()\n        if value and value != ours:\n            return False\n    home = env.get("HERMES_HOME", "").strip()\n    try:\n        scratch = str(get_scratch_dir(_expand_hermes_home(home) if home else get_process_hermes_home()))\n    except (RuntimeError, OSError):\n        # No HERMES_HOME and no resolvable user home (a child env built from nothing on\n        # Windows): there is no scratch dir to point at; the child keeps the OS default.\n        return False\n    for key in SCRATCH_TMP_ENV_VARS:\n        env[key] = scratch\n    env[SCRATCH_DIR_MARKER_ENV] = scratch\n    return True'

class MuxPmBootstrapGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.code = self.root / 'release'
        self.owner = self.root / 'hermes'
        self.home = self.owner / 'profiles' / 'worker'
        self.state = self.owner / 'installs' / hashlib.sha256(str(self.code).encode()).hexdigest()[:16]
        self.venv = self.state / 'environments' / 'abc123' / 'venv'
        self.interpreter = self.venv / 'bin' / 'python'
        for directory in (self.code / '.git', self.home, self.interpreter.parent):
            directory.mkdir(parents=True)
        (self.home / 'logs').mkdir(mode=0o700)
        self.interpreter.write_bytes(b'fixture-python-identity')
        self.interpreter.chmod(0o700)
        (self.venv / 'pyvenv.cfg').write_text('fixture\n')
        self.facts = self.state / 'facts.json'
        self.facts.write_text(json.dumps({'packages': {'venv': {
            'environment': str(self.venv), 'stamp': 'approved-dependency-stamp', 'extras': ['all'],
        }}}))
        self.receipt = self.owner / 'logs' / 'update_receipts' / 'pm-approved-sync.json'
        self.receipt.parent.mkdir(parents=True)
        self.receipt.write_text(json.dumps({'schema': 1, 'kind': 'sync', 'outcome': 'ok',
                                           'exit_code': 0, 'finished_at': '2026-10-19T00:00:00Z'}))
        (self.state / '.install.lock').touch(mode=0o600)
        self.pins = []
        for relative in PM_BOOTSTRAP_SOURCES:
            path = self.code / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture input ' + relative)
            self.pins.append((str(path), self.sha(path)))
        stamp = self.code / 'install-stamp.json'
        stamp.write_text(json.dumps(dict(schemaVersion=2,updateMechanism='external',source='local',
                                        dirty=True,commit='a' * 40)))
        self.pins = [(path, self.sha(stamp) if path == str(stamp) else digest) for path, digest in self.pins]
        self.binding = dict(semantics='reviewed-hermes-pm-bootstrap-v1', ownerHome=str(self.owner),
                            installState=str(self.state), selectedVenv=str(self.venv),
                            interpreter=str(self.interpreter), interpreterSha256=self.sha(self.interpreter),
                            factsSha256=self.sha(self.facts), receiptPath=str(self.receipt),
                            receiptSha256=self.sha(self.receipt), dependencyStamp='approved-dependency-stamp')
        self.payload = dict(codeRoot=str(self.code), home=str(self.home), sourcePins=self.pins,
                            pmBinding=self.binding)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(sys, 'executable', str(self.interpreter)).start()
        mock.patch.object(sys, 'prefix', str(self.venv)).start()
        mock.patch.object(sys, 'version_info', (3, 14, 7)).start()
        mock.patch.dict(os.environ, {'HERMES_HOME': str(self.home)}).start()
        self.guards = []
        self.addCleanup(self.disable_guards)

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def disable_guards(self):
        for guard in self.guards:
            guard.active = False

    def guard(self):
        guard = PmBootstrapGuard(self.payload)
        self.guards.append(guard)
        return guard

    def test_approved_binding_and_official_lazy_guard_stops_before_pm_import(self):
        self.assertEqual(hashlib.sha256(OFFICIAL_PREPARE.encode()).hexdigest(), OFFICIAL_PREPARE_EXCERPT_SHA256)
        namespace = dict(Path=Path, _is_tail_script=lambda *_: False, _METADATA_FLAGS=set())
        parser = types.ModuleType('hermes_cli._parser'); parser.command_argv = lambda argv: argv
        steward = types.ModuleType('hermes_cli.steward')
        steward.read_install_stamp = mock.Mock(side_effect=AssertionError('PM/adoption must not run'))
        exec('from __future__ import annotations\n' + OFFICIAL_PREPARE, namespace)
        guard = self.guard()
        with mock.patch.dict(sys.modules, {'hermes_cli._parser': parser, 'hermes_cli.steward': steward}):
            guard.begin_imports()
            try:
                result = namespace['prepare_launch'](self.code, ['-p', 'worker', 'gateway', 'restart'])
            finally:
                guard.finish_imports()
        self.assertIsNone(result)
        steward.read_install_stamp.assert_not_called()
        self.assertEqual(os.environ['HERMES_DISABLE_LAZY_INSTALLS'], '1')

    def test_exact_official_profile_preparse_remains_target_scoped(self):
        self.assertEqual(hashlib.sha256(OFFICIAL_PREPARSE.encode()).hexdigest(), OFFICIAL_PREPARSE_EXCERPT_SHA256)
        namespace = dict(Path=Path, os=os, sys=sys, re=re, _PROFILE_NAME_RE=r'^[a-z][a-z0-9_-]{0,63}$')
        exec(OFFICIAL_PREPARSE, namespace)
        parser = types.ModuleType('hermes_cli._parser'); parser.top_level_value_flag_sets = lambda: (set(), set())
        profiles = types.ModuleType('hermes_cli.profiles')
        profiles.resolve_profile_env = lambda name: str(self.home) if name == 'worker' else (_ for _ in ()).throw(ValueError('wrong target'))
        guard = self.guard()
        with mock.patch.dict(sys.modules, {'hermes_cli._parser': parser, 'hermes_cli.profiles': profiles}), mock.patch.object(sys, 'argv', ['hermes', '-p', 'worker', 'gateway', 'restart']):
            guard.begin_imports()
            try:
                namespace['_apply_profile_override']()
            finally:
                guard.finish_imports()
            self.assertEqual(sys.argv, ['hermes', 'gateway', 'restart'])
            self.assertEqual(namespace['_explicit_cli_profile'], 'worker')
        self.assertEqual(os.environ['HERMES_HOME'], str(self.home))

    def test_missing_binding_cannot_reach_runtime_imports(self):
        del self.payload['pmBinding']
        with self.assertRaises(ValueError): self.guard()
        with self.assertRaises(ValueError): execute({})

    def test_facts_receipt_inputs_and_running_generation_must_match(self):
        cases = [('factsSha256', '0' * 64), ('receiptSha256', '0' * 64),
                 ('dependencyStamp', 'stale-stamp'), ('interpreterSha256', '0' * 64)]
        for key, value in cases:
            with self.subTest(key=key):
                original = self.binding[key]; self.binding[key] = value
                with self.assertRaises(ValueError): self.guard()
                self.binding[key] = original
        with mock.patch.object(sys, 'prefix', str(self.owner)):
            with self.assertRaises(ValueError): self.guard()
        self.payload['sourcePins'] = self.pins[1:]
        with self.assertRaises(ValueError): self.guard()

    def test_failed_receipt_not_approved_even_when_digest_matches(self):
        self.receipt.write_text(json.dumps({'schema': 1, 'kind': 'sync', 'outcome': 'failed', 'exit_code': 1, 'finished_at': 'x'}))
        self.binding['receiptSha256'] = self.sha(self.receipt)
        with self.assertRaises(ValueError): self.guard()

    def test_known_markers_rejected_without_consuming_or_repairing_them(self):
        markers = [self.code / '.git' / 'hermes-update-pull', self.code / '.hermes-update-zip-swap',
                   self.code / '.update-incomplete', self.code / '.lazy-refresh-incomplete',
                   self.owner / '.hermes-update-in-progress', self.state / 'publication.json',
                   self.state / '.repair-incomplete', self.state / 'source-completion-pending',
                   self.state / 'source-completion-attempts']
        for marker in markers:
            with self.subTest(marker=marker.name):
                marker.write_text('must remain unchanged')
                with self.assertRaises(ValueError): self.guard()
                self.assertEqual(marker.read_text(), 'must remain unchanged')
                marker.unlink()

    def test_publication_drift_after_initial_check_rejected(self):
        guard = self.guard()
        self.facts.write_text(self.facts.read_text() + ' ')
        with self.assertRaises(ValueError): guard.fence()

    def test_import_audit_blocks_exec_sync_and_recovery_writes_sticky(self):
        actions = [lambda: sys.audit('os.exec', '/bad', [], {}),
                   lambda: sys.audit('subprocess.Popen', '/bad', [], None, {}),
                   lambda: self.facts.write_text('replacement'),
                   lambda: (self.code / '.new-source').write_text('replacement')]
        for action in actions:
            with self.subTest(action=action):
                guard = self.guard(); guard.begin_imports()
                try:
                    with self.assertRaises(PermissionError): action()
                finally:
                    guard.active = False
                with self.assertRaises(ValueError): guard.finish_imports()
        self.assertEqual(json.loads(self.facts.read_text())['packages']['venv']['stamp'], 'approved-dependency-stamp')
        self.assertFalse((self.code / '.new-source').exists())

    def test_only_existing_lock_selected_leases_and_logs_permitted_during_import(self):
        guard = self.guard(); guard.begin_imports()
        try:
            fd = os.open(self.state / '.install.lock', os.O_RDWR | os.O_CREAT, 0o600); os.close(fd)
            leases = self.venv.parent / '.leases'; leases.mkdir()
            lease = leases / ('a' * 32); lease.write_text('lease'); lease.unlink()
            log = self.receipt.parent / 'import.log'; log.write_text('nonsecret fixture')
        finally:
            guard.finish_imports()
        self.assertEqual(log.read_text(), 'nonsecret fixture')

    def test_binary_interpreter_is_not_limited_to_source_budget(self):
        self.interpreter.write_bytes(b'X' * (3 * 1024 * 1024))
        self.binding['interpreterSha256'] = self.sha(self.interpreter)
        self.guard().fence()
        self.binding['interpreterSha256'] = '0' * 64
        with self.assertRaises(ValueError): self.guard()

    def test_binary_interpreter_has_finite_budget(self):
        with self.interpreter.open('wb') as handle:
            handle.truncate(256 * 1024 * 1024 + 1)
        # Refuse before hashing the sparse oversized executable.
        with mock.patch('stability_core.adapter_contract.sha256_file') as digest:
            with self.assertRaises(ValueError): self.guard()
        digest.assert_not_called()

    def test_fixed_loader_uses_declared_root_without_ambient_pythonpath_and_never_pyc(self):
        from stability_core.hermes_mux_bridge import prepare_runtime_imports
        from stability_core.hermes_native_route import MUX_RUNTIME_MODULES
        pins = dict(self.pins)
        for name in MUX_RUNTIME_MODULES:
            relative = Path(*name.split('.'))
            path = self.code / relative / '__init__.py' if name in {'hermes_cli', 'gateway'} else self.code / relative.with_suffix('.py')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('FIXED_BYTES = True\n')
            pins[str(path)] = self.sha(path)
        bootstrap = self.code / 'hermes_bootstrap.py'
        bootstrap.write_text('FIXED_BYTES = True\n')
        pins[str(bootstrap)] = self.sha(bootstrap)
        cache = self.code / '__pycache__'; cache.mkdir()
        (cache / 'hermes_bootstrap.cpython-314.pyc').write_bytes(b'untrusted cache')
        with mock.patch.object(sys, 'path', [str(self.root / 'unrelated')]), mock.patch.object(sys, 'meta_path', list(sys.meta_path)):
            origins = prepare_runtime_imports(self.code, tuple((Path(p), d) for p, d in pins.items()))
            self.assertEqual(origins['hermes_bootstrap'], str(bootstrap))
            module = types.ModuleType('hermes_bootstrap')
            sys.meta_path[0].find_spec('hermes_bootstrap', None).loader.exec_module(module)
            self.assertTrue(module.FIXED_BYTES)
            self.assertEqual(sys.path[0], str(self.code))

    def test_preloaded_bootstrap_cannot_bypass_source_loader(self):
        from stability_core.hermes_mux_bridge import prepare_runtime_imports
        with mock.patch.dict(sys.modules, {'hermes_bootstrap': types.ModuleType('hermes_bootstrap')}):
            with self.assertRaises(ValueError): prepare_runtime_imports(self.code, tuple(self.pins))

    def test_official_scratch_export_honors_bridge_temp_without_chmod_or_prune(self):
        scratch = mock.Mock(side_effect=AssertionError('automatic scratch maintenance forbidden'))
        namespace = dict(SCRATCH_TMP_ENV_VARS=('TMPDIR', 'TMP', 'TEMP'),
                         SCRATCH_DIR_MARKER_ENV='HERMES_SCRATCH_DIR', get_scratch_dir=scratch)
        exec('from __future__ import annotations\n' + OFFICIAL_SCRATCH_ENV, namespace)
        os.environ['HERMES_SCRATCH_DIR'] = 'stale-parent-marker'
        guard = self.guard(); guard.begin_imports()
        try:
            self.assertFalse(namespace['apply_scratch_tmp_env'](os.environ))
        finally:
            guard.finish_imports()
        scratch.assert_not_called()
        self.assertEqual(os.environ['TMPDIR'], str(self.home / 'logs'))
        self.assertNotIn('HERMES_SCRATCH_DIR', os.environ)

    def test_source_stamp_is_pinned_and_cannot_erase_external_owner(self):
        stamp = self.code / 'install-stamp.json'
        original = stamp.read_bytes()
        for override in ({'updateMechanism': 'self'}, {'source': 'fallback'}, {'commit': '0' * 40}, {'runtimeDir': '/unapproved'}):
            value = json.loads(original); value.update(override); stamp.write_text(json.dumps(value))
            # Even a new declared digest cannot relax this source-owner contract.
            self.payload['sourcePins'] = [(path, self.sha(stamp) if path == str(stamp) else digest) for path, digest in self.pins]
            with self.subTest(override=override), self.assertRaises(ValueError): self.guard()
        stamp.write_bytes(original)
        self.payload['sourcePins'] = self.pins
        self.guard().fence()

    def test_directory_chmod_may_only_repeat_identical_target_home_bits(self):
        os.chmod(self.home, 0o700)
        guard = self.guard(); guard.begin_imports()
        try:
            os.chmod(self.home, 0o700)
        finally:
            guard.finish_imports()
        for path, mode in ((self.home, 0o755), (self.home / 'logs', 0o755), (self.state, self.state.stat().st_mode & 0o7777),
                           (self.home / 'config-not-created', 0o700)):
            guard = self.guard(); guard.begin_imports()
            try:
                with self.subTest(path=path, mode=mode), self.assertRaises((PermissionError, FileNotFoundError)):
                    os.chmod(path, mode)
            finally:
                guard.active = False
        self.assertEqual(self.home.stat().st_mode & 0o7777, 0o700)

    def factory_fixture(self):
        from stability_core.installation_capability import InstallationFactory
        from stability_core.effect_capability import EffectRequest, EffectOperation
        (self.home / 'config.yaml').write_text('gateway:\n  standalone: false\n')
        source_files = [dict(path=str(Path(path).relative_to(self.code)), sha256=digest)
                        for path, digest in self.pins]
        contract = dict(id='reviewed-fixture-mux', family='hermes', kind='mux',
            semantics='reviewed-hermes-mux-cli-logical-membership-v1', status='reviewed',
            files=source_files, bridgeSha256='a' * 64)
        layout = dict(id='fixture-installation', family='hermes', nodeId='fixture-node', status='qualified',
            ownerUid=os.getuid(), codeRoot=str(self.code), runtimeRoot=str(self.owner),
            contracts=dict(mux=contract['id']), interpreterEntry=str(self.interpreter),
            interpreterSha256=self.binding['interpreterSha256'], cliEntry=str(self.code / 'hermes'),
            cliSha256='b' * 64, muxPeerArgv=['/declared/host-python', '-c', "print({'a': 1})"],
            muxEnvironment=[['HERMES_HOME', '{home}']], socketPath=str(self.owner / 'gateway.sock'),
            hostHome=str(self.owner), pmBinding=copy.deepcopy(self.binding))
        artifact = self.root / 'qualified.json'
        raw = json.dumps(dict(schemaVersion=1, sourceContracts=[contract], installations=[layout])).encode()
        artifact.write_bytes(raw)
        factory = InstallationFactory.from_artifact(artifact, hashlib.sha256(raw).hexdigest(), boot_reader=lambda: 'boot')
        request = EffectRequest('hermes.profile.lifecycle', EffectOperation.HERMES_CLI,
            'hermes-profile:worker', 'fixture-node', 'fixture-node:boot')
        registry = dict(source='db', writeEligible=True, records=[dict(agent_id='fixture-agent', runtime='hermers',
            platform='hermers', execution_adapter='acp', endpoint_ref='hermes-profile:worker',
            status='active', can_receive_dispatch=1)])
        return factory, request, registry

    def test_reviewed_factory_to_immutable_qualification_to_command_to_bridge(self):
        from stability_core.hermes_native_route import MuxRoute
        factory, request, registry = self.factory_fixture()
        result = factory.hermes(request, registry, 'worker')
        self.assertEqual(result.status, 'supported-mux', result)
        self.assertFalse(result.action_authorized)
        q = result.qualification
        self.assertIsInstance(q.pm_binding, tuple)
        route = MuxRoute.__new__(MuxRoute)
        route.q, route.profile = q, 'worker'
        route.peer_identity = dict(pid=42)
        route._pin = ({str(self.home): [1, 2, 3, 4]},)
        route.last_residency = 'served'
        argv, environment, cwd = route.command('restart')
        payload = json.loads(argv[-1])
        self.assertEqual(payload['pmBinding'], self.binding)
        self.assertEqual(payload['profile'], 'worker')
        self.assertEqual(environment['HERMES_HOME'], str(self.home))
        guard = PmBootstrapGuard(payload)
        guard.fence()
        self.facts.write_text(self.facts.read_text() + ' ')
        with self.assertRaises(ValueError): route.command('restart')

    def test_factory_missing_or_invalid_binding_cannot_become_supported(self):
        factory, request, registry = self.factory_fixture()
        layout = factory._manifest['installations'][0]
        del layout['pmBinding']
        self.assertEqual(factory.hermes(request, registry, 'worker').status, 'unknown')
        layout['pmBinding'] = dict(self.binding, receiptSha256='measured-not-approved')
        self.assertEqual(factory.hermes(request, registry, 'worker').status, 'unknown')

    def test_old_qualification_object_can_be_inspected_but_never_commands(self):
        from stability_core.hermes_native_route import MuxRoute
        route = MuxRoute.__new__(MuxRoute)
        route.q = types.SimpleNamespace(pm_binding=())
        self.assertIsNone(route._pm_guard(required=False))
        with self.assertRaises(ValueError): route.command('restart')

    def test_payload_binding_cannot_disagree_with_declared_interpreter(self):
        from stability_core.hermes_native_route import MuxRoute, freeze_mux_pm_binding
        route = MuxRoute.__new__(MuxRoute)
        route.q = types.SimpleNamespace(pm_binding=freeze_mux_pm_binding(self.binding),
            interpreter_entry=self.interpreter, interpreter_sha256='0' * 64, runtime_root=self.owner)
        with self.assertRaises(ValueError): route._pm_guard(required=True)


if __name__ == '__main__':
    unittest.main()
