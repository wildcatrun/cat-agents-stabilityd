"""Pinned offline policy replay, never a live shadow/service qualification."""
from __future__ import annotations
import argparse
import __future__
import ast
import builtins
import copy
import hashlib
from functools import lru_cache
import json
import subprocess
import symtable
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'tests/fixtures/compat/current_policy_shadow_v1.json'
FUNCTIONS = ('max_severity', 'resource_pressure_active', 'auth_finding_is_pressure',
             'hot', 'sustained', 'build_lane_policy', 'policy_from_findings',
             'build_repair_gate_from_policy')
STUBS = {'epoch', 'ts', 'db_get', 'recent_restart_history',
         'recent_hermers_gateway_restart_history', 'update_lane_recovery'}
SAFE_BUILTINS = {name: getattr(builtins, name) for name in
                 ('str', 'bool', 'dict', 'int', 'any', 'all', 'sorted', 'isinstance',
                  'len', 'max', 'min', 'set', 'list', 'tuple', 'float')}

def compare_policy_outputs(before, after, permitted_added):
    added = set(after['policy']) - set(before['policy'])
    return {'added': sorted(added - set(permitted_added)),
            'removed': sorted(set(before['policy']) - set(after['policy'])),
            'changed': sorted(key for key in set(before['policy']) & set(after['policy'])
                              if before['policy'][key] != after['policy'][key]),
            'repairGateChanged': before['repairGate'] != after['repairGate']}

@lru_cache(maxsize=2)
def source_segments(source):
    lines = source.splitlines(keepends=True)
    return {node.name: ''.join(lines[node.lineno-1:node.end_lineno]).rstrip('\n')
            for node in ast.parse(source).body
            if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS}

def synthetic_settings():
    """Explicit common input, deliberately does not evaluate runtime env parsing."""
    values = dict(POLICY_TTL_SECONDS=180, RESTART_COOLDOWN_SECONDS=1800,
                  RESTART_WINDOW_SECONDS=3600, MAX_RESTARTS_PER_WINDOW=3,
                  ACTION_STREAK_THRESHOLD=3, HERMERS_GATEWAY_RESTART_LIMIT=2,
                  HERMERS_LSP_IDLE_SECONDS=14400, SOFT_RESCUE_STREAK_THRESHOLD=20,
                  CONTROL_PLANE_BACKPRESSURE_SECONDS=1800,
                  CRON_MAX_CONCURRENCY_NORMAL=3, CRON_MAX_CONCURRENCY_DEGRADED=1,
                  CRON_RECOVERY_OPEN_HEALTHY_STREAK=10, AUTH_WARN_SECONDS=259200,
                  AUTH_CRITICAL_SECONDS=86400, AUTH_OPENCLAW_PROBE_TTL_SECONDS=900,
                  AUTH_OPENCLAW_PROBE_NEAR_TTL_SECONDS=60,
                  AUTH_OPENCLAW_PROBE_URGENT_TTL_SECONDS=30,
                  AUTH_OPENCLAW_PROBE_URGENT_WINDOW_SECONDS=900)
    for name in ('HERMERS_ACP_ORPHAN_REAP_ENABLED', 'HERMERS_GATEWAY_RESTART_ENABLED',
                 'HERMERS_LSP_IDLE_REAP_ENABLED', 'HERMERS_PROFILE_MODE_ACTUATE_ENABLED',
                 'CRON_MUTATION_ENABLED', 'GATEWAY_RESTART_ACTUATOR_SUPPORTED',
                 'GATEWAY_RESTART_ENABLED', 'HERMERS_PROFILE_MODE_ENABLED',
                 'HERMERS_PROFILE_MODE_START_ENABLED', 'LEASE_REAP_ENABLED',
                 'SESSION_RESET_ENABLED', 'SOFT_GATEWAY_RESTART_ENABLED',
                 'SOFT_RESCUE_RESTART_ENABLED'):
        values[name] = True
    values['SEVERITY_RANK'] = {'ok': 0, 'info': 1, 'warning': 2, 'high': 3, 'critical': 4}
    values['CONTROL_PLANE_DIRECT_SESSION_KEYS'] = {'agent:main:fixture:direct:synthetic'}
    values['RESOURCE_PRESSURE_KEYS'] = {'gateway_resource_incident', 'gateway_resource_saturation',
        'gateway_resource_pressure', 'gateway_swap_saturation', 'gateway_swap_pressure',
        'gateway_memory_growth', 'system_memory_saturation', 'system_memory_pressure',
        'system_swap_saturation', 'system_swap_pressure', 'system_commit_saturation',
        'system_commit_pressure', 'disk_pressure'}
    return values

def load_selected(source, pin, settings, case):
    if hashlib.sha256(source.encode()).hexdigest() != pin['sourceSha256']:
        raise ValueError('pinned source changed')
    segments = source_segments(source)
    if set(segments) != set(FUNCTIONS) or set(pin['functions']) != set(FUNCTIONS):
        raise ValueError('policy function inventory changed')
    namespace = {**copy.deepcopy(settings), '__builtins__': SAFE_BUILTINS,
                 'List': list, 'os': SimpleNamespace(environ={}),
                 'epoch': lambda: case['nowEpoch'], 'ts': lambda: 'fixture-time',
                 'db_get': lambda _conn, key, default=None: case.get('kv', {}).get(key, default),
                 'recent_restart_history': lambda _conn: list(case.get('restartHistory', [])),
                 'recent_hermers_gateway_restart_history': lambda _conn: list(case.get('hermersHistory', [])),
                 'update_lane_recovery': lambda *_: copy.deepcopy(case['recovery'])}
    allowed = set(namespace) | set(FUNCTIONS) | set(SAFE_BUILTINS)
    nodes = []
    for name in FUNCTIONS:
        segment = segments[name]
        if hashlib.sha256(segment.encode()).hexdigest() != pin['functions'][name]:
            raise ValueError('pinned policy function changed')
        node = ast.parse(segment).body[0]
        if node.decorator_list:
            raise ValueError('executable definition hooks prohibited')
        for default in [*node.args.defaults, *[x for x in node.args.kw_defaults if x is not None]]:
            try: ast.literal_eval(default)
            except (ValueError, TypeError): raise ValueError('executable definition hooks prohibited')
        table = symtable.symtable(segment, '<policy>', 'exec').get_children()[0]
        def globals_in(table):
            names = {s.get_name() for s in table.get_symbols() if s.is_global() and s.is_referenced()}
            for child in table.get_children():
                names |= globals_in(child)
            return names
        if globals_in(table) - allowed:
            raise ValueError('unapproved policy dependency')
        nodes.append(node)
    selected = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(selected, '<hash-pinned-offline-policy>', 'exec', flags=__future__.annotations.compiler_flag), namespace)
    return namespace

def scenarios(root):
    golden = json.loads((root / 'tests/fixtures/compat/cli_policy_golden_v1.json').read_text())
    result = []
    for original in golden['cases']:
        case = copy.deepcopy(original['input'])
        case.update(name='golden/' + original['name'], snapshot={'gateway': case['gateway'],
                                                               'cron': {'storageStatus': {'storage': 'json'}}})
        case['kv'] = {'stabilityd_last_gateway_restart_at': case.get('lastGatewayRestartAt', 0)}
        case['restartHistory'] = [1, 1, 1] if case.get('restartStorm') else []
        case['settings'] = {'GATEWAY_RESTART_ENABLED': case.get('gatewayRestartEnabled', True)}
        result.append(case)
    base = copy.deepcopy(result[0])
    pressure_groups = {'hard-fault': ['gateway_service_down'], 'cron': ['cron_expired_leases'],
        'session': ['session_problem_backlog'], 'channel': ['telegram_fixture_consumer_lag'],
        'provider': ['telegram_provider_network_errors'], 'resource': ['system_commit_saturation'],
        'auth': ['codex_cli_oauth_access_expired'], 'hermers': ['hermers_gateway_service_down'],
        'combined-rescue': ['cron_expired_leases', 'session_problem_backlog', 'system_memory_saturation']}
    for group, keys in pressure_groups.items():
        for severity in ('warning', 'high', 'critical'):
            for phase in ('cold', 'hot', 'cooldown', 'storm', 'startup', 'disabled', 'sqlite'):
                case = copy.deepcopy(base)
                case.update(name=f'matrix/{group}/{severity}/{phase}', keys=keys, severity=severity,
                            streaks={key: {'count': 20 if phase != 'cold' else 0} for key in keys}, kv={},
                            restartHistory=[], hermersHistory=[], settings={})
                if phase == 'cooldown': case['kv']['stabilityd_last_gateway_restart_at'] = case['nowEpoch'] - 1
                if phase == 'storm': case['restartHistory'] = [case['nowEpoch'] - 3] * 3
                if phase == 'startup': case['snapshot']['gateway']['startupGraceActive'] = True
                if phase == 'disabled': case['settings'].update(GATEWAY_RESTART_ENABLED=False, HERMERS_GATEWAY_RESTART_ENABLED=False)
                if phase == 'sqlite': case['snapshot']['cron']['storageStatus']['storage'] = 'sqlite'
                if group == 'hard-fault': case['snapshot']['gateway'].update(active=False, portOk=False)
                if group == 'hermers': case['snapshot']['hermers'] = {'profiles': {'fixture': {'active': False}}}
                result.append(case)
    for name, settings, storage in (
            ('lease-off-json', {'LEASE_REAP_ENABLED': False}, 'json'),
            ('lease-off-sqlite', {'LEASE_REAP_ENABLED': False}, 'sqlite'),
            ('lease-on-sqlite', {'LEASE_REAP_ENABLED': True}, 'sqlite'),
            ('mode-off-actuate-on', {'HERMERS_PROFILE_MODE_ENABLED': False,
                                    'HERMERS_PROFILE_MODE_ACTUATE_ENABLED': True}, 'json'),
            ('mode-on-actuate-off', {'HERMERS_PROFILE_MODE_ENABLED': True,
                                    'HERMERS_PROFILE_MODE_ACTUATE_ENABLED': False,
                                    'HERMERS_PROFILE_MODE_START_ENABLED': False}, 'json')):
        case = copy.deepcopy(base)
        case.update(name='flags/' + name, settings=settings)
        case['snapshot']['cron']['storageStatus']['storage'] = storage
        result.append(case)
    if len(result) > 256 or len({c['name'] for c in result}) != len(result):
        raise ValueError('scenario budget/identity invalid')
    return result

def replay(root=ROOT, *, baseline_source=None, candidate_source=None):
    fixture = json.loads((root / 'tests/fixtures/compat/current_policy_shadow_v1.json').read_text())
    baseline_source = baseline_source if baseline_source is not None else subprocess.check_output(
        ['git', 'show', fixture['baselineCommit'] + ':bin/cat_agents_stabilityd.py'], cwd=root, text=True, timeout=10)
    candidate_source = candidate_source if candidate_source is not None else (root / 'bin/cat_agents_stabilityd.py').read_text()
    cases = scenarios(root)
    differences, extensions = [], []
    for case in cases:
        outputs = {}
        for kind, source in (('baseline', baseline_source), ('candidate', candidate_source)):
            namespace = load_selected(source, fixture['pins'][kind],
                                      {**synthetic_settings(), **case.get('settings', {})}, case)
            findings = [{'key': key, 'severity': case['severity'], 'component': 'fixture', 'message': 'synthetic'}
                        for key in (case['keys'] or ['fixture_observation'])]
            policy = namespace['policy_from_findings'](None, findings, copy.deepcopy(case['snapshot']), copy.deepcopy(case['streaks']))
            outputs[kind] = {'policy': policy, 'repairGate': namespace['build_repair_gate_from_policy'](policy)}
        before, after = outputs['baseline'], outputs['candidate']
        added = set(after['policy']) - set(before['policy'])
        difference = compare_policy_outputs(before, after, fixture['permittedAddedFields'])
        if added: extensions.append({'scenario': case['name'], 'fields': sorted(added),
                                     'values': {key: after['policy'][key] for key in sorted(added)}})
        if any(difference.values()):
            differences.append({'scenario': case['name'], **difference})
    return {'schemaVersion': 1, 'executionMode': 'offline-policy-replay',
            'baselineCommit': fixture['baselineCommit'], 'candidateSourceCommit': fixture['candidateCommit'],
            'sourcePins': fixture['pins'], 'scenarioCount': len(cases),
            'extensionReview': fixture['extensionReview'],
            'inputMatrixSha256': hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'syntheticSettingsSha256': hashlib.sha256(json.dumps(synthetic_settings(), sort_keys=True,
                separators=(',', ':'), default=lambda value: sorted(value)).encode()).hexdigest(),
            'status': 'compatible-in-declared-offline-scope' if not differences else 'differences-require-review',
            'differences': differences, 'declaredExtensions': extensions,
            'automaticActivation': False, 'collectorExecution': False, 'actuatorExecution': False,
            'coverage': ['policy_from_findings', 'full lane policy', 'repair gate', 'synthetic restart/cooldown/storm/startup inputs'],
            'excluded': ['runtime environment/config parsing', 'fresh observations', 'actual protected registry',
                         'authorization execution', 'latency qualification', 'live shadow', 'service rollback']}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    result = replay(args.root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not result['differences'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
