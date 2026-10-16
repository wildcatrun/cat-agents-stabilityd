"""V2 selected-function offline replay; never an actuator/installation grant.

V1 pins and its 203 cases remain immutable historical evidence. V2 compares
complete policy + repair gate outputs against the old pinned policy with only
independently specified timing input substitutions. No changed-field wildcard.
"""
import __future__
import ast
import copy
import hashlib
import json
import re
from pathlib import Path
import subprocess
import symtable
from types import SimpleNamespace
from . import verify_current_policy_shadow as v1

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT/'tests/fixtures/compat/clock_policy_scope_v2.json'
GATE = ROOT/'tests/fixtures/compat/policy_replay_gate_v2.json'


def digest(value):
    return hashlib.sha256(value).hexdigest()


def load_candidate(source, pin, settings, case, projection):
    if digest(source.encode()) != pin['sourceSha256']:
        raise ValueError('v2 pinned source changed')
    segments = v1.source_segments(source)
    if set(segments) != set(v1.FUNCTIONS) or set(pin['functions']) != set(v1.FUNCTIONS):
        raise ValueError('v2 function inventory changed')
    namespace = {**copy.deepcopy(settings), '__builtins__':v1.SAFE_BUILTINS,
        'List':list, 'os':SimpleNamespace(environ={}),
        'epoch':lambda:case['nowEpoch'], 'ts':lambda:'fixture-time',
        'db_get':lambda _conn,key,default=None:case.get('kv',{}).get(key,default),
        'recent_restart_history':lambda _conn:list(case.get('restartHistory',[])),
        'recent_hermers_gateway_restart_history':lambda _conn:list(case.get('hermersHistory',[])),
        'update_lane_recovery':lambda *_:copy.deepcopy(case['recovery']),
        'mechanical_timing_projection':lambda _conn:copy.deepcopy(projection)}
    allowed=set(namespace)|set(v1.FUNCTIONS)|set(v1.SAFE_BUILTINS)
    nodes=[]
    for name in v1.FUNCTIONS:
        segment=segments[name]
        if digest(segment.encode()) != pin['functions'][name]:
            raise ValueError('v2 pinned policy function changed')
        node=ast.parse(segment).body[0]
        if node.decorator_list:
            raise ValueError('v2 executable definition hook prohibited')
        for default in [*node.args.defaults,*[x for x in node.args.kw_defaults if x is not None]]:
            try:ast.literal_eval(default)
            except (ValueError,TypeError):raise ValueError('v2 executable default prohibited')
        def globals_in(table):
            result={s.get_name() for s in table.get_symbols() if s.is_global() and s.is_referenced()}
            for child in table.get_children():result |= globals_in(child)
            return result
        table=symtable.symtable(segment,'<clock-policy-v2>','exec').get_children()[0]
        if globals_in(table)-allowed:
            raise ValueError('v2 unapproved policy dependency')
        nodes.append(node)
    selected=ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[]))
    exec(compile(selected,'<clock-policy-v2>','exec',flags=__future__.annotations.compiler_flag),namespace)
    return namespace


def output(namespace,case):
    findings=[dict(key=key,severity=case['severity'],component='fixture',message='synthetic')
              for key in (case['keys'] or ['fixture_observation'])]
    policy=namespace['policy_from_findings'](None,findings,copy.deepcopy(case['snapshot']),copy.deepcopy(case['streaks']))
    return {'policy':policy,'repairGate':namespace['build_repair_gate_from_policy'](policy)}


def reference_case(case, *, cooldown_remaining=0, history_remaining=(), hermes_remaining=(), blocked_profiles=()):
    result=copy.deepcopy(case)
    settings={**v1.synthetic_settings(),**case.get('settings',{})}
    now=case['nowEpoch'];cooldown=settings['RESTART_COOLDOWN_SECONDS'];window=settings['RESTART_WINDOW_SECONDS']
    result.setdefault('kv',{})['stabilityd_last_gateway_restart_at']=now-cooldown+cooldown_remaining//1000 if cooldown_remaining else 0
    result['kv']['stabilityd_last_hermers_gateway_restart_at']=0
    result['restartHistory']=[now-window+remaining//1000 for remaining in history_remaining]
    result['hermersHistory']=[{'tsEpoch':now-window+remaining//1000,'profile':''} for remaining in hermes_remaining]
    for profile in blocked_profiles:
        result['snapshot']['hermers']['profiles'].pop(profile)
    return result


def compare(expected, actual, projection):
    actual=copy.deepcopy(actual)
    metadata=actual['policy'].pop('clockDiscipline',None)
    wanted={'state':'available' if projection is not None else 'unavailable-or-quarantined',
            'epoch':projection['epoch'] if projection is not None else None,
            'executionFence':'required-for-time-dependent-effects'}
    if metadata != wanted:
        return {'metadataMismatch':True}
    # Exact equality includes nested lanes, protected scope hints, policy flags,
    # repair gate, unrelated governance and all additive V1 visibility fields.
    return {} if expected==actual else {'policyOrGateMismatch':True}


def replay(root=ROOT, *, candidate_source=None):
    fixture=json.loads((root/'tests/fixtures/compat/clock_policy_scope_v2.json').read_text())
    gate=json.loads((root/'tests/fixtures/compat/policy_replay_gate_v2.json').read_text())
    if gate != {'schemaVersion':2,'currentGate':'clock-policy-scope-v2',
                'fixture':'tests/fixtures/compat/clock_policy_scope_v2.json',
                'historicalGate':'current-policy-shadow-v1','automaticActivation':False}:
        raise ValueError('policy gate version selection refused')
    if fixture.get('schemaVersion') != 2 or fixture.get('approvedNewDependency') != 'mechanical_timing_projection' or fixture.get('approvedNewField') != 'clockDiscipline' or fixture.get('automaticActivation') is not False:
        raise ValueError('clock scope version refused')
    old_path=root/'tests/fixtures/compat/current_policy_shadow_v1.json'
    if digest(old_path.read_bytes()) != fixture['v1FixtureSha256']:
        raise ValueError('historical fixture drift')
    old=json.loads(old_path.read_text())
    historical=subprocess.check_output(['git','show',old['candidateCommit']+':bin/cat_agents_stabilityd.py'],cwd=root,text=True,timeout=10)
    source=candidate_source if candidate_source is not None else (root/'bin/cat_agents_stabilityd.py').read_text()
    cases=v1.scenarios(root)
    if len(cases)!=203:raise ValueError('historical scenario inventory changed')
    differences=[];evaluated=0
    def evaluate(name,case,projection,reference):
        nonlocal evaluated
        settings={**v1.synthetic_settings(),**case.get('settings',{})}
        prior=output(v1.load_selected(historical,old['pins']['candidate'],settings,reference),reference)
        current=output(load_candidate(source,fixture['candidate'],settings,case,projection),case)
        difference=compare(prior,current,projection)
        if difference:differences.append({'scenario':name,**difference})
        evaluated+=1
        return current
    for case in cases:
        evaluate(case['name']+'/clock-unavailable',case,None,case)
        evaluate(case['name']+'/clock-available-empty',case,
                 {'windows':{},'history':{},'epoch':'fixture-clock-epoch-1'},reference_case(case))
    by_name={case['name']:case for case in cases}
    explicit=[]
    for scenario in fixture['clockScenarios']:
        case=copy.deepcopy(by_name[scenario['baseCase']])
        case['nowEpoch']=scenario['wallEpoch']
        case['kv']={'stabilityd_last_gateway_restart_at':scenario['legacyRestartEpoch']}
        projection=scenario['projection']
        reference=case if projection is None else reference_case(case,
            cooldown_remaining=scenario['remainingMs'],history_remaining=scenario.get('historyRemainingMs',()))
        settings={**v1.synthetic_settings(),**case.get('settings',{})}
        legacy=output(v1.load_selected(historical,old['pins']['candidate'],settings,case),case)
        if legacy['policy']['canRestartGateway'] is not scenario['expectedLegacyCanRestart']:
            differences.append({'scenario':scenario['name'],'legacyExpectationMismatch':True})
        actual=evaluate(scenario['name'],case,projection,reference)
        if actual['policy']['canRestartGateway'] is not scenario['expectedCandidateCanRestart']:
            differences.append({'scenario':scenario['name'],'explicitAdmissionMismatch':True})
        explicit.append({'scenario':scenario['name'],'candidateCanRestart':actual['policy']['canRestartGateway'],
                         'legacyCandidateCanRestart':legacy['policy']['canRestartGateway'],
                         'clockState':actual['policy']['clockDiscipline']['state']})
    hermes=fixture['hermesProfileScenario']
    registry=hermes['runtimeAgents']
    if type(registry) is not list or not 2 == len(registry):
        raise ValueError('synthetic registry shape refused')
    profiles={}
    for row in registry:
        endpoint=row.get('endpoint_ref','')
        if row.get('runtime') != 'hermes_acp' or not re.fullmatch('hermes-profile:[a-z][a-z0-9_]{0,63}',endpoint):
            raise ValueError('synthetic registry scope refused')
        profile=endpoint.split(':',1)[1]
        if profile in profiles:raise ValueError('synthetic registry duplicate')
        profiles[profile]={'active':False,'unit':'hermes-gateway-'+profile+'.service'}
    cooling=hermes['coolingProfile']
    if cooling not in profiles:raise ValueError('synthetic cooling profile missing')
    hermes_results=[]
    for phase in hermes['phases']:
        case=copy.deepcopy(by_name[hermes['baseCase']])
        case['snapshot']['hermers']['profiles']=copy.deepcopy(profiles)
        remaining=[hermes['historyRemainingMs']]*phase['globalHistoryCount']
        projection={'windows':{'hermes.gateway:'+cooling:hermes['remainingMs']},
                    'history':{'hermes.gateway.history':remaining},'epoch':'fixture-hermes-clock-epoch'}
        reference=reference_case(case,hermes_remaining=remaining,blocked_profiles=(cooling,))
        actual=evaluate(phase['name'],case,projection,reference)
        policy=actual['policy']
        eligible=[row['profile'] for row in policy['hermersGatewayRestartCandidateProfiles']]
        expected_eligible=sorted(set(profiles)-{cooling})
        if (eligible != expected_eligible
                or policy['canRestartHermersGateway'] is not phase['expectedCanRestart']
                or policy['hermersGatewayRestartRemaining'] != max(0,v1.synthetic_settings()['MAX_RESTARTS_PER_WINDOW']-len(remaining))):
            differences.append({'scenario':phase['name'],'perProfileOrGlobalHistoryMismatch':True})
        hermes_results.append({'scenario':phase['name'],'eligibleProfiles':eligible,
            'coolingProfile':cooling,'globalHistoryCount':len(remaining),
            'remainingGlobalBudget':policy['hermersGatewayRestartRemaining'],
            'candidateCanRestart':policy['canRestartHermersGateway']})
    return {'schemaVersion':2,'gate':'clock-policy-scope-v2','executionMode':'offline-selected-policy-replay',
        'historicalScenarioCount':203,'matrixEvaluations':406,'totalEvaluations':evaluated,
        'status':'compatible-in-declared-clock-scope' if not differences else 'differences-require-review',
        'differences':differences,'explicitClockResults':explicit,'hermesProfileResults':hermes_results,'sourcePin':fixture['candidate'],
        'automaticActivation':False,'actuatorExecution':False,'collectorExecution':False,
        'authority':'none; actual effects require fresh matching clock epoch and existing authorization gates'}


if __name__=='__main__':
    result=replay();print(json.dumps(result,indent=2));raise SystemExit(bool(result['differences']))
