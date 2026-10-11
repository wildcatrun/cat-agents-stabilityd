"""Pure monotonic observation-round budgets; never grants actuator authority.

Nine collectors retain their independent 60s cap. This is an admission and
cooperative deadline contract, NOT a 30s loop SLO or a mechanism to interrupt
kernel fsync, worker cleanup, or an already executing external side effect.
The caller must preserve its existing fatal worker-cleanup fence independently.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import os
import threading
import re
import time
from typing import Callable, Mapping

COMPONENTS = ('gateway', 'cron', 'session', 'channel', 'hermers', 'auth',
              'resource', 'config', 'desired_state')
COMPONENT_CAP_MS = 60000
TOTAL_NAME = 'CAT_AGENTS_STABILITY_ROUND_TOTAL_MS'
CLEANUP_NAME = 'CAT_AGENTS_STABILITY_ROUND_CLEANUP_RESERVE_MS'
PARENT_NAME = 'CAT_AGENTS_STABILITY_ROUND_PARENT_RESERVE_MS'


class RoundBudgetError(ValueError):
    """Fixed codes only: do not echo configuration or source clock values."""


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RoundBudgetError('round-budget-config-invalid')
    return value


@dataclass(frozen=True)
class BudgetConfig:
    total_ms: int = 600000
    cleanup_reserve_ms: int = 2000
    parent_reserve_ms: int = 30000
    source: str = 'default'

    def __post_init__(self):
        _integer(self.total_ms, 588000, 3600000)
        _integer(self.cleanup_reserve_ms, 2000, 30000)
        _integer(self.parent_reserve_ms, 30000, 120000)
        if self.source not in ('default', 'environment'):
            raise RoundBudgetError('round-budget-source-invalid')
        minimum = len(COMPONENTS) * (COMPONENT_CAP_MS + self.cleanup_reserve_ms) + self.parent_reserve_ms
        if self.total_ms < minimum:
            raise RoundBudgetError('round-budget-reserve-underfunded')


def parse_config(environment: Mapping[str, object]) -> BudgetConfig:
    """Read three known values; perform a names-only schema check of our prefix.

    Unrelated environment values (including credentials/legacy settings) are
    never read. Unknown own-namespace names fail with a fixed redacted code.
    """
    allowed = {TOTAL_NAME, CLEANUP_NAME, PARENT_NAME}
    for name in environment:
        if isinstance(name, str) and name.startswith("CAT_AGENTS_STABILITY_ROUND_") and name not in allowed:
            raise RoundBudgetError("round-budget-config-field-unknown")
    values = [600000, 2000, 30000]
    configured = False
    missing = object()
    for index, name in enumerate((TOTAL_NAME, CLEANUP_NAME, PARENT_NAME)):
        value = environment.get(name, missing)
        if value is missing:
            continue
        configured = True
        if type(value) is int:
            values[index] = value
        elif isinstance(value, str) and len(value) <= 10 and re.fullmatch(r'[0-9]+', value):
            values[index] = int(value)
        else:
            raise RoundBudgetError('round-budget-config-invalid')
    return BudgetConfig(*values, source='environment' if configured else 'default')


@dataclass(frozen=True)
class Allocation:
    component: str
    status: str
    reason: str
    elapsed_ms: int | None
    remaining_ms: int | None
    allocated_ms: int
    future_reserve_ms: int
    cleanup_reserve_ms: int
    parent_reserve_ms: int
    deadline_monotonic: float | None
    source: str
    clock_valid: bool

    def evidence(self):
        return {'component':self.component, 'status':self.status, 'reason':self.reason,
                'elapsedMs':self.elapsed_ms, 'remainingMs':self.remaining_ms,
                'allocatedMs':self.allocated_ms, 'futureReserveMs':self.future_reserve_ms,
                'cleanupReserveMs':self.cleanup_reserve_ms, 'parentReserveMs':self.parent_reserve_ms,
                'source':self.source, 'clockValid':self.clock_valid,
                'coverage':False if self.status == 'skip' else None,
                'authorityGranted':False}


class RoundBudget:
    """One fixed-sequence owned context. A skip does not consume reserved future time.

    allocate -> collector/cleanup (or skip) -> finish. The caller converts skip
    to typed unknown data. finish never certifies cleanup or clears its fence.
    The admission rule is conservative: preserve complete future caps even if
    the current collector has to receive a shorter deadline or be skipped.
    """
    def __init__(self, config: BudgetConfig | None = None, *, clock: Callable[[], float] = time.monotonic):
        self.config = BudgetConfig() if config is None else config
        if not isinstance(self.config, BudgetConfig) or not callable(clock):
            raise RoundBudgetError('round-budget-context-invalid')
        self._owner_pid = os.getpid()
        self._owner_thread = threading.get_ident()
        self.clock = clock
        self._start = None
        self._last = None
        self._clock_invalid = False
        self._index = 0
        self._active = None
        self._history = []
        self._start = self._sample()
        self.deadline_monotonic = (self._start + self.config.total_ms / 1000
                                   if self._start is not None else None)
        if self.deadline_monotonic is not None and (not math.isfinite(self.deadline_monotonic)
                or self.deadline_monotonic <= self._start):
            self._clock_invalid = True
            self.deadline_monotonic = None

    def __copy__(self):
        raise RoundBudgetError('round-budget-context-copy-forbidden')

    def __deepcopy__(self, memo):
        raise RoundBudgetError('round-budget-context-copy-forbidden')

    def _check_owner(self):
        if os.getpid() != self._owner_pid or threading.get_ident() != self._owner_thread:
            raise RoundBudgetError('round-budget-owner-context-required')

    def _sample(self):
        if self._clock_invalid:
            return None
        try:
            value = self.clock()
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError()
            value = float(value)
            if math.ulp(value) > 0.001:
                raise ValueError()
            if self._last is not None and value < self._last:
                raise ValueError()
            self._last = value
            return value
        except Exception:
            self._clock_invalid = True
            return None

    def _time(self):
        now = self._sample()
        if now is None or self._start is None:
            return None, None, None
        # ceil spent/floor remaining avoids donating fractional milliseconds.
        elapsed = math.ceil((now - self._start) * 1000)
        return now, elapsed, max(0, self.config.total_ms - elapsed)

    def allocate(self, component: str) -> Allocation:
        self._check_owner()
        if self._active is not None or self._index >= len(COMPONENTS) or component != COMPONENTS[self._index]:
            raise RoundBudgetError('round-budget-owned-sequence-required')
        now, elapsed, remaining = self._time()
        future = (len(COMPONENTS) - self._index - 1) * (COMPONENT_CAP_MS + self.config.cleanup_reserve_ms)
        available = (remaining - future - self.config.cleanup_reserve_ms - self.config.parent_reserve_ms
                     if remaining is not None else 0)
        allocated = max(0, min(COMPONENT_CAP_MS, available))
        reason = ('clock-invalid' if now is None else 'future-reserve-preserved' if allocated == 0 else
                  'component-cap' if allocated == COMPONENT_CAP_MS else 'remaining-round-budget')
        decision = Allocation(component, 'allocated' if allocated else 'skip', reason,
                              elapsed, remaining, allocated, future, self.config.cleanup_reserve_ms,
                              self.config.parent_reserve_ms, now + allocated / 1000 if allocated and now is not None else None,
                              self.config.source, now is not None)
        self._active = decision
        return decision

    def finish(self, decision: Allocation):
        self._check_owner()
        if self._active is not decision:
            raise RoundBudgetError('round-budget-owned-allocation-required')
        now, elapsed, remaining = self._time()
        report = decision.evidence()
        report.update(finishedElapsedMs=elapsed, finishedRemainingMs=remaining,
                      finishedClockValid=now is not None, cleanupQualification='caller-owned-fatal-fence')
        self._history.append(report)
        self._active = None
        self._index += 1
        return dict(report)

    def check_parent(self, stage: str):
        self._check_owner()
        if stage not in ('policy', 'actuation', 'publication', 'return'):
            raise RoundBudgetError('round-budget-parent-stage-invalid')
        now, elapsed, remaining = self._time()
        available = now is not None and remaining > 0
        return {'stage':stage, 'status':'available' if available else 'unknown',
                'reason':'cooperative-only' if available else 'clock-invalid' if now is None else 'round-deadline-exhausted',
                'elapsedMs':elapsed, 'remainingMs':remaining, 'parentReserveMs':self.config.parent_reserve_ms,
                'source':self.config.source, 'clockValid':now is not None,
                'authorityGranted':False, 'canInterruptExternalSideEffect':False}

    def evidence(self):
        self._check_owner()
        now, elapsed, remaining = self._time()
        return {'scope':'collector-round-cooperative-budget', 'totalMs':self.config.total_ms,
                'componentCapMs':COMPONENT_CAP_MS, 'cleanupReserveMs':self.config.cleanup_reserve_ms,
                'parentReserveMs':self.config.parent_reserve_ms, 'elapsedMs':elapsed,
                'remainingMs':remaining, 'source':self.config.source, 'clockValid':now is not None,
                'completedComponents':self._index, 'componentCount':len(COMPONENTS),
                'allocations':[dict(item) for item in self._history],
                'authorityGranted':False, 'loopIntervalIsSlo':False,
                'enforcement':'collector-deadlines-and-parent-cooperative-checks'}
