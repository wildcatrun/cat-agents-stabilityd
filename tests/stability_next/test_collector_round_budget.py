import dataclasses
import copy
import os
import threading
import math
import unittest

from stability_core.collector_budget import (Allocation, BudgetConfig, COMPONENTS, RoundBudget,
    RoundBudgetError, parse_config, TOTAL_NAME, CLEANUP_NAME, PARENT_NAME)


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value
    def advance(self, ms): self.value += ms / 1000


class CollectorRoundBudgetTests(unittest.TestCase):
    def test_default_preserves_all_nine_full_caps_cleanup_and_parent(self):
        clock = Clock(); budget = RoundBudget(clock=clock)
        for component in COMPONENTS:
            allocation = budget.allocate(component)
            self.assertEqual(allocation.allocated_ms, 60000)
            clock.advance(62000)
            budget.finish(allocation)
        self.assertEqual(budget.evidence()['remainingMs'], 42000)
        self.assertEqual(budget.check_parent('publication')['status'], 'available')
        self.assertFalse(budget.evidence()['loopIntervalIsSlo'])

    def test_legal_cold_collector_near_sixty_seconds_retains_future(self):
        clock = Clock(); budget = RoundBudget(clock=clock)
        first = budget.allocate('gateway')
        clock.advance(59990)
        clock.advance(2000)
        budget.finish(first)
        second = budget.allocate('cron')
        self.assertEqual(second.allocated_ms, 60000)
        self.assertGreaterEqual(second.remaining_ms - second.allocated_ms,
            second.future_reserve_ms + second.cleanup_reserve_ms + second.parent_reserve_ms)

    def test_first_admission_exhausted_skips_current_and_protects_next(self):
        clock = Clock(); budget = RoundBudget(clock=clock)
        clock.advance(80000)  # earlier parent work consumed spare and current allowance
        first = budget.allocate('gateway')
        self.assertEqual(first.status, 'skip')
        self.assertEqual(first.reason, 'future-reserve-preserved')
        self.assertFalse(first.evidence()['coverage'])
        budget.finish(first)
        second = budget.allocate('cron')
        self.assertEqual(second.allocated_ms, 54000)
        budget.finish(second)
        # Skip spent no new time, so the later independent component regains cap.
        self.assertEqual(budget.allocate('session').allocated_ms, 60000)

    def test_partial_current_budget_does_not_borrow_future_reserves(self):
        clock = Clock(); budget = RoundBudget(clock=clock)
        clock.advance(30000)
        item = budget.allocate('gateway')
        self.assertEqual(item.allocated_ms, 42000)
        self.assertEqual(item.reason, 'remaining-round-budget')
        clock.advance(44000)
        budget.finish(item)
        self.assertEqual(budget.allocate('cron').allocated_ms, 60000)

    def test_deadline_exhaustion_is_unknown_and_not_side_effect_interrupt(self):
        clock = Clock(); budget = RoundBudget(clock=clock)
        clock.advance(600000)
        result = budget.check_parent('actuation')
        self.assertEqual(result['status'], 'unknown')
        self.assertFalse(result['canInterruptExternalSideEffect'])
        self.assertFalse(result['authorityGranted'])

    def test_invalid_and_backwards_clock_fail_closed_without_values(self):
        for value in (True, None, float('nan'), float('inf'), -1, 1e308):
            with self.subTest(value=value):
                budget = RoundBudget(clock=lambda: value)
                item = budget.allocate('gateway')
                self.assertEqual(item.reason, 'clock-invalid')
                self.assertEqual(item.allocated_ms, 0)
                budget.finish(item)
                self.assertIsNone(budget.evidence()['remainingMs'])
        clock = Clock(); clock.value = 10
        budget = RoundBudget(clock=clock)
        clock.value = 9
        self.assertEqual(budget.allocate('gateway').reason, 'clock-invalid')
        clock.value = 100
        self.assertFalse(budget.evidence()['clockValid'])

    def test_clock_exception_redacted(self):
        def fail(): raise RuntimeError('credential-sensitive-message')
        budget = RoundBudget(clock=fail)
        self.assertNotIn('credential', repr(budget.evidence()))

    def test_strict_numeric_config_and_underfunded_reserves(self):
        for value in (True, False, 600000.0, float('nan'), float('inf'), -1, 587999, 3600001):
            with self.subTest(value=value), self.assertRaises(RoundBudgetError):
                BudgetConfig(total_ms=value)
        with self.assertRaisesRegex(RoundBudgetError, 'underfunded'):
            BudgetConfig(cleanup_reserve_ms=30000)
        for value in (None, '-1', '+600000', ' 600000', 'nan', 'inf', '600000.0', 'SECRET', '9' * 100):
            with self.subTest(value=value), self.assertRaises(RoundBudgetError) as caught:
                parse_config({TOTAL_NAME:value})
            self.assertNotIn(str(value), str(caught.exception))
        self.assertEqual(parse_config({TOTAL_NAME:'600000'}).source, 'environment')
        self.assertEqual(parse_config({TOTAL_NAME:600000}).total_ms, 600000)

    def test_context_copy_and_cross_instance_cannot_consume_active_token(self):
        budget = RoundBudget(clock=Clock())
        allocation = budget.allocate('gateway')
        for clone in (copy.copy, copy.deepcopy):
            with self.assertRaisesRegex(RoundBudgetError, 'copy-forbidden'):
                clone(budget)
        other = RoundBudget(clock=Clock())
        with self.assertRaisesRegex(RoundBudgetError, 'owned-allocation-required'):
            other.finish(allocation)
        self.assertEqual(budget.finish(allocation)['component'], 'gateway')
        self.assertEqual(budget.evidence()['completedComponents'], 1)
        self.assertEqual(other.evidence()['completedComponents'], 0)

    def test_other_thread_rejects_every_context_entry_without_mutation(self):
        budget = RoundBudget(clock=Clock())
        allocation = budget.allocate('gateway')
        codes = []
        def worker():
            for operation in (lambda: budget.allocate('cron'), lambda: budget.finish(allocation),
                              lambda: budget.check_parent('policy'), budget.evidence):
                try:
                    operation()
                except RoundBudgetError as error:
                    codes.append(str(error))
                else:
                    codes.append('UNEXPECTED-SUCCESS')
        thread = threading.Thread(target=worker)
        thread.start(); thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(codes, ['round-budget-owner-context-required'] * 4)
        self.assertEqual(budget.finish(allocation)['component'], 'gateway')
        self.assertEqual(budget.evidence()['completedComponents'], 1)

    @unittest.skipUnless(hasattr(os, 'fork'), 'actual fork unavailable')
    def test_real_fork_child_rejects_context_and_parent_keeps_original(self):
        budget = RoundBudget(clock=Clock())
        allocation = budget.allocate('gateway')
        reader, writer = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(reader)
            codes = []
            try:
                for operation in (lambda: budget.allocate('cron'), lambda: budget.finish(allocation),
                                  lambda: budget.check_parent('publication'), budget.evidence):
                    try:
                        operation()
                    except RoundBudgetError as error:
                        codes.append(str(error))
                    else:
                        codes.append('UNEXPECTED-SUCCESS')
                os.write(writer, '|'.join(codes).encode())
                os._exit(0)
            except BaseException:
                os._exit(3)
        os.close(writer)
        try:
            proof = os.read(reader, 4096).decode().split('|')
        finally:
            os.close(reader)
            _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual(proof, ['round-budget-owner-context-required'] * 4)
        self.assertEqual(budget.finish(allocation)['component'], 'gateway')
        self.assertEqual(budget.evidence()['completedComponents'], 1)

    def test_invalid_context_config_not_silently_defaulted(self):
        for config in (False, 0, {}, '600000'):
            with self.subTest(config=config), self.assertRaises(RoundBudgetError):
                RoundBudget(config)

    def test_parser_reads_only_three_new_names_and_source_whitelisted(self):
        class Restricted(dict):
            def get(self, name, default=None):
                if name not in (TOTAL_NAME, CLEANUP_NAME, PARENT_NAME):
                    raise AssertionError('unexpected environment access')
                return super().get(name, default)
        self.assertEqual(parse_config(Restricted({'SECRET':'private', 'OLD_BUDGET':'1'})), BudgetConfig())
        with self.assertRaises(RoundBudgetError): BudgetConfig(source='token-secret')

    def test_unknown_own_namespace_name_refuses_without_reading_secret_value(self):
        class NeverRead(dict):
            def get(self, name, default=None):
                raise AssertionError('unknown field must reject before reading values')
            def __getitem__(self, name):
                raise AssertionError('source values must not be indexed')
        unknown = 'CAT_AGENTS_STABILITY_ROUND_TOTAL_BUDGET_MS'
        with self.assertRaises(RoundBudgetError) as caught:
            parse_config(NeverRead({unknown:'synthetic-secret-token'}))
        self.assertEqual(str(caught.exception), 'round-budget-config-field-unknown')
        self.assertNotIn(unknown, str(caught.exception))
        self.assertNotIn('synthetic-secret', str(caught.exception))

    def test_other_namespace_credentials_remain_values_unread(self):
        touched = []
        class SecretEnvironment(dict):
            def get(self, name, default=None):
                touched.append(name)
                if name not in (TOTAL_NAME, CLEANUP_NAME, PARENT_NAME):
                    raise AssertionError('credential value inspected')
                return super().get(name, default)
            def __getitem__(self, name):
                raise AssertionError('source values must not be indexed')
        config = parse_config(SecretEnvironment({'OPENAI_API_KEY':'synthetic-private',
                              'OLD_COLLECTOR_BUDGET_MS':'1', 'CAT_AGENTS_OTHER_SECRET':'synthetic-private'}))
        self.assertEqual(config, BudgetConfig())
        self.assertEqual(touched, [TOTAL_NAME, CLEANUP_NAME, PARENT_NAME])

    def test_sequence_tokens_cannot_be_reordered_reused_or_copied(self):
        budget = RoundBudget(clock=Clock())
        with self.assertRaises(RoundBudgetError): budget.allocate('cron')
        first = budget.allocate('gateway')
        with self.assertRaises(RoundBudgetError): budget.allocate('cron')
        with self.assertRaises(RoundBudgetError): budget.finish(dataclasses.replace(first))
        budget.finish(first)
        with self.assertRaises(RoundBudgetError): budget.finish(first)
        second = budget.allocate('cron')
        self.assertEqual(second.component, 'cron')
        self.assertEqual(budget.finish(second)['cleanupQualification'], 'caller-owned-fatal-fence')


if __name__ == '__main__': unittest.main()
