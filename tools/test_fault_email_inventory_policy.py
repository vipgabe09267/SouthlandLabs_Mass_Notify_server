#!/usr/bin/env python3
"""Private health observations and an inert sender exercise inventory mail policy."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'
sys.path.insert(0, str(RUNTIME))
SPEC = importlib.util.spec_from_file_location('inventory_notification_policy', RUNTIME / 'sls_system_notifications.py')
NOTIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTIFY)
NOW = 1800000000


class InventoryMailPolicy(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='sll-inventory-mail-')
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name) / 'notification-state.json'
        self.calls = []
        self.config = {'system_notification_emails': 'fixture@example.invalid'}

    def sender(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return True

    def faults(self, at=NOW, component='external', code='snapshot_busy', **updates):
        summary = {'checked_at': at, 'free_bytes': 1024 * 1024 * 1024,
                   'queue_errors': int(component == 'external'),
                   'queue_scan_incomplete': component == 'external',
                   'weather_scan_incomplete': component == 'weather',
                   'audit_fault_active': component == 'control_audit',
                   'security_audit_fault_active': component == 'security_audit',
                   'inspection_issues': [{'component': component, 'code': code}]}
        summary.update(updates)
        worker = {'checked_at': datetime.fromtimestamp(at, timezone.utc).isoformat(), 'ok': True}
        return NOTIFY.collect_health_faults(worker, summary, now=at)

    def process(self, faults, at=NOW):
        return NOTIFY.process_faults(self.config, faults, self.state, sender=self.sender, now=at)

    def test_one_busy_snapshot_then_recovery_never_sends(self):
        for component in ('external', 'weather', 'control_audit', 'security_audit'):
            with self.subTest(component=component):
                self.assertEqual(self.process(self.faults(component=component))['sent'], 0)
                self.assertEqual(self.process({}, NOW + 60), {'sent': 0, 'active': 0})
                self.assertEqual(json.loads(self.state.read_text())['attempts'], {})
        self.assertEqual(self.calls, [])

    def test_persistent_busy_requires_two_minutes_and_new_summary_then_sends_once(self):
        self.assertEqual(self.process(self.faults())['sent'], 0)
        self.assertEqual(self.process(self.faults(NOW + 119), NOW + 119)['sent'], 0)
        self.assertEqual(self.process(self.faults(NOW + 120), NOW + 120)['sent'], 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.process(self.faults(NOW + 180), NOW + 180)['sent'], 0)
        self.process({}, NOW + 240)
        self.assertEqual(self.process(self.faults(NOW + 300), NOW + 300)['sent'], 0)
        self.assertEqual(len(self.calls), 1, 'Daily duplicate suppression must remain intact')

    def test_reusing_same_fresh_summary_cannot_confirm_an_inspection_failure(self):
        observed = self.faults()
        self.assertEqual(self.process(observed)['sent'], 0)
        self.assertEqual(self.process(observed, NOW + 120)['sent'], 0)
        self.assertEqual(self.process(observed, NOW + 180)['sent'], 0)
        self.assertEqual(self.process(self.faults(NOW + 1), NOW + 180)['sent'], 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.process(self.faults(NOW + 181), NOW + 181)['sent'], 1)

    def test_changing_inspection_source_does_not_confirm_the_previous_problem(self):
        self.assertEqual(self.process(self.faults())['sent'], 0)
        self.assertEqual(self.process(self.faults(NOW + 120, 'weather'), NOW + 120)['sent'], 0)
        self.assertEqual(self.process(self.faults(NOW + 180, 'weather'), NOW + 180)['sent'], 0)
        self.assertEqual(self.process(self.faults(NOW + 240, 'weather'), NOW + 240)['sent'], 1)
        self.assertIn('Weather', self.calls[0][0][2])
        self.assertNotIn('External delivery inventory', self.calls[0][0][2])

    def test_sustained_atomic_replacement_races_are_rechecked_as_well(self):
        self.assertEqual(self.process(self.faults(code='snapshot_changed'))['sent'], 0)
        self.assertEqual(self.process(self.faults(NOW + 120, code='snapshot_changed'), NOW + 120)['sent'], 1)

    def test_alternating_transient_reasons_cannot_hide_persistently_unknown_inventory(self):
        self.assertEqual(self.process(self.faults())['sent'], 0)
        self.assertEqual(self.process(self.faults(NOW + 60, code='snapshot_changed'), NOW + 60)['sent'], 0)
        duplicate = [{'component': 'external', 'code': 'snapshot_changed'}] * 2
        self.assertEqual(self.process(self.faults(NOW + 120, inspection_issues=duplicate), NOW + 120)['sent'], 1)

    def test_real_unreadable_invalid_unsafe_and_capacity_faults_alert_immediately(self):
        for component in ('external', 'weather', 'control_audit', 'security_audit'):
            for code in ('unreadable', 'invalid', 'unsafe', 'scan_limit'):
                with self.subTest(component=component, code=code):
                    self.state.unlink(missing_ok=True)
                    before = len(self.calls)
                    self.assertEqual(self.process(self.faults(component=component, code=code))['sent'], 1)
                    self.assertEqual(len(self.calls), before + 1)
                    body = self.calls[-1][0][2]
                    self.assertIn(code, body, 'A persistent failure must leave a useful nonsecret reason')
                    if component != 'external':
                        self.assertNotIn('External delivery inventory', body)

    def test_busy_inventory_does_not_delay_independent_real_faults(self):
        for update in ({'free_bytes': 0}, {'recent_expired_external': 1},
                       {'recent_failed_weather': 1}, {'audit_at_capacity': True},
                       {'audit_failed_records': 1, 'audit_fault_active': True},
                       {'media_over_budget': True}, {'maintenance_failed_stages': ['event_logs']}):
            with self.subTest(update=update):
                self.state.unlink(missing_ok=True)
                self.assertEqual(self.process(self.faults(**update))['sent'], 1)

    def test_forwarding_inspection_contention_is_distinct_from_real_logger_failure(self):
        for component, prefix, placeholder in (
                ('control_audit', 'audit_', 'audit_forwarding_health_unavailable'),
                ('security_audit', 'security_audit_', 'audit_health_unavailable')):
            with self.subTest(component=component):
                self.state.unlink(missing_ok=True)
                unread = {prefix + 'fault_active': False, prefix + 'forwarding_active': True,
                          prefix + 'forwarding_error': placeholder}
                self.assertEqual(self.process(self.faults(component=component, **unread))['sent'], 0)
                self.process({}, NOW + 60)
                failure = dict(unread, **{prefix + 'forwarding_error': 'audit_syslog_unavailable',
                                         prefix + 'forwarding_failed_records': 1})
                self.assertEqual(self.process(self.faults(NOW + 120, component, **failure), NOW + 120)['sent'], 1)

    def test_unavailable_weather_inventory_remains_a_fault_without_external_label(self):
        found = self.faults(component='weather', code='unreadable')
        self.assertIn('storage', found)
        self.assertIn('Weather', found['storage']['message'])
        self.assertNotIn('External delivery inventory', found['storage']['message'])

    def test_untrusted_diagnostics_do_not_leak_or_turn_unknown_into_healthy(self):
        secret = 'PRIVATE-CREDENTIAL-FIXTURE'
        for invalid in (None, {}, [secret], [{'component': 'external', 'code': secret}],
                        [{'component': 'external', 'code': 'snapshot_busy', 'path': secret}],
                        [{'component': 'weather', 'code': 'snapshot_busy'}] * 33):
            with self.subTest(invalid=invalid):
                self.state.unlink(missing_ok=True)
                found = self.faults(inspection_issues=invalid)
                self.assertIn('storage', found)
                self.assertNotIn(secret, json.dumps(found))
                self.assertEqual(self.process(found)['sent'], 1)

    def test_malformed_audit_reason_fields_are_corruption_faults_not_exceptions(self):
        for component, prefix in (('control_audit', 'audit_'), ('security_audit', 'security_audit_')):
            for field in ('failure_code', 'forwarding_error'):
                for invalid in ([], {}, 7, True):
                    with self.subTest(component=component, field=field, invalid=invalid):
                        self.state.unlink(missing_ok=True)
                        found = self.faults(component=component, **{prefix + field: invalid})
                        self.assertIn('invalid', found['storage']['message'])
                        self.assertEqual(self.process(found)['sent'], 1)

    def test_unknown_legacy_inventory_failure_gets_bounded_confirmation(self):
        # An older producer lacks the categorized read evidence. Its counts
        # remain explicitly unknown and must be rechecked before sending mail.
        worker = {'ok': True, 'checked_at': datetime.fromtimestamp(NOW, timezone.utc).isoformat()}
        summary = {'checked_at': NOW, 'free_bytes': 1000000, 'queue_errors': 1}
        found = NOTIFY.collect_health_faults(worker, summary, now=NOW)
        self.assertEqual(self.process(found)['sent'], 0)
        summary['checked_at'] = NOW + 120
        found = NOTIFY.collect_health_faults(worker, summary, now=NOW + 120)
        self.assertEqual(self.process(found, NOW + 120)['sent'], 1)


if __name__ == '__main__':
    unittest.main()
