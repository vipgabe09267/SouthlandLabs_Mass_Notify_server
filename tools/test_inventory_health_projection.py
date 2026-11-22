#!/usr/bin/env python3
"""Incomplete delivery inventories remain unknown in UI and redacted diagnostics."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh; no product code was loaded.')

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'slsmassnotifyserver'
RUNTIME = MODULE / 'bin/sls_mass_notify'
spec = importlib.util.spec_from_file_location('inventory_support_snapshot', RUNTIME / 'sls_support_snapshot.py')
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


def method(name):
    """Keep the production consumer; replace only its external PBX dependencies."""
    source = (MODULE / 'Slsmassnotifyserver.class.php').read_text()
    start = re.search(r'(?m)^\t(?:public|private|protected) function ' + re.escape(name) + r'\(', source)
    if start is None:
        raise AssertionError('Missing production consumer: ' + name)
    end = re.search(r'(?m)^\t(?:public|private|protected) function ', source[start.end():])
    return source[start.start():start.end() + end.start() if end else len(source)]


def php_consumer(operation, summary):
    prefix = r'''
namespace FreePBX\modules;
set_error_handler(static function($severity,$message,$file,$line){
    if (!(error_reporting() & $severity)) { return false; }
    throw new \ErrorException($message,0,$severity,$file,$line);
});
require_once MODULE_PATH.'/StatusHealth.php';
require_once MODULE_PATH.'/SupportDiagnostics.php';
class InventoryProjectionFixture {
    use SlsSupportDiagnostics;
    const MODULE_VERSION='0.0.0-test';
    const SETTINGS_JSON=DATA_PATH.'/settings';
    const PLUGIN_DATA_DIR=DATA_PATH;
    const RUNTIME_DIR=DATA_PATH.'/runtime';
    const PIPER_BIN=DATA_PATH.'/piper';
    const PIPER_VOICE=DATA_PATH.'/voice';
    const TTS_DIR=DATA_PATH.'/audio';
    const EVENTS_LOG=DATA_PATH.'/events';
    const VISUAL_PUSH_SCRIPT=DATA_PATH.'/visual';
    public $FreePBX;
    private $storage;
    public function __construct($storage){
        $this->storage=$storage;
        $this->FreePBX=new class {
            public function Database(){return $this;}
            public function prepare($sql){return $this;}
            public function execute($arguments){}
            public function fetchColumn(){return '17.0.5';}
        };
    }
    public function getActiveSettings(){return [];}
    public function getAnnouncementWorkerHealth(){return ['ok'=>true,'latest_state'=>'idle','failure_reason'=>''];}
    public function getPhoneEventCollectorDisplayHealth(){return ['ok'=>true,'message'=>'Fixture collector is available.'];}
    public function hasConfiguredNotificationEmailRecipients($settings){return false;}
    public function getDetectedEndpointFormats(){return [];}
    public function getDesktopClientDiagnostics($settings){return [];}
    public function getControlApiAuditSummary(){return [];}
    public function getUiLogNotices($kind){return [];}
    public function getDeviceOverrideInventory(){return ['success'=>true,'devices'=>[]];}
    private function loadJsonFile($path){return $this->storage;}
    /* PRODUCTION_CONSUMERS */
    public function dashboardWarnings(){
        $warnings=[];$now=time();
        /* DASHBOARD_STORAGE */
        return $warnings;
    }
}
$storage=json_decode(stream_get_contents(STDIN),true,64,JSON_THROW_ON_ERROR);
$fixture=new InventoryProjectionFixture($storage);
$operation=$argv[1];
if($operation==='queues'){$result=SlsStatusHealth::queueFaults($storage);}
elseif($operation==='dashboard'){$result=$fixture->dashboardWarnings();}
elseif($operation==='diagnostics'){$result=$fixture->getDiagnosticsSummary(false);}
else{$result=$fixture->getRedactedSupportDiagnostics();}
echo json_encode($result,JSON_THROW_ON_ERROR);
'''
    with tempfile.TemporaryDirectory(prefix='sls-inventory-ui-') as temporary:
        body = ('define("MODULE_PATH",' + json.dumps(str(MODULE)) + ');'
                'define("DATA_PATH",' + json.dumps(temporary) + ');')
        # These two methods remain unchanged; only __DIR__ resolves back to the
        # frozen candidate module instead of the private fixture's directory.
        consumers = '\n'.join(method(name) for name in ('getDiagnosticsSummary', 'diagnosticCheck'))
        consumers = consumers.replace('__DIR__', json.dumps(str(MODULE)))
        dashboard = method('dashboardService')
        start = dashboard.index("\n\t\t$storage = $this->loadJsonFile(self::PLUGIN_DATA_DIR . '/storage-summary.json');")
        end = dashboard.index('\n\t\tif (!empty($enabledSchedules))', start)
        program = prefix.replace('namespace FreePBX\\modules;', 'namespace FreePBX\\modules;\n' + body)
        program = program.replace('/* PRODUCTION_CONSUMERS */', consumers)
        program = program.replace('/* DASHBOARD_STORAGE */', dashboard[start:end])
        result = subprocess.run(['/usr/bin/php', '-r', program, operation], input=json.dumps(summary),
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)


def summary(**changes):
    return {'checked_at': int(time.time()), 'free_bytes': 1073741824,
            'queue_errors': 0, 'queue_scan_incomplete': False, 'queue_files_scanned': 3,
            'queue_files_seen': 3, 'pending_external': 0, 'expired_external': 0,
            'pending_weather': 0, 'weather_running': 0, 'failed_weather': 0,
            'uncertain_weather': 0, 'expired_weather': 0, 'weather_deadline_misses': 0,
            'recent_expired_external': 0, 'recent_failed_weather': 0,
            'recent_uncertain_weather': 0, 'recent_expired_weather': 0,
            'recent_weather_deadline_misses': 0, 'maintenance_failed_stages': [], **changes}


class InventoryHealthProjection(unittest.TestCase):
    def test_queue_health_keeps_incomplete_weather_separate_from_external_failures(self):
        cases = [
            ({}, {'external': False, 'weather': False}),
            ({'weather_scan_incomplete': True}, {'external': False, 'weather': True}),
            ({'queue_errors': 1, 'queue_scan_incomplete': True}, {'external': True, 'weather': False}),
            ({'recent_failed_weather': 1}, {'external': False, 'weather': True}),
        ]
        for fields, expected in cases:
            with self.subTest(fields=fields):
                self.assertEqual(php_consumer('queues', summary(**fields)), expected)

    def test_incomplete_weather_diagnostics_warn_and_keep_counts_as_lower_bounds(self):
        report = php_consumer('diagnostics', summary(weather_scan_incomplete=True))
        checks = {row['label']: row for row in report['checks']}
        self.assertFalse(checks['Weather delivery queue']['ok'])
        self.assertIn('lower bound', checks['Weather delivery queue']['detail'].lower())
        self.assertIn('weather', checks['Weather delivery queue']['detail'].lower())
        self.assertTrue(checks['External delivery queue']['ok'])

    def test_external_partial_diagnostics_remain_warning_and_lower_bounds(self):
        report = php_consumer('diagnostics', summary(queue_scan_incomplete=True, pending_external=2))
        checks = {row['label']: row for row in report['checks']}
        self.assertFalse(checks['External delivery queue']['ok'])
        self.assertIn('lower bound', checks['External delivery queue']['detail'].lower())
        self.assertTrue(checks['Weather delivery queue']['ok'])

    def test_dashboard_attributes_incomplete_inventory_to_its_own_subsystem(self):
        weather = php_consumer('dashboard', summary(weather_scan_incomplete=True))
        self.assertTrue(any('weather' in row.lower() and 'inventory' in row.lower() for row in weather))
        self.assertTrue(any('lower bound' in row.lower() for row in weather))
        self.assertFalse(any('external' in row.lower() for row in weather))
        external = php_consumer('dashboard', summary(queue_scan_incomplete=True, pending_external=2))
        self.assertTrue(any('external' in row.lower() and 'lower bound' in row.lower() for row in external))
        self.assertFalse(any('weather' in row.lower() for row in external))

    def test_redacted_download_keeps_unknown_weather_counts_and_safe_reason_pairs(self):
        fields = summary(weather_scan_incomplete=True, inspection_issues=[
            {'component': 'weather', 'code': 'snapshot_busy'},
            {'component': 'weather', 'code': 'SECRET_REASON'},
            {'component': 'SECRET_COMPONENT', 'code': 'unreadable'},
            {'component': 'weather', 'code': 'invalid', 'path': 'SECRET_PATH'},
            {'component': ['SECRET_COMPONENT'], 'code': 'unreadable'},
            {'component': 'weather', 'code': {'message': 'SECRET_REASON'}},
        ])
        report = php_consumer('support', fields)
        self.assertIs(report.get('weather_scan_incomplete'), True)
        self.assertIsNone(report['queue_counts']['pending_weather'])
        self.assertEqual(report['queue_counts']['pending_external'], 0)
        self.assertIs(report['queue_scan_incomplete'], False)
        self.assertEqual(report.get('inspection_issues'), [{'component': 'weather', 'code': 'snapshot_busy'}])
        self.assertNotIn('SECRET_', json.dumps(report))

    def test_cached_snapshot_omits_unverified_weather_metrics_and_redacts_details(self):
        fields = summary(weather_scan_incomplete=True, inspection_issues=[
            {'component': 'weather', 'code': 'snapshot_changed'},
            {'component': 'external', 'code': 'invalid', 'detail': 'SECRET_QUEUE'},
        ])
        with tempfile.TemporaryDirectory(prefix='sls-inventory-snapshot-') as temporary:
            directory = Path(temporary)
            path = directory / 'storage-summary.json'
            path.write_text(json.dumps(fields)); path.chmod(0o640)
            with patch.object(snapshot, 'postfix_health', return_value={}):
                report = snapshot.collect(directory, directory / 'missing-installer', int(time.time()))
        self.assertIs(report.get('weather_scan_incomplete'), True)
        self.assertNotIn('pending_weather', report['queues'])
        self.assertNotIn('failed_weather', report['queues'])
        self.assertEqual(report['queues']['pending_external'], 0)
        self.assertEqual(report.get('inspection_issues'), [{'component': 'weather', 'code': 'snapshot_changed'}])
        self.assertNotIn('SECRET_', json.dumps(report))

    def test_cached_snapshot_keeps_external_incompleteness_and_omits_partial_counts(self):
        fields = summary(queue_scan_incomplete=True, pending_external=2)
        with tempfile.TemporaryDirectory(prefix='sls-external-snapshot-') as temporary:
            directory = Path(temporary)
            path = directory / 'storage-summary.json'
            path.write_text(json.dumps(fields)); path.chmod(0o640)
            with patch.object(snapshot, 'postfix_health', return_value={}):
                report = snapshot.collect(directory, directory / 'missing-installer', int(time.time()))
        self.assertIs(report.get('queue_scan_incomplete'), True)
        self.assertNotIn('pending_external', report['queues'])
        self.assertEqual(report['queues']['pending_weather'], 0)

    def test_safe_issue_projection_is_bounded_and_healthy_weather_counts_survive(self):
        fields = summary(inspection_issues=[{'component': 'external', 'code': 'scan_limit'}] * 40)
        report = php_consumer('support', fields)
        self.assertEqual(report['queue_counts']['pending_weather'], 0)
        self.assertEqual(len(report.get('inspection_issues', [])), 32)
        self.assertTrue(all(row == {'component': 'external', 'code': 'scan_limit'}
                            for row in report['inspection_issues']))
        with tempfile.TemporaryDirectory(prefix='sls-bounded-snapshot-') as temporary:
            directory = Path(temporary)
            path = directory / 'storage-summary.json'
            path.write_text(json.dumps(fields)); path.chmod(0o640)
            with patch.object(snapshot, 'postfix_health', return_value={}):
                cached = snapshot.collect(directory, directory / 'missing-installer', int(time.time()))
        self.assertEqual(len(cached['inspection_issues']), 32)
        self.assertEqual(cached['queues']['pending_weather'], 0)


if __name__ == '__main__':
    unittest.main()
