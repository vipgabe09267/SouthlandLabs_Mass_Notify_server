#!/usr/bin/python3
"""Actual rollback SQL must preserve native recording IDs and dependencies.

The actual PHP body runs against real PDO/SQLite; only MySQL SHOW TABLES syntax
and the FreePBX service boundary are adapted. Foreign-key RESTRICT independently
detects delete/reinsert of a still-referenced recording ID.
"""
import json
import importlib.util
from contextlib import nullcontext
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
import wave

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'tools/install_release.sh').read_text()
RESTORE = SOURCE.split('restore_module_registration() {', 1)[1].split("php -r '\n", 1)[1].split("\n' <", 1)[0]
FILENAMES = ['custom/SLS_Mass_Notify_Paging_Tone_Opening', 'custom/SLS_Mass_Notify_Paging_Tone_Closing',
             'custom/SLS_Mass_Notify_NWS_Alert', 'custom/SLS_Mass_Notify_Lightning_Alert',
             'custom/Paging_Tone_Opening', 'custom/Paging_Tone_Closing', 'custom/NWS_alert', 'custom/Lightning_alert']
HARNESS = r'''<?php
class RecordingFixturePDO extends PDO {
 public function prepare(string $query,array $options=[]): PDOStatement|false {
  if($query==='SHOW TABLES LIKE ?'){$query="SELECT name FROM sqlite_master WHERE type='table' AND name = ?";}
  return parent::prepare($query,$options);
 }
}
class DashboardHooks {static function genHooks($order){return [];}}
class RecordingFixtureDashboard {function getConfig($key){return [];} function setConfig($key,$value){}}
class FreePBX {
 static function Database(){static $db;if(!$db){$db=new RecordingFixturePDO('sqlite:'.getenv('FIXTURE_RECORDING_DB'));
  $db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$db->setAttribute(PDO::ATTR_STRINGIFY_FETCHES,true);
  $db->exec('PRAGMA foreign_keys = ON');}return $db;}
 static function Dashboard(){return new RecordingFixtureDashboard;}
}
'''
SPEC = importlib.util.spec_from_file_location('recording_static_recovery',
    ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_installer_recovery.py')
STATIC = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(STATIC)


class RecordingRecoveryPreservation(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir='/run', prefix='sls-recording-recovery-')
        self.addCleanup(self.temporary.cleanup); self.root = Path(self.temporary.name)
        self.database = self.root / 'native.sqlite'; self.harness = self.root / 'freepbx.php'
        self.harness.write_text(HARNESS)
        with sqlite3.connect(self.database) as db:
            db.executescript('''PRAGMA foreign_keys=ON;
                CREATE TABLE modules(modulename TEXT PRIMARY KEY,version TEXT,enabled TEXT);
                INSERT INTO modules VALUES('slsmassnotifyserver','candidate','1');
                CREATE TABLE recordings(id TEXT PRIMARY KEY,filename TEXT,displayname TEXT,description TEXT);
                CREATE TABLE ivr_entries(id TEXT PRIMARY KEY,recording_id TEXT REFERENCES recordings(id) ON DELETE RESTRICT);
            ''')

    def row(self, identifier='12', name='SLL Mass Notify Server - NWS Alert',
            description='Default Southland Labs NWS alert opening tone.', filename=FILENAMES[2]):
        return {'id': identifier, 'filename': filename, 'displayname': name, 'description': description}

    def insert(self, row, reference=False):
        with sqlite3.connect(self.database) as db:
            db.execute('INSERT INTO recordings VALUES(?,?,?,?)', tuple(row.values()))
            if reference: db.execute('INSERT INTO ivr_entries VALUES(?,?)', ('ivr-' + row['id'], row['id']))

    def snapshot(self, rows=()):
        recordings = {name: [] for name in FILENAMES}
        for row in rows: recordings[row['filename']].append(row)
        return {'schema': 2, 'row': {'modulename': 'slsmassnotifyserver', 'version': 'previous', 'enabled': '1'},
                'recordings': recordings, 'backup_enrollment': []}

    def recover(self, snapshot):
        code = RESTORE.replace('/etc/freepbx.conf', str(self.harness)).replace(
            '/var/www/html/admin/modules/dashboard/classes/DashboardHooks.class.php', str(self.harness))
        return subprocess.run(['php', '-r', code], input=json.dumps(snapshot), text=True,
            capture_output=True, timeout=10, env={**os.environ, 'FIXTURE_RECORDING_DB': str(self.database)})

    def state(self):
        with sqlite3.connect(self.database) as db:
            db.row_factory = sqlite3.Row
            return {'recordings': [dict(row) for row in db.execute('SELECT * FROM recordings ORDER BY id')],
                    'references': [dict(row) for row in db.execute('SELECT * FROM ivr_entries ORDER BY id')],
                    'version': db.execute("SELECT version FROM modules WHERE modulename='slsmassnotifyserver'").fetchone()[0]}

    def test_new_owned_recording_with_native_reference_is_retained_during_rollback(self):
        row = self.row(); self.insert(row, reference=True)
        result = self.recover(self.snapshot())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()['recordings'], [row])
        self.assertEqual(self.state()['references'], [{'id': 'ivr-12', 'recording_id': '12'}])
        self.assertEqual(self.state()['version'], 'previous')

    def test_new_independent_duplicate_rows_are_preserved_with_owned_rows(self):
        owned = self.row(); independent = self.row(identifier='13', name='Administrator announcement', description='Independent native recording')
        self.insert(owned, reference=True); self.insert(independent, reference=True)
        result = self.recover(self.snapshot())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()['recordings'], [owned, independent])
        self.assertEqual(len(self.state()['references']), 2)

    def test_rebrand_recovery_updates_exact_row_without_deleting_referenced_id(self):
        original = self.row(name='SLS Mass Notify - NWS Alert', description='Default Southland Servers NWS alert opening tone.')
        self.insert(self.row(), reference=True)
        result = self.recover(self.snapshot([original]))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()['recordings'], [original])
        self.assertEqual(self.state()['references'], [{'id': 'ivr-12', 'recording_id': '12'}])

    def test_occupied_original_id_is_a_conflict_and_never_replaced(self):
        original = self.row(name='SLS Mass Notify - NWS Alert', description='Default Southland Servers NWS alert opening tone.')
        unrelated = self.row(filename='custom/administrator-message', name='Administrator message', description='Preserve this identifier')
        self.insert(unrelated, reference=True); before = self.state()
        result = self.recover(self.snapshot([original]))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state(), before)


class NativeRecordingAudioRecovery(unittest.TestCase):
    def setUp(self):
        self.fixture = RecordingRecoveryPreservation(methodName='test_new_owned_recording_with_native_reference_is_retained_during_rollback')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        prefix = self.fixture.root / 'fs'; prefix.mkdir(mode=0o700)
        private = self.fixture.root / 'private'; private.mkdir(mode=0o700)
        self.tables = {'root': b'', 'asterisk': b''}
        def table(user):
            def access(body=None):
                if body is not None: self.tables[user] = body
                return self.tables[user]
            return access
        def command(arguments, check=True):
            if arguments[1:3] == ['show', STATIC.SERVICE]:
                return 'LoadState=not-found\nUnitFileState=not-found\nActiveState=inactive'
            raise AssertionError('Unexpected native service request: ' + repr(arguments))
        self.recovery = STATIC.Recovery(private / 'static', prefix, cron=table('root'),
            user_cron=table('asterisk'), command=command, cron_lock=lambda accounts: nullcontext())
        self.audio = self.recovery.dest('/var/lib/asterisk/sounds/en/custom/SLS_Mass_Notify_NWS_Alert.wav')

    def write_audio(self, sample):
        self.audio.parent.mkdir(parents=True, exist_ok=True)
        with wave.open(str(self.audio), 'wb') as sound:
            sound.setnchannels(1); sound.setsampwidth(2); sound.setframerate(8000)
            sound.writeframes(sample * 16)
        self.audio.chmod(0o644)
        return self.audio.read_bytes()

    def test_static_then_database_rollback_preserves_new_audio_referenced_by_native_ivr(self):
        self.recovery.snapshot_create()
        row = self.fixture.row(); self.fixture.insert(row, reference=True)
        audio = self.write_audio(b'\0\0')
        self.assertTrue(self.recovery.restore()['ok'])
        database = self.fixture.recover(self.fixture.snapshot())
        self.assertEqual(database.returncode, 0, database.stderr)
        self.assertEqual(self.fixture.state()['recordings'], [row])
        self.assertEqual(self.fixture.state()['references'], [{'id': 'ivr-12', 'recording_id': '12'}])
        self.assertTrue(self.audio.is_file(), 'static rollback deleted audio required by the retained native recording ID')
        self.assertEqual(self.audio.read_bytes(), audio)
        verified = self.recovery.verify()
        self.assertTrue(verified['snapshot_verified'])
        self.assertGreaterEqual(verified.get('retained_additional_recording_audio', 0), 1)

    def test_independently_changed_required_native_audio_is_preserved_as_conflict(self):
        self.write_audio(b'\0\0'); self.recovery.snapshot_create()
        changed = self.write_audio(b'\1\0')
        with self.assertRaises(STATIC.RecoveryError): self.recovery.restore()
        self.assertEqual(self.audio.read_bytes(), changed)

    def test_missing_required_audio_restores_exact_original_snapshot(self):
        original = self.write_audio(b'\0\0'); self.recovery.snapshot_create()
        self.audio.unlink()
        self.assertTrue(self.recovery.restore()['ok'])
        self.assertEqual(self.audio.read_bytes(), original)
        self.assertTrue(self.recovery.verify()['snapshot_verified'])


if __name__ == '__main__':
    unittest.main()
