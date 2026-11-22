#!/usr/bin/python3
"""Preserve native recording rows and audio during lifecycle cleanup.

The actual SLL PHP methods/inline removal body execute as asterisk. Only native
bootstrap wiring, private DB location, and audio destination roots are adapted.
No installed PBX DB, native hook, installer, uninstaller, or provider is executed.
"""
import json
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'slsmassnotifyserver/Slsmassnotifyserver.class.php'


class RecordingPreservation(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0 or os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
            self.skipTest('Requires official isolated root/service-account fixture')
        temporary = tempfile.TemporaryDirectory(prefix='sls-recording-preservation-', dir='/run')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o755)
        self.account = pwd.getpwnam('asterisk')
        self.data = self.root / 'data'
        self.data.mkdir(mode=0o750)
        os.chown(self.data, self.account.pw_uid, self.account.pw_gid)
        self.sound = self.data / 'sound-custom'
        self.sound.mkdir(mode=0o750)
        os.chown(self.sound, self.account.pw_uid, self.account.pw_gid)
        self.tones = self.data / 'sounds/tones'
        self.tones.mkdir(mode=0o750, parents=True)
        for folder in (self.tones.parent, self.tones):
            os.chown(folder, self.account.pw_uid, self.account.pw_gid)
        self.db = self.data / 'fixture.sqlite'
        self.method_source = SOURCE.read_text()

    def database(self, records):
        if self.db.exists():
            self.db.unlink()
        with sqlite3.connect(self.db) as connection:
            connection.execute('CREATE TABLE recordings (id INTEGER PRIMARY KEY, displayname TEXT, filename BLOB, description TEXT)')
            connection.executemany('INSERT INTO recordings(id,displayname,filename,description) VALUES(?,?,?,?)', records)
        os.chown(self.db, self.account.pw_uid, self.account.pw_gid)
        self.db.chmod(0o640)

    def rows(self):
        with sqlite3.connect(self.db) as connection:
            return connection.execute('SELECT id,displayname,filename,description FROM recordings ORDER BY id').fetchall()

    def method(self, name):
        start = self.method_source.index('\tprivate function ' + name + '(')
        end = self.method_source.index('\n\tprivate function ', start + 1)
        return self.method_source[start:end].replace('/var/lib/asterisk/sounds/en/custom/', str(self.sound) + '/')

    def prefix(self):
        # SQLite executes the actual SELECT/LIMIT/DELETE statements. The sole
        # native-DB dialect adapter maps SHOW TABLES to sqlite_master lookup.
        return '''<?php
class AuditDatabase {
    private $pdo;
    public function __construct($path){$this->pdo=new PDO('sqlite:'.$path);$this->pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);}
    public function prepare($sql){return $this->pdo->prepare($sql);}
    public function query($sql){return $this->pdo->query($sql==="SHOW TABLES LIKE 'recordings'" ? "SELECT name FROM sqlite_master WHERE type='table' AND name='recordings'" : $sql);}
}
class FreePBX {public static $db;public static function Database(){return self::$db;}}
class AuditContainer {public function Database(){return FreePBX::$db;}}
FreePBX::$db=new AuditDatabase($argv[1]);
'''

    def class_program(self, name):
        methods = self.method('bundledRecordingRowOwned') + '\n' + self.method(name)
        return self.prefix() + '\nclass AuditRecordings {\npublic $FreePBX;\n' + \
            'const TONES_DIR=' + repr(str(self.tones)) + ';\n' + \
            'const DEFAULT_ANNOUNCEMENT_OPENING_TONE="opening_Paging_Tone_Opening";\n' + \
            'const DEFAULT_ANNOUNCEMENT_CLOSING_TONE="closing_Paging_Tone_Closing";\n' + \
            'const DEFAULT_NWS_OPENING_TONE="opening_NWS_alert";\n' + \
            'const DEFAULT_LIGHTNING_OPENING_TONE="opening_Lightning_alert";\n' + methods + '\n}\n' + \
            '$reflection=new ReflectionClass(AuditRecordings::class);$object=$reflection->newInstanceWithoutConstructor();\n' + \
            '$object->FreePBX=new AuditContainer();$reflection->getMethod(' + repr(name) + ')->invoke($object);\n'

    def inline_program(self):
        source = (ROOT / 'tools/uninstall_release.sh').read_text()
        body = source.split('remove_bundled_system_recordings() {', 1)[1].split("<<'PHP'\n", 1)[1].split('\nPHP\n', 1)[0]
        body = body.replace("require '/etc/freepbx.conf';", '// Private audit DB wiring; no PBX bootstrap.')
        body = body.replace('/var/lib/asterisk/sounds/en/custom/', str(self.sound) + '/')
        return self.prefix() + body.removeprefix('<?php')

    def php(self, program):
        fixture = self.root / 'recording-audit.php'
        fixture.write_text(program)
        fixture.chmod(0o644)
        def drop():
            os.setgroups([self.account.pw_gid])
            os.setgid(self.account.pw_gid)
            os.setuid(self.account.pw_uid)
        result = subprocess.run(['/usr/bin/php', str(fixture), str(self.db)], preexec_fn=drop,
            env=dict(os.environ, SLS_DATA_DIR=str(self.data)), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_legacy_cleanup_preserves_duplicate_and_unrelated_native_rows(self):
        owned = (1, 'NWS Alert', 'custom/NWS_alert', 'Default Southland Servers NWS alert opening tone.')
        administrator = (2, 'Administrator recording', 'custom/NWS_alert', 'Independent administrator recording.')
        unrelated = (3, 'Retained message', 'custom/retained', 'Unrelated native recording.')
        self.database([owned, administrator, unrelated])
        self.php(self.class_program('cleanupLegacyBundledSystemRecordings'))
        self.assertEqual(self.rows(), [owned, administrator, unrelated],
                         'Legacy cleanup must preserve native recording identities without complete dependency authority')

    def test_standalone_removal_preserves_owned_and_duplicate_native_rows(self):
        owned = (1, 'SLL Mass Notify Server - NWS Alert', 'custom/SLS_Mass_Notify_NWS_Alert', 'Default Southland Labs NWS alert opening tone.')
        administrator = (2, 'Administrator duplicate', owned[2], 'Independent administrator recording.')
        unrelated = (3, 'Retained message', 'custom/retained', 'Unrelated native recording.')
        self.database([owned, administrator, unrelated])
        self.php(self.inline_program())
        self.assertEqual(self.rows(), [owned, administrator, unrelated],
                         'Standalone removal must not delete recording rows on filename ownership alone')

    def test_compound_recording_keeps_its_bundled_audio_after_both_removal_paths(self):
        owned = (1, 'SLL Mass Notify Server - NWS Alert', 'custom/SLS_Mass_Notify_NWS_Alert', 'Default Southland Labs NWS alert opening tone.')
        compound = (2, 'Compound recording', owned[2] + '&custom/administrator-message', 'Independent composite recording.')
        body = b'private inert audio bytes retained for native recording playback'
        for operation in ('class', 'standalone'):
            with self.subTest(operation=operation):
                self.database([owned, compound])
                path = self.sound / 'SLS_Mass_Notify_NWS_Alert.wav'
                tone = self.tones / 'opening_NWS_alert.wav'
                for target in (path, tone):
                    target.write_bytes(body)
                    os.chown(target, self.account.pw_uid, self.account.pw_gid)
                    target.chmod(0o640)
                self.php(self.class_program('removeBundledSystemRecordings') if operation == 'class' else self.inline_program())
                self.assertEqual(self.rows(), [owned, compound])
                self.assertTrue(path.is_file(), 'A compound recording must retain its referenced audio')
                self.assertEqual(path.read_bytes(), body)
                self.assertEqual(tone.read_bytes(), body)

    def test_unknown_native_recording_id_usage_preserves_the_owned_recording(self):
        owned = (1, 'SLL Mass Notify Server - NWS Alert', 'custom/SLS_Mass_Notify_NWS_Alert', 'Default Southland Labs NWS alert opening tone.')
        self.database([owned])
        with sqlite3.connect(self.db) as connection:
            connection.execute('CREATE TABLE ivr_details (id INTEGER PRIMARY KEY, announcement INTEGER)')
            connection.execute('INSERT INTO ivr_details VALUES (7, 1)')
        self.php(self.class_program('removeBundledSystemRecordings'))
        self.assertEqual(self.rows(), [owned], 'Unknown foreign native-ID dependencies require conservative retention')
        with sqlite3.connect(self.db) as connection:
            self.assertEqual(connection.execute('SELECT filename FROM recordings WHERE id=(SELECT announcement FROM ivr_details WHERE id=7)').fetchone(), (owned[2],))


if __name__ == '__main__':
    unittest.main(verbosity=2)
