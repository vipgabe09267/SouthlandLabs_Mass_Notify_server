#!/usr/bin/python3
"""Exercise real paging prompt generation from a root reload and native PHP."""
import json
import importlib.util
import io
import sys
import tempfile
from unittest import mock
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import unittest
import wave

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered' or any(
        os.environ.get('SLS_TEST_PARENT_' + label + '_NS') in (None, '', os.readlink('/proc/self/ns/' + ns))
        for label, ns in [('MOUNT','mnt'), ('NET','net'), ('PID','pid')]):
    raise SystemExit('Use the isolated test runner.')

ROOT = Path(__file__).resolve().parents[1]
DATA = Path('/var/lib/asterisk/SLS_Mass_Notifications_Plugin')
ENGINE = Path('/usr/local/bin/sls_mass_notify/piper/venv/bin')
ACCOUNT = pwd.getpwnam('asterisk')
PHP = r'''
interface BMO {}
require $argv[1];
if ($argv[2] === 'native') {
    $user = posix_getpwnam('asterisk');
    if (!posix_initgroups('asterisk', $user['gid']) || !posix_setgid($user['gid']) || !posix_setuid($user['uid'])) { exit(81); }
}
$class = new ReflectionClass(\FreePBX\modules\Slsmassnotifyserver::class);
$module = $class->newInstanceWithoutConstructor();
$settings = ['live_paging'=>['enabled'=>'1','extension'=>'700','allowed_callers'=>['1000'],
    'groups'=>[['group_id'=>'grp_office','menu_number'=>1,'require_pin'=>'0']]], 'announcement_groups'=>[
    ['id'=>'grp_office','name'=>'Office','extensions'=>['1001']]]];
try {
    $class->getMethod('ensureLivePagingPrompts')->invoke($module,$settings);
    $class->getMethod('assertLivePagingPromptsReady')->invoke($module,$settings);
} catch (\FreePBX\modules\SlsPagingPromptUnavailableException $error) {
    if (($argv[3] ?? '') !== 'capacity') { throw $error; }
    $class->getMethod('warnPagingPromptsDuringReload')->invoke($module, true, $error);
    echo $error->getMessage();
    exit(73);
}
'''
INERT_SYNTH = """#!/usr/bin/python3 -I
import os,pwd,sys,wave
from pathlib import Path
uid=pwd.getpwnam('asterisk').pw_uid
assert os.geteuid()==uid
inp=Path(sys.argv[sys.argv.index('--input-file')+1])
assert inp.stat().st_uid==uid and inp.parent.stat().st_uid==uid and inp.read_bytes().strip()
assert inp.parent.stat().st_mode & 0o077==0
path=sys.argv[sys.argv.index('--output-file')+1]
with wave.open(path,'wb') as w:
    w.setparams((1,2,16000,0,'NONE','not compressed'))
    w.writeframes(bytes(3200))
"""


class NativePromptRenderer(unittest.TestCase):
    def prepare_native_renderer(self):
        model_name = os.environ.get('SLS_PINNED_VOICE_FIXTURE')
        if not model_name:
            self.skipTest('Set SLS_PINNED_VOICE_FIXTURE to the reviewed offline Piper voice.')
        subprocess.run(['mount','-o','remount,size=1024m','/var/lib/asterisk'],check=True)
        subprocess.run(['mount','-t','tmpfs','-o','size=16m,mode=755','tmpfs','/var/www/html/sls_mass_notify'],check=True)
        for folder in (DATA, DATA/'sounds', DATA/'sounds/tts', DATA/'sounds/paging', DATA/'piper', DATA/'piper/voices'):
            folder.mkdir(exist_ok=True)
            os.chown(folder, ACCOUNT.pw_uid, ACCOUNT.pw_gid)
            folder.chmod(0o750)
        model = Path(model_name)
        for source in (model, model.with_suffix('.onnx.json')):
            target = DATA/'piper/voices'/source.name
            shutil.copyfile(source,target)
            target.chmod(0o644)
        ENGINE.mkdir(parents=True, exist_ok=True)
        for directory in (ENGINE.parent.parent.parent, ENGINE.parent.parent, ENGINE.parent, ENGINE):
            directory.chmod(0o755)
        for name in ('piper','python3'):
            (ENGINE/name).write_text(INERT_SYNTH)
            (ENGINE/name).chmod(0o755)
    def test_native_capacity_refusal_reaches_php_and_freepbx_log(self):
        self.prepare_native_renderer()
        mount = Path('/var/lib/asterisk')
        usage = os.statvfs(mount)
        used = (usage.f_blocks - usage.f_bfree) * usage.f_frsize
        free_target = 4 * 1024**2
        subprocess.run(['mount', '-o', f'remount,size={used + free_target}', str(mount)], check=True)
        self.addCleanup(subprocess.run, ['mount', '-o', 'remount,size=1024m', str(mount)], check=True)
        for role in ('root', 'native'):
            result = subprocess.run(['php', '-r', PHP, str(ROOT/'slsmassnotifyserver/Slsmassnotifyserver.class.php'),
                                     role, 'capacity'], text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 73, (result.stdout, result.stderr))
            fields = dict(re.findall(r'(role|available_bytes|required_bytes|reserve_bytes)=([A-Za-z0-9]+)', result.stdout))
            self.assertIn(fields.get('role'), ('data', 'destination'), result.stdout)
            self.assertLessEqual(int(fields['available_bytes']), free_target)
            self.assertGreater(int(fields['required_bytes']), int(fields['available_bytes']))
            self.assertGreater(int(fields['reserve_bytes']), 0)
            for name, value in fields.items():
                self.assertIn(f'{name}={value}', result.stderr, 'FreePBX log lost the measured cause.')
            self.assertNotIn('grp_office', result.stderr)
            self.assertFalse(list((DATA/'sounds/paging').glob('*.wav')))
            print('PHP capacity refusal', role, fields, flush=True)

    def test_root_then_native_reload_render_and_reuse_all_prompts(self):
        self.prepare_native_renderer()
        def render(role):
            result = subprocess.run(['php','-r',PHP,str(ROOT/'slsmassnotifyserver/Slsmassnotifyserver.class.php'),role],
                                    text=True,capture_output=True,timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        render('root')
        paging=DATA/'sounds/paging'
        files=sorted(paging.glob('*.wav'))
        self.assertGreaterEqual(len(files),13)
        for path in files:
            self.assertEqual((path.stat().st_uid,stat.S_IMODE(path.stat().st_mode)),(ACCOUNT.pw_uid,0o640))
            with wave.open(str(path),'rb') as audio:
                self.assertEqual((audio.getframerate(),audio.getnchannels(),audio.getsampwidth()),(8000,1,2))
        before={p.name:p.stat().st_ino for p in files}
        render('native')
        self.assertEqual({p.name:p.stat().st_ino for p in paging.glob('*.wav')},before)
        files[0].unlink()
        render('native')
        self.assertEqual(len(list(paging.glob('*.wav'))),len(files))
        self.assertFalse(list(paging.glob('.prompt-*')))
        self.assertFalse(list(Path('/tmp').glob('sls_announcement_*')))
        for job in DATA.glob('speech-slot-*.json'):
            records=json.loads(job.read_text())
            self.assertEqual(records,[])


class PromptPublication(unittest.TestCase):
    def setUp(self):
        runtime = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'
        spec = importlib.util.spec_from_file_location('test_native_prompt_publication', runtime/'sls_render_paging_prompt.py')
        self.renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.renderer)
        private = tempfile.TemporaryDirectory()
        self.addCleanup(private.cleanup)
        self.path = Path(private.name)
        self.directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.directory)
        self.name = 'b' * 64 + '.wav'
        self.target = self.path / self.name
        self.raw = self.path / 'raw.wav'
        with wave.open(str(self.raw), 'wb') as output:
            output.setparams((1, 2, 16000, 0, 'NONE', 'not compressed'))
            output.writeframes(bytes(3200))
        location = mock.patch.object(self.renderer, 'PAGING', self.path)
        location.start()
        self.addCleanup(location.stop)

    def test_publication_io_failure_restores_the_previous_inode_or_absence(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    self.target.write_bytes(b'previous prompt')
                    self.target.chmod(0o640)
                before = self.renderer.previous_identity(self.directory, self.name)
                real_sync = os.fsync
                refused = False
                def fail_first_directory_sync(fd):
                    nonlocal refused
                    if not refused and stat.S_ISDIR(os.fstat(fd).st_mode):
                        refused = True
                        raise OSError('fixture directory sync failed')
                    return real_sync(fd)
                with mock.patch.object(os, 'fsync', side_effect=fail_first_directory_sync), self.assertRaises(OSError):
                    self.renderer.publish(self.directory, self.name, before, self.raw, 25)
                self.assertTrue(refused)
                self.assertEqual(self.renderer.previous_identity(self.directory, self.name), before)
                if existing:
                    self.assertEqual(self.target.read_bytes(), b'previous prompt')
                self.assertEqual(list(self.path.glob('.prompt-*')), [])

    def test_ordinary_in_place_edit_during_conversion_is_preserved(self):
        self.target.write_bytes(b'previous')
        self.target.chmod(0o640)
        before = self.renderer.previous_identity(self.directory, self.name)
        real_convert = subprocess.run
        def concurrent_edit(*args, **kwargs):
            result = real_convert(*args, **kwargs)
            self.target.write_bytes(b'new concurrent content')
            return result
        with mock.patch.object(subprocess, 'run', side_effect=concurrent_edit), self.assertRaises((ValueError, OSError)):
            self.renderer.publish(self.directory, self.name, before, self.raw, 25)
        self.assertEqual(self.target.read_bytes(), b'new concurrent content')
        self.assertEqual(list(self.path.glob('.prompt-*')), [])

    def test_new_prompt_has_atomic_fallback_if_rename_flags_are_unavailable(self):
        with mock.patch.object(self.renderer.ctypes, 'CDLL', return_value=object()):
            self.renderer.publish(self.directory, self.name, 'missing', self.raw, 25)
            self.assertTrue(self.target.is_file())
            self.assertEqual(self.target.stat().st_nlink, 1)
            prior = self.renderer.previous_identity(self.directory, self.name)
            content = self.target.read_bytes()
            with self.assertRaises(OSError) as refusal:
                self.renderer.publish(self.directory, self.name, prior, self.raw, 35)
            self.assertEqual(refusal.exception.errno, self.renderer.errno.EOPNOTSUPP)
            self.assertEqual(self.renderer.previous_identity(self.directory, self.name), prior)
            self.assertEqual(self.target.read_bytes(), content)
        self.assertEqual(list(self.path.glob('.prompt-*')), [])

    def test_concurrent_first_publication_keeps_the_winning_file(self):
        real_rename = self.renderer.rename_prompt
        def publish_other(directory, source, destination, flags):
            self.target.write_bytes(b'completed concurrently')
            self.target.chmod(0o640)
            return real_rename(directory, source, destination, flags)
        with mock.patch.object(self.renderer, 'rename_prompt', side_effect=publish_other), self.assertRaises(FileExistsError):
            self.renderer.publish(self.directory, self.name, 'missing', self.raw, 25)
        self.assertEqual(self.target.read_bytes(), b'completed concurrently')
        self.assertEqual(list(self.path.glob('.prompt-*')), [])

    def test_competing_completion_is_retryable_and_unsafe_storage_is_distinct(self):
        old_umask = os.umask(0o027)
        self.addCleanup(os.umask, old_umask)
        arguments = ['renderer', self.name, '/tmp/unused.onnx', 'missing', '25']
        for refusal, expected in ((FileExistsError(17, 'another renderer completed first'), 75),
                                  (ValueError('unsafe prompt'), 77)):
            with self.subTest(expected=expected), mock.patch.object(sys, 'argv', arguments), \
                    mock.patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(b'fixture'))), \
                    mock.patch.object(self.renderer, 'render', side_effect=refusal):
                self.assertEqual(self.renderer.main(), expected)

    def test_native_kernel_destination_exhaustion_is_reported_after_admission(self):
        self.path.chmod(0o750)
        os.chown(self.path, ACCOUNT.pw_uid, ACCOUNT.pw_gid)
        model = self.renderer.DATA / 'piper/voices' / next(name for name in self.renderer.VOICE_BYTES if name.endswith('.onnx'))
        refusal = OSError(self.renderer.errno.ENOSPC, 'private path must not appear in diagnostics')
        with mock.patch.object(os, 'geteuid', return_value=ACCOUNT.pw_uid), \
                mock.patch.object(self.renderer, 'read_private_json', return_value={}), \
                mock.patch.object(self.renderer, 'piper_voice_current', return_value=True), \
                mock.patch.object(self.renderer, 'Admission') as lease, \
                mock.patch.object(self.renderer, 'synthesize', return_value=0), \
                mock.patch.object(self.renderer, 'publish', side_effect=refusal), \
                self.assertRaises(self.renderer.SpeechCapacityError) as result:
            self.renderer.render(self.name, model, 'missing', 25, b'private text')
        self.assertIn('role=destination', str(result.exception))
        self.assertIn('kernel_errno=28', str(result.exception))
        self.assertNotIn('private', str(result.exception))
        self.assertNotIn(str(self.path), str(result.exception))
        lease.return_value.complete.assert_not_called()
        lease.return_value.close.assert_called_once()

    def test_worker_storage_like_status_without_a_measurement_stays_distinct(self):
        self.path.chmod(0o750)
        os.chown(self.path, ACCOUNT.pw_uid, ACCOUNT.pw_gid)
        model = self.renderer.DATA / 'piper/voices' / next(name for name in self.renderer.VOICE_BYTES if name.endswith('.onnx'))
        with mock.patch.object(os, 'geteuid', return_value=ACCOUNT.pw_uid), \
                mock.patch.object(self.renderer, 'read_private_json', return_value={}), \
                mock.patch.object(self.renderer, 'piper_voice_current', return_value=True), \
                mock.patch.object(self.renderer, 'Admission') as lease, \
                mock.patch.object(self.renderer, 'synthesize', return_value=73):
            code = self.renderer.render(self.name, model, 'missing', 25, b'Pending prompt.')
        self.assertEqual(code, 77)
        lease.return_value.complete.assert_not_called()
        lease.return_value.close.assert_called_once()
        self.assertFalse(self.target.exists())


if __name__=='__main__':
    unittest.main()
