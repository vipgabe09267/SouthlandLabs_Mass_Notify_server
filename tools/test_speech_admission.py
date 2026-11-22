#!/usr/bin/python3
"""Private lock/quota/process tests; no installed Piper, PBX or notifications."""
import json
import builtins
import fcntl
import os
from pathlib import Path
import subprocess
import signal
import time
import sys
import tempfile
import unittest
import threading
from types import SimpleNamespace
from contextlib import redirect_stderr, redirect_stdout
import io
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'slsmassnotifyserver/bin/sls_mass_notify'))
import sls_speech_admission as speech
import sls_piper_worker as worker


class SpeechTests(unittest.TestCase):
    def test_root_transition_retains_telemetry_opt_out_without_parent_secrets(self):
        class Relayed(Exception): pass
        with mock.patch.object(speech.os, 'geteuid', return_value=0), \
             mock.patch.object(speech.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1001)), \
             mock.patch.object(speech.os, 'execve', side_effect=Relayed) as relay, \
             mock.patch.dict(os.environ, {'ORT_DISABLE_TELEMETRY': '1', 'GITHUB_TOKEN': 'private-fixture'}), \
             mock.patch.object(sys, 'argv', ['admission', '--reserve-media-bytes', '1']), self.assertRaises(Relayed):
            speech.main()
        self.assertEqual(relay.call_args.args[2]['ORT_DISABLE_TELEMETRY'], '1')
        self.assertNotIn('GITHUB_TOKEN', relay.call_args.args[2])

    def test_admitted_child_always_receives_telemetry_opt_out_in_clean_environment(self):
        code = 'import json,os;print(json.dumps({"telemetry":os.environ.get("ORT_DISABLE_TELEMETRY"),"secret":os.environ.get("GITHUB_TOKEN")}))'
        for initial in ('1', '0', ''):
            with self.subTest(initial=initial), mock.patch.dict(os.environ, {'ORT_DISABLE_TELEMETRY': initial, 'GITHUB_TOKEN': 'private-fixture'}), \
                 redirect_stdout(io.StringIO()) as output:
                self.assertEqual(speech.launch([sys.executable, '-c', code], 3), 0)
            self.assertEqual(json.loads(output.getvalue()), {'telemetry': '1', 'secret': None})

    def test_worker_disables_telemetry_before_native_import_and_session_creation(self):
        events = []
        class Options:
            def add_session_config_entry(self, *_args): pass
        def session(*_args, **_kwargs):
            events.append('session')
            self.assertEqual(events, ['import', 'disable', 'session'])
            return object()
        runtime = SimpleNamespace(SessionOptions=Options, ExecutionMode=SimpleNamespace(ORT_SEQUENTIAL=1),
                                  disable_telemetry_events=lambda: events.append('disable'), InferenceSession=session)
        piper = SimpleNamespace(PiperVoice=lambda **_kwargs: SimpleNamespace(synthesize=lambda *_args: []),
                                SynthesisConfig=lambda **_kwargs: object())
        config = SimpleNamespace(PiperConfig=SimpleNamespace(from_dict=lambda _value: SimpleNamespace(num_speakers=1, sample_rate=16000)))
        original_import = builtins.__import__
        def native_import(name, *args, **kwargs):
            if name == 'onnxruntime':
                self.assertEqual(os.environ.get('ORT_DISABLE_TELEMETRY'), '1', 'Opt-out must precede native module initialization')
                events.append('import')
                return runtime
            if name == 'piper': return piper
            if name == 'piper.config': return config
            return original_import(name, *args, **kwargs)
        model = self.root / 'private-voice.onnx'
        Path(str(model) + '.json').write_text('{}')
        with (self.root / 'private.wav').open('w+b') as output, \
             mock.patch.dict(os.environ, {'ORT_DISABLE_TELEMETRY': '0'}), \
             mock.patch.object(builtins, '__import__', side_effect=native_import), \
             mock.patch.object(sys, 'stdin', io.StringIO('Private fixture.\n')), \
             mock.patch.object(sys, 'argv', ['worker', '--model', str(model), '--output-file', '/proc/self/fd/' + str(output.fileno())]):
            self.assertEqual(worker.main(), 0)
        self.assertEqual(events, ['import', 'disable', 'session'])

    def test_native_session_has_explicit_bounded_threads_without_spinning(self):
        class Options:
            def __init__(self): self.entries = {}
            def add_session_config_entry(self, name, value): self.entries[name] = value
        class Runtime:
            SessionOptions = Options
            class ExecutionMode:
                ORT_SEQUENTIAL = object()
        options = worker.session_options(Runtime)
        self.assertEqual((options.intra_op_num_threads, options.inter_op_num_threads), (1, 1))
        self.assertIs(options.execution_mode, Runtime.ExecutionMode.ORT_SEQUENTIAL)
        self.assertEqual(options.entries, {'session.intra_op.allow_spinning':'0', 'session.inter_op.allow_spinning':'0'})

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sls-speech-admission-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'sounds/tts').mkdir(parents=True)
        self.web = self.root / 'web'; self.web.mkdir()
        self.config = {'speech_queue_wait_seconds': 0}

    def admission(self, config=None):
        value = speech.Admission(config or self.config, 30, self.root, self.web)
        self.addCleanup(value.close)
        return value

    def test_shared_limit_queue_and_immediate_reuse(self):
        first = self.admission().acquire()
        second = self.admission()
        with self.assertRaisesRegex(speech.SpeechAdmissionError, 'waited too long'): second.acquire()
        first.close()
        # Conversion reservations remain, but must not block the CPU slot.
        third = self.admission().acquire()
        self.assertIsNotNone(third.active)

    def test_completed_paging_prompts_on_separate_data_and_scratch_mounts(self):
        if os.geteuid() != 0 or os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
            self.skipTest('The isolated mount fixture is required')
        stage = """
            mount -t tmpfs -o size=376m,mode=1777 tmpfs /tmp
            mkdir -m 0700 /run/sls-prompt-data
            mount -t tmpfs -o size=1100m,mode=0700 tmpfs /run/sls-prompt-data
            mkdir -p /tmp/output-low /tmp/output-full /tmp/output-ready /tmp/output-ro /tmp/output-single
            mount -t tmpfs -o size=128m tmpfs /tmp/output-low
            mount -t tmpfs -o size=376m,nr_inodes=2 tmpfs /tmp/output-full
            touch /tmp/output-full/last-inode
            mount -t tmpfs -o size=376m,nr_inodes=2 tmpfs /tmp/output-single
            mount --bind /tmp/output-ready /tmp/output-ro
            mount -o remount,bind,ro /tmp/output-ro
            exec "$@"
        """
        result = subprocess.run(['/usr/bin/unshare', '--mount', '--propagation', 'private',
            '/bin/sh', '-ec', stage, 'prompt-fixture', sys.executable, '-B', __file__,
            'SpeechTests.split_prompt_sequence', 'SpeechTests.split_destination_admission'], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def split_prompt_sequence(self):
        data = Path('/run/sls-prompt-data')
        self.assertNotEqual(data.stat().st_dev, Path('/tmp').stat().st_dev)
        raw = self.root / 'render.wav'
        available = os.statvfs('/tmp')
        free = available.f_bavail * available.f_frsize
        amount = 600 * 160000 + speech.MIB
        self.assertLess(128 * speech.MIB + 2 * amount, free)
        self.assertGreater(128 * speech.MIB + 3 * amount, free)
        for completed in (False, True):
            directory = data / ('completed' if completed else 'grace')
            audio = directory / 'sounds/tts'
            audio.mkdir(parents=True)
            for index in range(14):
                job = speech.Admission(self.config, 600, directory, self.web)
                try:
                    if not completed and index == 2:
                        with self.assertRaisesRegex(speech.SpeechAdmissionError, 'protected free-space reserve') as error:
                            job.acquire()
                        self.assertIsInstance(error.exception, speech.SpeechCapacityError)
                        self.assertEqual(error.exception.code, 73)
                        actual = os.statvfs('/tmp')
                        for detail in ('role=temporary', 'available_bytes=' + str(actual.f_bavail * actual.f_frsize),
                                       'required_bytes=' + str(128 * speech.MIB + 3 * amount),
                                       'reserved_bytes=' + str(2 * amount), 'requested_bytes=' + str(amount)):
                            self.assertIn(detail, str(error.exception))
                        break
                    job.acquire()
                    raw.write_bytes(bytes(4096))
                    final = audio / ('announcement_tts_20260101010101_%032x.wav' % index)
                    final.write_bytes(raw.read_bytes())
                    raw.unlink()
                    if completed:
                        job.complete()
                finally:
                    job.close()
            self.assertEqual(len(list(audio.glob('*.wav'))), 14 if completed else 2)

    def split_destination_admission(self):
        data = Path('/run/sls-prompt-data') / 'destination-ledger'
        (data / 'sounds/tts').mkdir(parents=True)
        for name, reason in [('output-low', 'protected free-space reserve'), ('output-full', 'available_inodes=0'),
                             ('output-ro', 'read_only=1'), ('output-ready', None)]:
            with self.subTest(mount=name):
                target = Path('/tmp') / name
                source = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    job = speech.Admission(self.config, 600, data, self.web, additional_media_directory_fd=source)
                finally:
                    os.close(source)
                try:
                    if reason is None:
                        # Destination shares the same 376 MiB mount as /tmp. A double byte charge would refuse.
                        job.acquire()
                        job.complete()
                    else:
                        with self.assertRaisesRegex(speech.SpeechCapacityError, reason) as error:
                            job.acquire()
                        self.assertIn('role=destination', str(error.exception))
                finally:
                    job.close()
        # Two admitted workers must not claim the same last output inode while
        # the first is still processing its input on another filesystem.
        source = os.open('/tmp/output-single', os.O_RDONLY | os.O_DIRECTORY)
        try:
            config = {**self.config, 'speech_synthesis_limit': 2}
            first = speech.Admission(config, 600, data, self.web, additional_media_directory_fd=source)
            second = speech.Admission(config, 600, data, self.web, additional_media_directory_fd=source)
            try:
                first.acquire()
                with self.assertRaisesRegex(speech.SpeechCapacityError, 'available_inodes=1 required_inodes=2') as error:
                    second.acquire()
                self.assertIn('role=destination', str(error.exception))
                self.assertIn('outstanding_reservations=1', str(error.exception))
                first.complete()
            finally:
                first.close()
                second.close()
            retry = speech.Admission(config, 600, data, self.web, additional_media_directory_fd=source)
            try:
                retry.acquire()
                retry.complete()
            finally:
                retry.close()
        finally:
            os.close(source)
        # Scratch needs three nodes. On a shared mount the output stage needs a fourth.
        for inode_limit, shared, available, required in [(3, False, 2, 3), (5, True, 3, 4)]:
            subprocess.run(['mount', '-t', 'tmpfs', '-o', f'size=376m,nr_inodes={inode_limit}', 'tmpfs', '/tmp'], check=True)
            try:
                destination = data
                if shared:
                    destination = Path('/tmp/paging')
                    destination.mkdir()
                source = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    job = speech.Admission(self.config, 600, data, self.web, additional_media_directory_fd=source)
                finally:
                    os.close(source)
                try:
                    with self.assertRaises(speech.SpeechCapacityError) as error:
                        job.acquire()
                    self.assertIn('role=temporary', str(error.exception))
                    self.assertIn(f'available_inodes={available} required_inodes={required}', str(error.exception))
                finally:
                    job.close()
            finally:
                subprocess.run(['umount', '/tmp'], check=True)

    def test_capacity_diagnostics_identify_numbers_without_private_names(self):
        private_name = 'announcement_tts_private_fixture.wav'
        (self.root / 'sounds/tts' / private_name).write_bytes(bytes(4096))
        holder = self.admission()
        holder.reserve_media(1024)
        holder.close()
        job = speech.Admission({**self.config, 'generated_media_cache_mib': 64}, 600, self.root, self.web)
        self.addCleanup(job.close)
        with self.assertRaises(speech.SpeechCapacityError) as refusal:
            job.acquire()
        for detail in ('limit_bytes=67108864', 'used_bytes=4096', 'reserved_bytes=1024',
                       'requested_bytes=97048576', 'required_bytes=97053696'):
            self.assertIn(detail, str(refusal.exception))
        self.assertNotIn(private_name, str(refusal.exception))
        media = self.admission()
        with mock.patch.object(speech, 'MAX_GENERATED_FILES', 1), self.assertRaises(speech.SpeechCapacityError) as refusal:
            media.reserve_media(10)
        self.assertIn('file_count=1 limit_files=1', str(refusal.exception))
        for role, target in (('data', self.root), ('web', self.web), ('temporary', Path('/tmp'))):
            def capacity(path):
                low = path == target or (role == 'data' and path == media.fd)
                return SimpleNamespace(f_bavail=1 if low else 10**9, f_frsize=4, f_flag=0, f_files=1000, f_favail=999)
            with self.subTest(role=role), mock.patch.object(os, 'statvfs', side_effect=capacity), self.assertRaises(speech.SpeechCapacityError) as refusal:
                media.reserve_media(10)
            for detail in ('role=' + role, 'available_bytes=4', 'required_bytes=134218762',
                           'reserve_bytes=134217728', 'reserved_bytes=1024', 'requested_bytes=10'):
                self.assertIn(detail, str(refusal.exception))
            self.assertNotIn(str(self.root), str(refusal.exception))

    def test_completion_preserves_other_reservations_and_crash_fallback(self):
        crashed = os.fork()
        if crashed == 0:
            try:
                self.admission().acquire()
                os._exit(0)
            except BaseException:
                os._exit(1)
        self.assertEqual(os.waitpid(crashed, 0)[1], 0)
        state = self.root / 'speech-slot-00.json'
        initial = json.loads(state.read_text())
        self.assertEqual(len(initial), 1)
        self.assertGreater(initial[0]['expires'], time.time() + 60)
        media = self.admission()
        media.reserve_media(speech.MIB)
        media.close()
        before = json.loads(state.read_text())
        completed = self.admission().acquire()
        self.assertEqual(len(json.loads(state.read_text())), len(before) + 1)
        completed.complete()
        completed.close()
        self.assertEqual(json.loads(state.read_text()), before)

    def test_completion_write_failure_keeps_record_and_releases_slot(self):
        completed = self.admission().acquire()
        state = self.root / 'speech-slot-00.json'
        before = state.read_bytes()
        with mock.patch.object(completed, 'write', side_effect=OSError('persistence failed')):
            with self.assertRaisesRegex(OSError, 'persistence failed'):
                completed.complete()
        self.assertEqual(state.read_bytes(), before)
        self.assertIsNone(completed.fd)
        self.assertIsNotNone(self.admission().acquire().active)

    def test_regular_control_contention_waits_for_the_current_writer(self):
        holder=self.admission()
        descriptor=holder.file('speech-admission.lock')
        holder.lock_control(descriptor)
        errors=[]
        completed=threading.Event()
        other=self.admission()
        def work():
            try:
                other.acquire()
                completed.set()
            except BaseException as error:
                errors.append(error)
        thread=threading.Thread(target=work)
        thread.start()
        time.sleep(.15)
        fcntl.flock(descriptor,fcntl.LOCK_UN)
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors,[])
        self.assertTrue(completed.is_set())

    def test_configured_parallel_limit_and_bounded_queue(self):
        config = {'speech_queue_wait_seconds': 0, 'speech_synthesis_limit': 2, 'speech_queue_limit': 2}
        self.admission(config).acquire(); self.admission(config).acquire()
        third = self.admission(config)
        with self.assertRaisesRegex(speech.SpeechAdmissionError, 'waited too long'): third.acquire()
        third.close()
        waiting=[]
        for index in range(2):
            path=self.root/('speech-wait-%02d.lock' % index);file=path.open('a+');path.chmod(0o640)
            self.addCleanup(file.close);fcntl.flock(file,fcntl.LOCK_EX|fcntl.LOCK_NB);waiting.append(file)
        with self.assertRaisesRegex(speech.SpeechAdmissionError, 'queue is full'): self.admission(config).acquire()

    def test_lite_profile_enforces_runtime_limits_even_if_config_is_malformed(self):
        admission = self.admission({'deployment_profile': 'lite', 'speech_queue_wait_seconds': 0})
        self.assertEqual((admission.limit, admission.queue), (1, 2))
        for config in ({'deployment_profile': 'lite', 'speech_synthesis_limit': 2},
                       {'deployment_profile': 'lite', 'speech_queue_limit': 3},
                       {'deployment_profile': 'unknown'}):
            with self.subTest(config=config), self.assertRaisesRegex(speech.SpeechAdmissionError, 'Invalid speech admission setting'):
                self.admission(config)

    def test_current_media_and_reserved_work_share_the_budget(self):
        path = self.root / 'sounds/tts/announcement_tts_fixture.wav'
        with path.open('wb') as handle: handle.truncate(64 * speech.MIB)
        with self.assertRaisesRegex(speech.SpeechAdmissionError, 'cache budget'):
            self.admission({'speech_queue_wait_seconds': 0, 'generated_media_cache_mib': 64}).acquire()
        self.assertTrue(path.exists(), 'Quota enforcement deleted referenced/new media')

    def test_non_speech_reserves_without_using_synthesis_slot(self):
        first = self.admission().acquire()
        media = self.admission(); media.reserve_media(speech.MIB)
        self.assertIsNone(media.active)
        records = [row for file in self.root.glob('speech-slot-*.json') for row in json.loads(file.read_text() or '[]')]
        self.assertEqual(sum(row['bytes'] for row in records), first.bytes + speech.MIB)

    def test_reservation_reads_and_writes_reject_replaced_names(self):
        admission = self.admission()
        control = admission.file('speech-admission.lock');self.assertTrue(admission.available(control))
        slot = admission.file('speech-slot-00.lock');self.assertTrue(admission.available(slot))
        state = self.root/'speech-slot-00.json';state.write_text('[]');state.chmod(0o640)
        displaced = self.root/'displaced.json';real_stat = speech.os.stat;replaced = False
        def replace_read(name, *args, **kwargs):
            nonlocal replaced
            if name == state.name and kwargs.get('dir_fd') == admission.fd and not replaced:
                state.rename(displaced);state.write_text('[]');state.chmod(0o640);replaced = True
            return real_stat(name, *args, **kwargs)
        with mock.patch.object(speech.os, 'stat', side_effect=replace_read):
            with self.assertRaisesRegex(speech.SpeechAdmissionError, 'changed while being read'):
                admission.record(slot)
        state.unlink();displaced.rename(state);replaced = False
        staged = self.root/'staged-original'
        def replace_write(name, *args, **kwargs):
            nonlocal replaced
            if isinstance(name, str) and name.startswith('.speech-budget-') and kwargs.get('dir_fd') == admission.fd and not replaced:
                (self.root/name).rename(staged);(self.root/name).write_text('[]');(self.root/name).chmod(0o640);replaced = True
            return real_stat(name, *args, **kwargs)
        with mock.patch.object(speech.os, 'stat', side_effect=replace_write):
            with self.assertRaisesRegex(speech.SpeechAdmissionError, 'staging changed'):
                admission.write(slot, [])
        self.assertTrue(staged.exists())
        altered = False
        def alter_write(name, *args, **kwargs):
            nonlocal altered
            if isinstance(name, str) and name.startswith('.speech-budget-') and kwargs.get('dir_fd') == admission.fd and not altered:
                (self.root/name).chmod(0o666);altered = True
            return real_stat(name, *args, **kwargs)
        with mock.patch.object(speech.os, 'stat', side_effect=alter_write):
            with self.assertRaisesRegex(speech.SpeechAdmissionError, 'staging changed'):
                admission.write(slot, [])

    def test_unsafe_lock_and_invalid_config_rejected(self):
        os.symlink(self.root/'outside', self.root/'speech-admission.lock')
        with self.assertRaises(OSError): self.admission().acquire()
        for value in ('1', True, 0, 5):
            with self.assertRaises(speech.SpeechAdmissionError): speech.Admission({'speech_synthesis_limit': value}, 30, self.root, self.web)

    def test_child_timeout_stops_processing_and_returns_explicit_code(self):
        marker = self.root/'should-not-exist'
        command = [sys.executable, '-c', 'import time,pathlib;time.sleep(3);pathlib.Path('+repr(str(marker))+').write_text("bad")']
        self.assertEqual(speech.launch(command, .1), 124)
        self.assertFalse(marker.exists())

    def test_child_receives_only_the_bounded_runtime_environment(self):
        command = [sys.executable, '-c', 'import os,sys;sys.exit(9 if os.getenv("SLS_PRIVATE_PARENT_TOKEN") else 0)']
        with mock.patch.dict(os.environ, {'SLS_PRIVATE_PARENT_TOKEN': 'must-not-leak'}):
            self.assertEqual(speech.launch(command, 2), 0)

    def test_cli_cannot_execute_arbitrary_programs(self):
        result = subprocess.run([sys.executable, '-I', speech.__file__, '--max-seconds', '30', '--', '/bin/true'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def synthesis_command(self, duration=1, rate=16000, force_success=False, noisy=False):
        model = self.root/'voice.onnx'
        model.with_suffix('.onnx.json').write_text(json.dumps({'audio': {'sample_rate': rate}}))
        script = self.root/'producer.py'
        script.write_text('''import argparse, json, sys, wave
p=argparse.ArgumentParser();p.add_argument('--model');p.add_argument('--output-file');a=p.parse_args()
rate=json.load(open(a.model+'.json'))['audio']['sample_rate']
try:
 with wave.open(a.output_file,'wb') as output:
  output.setnchannels(1);output.setsampwidth(2);output.setframerate(rate)
  for _ in range(int(DURATION*10)):output.writeframes(b'\\0\\0'*int(rate/10))
except OSError:
 if not FORCE_SUCCESS:raise
if NOISY:sys.stderr.write('diagnostic\\n'*20000)
'''.replace('DURATION',repr(duration)).replace('FORCE_SUCCESS',repr(force_success)).replace('NOISY',repr(noisy)))
        return [sys.executable, str(script), '--model', str(model), '--output-file', str(self.root/'speech.wav')]

    def test_exact_duration_and_catalog_rates_fit_reserved_workspace(self):
        for rate in (16000,22050,48000):
            command=self.synthesis_command(rate=rate)
            self.assertEqual(speech.synthesize(command, 1, 3),0)
            path=self.root/'speech.wav'
            self.assertEqual(path.stat().st_size, rate*2+44)
            self.assertLess(path.stat().st_size, self.admission().bytes)
            path.unlink()

    def test_overlong_duration_below_byte_guard_is_rejected(self):
        diagnostic=io.StringIO()
        with redirect_stderr(diagnostic):
            self.assertEqual(speech.synthesize(self.synthesis_command(1.2),1,3),65)
        self.assertIn('configured maximum of 1 seconds',diagnostic.getvalue())
        self.assertFalse((self.root/'speech.wav').exists())

    def test_kernel_cap_rejects_partial_success_and_leaves_parent_writes_unlimited(self):
        command=self.synthesis_command(20,force_success=True,noisy=True)
        command,descriptor,output,bound=speech.speech_output(command,1)
        large_log=self.root/'existing.log'
        with large_log.open('wb') as log:log.truncate(2*speech.MIB)
        try:
            with large_log.open('a') as log, redirect_stderr(log):
                self.assertEqual(speech.launch(command,3,output_fd=descriptor,max_bytes=bound),65)
            self.assertEqual(os.fstat(descriptor).st_size,bound)
            self.assertEqual(large_log.stat().st_size,2*speech.MIB+speech.MAX_DIAGNOSTIC_BYTES)
            admission=self.admission().acquire();admission.close()
            self.assertTrue((self.root/'speech-slot-00.json').exists(),'Child file limit blocked parent admission state')
        finally:
            os.close(descriptor)

    def test_full_synthesis_discards_bound_reached_output_and_unsafe_targets(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(speech.synthesize(self.synthesis_command(20,force_success=True),1,3),65)
        self.assertFalse((self.root/'speech.wav').exists())
        command=self.synthesis_command()
        path=self.root/'speech.wav';path.write_bytes(b'previous audio')
        with self.assertRaisesRegex(speech.SpeechAdmissionError,'empty private'):
            speech.speech_output(command,1)
        self.assertEqual(path.read_bytes(),b'previous audio')
        path.write_bytes(b'');path.chmod(0o644)
        with self.assertRaisesRegex(speech.SpeechAdmissionError,'empty private'):
            speech.speech_output(command,1)
        path.unlink();os.symlink(self.root/'outside',path)
        with self.assertRaises(OSError):speech.speech_output(command,1)
        path.unlink()
        metadata=self.root/'voice.onnx.json';metadata.write_text('{"audio":{"sample_rate":96000}}')
        with self.assertRaisesRegex(speech.SpeechAdmissionError,'unsupported sample rate'):
            speech.speech_output(command,1)
        for value in ('[]','{"audio":[]}','{broken'):
            metadata.write_text(value)
            with self.assertRaisesRegex(speech.SpeechAdmissionError,'voice metadata is invalid'):
                speech.speech_output(command,1)

    def test_success_requires_the_original_private_output_path(self):
        command = self.synthesis_command()
        original = self.root/'speech.wav'
        displaced = self.root/'displaced.wav'
        def replace_output(_command, _timeout, _slot, descriptor, _limit):
            with os.fdopen(os.dup(descriptor), 'wb') as raw:
                import wave
                with wave.open(raw, 'wb') as output:
                    output.setnchannels(1);output.setsampwidth(2);output.setframerate(16000)
                    output.writeframes(b'\0\0' * 16000)
            original.rename(displaced)
            original.write_bytes(b'replacement')
            original.chmod(0o600)
            return 0
        with mock.patch.object(speech, 'launch', side_effect=replace_output):
            self.assertEqual(speech.synthesize(command, 1, 3), 74)
        self.assertEqual(original.read_bytes(), b'replacement')
        self.assertTrue(displaced.exists())

    def test_killed_supervisor_cannot_leave_synthesis_running(self):
        child_pid = self.root/'child.pid'
        marker = self.root/'late-output'
        child_code = 'import os,time,pathlib;pathlib.Path('+repr(str(child_pid))+').write_text(str(os.getpid()));time.sleep(30);pathlib.Path('+repr(str(marker))+').touch()'
        supervisor_code = 'import sys;sys.path.insert(0,'+repr(str(Path(speech.__file__).parent))+');import sls_speech_admission as s;s.launch('+repr([sys.executable,'-c',child_code])+',60)'
        supervisor = subprocess.Popen([sys.executable,'-c',supervisor_code])
        try:
            deadline = time.monotonic()+3
            while not child_pid.exists() and time.monotonic()<deadline:time.sleep(.02)
            self.assertTrue(child_pid.exists())
            pid = int(child_pid.read_text())
            supervisor.kill(); supervisor.wait(timeout=2)
            deadline = time.monotonic()+3
            while time.monotonic()<deadline:
                try: state = Path('/proc/'+str(pid)+'/stat').read_text().split()[2]
                except FileNotFoundError: break
                if state == 'Z': break
                time.sleep(.02)
            else: self.fail('Speech child survived its killed supervisor')
            self.assertFalse(marker.exists())
        finally:
            if supervisor.poll() is None:supervisor.kill();supervisor.wait(timeout=2)


if __name__ == '__main__':
    if os.environ.get('SLS_ORDINARY_SPEECH_ONLY')=='1':
        names=['test_shared_limit_queue_and_immediate_reuse','test_non_speech_reserves_without_using_synthesis_slot',
               'test_regular_control_contention_waits_for_the_current_writer','test_exact_duration_and_catalog_rates_fit_reserved_workspace']
        result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(SpeechTests(name) for name in names))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main()
