#!/usr/bin/python3
"""Actual interrupted publication must remain readable and safely retryable."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import sys
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


transaction = load('interrupted_transaction', HELPERS / 'sls_install_transaction.py')
permission = load('interrupted_permission', HELPERS / 'sls_legacy_permissions.py')
JOURNAL_CHILD = r'''
import importlib.util,os,pathlib,signal,sys
spec=importlib.util.spec_from_file_location('child_transaction',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
def die(*args,**kwargs):os.kill(os.getpid(),signal.SIGKILL)
module.os.replace=die
if sys.argv[2]=='begin':module.begin(pathlib.Path(sys.argv[3]))
else:module.update(pathlib.Path(sys.argv[3]),'abandoned',{})
'''
CHOWN_CHILD = r'''
import importlib.util,os,pathlib,signal,sys
spec=importlib.util.spec_from_file_location('child_permission',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
replace=module.os.replace
def die_after_publish(*args,**kwargs):
    result=replace(*args,**kwargs)
    os.kill(os.getpid(),signal.SIGKILL)
module.os.replace=die_after_publish
module.protect_chown(*map(pathlib.Path,sys.argv[2:]))
'''


class InterruptedJournal(unittest.TestCase):
    def kill_at_publish(self, operation, path):
        result = subprocess.run([sys.executable, '-I', '-c', JOURNAL_CHILD,
            str(HELPERS / 'sls_install_transaction.py'), operation, str(path)],
            capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)

    def discover(self, root):
        return subprocess.run(['bash', '-c',
            'source "$1"; INSTALL_TRANSACTION_ROOT="$2"; check_interrupted_installation',
            'fixture', str(ROOT / 'tools/install_release.sh'), str(root)],
            capture_output=True, text=True, timeout=8)

    def test_first_created_zero_byte_temporary_does_not_authorize_or_block_new_install(self):
        child = r'''
import importlib.util,os,pathlib,signal,sys
spec=importlib.util.spec_from_file_location('created_only_transaction',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
original_open=module.os.open
def die_after_create(name,*args,**kwargs):
    descriptor=original_open(name,*args,**kwargs)
    if isinstance(name,str) and name.startswith('.new-') and args and args[0]&os.O_CREAT:
        os.kill(os.getpid(),signal.SIGKILL)
    return descriptor
module.os.open=die_after_create
module.begin(pathlib.Path(sys.argv[2]))
'''
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name)/'journal'
            result=subprocess.run([sys.executable,'-I','-c',child,
                str(HELPERS/'sls_install_transaction.py'),str(root)],capture_output=True,text=True,timeout=8)
            self.assertEqual(result.returncode,-signal.SIGKILL,result.stderr)
            interrupted=next(root.iterdir());temporary=next(interrupted.glob('.new-*'))
            self.assertEqual(temporary.read_bytes(),b'')
            self.assertEqual(stat.S_IMODE(temporary.stat().st_mode),0o600)
            with self.subTest(boundary='helper-discovery'):
                self.assertEqual(transaction.pending(root),[])
            with self.subTest(boundary='early-shell-discovery'):
                discovery=self.discover(root)
                self.assertEqual(discovery.returncode,0,discovery.stdout+discovery.stderr)
            with self.subTest(boundary='new-begin-and-cleanup'):
                created=transaction.begin(root)
                self.assertNotEqual(created,interrupted)
                self.assertEqual(transaction.state(interrupted)['phase'],'abandoned')
                self.assertFalse((interrupted/'installer.sh').exists())
            self.assertEqual(temporary.read_bytes(),b'')

    def test_partial_nonempty_first_temporary_is_preserved_and_refused(self):
        child = r'''
import importlib.util,os,pathlib,signal,sys
spec=importlib.util.spec_from_file_location('partial_first_transaction',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
original_fdopen=module.os.fdopen
class PartialFirstWrite:
    def __init__(self,stream):self.stream=stream
    def __enter__(self):self.stream.__enter__();return self
    def __exit__(self,*args):return self.stream.__exit__(*args)
    def write(self,body):
        self.stream.write(body[:1]);self.stream.flush();os.fsync(self.stream.fileno())
        os.kill(os.getpid(),signal.SIGKILL)
def partial(fd,*args,**kwargs):return PartialFirstWrite(original_fdopen(fd,*args,**kwargs))
module.os.fdopen=partial
module.begin(pathlib.Path(sys.argv[2]))
'''
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name)/'journal'
            result=subprocess.run([sys.executable,'-I','-c',child,
                str(HELPERS/'sls_install_transaction.py'),str(root)],capture_output=True,text=True,timeout=8)
            self.assertEqual(result.returncode,-signal.SIGKILL,result.stderr)
            interrupted=next(root.iterdir());temporary=next(interrupted.glob('.new-*'))
            self.assertEqual(temporary.read_bytes(),b'{')
            with self.assertRaises((transaction.TransactionError,json.JSONDecodeError)):transaction.pending(root)
            self.assertNotEqual(self.discover(root).returncode,0)
            with self.assertRaises((transaction.TransactionError,json.JSONDecodeError)):transaction.begin(root)
            self.assertEqual(temporary.read_bytes(),b'{')

    def empty_initial(self, parent):
        root=parent/'journal';root.mkdir(mode=0o700)
        interrupted=root/('transaction-'+'b'*24);interrupted.mkdir(mode=0o700)
        temporary=interrupted/('.new-'+'a'*24);temporary.write_bytes(b'');temporary.chmod(0o600)
        return root,interrupted,temporary

    def test_helper_alone_archives_only_the_same_unwritten_first_journal(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root,interrupted,temporary=self.empty_initial(Path(name))
            original=temporary.stat()
            created=transaction.begin(root)
            self.assertNotEqual(created,interrupted)
            marker=transaction.state(interrupted)
            self.assertEqual(marker['phase'],'abandoned')
            self.assertIs(marker['empty_preparation'],True)
            self.assertEqual(marker['settings'],{})
            self.assertEqual(marker['empty_preparation_temporary']['inode'],original.st_ino)
            self.assertEqual(temporary.read_bytes(),b'')
            self.assertEqual(self.discover(root).returncode,0)

    def test_archived_zero_binding_never_approves_changed_or_noninitial_evidence(self):
        for kind in('replacement','mode','owner','hardlink','multiple','artifact','partial',
                    'marker-settings','marker-extra','marker-flag','marker-phase','marker-bool-identity'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir='/run') as name:
                parent=Path(name);root,interrupted,temporary=self.empty_initial(parent)
                discovered=self.discover(root)
                self.assertEqual(discovered.returncode,0,discovered.stderr)
                marker_path=interrupted/'transaction.json';marker=json.loads(marker_path.read_bytes())
                self.assertEqual(marker['empty_preparation_temporary']['name'],temporary.name)
                if kind=='replacement':
                    other=parent/'replacement';other.write_bytes(b'');other.chmod(0o600);os.replace(other,temporary)
                if kind=='mode':temporary.chmod(0o640)
                if kind=='owner':os.chown(temporary,pwd.getpwnam('asterisk').pw_uid,pwd.getpwnam('asterisk').pw_gid)
                if kind=='hardlink':os.link(temporary,parent/'outside-link')
                if kind=='multiple':extra=interrupted/('.new-'+'c'*24);extra.write_bytes(b'');extra.chmod(0o600)
                if kind=='artifact':extra=interrupted/'installer.sh';extra.write_bytes(b'unapproved');extra.chmod(0o600)
                if kind=='partial':temporary.write_bytes(b'{')
                if kind=='marker-settings':marker['settings']={'MODULE_ACTIVATED':'1'}
                if kind=='marker-extra':marker['stage']='initialization'
                if kind=='marker-flag':marker['empty_preparation']=False
                if kind=='marker-phase':marker['phase']='committed'
                if kind=='marker-bool-identity':marker['empty_preparation_temporary']['nlink']=True
                if kind.startswith('marker-'):marker_path.write_text(json.dumps(marker));marker_path.chmod(0o600)
                original=marker_path.read_bytes()
                with self.assertRaises(transaction.TransactionError):transaction.pending(root)
                self.assertNotEqual(self.discover(root).returncode,0)
                with self.assertRaises(transaction.TransactionError):transaction.begin(root)
                self.assertEqual(marker_path.read_bytes(),original)

    def test_unbound_zero_is_not_accepted_as_an_ordinary_terminal_afterimage(self):
        for phase in('committed','rolled_back','abandoned'):
            with self.subTest(phase=phase),tempfile.TemporaryDirectory(dir='/run') as name:
                root,interrupted,temporary=self.empty_initial(Path(name))
                transaction.atomic(interrupted/'transaction.json',{'schema':1,'directory':str(interrupted),
                    'phase':phase,'created_at':0,'updated_at':0,'settings':{}})
                marker=(interrupted/'transaction.json').read_bytes()
                with self.assertRaises((transaction.TransactionError,json.JSONDecodeError)):transaction.begin(root)
                self.assertEqual((interrupted/'transaction.json').read_bytes(),marker)
                self.assertEqual(temporary.read_bytes(),b'')

    def test_empty_temporary_never_approves_unknown_unsafe_or_noninitial_evidence(self):
        for kind in('mode','owner','hardlink','multiple','artifact','unknown-name','symlink'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir='/run') as name:
                parent=Path(name);root=parent/'journal';root.mkdir(mode=0o700)
                interrupted=root/('transaction-'+'b'*24);interrupted.mkdir(mode=0o700)
                temporary=interrupted/('.new-'+'a'*24);temporary.write_bytes(b'');temporary.chmod(0o600)
                if kind=='mode':temporary.chmod(0o640)
                if kind=='owner':os.chown(temporary,pwd.getpwnam('asterisk').pw_uid,pwd.getpwnam('asterisk').pw_gid)
                if kind=='hardlink':os.link(temporary,parent/'outside-link')
                if kind=='multiple':extra=interrupted/('.new-'+'c'*24);extra.write_bytes(b'');extra.chmod(0o600)
                if kind=='artifact':extra=interrupted/'installer.sh';extra.write_bytes(b'unapproved');extra.chmod(0o600)
                if kind=='unknown-name':temporary.rename(interrupted/'.unexpected')
                if kind=='symlink':temporary.unlink();temporary.symlink_to(parent/'missing')
                with self.assertRaises((transaction.TransactionError,json.JSONDecodeError)):transaction.pending(root)
                self.assertNotEqual(self.discover(root).returncode,0)
                with self.assertRaises((transaction.TransactionError,json.JSONDecodeError)):transaction.begin(root)
                self.assertFalse((interrupted/'transaction.json').exists())

    def test_first_private_preparing_temporary_does_not_authorize_or_block_new_install(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name) / 'journal'; self.kill_at_publish('begin', root)
            interrupted = next(root.iterdir()); temporary = next(interrupted.iterdir())
            original = temporary.read_bytes()
            self.assertEqual(json.loads(original)['phase'], 'preparing')
            self.assertEqual(transaction.pending(root), [])
            discovery = self.discover(root)
            self.assertEqual(discovery.returncode, 0, discovery.stdout + discovery.stderr)
            created = transaction.begin(root)
            self.assertNotEqual(created, interrupted)
            self.assertEqual(transaction.state(interrupted)['phase'], 'abandoned')
            self.assertEqual(temporary.read_bytes(), original)
            self.assertFalse((interrupted / 'installer.sh').exists())

    def test_late_private_temporary_preserves_published_state_and_retry_evidence(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name) / 'journal'; interrupted = transaction.begin(root)
            self.kill_at_publish('update', interrupted)
            temporary = next(interrupted.glob('.new-*')); original = temporary.read_bytes()
            discovery = self.discover(root)
            self.assertEqual(discovery.returncode, 0, discovery.stdout + discovery.stderr)
            self.assertEqual(transaction.state(interrupted)['phase'], 'abandoned')
            created = transaction.begin(root)
            self.assertNotEqual(created, interrupted)
            self.assertEqual(temporary.read_bytes(), original)

    def test_unknown_or_unbound_temporary_is_preserved_and_refused(self):
        for name, body in [('.new-' + 'a' * 24, b'{"schema":1,"directory":"/different","phase":"preparing"}'),
                           ('.unexpected-evidence', b'preserve unknown evidence')]:
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir='/run') as directory:
                root = Path(directory) / 'journal'; root.mkdir(mode=0o700)
                interrupted = root / ('transaction-' + 'b' * 24); interrupted.mkdir(mode=0o700)
                evidence = interrupted / name; evidence.write_bytes(body); evidence.chmod(0o600)
                with self.assertRaises(transaction.TransactionError): transaction.begin(root)
                self.assertNotEqual(self.discover(root).returncode, 0)
                self.assertEqual(evidence.read_bytes(), body)


class ChownPublication(unittest.TestCase):
    def paths(self, root, uid, gid, mode):
        root.chmod(0o755)
        private = root / 'private'; private.mkdir(mode=0o700)
        approval = private / 'approval.json'
        approval.write_text('{"schema":1,"source":"fresh-install","files":{}}'); approval.chmod(0o600)
        config = root / 'freepbx_chown.conf'; original = b'; independent native rules\n[blacklist]\ndirectory=/srv/keep\n'
        config.write_bytes(original); os.chown(config, uid, gid); config.chmod(mode)
        return config, private / 'snapshot.json', approval, original

    def test_final_metadata_is_applied_before_native_config_becomes_visible(self):
        account = pwd.getpwnam('asterisk')
        for uid, gid, mode in [(0, 0, 0o644), (account.pw_uid, account.pw_gid, 0o664)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir='/run') as name:
                config, snapshot, approval, original = self.paths(Path(name), uid, gid, mode)
                result = subprocess.run([sys.executable, '-I', '-c', CHOWN_CHILD,
                    str(HELPERS / 'sls_legacy_permissions.py'), str(config), str(snapshot), str(approval)],
                    capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
                info = config.stat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (uid, gid, mode))
                self.assertEqual(config.read_bytes(), permission.chown_transform(original))
                self.assertTrue(permission.restore_chown(config, snapshot)['ok'])
                self.assertEqual(config.read_bytes(), original)

    def test_legacy_exact_root_private_afterimage_can_restore_from_protected_snapshot(self):
        account = pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(dir='/run') as name:
            config, snapshot, approval, original = self.paths(Path(name), account.pw_uid, account.pw_gid, 0o664)
            permission.protect_chown(config, snapshot, approval)
            # Exact older publisher writer's documented post-rename state.
            os.chown(config, 0, 0); config.chmod(0o600)
            self.assertTrue(permission.restore_chown(config, snapshot)['ok'])
            info = config.stat()
            self.assertEqual(config.read_bytes(), original)
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                             (account.pw_uid, account.pw_gid, 0o664))

    def test_same_intermediate_metadata_never_authorizes_changed_native_bytes(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            config, snapshot, approval, original = self.paths(Path(name), 0, 0, 0o644)
            permission.protect_chown(config, snapshot, approval)
            changed = config.read_bytes() + b'; independent administrator rule\n'
            config.write_bytes(changed); os.chown(config, 0, 0); config.chmod(0o600)
            before = snapshot.read_bytes()
            with self.assertRaises(permission.PermissionRecoveryError): permission.restore_chown(config, snapshot)
            self.assertEqual(config.read_bytes(), changed)
            self.assertEqual(snapshot.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
