#!/usr/bin/python3
"""Behavioral Piper repair/publication regressions over private inert files."""
import importlib.util
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/'slsmassnotifyserver/bin/sls_mass_notify'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
environment=load('piper_lifecycle_environment',RUNTIME/'sls_piper_environment.py')
dependency_fixture=load('piper_lifecycle_dependency_fixture',ROOT/'tools/test_piper_dependencies.py')
VOICE=(ROOT/'slsmassnotifyserver/bin/sls_mass_notify_install_piper_voices.sh').read_text()
PRODUCER=VOICE.split('install_piper_compatibility_path() {',1)[1].split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
class PiperLifecycle(unittest.TestCase):
    def test_stale_console_shebang_replaces_otherwise_healthy_environment(self):
        write=Path.write_text
        def stale_entry(path,text,*args,**kwargs):
            if path.name=='piper' and path.parent.name=='bin' and 'sls-piper-runtime-' in str(path) and '.replacement-' not in str(path):
                text='#!/missing-sls-piper-interpreter\n'
            return write(path,text,*args,**kwargs)
        fixture=dependency_fixture.PiperDependencyTests()
        with mock.patch.object(Path,'write_text',stale_entry):
            result,installs,rebuilt=fixture.runtime_fixture('exact')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertTrue(rebuilt,'A protected stale console entry point must trigger the normal replacement path')
        self.assertEqual(len(installs),2)

    def test_restrictive_caller_umask_keeps_activated_environment_readable_by_asterisk(self):
        account=pwd.getpwnam('asterisk')
        for caller_umask in (0o027,0o077):
            with self.subTest(umask=oct(caller_umask)),tempfile.TemporaryDirectory(dir='/tmp',prefix='sls-piper-publish-mode-') as name:
                base=Path(name);base.chmod(0o755);root=base/'runtime';root.mkdir();root.chmod(0o755)
                (root/'venv').mkdir();(root/'venv').chmod(0o755)
                def build(stage,lock):
                    payload=stage/'venv/payload';payload.write_bytes(b'validated inert package');payload.chmod(0o644)
                old=os.umask(caller_umask)
                try:
                    # Permissions/publication use inert files under the namespace mounts.
                    with mock.patch.object(environment,'admit_replacement_capacity') as admission:
                        environment.replace_environment(root,build,lambda unused:None,workers_paused=True)
                        admission.assert_called_once_with(root,profile=None)
                finally:os.umask(old)
                result=subprocess.run(['/usr/bin/python3','-I','-c','from pathlib import Path;import sys;print(Path(sys.argv[1]).read_text())',str(root/'venv/payload')],user=account.pw_uid,group=account.pw_gid,extra_groups=[],capture_output=True,text=True,timeout=4)
                self.assertEqual(result.returncode,0,'Published environment must be traversable by its service account: '+result.stderr)
                self.assertEqual(result.stdout.strip(),'validated inert package')

    def test_retry_finishes_only_its_exact_root_owned_compatibility_symlink(self):
        if os.environ.get('SLS_TEST_NAMESPACE')!='entered':self.skipTest('Official namespace wrapper required')
        root=Path('/var/lib/asterisk/SLS_Mass_Notifications_Plugin/piper')
        self.assertFalse(root.exists(),'Private state must begin absent')
        binary=root/'venv/bin';binary.mkdir(parents=True)
        for parent in (root,root/'venv',binary):parent.chmod(0o755)
        self.addCleanup(shutil.rmtree,root)
        pending=binary/('.piper.'+'a'*16);pending.symlink_to('/usr/local/bin/piper')
        result=subprocess.run(['/usr/bin/python3','-I','-c',PRODUCER],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,'Recognized interrupted publication must be retryable: '+result.stderr)
        self.assertFalse(pending.is_symlink())
        self.assertEqual(os.readlink(binary/'piper'),'/usr/local/bin/piper')
        (binary/'piper').unlink();unknown=binary/('.piper.'+'b'*16);unknown.symlink_to('/administrator-owned-target')
        rejected=subprocess.run(['/usr/bin/python3','-I','-c',PRODUCER],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(rejected.returncode,0)
        self.assertEqual(os.readlink(unknown),'/administrator-owned-target')
if __name__=='__main__':unittest.main()
