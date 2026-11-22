#!/usr/bin/python3
"""Actual retained Piper build evidence versus runtime-account measurement.

Only disposable inert directories are exchanged. The unmodified replacement
function creates a real root-private failed stage and later succeeds without
removing that older evidence. The real measure_tree function runs as asterisk;
no installed helper, application process, network or package installation runs.
"""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

for label, kind in [('MOUNT', 'mnt'), ('NET', 'net'), ('PID', 'pid')]:
    if (os.environ.get('SLS_TEST_NAMESPACE') != 'entered'
            or os.environ.get('SLS_TEST_PARENT_' + label + '_NS')
            in (None, '', os.readlink('/proc/self/ns/' + kind))):
        raise SystemExit('Fresh private namespace required; no runtime was used.')

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


environment = load('audit_private_piper_environment', RUNTIME / 'sls_piper_environment.py')
resource = load('audit_private_piper_resource', RUNTIME / 'sls_resource_capacity.py')
READ = r'''
import importlib.util,json,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('audit_resource_reader',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
try:
    result=module.measure_tree(Path(sys.argv[2]),time.monotonic()+3)
    print(json.dumps({'ok':True,'files':result['files'],'directories':result['directories']}))
except module.ResourceProbeError as error:
    print(json.dumps({'ok':False,'failure_code':error.code}))
    raise SystemExit(3)
'''


class PiperRecoveryMeasurement(unittest.TestCase):
    def setUp(self):
        # Replacement/retention and service-account measurements remain real.
        # This private tree uses empty/inert files on a small namespace tmpfs.
        admission = patch.object(environment, 'admit_replacement_capacity')
        admission.start(); self.addCleanup(admission.stop)

    def test_retained_private_stage_does_not_block_service_account_storage_measurement(self):
        self.assertEqual(os.geteuid(), 0)
        account = pwd.getpwnam('asterisk')
        # The official wrapper may keep /run private; sticky /tmp is the
        # intended shared traversal ancestor for the native Asterisk control.
        with tempfile.TemporaryDirectory(prefix='sls-piper-evidence-audit-', dir='/tmp') as name:
            base = Path(name); base.chmod(0o755)
            root = base / 'runtime'; root.mkdir(mode=0o755); root.chmod(0o755)
            (root / 'venv').mkdir(mode=0o755); (root / 'venv').chmod(0o755)
            (root / 'venv/working').write_bytes(b'original inert package')
            (root / 'venv/working').chmod(0o644)
            helper = base / 'sls_resource_capacity.py'
            shutil.copyfile(RUNTIME / helper.name, helper); helper.chmod(0o644)
            def as_asterisk():
                result = subprocess.run(['/usr/bin/python3', '-I', '-c', READ, str(helper), str(root)],
                    user=account.pw_uid, group=account.pw_gid, extra_groups=[], cwd='/',
                    capture_output=True, text=True, timeout=5)
                return result.returncode, json.loads(result.stdout)
            healthy = as_asterisk()
            self.assertEqual(healthy[0], 0, healthy)

            def failed(stage, lock):
                (stage / 'venv').chmod(0o755)
                (stage / 'venv/inert-failed-candidate').write_bytes(b'preserve failed build evidence')
                (stage / 'venv/inert-failed-candidate').chmod(0o644)
                raise RuntimeError('Deliberate bounded private build failure')
            with self.assertRaises(environment.EnvironmentError):
                environment.replace_environment(root, failed, lambda unused: None, True)
            self.assertEqual((root / 'venv/working').read_bytes(), b'original inert package')
            retained = next(path for path in root.glob('.replacement-*') if path.is_dir())
            self.assertEqual(retained.stat().st_mode & 0o777, 0o700)
            retained_bytes = (retained / 'venv/inert-failed-candidate').read_bytes()
            after_failure = as_asterisk()
            self.assertEqual(after_failure[0], 0, 'Recognized private build evidence must not block runtime diagnostics: '+str(after_failure))

            def success(stage, lock):
                (stage / 'venv').chmod(0o755)
                (stage / 'venv/validated-new-package').write_bytes(b'new inert package')
                (stage / 'venv/validated-new-package').chmod(0o644)
            def validate(active):
                self.assertEqual((active / 'venv/validated-new-package').read_bytes(), b'new inert package')
            replaced = environment.replace_environment(root, success, validate, True)
            self.assertTrue(replaced['ok'])
            self.assertTrue((root / 'venv/validated-new-package').is_file())
            self.assertEqual((retained / 'venv/inert-failed-candidate').read_bytes(), retained_bytes)
            self.assertEqual(retained.stat().st_mode & 0o777, 0o700)
            after_success = as_asterisk()
            self.assertEqual(after_success[0], 0, 'Later successful replacement must retain usable diagnostics')
            root_walk = resource.measure_tree(root, time.monotonic() + 3)
            self.assertGreater(root_walk['files'], 0)
            unknown = root / ('.replacement-' + 'e' * 24)
            unknown.mkdir(mode=0o700)
            (unknown / 'unreviewed').write_text('unknown private state must remain visible as an error')
            refused = as_asterisk()
            self.assertEqual(refused, (3, {'ok': False, 'failure_code': 'storage_directory_unreadable'}),
                             'A matching directory prefix alone must never suppress unknown evidence')


    def test_authenticated_root_preparation_marks_existing_safe_evidence_only(self):
        with tempfile.TemporaryDirectory(prefix='sls-piper-legacy-evidence-',dir='/tmp') as name:
            base=Path(name);base.chmod(0o755);root=base/'runtime';root.mkdir();root.chmod(0o755)
            (root/'venv').mkdir();(root/'venv').chmod(0o755)
            original=root/'venv/original';original.write_bytes(b'preserved active environment');original.chmod(0o644)
            def failed(stage,lock):
                pending=stage/'venv/incomplete';pending.write_bytes(b'original failed build evidence');pending.chmod(0o644)
                raise RuntimeError('Private older failed-stage fixture')
            with self.assertRaises(environment.EnvironmentError):
                environment.replace_environment(root,failed,lambda unused:None,True)
            stage=next(path for path in root.glob('.replacement-*') if path.is_dir())
            marker=root/(stage.name+'.retained.json');marker.unlink()
            try: environment.mark_retained_stages(root)
            except AttributeError: self.fail('Authenticated root preparation must qualify an existing safe retained stage')
            self.assertTrue(marker.is_file())
            self.assertEqual(marker.stat().st_mode&0o777,0o644)
            self.assertEqual(stage.stat().st_mode&0o777,0o700)
            self.assertEqual((stage/'venv/incomplete').read_bytes(),b'original failed build evidence')
            self.assertEqual(original.read_bytes(),b'preserved active environment')
            unknown=root/('.replacement-'+'d'*24);unknown.mkdir(mode=0o700)
            (unknown/'unqualified').write_bytes(b'unknown evidence is preserved')
            with self.assertRaises(environment.EnvironmentError):environment.mark_retained_stages(root)
            self.assertFalse((root/(unknown.name+'.retained.json')).exists())
            self.assertEqual((unknown/'unqualified').read_bytes(),b'unknown evidence is preserved')



if __name__ == '__main__':
    unittest.main()
