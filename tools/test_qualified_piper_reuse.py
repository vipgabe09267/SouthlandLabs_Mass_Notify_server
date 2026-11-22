"""Qualified Piper reuse regressions for isolated validation snapshots.

Native probes use disposable stdlib venvs or inert scripts; no wheel download or
installed Piper execution occurs. Run only through the validation wrapper.
"""
from pathlib import Path
import importlib.util
import fcntl
import os
import json
import pwd
import subprocess
import signal
import time
import shutil
import stat
import tempfile
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
HELPER=ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_piper_environment.py'
DATA_CONTRACT_NAMES=('piper-requirements.txt','piper-requirements.lock','piper-packaging.lock')
CONTRACT_NAMES=(*DATA_CONTRACT_NAMES,'sls_piper_dependencies.py','sls_install_guard.py')

def load_product_only_inside_validation_snapshot():
    spec=importlib.util.spec_from_file_location('qualified_piper_fixture',HELPER)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

@unittest.skipUnless(os.geteuid()==0,'Root-owned disposable filesystem fixtures required')
class QualifiedPiperReuse(unittest.TestCase):
    def setUp(self):
        self.module=load_product_only_inside_validation_snapshot()
        temp=tempfile.TemporaryDirectory(prefix='sls-qualified-piper-reuse-',dir='/tmp');self.addCleanup(temp.cleanup);self.base=Path(temp.name)
        self.root=self.base/'piper';self.root.mkdir(mode=0o755)
        (self.root/'.replacement.lock').touch(mode=0o600)
        self.venv=self.root/'venv';(self.venv/'bin').mkdir(parents=True,mode=0o755)
        (self.venv/'bin/python').symlink_to('/usr/bin/python3')
        (self.venv/'bin/piper').write_bytes(b'#!/usr/bin/python3\n');(self.venv/'bin/piper').chmod(0o755)
        (self.venv/'pyvenv.cfg').write_text('home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.11.0\n')
        self.package=self.venv/'fixture_runtime.py';self.package.write_bytes(b'old fixture bytes\n')
        site=self.venv/'lib/python3.11/site-packages';site.mkdir(parents=True)
        (site/'distutils-precedence.pth').write_bytes(b"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n")
        self.candidate=self.base/'candidate';self.previous=self.base/'approved-previous'
        for directory in(self.candidate,self.previous):
            directory.mkdir(mode=0o700)
            for name in CONTRACT_NAMES:
                body=(HELPER.parent/name).read_bytes();target=directory/name;target.write_bytes(body);target.chmod(0o644)

    def qualification(self,validator=None):
        with mock.patch.object(self.module,'validate_runtime',side_effect=validator)as checked:
            result=self.module.probe_runtime_reuse(self.root,self.candidate,self.previous)
        return result,checked

    def unavailable(self,call):
        try:result=call()
        except(self.module.EnvironmentError,OSError):return
        self.assertIsNone(result,'Unknown/tampered/incompatible state must never return a qualified snapshot')

    def test_identical_authenticated_contracts_and_healthy_stable_tree_produce_snapshot(self):
        result,checked=self.qualification();self.assertIsInstance(result,dict);checked.assert_called_once()
        self.assertEqual(self.package.read_bytes(),b'old fixture bytes\n');self.assertFalse(list(self.root.glob('.replacement-*')))

    def test_exclusive_replacement_lock_refuses_reuse_until_released(self):
        # A different open description models the actual replacement owner.
        with (self.root/'.replacement.lock').open('rb')as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with mock.patch.object(self.module,'validate_runtime')as checked:
                self.assertIsNone(self.module.probe_runtime_reuse(self.root,self.candidate,self.previous))
                checked.assert_not_called()
        result,checked=self.qualification();self.assertIsInstance(result,dict);checked.assert_called_once()

    def test_each_candidate_contract_mismatch_refuses_before_any_interpreter(self):
        for name in DATA_CONTRACT_NAMES:
            target=self.candidate/name;original=target.read_bytes();target.write_bytes(original+b'\n# changed candidate contract\n')
            with self.subTest(name=name),mock.patch.object(self.module,'validate_runtime')as checked:
                self.unavailable(lambda:self.module.probe_runtime_reuse(self.root,self.candidate,self.previous));checked.assert_not_called()
            target.write_bytes(original)

    def test_changed_candidate_authenticated_checker_can_validate_same_pin_contract(self):
        # Full candidate source authentication belongs to the caller. The new
        # checker may be stronger; data pins/locks alone define compatibility.
        checker=self.candidate/'sls_piper_dependencies.py';checker.write_bytes(checker.read_bytes()+b'\n# candidate validator source revision\n')
        result,checked=self.qualification();self.assertIsInstance(result,dict);checked.assert_called_once()

    def test_unprotected_candidate_checker_refuses_before_interpreter(self):
        checker=self.candidate/'sls_piper_dependencies.py';checker.chmod(0o666)
        with mock.patch.object(self.module,'validate_runtime')as checked:
            self.unavailable(lambda:self.module.probe_runtime_reuse(self.root,self.candidate,self.previous));checked.assert_not_called()

    def test_previous_approved_contract_needs_only_three_data_files(self):
        for name in('sls_piper_dependencies.py','sls_install_guard.py'):(self.previous/name).unlink()
        result,checked=self.qualification();self.assertIsInstance(result,dict);checked.assert_called_once()

    def test_cfg_version_duplicates_noncanonical_keys_and_system_site_refuse(self):
        cfg=self.venv/'pyvenv.cfg';original=cfg.read_bytes()
        for body in(original.replace(b'3.11.0',b'3.12.0'),original+b'home = /usr/bin\n',original.replace(b'home =',b'Home ='),original.replace(b'= false',b'= true')):
            cfg.write_bytes(body)
            with mock.patch.object(self.module,'validate_runtime')as checked:
                self.unavailable(lambda:self.module.probe_runtime_reuse(self.root,self.candidate,self.previous));checked.assert_not_called()
        cfg.write_bytes(original)

    def test_missing_previous_contract_and_contract_symlink_never_execute_runtime(self):
        with mock.patch.object(self.module,'validate_runtime')as checked:
            self.unavailable(lambda:self.module.probe_runtime_reuse(self.root,self.candidate,self.base/'missing-previous'));checked.assert_not_called()
        target=self.candidate/'piper-requirements.txt';target.unlink();target.symlink_to(self.previous/'piper-requirements.txt')
        with mock.patch.object(self.module,'validate_runtime')as checked:
            self.unavailable(lambda:self.module.probe_runtime_reuse(self.root,self.candidate,self.previous));checked.assert_not_called()

    def test_unsafe_whole_runtime_tree_refuses_before_any_interpreter(self):
        for kind in('writable','service-owned','hardlink','symlink','fifo'):
            target=self.venv/'unsafe'
            if kind=='symlink':target.symlink_to(self.base/'outside')
            elif kind=='fifo':os.mkfifo(target,0o600)
            elif kind=='hardlink':os.link(self.package,target)
            else:
                target.write_bytes(b'inert')
                if kind=='writable':target.chmod(0o666)
                else:os.chown(target,999,996)
            with self.subTest(kind=kind),mock.patch.object(self.module,'validate_runtime')as checked:
                self.unavailable(lambda:self.module.probe_runtime_reuse(self.root,self.candidate,self.previous));checked.assert_not_called()
            target.unlink()

    def test_tree_content_drift_during_successful_probe_never_gets_discount(self):
        def mutate(*args,**kw):self.package.write_bytes(b'new fixture bytes\n')
        result,checked=self.qualification(mutate);self.assertIsNone(result);checked.assert_called_once()
        self.assertEqual(self.package.read_bytes(),b'new fixture bytes\n','The validator observes drift; it does not restore a stale tree')

    def test_runtime_health_or_abi_failure_never_produces_reuse_snapshot(self):
        for reason in('qualified ABI mismatch','dependency mismatch','pip conflict','CLI failed','module failed','bounded timeout'):
            with self.subTest(reason=reason):
                result,checked=self.qualification(lambda*a,**kw:(_ for _ in()).throw(self.module.EnvironmentError(reason)))
                self.assertIsNone(result);checked.assert_called_once()
        self.assertEqual(self.package.read_bytes(),b'old fixture bytes\n')

    def test_replacement_readmission_enforces_common_capacity_refusal_without_writes(self):
        # Common resource math is covered by the resource suites. Exercise the
        # actual protected-source delegation boundary, without a path rejection
        # accidentally standing in for the intended byte/inode/readonly refusal.
        runtime=self.base/'replacement-contract';runtime.mkdir(mode=0o700)
        helper=runtime/'sls_resource_capacity.py';marker=self.base/'common-admission-calls'
        original_inode=self.venv.stat().st_ino
        for reason in('bytes','inodes','readonly'):
            helper.write_text('from pathlib import Path\n'
                'def admit_piper_preparation_storage(selected, *, profile):\n'
                '    if profile != "lite": raise ValueError("explicit Lite profile was lost")\n'
                '    with Path('+repr(str(marker))+').open("a") as stream: stream.write(selected+" '+reason+'\\n")\n'
                '    raise ValueError("common '+reason+' capacity refusal")\n')
            helper.chmod(0o644)
            with self.subTest(reason=reason),mock.patch.object(self.module,'RUNTIME',runtime):
                with self.assertRaises(self.module.EnvironmentError)as caught:
                    self.module.admit_replacement_capacity(self.root,temporary_directory='/tmp',profile='lite')
                self.assertIsInstance(caught.exception.__cause__,ValueError)
                self.assertEqual(str(caught.exception.__cause__),'common '+reason+' capacity refusal')
        self.assertEqual(marker.read_text().splitlines(),['/tmp bytes','/tmp inodes','/tmp readonly'])
        self.assertEqual(self.venv.stat().st_ino,original_inode)
        self.assertFalse(list(self.root.glob('.replacement-*')))
        self.assertEqual(self.package.read_bytes(),b'old fixture bytes\n')

    def test_later_failed_reuse_cannot_reach_builder_before_full_readmission(self):
        before=self.venv.stat().st_ino;builder=mock.Mock()
        with mock.patch.object(self.module,'admit_replacement_capacity',side_effect=self.module.EnvironmentError('full replacement capacity refused'))as admission:
            with self.assertRaises(self.module.EnvironmentError):self.module.replace_environment(self.root,builder,mock.Mock(),workers_paused=True)
        admission.assert_called();builder.assert_not_called();self.assertEqual(self.venv.stat().st_ino,before)
        self.assertEqual(self.package.read_bytes(),b'old fixture bytes\n');self.assertFalse(list(self.root.glob('.replacement-*')))

    def test_unknown_root_entries_retained_stages_and_nonempty_lock_never_probe(self):
        for name,is_dir in(('unknown',False),('.replacement-'+'a'*24,True)):
            entry=self.root/name
            if is_dir:entry.mkdir(mode=0o700)
            else:entry.write_bytes(b'preserve')
            with mock.patch.object(self.module,'validate_runtime')as checked:
                self.unavailable(lambda:self.module.probe_runtime_reuse(self.root,self.candidate,self.previous));checked.assert_not_called()
            if is_dir:entry.rmdir()
            else:entry.unlink()
        (self.root/'.replacement.lock').write_bytes(b'unknown lock contents')
        with mock.patch.object(self.module,'validate_runtime')as checked:
            self.unavailable(lambda:self.module.probe_runtime_reuse(self.root,self.candidate,self.previous));checked.assert_not_called()

    def test_build_child_only_inherits_approved_network_controls(self):
        allowed=('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy','ALL_PROXY','all_proxy','NO_PROXY','no_proxy',
                 'SSL_CERT_FILE','PIP_CERT','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE')
        poison={key:'PRIVATE_'+key for key in('LD_PRELOAD','LD_LIBRARY_PATH','PYTHONPATH','PYTHONHOME','BASH_ENV','PIP_INDEX_URL','PIP_EXTRA_INDEX_URL','GNUPGHOME')}
        network={key:'APPROVED_'+key for key in allowed}
        with mock.patch.dict(os.environ,{**network,**poison,'TMPDIR':'/tmp','HOME':'PRIVATE_HOME','PATH':'PRIVATE_PATH'},clear=True):
            build=self.module.runtime_environment()
            clean=self.module._reuse_validation_environment()
        self.assertEqual({key:build.get(key)for key in allowed},network)
        self.assertFalse(set(poison)&set(build));self.assertFalse(set(allowed)&set(clean))
        self.assertEqual(build['TMPDIR'],'/tmp');self.assertEqual(build['HOME'],'/root')
        self.assertEqual(build['PATH'],'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
        self.assertEqual(build['ORT_DISABLE_TELEMETRY'],'1')

    def test_validation_command_is_quiet_clean_native_and_candidate_supervised(self):
        account=types.SimpleNamespace(pw_name='nobody',pw_uid=65534,pw_gid=65534)
        with mock.patch.object(self.module.pwd,'getpwnam',return_value=account),mock.patch.object(self.module,'checked')as checked,mock.patch.dict(os.environ,{'LD_PRELOAD':'PRIVATE_POISON','LD_LIBRARY_PATH':'PRIVATE_POISON','PYTHONPATH':'PRIVATE_POISON','PYTHONHOME':'PRIVATE_POISON'}):
            self.module._reuse_as_native(['/usr/bin/true'],contract=self.candidate)
        kw=checked.call_args.kwargs;self.assertTrue(kw['quiet']);self.assertEqual(Path(kw['supervisor_directory']),self.candidate)
        self.assertFalse(any(k in kw['environment']for k in('LD_PRELOAD','LD_LIBRARY_PATH','PYTHONPATH','PYTHONHOME')))
        command=checked.call_args.args[0];self.assertEqual(command[:6],['/usr/sbin/runuser','-u','nobody','--','/usr/bin/env','-i'])
        self.assertNotIn('PRIVATE_POISON',str(command));self.assertEqual(kw['environment']['ORT_DISABLE_TELEMETRY'],'1')

    def native_account(self):
        try:account=pwd.getpwnam('nobody')
        except KeyError:self.skipTest('Disposable unprivileged account unavailable')
        if account.pw_uid<=0:self.skipTest('Unprivileged test account required')
        self.base.chmod(0o711)
        return account

    def test_real_disposable311_venv_no_site_abi_then_site_prefix(self):
        # Real stdlib venv, no wheel/Piper install/import. Capture actual product
        # commands, execute only its ABI/prefix stages as an unprivileged user.
        account=self.native_account();root=self.base/'real-abi';root.mkdir(mode=0o755);root.chmod(0o755)
        subprocess.run(['/usr/bin/python3','-I','-B','-m','venv','--without-pip',str(root/'venv')],check=True,timeout=30,umask=0o022,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        commands=[];stable={'python':{'path':str(Path('/usr/bin/python3').resolve())}}
        with mock.patch.object(self.module,'_reuse_snapshot',return_value=stable),mock.patch.object(self.module,'_reuse_as_native',side_effect=lambda command,**kw:commands.append(command)):
            self.module.validate_runtime(root,contract=self.candidate)
        abi=next(command for command in commands if '-S'in command)
        prefix=next(command for command in commands if '-c'in command and 'sys.prefix!=sys.base_prefix'in command[command.index('-c')+1])
        with mock.patch.object(self.module.pwd,'getpwnam',return_value=account):
            self.module._reuse_as_native(abi,contract=self.candidate)
            self.module._reuse_as_native([str(root/'venv/bin/python'),'-I','-B','-S','-c','import sys; assert sys.prefix==sys.base_prefix'],contract=self.candidate)
            self.module._reuse_as_native(prefix,contract=self.candidate)

    def test_actual_candidate_checker_memfd_has_file_context_without_real_packages(self):
        account=self.native_account();checker=(self.candidate/'sls_piper_dependencies.py').read_bytes();requirements=(self.candidate/'piper-requirements.txt').read_bytes()
        pins={line.split('==')[0]:line.split('==')[1]for line in requirements.decode().splitlines()if line and not line.startswith('#')}
        program='import importlib.metadata; _fixture_pins='+repr(pins)+'; importlib.metadata.version=lambda name:_fixture_pins[name]; '+self.module._reuse_checker_program(checker,requirements)
        with mock.patch.object(self.module.pwd,'getpwnam',return_value=account):
            self.module._reuse_as_native(['/usr/bin/python3','-I','-B','-S','-c',program],contract=self.candidate)

    def test_native_validation_stdout_cannot_contaminate_single_json_report(self):
        account=self.native_account()
        # Run product helper in a separate validation-process fixture so OS-level
        # child stdout/stderr are captured rather than StringIO-only redirected.
        code="from pathlib import Path; import importlib.util,json,os,pwd; p=Path("+repr(str(HELPER))+"); spec=importlib.util.spec_from_file_location('quiet_validation_fixture',p); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); account=pwd.getpwnam('nobody'); m.pwd.getpwnam=lambda name:account; os.environ.update({'LD_PRELOAD':'PRIVATE_POISON','PYTHONPATH':'PRIVATE_POISON','PYTHONHOME':'PRIVATE_POISON'}); m._reuse_as_native(['/usr/bin/python3','-I','-B','-S','-c',"+repr("import os,sys; assert 'LD_PRELOAD' not in os.environ and 'PYTHONPATH' not in os.environ and 'PYTHONHOME' not in os.environ; print('UNWANTED_NATIVE_STDOUT'); sys.stderr.write('UNWANTED_NATIVE_STDERR')")+"],contract=Path("+repr(str(self.candidate))+")); print(json.dumps({'schema':1,'ok':True}))"
        child=subprocess.run(['/usr/bin/python3','-I','-B','-c',code],capture_output=True,text=True,timeout=45)
        self.assertEqual(child.returncode,0,child.stderr);self.assertEqual(child.stderr,'');self.assertEqual(child.stdout.strip(),'{"schema": 1, "ok": true}');self.assertEqual(len(child.stdout.splitlines()),1)

    def test_sitecustomize_and_usercustomize_package_hook_refuse_before_probe(self):
        for name in('sitecustomize','usercustomize'):
            package=self.venv/'lib/python3.11/site-packages'/name;package.mkdir();(package/'__init__.py').write_text('raise RuntimeError("must never execute")\n')
            with mock.patch.object(self.module,'validate_runtime')as checked:
                self.unavailable(lambda:self.module.probe_runtime_reuse(self.root,self.candidate,self.previous));checked.assert_not_called()
            (package/'__init__.py').unlink();package.rmdir()

    def test_voice_fastpath_and_fallback_never_execute_old_root_piper_interpreter(self):
        # Exercise the real shell boundary in a relocated disposable IO root;
        # the fixed candidate helper is inert while old PIPER_PY is a tripwire.
        script=(ROOT/'slsmassnotifyserver/bin/sls_mass_notify_install_piper_voices.sh').read_text()
        body=script.split('ensure_piper_runtime() {',1)[1].split('\ninstall_piper_wrapper()',1)[0]
        function='ensure_piper_runtime() {'+body
        runtime=self.base/'shell-runtime';runtime.mkdir();piper=runtime/'piper';piper.mkdir();events=self.base/'helper-events';tripwire=self.base/'old-root-executed'
        helper=runtime/'sls_piper_environment.py'
        for probe_exit in(0,1):
            events.unlink(missing_ok=True);tripwire.unlink(missing_ok=True)
            helper.write_text('import json,sys\nfrom pathlib import Path\np=Path('+repr(str(events))+'); p.open("a").write(json.dumps(sys.argv[1:])+"\\n")\nraise SystemExit('+str(probe_exit)+' if "--probe-reuse" in sys.argv else 0)\n')
            fake=self.base/'old-python';fake.write_text('#!/bin/sh\nprintf executed > '+str(tripwire)+'\nexit 0\n');fake.chmod(0o755)
            wrapped='log(){ :; }\nvalidate_piper_runtime_tree(){ return 0; }\npiper_venv_usable(){ "$PIPER_PY"; }\n'+"PIPER_DIR="+repr(str(piper))+"\nPIPER_PY="+repr(str(fake))+"\nPIPER_BIN="+repr(str(fake))+"\nPIPER_WHEELHOUSE=\nPIPER_WORKERS_PAUSED=1\nPIPER_ARTIFACTS_CHANGED=0\nLOG_FD=2\n"+function.replace('/usr/local/bin/sls_mass_notify',str(runtime))+'\nensure_piper_runtime\n'
            child=subprocess.run(['/bin/bash'],input=wrapped,text=True,capture_output=True,timeout=20)
            self.assertEqual(child.returncode,0,child.stderr);self.assertFalse(tripwire.exists(),'The shell must not execute old Piper packages as root')
            calls=[json.loads(line)for line in events.read_text().splitlines()];self.assertIn('--probe-reuse',calls[0])
            self.assertEqual(len(calls),1 if probe_exit==0 else 2)

    def _owned_identity_retired(self,row):
        try:fields=Path('/proc',str(row['pid']),'stat').read_text().rsplit(')',1)[1].split()
        except FileNotFoundError:return True
        return fields[19]!=row['start_tick']

    def _supervised_owned_children(self,timeout_case):
        account=self.native_account();folder=self.base/'native-owned';folder.mkdir(mode=0o700);os.chown(folder,account.pw_uid,account.pw_gid);marker=folder/'owned.json'
        code="import json,os,subprocess,sys,time; from pathlib import Path; child=subprocess.Popen(['/usr/bin/python3','-I','-B','-S','-c','import time;time.sleep(90)'],start_new_session=True); ids=[{'pid':pid,'start_tick':Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]}for pid in(os.getpid(),child.pid)]; Path(sys.argv[1]).write_text(json.dumps(ids)); "+('time.sleep(90)'if timeout_case else 'raise SystemExit(7)')
        try:
            with mock.patch.object(self.module.pwd,'getpwnam',return_value=account):
                with self.assertRaises((self.module.EnvironmentError,subprocess.TimeoutExpired)):
                    self.module._reuse_as_native(['/usr/bin/python3','-I','-B','-S','-c',code,str(marker)],timeout=3,contract=self.candidate)
            self.assertTrue(marker.exists(),'Owned-child readiness must be established before asserting cleanup')
            identities=json.loads(marker.read_text());self.assertTrue(all(self._owned_identity_retired(row)for row in identities),'Return must reap both owned native parent and detached grandchild')
        finally:
            if marker.exists():
                for row in reversed(json.loads(marker.read_text())):
                    if not self._owned_identity_retired(row):
                        try:
                            fd=os.pidfd_open(row['pid'])
                            try:
                                if not self._owned_identity_retired(row):signal.pidfd_send_signal(fd,signal.SIGKILL)
                            finally:os.close(fd)
                        except ProcessLookupError:pass
                        try:os.waitpid(row['pid'],0)
                        except ChildProcessError:pass

    def test_validation_failure_reaps_detached_native_grandchild_before_return(self):self._supervised_owned_children(False)
    def test_validation_timeout_reaps_detached_native_grandchild_before_return(self):self._supervised_owned_children(True)

if __name__=='__main__':unittest.main()
