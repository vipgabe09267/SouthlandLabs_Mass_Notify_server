#!/usr/bin/python3
"""Owned Manager revocation evidence; only private namespace data and Asterisk."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]


class UninstallAmiEvidence(unittest.TestCase):
    def setUp(self):
        text = (ROOT / 'tools/uninstall_release.sh').read_text()
        self.assertTrue("<<'PYUNINSTALLAMIEVIDENCE'\n" in text,
                        'Removal needs protected owned-name evidence and native outcome classification')
        body = text.split("<<'PYUNINSTALLAMIEVIDENCE'\n", 1)[1].split('\nPYUNINSTALLAMIEVIDENCE', 1)[0]
        self.temporary = tempfile.TemporaryDirectory(dir='/run', prefix='sll-uninstall-ami-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'uninstaller'; self.root.mkdir(mode=0o750)
        self.trust = self.base / 'trust'; self.trust.mkdir(mode=0o700)
        self.source = self.trust / ('slsmassnotifyserver-' + 'a' * 64) / 'module'
        self.source.mkdir(parents=True)
        self.program = self.base / 'evidence.py'
        self.program.write_text(body.replace('/var/lib/sls-mass-notify-uninstaller', str(self.root))
                               .replace('/var/lib/sls-mass-notify-trust', str(self.trust)))
        self.proc = self.base / 'empty-proc'; self.proc.mkdir(mode=0o700)
        self.program.write_text(self.program.read_text().replace("Path('/proc')", 'Path(' + repr(str(self.proc)) + ')'))
        self.count = 0

    def transaction(self, names):
        self.count += 1
        path = self.root / ('sls-uninstall-transaction.' + format(self.count, '08x'))
        path.mkdir(mode=0o700)
        (path / 'transaction.json').write_text(json.dumps({'schema':1,'approved_source':str(self.source),'phase':'prepared'}))
        (path / 'transaction.json').chmod(0o600)
        ownership = {'owned_names': names, 'credential_sha256': 'b' * 64}
        result = self.run_helper('prepare', path, self.source, data=json.dumps(ownership))
        self.assertEqual(result.returncode, 0, result.stderr)
        return path

    def run_helper(self, *args, data='', program=None):
        return subprocess.run(['/usr/bin/python3', '-I', str(program or self.program), *map(str,args)],
                              input=data, capture_output=True, text=True, timeout=5)

    def plans(self, path, followup=False):
        result = self.run_helper('plans', path, 'followup' if followup else 'normal')
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def finish(self, path, plans, rows, readonly=False):
        return self.run_helper('finish', path, json.dumps(plans), 'readonly' if readonly else 'write',
                               data='\n'.join(json.dumps(row) for row in rows))

    def row(self, name, output, code=0):
        result = self.run_helper('probe', name, code, data=output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('secret:', result.stdout)
        return json.loads(result.stdout)

    def test_plan_is_immutable_private_and_bound_to_exact_owned_names(self):
        path = self.transaction(['sll_owned'])
        self.assertEqual((path / 'ami-removal-plan.json').stat().st_mode & 0o777, 0o600)
        before = (path / 'ami-removal-plan.json').read_bytes()
        second = self.run_helper('prepare', path, self.source,
                                 data=json.dumps({'owned_names':['other'],'credential_sha256':'b'*64}))
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual((path / 'ami-removal-plan.json').read_bytes(), before)
        plans = self.plans(path)
        self.assertEqual(plans['names'], ['sll_owned'])
        self.assertEqual(plans['plans'][0]['sha256'], hashlib.sha256(before).hexdigest())

    def test_shell_evidence_entry_keeps_piped_ownership_payload(self):
        path=self.root/'sls-uninstall-transaction.abcdef01';path.mkdir(mode=0o700)
        (path/'transaction.json').write_text(json.dumps({'schema':1,'approved_source':str(self.source),'phase':'prepared'}))
        (path/'transaction.json').chmod(0o600)
        script=self.base/'uninstall.sh'
        script.write_text((ROOT/'tools/uninstall_release.sh').read_text()
                          .replace('/var/lib/sls-mass-notify-uninstaller',str(self.root))
                          .replace('/var/lib/sls-mass-notify-trust',str(self.trust)))
        result=subprocess.run(['/bin/bash','-c','source "$1"; printf "%s" "$2" | uninstall_ami_evidence prepare "$3" "$4"',
             'fixture',str(script),json.dumps({'owned_names':['sll_owned'],'credential_sha256':'b'*64}),str(path),str(self.source)],
             capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((path/'ami-removal-plan.json').read_text())['owned_names'],['sll_owned'])

    def test_optional_manager_table_file_fallback_is_planned_and_rechecked(self):
        account = 'fixture_owned'
        secret = 'private-fixture-only'
        managed = self.base / 'manager_custom.conf'
        unchanged = '[independent]\nread = system\n'
        block = ('; BEGIN SLS Mass Notifications AMI\n['+account+']\nsecret = '+secret+'\n'
                 'deny = 0.0.0.0/0.0.0.0\ndeny = ::/0\npermit = 127.0.0.1/255.255.255.255\n'
                 'permit = ::1/128\nread = system,call,originate,reporting\n'
                 'write = system,call,originate,reporting\n; END SLS Mass Notifications AMI\n')
        managed.write_text(unchanged + block)
        managed.chmod(0o640)
        bootstrap = self.base / 'freepbx.php'
        bootstrap.write_text("""<?php
class FreePBX {
    static function Database() { return new class {
        function prepare($sql) {
            if ($sql !== 'SHOW TABLES LIKE ?') { throw new RuntimeException('Native Manager table absent'); }
            return new class { function execute($args){return true;} function fetchColumn(){return false;} };
        }
    }; }
    static function Config(){ return new class {function get($key){return 'pbx_admin';}}; }
}""")
        script = self.base / 'uninstall.sh'
        script.write_text((ROOT / 'tools/uninstall_release.sh').read_text()
                          .replace('/etc/freepbx.conf', str(bootstrap))
                          .replace('/etc/asterisk/manager_custom.conf', str(managed)))
        def invoke(operation):
            return subprocess.run(['/bin/bash','-c',
                'source "$1"; CONFIGURED_AMI_USERNAME="$2"; CONFIGURED_AMI_SECRET_HASH="$3"; '
                'RECOVERY_AMI_OWNERSHIP_HELPER="$4"; UNINSTALL_TRANSACTION_DIR=/run/fixture; UNINSTALL_APPROVED_SOURCE=/run/source; '
                'run_as_asterisk(){ env "$@"; }; run_bounded_as_asterisk(){ env "$@"; }; '
                'uninstall_ami_evidence(){ cat; }; remove_managed_path(){ :; }; '+operation,
                'fixture', str(script), account, hashlib.sha256(secret.encode()).hexdigest(),
                str(ROOT/'slsmassnotifyserver/AmiUserOwnership.php'),str(managed)],
                capture_output=True,text=True,timeout=8)
        # Capture the same JSON normally persisted through uninstall_ami_evidence.
        capture = script.read_text().replace('uninstall_ami_evidence prepare "$UNINSTALL_TRANSACTION_DIR" "$UNINSTALL_APPROVED_SOURCE" >/dev/null',
                                             'uninstall_ami_evidence prepare "$UNINSTALL_TRANSACTION_DIR" "$UNINSTALL_APPROVED_SOURCE"')
        script.write_text(capture)
        result = invoke('prepare_uninstall_ami_plan')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['owned_names'], [account])
        self.assertNotIn(secret, result.stdout+result.stderr)
        self.assertEqual(invoke('remove_freepbx_manager_users').returncode, 0)
        modified = managed.read_text().replace('read = system,call,originate,reporting',
                                               'deny = 127.0.0.1/32\nread = system,call,originate,reporting')
        managed.write_text(modified)
        self.assertNotEqual(invoke('rewrite_managed_text_file "$5" managed-block "SLS Mass Notifications AMI"').returncode, 0)
        self.assertEqual(managed.read_text(), modified)
        managed.write_text(unchanged + block)
        result = invoke('rewrite_managed_text_file "$5" managed-block "SLS Mass Notifications AMI"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(managed.read_text(), unchanged)

    def test_plan_needs_durable_transaction_before_publication(self):
        path=self.root/'sls-uninstall-transaction.abcdef02';path.mkdir(mode=0o700)
        data=json.dumps({'owned_names':['sll_owned'],'credential_sha256':'b'*64})
        result=self.run_helper('prepare',path,self.source,data=data)
        self.assertNotEqual(result.returncode,0,'A crash must not leave an unbound plan before the first transaction journal')
        self.assertFalse((path/'ami-removal-plan.json').exists())

    def test_only_exact_successful_absence_proves_removed_user(self):
        self.assertEqual(self.row('sll_owned', 'There is no manager called sll_owned\n')['state'], 'absent')
        self.assertEqual(self.row('sll_owned','No ethernet interface found for seeding global EID. You will have to set it manually.\nThere is no manager called sll_owned\n')['state'],'absent')
        for output, code in [('There is no manager called other\n',0), ('No such command\n',0),
                             ('There is no manager called sll_owned\n',124), ('',0), ('x'*8193,0)]:
            with self.subTest(code=code, prefix=output[:30]):
                self.assertEqual(self.row('sll_owned',output,code)['state'],'unverified')
        present = self.row('sll_owned','  username: sll_owned\n  secret: <Set>\n  Variables: PRIVATE_SENTINEL\n')
        self.assertEqual(present['state'],'present')
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(present))

    def test_native_absence_and_live_unknown_are_distinct(self):
        path = self.transaction(['sll_owned']); plans = self.plans(path)
        result = self.finish(path,plans,[{'name':'sll_owned','state':'unverified'}])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['classification'],'daemon_absent')
        # Same conservative /proc executable inspection as teardown's idle guard.
        process = self.proc / '123'; process.mkdir(); (process/'exe').symlink_to('/usr/sbin/asterisk')
        result = self.finish(path,plans,[{'name':'sll_owned','state':'unverified'}],readonly=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['classification'],'pending_unverified')

    def test_prior_pending_plan_survives_empty_retry_and_purge_without_raw_output(self):
        first = self.transaction(['sll_owned']); plans = self.plans(first)
        process = self.proc/'123'; process.mkdir(); (process/'exe').symlink_to('/usr/sbin/asterisk')
        result = self.finish(first,plans,[{'name':'sll_owned','state':'present'}])
        self.assertEqual(result.returncode,0,result.stderr)
        second = self.transaction([]); next_plans = self.plans(second)
        self.assertEqual(next_plans['names'],['sll_owned'])
        result = self.finish(second,next_plans,[{'name':'sll_owned','state':'unverified'}])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['classification'],'pending_unverified')
        # No active settings/runtime are inputs to the read-only follow-up.
        before = {p: p.read_bytes() for p in self.root.rglob('*.json')}
        followup = self.plans(second,True)
        self.assertEqual(followup['names'],['sll_owned'])
        result = self.finish(second,followup,[{'name':'sll_owned','state':'absent'}],readonly=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['classification'],'verified_absent')
        self.assertEqual(before,{p:p.read_bytes() for p in self.root.rglob('*.json')})

    def test_foreign_transaction_plan_replacement_and_links_refuse(self):
        path = self.transaction(['sll_owned']); plans = self.plans(path)
        wrong = json.loads(json.dumps(plans)); wrong['plans'][0]['sha256']='c'*64
        self.assertNotEqual(self.finish(path,wrong,[{'name':'sll_owned','state':'absent'}]).returncode,0)
        original = path/'ami-removal-plan.json'; moved = path/'original-plan'; original.rename(moved); original.symlink_to(moved)
        self.assertNotEqual(self.run_helper('plans',path,'followup').returncode,0)
        for bad in [self.base, path/'..', self.root/'sls-uninstall-transaction.sequence']:
            self.assertNotEqual(self.run_helper('plans',bad,'followup').returncode,0)

    def test_missing_referenced_pending_plan_cannot_be_silenced_by_empty_retry(self):
        first=self.transaction(['sll_owned']);plans=self.plans(first)
        process=self.proc/'123';process.mkdir();(process/'exe').symlink_to('/usr/sbin/asterisk')
        self.assertEqual(self.finish(first,plans,[{'name':'sll_owned','state':'present'}]).returncode,0)
        second=self.transaction([]);plans=self.plans(second)
        self.assertEqual(self.finish(second,plans,[{'name':'sll_owned','state':'unverified'}]).returncode,0)
        (first/'ami-removal-plan.json').unlink()
        third=self.transaction([])
        result=self.run_helper('plans',third,'normal')
        self.assertNotEqual(result.returncode,0,'Missing referenced evidence cannot erase a retained owned-name obligation')

    def test_direct_pending_result_with_missing_or_linked_plan_cannot_be_silenced(self):
        first=self.transaction(['sll_owned']);plans=self.plans(first)
        process=self.proc/'123';process.mkdir();(process/'exe').symlink_to('/usr/sbin/asterisk')
        self.assertEqual(self.finish(first,plans,[{'name':'sll_owned','state':'present'}]).returncode,0)
        saved=(first/'ami-removal-plan.json').read_bytes();(first/'ami-removal-plan.json').unlink()
        second=self.transaction([])
        self.assertNotEqual(self.run_helper('plans',second,'normal').returncode,0,
                            'A missing plan with a retained native result is not a legacy no-plan transaction')
        (first/'ami-removal-plan.json').symlink_to(first/'missing-plan')
        self.assertNotEqual(self.run_helper('plans',second,'normal').returncode,0)

    def test_actual_native_manager_present_absent_and_reload_preserve_other_user(self):
        real_program = self.base/'native-evidence.py'
        real_program.write_text(self.program.read_text().replace('Path('+repr(str(self.proc))+')',"Path('/proc')"))
        account = pwd.getpwnam('asterisk')
        subprocess.run(['/usr/sbin/ip','link','set','lo','up'],check=True,capture_output=True)
        native = self.base/'native'; native.mkdir(mode=0o755); self.base.chmod(0o755)
        for name in ['etc','run','log','spool','data','cache']:(native/name).mkdir(mode=0o755)
        (native/'data/documentation').mkdir(mode=0o755)
        shutil.copyfile('/tmp/sls-asterisk-vendor-docs/core-en_US.xml',native/'data/documentation/core-en_US.xml')
        modules = next(Path(p) for p in ['/usr/lib/asterisk/modules','/usr/lib64/asterisk/modules',
                       '/usr/lib/x86_64-linux-gnu/asterisk/modules'] if Path(p).is_dir())
        paths={'astetcdir':native/'etc','astmoddir':modules,'astvarlibdir':native/'data','astdbdir':native/'data',
               'astdatadir':native/'data','astspooldir':native/'spool','astrundir':native/'run',
               'astlogdir':native/'log','astcachedir':native/'cache'}
        config=native/'etc/asterisk.conf'; config.write_text('[directories]\n'+''.join(k+' = '+str(v)+'\n' for k,v in paths.items()))
        (native/'etc/modules.conf').write_text('[modules]\nautoload=no\n')
        (native/'etc/logger.conf').write_text('[general]\n[logfiles]\n')
        manager=native/'etc/manager.conf'; manager.write_text('[general]\nenabled=yes\nport=5038\nbindaddr=127.0.0.1\n[sll_owned]\nsecret=private-fixture-only\n[unrelated]\nsecret=unrelated-private-only\n')
        for p in [native,*native.rglob('*')]:os.chown(p,account.pw_uid,account.pw_gid)
        log=(self.base/'native-console.log').open('wb')
        self.addCleanup(log.close)
        process=subprocess.Popen(['/usr/sbin/asterisk','-C',str(config),'-f','-g','-n','-U','asterisk','-G','asterisk'],
                                  stdout=log,stderr=log,cwd='/')
        def cli(command):return subprocess.run(['/usr/sbin/asterisk','-C',str(config),'-rx',command],capture_output=True,text=True,timeout=3)
        session=None;stream=None
        def ami(action,identifier,extra=''):
            session.sendall(('Action: '+action+'\r\nActionID: '+identifier+'\r\n'+extra+'\r\n').encode())
            for _ in range(12):
                frame={};size=0
                while True:
                    line=stream.readline(8193);size+=len(line)
                    if not line or len(line)>8192 or size>8192:raise AssertionError('Private Manager frame exceeded its bound')
                    if line in (b'\n',b'\r\n'):break
                    key,separator,value=line.decode('ascii').partition(':')
                    if separator:frame[key]=value.strip()
                if frame.get('ActionID')==identifier:
                    return {key:frame[key] for key in ('ActionID','Response','Ping') if key in frame}
            raise AssertionError('Private Manager response identity was unavailable')
        try:
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                self.assertIsNone(process.poll(),'Private native Asterisk exited before its control socket: '+(self.base/'native-console.log').read_text(errors='replace'))
                if (native/'run/asterisk.ctl').exists():
                    ready=cli('manager show user sll_owned')
                    if ready.returncode==0 and 'username: sll_owned' in ready.stdout:break
                time.sleep(.05)
            present=cli('manager show user sll_owned'); self.assertEqual(present.returncode,0,present.stderr)
            self.assertEqual(self.row('sll_owned',present.stdout,present.returncode)['state'],'present')
            session=socket.create_connection(('127.0.0.1',5038),timeout=2);stream=session.makefile('rb')
            self.assertTrue(stream.readline(8193).startswith(b'Asterisk Call Manager/'))
            self.assertEqual(ami('Login','qa-login','Username: sll_owned\r\nSecret: private-fixture-only\r\nEvents: off\r\n').get('Response'),'Success')
            path=self.transaction(['sll_owned']); plans=self.plans(path)
            shell=self.base/'native-uninstall.sh'
            shell.write_text((ROOT/'tools/uninstall_release.sh').read_text()
                .replace('/var/lib/sls-mass-notify-uninstaller',str(self.root))
                .replace('/var/lib/sls-mass-notify-trust',str(self.trust))
                .replace('asterisk -rx "manager show user $name"','asterisk -C "$ASTERISK_QA_CONFIG" -rx "manager show user $name"'))
            def verify(mode):
                return subprocess.run(['/bin/bash','-c','source "$1"; ASTERISK_QA_CONFIG="$3"; UNINSTALL_APPROVED_SOURCE="$4"; verify_uninstall_runtime_ami "$2" "$5"',
                    'fixture',str(shell),str(path),str(config),str(self.source),mode],capture_output=True,text=True,timeout=5)
            pending=verify('normal')
            self.assertEqual(pending.returncode,0,pending.stderr)
            self.assertIn('loaded SLL Manager account may remain',pending.stdout)
            self.assertNotIn('private-fixture-only',pending.stdout+pending.stderr)
            self.assertNotIn('secret:',pending.stdout+pending.stderr)
            original_result=(path/'ami-revocation.json').read_bytes()
            stopped=False
            try:
                os.kill(process.pid,signal.SIGSTOP); stopped=True
                with self.assertRaises(subprocess.TimeoutExpired):cli('manager show user sll_owned')
                result=self.run_helper('finish',path,json.dumps(plans),'readonly',program=real_program,
                                      data=json.dumps({'name':'sll_owned','state':'unverified'}))
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(result.stdout)['classification'],'pending_unverified')
            finally:
                if stopped:os.kill(process.pid,signal.SIGCONT)
            manager.write_text('[general]\nenabled=yes\nport=5038\nbindaddr=127.0.0.1\n[unrelated]\nsecret=unrelated-private-only\n')
            self.assertEqual(cli('manager reload').returncode,0)
            absent=cli('manager show user sll_owned')
            diagnostic={'exit_code':absent.returncode,'bytes':len(absent.stdout),'lines':len(absent.stdout.splitlines()),
                        'absence_line':any(line.strip()=='There is no manager called sll_owned' for line in absent.stdout.splitlines()),
                        'present_line':'username: sll_owned' in absent.stdout,
                        'disconnect_notice':'Disconnected from Asterisk server' in absent.stdout,
                        'cleanup_notice':'Executing last minute cleanups' in absent.stdout,
                        'unknown_command':'No such command' in absent.stdout,
                        'other_line_sha256':[hashlib.sha256(line.strip().encode()).hexdigest() for line in absent.stdout.splitlines()
                                             if line.strip() and line.strip()!='There is no manager called sll_owned']}
            self.assertEqual(self.row('sll_owned',absent.stdout,absent.returncode)['state'],'absent',diagnostic)
            self.assertIn('username: unrelated',cli('manager show user unrelated').stdout)
            # Account removal is not session termination. Exercise only a read-only
            # Ping on this already-authenticated private connection after reload.
            self.assertEqual(ami('Ping','qa-after-reload').get('Ping'),'Pong')
            followup=verify('followup')
            self.assertEqual(followup.returncode,0,followup.stderr)
            self.assertEqual(json.loads(followup.stdout)['classification'],'verified_absent')
            self.assertIs(json.loads(followup.stdout)['existing_sessions_inspected'],False)
            self.assertEqual((path/'ami-revocation.json').read_bytes(),original_result)
        finally:
            if stream is not None:stream.close()
            if session is not None:session.close()
            if process.poll() is None:
                os.kill(process.pid,signal.SIGCONT); process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


if __name__=='__main__':unittest.main()
