#!/usr/bin/python3
"""Private interruption, persistent-lock and startup configuration regressions."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify'
sys.path.insert(0, str(RUNTIME))
import sls_atomic_json as atomic
import sls_mail_admission as mail
import sls_phone_admission as phone


def candidate_updater(root, account):
    helper = Path(root) / 'candidate-sls-update-status.py'
    helper.write_bytes((RUNTIME / 'sls_update_status.py').read_bytes())
    os.chown(helper, account.pw_uid, account.pw_gid)
    helper.chmod(0o500)
    return helper


class StorageAndStartup(unittest.TestCase):
    def test_failed_atomic_status_commit_preserves_previous_bytes_and_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            with atomic.locked_json(path) as data:
                data['retained'] = 'previous worker'
            before = path.read_bytes()
            inode = path.with_name('status.json.lock').stat().st_ino
            with mock.patch.object(atomic.os, 'replace', side_effect=OSError('injected failure')):
                with self.assertRaises(OSError), atomic.locked_json(path) as data:
                    data['retained'] = 'replacement'
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(path.with_name('status.json.lock').stat().st_ino, inode)
            with atomic.locked_json(path) as data:
                data['second'] = 'another worker'
            self.assertEqual(json.loads(path.read_text()), {'retained':'previous worker','second':'another worker'})

    def test_atomic_status_special_files_and_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            for kind in ('fifo','symlink','hardlink','oversize','duplicate'):
                if kind == 'fifo': os.mkfifo(path)
                elif kind == 'symlink': path.symlink_to(Path(directory)/'elsewhere')
                elif kind == 'hardlink':
                    other=Path(directory)/'other';other.write_text('{}');os.link(other,path)
                elif kind == 'oversize': path.write_bytes(b'x'*1025)
                else: path.write_text('{"kept":1,"kept":0}')
                if kind != 'symlink': path.chmod(0o640)
                with self.assertRaises((OSError,RuntimeError,ValueError)), atomic.locked_json(path,maximum=1024): pass
                path.unlink()

    def test_atomic_transaction_rejects_in_place_change_during_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'status.json'
            with atomic.locked_json(path) as data:
                data['retained'] = 'original'
            target_inode = path.stat().st_ino
            original_fstat = os.fstat
            observations = 0

            def changed_after_read(descriptor):
                nonlocal observations
                info = original_fstat(descriptor)
                if info.st_ino != target_inode:
                    return info
                observations += 1
                if observations != 2:
                    return info
                fields = {name: getattr(info, name) for name in (
                    'st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid', 'st_size',
                    'st_atime', 'st_mtime', 'st_ctime', 'st_atime_ns', 'st_mtime_ns', 'st_ctime_ns')}
                fields['st_mtime_ns'] += 1
                return types.SimpleNamespace(**fields)

            with mock.patch.object(atomic.os, 'fstat', side_effect=changed_after_read):
                with self.assertRaisesRegex(RuntimeError, 'json_storage_changed'):
                    with atomic.locked_json(path):
                        pass

    def test_collector_heartbeats_preserve_retained_ledger_and_reject_stale_incarnations(self):
        with tempfile.TemporaryDirectory() as directory:
            tick=[1000.0]
            store=phone.PhoneAdmissionStore(Path(directory),clock=lambda:tick[0],boot_id='fixture-boot')
            store.collector_heartbeat('a'*32)
            path=Path(directory)/'phone-admission.json';before=path.read_bytes();inode=path.stat().st_ino
            for _ in range(10):
                tick[0]+=5;store.collector_heartbeat('a'*32)
            self.assertEqual(path.read_bytes(),before);self.assertEqual(path.stat().st_ino,inode)
            state=phone.read_private_json('phone-admission.json',Path(directory))
            self.assertEqual(store.require_collector(state)['heartbeat_tick'],tick[0])
            tick[0]+=16
            with self.assertRaises(phone.PhoneAdmissionError): store.require_collector(state)
            store.collector_heartbeat('b'*32)
            with self.assertRaises(phone.PhoneAdmissionError): store.require_collector(state)
            new=phone.read_private_json('phone-admission.json',Path(directory))
            self.assertEqual(store.require_collector(new)['generation'],'b'*32)

    def test_empty_mail_initialization_resumes_without_refunding_submission_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);account=pwd.getpwnam('asterisk');os.chown(root,account.pw_uid,account.pw_gid)
            marker=root/mail.LOCK;marker.write_bytes(b'');os.chown(marker,account.pw_uid,account.pw_gid);marker.chmod(0o640)
            initial={'schema':1,'last_at':1000,'windows':{str(period):[] for period in mail.LIMITS},'probe':None}
            intent=root/'.mail-admission-initializing';intent.write_text(json.dumps({'schema':1,'initial':initial}));intent.chmod(0o640);os.chown(intent,account.pw_uid,account.pw_gid)
            for present in (False,True):
                if present:
                    (root/mail.STATE).write_text(json.dumps(initial));(root/mail.STATE).chmod(0o640);os.chown(root/mail.STATE,account.pw_uid,account.pw_gid)
                mail.reserve(directory=root,clock=lambda:1000,queue_inspector=lambda:0)
                self.assertFalse(intent.exists());self.assertEqual(marker.read_bytes(),mail.MARKER)
                state=json.loads((root/mail.STATE).read_text())
                self.assertEqual(state['windows']['60'][0]['counts']['total'],[1,1])
                if not present:
                    # A new, separately isolated unfinished empty initialization.
                    (root/mail.STATE).unlink();marker.write_bytes(b'');intent.write_text(json.dumps({'schema':1,'initial':initial}));intent.chmod(0o640);os.chown(intent,account.pw_uid,account.pw_gid)
            intent.write_text(json.dumps({'schema':1,'initial':initial}));intent.chmod(0o640);os.chown(intent,account.pw_uid,account.pw_gid)
            before=(root/mail.STATE).read_bytes()
            with self.assertRaises(mail.MailAdmissionBlocked): mail.reserve(directory=root,clock=lambda:1000,queue_inspector=lambda:0)
            self.assertEqual((root/mail.STATE).read_bytes(),before)

    def test_asterisk_restart_includes_templates_and_noload_precedence(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        code=source.split("<<'PYASTERISKSTART'\n",1)[1].split('\nPYASTERISKSTART',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=root/'modules.conf'
            config.write_text('[modules]\nautoload=yes\n#include "custom.conf"\n')
            custom=root/'custom.conf';custom.write_text('noload => app_read.so\n')
            def run(): return subprocess.run(['python3','-I','-c',code,'app_read.so',str(config)],capture_output=True,text=True,timeout=3)
            self.assertEqual(run().returncode,1)
            custom.write_text('load => app_read\n');self.assertEqual(run().returncode,0)
            config.write_text('[base](!)\nautoload=no\n[modules](base)\n#tryinclude missing*.conf\n#include "custom.conf"\n')
            self.assertEqual(run().returncode,0)
            custom.write_text('noload => app_read\n');self.assertEqual(run().returncode,1)
            custom.write_text('#include modules.conf\n');self.assertEqual(run().returncode,2)
            custom.write_text('#exec /bin/true\n');self.assertEqual(run().returncode,2)
            custom.write_text('[modules](+)\nload=app_read.so\n');self.assertEqual(run().returncode,0)

    def test_asterisk_restart_uses_first_native_category_and_first_autoload(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        code=source.split("<<'PYASTERISKSTART'\n",1)[1].split('\nPYASTERISKSTART',1)[0]
        cases = [
            ('[modules]\nautoload=yes\nautoload=no\n', 0),
            ('[modules]\nautoload=no\nautoload=yes\n', 1),
            ('[modules]\nautoload=yes\n[modules]\nnoload=app_read.so\n', 0),
            ('[modules]\nautoload=no\n[modules]\nload=app_read.so\n', 1),
            ('[modules](!)\nautoload=no\n[modules]\nautoload=yes\n', 0),
            ('[base](!)\nautoload=no\n[modules](base)\nautoload=yes\n', 1),
            ('[modules]\nautoload=no\n[modules](+)\nload=app_read.so\n', 0),
        ]
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'modules.conf'
            for contents,expected in cases:
                with self.subTest(contents=contents):
                    config.write_text(contents)
                    result=subprocess.run(['python3','-I','-c',code,'app_read.so',str(config)],capture_output=True,text=True,timeout=3)
                    self.assertEqual(result.returncode,expected,result.stderr)

    def test_asterisk_restart_bounds_total_inherited_settings(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        code=source.split("<<'PYASTERISKSTART'\n",1)[1].split('\nPYASTERISKSTART',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'modules.conf'
            contents='[base0](!)\nautoload=yes\n'
            for index in range(1,18):
                contents+=f'[base{index}](!,base{index-1},base{index-1})\n'
            config.write_text(contents+'[modules](base17)\n')
            result=subprocess.run(['python3','-I','-c',code,'app_read.so',str(config)],capture_output=True,text=True,timeout=3)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertIn('inherited setting limit',result.stderr)

    def test_startup_gate_checks_cut_and_caller_ready_signal_providers(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        function=re.search(r'^verify_asterisk_module_startup_persistence\(\) \{.*?(?=^asterisk_channel_type_available\(\))',source,re.M|re.S).group(0)
        harness='log() { :; }\nasterisk_setting_value() { printf /etc/asterisk; }\nasterisk_module_starts_persistently() { [ "$1" != "$disabled" ]; }\n'+function+'\ndisabled="$1"; verify_asterisk_module_startup_persistence\n'
        for provider in ('func_cut.so','res_mutestream.so','app_senddtmf.so','app_playtones.so'):
            with self.subTest(provider=provider):
                result=subprocess.run(['bash','-c',harness,'fixture',provider],capture_output=True,text=True,timeout=3)
                self.assertNotEqual(result.returncode,0,'A restart-blocked required provider was omitted: '+provider)

    def test_startup_gate_uses_the_active_configuration_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755)
            config=root/'modules.conf';config.write_text('[modules]\nautoload=yes\n');config.chmod(0o644)
            harness='source "$1"\nlog() { :; }\nfixture_configuration_root="$2"\nasterisk_setting_value() { [ "$1" = "Configuration directory" ] && printf "%s\\n" "$fixture_configuration_root"; }\nasterisk() { return 91; }\nverify_asterisk_module_startup_persistence\n'
            result=subprocess.run(['bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),str(root)],capture_output=True,text=True,timeout=8)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_startup_configuration_must_be_readable_by_the_runtime_account(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755)
            config=root/'modules.conf';config.write_text('[modules]\nautoload=yes\n')
            harness='source "$1"\nlog() { :; }\nasterisk_module_starts_persistently app_read.so "$2"\n'
            command=['bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),str(config)]
            config.chmod(0o600)
            result=subprocess.run(command,capture_output=True,text=True,timeout=4)
            self.assertNotEqual(result.returncode,0,'Root readability cannot qualify a file unavailable to the daemon')
            config.chmod(0o644)
            result=subprocess.run(command,capture_output=True,text=True,timeout=4)
            self.assertEqual(result.returncode,0,result.stderr)
            root.chmod(0o700)
            result=subprocess.run(command,capture_output=True,text=True,timeout=4)
            self.assertNotEqual(result.returncode,0,'The daemon must traverse every configuration parent')

    def test_failed_cli_status_cannot_authorize_an_asterisk_capability_or_path(self):
        cases=[
            ("asterisk_setting_value 'Module directory'",'  Module directory: /usr/lib/asterisk/modules'),
            ("asterisk_labeled_value 'manager show settings' bindaddr",'  bindaddr: 127.0.0.1'),
            ('asterisk_capability_available function CUT',"-= Info about Function 'CUT' =-"),
            ('asterisk_capability_available application Page',"-= Info about Application 'Page' =-"),
            ('asterisk_module_loaded app_page.so','app_page.so Page 0 Running core'),
            ('asterisk_channel_type_available Local','-- Info about channel driver: Local --'),
        ]
        for command,output in cases:
            with self.subTest(command=command):
                harness='source "$1"\nlog() { :; }\nfixture_cli_output="$2"\nasterisk() { printf "%s\\n" "$fixture_cli_output"; return 23; }\n'+command+'\n'
                result=subprocess.run(['bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),output],capture_output=True,text=True,timeout=3)
                self.assertNotEqual(result.returncode,0,'Failed native CLI output was accepted by '+command)

    def test_missing_custom_provider_is_not_loaded_speculatively(self):
        with tempfile.TemporaryDirectory() as directory:
            calls=Path(directory)/'calls'
            harness='''source "$1"
log() { :; }
fixture_calls="$2"
fixture_available=0
asterisk_capability_available() { [ "$fixture_available" -eq 1 ]; }
asterisk_module_starts_persistently() { return 0; }
asterisk_module_file() { printf /opt/custom-asterisk/modules/func_cut.so; }
asterisk_provider_package() { return 1; }
repair_asterisk_provider_package() { return 1; }
asterisk() { printf '%s\\n' "$*" >>"$fixture_calls"; fixture_available=1; }
ensure_asterisk_capability function CUT func_cut.so
'''
            result=subprocess.run(['bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),str(calls)],capture_output=True,text=True,timeout=3)
            self.assertNotEqual(result.returncode,0,'Missing unmanaged provider was loaded without matching build authority')
            self.assertFalse(calls.exists(),'Installer issued module load/reload before provider admission')

    def test_restart_blocked_provider_is_never_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            calls=Path(directory)/'calls'
            harness='''source "$1"
log() { :; }
fixture_calls="$2"
fixture_available=0
asterisk_capability_available() { [ "$fixture_available" -eq 1 ]; }
asterisk_module_starts_persistently() { return 1; }
asterisk_provider_package() { printf asterisk-core; }
verify_asterisk_packaged_binary() { return 0; }
asterisk_module_file() { printf /usr/lib/asterisk/modules/func_cut.so; }
dpkg-query() { printf '22.11.0-1'; }
repair_asterisk_provider_package() { return 1; }
asterisk() { printf '%s\\n' "$*" >>"$fixture_calls"; fixture_available=1; }
ensure_asterisk_capability function CUT func_cut.so
'''
            result=subprocess.run(['bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),str(calls)],capture_output=True,text=True,timeout=3)
            self.assertNotEqual(result.returncode,0,'A noloaded provider was loaded before checking its restart policy')
            self.assertFalse(calls.exists(),'Explicit module restart policy was ignored')

    def test_final_notify_verification_only_observes_existing_provider_readiness(self):
        harness='''source "$1"
fixture_available_after="$2"; fixture_manager="$3"; fixture_startup="$4"
fixture_checks=0; fixture_sleeps=0; fixture_mutations=0
log() { :; }
asterisk_module_starts_persistently() { [ "$fixture_startup" -eq 1 ]; }
asterisk_module_loaded() { fixture_checks=$((fixture_checks+1)); [ "$fixture_available_after" -gt 0 ] && [ "$fixture_checks" -ge "$fixture_available_after" ]; }
asterisk_capability_available() { [[ "$*" = 'manager PJSIPNotify' ]] && [ "$fixture_manager" -eq 1 ]; }
asterisk() { fixture_mutations=$((fixture_mutations+1)); return 0; }
repair_asterisk_provider_package() { fixture_mutations=$((fixture_mutations+1)); return 0; }
verify_asterisk_provider_admission() { fixture_mutations=$((fixture_mutations+1)); return 0; }
sleep() { fixture_sleeps=$((fixture_sleeps+1)); }
if verify_asterisk_notify_readiness; then fixture_status=0; else fixture_status=$?; fi
printf '%s %s %s %s\\n' "$fixture_status" "$fixture_checks" "$fixture_sleeps" "$fixture_mutations"
'''
        for available,manager,startup,status,checks,sleeps in ((1,1,1,0,1,0),(3,1,1,0,3,2),
                (0,1,1,1,20,19),(1,0,1,1,20,19),(1,1,0,1,0,0)):
            with self.subTest(available=available,manager=manager,startup=startup):
                result=subprocess.run(['bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),
                                       str(available),str(manager),str(startup)],capture_output=True,text=True,timeout=3)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout.strip(),f'{status} {checks} {sleeps} 0')
        source=(ROOT/'tools/install_release.sh').read_text()
        verification=source.split('\nverify_install() {',1)[1].split('\nverify_runtime_shell_syntax() {',1)[0]
        self.assertTrue('verify_asterisk_notify_readiness' in verification,'Final verification must observe provider readiness')
        self.assertNotIn('module load ',verification,'Final verification bypasses provider admission with a raw load')

    def test_active_configuration_inode_and_daemon_ids_match_the_fixed_runtime(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        marker="<<'PYASTERISKRUNTIME'\n"
        self.assertTrue(marker in source,'Active Asterisk configuration and daemon identity admission is missing')
        code=source.split(marker,1)[1].split('\nPYASTERISKRUNTIME',1)[0]
        account=pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(prefix='sls-native-runtime-id-',dir='/run') as directory:
            root=Path(directory);config=root/'configuration';config.mkdir();alias=root/'same-configuration';alias.symlink_to(config,target_is_directory=True)
            other=root/'other';other.mkdir();binary=root/'asterisk';binary.write_bytes(b'inert executable identity')
            processes=root/'proc';processes.mkdir();daemon=processes/'51';daemon.mkdir();(daemon/'exe').symlink_to(binary)
            (daemon/'cmdline').write_bytes(b'asterisk\0-f\0')
            def status(uid=account.pw_uid,gid=account.pw_gid):
                (daemon/'status').write_text('Uid:\t'+('\t'.join([str(uid)]*4))+'\nGid:\t'+('\t'.join([str(gid)]*4))+'\n')
            def check(active,expected):
                result=subprocess.run(['/usr/bin/python3','-I','-c',code,str(active),str(config),str(processes),str(binary)],capture_output=True,text=True,timeout=3)
                self.assertEqual(result.returncode==0,expected,result.stdout+result.stderr)
            status();check(config,True);check(alias,True);check(other,False)
            status(uid=0);check(config,False)
            status(gid=0);check(config,False)
            status()
            for remote in (b'-rx',b'-R',b'-x'):
                with self.subTest(remote=remote):
                    (daemon/'cmdline').write_bytes(b'asterisk\0'+remote+b'\0core show settings\0');check(config,False)
            (daemon/'cmdline').write_bytes(b'asterisk\0-f\0')
            second=processes/'52';second.mkdir();(second/'exe').symlink_to(binary);(second/'cmdline').write_bytes(b'asterisk\0-f\0');(second/'status').write_bytes((daemon/'status').read_bytes());check(config,False)

    def test_initial_platform_check_qualifies_startup_and_defers_approved_stock_loads(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        platform='preflight_platform() {'+source.split('\npreflight_platform() {',1)[1].split('\npreflight_piper_platform() {',1)[0]
        platform=platform.replace('/usr/sbin/apache2ctl','private_apache2ctl')
        harness='''source "$1"
fixture_allowed="$2"; fixture_mutations=0; fixture_admissions=0; fixture_startup=0
log() { :; }
sls_as_asterisk() { return 0; }
private_apache2ctl() { printf 'rewrite_module setenvif_module\\n'; }
systemctl() { return 0; }
asterisk() { [[ "$*" = '-rx core show version' ]] || fixture_mutations=$((fixture_mutations+1)); }
verify_supported_asterisk_directories() { return 0; }
validate_piper_wrapper_ownership() { return 0; }
preflight_piper_platform() { return 0; }
verify_asterisk_module_startup_persistence() { fixture_startup=$((fixture_startup+1)); [ "$fixture_allowed" -eq 1 ]; }
asterisk_module_loaded() { return 1; }
asterisk_channel_type_available() { return 0; }
asterisk_capability_available() { [[ "$*" = 'manager Setvar' || "$*" = 'manager Getvar' || "$*" = 'application Wait' ]]; }
verify_asterisk_provider_admission() { fixture_admissions=$((fixture_admissions+1)); return 0; }
secure_asterisk_spool() { fixture_mutations=$((fixture_mutations+1)); }
'''+platform+'''
preflight_platform check
printf '%s %s %s\\n' "$fixture_mutations" "$fixture_admissions" "$fixture_startup"
'''
        approved=subprocess.run(['bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),'1'],capture_output=True,text=True,timeout=3)
        self.assertEqual(approved.returncode,0,approved.stderr)
        mutations,admissions,startup=map(int,approved.stdout.split())
        self.assertEqual((mutations,startup),(0,1));self.assertGreater(admissions,0)
        denied=subprocess.run(['bash','-c',harness+'\nexit 99\n','fixture',str(ROOT/'tools/install_release.sh'),'0'],capture_output=True,text=True,timeout=3)
        self.assertEqual(denied.returncode,1,denied.stderr)

    def test_read_only_missing_provider_analysis_never_invokes_opt_in_repair(self):
        with tempfile.TemporaryDirectory(prefix='sls-read-only-provider-') as directory:
            root=Path(directory);calls=root/'forbidden-repair';provider=root/'absent.so'
            harness='''source "$1"
log() { :; }
ASTERISK_READ_ONLY_ADMISSION=1; REPAIR_ASTERISK_PACKAGES="$4"
fixture_provider="$2"; fixture_calls="$3"
asterisk_module_starts_persistently() { return 0; }
asterisk_module_file() { printf '%s\\n' "$fixture_provider"; }
asterisk_provider_package() { printf 'asterisk-core\\n'; }
dpkg-query() { printf '22.11.0-1\\n'; }
verify_asterisk_packaged_binary() { return 0; }
repair_asterisk_provider_package() { touch "$fixture_calls"; return 0; }
verify_asterisk_provider_admission res_pjsip_notify.so
'''
            for opt_in,expected in ((0,1),(1,0)):
                with self.subTest(opt_in=opt_in):
                    result=subprocess.run(['bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),str(provider),str(calls),str(opt_in)],capture_output=True,text=True,timeout=3)
                    self.assertEqual(result.returncode,expected,result.stderr)
                    self.assertFalse(calls.exists(),'Read-only preflight changed package state')


    def test_packaged_provider_checks_peers_and_actual_mapped_identities(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        marker="<<'PYASTERISKMODULESET'\n"
        if marker not in source:
            self.fail('Packaged provider admission has no module peer/image verification')
        program=source.split(marker,1)[1].split('\nPYASTERISKMODULESET',1)[0]
        with tempfile.TemporaryDirectory(prefix='sls-module-peers-',dir='/run') as directory:
            root=Path(directory);modules=root/'modules';modules.mkdir()
            target=modules/'res_pjsip_notify.so';peer=modules/'res_pjsip.so'
            original_target=b'packaged notify module';original_peer=b'packaged PJSIP peer'
            target.write_bytes(original_target);peer.write_bytes(original_peer)
            metadata=root/'package.md5sums'
            import hashlib
            metadata.write_text(''.join(hashlib.md5(body,usedforsecurity=False).hexdigest()+'  '+str(path).lstrip('/')+'\n' for path,body in ((target,original_target),(peer,original_peer))))
            processes=root/'proc';processes.mkdir();daemon=processes/'42';daemon.mkdir()
            binary=root/'asterisk';binary.write_bytes(b'packaged binary validated separately')
            (daemon/'exe').symlink_to(binary);(daemon/'cmdline').write_bytes(str(binary).encode()+b'\0-f\0')
            def maps(path=peer,inode=None,deleted=False):
                info=path.stat();dev=f'{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}'
                (daemon/'maps').write_text(f'1000-2000 r-xp 00000000 {dev} {info.st_ino if inode is None else inode} {path}'+(' (deleted)' if deleted else '')+'\n')
            ownership=''.join('asterisk-core: '+str(path)+'\n' for path in (target,peer))
            def check(expected,label,version='22.11.0-1',query_status=0,owners=ownership):
                preamble='''import subprocess,sys,types
fixture_metadata,fixture_version,fixture_owners,fixture_status=sys.argv[1:5]
def native_query(args,**kwargs):
    if args[0]!='/usr/bin/dpkg-query': raise AssertionError('Unexpected native command')
    if args[1]=='-S': return types.SimpleNamespace(returncode=int(fixture_status),stdout=fixture_owners,stderr='')
    if args[1]=='-W': return types.SimpleNamespace(returncode=0,stdout='ii \\t'+fixture_version,stderr='')
    if args[1]=='--control-path': return types.SimpleNamespace(returncode=0,stdout=fixture_metadata+'\\n',stderr='')
    raise AssertionError('Unexpected native package query')
subprocess.run=native_query
sys.argv=sys.argv[4:]
'''
                result=subprocess.run(['python3','-I','-',str(metadata),version,owners,str(query_status),str(modules),'asterisk-core','22.11.0-1',target.name,str(processes),str(binary)],input=preamble+program,capture_output=True,text=True,timeout=4)
                self.assertEqual(result.returncode==0,expected,label+': '+result.stdout+result.stderr)
            maps();check(True,'Unchanged package peers and mapped identity')
            peer.write_bytes(b'custom peer over a still-packaged binary');maps();check(False,'Modified custom peer')
            peer.write_bytes(original_peer);maps()
            target.unlink();check(True,'Only the missing targeted provider may be repaired')
            target.write_bytes(original_target);peer.unlink();check(False,'Another missing package peer')
            peer.write_bytes(original_peer);maps(inode=peer.stat().st_ino+1);check(False,'Mapped inode differs from installed module')
            maps(deleted=True);check(False,'Deleted mapped module')
            maps();check(False,'Different installed package version',version='20.7.0-1')
            check(False,'Failed native ownership query',query_status=2)
            check(False,'Missing module package authority',owners='asterisk-core: '+str(target)+'\n')
            metadata.chmod(0o664);check(False,'Writable checksum authority');metadata.chmod(0o644)
            outside=root/'other';outside.mkdir();foreign=outside/peer.name;foreign.write_bytes(original_peer)
            maps(foreign);check(False,'Custom mapped peer outside the active module directory')

    def test_startup_checker_rejects_native_loader_errors_in_the_effective_category(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        code=source.split("<<'PYASTERISKSTART'\n",1)[1].split('\nPYASTERISKSTART',1)[0]
        cases=[
            ('[modules]\nautoload=yes\nload_typo=app_read.so\n',2),
            ('[modules]\nautoload=yes\npreload-optional=app_read.so\n',2),
            ('[modules]\nautoload=yes\nrequire=res_other.so\nnoload=res_other.so\n',2),
            ('[modules]\nautoload=yes\n[modules]\nload_typo=app_read.so\n',0),
        ]
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'modules.conf'
            for contents,expected in cases:
                with self.subTest(contents=contents):
                    config.write_text(contents)
                    result=subprocess.run(['python3','-I','-c',code,'app_read.so',str(config)],capture_output=True,text=True,timeout=3)
                    self.assertEqual(result.returncode,expected,result.stderr)

    def test_startup_checker_refuses_a_configuration_replaced_during_include_read(self):
        source=(ROOT/'tools/install_release.sh').read_text()
        code=source.split("<<'PYASTERISKSTART'\n",1)[1].split('\nPYASTERISKSTART',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=root/'modules.conf'
            config.write_text('[modules]\nautoload=yes\n#include late.conf\n')
            (root/'late.conf').write_text('; ordinary include\n')
            preamble='''import os,pathlib,sys
fixture_config=pathlib.Path(sys.argv[2]);fixture_open=os.open
def replacing_open(path,flags,*args,**kwargs):
    descriptor=fixture_open(path,flags,*args,**kwargs)
    if pathlib.Path(path).name=='late.conf':
        replacement=fixture_config.with_suffix('.new')
        replacement.write_text('[modules]\\nautoload=no\\n')
        os.replace(replacement,fixture_config)
    return descriptor
os.open=replacing_open
'''
            result=subprocess.run(['python3','-I','-c',preamble+code,'app_read.so',str(config)],capture_output=True,text=True,timeout=3)
            self.assertEqual(result.returncode,2,result.stderr)
            self.assertIn('changed during inspection',result.stderr)

    def test_signer_preserves_shared_parent_and_existing_lock_inode(self):
        source=(ROOT/'slsmassnotifyserver/bin/sign_sls_mass_notify_local_sig.sh').read_text()
        function=re.search(r'^acquire_signing_lock\(\) \{.*?(?=^prepare_signing_home\(\))',source,re.M|re.S).group(0)
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory)/'shared';parent.mkdir();parent.chmod(0o1777)
            lock=parent/'signing.lock';lock.touch(mode=0o600);inode=lock.stat().st_ino
            harness='set -euo pipefail\nlog() { :; }\nvalidate_absolute_path() { :; }\n'+function+'\nLOCK_FILE="$1"; acquire_signing_lock\n'
            result=subprocess.run(['bash','-c',harness,'fixture',str(lock)],capture_output=True,text=True,timeout=4)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(parent.stat().st_mode&0o7777,0o1777);self.assertEqual(lock.stat().st_ino,inode)
            lock.unlink();os.mkfifo(lock)
            result=subprocess.run(['bash','-c',harness,'fixture',str(lock)],capture_output=True,text=True,timeout=4)
            self.assertNotEqual(result.returncode,0);self.assertEqual(parent.stat().st_mode&0o7777,0o1777)

    def test_updater_display_writer_drops_root_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);account=pwd.getpwnam('asterisk');os.chown(root,account.pw_uid,account.pw_gid)
            helper=candidate_updater(root,account)
            path=root/'update-status.json'
            command=['runuser','-u','asterisk','--','python3','-I',str(helper),str(path)]
            def run(): return subprocess.run(command,input='{"state":"complete"}',capture_output=True,text=True,timeout=3)
            result=run();self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(path.stat().st_uid,account.pw_uid)
            inode=path.with_name(path.name+'.lock').stat().st_ino
            self.assertEqual(run().returncode,0);self.assertEqual(path.with_name(path.name+'.lock').stat().st_ino,inode)
            path.unlink();other=root/'other';other.write_text('preserved');path.symlink_to(other)
            self.assertNotEqual(run().returncode,0);self.assertEqual(other.read_text(),'preserved')
            path.unlink();os.link(other,path);self.assertNotEqual(run().returncode,0)

    def test_updater_accepts_trusted_pbx_ancestor_but_not_writable_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);account=pwd.getpwnam('asterisk')
            os.chown(root,0,account.pw_gid);root.chmod(0o2775)
            helper=candidate_updater(root,account)
            data=root/'data';data.mkdir();os.chown(data,account.pw_uid,account.pw_gid);data.chmod(0o750)
            path=data/'update-status.json'
            command=['runuser','-u','asterisk','--','python3','-I',str(helper),str(path)]
            def run():return subprocess.run(command,input='{"state":"complete"}',capture_output=True,text=True,timeout=3)
            result=run();self.assertEqual(result.returncode,0,result.stderr)
            saved=path.read_bytes();inode=path.with_name(path.name+'.lock').stat().st_ino
            self.assertEqual(root.stat().st_mode&0o7777,0o2775)
            data.chmod(0o2770);self.assertNotEqual(run().returncode,0);data.chmod(0o750)
            os.chown(root,0,65534);self.assertNotEqual(run().returncode,0);os.chown(root,0,account.pw_gid)
            self.assertEqual(path.read_bytes(),saved);self.assertEqual(path.with_name(path.name+'.lock').stat().st_ino,inode)

    def test_updater_replaced_named_lease_preserves_old_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);account=pwd.getpwnam('asterisk');os.chown(root,account.pw_uid,account.pw_gid)
            helper=candidate_updater(root,account)
            code=r'''
import importlib.util, json, os, pathlib, sys
spec=importlib.util.spec_from_file_location('writer',sys.argv[2])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(sys.argv[1]);path=root/'update-status.json';module.write(path,{'state':'retained'})
saved=path.read_bytes();stat=module.os.stat;changed=False
def replace_lease(name,*args,**kwargs):
 global changed
 if name==path.name and kwargs.get('dir_fd') is not None and not changed:
  changed=True;lock=path.with_name(path.name+'.lock');os.rename(lock,root/'old-lock');lock.touch(mode=0o640)
 return stat(name,*args,**kwargs)
module.os.stat=replace_lease
try:module.write(path,{'state':'new'})
except ValueError as error:
 assert 'lock changed' in str(error)
else:raise RuntimeError('Detached updater lock was accepted.')
assert changed and path.read_bytes()==saved
assert not list(root.glob('.update-state-*'))
print('Private updater lease replacement refused; retained status and temporary cleanup verified.')
'''
            result=subprocess.run(['runuser','-u','asterisk','--','python3','-I','-c',code,str(root),str(helper)],capture_output=True,text=True,timeout=4)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)


if __name__ == '__main__': unittest.main()
