#!/usr/bin/python3
"""Observe the provider-repair branch of the console-classification family.

Runs exact unchanged embedded Python from install_release.sh over inert fake
/proc, image, package-checksum and module-map files. The module-peer worker has
one explicit dpkg-query read-response adapter copied from the repository's
existing module-peer fixture pattern. It permits no other external command.
No native Asterisk/PBX/application, package install, service or socket is used.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import unittest

for label, kind in [('MOUNT', 'mnt'), ('NET', 'net'), ('PID', 'pid')]:
    if (os.environ.get('SLS_TEST_NAMESPACE') != 'entered' or
            os.environ.get('SLS_TEST_PARENT_' + label + '_NS') in
            (None, '', os.readlink('/proc/self/ns/' + kind))):
        raise SystemExit('Fresh private namespaces required; no observation ran.')

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'tools/install_release.sh').read_text()

def embedded(marker):
    return SOURCE.split("<<'" + marker + "'\n", 1)[1].split('\n' + marker, 1)[0]

RUNTIME = embedded('PYASTERISKRUNTIME')
BINARY = embedded('PYPACKAGEDASTERISK')
PEERS = embedded('PYASTERISKMODULESET')
ACCOUNT = pwd.getpwnam('asterisk')

class ProviderRemoteClientObservation(unittest.TestCase):
    def test_native_owned_mapped_independent_addon_keeps_package_authority(self):
        with tempfile.TemporaryDirectory(prefix='sll-native-addon-', dir='/run') as name:
            root=Path(name);root.chmod(0o700)
            modules=root/'modules';modules.mkdir(mode=0o755)
            binary=root/'asterisk';binary.write_bytes(b'inert daemon image')
            target=modules/'res_pjsip_notify.so';target.write_bytes(b'inert root-owned target')
            addon=modules/'app_flite.so';original=b'inert independently packaged addon';addon.write_bytes(original)
            core_sums=root/'core.md5sums';addon_sums=root/'addon.md5sums'
            def sums(path,entries):
                path.write_text(''.join(hashlib.md5(body,usedforsecurity=False).hexdigest()+'  '+str(p).lstrip('/')+'\n'for p,body in entries))
                path.chmod(0o644)
            sums(core_sums,[(target,target.read_bytes()),(addon,original)])
            sums(addon_sums,[(addon,original)])
            for p in(binary,target,addon):p.chmod(0o755)
            processes=root/'proc';processes.mkdir(mode=0o755)
            daemon=processes/'51';daemon.mkdir(mode=0o755);(daemon/'exe').symlink_to(binary)
            (daemon/'cmdline').write_bytes(str(binary).encode()+b'\0-f\0')
            fields=['S']+['0']*18+['12345']+['0']*5
            (daemon/'stat').write_text('51 (asterisk) '+' '.join(fields)+'\n')
            adapter=r'''import hashlib,json,pathlib,subprocess,sys,types
fixture=json.loads(sys.argv[1]);sys.argv=sys.argv[1:]
def query(args,**kwargs):
    if args[0]!='/usr/bin/dpkg-query':raise AssertionError('Unexpected native command')
    if args[1]=='-S':return types.SimpleNamespace(returncode=0,stdout=fixture['owners'],stderr='')
    owner=args[-1] if args[1]=='-W' else args[2]
    if args[1]=='-W':return types.SimpleNamespace(returncode=0,stdout='hi \t'+fixture['versions'][owner],stderr='')
    if args[1]=='--control-path':return types.SimpleNamespace(returncode=0,stdout=fixture['metadata'][owner]+'\n',stderr='')
    raise AssertionError('Unexpected package query')
subprocess.run=query
original_md5=hashlib.md5
def md5(data,*args,**kwargs):
    value=original_md5(data,*args,**kwargs)
    if fixture['mutate'] and data==b'inert independently packaged addon':
        pathlib.Path(fixture['addon']).write_bytes(b'changed after the verified hash read')
    if fixture['mutate_start'] and data==b'inert independently packaged addon':
        path=pathlib.Path(fixture['process'])/'stat';path.write_text(path.read_text().replace('12345','12346'))
    return value
hashlib.md5=md5
'''
            foreign=pwd.getpwnam('www-data')
            def check(*,uid=ACCOUNT.pw_uid,gid=ACCOUNT.pw_gid,mode=0o755,owner='asterisk-flite',
                    daemon_uid=ACCOUNT.pw_uid,daemon_gid=ACCOUNT.pw_gid,changed=False,wrong_inode=False,
                    metadata_native=False,hardlink=False,symlink=False,mutate=False,unmapped_target=False,unknown=False,
                    mutate_start=False,target_native=False,mixed_uid=False,mixed_gid=False):
                addon.write_bytes(b'changed before the checksum read'if changed else original)
                os.chown(addon,uid,gid);addon.chmod(mode)
                os.chown(target,ACCOUNT.pw_uid if target_native else 0,ACCOUNT.pw_gid if target_native else 0);target.chmod(0o755)
                os.chown(addon_sums,ACCOUNT.pw_uid if metadata_native else 0,ACCOUNT.pw_gid if metadata_native else 0)
                uids=[str(daemon_uid)]*4;gids=[str(daemon_gid)]*4
                if mixed_uid:uids[-1]='0'
                if mixed_gid:gids[-1]='0'
                (daemon/'status').write_text('Uid:\t'+'\t'.join(uids)+'\nGid:\t'+'\t'.join(gids)+'\n')
                (daemon/'stat').write_text('51 (asterisk) '+' '.join(fields)+'\n')
                s=addon.stat();mapped=('1000-2000 r-xp 00000000 '+f'{os.major(s.st_dev):02x}:{os.minor(s.st_dev):02x} '+str(s.st_ino+int(wrong_inode))+' '+str(addon)+'\n')
                (daemon/'maps').write_text(''if unmapped_target else mapped+mapped)
                extra=root/'extra-link';saved=root/'saved-addon'
                if hardlink:os.link(addon,extra)
                if symlink:addon.rename(saved);addon.symlink_to(saved)
                owners='asterisk-core: '+str(target)+'\n'+(''if unknown else owner+': '+str(addon)+'\n')
                fixture={'owners':owners,'versions':{'asterisk-core':'22.11.0-1','asterisk-flite':'0.6'},
                    'metadata':{'asterisk-core':str(core_sums),'asterisk-flite':str(addon_sums)},'addon':str(addon),'mutate':mutate,
                    'mutate_start':mutate_start,'process':str(daemon)}
                args=[str(modules),'asterisk-flite'if unmapped_target else 'asterisk-core',
                    '0.6'if unmapped_target else '22.11.0-1',addon.name if unmapped_target else target.name,str(processes),str(binary)]
                try:return subprocess.run(['/usr/bin/python3','-I','-c',adapter+PEERS,json.dumps(fixture),*args],capture_output=True,text=True,timeout=4)
                finally:
                    if hardlink:extra.unlink()
                    if symlink:addon.unlink();saved.rename(addon)
            with self.subTest(case='root_owned_control'):
                r=check(uid=0,gid=0);self.assertEqual(r.returncode,0,r.stderr)
            with self.subTest(case='native_owned_loaded_independent_addon'):
                r=check();self.assertEqual(r.returncode,0,r.stderr)
            controls={'foreign_uid':{'uid':foreign.pw_uid},'foreign_gid':{'gid':foreign.pw_gid},
                'group_writable':{'mode':0o775},'hardlinked':{'hardlink':True},'symlink':{'symlink':True},
                'native_owned_core_peer':{'owner':'asterisk-core'},'native_owned_unmapped_target':{'unmapped_target':True},
                'native_owned_target':{'target_native':True},'mixed_daemon_uid':{'mixed_uid':True},'mixed_daemon_gid':{'mixed_gid':True},
                'native_owned_checksum_authority':{'metadata_native':True},'changed_bytes':{'changed':True},
                'wrong_mapped_inode':{'wrong_inode':True},'root_daemon':{'daemon_uid':0,'daemon_gid':0},
                'foreign_daemon_gid':{'daemon_gid':foreign.pw_gid},'unknown_package_owner':{'unknown':True}}
            for label,options in controls.items():
                with self.subTest(case=label):
                    r=check(**options);self.assertNotEqual(r.returncode,0,(label,r.stdout,r.stderr))
            with self.subTest(case='native_peer_mutates_after_first_hash_before_cached_mapping'):
                r=check(mutate=True);self.assertNotEqual(r.returncode,0,r.stderr)
                self.assertIn('native mapped peer changed',r.stderr)
            with self.subTest(case='native_daemon_start_changes_during_peer_inspection'):
                r=check(mutate_start=True);self.assertNotEqual(r.returncode,0,r.stderr)
                self.assertIn('native mapped peer daemon changed',r.stderr)

    def test_provider_package_requires_healthy_installed_status_including_holds(self):
        code = SOURCE.split('asterisk_provider_package() {\n', 1)[1].split('\n}\n', 1)[0]
        with tempfile.TemporaryDirectory(prefix='sll-provider-status-', dir='/run') as name:
            provider = Path(name)/'res_pjsip_notify.so'
            provider.write_bytes(b'inert package-owned provider')
            script = '''set -eu
fixture_provider=$1
fixture_status=$2
dpkg-query() {
  case "$1" in
    -S) printf 'asterisk-core: %s\\n' "$fixture_provider" ;;
    -W) [ "$2" = '-f=${db:Status-Abbrev}' ]; printf '%s' "$fixture_status" ;;
    *) return 99 ;;
  esac
}
asterisk_provider_package() {
''' + code + '\n}\nasterisk_provider_package "$fixture_provider"\n'
            for status in ('ii ', 'hi ', 'iiR', 'hiR', 'iF ', 'iU ', 'ri ', 'pi ', 'rc ', 'ii', 'ii  '):
                with self.subTest(status=status):
                    result = subprocess.run(['/bin/bash', '-c', script, 'status-fixture', str(provider), status],
                        capture_output=True, text=True, timeout=4)
                    if status in ('ii ', 'hi '):
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, 'asterisk-core\n')
                    else:
                        self.assertNotEqual(result.returncode, 0, status)
                        self.assertEqual(result.stdout, '')

    def test_exact_provider_classifiers_against_standalone_remote_flags(self):
        self.assertGreater(ACCOUNT.pw_uid, 0)
        self.assertGreater(ACCOUNT.pw_gid, 0)
        with tempfile.TemporaryDirectory(prefix='sll-audit-provider-clients-', dir='/run') as name:
            root = Path(name)
            root.chmod(0o700)
            configuration = root/'configuration'
            configuration.mkdir(mode=0o755)
            modules = root/'modules'
            modules.mkdir(mode=0o755)
            binary = root/'asterisk'
            binary.write_bytes(b'inert package-owned Asterisk image; never executable')
            target = modules/'res_pjsip_notify.so'
            target.write_bytes(b'inert intended packaged provider')
            peer = modules/'res_pjsip.so'
            peer.write_bytes(b'inert mapped PJSIP peer')
            metadata = root/'package.md5sums'
            metadata.write_text(''.join(hashlib.md5(p.read_bytes(), usedforsecurity=False).hexdigest()
                + '  ' + str(p).lstrip('/') + '\n' for p in (binary, target, peer)))
            for path in (binary, target, peer, metadata):
                path.chmod(0o644)
            processes = root/'proc'
            processes.mkdir(mode=0o755)
            peer_info = peer.stat()
            peer_map = ('1000-2000 r-xp 00000000 '
                + f'{os.major(peer_info.st_dev):02x}:{os.minor(peer_info.st_dev):02x}'
                + f' {peer_info.st_ino} {peer}\n')
            def process(pid, arguments, uid=ACCOUNT.pw_uid, gid=ACCOUNT.pw_gid, mapped=''):
                path = processes/str(pid)
                path.mkdir(mode=0o755)
                (path/'exe').symlink_to(binary)
                (path/'cmdline').write_bytes(b'\0'.join([str(binary).encode(), *arguments]) + b'\0')
                (path/'status').write_text('Uid:\t' + '\t'.join([str(uid)]*4)
                    + '\nGid:\t' + '\t'.join([str(gid)]*4) + '\n')
                (path/'maps').write_text(mapped)
                return path
            daemon = process(51, [b'-f', b'-U', b'asterisk', b'-G', b'asterisk'], mapped=peer_map)
            owners = ''.join('asterisk-core: '+str(p)+'\n' for p in (target, peer))
            # Only native package database read responses are adapted. The exact
            # embedded code still validates protected file modes/checksums,
            # the installed image, native device+inode map identities and counts.
            adapter = '''import subprocess,sys,types
fixture_metadata,fixture_version,fixture_owners,fixture_status=sys.argv[1:5]
def native_query(args,**kwargs):
    if args[0]!='/usr/bin/dpkg-query': raise AssertionError('Unexpected external command')
    if args[1]=='-S': return types.SimpleNamespace(returncode=0,stdout=fixture_owners,stderr='')
    if args[1]=='-W': return types.SimpleNamespace(returncode=0,stdout=fixture_status+'\\t'+fixture_version,stderr='')
    if args[1]=='--control-path': return types.SimpleNamespace(returncode=0,stdout=fixture_metadata+'\\n',stderr='')
    raise AssertionError('Unexpected package query')
subprocess.run=native_query
sys.argv=sys.argv[4:]
'''
            def check(package_status='ii '):
                commands = {
                    'runtime_identity': (RUNTIME, [str(configuration), str(configuration), str(processes), str(binary)]),
                    'packaged_binary': (BINARY, [str(binary), str(metadata), str(processes)]),
                    'module_peers': (adapter+PEERS, [str(metadata), '22.11.0-1', owners, package_status,
                        str(modules), 'asterisk-core', '22.11.0-1', target.name, str(processes), str(binary)]),
                }
                results = {}
                for label, (code, arguments) in commands.items():
                    result = subprocess.run(['/usr/bin/python3', '-I', '-c', code, *arguments],
                        capture_output=True, text=True, timeout=4)
                    results[label] = {'exit': result.returncode, 'stderr': result.stderr.strip()}
                return results
            observations = []
            clean = check()
            self.assertEqual([clean[k]['exit'] for k in clean], [0, 0, 0], clean)
            observations.append({'case': 'one_correct_nonroot_daemon', 'checks': clean})
            for status in ('ii ', 'hi ', 'iiR', 'hiR', 'iF ', 'iU ', 'ri ', 'pi ', 'rc ', 'ii', 'ii  '):
                with self.subTest(package_status=status):
                    observed = check(status)['module_peers']
                    if status in ('ii ', 'hi '):
                        self.assertEqual(observed['exit'], 0, observed)
                    else:
                        self.assertNotEqual(observed['exit'], 0, status)
                        self.assertIn('not installed with version authority', observed['stderr'])
            for identity, uid, gid in [('root', 0, 0), ('runtime', ACCOUNT.pw_uid, ACCOUNT.pw_gid)]:
                for option, argument, expected in [(b'-r', [], [0, 0, 0]),
                        (b'-R', [], [0, 0, 0]),
                        (b'-x', [b'core show version'], [0, 0, 0])]:
                    client = process(52, [option, *argument], uid=uid, gid=gid)
                    result = check()
                    self.assertEqual([result[k]['exit'] for k in result], expected, result)
                    observations.append({'case': 'valid_daemon_plus_'+identity+'_client',
                        'remote_option': option.decode(), 'synthetic_client_uid': uid, 'checks': result})
                    shutil.rmtree(client)
            # The runtime gate continues to reject an actual root daemon. The
            # provider proofs intentionally establish image authority, not UID.
            (daemon/'status').write_text('Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n')
            root_daemon = check()
            self.assertEqual([root_daemon[k]['exit'] for k in root_daemon], [1, 0, 0], root_daemon)
            self.assertIn('active daemon Uid', root_daemon['runtime_identity']['stderr'])
            observations.append({'case': 'actual_root_daemon_still_refused_by_runtime_gate', 'checks': root_daemon})
            (daemon/'status').write_text('Uid:\t'+'\t'.join([str(ACCOUNT.pw_uid)]*4)
                +'\nGid:\t'+'\t'.join([str(ACCOUNT.pw_gid)]*4)+'\n')
            # Preserve meaningful provenance controls: root-protected changed
            # bytes and a wrong mapped inode still fail their respective proofs.
            binary.write_bytes(b'changed inert image')
            bad_binary = check()
            self.assertNotEqual(bad_binary['packaged_binary']['exit'], 0)
            self.assertIn('binary differs', bad_binary['packaged_binary']['stderr'])
            observations.append({'case': 'changed_package_image_refused', 'checks': bad_binary})
            binary.write_bytes(b'inert package-owned Asterisk image; never executable')
            (daemon/'maps').write_text(peer_map.replace(' '+str(peer_info.st_ino)+' ', ' '+str(peer_info.st_ino+1)+' '))
            bad_map = check()
            self.assertNotEqual(bad_map['module_peers']['exit'], 0)
            self.assertIn('installed package inode', bad_map['module_peers']['stderr'])
            observations.append({'case': 'wrong_mapped_inode_refused', 'checks': bad_map})
            (daemon/'maps').write_text(peer_map)
            restored = check()
            self.assertEqual([restored[k]['exit'] for k in restored], [0, 0, 0], restored)
            print(json.dumps({'audit_observation': 'provider_repair_remote_client_family_expansion',
                'source_sha256': hashlib.sha256(SOURCE.encode()).hexdigest(),
                'embedded_code_sha256': {k:hashlib.sha256(v.encode()).hexdigest()
                    for k,v in [('runtime',RUNTIME),('binary',BINARY),('peers',PEERS)]},
                'observations': observations,
                'healthy_control_passes_again': True,
                'actual_external_commands_used': ['/usr/bin/python3'],
                'package_adapter': 'only inert dpkg-query -S/-W/--control-path read responses',
                'limits': 'Exact component classification only; no provider install, native PBX execution, full installer or target-cause attribution.'}, sort_keys=True), flush=True)

if __name__ == '__main__':
    unittest.main()
