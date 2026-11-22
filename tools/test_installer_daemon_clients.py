#!/usr/bin/python3
"""Daemon admission must ignore native remote consoles and reject real wrong daemons.

Exact embedded installer checker, synthetic /proc controls and one disposable
native daemon/remote console. No production socket, configuration, channel,
module installer, network peer or service operation is used.
"""
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import time
import unittest

for label, kind in [('MOUNT','mnt'),('NET','net'),('PID','pid')]:
    if (os.environ.get('SLS_TEST_NAMESPACE')!='entered' or
            os.environ.get('SLS_TEST_PARENT_'+label+'_NS') in
            (None,'',os.readlink('/proc/self/ns/'+kind))):
        raise SystemExit('Fresh private namespaces required; no daemon was started.')

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'tools/install_release.sh').read_text()
CHECK=SOURCE.split("<<'PYASTERISKRUNTIME'\n",1)[1].split('\nPYASTERISKRUNTIME',1)[0]
ACCOUNT=pwd.getpwnam('asterisk')

def inspect(configuration, processes, binary):
    return subprocess.run(['/usr/bin/python3','-I','-c',CHECK,str(configuration),
        str(configuration),str(processes),str(binary)],capture_output=True,text=True,timeout=5)

def identities(pid):
    text=Path('/proc',str(pid),'status').read_text()
    return {key:[int(value) for value in next(line for line in text.splitlines()
        if line.startswith(key+':')).split()[1:]] for key in ('Uid','Gid')}

class RuntimeClientObservation(unittest.TestCase):
    def test_exact_checker_proc_controls_and_console_option_shapes(self):
        with tempfile.TemporaryDirectory(prefix='sll-audit-uid-proc-',dir='/run') as name:
            root=Path(name);configuration=root/'configuration';configuration.mkdir()
            binary=root/'asterisk';binary.write_bytes(b'inert identity fixture')
            processes=root/'proc';processes.mkdir()
            def process(pid,argv,uid=ACCOUNT.pw_uid,gid=ACCOUNT.pw_gid):
                path=processes/str(pid);path.mkdir();(path/'exe').symlink_to(binary)
                (path/'cmdline').write_bytes(b'\0'.join(argv)+b'\0')
                (path/'status').write_text('Uid:\t'+'\t'.join([str(uid)]*4)+
                    '\nGid:\t'+'\t'.join([str(gid)]*4)+'\n')
                return path
            daemon=process(51,[b'/usr/sbin/asterisk',b'-f'])
            self.assertEqual(inspect(configuration,processes,binary).returncode,0)
            controls=[]
            for option in (b'-r',b'-R',b'-rx'):
                argv=[b'/usr/sbin/asterisk',option]
                if option==b'-rx': argv.append(b'core show version')
                client=process(52,argv,uid=0,gid=0)
                result=inspect(configuration,processes,binary)
                self.assertEqual(result.returncode,0,result.stderr)
                shutil.rmtree(client)
                controls.append(option.decode())
            cases=[]
            for argv in ([b'/usr/sbin/asterisk',b'-vvvr'],
                         [b'/usr/sbin/asterisk',b'-gr'],
                         [b'rasterisk',b'-vvv']):
                client=process(52,argv,uid=0,gid=0)
                result=inspect(configuration,processes,binary)
                self.assertEqual(result.returncode,0,result.stderr)
                cases.append({'argv':[part.decode() for part in argv],
                              'healthy_daemon_plus_root_console_exit':result.returncode})
                shutil.rmtree(client)
            # Matching-UID consoles also produce a false duplicate-daemon result.
            client=process(52,[b'rasterisk',b'-vvv'])
            result=inspect(configuration,processes,binary)
            self.assertEqual(result.returncode,0,result.stderr)
            shutil.rmtree(client)
            second=process(52,[b'/usr/sbin/asterisk',b'-f'])
            self.assertNotEqual(inspect(configuration,processes,binary).returncode,0)
            shutil.rmtree(second)
            (daemon/'cmdline').write_bytes(b'/usr/sbin/asterisk\0-Uasterisk\0-Gasterisk\0-C/etc/asterisk/asterisk.conf\0-f\0')
            self.assertEqual(inspect(configuration,processes,binary).returncode,0)
            # A genuinely privileged daemon is still correctly refused.
            (daemon/'status').write_text('Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n')
            self.assertIn('active daemon Uid',inspect(configuration,processes,binary).stderr)
            print(json.dumps({'audit_observation':'asterisk_console_proc_identity',
                'valid_nonroot_daemon_control_passed':True,
                'standalone_remote_flags_correctly_ignored':controls,
                'root_console_shapes_admitted':cases,
                'service_uid_console_ignored':True,
                'real_root_daemon_control_refused':True,
                'full_installer_not_executed':True},sort_keys=True),flush=True)

    def test_real_private_nonroot_daemon_and_native_root_remote_console(self):
        binary=Path('/usr/sbin/asterisk')
        self.assertTrue(binary.is_file())
        with tempfile.TemporaryDirectory(prefix='sll-audit-native-uid-',dir='/tmp') as name:
            root=Path(name);root.chmod(0o755)
            for directory in ('etc','run','log','spool','data','data/documentation','cache','agi'):
                path=root/directory;path.mkdir(parents=True,exist_ok=True);path.chmod(0o755)
                os.chown(path,ACCOUNT.pw_uid,ACCOUNT.pw_gid)
            modules=next(Path(path) for path in ('/usr/lib/asterisk/modules',
                '/usr/lib64/asterisk/modules','/usr/lib/x86_64-linux-gnu/asterisk/modules')
                if Path(path).is_dir())
            document=Path('/tmp/sls-asterisk-vendor-docs/core-en_US.xml')
            if document.is_file():
                target=root/'data/documentation/core-en_US.xml'
                shutil.copyfile(document,target);target.chmod(0o644)
            paths={'astetcdir':root/'etc','astmoddir':modules,'astvarlibdir':root/'data',
                'astdbdir':root/'data','astdatadir':root/'data','astagidir':root/'agi',
                'astspooldir':root/'spool','astrundir':root/'run','astlogdir':root/'log',
                'astcachedir':root/'cache'}
            configuration=root/'etc/asterisk.conf'
            configuration.write_text('[directories]\n'+''.join(k+' = '+str(v)+'\n'
                for k,v in paths.items())+'[options]\nverbose=0\n')
            (root/'etc/modules.conf').write_text('[modules]\nautoload=no\n')
            (root/'etc/logger.conf').write_text('[general]\n[logfiles]\nconsole => error,warning\n')
            for path in (root/'etc').iterdir():path.chmod(0o644)
            with (root/'daemon.log').open('wb') as log:
                daemon=subprocess.Popen([str(binary),'-f','-g','-q','-n','-C',str(configuration),
                    '-U','asterisk','-G','asterisk'],stdin=subprocess.DEVNULL,
                    stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                try:
                    deadline=time.monotonic()+10
                    while not (root/'run/asterisk.ctl').exists():
                        if daemon.poll() is not None or time.monotonic()>deadline:
                            self.fail('Private daemon did not become ready: '+
                                      (root/'daemon.log').read_text(errors='replace')[-2500:])
                        time.sleep(.05)
                    daemon_ids=identities(daemon.pid)
                    self.assertEqual(daemon_ids['Uid'],[ACCOUNT.pw_uid]*4)
                    self.assertEqual(daemon_ids['Gid'],[ACCOUNT.pw_gid]*4)
                    control=inspect(root/'etc',Path('/proc'),binary)
                    self.assertEqual(control.returncode,0,control.stderr)
                    observations=[]
                    alias=root/'rasterisk';alias.symlink_to(binary)
                    cases=((binary,'-r',False),(binary,'-vvvr',False),
                           (alias,'-vvv',False),(binary,'-vvvr',True))
                    for index,(entry,option,service_user) in enumerate(cases):
                        with (root/('client-'+str(index)+'.log')).open('wb') as client_log:
                            credentials={'user':ACCOUNT.pw_uid,'group':ACCOUNT.pw_gid,'extra_groups':[]} if service_user else {}
                            client=subprocess.Popen([str(entry),'-C',str(configuration),option],
                                stdin=subprocess.PIPE,stdout=client_log,stderr=subprocess.STDOUT,
                                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','TERM':'dumb'},
                                start_new_session=True,**credentials)
                            try:
                                deadline=time.monotonic()+3
                                while True:
                                    self.assertIsNone(client.poll(),'Private remote client exited early')
                                    raw=Path('/proc',str(client.pid),'cmdline').read_bytes()
                                    if b'rasterisk' in raw or time.monotonic()>deadline:break
                                    time.sleep(.02)
                                time.sleep(.1)
                                client_ids=identities(client.pid)
                                result=inspect(root/'etc',Path('/proc'),binary)
                                observations.append({'invoked_binary_name':entry.name,
                                    'invoked_option':option,'service_uid_client':service_user,
                                    'native_cmdline':[part.decode(errors='replace') for part in raw.split(b'\0') if part],
                                    'client_ids':client_ids,'admission_exit':result.returncode,
                                    'reported_uid_mismatch':'active daemon Uid' in result.stderr})
                                if service_user:
                                    self.assertEqual(client_ids['Uid'],[ACCOUNT.pw_uid]*4)
                                    self.assertEqual(result.returncode,0,result.stderr)
                                elif option!='-r':
                                    self.assertEqual(result.returncode,0,result.stderr)
                                else:self.assertEqual(result.returncode,0,result.stderr)
                            finally:
                                if client.poll() is None:client.kill()
                                client.communicate(timeout=3)
                    self.assertEqual(inspect(root/'etc',Path('/proc'),binary).returncode,0)
                    print(json.dumps({'audit_observation':'native_asterisk_remote_console_uid',
                        'daemon_ids':daemon_ids,'valid_daemon_control_exit':control.returncode,
                        'native_console_observations':observations,
                        'control_passes_again_after_own_client_exits':True,
                        'no_production_socket_services_calls_or_installer':True},sort_keys=True),flush=True)
                finally:
                    if daemon.poll() is None:daemon.terminate()
                    try:daemon.wait(timeout=5)
                    except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=3)

if __name__=='__main__':unittest.main()
