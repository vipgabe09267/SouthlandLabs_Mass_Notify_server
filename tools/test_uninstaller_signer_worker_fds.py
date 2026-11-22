#!/usr/bin/python3
"""Actual retained signer metadata PHP must not receive worker leases."""
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT=Path(__file__).resolve().parents[1]
GUARD=ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_guard.py'
SIGNER=ROOT/'slsmassnotifyserver/bin/sign_sls_mass_notify_local_sig.sh'


class UninstallerSignerWorkerDescriptors(unittest.TestCase):
    def test_native_public_key_cleanup_gets_no_worker_descriptors(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            private=Path(name);private.chmod(0o755)
            data=private/'data';data.mkdir(mode=0o700)
            helper=private/'helper';helper.mkdir(mode=0o700)
            shutil.copyfile(GUARD,helper/'sls_install_guard.py')
            account=pwd.getpwnam('asterisk')
            native=private/'native';native.mkdir(mode=0o750);os.chown(native,account.pw_uid,account.pw_gid)
            home=native/'gnupg';home.mkdir(mode=0o700);os.chown(home,account.pw_uid,account.pw_gid)
            observation=native/'gpg-observations.jsonl'
            probe=private/'gpg-observer.py'
            probe.write_text('''import json,os,pathlib,sys
observed=[]
for fd in pathlib.Path('/proc/self/fd').iterdir():
    try:target=os.readlink(fd)
    except FileNotFoundError:continue
    if target.startswith(%r):observed.append(target)
with open(%r,'a') as output:output.write(json.dumps({'uid':os.getuid(),'fds':observed,'args':sys.argv[1:]})+'\\n')
if '--import-ownertrust' in sys.argv:sys.stdin.buffer.read()
''' % (str(data)+'/',str(observation)))
            probe.chmod(0o644)
            # Run the actual cleanup function and actual privilege boundary;
            # only candidate homes and the GPG executable are private. No key
            # operation or native PBX module bootstrap is performed.
            source=(ROOT/'tools/uninstall_release.sh').read_text()
            source=source.replace('for home in /root/.gnupg /home/asterisk/.gnupg /var/lib/asterisk/.gnupg; do',
                                  'for home in '+shlex.quote(str(home))+'; do',1)
            invocation='/usr/bin/python3 -I '+shlex.quote(str(probe))
            source=source.replace('/usr/bin/gpg',invocation)
            source=re.sub(r'(?<![A-Za-z0-9_/-])gpg(?=\s)',lambda _:invocation,source)
            candidate=private/'uninstall.sh';candidate.write_text(source);candidate.chmod(0o700)
            script=r'''
source "$1"
DATA_DIR="$2/data";RECOVERY_SIGNER_DIR="$2/helper"
SIGN_HOME="$2/no-private-key-material";SIGNING_FINGERPRINT=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
trap release_uninstall_workers EXIT
acquire_uninstall_workers
remove_trusted_signing_key
'''
            result=subprocess.run(['bash','-c',script,'fixture',str(candidate),str(private)],
                capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            rows=[json.loads(line) for line in observation.read_text().splitlines()]
            self.assertEqual(len(rows),2,rows)
            self.assertEqual({row['uid'] for row in rows},{account.pw_uid})
            self.assertTrue(any('--delete-key' in row['args'] for row in rows))
            self.assertTrue(any('--import-ownertrust' in row['args'] for row in rows))
            for row in rows:self.assertEqual(row['fds'],[],
                'native public-key cleanup inherited unlock-capable worker descriptors')

    def test_actual_signer_metadata_php_never_inherits_worker_descriptions(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            private=Path(name);data=private/'data';data.mkdir(mode=0o700)
            helper=private/'helper';helper.mkdir(mode=0o700)
            shutil.copyfile(GUARD,helper/'sls_install_guard.py')
            # Stop the actual signer's first native metadata query before its
            # PBX bootstrap, signature inventory, key work or signing. Only
            # the signing-lock path is adapted to this private fixture.
            probe='''$observed=[];
foreach (glob("/proc/self/fd/*") as $fd) {
    $target=@readlink($fd);
    if (is_string($target) && str_starts_with($target, %s)) { $observed[]=$target; }
}
fwrite(STDERR, "SLS_WORKER_FD_OBSERVATION ".json_encode(["uid"=>posix_geteuid(),"fds"=>$observed])."\\n");
exit(37);''' % json.dumps(str(data)+'/')
            source=SIGNER.read_text()
            self.assertIn('require "/etc/freepbx.conf";',source)
            source=source.replace('require "/etc/freepbx.conf";',probe,1)
            source=source.replace('LOCK_FILE="${SLS_LOCAL_SIGN_LOCK:-/run/lock/sls-mass-notify-signing.lock}"',
                                  'LOCK_FILE='+shlex.quote(str(private/'signing.lock')),1)
            signer=helper/'sign_sls_mass_notify_local_sig.sh';signer.write_text(source);signer.chmod(0o700)
            script=r'''
source "$1"
DATA_DIR="$2/data";RECOVERY_SIGNER_DIR="$2/helper"
RECOVERY_SIGNER="$RECOVERY_SIGNER_DIR/sign_sls_mass_notify_local_sig.sh"
STOCK_RESTORE_LOG="$2/signer.log"
trap release_uninstall_workers EXIT
acquire_uninstall_workers
locally_sign_stock_module dashboard
'''
            result=subprocess.run(['bash','-c',script,'fixture',str(ROOT/'tools/uninstall_release.sh'),
                str(private)],capture_output=True,text=True,timeout=12)
            self.assertEqual(result.returncode,1,result.stdout+result.stderr)
            entries=[line.removeprefix('SLS_WORKER_FD_OBSERVATION ') for line in
                     (private/'signer.log').read_text().splitlines() if line.startswith('SLS_WORKER_FD_OBSERVATION ')]
            self.assertEqual(len(entries),1,(private/'signer.log').read_text())
            observed=json.loads(entries[0]);self.assertEqual(observed['uid'],pwd.getpwnam('asterisk').pw_uid)
            self.assertEqual(observed['fds'],[],
                             'actual protected signer passed unlock-capable worker descriptions to native metadata PHP')


if __name__=='__main__':unittest.main()
