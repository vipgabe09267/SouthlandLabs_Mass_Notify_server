#!/usr/bin/python3
"""A rejected signature must never replace the outstanding exact beforeimage."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':
    raise RuntimeError('Run only through tools/run_isolated_tests.sh')
ROOT=Path(__file__).resolve().parents[1]


class PendingSignature(unittest.TestCase):
    def test_second_publication_cannot_replace_unrestored_original_snapshot(self):
        with tempfile.TemporaryDirectory(prefix='sls-v020-pending-signature-',dir='/run') as name:
            root=Path(name);web=root/'web';web.mkdir()
            subprocess.run(['/bin/mount','-t','tmpfs','-o','nosuid,nodev,size=2m','sls-v020-pending',str(web)],
                           check=True,capture_output=True)
            try:
                module=web/'admin/modules/framework';module.mkdir(parents=True)
                original=b'exact original inert signature\n';candidate=b'rejected inert candidate\n'
                (module/'module.sig').write_bytes(original)
                work=root/'work';work.mkdir(mode=0o700);(work/'module.sig.candidate').write_bytes(candidate)
                program='''source "$1"
MODULE=framework;FREEPBX_WEB_ROOT="$2";FREEPBX_WEB_USER=asterisk
MODULE_DIR="$FREEPBX_WEB_ROOT/admin/modules/$MODULE"
TRUST_HELPER="$3";WORKDIR="$4"
prepare_freepbx_gpg_home(){ /bin/mount -o remount,ro "$FREEPBX_WEB_ROOT" || return 90;return 19; }
if publish_candidate_transactionally;then exit 97;fi
if publish_candidate_transactionally;then exit 98;fi
exit 19
'''
                result=subprocess.run(['/bin/bash','-c',program,'fixture',
                    str(ROOT/'slsmassnotifyserver/bin/sign_sls_mass_notify_local_sig.sh'),str(web),
                    str(ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_module_trust.py'),str(work)],
                    capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,19,result.stderr)
                self.assertEqual((module/'module.sig').read_bytes(),candidate,result.stderr)
                self.assertEqual((work/'module.sig.previous').read_bytes(),original,
                                 'A second backup replaced the original signature with rejected bytes')
            finally:
                subprocess.run(['/bin/umount',str(web)],check=True,capture_output=True)


if __name__=='__main__':unittest.main()
