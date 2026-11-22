#!/usr/bin/python3
"""Protected retained signer execution works without executable state mounts."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':
    raise RuntimeError('Run only through tools/run_isolated_tests.sh')
ROOT=Path(__file__).resolve().parents[1]


class RetainedSignerNoexec(unittest.TestCase):
    def observe(self,syntax_error=False,symlink=False,foreign_owner=False):
        with tempfile.TemporaryDirectory(prefix='sls-v020-uninstall-noexec-',dir='/run') as name:
            root=Path(name);state=root/'state';state.mkdir(mode=0o700)
            subprocess.run(['/bin/mount','-t','tmpfs','-o','noexec,nosuid,nodev,size=2m,mode=0700',
                            'sls-v020-uninstall-signer',str(state)],check=True,capture_output=True)
            try:
                source=state/'approved-source.sh'
                source.write_text('#!/bin/bash\nif broken\n' if syntax_error else
                    '#!/bin/bash\n[ "$SLS_LOCAL_TRUST_MODE" = uninstalled ] || exit 41\n'
                    '[ "$SLS_LOCAL_TRUST_HELPER" = "$V020_EXPECTED_HELPER" ] || exit 42\n'
                    'printf "%s" "$1" > "$V020_SIGN_MARKER"\n')
                source.chmod(0o700)
                signer=state/'sign_sls_mass_notify_local_sig.sh'
                if symlink:signer.symlink_to(source)
                else:signer.write_bytes(source.read_bytes());signer.chmod(0o700)
                if foreign_owner:
                    import pwd
                    account=pwd.getpwnam('asterisk');os.chown(signer,account.pw_uid,account.pw_gid)
                marker=root/'signed'
                program='''source "$1"
RECOVERY_SIGNER_DIR="$2";RECOVERY_SIGNER="$2/sign_sls_mass_notify_local_sig.sh"
STOCK_RESTORE_LOG="$2/signing.log"
verify_stock_module(){ [ "$1" = framework ]; }
locally_sign_stock_module framework
'''
                result=subprocess.run(['/bin/bash','-c',program,'fixture',str(ROOT/'tools/uninstall_release.sh'),str(state)],
                    capture_output=True,text=True,timeout=10,
                    env={**os.environ,'V020_EXPECTED_HELPER':str(state/'sls_module_trust.py'),'V020_SIGN_MARKER':str(marker)})
                if syntax_error or symlink or foreign_owner:
                    self.assertNotEqual(result.returncode,0)
                    self.assertFalse(marker.exists())
                else:
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(marker.read_text(),'framework')
                self.assertTrue(os.statvfs(state).f_flag&os.ST_NOEXEC)
                self.assertEqual(source.read_text(),'#!/bin/bash\nif broken\n' if syntax_error else
                    '#!/bin/bash\n[ "$SLS_LOCAL_TRUST_MODE" = uninstalled ] || exit 41\n'
                    '[ "$SLS_LOCAL_TRUST_HELPER" = "$V020_EXPECTED_HELPER" ] || exit 42\n'
                    'printf "%s" "$1" > "$V020_SIGN_MARKER"\n')
            finally:
                subprocess.run(['/bin/umount',str(state)],check=True,capture_output=True)

    def test_exact_retained_script_runs_on_noexec_state_without_changing_mount(self):
        self.observe()

    def test_syntax_invalid_retained_script_refuses_before_execution(self):
        self.observe(syntax_error=True)

    def test_retained_script_symlink_is_not_executed(self):
        self.observe(symlink=True)

    def test_foreign_owned_retained_script_is_not_executed(self):
        self.observe(foreign_owner=True)


if __name__=='__main__':unittest.main()
