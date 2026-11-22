#!/usr/bin/python3
"""A live guard must revalidate its parents before affirming coordination."""
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT=Path(__file__).resolve().parents[1]
GUARD=ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_guard.py'


class GuardDirectoryMetadata(unittest.TestCase):
    def changed_after_ready(self, kind, command):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            parent=Path(name);data=parent/'data';data.mkdir(mode=0o700)
            process=subprocess.Popen([sys.executable,'-I',str(GUARD),'--data',str(data),'hold'],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                self.assertTrue(select.select([process.stdout],[],[],5)[0])
                self.assertEqual(process.stdout.readline(),b'ready\n')
                if kind=='ancestor-mode':parent.chmod(0o777)
                elif kind=='data-mode':data.chmod(0o770)
                elif kind=='data-owner':os.chown(data,12345,12345)
                elif kind=='paging-mode':(data/'live-paging-slots').chmod(0o770)
                elif kind=='paging-owner':os.chown(data/'live-paging-slots',12345,12345)
                else:self.fail('unknown fixture mutation')
                process.stdin.write(command);process.stdin.flush()
                self.assertTrue(select.select([process.stdout],[],[],5)[0])
                response=process.stdout.readline()
                self.assertNotIn(response,(b'checked\n',b'settings-ready\n'),
                                 'guard accepted unsafe live directory metadata: '+kind)
                process.communicate(timeout=5)
                self.assertNotEqual(process.returncode,0)
                self.assertFalse((data/'mass-notifications.config').exists())
            finally:
                if process.poll() is None:process.kill()
                process.communicate(timeout=5)
                parent.chmod(0o700)

    def test_ready_guard_rejects_unsafe_live_parent_or_paging_metadata(self):
        for kind in ('ancestor-mode','data-mode','data-owner','paging-mode','paging-owner'):
            with self.subTest(kind=kind):self.changed_after_ready(kind,b'check\n')

    def test_settings_join_does_not_accept_unsafe_parent_or_paging_metadata(self):
        for kind in ('data-mode','paging-mode'):
            with self.subTest(kind=kind):self.changed_after_ready(kind,b'settings\n')


if __name__=='__main__':unittest.main()
