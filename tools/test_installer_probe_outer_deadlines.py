#!/usr/bin/python3
"""Actual installer/runtime boundary with inert PHP and shortened deadlines."""
import json
import os
from pathlib import Path
import pwd
import shlex
import subprocess
import tempfile
import time
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'tools/install_release.sh').read_text()
FUNCTIONS = {
    'verify_desktop_transport': 'verify_media_access',
    'verify_media_access': 'verify_control_api_authentication',
    'verify_control_api_authentication': 'verify_fresh_install_defaults',
}


class ProbeDeadlines(unittest.TestCase):
    def run_probe(self, function, *, slow=False, status=0, authority=True):
        account = pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(dir='/run', prefix='sls-probe-deadline-') as name:
            root = Path(name); root.chmod(0o755)
            evidence = root / 'evidence'; evidence.mkdir(mode=0o750)
            os.chown(evidence, account.pw_uid, account.pw_gid)
            receipt, finished = evidence / 'receipt.json', evidence / 'finished'
            fake = root / 'fake-php'
            fake.write_text('#!/usr/bin/python3\nimport json,os,signal,time\n'
                'from pathlib import Path\n'
                + ('signal.signal(signal.SIGTERM,signal.SIG_IGN)\n' if slow else '')
                + 'Path('+repr(str(receipt))+').write_text(json.dumps({"uid":os.geteuid(),'
                  '"config":os.environ.get("SLS_LOCAL_WEB_CONFIG_DUMP"),'
                  '"vhosts":os.environ.get("SLS_LOCAL_WEB_VHOST_DUMP")}))\n'
                + ('time.sleep(3)\n' if slow else '')
                + 'Path('+repr(str(finished))+').write_text("finished")\n'
                + 'raise SystemExit('+str(status)+')\n')
            fake.chmod(0o755)
            block = SOURCE.split(function+'() {', 1)[1].split('\n'+FUNCTIONS[function]+'() {', 1)[0]
            program = shlex.quote(str(fake))
            # Narrow fixture adapters: replace only the PHP execution boundary,
            # then shorten the fixed production wall deadline and kill grace.
            block = block.replace('/usr/bin/php', program)
            block = block.replace(' 60 '+program, ' 0.2 '+program).replace('--kill-after=2', '--kill-after=0.1')
            adapted = root / 'probe-function.sh'
            adapted.write_text(function+'() {'+block+'\n')
            shell = r'''
source "$1"
source "$2"
fixture_program="$4"; fixture_authority="$5"; fixture_function="$6"
LOG_FILE="$3/log"
log() { printf '%s\n' "$*" >>"$LOG_FILE"; }
capture_local_web_probe_authority() {
  [ "$fixture_authority" = yes ] || return 17
  SLS_LOCAL_WEB_CONFIG_DUMP='DocumentRoot /var/www/html'
  SLS_LOCAL_WEB_VHOST_DUMP='*:8443 pbx.fixture.invalid'
}
php() { sls_as_asterisk "$fixture_program" "$@"; }
"$fixture_function"
'''
            started = time.monotonic()
            result = subprocess.run(['/bin/bash', '-c', shell, 'fixture', str(ROOT/'tools/install_release.sh'),
                str(adapted), str(root), str(fake), 'yes' if authority else 'no', function],
                capture_output=True, text=True, timeout=6)
            elapsed = time.monotonic()-started
            observed = json.loads(receipt.read_text()) if receipt.exists() else None
            completed = finished.exists()
            log = (root/'log').read_text() if (root/'log').exists() else ''
            return result, elapsed, observed, completed, log

    def test_slow_native_probes_are_stopped_before_their_write_finishes(self):
        for function in FUNCTIONS:
            with self.subTest(function=function):
                result, elapsed, receipt, completed, log = self.run_probe(function, slow=True)
                self.assertIsNotNone(receipt, 'The real service-account PHP boundary was never reached')
                self.assertEqual(receipt['uid'], pwd.getpwnam('asterisk').pw_uid)
                self.assertEqual(receipt['config'], 'DocumentRoot /var/www/html')
                self.assertEqual(receipt['vhosts'], '*:8443 pbx.fixture.invalid')
                self.assertNotEqual(result.returncode, 0, 'Slow PHP completed without an outer installer deadline')
                self.assertFalse(completed, 'Timed-out PHP reached its later fixture write')
                self.assertLess(elapsed, 1.5, 'Installer outer deadline did not bound the native execution')

    def test_fast_success_and_existing_disabled_policy_statuses_are_preserved(self):
        cases = {'verify_desktop_transport': (0, 3, 4), 'verify_media_access': (0,),
                 'verify_control_api_authentication': (0, 3, 4, 5)}
        for function, statuses in cases.items():
            for status in statuses:
                with self.subTest(function=function, status=status):
                    result, elapsed, receipt, completed, log = self.run_probe(function, status=status)
                    self.assertEqual(result.returncode, 0, result.stderr+log)
                    self.assertEqual(receipt['uid'], pwd.getpwnam('asterisk').pw_uid)
                    self.assertTrue(completed)

    def test_authority_refusal_never_starts_php(self):
        for function in FUNCTIONS:
            with self.subTest(function=function):
                result, elapsed, receipt, completed, log = self.run_probe(function, authority=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(receipt)
                self.assertFalse(completed)


if __name__ == '__main__':
    unittest.main()
