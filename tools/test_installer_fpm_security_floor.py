#!/usr/bin/python3
"""A healthy CLI cannot hide an outdated served FPM binary before mutation."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'tools/install_release.sh').read_text()


class FpmSecurityFloor(unittest.TestCase):
    def check(self, banner, *, profile='8.2:fpm', status=0):
        with tempfile.TemporaryDirectory(dir='/run', prefix='sls-fpm-floor-') as name:
            base = Path(name)
            policy = base / 'stage/slsmassnotifyserver/bin/sls_mass_notify/php-security-policy.json'
            policy.parent.mkdir(parents=True)
            # The real fixture CLI is newer than this floor. Only the served
            # inert FPM banner varies; no daemon, service or PBX is started.
            policy.write_text(json.dumps({'schema': 1, 'branches': {'8.2': '8.2.1'}}))
            binary = base / 'php-fpm8.2'
            binary.write_text('#!/bin/sh\n[ "$1" = -n ] && [ "$2" = -v ] || exit 92\n'
                + 'printf called >"' + str(base / 'fpm-called') + '"\n'
                + 'cat <<\'BANNER\'\n' + banner + '\nBANNER\nexit ' + str(status) + '\n')
            binary.chmod(0o755)
            installer = base / 'installer.sh'
            # Explicit fixture-only relocation of the fixed binary directory.
            installer.write_text(SOURCE.replace('/usr/sbin/php-fpm', str(base / 'php-fpm')))
            harness = r'''
source "$1"
STAGING_DIR="$2/stage"; SERVED_PHP_PROFILES="$3"
log() { printf '%s\n' "$*" >&2; }
sls_as_asterisk() { "$@"; }
sls_supervised_as_asterisk() { "$@"; }
verify_php_security_versions_before_mutation
'''
            result = subprocess.run(['bash', '-c', harness, 'fixture', str(installer), str(base), profile],
                capture_output=True, text=True, timeout=10)
            result.fpm_called = (base / 'fpm-called').exists()
            return result

    def test_healthy_cli_does_not_admit_below_floor_fpm(self):
        result = self.check('PHP 8.2.0 (fpm-fcgi) (built: fixture)')
        self.assertNotEqual(result.returncode, 0, 'Outdated served FPM passed the pre-mutation security check')
        self.assertIn('security floor', result.stdout + result.stderr)

    def test_qualified_fpm_banner_is_checked_and_accepted(self):
        result = self.check('PHP 8.2.1 (fpm-fcgi) (built: fixture)')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.fpm_called, 'Only the matching CLI was checked')

    def test_wrong_abi_prerelease_wrong_sapi_and_failed_probe_refuse(self):
        for banner, status in (
            ('PHP 8.3.99 (fpm-fcgi)', 0),
            ('PHP 8.2.99RC1 (fpm-fcgi)', 0),
            ('PHP 8.2.99 (cli)', 0),
            ('PHP 8.2.99 (fpm-fcgi)', 23),
        ):
            with self.subTest(banner=banner, status=status):
                result = self.check(banner, status=status)
                self.assertNotEqual(result.returncode, 0, 'Unqualified FPM probe passed')

    def test_apache_only_profile_does_not_require_an_unused_fpm(self):
        result = self.check('unusable unused FPM', profile='8.2:apache2', status=23)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(result.fpm_called)


if __name__ == '__main__':
    unittest.main()
