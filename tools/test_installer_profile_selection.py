#!/usr/bin/env python3
"""Exercise real installer selection and terminal consent without host mutation."""
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerProfileSelection(unittest.TestCase):
    def run_selection(self, memory=2, option='', answer=None, lite_error=None, existing=False, piped_output=False):
        with tempfile.TemporaryDirectory(prefix='sll-profile-choice-') as temporary:
            folder = Path(temporary)
            standard_ram = memory >= 3.75
            eligibility = {'standard_memory_eligible': standard_ram,
                'lite_memory_eligible': 1.875 <= memory < 3.75}
            for profile in ('standard', 'lite'):
                errors = ([] if standard_ram else [{'code': 'memory_insufficient', 'message': 'Standard requires 4 GiB nominal RAM.'}]) if profile == 'standard' else ([] if memory >= 1.875 else [{'code': 'memory_insufficient', 'message': 'Lite requires 2 GiB nominal RAM.'}])
                if profile == 'lite' and lite_error:
                    errors = [{'code': lite_error, 'message': 'Fixture resource shortage.'}]
                value = {'deployment_profile': profile, 'profile_selection': eligibility,
                    'errors': errors, 'requested_phone_limit': 25,
                    'auto_phone_selection': {'detected_phone_contacts': 2, 'rounded_phone_capacity': 25}}
                (folder / (profile + '.json')).write_text(json.dumps(value))
            if existing:
                (folder / 'config').write_text('{}')
            script = r'''
source "$1" "$2"
CONFIG_FILE="$3/config"
LOG_FILE="$3/install.log"
fixture_root="$3"
bootstrap_resource_capacity() {
  local profile=standard previous="" argument
  for argument in "$@"; do
    if [ "$previous" = --profile ]; then profile="$argument"; fi
    previous="$argument"
  done
  /usr/bin/python3 -I -c 'import json,sys;v=json.load(open(sys.argv[1]));print(json.dumps(v));sys.exit(2 if v["errors"] else 0)' "$fixture_root/$profile.json"
}
select_install_temp_root(){ printf 'filesystem-selection\n' >>"$fixture_root/effects"; }
set +e
preflight_hardware_requirements
result=$?
printf '%s\n%s\n%s\n' "$result" "$REQUESTED_DEPLOYMENT_PROFILE" "$FRESH_DEPLOYMENT_PROFILE" >"$fixture_root/result"
exit "$result"
'''
            args = ['bash', '-c', script, 'fixture', str(ROOT / 'tools/install_release.sh'), option, str(folder)]
            if answer is None:
                process = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
                code, output = process.returncode, process.stdout + process.stderr
            else:
                master, slave = pty.openpty()
                process = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE if piped_output else slave, stderr=slave)
                os.close(slave)
                data = bytearray(); sent = False; deadline = time.monotonic() + 15
                try:
                    while process.poll() is None and time.monotonic() < deadline:
                        ready, _, _ = select.select([master], [], [], .1)
                        if ready:
                            try: chunk = os.read(master, 65536)
                            except OSError: break
                            if not chunk: break
                            data.extend(chunk)
                        if b'[y/N]' in data and not sent:
                            os.write(master, answer.encode() + b'\n'); sent = True
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
                    while select.select([master], [], [], 0)[0]:
                        try: chunk = os.read(master, 65536)
                        except OSError: break
                        if not chunk: break
                        data.extend(chunk)
                finally:
                    os.close(master)
                if piped_output:
                    data.extend(process.stdout.read()); process.stdout.close()
                code, output = process.returncode, data.decode(errors='replace')
            state = (folder / 'result').read_text().splitlines() if (folder / 'result').exists() else []
            return code, output, state, (folder / 'effects').exists()

    def test_low_ram_acceptance_selects_lite_after_showing_hard_limits(self):
        code, output, state, effects = self.run_selection(answer='y')
        self.assertEqual(code, 0, output)
        self.assertEqual(state, ['0', 'lite', 'lite'])
        for term in ('25 desktops', '25 phone contacts', 'Enterprise Labs', '[y/N]'):
            self.assertIn(term, output)
        self.assertTrue(effects)

    def test_decline_eof_and_noninteractive_never_select_lite_implicitly(self):
        for answer in ('n', '', None):
            with self.subTest(answer=answer):
                code, output, state, effects = self.run_selection(answer=answer)
                self.assertNotEqual(code, 0, output)
                self.assertFalse(effects)
                self.assertEqual(state[1:], ['', 'standard'])

    def test_terminal_consent_still_works_when_output_is_piped_to_a_log(self):
        code, output, state, effects = self.run_selection(answer='yes', piped_output=True)
        self.assertEqual(code, 0, output)
        self.assertEqual(state, ['0', 'lite', 'lite'])
        self.assertIn('Enterprise Labs', output)
        self.assertTrue(effects)

    def test_standard_host_rejects_explicit_lite(self):
        code, output, state, effects = self.run_selection(memory=8, option='--lite')
        self.assertNotEqual(code, 0, output)
        self.assertFalse(effects)
        self.assertIn('Standard', output)

    def test_noninteractive_explicit_lite_is_consent_on_eligible_hardware(self):
        code, output, state, effects = self.run_selection(option='--lite')
        self.assertEqual(code, 0, output)
        self.assertIn('Enterprise Labs', output)
        self.assertTrue(effects)

    def test_cpu_storage_or_phone_shortage_cannot_be_bypassed_by_offer(self):
        for error in ('cpu_insufficient', 'storage_insufficient', 'lite_capacity_exceeded'):
            with self.subTest(error=error):
                code, output, state, effects = self.run_selection(lite_error=error)
                self.assertNotEqual(code, 0, output)
                self.assertFalse(effects)
                self.assertNotIn('[y/N]', output)

    def test_insufficient_lite_ram_never_offers_an_install(self):
        code, output, state, effects = self.run_selection(memory=1)
        self.assertNotEqual(code, 0, output)
        self.assertFalse(effects)
        self.assertNotIn('[y/N]', output)

    def test_nominal_four_gib_host_remains_standard(self):
        code, output, state, effects = self.run_selection(memory=3.8)
        self.assertEqual(code, 0, output)
        self.assertEqual(state, ['0', '', 'standard'])
        self.assertNotIn('[y/N]', output)

    def test_explicit_standard_never_downgrades_without_request(self):
        code, output, state, effects = self.run_selection(option='--standard')
        self.assertNotEqual(code, 0, output)
        self.assertFalse(effects)
        self.assertNotIn('[y/N]', output)


if __name__ == '__main__':
    unittest.main()
