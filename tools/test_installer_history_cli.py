#!/usr/bin/python3
"""Run the recovery argument boundary without installing anything on the host."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TRANSACTION = '/var/lib/sls-mass-notify-installer/transaction-' + 'a' * 24
CHALLENGE = 'b' * 64


class HistoryRecoveryCLI(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sll-history-cli-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        header = (ROOT / 'tools/install_release.sh').read_text().split('\nMODULE="slsmassnotifyserver"', 1)[0]
        self.parser = self.directory / 'parse.sh'
        self.parser.write_text(header + '\nprintf "%s\\n" "$REQUESTED_RECOVERY" "$REQUESTED_HISTORY_EVIDENCE" '
            '"$REQUESTED_HISTORY_REVIEW" "$REQUESTED_HISTORY_LOSS_APPROVAL" '
            '"$REQUESTED_HISTORY_LOSS_OPERATOR" "$REQUESTED_HISTORY_LOSS_REASON"\n')

    def parse(self, arguments):
        return subprocess.run(['/bin/bash', str(self.parser), *arguments],
            capture_output=True, text=True, timeout=5)

    def test_review_option_only_produces_report_mode_and_keeps_spaced_evidence_path(self):
        evidence = '/root/original backup/phone-admission.json'
        for tail in (['--review-history', '--history-evidence', evidence],
                     ['--history-evidence', evidence, '--review-history']):
            with self.subTest(tail=tail):
                result = self.parse(['--recover', TRANSACTION, *tail])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [TRANSACTION, evidence, '1', '', '', ''])

    def test_approval_requires_an_exact_challenge_and_named_administrator_reason(self):
        result = self.parse(['--recover', TRANSACTION, '--approve-history-loss', CHALLENGE,
            '--history-loss-operator', 'PBX administrator', '--history-loss-reason', 'Backups reviewed; accept the recorded loss.'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [TRANSACTION, '', '0', CHALLENGE,
            'PBX administrator', 'Backups reviewed; accept the recorded loss.'])

    def test_ambiguous_or_incomplete_loss_approval_refuses_before_any_host_actions(self):
        cases = [
            ['--review-history', '--approve-history-loss', CHALLENGE],
            ['--approve-history-loss', CHALLENGE],
            ['--approve-history-loss', 'wrong', '--history-loss-operator', 'admin', '--history-loss-reason', 'reviewed'],
            ['--history-loss-operator', 'admin'],
            ['--history-loss-reason', 'reviewed'],
            ['--review-history', '--review-history'],
            ['--history-evidence', '/root/a', '--history-evidence', '/root/b'],
            ['--approve-history-loss', CHALLENGE, '--history-loss-operator', '', '--history-loss-reason', 'reviewed'],
            ['--approve-history-loss', CHALLENGE, '--history-loss-operator', 'admin', '--history-loss-reason', ''],
        ]
        for tail in cases:
            with self.subTest(tail=tail):
                result = self.parse(['--recover', TRANSACTION, *tail])
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        for arguments in (['--review-history'], ['--approve-history-loss', CHALLENGE],
                          ['--recover', TRANSACTION, '--review-history', '--inspect']):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.parse(arguments).returncode, 2)

    @unittest.skipUnless(os.geteuid() == 0, 'root bootstrap parser')
    def test_verified_bootstrap_forwards_review_and_explicit_approval_without_splitting(self):
        source = (ROOT / 'tools/install_bootstrap.sh').read_text().replace(
            '/var/lib/sls-mass-notify-trust', str(self.directory / 'unused-trust'))
        bootstrap = self.directory / 'bootstrap.sh'
        bootstrap.write_text(source)
        marker = self.directory / 'arguments'
        command = r'''
source "$1"
shift
bootstrap_download() {
  printf '#!/bin/bash\nprintf "%%s\\n" "$@" >"%s"\n' "$MARKER" >"$1/install_release.sh"
  chmod 0700 "$1/install_release.sh"
}
bootstrap_verify() { :; }
bootstrap_main 0.1.9-beta "$@"
'''
        options = [
            ['--recover', TRANSACTION, '--review-history', '--history-evidence', '/root/a backup/ledger.json'],
            ['--recover', TRANSACTION, '--approve-history-loss', CHALLENGE,
             '--history-loss-operator', 'PBX administrator', '--history-loss-reason', 'Reviewed unavailable backups.'],
        ]
        for arguments in options:
            with self.subTest(arguments=arguments):
                result = subprocess.run(['/bin/bash', '-c', command, 'fixture', str(bootstrap), *arguments],
                    env={**os.environ, 'MARKER': str(marker)}, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(marker.read_text().splitlines(), arguments)


if __name__ == '__main__':
    unittest.main()
