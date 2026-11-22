#!/usr/bin/env python3
"""Execute repair control flow with recorded operations; no PBX command runs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'slsmassnotifyserver/bin/sls_mass_notify_maintenance.sh').read_text()
REPAIR = SOURCE[SOURCE.index('repair_ok=1\n'):]
PRIVILEGED_HELPER = '/usr/local/bin/sls_mass_notify/sls_privileged_install.py'

class ProtectedMaintenance(unittest.TestCase):
    def stock_integration(self, disposition='due', reconcile_status=0, signer_output='valid'):
        with tempfile.TemporaryDirectory(prefix='sls-stock-automation-') as folder:
            base = Path(folder)
            stock = base/'modules'
            for module in ('framework','dashboard'):
                (stock/module).mkdir(parents=True)
            for relative in ('sections/SlsMassNotifyAnnouncement.class.php', 'views/sections/sls-mass-notify-announcement.php'):
                for source in (base/'sll/dashboard', stock/'dashboard'):
                    target = source/relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text('existing authenticated widget\n')
            (base/'menu').write_text('<?php // stock upstream menu, no SLL insertion\n')
            block = SOURCE[SOURCE.index('# Dashboard and Framework upgrades'):SOURCE.index('claim_request()')]
            block = block.replace('/var/www/html/admin/modules/',str(stock)+'/')
            script = '''set -eu
cd "$1"
exec {LOG_FD}>>log
INTEGRATION_REPAIR_FILE="$1/retry"; MODULE_DIR="$1/sll"; DASHBOARD_DIR="$1/modules/dashboard"; MENU_FILE="$1/menu"
SIGNER=fixture-signer
safe_single_regular_file() { [ -f "$1" ]; }
log() { echo "$*" >>log; }
mark_integration_retry() { touch retry; }
clear_integration_retry() { rm -f retry; }
acquire_mutation_coordination() { return 0; }
release_mutation_coordination() { return 0; }
verify_installed_sls_module() { return 0; }
verify_mutation_idle() { return 0; }
stock_maintenance_control() {
    echo "$1" >>actions
    if [[ "$1" = complete ]]; then
        [[ "$2" = --verified-signatures && "$3" = "$(printf 'a%.0s' {1..64})" && "$4" = "$(printf 'b%.0s' {1..64})" ]]
        return
    fi
    case "$1" in probe) echo "$STOCK_PLAN";; reconcile) return "$RECONCILE_STATUS";; esac
    return 0
}
run_without_maintenance_lock() {
    if [[ "$1" == stock_maintenance_control ]]; then "$@"; return; fi
    if [[ " $* " == *" fixture-signer "* ]]; then
        [[ "${!#}" = --verified-digest ]] || return 1
        local a=("$@"); local module="${a[-2]}"
        echo "signed $module" >>actions
        if [[ "$SIGNER_OUTPUT" != valid ]]; then echo "$SIGNER_OUTPUT"; return; fi
        if [[ "$module" = dashboard ]]; then printf 'a%.0s' {1..64}; else printf 'b%.0s' {1..64}; fi
    else echo "published widgets" >>actions; fi
}
''' + block
            shell = base/'check.sh'; shell.write_text(script)
            result = subprocess.run(['bash',str(shell),str(base)], env={**os.environ, 'STOCK_PLAN':disposition,
                'RECONCILE_STATUS':str(reconcile_status), 'SIGNER_OUTPUT':signer_output}, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            return ((base/'actions').read_text().splitlines() if (base/'actions').exists() else [],
                    (base/'retry').exists())

    def test_stock_change_triggers_signing_with_intact_widgets_and_original_framework_menu(self):
        actions, retry = self.stock_integration()
        self.assertIn('reconcile',actions)
        self.assertLess(actions.index('reconcile'),actions.index('signed framework'))
        self.assertIn('complete',actions)
        self.assertFalse(retry)

    def test_unusable_signer_output_keeps_retry_without_stock_completion(self):
        actions, retry = self.stock_integration(signer_output='unverified status')
        self.assertTrue(retry)
        self.assertIn('failed',actions)
        self.assertNotIn('complete',actions)

    def test_failed_stock_review_never_publishes_widgets_or_signatures_and_does_not_retry_each_minute(self):
        actions, retry = self.stock_integration(reconcile_status=1)
        self.assertNotIn('published widgets',actions)
        self.assertNotIn('signed framework',actions)
        self.assertIn('failed',actions)
        self.assertTrue(retry)
        self.assertEqual(self.stock_integration(disposition='waiting')[0],['probe'])

    def run_repair(self, failure=''):
        with tempfile.TemporaryDirectory(prefix='sls-protected-repair-') as name:
            base=Path(name)
            modules=base/'modules'
            for module in ('slsmassnotifyserver','dashboard','framework'): (modules/module).mkdir(parents=True)
            script='''set -euo pipefail
LOG_FILE="$1/log"
exec {LOG_FD}>>"$LOG_FILE"
PRIVILEGED_HELPER=/usr/local/bin/sls_mass_notify/sls_privileged_install.py
SIGNER=/usr/local/sbin/sign_sls_mass_notify_local_sig.sh
run_without_maintenance_lock() {
  /usr/bin/python3 -I - "$@" <<'RECORD'
import json,os,subprocess,sys
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as output: output.write(json.dumps(args)+'\\n')
failure=os.environ.get('FAILURE')
if failure and any(failure == item or failure in item for item in args): raise SystemExit(29)
if '/usr/sbin/fwconsole' in args:
    # Execute the real env prefix with an inert child in place of fwconsole.
    # This proves the flag reaches the child, without invoking a PBX command.
    boundary=args.index('/usr/sbin/runuser')
    # Keep the real credential scrub; replace only the account transition
    # with an inert child because the fixture must not run PBX commands.
    command=args[:boundary]+args[boundary+4:]
    index=command.index('/usr/sbin/fwconsole')
    command[index:]=[sys.executable, '-c', "import os; print('RELOAD_PENDING=' + os.environ.get('SLS_MASS_NOTIFY_PRESERVE_PENDING', 'missing'))"]
    subprocess.run(command, check=True)
RECORD
}
log() { printf '%s\\n' "$*" >>"$LOG_FILE"; }
# No disk/signature/status operations are performed by these completion stubs.
verify_mutation_idle() { return 0; }
clear_install_failure() { echo cleared >>"$LOG_FILE"; }
write_maintenance_progress() { log "$*"; }
write_install_failure() { log "$*"; }
fail_maintenance() { log "$*"; exit "$3"; }
'''+REPAIR.replace('/var/www/html/admin/modules/',str(modules)+'/')
            path=base/'fixture.sh';path.write_text(script)
            result=subprocess.run(['/bin/bash',str(path),str(base)],env={**os.environ,'CALLS':str(base/'calls'),'FAILURE':failure},capture_output=True,text=True,timeout=5)
            calls=[json.loads(line) for line in (base/'calls').read_text().splitlines()]
            return result,calls,(base/'log').read_text()
    def test_status_writer_refuses_links_and_does_not_change_their_victims(self):
        definitions=SOURCE[:SOURCE.index('[ "${EUID:-$(id -u)}" -eq 0 ] || exit 1')]
        for kind in ('symlink','hardlink','fifo','parent'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='sls-status-safe-') as name:
                base=Path(name); victim=base/'victim';victim.write_text('preserved');victim.chmod(0o600)
                target=base/'status.json'
                if kind=='symlink': target.symlink_to(victim)
                elif kind=='hardlink': os.link(victim,target)
                elif kind=='fifo': os.mkfifo(target)
                else:
                    (base/'redirect').symlink_to(base);target=base/'redirect/status.json'
                script=definitions+'\nwrite_status_json update "$1" complete "safe message" "" "" 0'
                result=subprocess.run(['/bin/bash','-c',script,'_',str(target)],capture_output=True,text=True,timeout=5)
                self.assertNotEqual(result.returncode,0,result.stderr)
                self.assertEqual(victim.read_text(),'preserved')
                self.assertEqual(victim.stat().st_mode & 0o777,0o600)
    def test_status_reader_does_not_block_on_fifo_or_follow_link(self):
        definitions=SOURCE[:SOURCE.index('[ "${EUID:-$(id -u)}" -eq 0 ] || exit 1')]
        for kind in ('fifo','symlink','oversized'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='sls-status-read-') as name:
                base=Path(name);target=base/'status.json'
                if kind=='fifo': os.mkfifo(target)
                elif kind=='symlink':
                    victim=base/'victim';victim.write_text('{"state":"complete"}');target.symlink_to(victim)
                else: target.write_bytes(b' ' * 65537)
                script=definitions+'\nUPDATE_PROGRESS_FILE="$1"; update_progress_is complete'
                result=subprocess.run(['/bin/bash','-c',script,'_',str(target)],capture_output=True,text=True,timeout=5)
                self.assertNotEqual(result.returncode,0,result.stderr)
    def test_success_separates_every_php_and_reload_from_root(self):
        result,calls,log=self.run_repair()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('cleared',log)
        self.assertIn('RELOAD_PENDING=1',log)
        reload_calls=[args for args in calls if '/usr/sbin/fwconsole' in args]
        self.assertEqual(len(reload_calls),1)
        scrub=['/usr/bin/env','-u','GITHUB_TOKEN','-u','GH_TOKEN','-u','SLS_MASS_NOTIFY_GITHUB_TOKEN']
        transition=['/usr/sbin/runuser','-u','asterisk','--']
        bounded=['/usr/bin/timeout','--signal=TERM','--kill-after=10','600']
        self.assertEqual(reload_calls[0],scrub+transition+bounded+['/usr/bin/env','SLS_MASS_NOTIFY_PRESERVE_PENDING=1','/usr/sbin/fwconsole','reload'])
        for args in calls:
            if '/usr/bin/php' in args or '/usr/sbin/fwconsole' in args:
                self.assertEqual(args[:11],scrub+transition)
        root_ops=[args for args in calls if '/usr/bin/python3' in args and PRIVILEGED_HELPER in args]
        self.assertEqual([args[args.index(PRIVILEGED_HELPER)+1] for args in root_ops],
                         ['prepare','dependencies','activate','verify'])
        self.assertFalse(any('chown' in args for args in calls))
        self.assertTrue(any('finalizeVerifiedUnprivilegedRestore' in arg for args in calls for arg in args))

    def test_guard_release_closes_original_coprocess_writer(self):
        definitions=SOURCE[:SOURCE.index('[ "${EUID:-$(id -u)}" -eq 0 ] || exit 1')]
        self.assertIn('read -r -t 125 status', definitions)
        with tempfile.TemporaryDirectory(prefix='sls-guard-release-') as name:
            base=Path(name);runtime=base/'runtime';runtime.mkdir()
            sentinel=base/'released'
            guard_source=(ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_guard.py').read_text()
            release="            if command in (b'', b'release\\n'):\n"
            self.assertEqual(guard_source.count(release),1)
            observed="""            if command == b'release\\n':
                with open(os.environ['GUARD_SENTINEL'],'w',encoding='utf-8') as output: output.write('release\\n')
"""
            (runtime/'sls_install_guard.py').write_text(guard_source.replace(release,observed+release,1))
            (runtime/'sls_install_idle.py').write_text('print("{}")\n')
            script=definitions.replace('/run/sls-maintenance-idle.XXXXXXXX',str(base/'idle.XXXXXXXX'))+'''\n
RUNTIME_DIR="$1/runtime"
CONFIG_FILE="$1/mass-notifications.config"
LOG_FILE="$1/log"
mutation_config_fingerprint() { printf '{}'; }
acquire_mutation_coordination
MUTATION_VERIFIED=1
release_mutation_coordination
test "$(cat "$GUARD_SENTINEL")" = release
'''
            result=subprocess.run(['/bin/bash','-c',script,'_',str(base)],
                                  env={**os.environ,'GUARD_SENTINEL':str(sentinel)},
                                  capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
    def test_every_required_stage_failure_preserves_failure_and_stops_following_stages(self):
        for stage in ('prepare','dependencies','installUnprivilegedPhase','/usr/sbin/fwconsole','activate','sign_sls_mass_notify_local_sig.sh','verify','verifyUnprivilegedIntegration'):
            with self.subTest(stage=stage):
                result,calls,log=self.run_repair(stage)
                self.assertEqual(result.returncode,29,result.stderr)
                self.assertNotIn('cleared',log)
                self.assertNotIn('completed successfully',log)
                last = next(index for index,args in enumerate(calls) if any(stage in item for item in args))
                remaining=calls[last+1:]
                self.assertTrue(not remaining or stage=='sign_sls_mass_notify_local_sig.sh')

if __name__=='__main__': unittest.main()
