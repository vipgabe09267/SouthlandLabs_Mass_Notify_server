#!/usr/bin/python3
"""Installer inspection and path-boundary regressions in disposable namespaces."""
import json
import os
import pwd
import re
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered' or any(
    os.environ.get('SLS_TEST_PARENT_' + label + '_NS') in
    (None, '', os.readlink('/proc/self/ns/' + kind))
    for label, kind in [('MOUNT', 'mnt'), ('NET', 'net'), ('PID', 'pid')]
):
    raise SystemExit('Use the private fixture runner; no spool or permission changes were made.')

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT/'tools/install_release.sh').read_text()


class Preparation(unittest.TestCase):
    def test_resource_relationship_proof_requires_authenticated_known_native_absence(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name)
            helper = root/'stage/slsmassnotifyserver/bin/sls_mass_notify/sls_resource_capacity.py'
            helper.parent.mkdir(parents=True)
            helper.write_text('''from pathlib import Path
def capture_fresh_release_proof(review,candidate_source,native_state):
 Path(review,'capture-called').write_text(native_state)
 return {'schema':1,'native_state':native_state,'candidate':str(candidate_source)}
''')
            harness = r'''source "$1"
fixture="$2"; AUTHENTICATED_INSTALLER_APPROVED="$3"
INITIAL_NATIVE_MODULE_REGISTRY_STATE="$4"
STAGING_DIR="$fixture/stage"; UPGRADE_TRUST_DIR="$fixture/review-$3-$4"
mkdir -m 700 "$UPGRADE_TRUST_DIR"
capture_install_resource_proof
printf '%s\n' "$UPGRADE_TRUST_DIR"
'''
            for approved, native, expected in [('0','known_absent',False), ('1','unknown',False),
                                                ('1','established',False), ('1','known_absent',True)]:
                with self.subTest(approved=approved,native=native):
                    proc=subprocess.run(['/bin/bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),
                        str(root),approved,native],capture_output=True,text=True,timeout=10)
                    self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
                    review=root/('review-'+approved+'-'+native)
                    proof=review/'resource-relationship-proof.json'
                    self.assertEqual((review/'capture-called').exists(),expected)
                    self.assertEqual(proof.exists(),expected)
                    if expected:
                        self.assertEqual(json.loads(proof.read_text())['native_state'],'known_absent')
                        self.assertEqual(stat.S_IMODE(proof.stat().st_mode),0o600)

    def test_real_enabled_and_disabled_staging_enum_reaches_upgrade_capacity_capture(self):
        import io,tarfile
        for state in('enabled','disabled'):
            with self.subTest(state=state),tempfile.TemporaryDirectory(dir='/run')as name:
                root=Path(name);(root/'config').write_text('preserved fixture configuration')
                helper=b"from pathlib import Path\ndef capture_prepared_upgrade_storage_proof(review,candidate_source,native_state):\n Path(review,'capture-called').write_text(native_state)\n return {'schema':3,'kind':'sll-prepared-upgrade-storage-proof-v3','native_state':native_state}\n"
                archive=root/'candidate.tgz'
                with tarfile.open(archive,'w:gz')as tar:
                    for relative,body in(('module.xml',b'<module/>'),('bin/sls_mass_notify/sls_resource_capacity.py',helper)):
                        entry=tarfile.TarInfo('slsmassnotifyserver/'+relative);entry.size=len(body);entry.mode=0o600;tar.addfile(entry,io.BytesIO(body))
                (root/'review').mkdir(mode=0o700)
                harness=r'''source "$1"
fixture="$2"; MODULE=slsmassnotifyserver; INSTALL_TEMP_ROOT="$fixture"; TGZ="$fixture/candidate.tgz"
CONFIG_FILE="$fixture/config"; UPGRADE_TRUST_DIR="$fixture/review"
lint_staged_module_php(){ return 0; }
log(){ :; }
NATIVE_FIXTURE_STATE="$3"
module_registry_state(){ printf '%s\t0.2.0-beta\n' "$NATIVE_FIXTURE_STATE"; }
stage_module_directory
[ "$INITIAL_NATIVE_MODULE_REGISTRY_STATE" = established ]
AUTHENTICATED_INSTALLER_APPROVED=1
capture_install_resource_proof
'''
                result=subprocess.run(['/bin/bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),str(root),state],capture_output=True,text=True,timeout=20)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                capsule=root/'review/resource-relationship-proof.json'
                self.assertTrue(capsule.is_file(),'Actual module staging state must reach the prepared-upgrade producer')
                self.assertEqual(json.loads(capsule.read_bytes())['native_state'],'established')

    def test_only_dependency_phase_receives_the_explicit_installer_resource_profile(self):
        with tempfile.TemporaryDirectory() as name:
            bootstrap = Path(name) / 'protected-helper'
            bootstrap.touch()
            for phase, profile in [('dependencies','lite'),('dependencies','standard'),
                                   ('dependencies',''),('activate','lite')]:
                with self.subTest(phase=phase,profile=profile):
                    script = r'''source "$1"
PRIVILEGED_INSTALL_BOOTSTRAP="$2"; REQUESTED_DEPLOYMENT_PROFILE="$4"
WORKER_COORDINATION_REQUIRED=0
run_logged(){ printf '%s\n' "$@"; }
protected_install_phase "$3" --apply
'''
                    result = subprocess.run(['/bin/bash','-c',script,'fixture',str(ROOT/'tools/install_release.sh'),
                        str(bootstrap),phase,profile],capture_output=True,text=True,timeout=8)
                    self.assertEqual(result.returncode,0,result.stderr)
                    arguments = result.stdout.splitlines()
                    if phase == 'dependencies' and profile:
                        self.assertEqual(arguments[arguments.index('--resource-profile')+1],profile)
                    else:
                        self.assertNotIn('--resource-profile',arguments)

    def test_resource_relationship_is_captured_before_new_transaction_and_passed_only_to_late_gate(self):
        main=SOURCE.split('main() {',1)[1].split('\nif [[',1)[0]
        self.assertLess(main.index('prepare_authenticated_installer'),main.index('capture_install_resource_proof'))
        self.assertLess(main.index('capture_install_resource_proof'),main.index('begin_install_transaction'))
        early=SOURCE.split('preflight_hardware_requirements() {',1)[1].split('\nselect_install_temp_root()',1)[0]
        self.assertNotIn('--prepared-release-review',early)
        late=SOURCE.split('verify_staged_hardware_requirements() {',1)[1].split('\npreflight_platform()',1)[0]
        self.assertIn('--prepared-release-review "$UPGRADE_TRUST_DIR"',late)

    def test_capacity_only_proof_survives_normal_prepared_transaction_cross_filesystem_move(self):
        self.check_prepared_capacity_transaction(retained=True)

    def test_cold_normal_prepared_transaction_uses_remaining_allocation_proof(self):
        self.check_prepared_capacity_transaction(retained=False)

    def test_known_present_upgrade_transaction_uses_complete_remaining_growth_roles(self):
        self.check_prepared_capacity_transaction(retained=False, upgrade=True)

    def check_prepared_capacity_transaction(self, retained, upgrade=False):
        import importlib.util
        spec=importlib.util.spec_from_file_location('prepared_capacity_fixture_tests',ROOT/'tools/test_resource_capacity.py')
        fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
        case=(fixtures.PreparedUpgradeRemainingGrowthTests() if upgrade else fixtures.PreparedInstallStorageProofTests());case.setUp();self.addCleanup(case.doCleanups)
        with tempfile.TemporaryDirectory(dir='/tmp') as name, tempfile.TemporaryDirectory(dir='/run') as transient:
            root=Path(name)/'root'
            review,candidate,put,release=case.upgrade_fixture(root) if upgrade else case.relationship_fixture(root,retained=retained)
            transient=Path(transient);self.assertNotEqual(root.stat().st_dev,transient.stat().st_dev)
            # Exercise the real publisher-protected helpers and GNU mv. Only the
            # fixture observation prefix redirects paths away from the host.
            runtime=ROOT/'slsmassnotifyserver/bin/sls_mass_notify'
            helper_names=('sls_module_trust.py','sls_release_trust.py','sls_privileged_install.py',
                'sls_installer_recovery.py','sls_install_transaction.py','sls_install_idle.py',
                'sls_install_guard.py','sls_audio_state.py','sls_config_crypto.py','sls_upgrade_trust.py',
                'sls_legacy_permissions.py','freepbx-mirror-signing.pub','sls_resource_capacity.py')
            for helper in helper_names:put(candidate/'bin/sls_mass_notify'/helper,(runtime/helper).read_bytes())
            source=SOURCE
            for function in ('capture_fresh_release_proof','capture_install_storage_proof','capture_prepared_upgrade_storage_proof'):
                old='proof = module.'+function+'(review, candidate, sys.argv[4])'
                source=source.replace(old,old[:-1]+', prefix=Path('+repr(str(root))+'))')
            installer=root/'installer.sh';put(installer,source.encode(),0o700)
            release['installer']=source.encode();case.rebuild_registry(review,candidate,put,release)
            put(root/'download/release-manifest.json',release['manifest'])
            put(root/'download/release-manifest.sig',release['sig']);put(root/'package.tgz',release['package'])
            originals={name:(root/name.lstrip('/')).read_bytes()for name in (
                case.DATA+'/mass-notifications.config','/etc/sls-mass-notify/config-keys.json')
                if (root/name.lstrip('/')).exists()}
            review_source=transient/'review';shutil.move(str(review),str(review_source))
            harness=r'''
source "$1"
fixture="$2"; transient="$3"; STAGING_DIR="$4"
AUTHENTICATED_INSTALLER_APPROVED=1; INITIAL_NATIVE_MODULE_REGISTRY_STATE=known_absent
INSTALL_TEMP_ROOT="$transient"; UPGRADE_TRUST_DIR="$transient/review"
INSTALL_TRANSACTION_ROOT="$fixture/var/lib/sls-mass-notify-installer"
DOWNLOAD_DIR="$fixture/download"; TGZ="$fixture/package.tgz"; LOG_FILE="$fixture/log"
INSTALL_STAGE='publisher and stock approval'
prepare_installer_bootstrap
capture_install_resource_proof
[ -f "$UPGRADE_TRUST_DIR/resource-relationship-proof.json" ]
begin_install_transaction
printf 'CURRENT_REVIEW=%s\n' "$UPGRADE_TRUST_DIR"
'''
            if upgrade:
                harness=harness.replace('INITIAL_NATIVE_MODULE_REGISTRY_STATE=known_absent',
                    'INITIAL_NATIVE_MODULE_REGISTRY_STATE=established; HAD_EXISTING_MODULE=1')
            proc=subprocess.run(['/bin/bash','-c',harness,'fixture',str(installer),str(root),
                str(transient),str(candidate.parent)],capture_output=True,text=True,timeout=30)
            self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
            moved=Path(next(line.split('=',1)[1]for line in proc.stdout.splitlines()if line.startswith('CURRENT_REVIEW=')))
            self.assertFalse(review_source.exists());self.assertEqual(moved.parent.parent,root/case.JOURNAL.lstrip('/'))
            reader=fixtures.RESOURCE.read_prepared_upgrade_storage_proof if upgrade else fixtures.RESOURCE.read_install_storage_proof
            proof=reader(moved,candidate,prefix=root)
            self.assertIsInstance(proof,dict,'Actual producer→begin move must yield a verified capacity-only proof')
            self.assertEqual(proof['kind'],'sll-prepared-upgrade-storage-proof-v3' if upgrade else 'sll-prepared-release-storage-proof-v2')
            for name,body in originals.items():self.assertEqual((root/name.lstrip('/')).read_bytes(),body)
            changed=moved.parent/'bootstrap/sls_install_guard.py';changed.write_bytes(b'changed published helper')
            self.assertIsNone(reader(moved,candidate,prefix=root))

    def test_resource_proof_survives_actual_transaction_move_between_filesystems(self):
        import hashlib
        import importlib.util
        spec=importlib.util.spec_from_file_location('fresh_resource_fixture_tests',ROOT/'tools/test_resource_capacity.py')
        fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
        case=fixtures.FreshReleaseStorageProofTests();case.setUp();self.addCleanup(case.doCleanups)
        with tempfile.TemporaryDirectory(dir='/tmp') as name, tempfile.TemporaryDirectory(dir='/run') as transient:
            root=Path(name)/'root';review,candidate,put=case.fixture(root,after_abandon=True)
            transient=Path(transient)
            self.assertNotEqual(root.stat().st_dev,transient.stat().st_dev,
                                'Isolated /run scratch must exercise the filesystem-copy path')
            # The fixture prefix redirects read-only establishment observations;
            # the producer, proof serialization, GNU mv and journal writer run.
            helper=(ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_resource_capacity.py').read_bytes()
            put(candidate/'bin/sls_mass_notify/sls_resource_capacity.py',helper,0o700)
            reference=json.loads((review/'registry/slsmassnotifyserver.active.json').read_text())
            generation=review/'registry'/reference['generation']
            inventory=json.loads((generation/'inventory.json').read_text())
            item='bin/sls_mass_notify/sls_resource_capacity.py'
            inventory['files'][item]={'sha256':hashlib.sha256(helper).hexdigest(),
                                     'target':'admin/modules/slsmassnotifyserver/'+item}
            encoded=(json.dumps(inventory,sort_keys=True)+'\n').encode()
            digest=hashlib.sha256(encoded).hexdigest();new=generation.with_name('slsmassnotifyserver-'+digest)
            generation.rename(new);put(new/'inventory.json',encoded)
            put(review/'registry/slsmassnotifyserver.active.json',{'generation':new.name,'sha256':digest})
            moved_source=transient/'review';shutil.move(str(review),str(moved_source));review=moved_source
            bootstrap=transient/'bootstrap';put(bootstrap/'sls_install_transaction.py',
                (ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_transaction.py').read_bytes(),0o700)
            put(root/'download/release-manifest.json',b'fixture-manifest')
            put(root/'download/release-manifest.sig',b'x'*64);put(root/'package.tgz',b'fixture-package')
            source=SOURCE.replace('proof = module.capture_fresh_release_proof(review, candidate, sys.argv[4])',
                'proof = module.capture_fresh_release_proof(review, candidate, sys.argv[4], prefix=Path('+repr(str(root))+'))')
            put(root/'installer.sh',source.encode(),0o700)
            harness=r'''source "$1"
fixture="$2"; transient="$3"; STAGING_DIR="$4"
AUTHENTICATED_INSTALLER_APPROVED=1; INITIAL_NATIVE_MODULE_REGISTRY_STATE=known_absent
UPGRADE_TRUST_DIR="$transient/review"; INSTALL_BOOTSTRAP_DIR="$transient/bootstrap"
INSTALL_TRANSACTION_ROOT="$fixture/var/lib/sls-mass-notify-installer"
DOWNLOAD_DIR="$fixture/download"; TGZ="$fixture/package.tgz"
INSTALL_STAGE='publisher and stock approval'; LOG_FILE="$fixture/log"
capture_install_resource_proof
[ -f "$UPGRADE_TRUST_DIR/resource-relationship-proof.json" ]
begin_install_transaction
printf 'CURRENT_REVIEW=%s\n' "$UPGRADE_TRUST_DIR"
'''
            proc=subprocess.run(['/bin/bash','-c',harness,'fixture',str(root/'installer.sh'),str(root),
                str(transient),str(candidate.parent)],capture_output=True,text=True,timeout=20)
            self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
            row=next(line for line in proc.stdout.splitlines()if line.startswith('CURRENT_REVIEW='))
            moved=Path(row.split('=',1)[1]);self.assertFalse(review.exists())
            self.assertEqual(moved.parent.parent,root/'var/lib/sls-mass-notify-installer')
            self.assertIsInstance(fixtures.RESOURCE.read_fresh_release_proof(moved,candidate,prefix=root),dict)
            changed=moved/'previous-root-approval.json';put(changed,{'schema':1,'source':'unknown','files':{},'root_jobs':[]})
            self.assertIsNone(fixtures.RESOURCE.read_fresh_release_proof(moved,candidate,prefix=root))

    def test_inspection_never_runs_repairs_locks_freepbx_or_failure_writes(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name)
            (root/'freepbx.conf').write_text('inspection sentinel')
            (root/'framework').mkdir(); (root/'framework/module.xml').write_text('<module/>')
            installer = root/'installer.sh'
            installer.write_text(SOURCE.replace('/etc/freepbx.conf', str(root/'freepbx.conf'))
                .replace('/var/www/html/admin/modules/framework', str(root/'framework')))
            harness = r'''
source "$1"
fixture="$2"; CONFIG_FILE="$fixture/config"; SLS_MASS_NOTIFY_INVENTORY_ONLY=1
bootstrap_resource_capacity() { printf '{"requirements":{},"deployment_profile":"standard","profile_selection":{"standard_memory_eligible":true,"lite_memory_eligible":false}}'; }
select_install_temp_root() { INSTALL_TEMP_ROOT="$fixture"; }
download_tgz() { DOWNLOAD_DIR="$fixture/download"; mkdir "$DOWNLOAD_DIR"; printf 'download\n' >>"$fixture/trace"; }
verify_tgz() { printf 'verified\n' >>"$fixture/trace"; }
stage_module_directory() { STAGING_DIR="$fixture/stage"; mkdir "$STAGING_DIR"; printf 'staged\n' >>"$fixture/trace"; }
prepare_installer_bootstrap() { INSTALL_BOOTSTRAP_DIR="$fixture/bootstrap"; mkdir "$INSTALL_BOOTSTRAP_DIR"; printf 'bootstrap\n' >>"$fixture/trace"; }
prepare_authenticated_installer() { printf 'approved\n' >>"$fixture/trace"; UPGRADE_TRUST_DIR="$fixture/evidence"; mkdir "$UPGRADE_TRUST_DIR"; }
for forbidden in ensure_installer_log_prerequisites acquire_update_coordination acquire_maintenance_coordination require_freepbx fwconsole install_dependencies initialize_configuration_keyring acquire_worker_coordination acquire_settings_coordination record_install_failure commit_authenticated_installer protect_freepbx_chown_permissions repair_authenticated_legacy_permissions restore_previous_phone_collector; do
 eval "$forbidden() { printf 'forbidden' >\"\$fixture/forbidden\"; return 99; }"
done
main
'''
            result = subprocess.run(['bash','-c',harness,'fixture',str(installer),str(root)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse((root/'forbidden').exists())
            self.assertEqual((root/'trace').read_text().splitlines(), ['download','verified','staged','bootstrap','approved'])
            self.assertEqual((root/'freepbx.conf').read_text(), 'inspection sentinel')
            self.assertTrue((root/'evidence').is_dir())
            self.assertFalse((root/'download').exists())
            self.assertFalse((root/'stage').exists())
            self.assertFalse((root/'bootstrap').exists())

    def test_failed_inspection_removes_transient_release_workspaces(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root = Path(name)
            (root/'freepbx.conf').write_text('inspection sentinel')
            (root/'framework').mkdir(); (root/'framework/module.xml').write_text('<module/>')
            installer = root/'installer.sh'
            installer.write_text(SOURCE.replace('/etc/freepbx.conf', str(root/'freepbx.conf'))
                .replace('/var/www/html/admin/modules/framework', str(root/'framework')))
            harness = r'''
source "$1"
fixture="$2"; CONFIG_FILE="$fixture/config"; SLS_MASS_NOTIFY_INVENTORY_ONLY=1
bootstrap_resource_capacity() { printf '{"requirements":{},"deployment_profile":"standard","profile_selection":{"standard_memory_eligible":true,"lite_memory_eligible":false}}'; }
select_install_temp_root() { INSTALL_TEMP_ROOT="$fixture"; }
download_tgz() { DOWNLOAD_DIR="$fixture/download"; mkdir "$DOWNLOAD_DIR"; }
verify_tgz() { :; }
stage_module_directory() { STAGING_DIR="$fixture/stage"; mkdir "$STAGING_DIR"; }
prepare_installer_bootstrap() { INSTALL_BOOTSTRAP_DIR="$fixture/bootstrap"; mkdir "$INSTALL_BOOTSTRAP_DIR"; }
prepare_authenticated_installer() { UPGRADE_TRUST_DIR="$fixture/evidence"; mkdir "$UPGRADE_TRUST_DIR"; return 23; }
main
'''
            result = subprocess.run(['bash','-c',harness,'fixture',str(installer),str(root)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
            self.assertTrue((root/'evidence').is_dir())
            self.assertFalse((root/'download').exists())
            self.assertFalse((root/'stage').exists())
            self.assertFalse((root/'bootstrap').exists())

    def test_optional_repairs_follow_approval_and_recovery(self):
        main = SOURCE.split('main() {',1)[1].split('\nif [[',1)[0]
        self.assertLess(main.index('preflight_platform check'),main.index('install_dependencies'))
        self.assertLess(main.index('prepare_authenticated_installer'),main.index('commit_authenticated_installer'))
        self.assertLess(main.index('commit_authenticated_installer'),main.index('install_dependencies'))
        bootstrap = re.search(r'^prepare_installer_bootstrap\(\) \{.*?(?=^[a-z_]+\(\) \{)', SOURCE, re.M | re.S).group(0)
        self.assertNotIn('initialize_configuration_keyring',bootstrap)

    def test_preparation_failures_report_the_actual_stage(self):
        cases=[('prepare_authenticated_installer','publisher and stock approval','install_command_failed'),
               ('repair_authenticated_legacy_permissions','legacy configuration and runtime permissions','legacy_permission_recovery_failed'),
               ('restore_previous_phone_collector','previous phone collector recovery','previous_collector_recovery_failed'),
               ('acquire_worker_coordination','notification worker coordination','worker_coordination_failed'),
               ('acquire_settings_coordination','configuration coordination','protected_config_validation_failed')]
        for operation,stage,category in cases:
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as name:
                root=Path(name)
                harness=r'''
source "$1"
fixture="$2"; failure="$3"
while read -r unused unused function; do
  case "$function" in main|set_install_stage) continue;; esac
  eval "$function() { :; }"
done < <(declare -F)
LOG_FILE="$fixture/log"
open_root_owned_file() { exec {INSTALL_LOG_FD}>>"$LOG_FILE"; }
guard_config_on_exit() {
  printf '%s\n%s\n%s\n' "$INSTALL_STAGE" "$INSTALL_ERROR_CATEGORY" "$INSTALL_EXIT_CODE" >"$fixture/failure"
}
eval "$failure() { return 17; }"
main
'''
                result=subprocess.run(['bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),str(root),operation],
                                      capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,17,result.stdout+result.stderr)
                lines=(root/'failure').read_text().splitlines()
                self.assertEqual(lines[:2],[stage,category])

    def php_profile(self, root, handler, user='asterisk', extra_pool='', custom_include=False,
                    listen='/run/php/php8.2-fpm.sock', extra_pools=None, binary_version='8.2', warning='', pool_mode=0o644,
                    apache_owner='root',pool_owner='root'):
        if 'LoadModule php_module ' in handler and not re.search(r'^\s*Group\s+',handler,re.M):
            handler += '\nGroup asterisk\n'
        apache=root/'apache';apache.mkdir(exist_ok=True)
        config=apache/'apache.conf';config.write_text(handler)
        owner=pwd.getpwnam(apache_owner);os.chown(apache,owner.pw_uid,owner.pw_gid);os.chown(config,owner.pw_uid,owner.pw_gid)
        (root/'mods-enabled').mkdir(exist_ok=True)
        (root/'envvars').write_text('export APACHE_RUN_USER='+user+'\n')
        php=root/'php/8.2/fpm';(php/'pool.d').mkdir(parents=True,exist_ok=True)
        (php/'php-fpm.conf').write_text('include = '+str(php/('other/*.conf' if custom_include else 'pool.d/*.conf'))+'\n')
        pool=php/'pool.d/asterisk.conf'
        pool.write_text('[asterisk]\nuser = '+user+'\nlisten = '+listen+'\n'+extra_pool);pool.chmod(pool_mode)
        owner=pwd.getpwnam(pool_owner);os.chown(pool,owner.pw_uid,owner.pw_gid)
        for name,body in (extra_pools or {}).items():
            (php/'pool.d'/name).write_text(body)
        binaries=root/'binaries';binaries.mkdir(exist_ok=True)
        binary=binaries/'php-fpm8.2'
        binary.write_text('#!/bin/sh\nprintf \'PHP '+binary_version+'.33 (fpm-fcgi)\\n\'\n');binary.chmod(0o755)
        code=SOURCE.split("<<'PYPHPHANDLER'\n",1)[1].split('\nPYPHPHANDLER',1)[0]
        # Model the active native directive tree, not an include filename. Real
        # Apache conditional/vhost behavior is covered by route-profile tests.
        dump='Included configuration files:\n  (*) '+str(config)+'\n# In file: '+str(config)+'\n'+handler
        if 'LoadModule php_module ' in handler: dump += '\n php_module (shared)\n'
        code=re.sub(r'^result = subprocess.run\(.*$',lambda unused:"result = type('Result', (), {'returncode':0,'stdout':"+repr(dump) + ",'stderr':"+repr(warning)+"})()",code,flags=re.M)
        code=code.replace('/etc/apache2/mods-enabled',str(root/'mods-enabled')).replace('/etc/apache2/envvars',str(root/'envvars')).replace("Path('/etc/php')","Path("+repr(str(root/'php'))+")")
        code=code.replace("Path('/usr/sbin')","Path("+repr(str(binaries))+")")
        return subprocess.run(['python3','-I','-c',code],capture_output=True,text=True,timeout=5)

    def test_mod_php_user_is_checked_without_changing_apache(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name);handler='LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so\nUser ${APACHE_RUN_USER}\n'
            result=self.php_profile(root,handler);self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),'8.2:apache2')
            for user in ['root','www-data','nonexistent_fixture_user']:
                result=self.php_profile(root,handler,user);self.assertNotEqual(result.returncode,0)
                self.assertIn('must run as the asterisk',result.stderr)
                self.assertEqual((root/'envvars').read_text(),'export APACHE_RUN_USER='+user+'\n')

    def test_fpm_served_pool_identity_and_disabled_functions_are_checked(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name);handler='SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n'
            result=self.php_profile(root,handler);self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.strip(),'8.2:fpm')
            result=self.php_profile(root,handler,'root');self.assertNotEqual(result.returncode,0);self.assertIn('must run as asterisk',result.stderr)
            result=self.php_profile(root,handler,extra_pool='php_admin_value[disable_functions] = exec,proc_open\n')
            self.assertNotEqual(result.returncode,0);self.assertIn('disables required functions: exec, proc_open',result.stderr)
            result=self.php_profile(root,handler,custom_include=True);self.assertNotEqual(result.returncode,0);self.assertIn('custom pool include layout',result.stderr)
            self.assertFalse((root/'trace').exists())

    def test_named_fpm_sockets_are_bound_to_the_actual_pool_and_binary_abi(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name)
            for listen in ('/run/php/php8.2-fpm-sls-desktop.sock','/run/php/desktop-notifications.sock'):
                handler='SetHandler "proxy:unix:'+listen+'|fcgi://localhost"\n'
                result=self.php_profile(root,handler,listen=listen)
                self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),'8.2:fpm')
                result=self.php_profile(root,handler,listen=listen,binary_version='8.3')
                self.assertNotEqual(result.returncode,0);self.assertIn('binary ABI disagree',result.stderr)
            result=self.php_profile(root,'SetHandler "proxy:unix:/var/run/php/php8.2-fpm-sls-desktop.sock|fcgi://localhost"\n',listen='/run/php/php8.2-fpm-sls-desktop.sock')
            self.assertEqual(result.returncode,0,result.stderr)
            listen='/run/php/php8.3-fpm-named.sock'
            result=self.php_profile(root,'SetHandler "proxy:unix:'+listen+'|fcgi://localhost"\n',listen=listen)
            self.assertNotEqual(result.returncode,0);self.assertIn('socket name and configured pool ABI disagree',result.stderr)

    def test_unrelated_coexisting_pool_is_allowed_but_duplicate_socket_is_not(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name);listen='/run/php/php8.2-fpm-sls-desktop.sock'
            handler='SetHandler "proxy:unix:'+listen+'|fcgi://localhost"\n'
            extra={'other.conf':'[unrelated]\nuser=www-data\nlisten=/run/php/php8.2-fpm-other.sock\nphp_admin_value[disable_functions]=exec,proc_open\n'}
            result=self.php_profile(root,handler,listen=listen,extra_pools=extra)
            self.assertEqual(result.returncode,0,result.stderr)
            extra['other.conf']='[duplicate]\nuser=asterisk\nlisten='+listen+'\n'
            result=self.php_profile(root,handler,listen=listen,extra_pools=extra)
            self.assertNotEqual(result.returncode,0);self.assertIn('exactly one configured local pool',result.stderr)

    def test_cross_version_socket_collision_is_rejected(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name);listen='/run/php/desktop-notifications.sock'
            php=root/'php/8.3/fpm';(php/'pool.d').mkdir(parents=True)
            (php/'php-fpm.conf').write_text('include='+str(php/'pool.d/*.conf')+'\n')
            (php/'pool.d/collision.conf').write_text('[collision]\nuser=asterisk\nlisten='+listen+'\n')
            result=self.php_profile(root,'SetHandler "proxy:unix:'+listen+'|fcgi://localhost"\n',listen=listen)
            self.assertNotEqual(result.returncode,0);self.assertIn('exactly one configured local pool',result.stderr)

    def test_remote_directive_cannot_hide_beside_a_valid_local_handler(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name);local='SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n'
            for remote in ('SetHandler "proxy:fcgi://192.0.2.1:9000"\n','ProxyPassMatch ^/(.*) fcgi://backend.example.test:9000/var/www/\n'):
                result=self.php_profile(root,local+remote)
                self.assertNotEqual(result.returncode,0);self.assertIn('remote FastCGI handler',result.stderr)
            result=self.php_profile(root,local,warning='AH00112: Warning: DocumentRoot [/invalid/folder/name] does not exist\n')
            self.assertEqual(result.returncode,0,result.stderr)

    def test_pool_permission_and_named_pool_function_failures_stay_fail_closed(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name);listen='/run/php/php8.2-fpm-sls-desktop.sock'
            handler='SetHandler "proxy:unix:'+listen+'|fcgi://localhost"\n'
            result=self.php_profile(root,handler,listen=listen,pool_mode=0o666)
            self.assertNotEqual(result.returncode,0);self.assertIn('writable parent or source',result.stderr)
            result=self.php_profile(root,handler,listen=listen,extra_pool='php_admin_value[disable_functions]=sodium_crypto_pwhash_str\n')
            self.assertNotEqual(result.returncode,0);self.assertIn('sodium_crypto_pwhash_str',result.stderr)

    def test_freepbx_managed_apache_ownership_does_not_weaken_pool_authority(self):
        with tempfile.TemporaryDirectory(dir='/run') as name:
            root=Path(name);handler='SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n'
            result=self.php_profile(root,handler,apache_owner='asterisk')
            self.assertEqual(result.returncode,0,result.stderr)
            result=self.php_profile(root,handler,apache_owner='www-data')
            self.assertNotEqual(result.returncode,0);self.assertIn('unexpected owner',result.stderr)
            result=self.php_profile(root,handler,apache_owner='asterisk',pool_owner='asterisk')
            self.assertNotEqual(result.returncode,0);self.assertIn('unexpected owner',result.stderr)

    def test_spool_symlink_is_rejected_before_chown(self):
        if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
            self.fail('Spool fixture requires the isolation wrapper')
        spool = Path('/var/spool/asterisk')
        with tempfile.TemporaryDirectory(dir='/run') as name:
            sentinel = Path(name)/'sentinel'; sentinel.mkdir(mode=0o700)
            for child in ('tmp','outgoing','outgoing_done'):
                path = spool/child
                if path.is_dir(): shutil.rmtree(path)
                elif path.is_symlink(): path.unlink()
            (spool/'tmp').mkdir(mode=0o700)
            (spool/'outgoing').symlink_to(sentinel)
            before = sentinel.stat()
            result = subprocess.run(['bash','-c','source "$1"; secure_asterisk_spool','fixture',str(ROOT/'tools/install_release.sh')],capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual((sentinel.stat().st_uid,sentinel.stat().st_mode),(before.st_uid,before.st_mode))
            self.assertEqual((spool/'tmp').stat().st_uid,0)
            (spool/'outgoing').unlink()

    def test_spool_unknown_metadata_is_preserved_without_partial_repair(self):
        self.assertEqual(os.environ.get('SLS_TEST_NAMESPACE'), 'entered')
        spool = Path('/var/spool/asterisk')
        for unsafe in ('foreign_group', 'world_writable'):
            with self.subTest(unsafe=unsafe):
                for child in ('tmp', 'outgoing', 'outgoing_done'):
                    path = spool/child
                    if path.is_symlink(): path.unlink()
                    elif path.exists(): shutil.rmtree(path)
                    path.mkdir(mode=0o700)
                suspect = spool/'outgoing_done'
                if unsafe == 'foreign_group': os.chown(suspect, 0, 65000)
                else: suspect.chmod(0o777)
                before = {child: (spool/child).stat() for child in ('tmp', 'outgoing', 'outgoing_done')}
                result = subprocess.run(['bash', '-c', 'source "$1"; secure_asterisk_spool', 'fixture', str(ROOT/'tools/install_release.sh')], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                for child, old in before.items():
                    current = (spool/child).stat()
                    self.assertEqual((current.st_ino, current.st_uid, current.st_gid, current.st_mode), (old.st_ino, old.st_uid, old.st_gid, old.st_mode))
        shutil.rmtree(spool/'tmp')
        (spool/'outgoing_done').chmod(0o777)
        result = subprocess.run(['bash', '-c', 'source "$1"; secure_asterisk_spool', 'fixture', str(ROOT/'tools/install_release.sh')], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertFalse((spool/'tmp').exists(), 'Unsafe existing spool metadata caused another directory to be created')

    def test_spool_recognized_layout_preserves_directory_inodes(self):
        self.assertEqual(os.environ.get('SLS_TEST_NAMESPACE'), 'entered')
        spool = Path('/var/spool/asterisk'); account = pwd.getpwnam('asterisk')
        for child in ('tmp', 'outgoing', 'outgoing_done'):
            path = spool/child
            if path.is_symlink(): path.unlink()
            elif path.exists(): shutil.rmtree(path)
            path.mkdir(mode=0o755); os.chown(path, 0, 0)
        before = {child: (spool/child).stat().st_ino for child in ('tmp', 'outgoing', 'outgoing_done')}
        result = subprocess.run(['bash', '-c', 'source "$1"; secure_asterisk_spool', 'fixture', str(ROOT/'tools/install_release.sh')], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        for child, mode in (('tmp', 0o775), ('outgoing', 0o775), ('outgoing_done', 0o750)):
            current = (spool/child).stat()
            self.assertEqual((current.st_ino, current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode)), (before[child], account.pw_uid, account.pw_gid, mode))


class CorrectedRecoveryCarrierCapacity(unittest.TestCase):
    """New signed recovery inputs need their own admission, not old free-space claims."""
    BOOTSTRAP = ('sls_module_trust.py','sls_release_trust.py','sls_privileged_install.py',
        'sls_installer_recovery.py','sls_install_transaction.py','sls_install_idle.py',
        'sls_install_guard.py','sls_audio_state.py','sls_config_crypto.py','sls_upgrade_trust.py',
        'sls_legacy_permissions.py','freepbx-mirror-signing.pub')

    def api(self):
        import types
        marker="<<'PYRECOVERYCARRIERCAPACITY'\n"
        self.assertTrue(marker in SOURCE,'Corrected recovery carrier actual-input admission is missing')
        body=SOURCE.split(marker,1)[1].split('\nPYRECOVERYCARRIERCAPACITY',1)[0]
        module=types.ModuleType('recovery_carrier_capacity_fixture')
        exec(compile(body,'<embedded-recovery-carrier-capacity>','exec'),module.__dict__)
        return module

    def fixture(self, root):
        import hashlib,io,tarfile
        root.mkdir(mode=0o700)
        def put(path,body,mode=0o600):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            path.write_bytes(body);path.chmod(mode)
        target=root/('transaction-'+'a'*24);target.mkdir(mode=0o700)
        put(target/'transaction.json',b'{"fixture":"original recovery evidence"}\n')
        inputs=root/'authenticated-inputs';inputs.mkdir(mode=0o700)
        installer=inputs/'installer.sh';put(installer,b'#!/bin/bash\n# inert signed fixture\n')
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w:gz')as tgz:
            for name in self.BOOTSTRAP:
                body=('authenticated fixture '+name+'\n').encode()
                info=tarfile.TarInfo('slsmassnotifyserver/bin/sls_mass_notify/'+name)
                info.size=len(body);info.mode=0o644;tgz.addfile(info,io.BytesIO(body))
                put(inputs/'bootstrap'/name,body,0o600 if name.endswith('.pub')else 0o700)
        package=inputs/'package.tgz';put(package,archive.getvalue())
        manifest=inputs/'release-manifest.json'
        put(manifest,(json.dumps({'schema':1,'installer_sha256':hashlib.sha256(installer.read_bytes()).hexdigest(),
                                 'package_sha256':hashlib.sha256(package.read_bytes()).hexdigest()})+'\n').encode())
        signature=inputs/'release-manifest.sig';put(signature,b's'*64)
        return (target,installer,package,manifest,signature,inputs/'bootstrap')

    def test_actual_current_inputs_are_measured_without_creating_a_carrier(self):
        module=self.api()
        with tempfile.TemporaryDirectory(dir='/run')as tmp:
            args=self.fixture(Path(tmp)/'root');before=(args[0]/'transaction.json').read_bytes()
            result=module.measure_recovery_carrier(*args)
            # Sixteen regular files, the carrier and bootstrap directories and
            # four metadata slots. This is independent of future release maxima.
            self.assertEqual(result['required_inodes'],22)
            self.assertLess(result['required_free_bytes'],2*1024**2)
            self.assertGreater(result['required_free_bytes'],sum(p.stat().st_size for p in args[1:5]))
            self.assertEqual(sorted(p.name for p in args[0].iterdir()),['transaction.json'])
            self.assertEqual((args[0]/'transaction.json').read_bytes(),before)

    def test_low_bytes_inodes_or_readonly_target_refuses_without_writing_evidence(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        module=self.api()
        for failure in ('bytes','inodes','readonly'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory(dir='/run')as tmp:
                args=self.fixture(Path(tmp)/'root');before=(args[0]/'transaction.json').read_bytes()
                usage=SimpleNamespace(f_frsize=4096,f_bavail=0 if failure=='bytes'else 100000,
                    f_files=100000,f_favail=0 if failure=='inodes'else 100000,
                    f_flag=os.ST_RDONLY if failure=='readonly'else 0)
                with patch.object(module.os,'fstatvfs',return_value=usage),self.assertRaises((OSError,ValueError)):
                    module.measure_recovery_carrier(*args)
                self.assertEqual(sorted(p.name for p in args[0].iterdir()),['transaction.json'])
                self.assertEqual((args[0]/'transaction.json').read_bytes(),before)

    def test_changed_unsafe_or_incomplete_authenticated_inputs_refuse(self):
        module=self.api()
        for change in ('package','installer','signature','bootstrap','missing_bootstrap',
                       'extra_bootstrap','symlink','hardlink','unsafe_parent','unsafe_target'):
            with self.subTest(change=change),tempfile.TemporaryDirectory(dir='/run')as tmp:
                args=self.fixture(Path(tmp)/'root');target,installer,package,manifest,signature,bootstrap=args
                if change=='package':package.write_bytes(b'changed')
                elif change=='installer':installer.write_bytes(b'changed')
                elif change=='signature':signature.write_bytes(b'partial')
                elif change=='bootstrap':(bootstrap/self.BOOTSTRAP[0]).write_bytes(b'changed')
                elif change=='missing_bootstrap':(bootstrap/self.BOOTSTRAP[0]).unlink()
                elif change=='extra_bootstrap':(bootstrap/'foreign.py').write_bytes(b'foreign')
                elif change=='symlink':
                    kept=installer.with_name('kept.sh');installer.rename(kept);installer.symlink_to(kept)
                elif change=='hardlink':os.link(package,package.with_name('second.tgz'))
                elif change=='unsafe_parent':installer.parent.chmod(0o777)
                elif change=='unsafe_target':target.chmod(0o722)
                with self.assertRaises((OSError,ValueError)):module.measure_recovery_carrier(*args)
                self.assertEqual(sorted(p.name for p in target.iterdir()),['transaction.json'])

    def test_input_change_during_read_refuses(self):
        from unittest.mock import patch
        module=self.api()
        with tempfile.TemporaryDirectory(dir='/run')as tmp:
            args=self.fixture(Path(tmp)/'root');installer=args[1];real_read=os.read;changed=[];seen=[]
            original=installer.stat()
            def read(fd,size):
                body=real_read(fd,size)
                opened=os.fstat(fd)
                seen.append((opened.st_dev,opened.st_ino,len(body)))
                if not changed and (opened.st_dev,opened.st_ino)==(original.st_dev,original.st_ino):
                    # Different length makes the mutation observable even on a
                    # filesystem whose timestamps share the same clock tick.
                    installer.write_bytes(b'changed during capacity observation with a different length\n');changed.append(True)
                return body
            failure=None
            with patch.object(module.os,'read',side_effect=read):
                try:module.measure_recovery_carrier(*args)
                except (OSError,ValueError)as error:failure=error
            self.assertTrue(changed,repr(((original.st_dev,original.st_ino),seen)))
            self.assertIsInstance(failure,(OSError,ValueError),'Changed input must refuse admission')
            self.assertEqual(sorted(p.name for p in args[0].iterdir()),['transaction.json'])

    def test_real_recovery_carrier_copies_only_after_capacity_admission(self):
        self.api()
        with tempfile.TemporaryDirectory(dir='/run')as tmp:
            root=Path(tmp)/'root';args=self.fixture(root);target,*_=args
            harness=r'''source "$1"
fixture="$2"; requested="$3"
INSTALL_TEMP_ROOT="$fixture"; TGZ="$fixture/authenticated-inputs/package.tgz"
INSTALLER_SOURCE_PATH="$fixture/authenticated-inputs/installer.sh"
LOG_FILE="$fixture/log"
download_tgz() { DOWNLOAD_DIR="$fixture/authenticated-inputs"; TGZ="$DOWNLOAD_DIR/package.tgz"; }
verify_tgz() { printf 'authenticated\n' >>"$fixture/trace"; }
if [ "$4" = refuse ]; then
 admit_recovery_carrier_capacity() { printf 'capacity-refused\n' >>"$fixture/trace"; return 1; }
fi
prepare_recovery_carrier "$requested"
'''
            # Refusal must happen before any new directory is created in the
            # original transaction. Successful normal copy is tested separately.
            result=subprocess.run(['/bin/bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),
                str(root),str(target),'refuse'],capture_output=True,text=True,timeout=20)
            self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual((root/'trace').read_text().splitlines(),['authenticated','capacity-refused'])
            self.assertEqual(sorted(p.name for p in target.iterdir()),['transaction.json'])

    def test_normal_corrected_carrier_retains_complete_inputs_and_original_transaction(self):
        self.api()
        with tempfile.TemporaryDirectory(dir='/run')as tmp:
            root=Path(tmp)/'root';args=self.fixture(root);target,installer,package,manifest,signature,bootstrap=args
            originals={'installer.sh':installer.read_bytes(),'package.tgz':package.read_bytes(),
                       'release-manifest.json':manifest.read_bytes(),'release-manifest.sig':signature.read_bytes()}
            expected_helpers={p.name:p.read_bytes()for p in bootstrap.iterdir()}
            journal=(target/'transaction.json').read_bytes()
            harness=r'''source "$1"
fixture="$2"; requested="$3"
INSTALL_TEMP_ROOT="$fixture"; TGZ="$fixture/authenticated-inputs/package.tgz"
INSTALLER_SOURCE_PATH="$fixture/authenticated-inputs/installer.sh"; LOG_FILE="$fixture/log"
download_tgz() { DOWNLOAD_DIR="$fixture/authenticated-inputs"; TGZ="$DOWNLOAD_DIR/package.tgz"; }
verify_tgz() { :; }
prepare_recovery_carrier "$requested"
printf 'CARRIER=%s\n' "${RECOVERY_PROGRAM_DIR%/bootstrap}"
'''
            result=subprocess.run(['/bin/bash','-c',harness,'fixture',str(ROOT/'tools/install_release.sh'),
                str(root),str(target)],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            carrier=Path(next(x.split('=',1)[1]for x in result.stdout.splitlines()if x.startswith('CARRIER=')))
            self.assertEqual(carrier.parent,target)
            self.assertEqual({p.name for p in carrier.iterdir()},set(originals)|{'bootstrap'})
            self.assertEqual({name:(carrier/name).read_bytes()for name in originals},originals)
            self.assertEqual({p.name:p.read_bytes()for p in(carrier/'bootstrap').iterdir()},expected_helpers)
            self.assertEqual((target/'transaction.json').read_bytes(),journal)
            self.assertEqual(stat.S_IMODE(carrier.stat().st_mode),0o700)


if __name__ == '__main__': unittest.main()
