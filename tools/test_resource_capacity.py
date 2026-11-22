#!/usr/bin/env python3
"""Resource admission calculations use fixtures; no PBX operations are invoked."""
import contextlib
import importlib.util
import io
import hashlib
import json
import os
import re
import stat
import shutil
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_resource_capacity.py'
SPEC = importlib.util.spec_from_file_location('resource_capacity_fixture', SOURCE)
RESOURCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESOURCE)
GIB = RESOURCE.GIB


def hardware(cpu=2, memory=4, total=60, available=4):
    return {'effective_cpu_count': cpu, 'effective_memory_bytes': memory * GIB,
            'filesystems': [{'device': '1', 'paths': ['/'], 'total_bytes': total * GIB,
                             'available_bytes': available * GIB, 'required_free_bytes': 4 * GIB,
                             'persistent': True}]}


def simulated_voice_storage(mode, payloads, *, verify_voice_content=False, **options):
    # Other CLI fixture roles use this inert probe rather than reading host voice files.
    return RESOURCE.storage_requirements(mode=mode, payloads=payloads,
        pending_voice_files=[] if verify_voice_content else None, **options)


class ResourceCapacityTests(unittest.TestCase):
    CPU_V2_FLAGS = 'sse sse2 pni ssse3 sse4_1 sse4_2 popcnt cx16 lahf_lm'

    def cpuinfo(self, flags=None, processor=0):
        return f'processor : {processor}\nflags : {self.CPU_V2_FLAGS if flags is None else flags}\n\n'

    def test_exact_pinned_cpu_baseline_accepts_v2_without_avx(self):
        report = RESOURCE.cpu_isa_report(self.cpuinfo(), {0})
        self.assertEqual(report['baseline'], 'x86-64-v2')
        self.assertEqual(report['checked_cpu_count'], 1)
        self.assertEqual(report['numpy_version'], '2.4.6')

    def test_each_pinned_baseline_feature_is_required_on_each_allowed_cpu(self):
        flags = self.CPU_V2_FLAGS.split()
        for missing in flags:
            with self.subTest(missing=missing), self.assertRaises(RESOURCE.ResourceProbeError) as caught:
                RESOURCE.cpu_isa_report(self.cpuinfo() + self.cpuinfo(' '.join(f for f in flags if f != missing), 3), {0, 3})
            self.assertEqual(caught.exception.code, 'cpu_isa_unsupported')
            self.assertIn(missing, str(caught.exception))
            self.assertIn('hypervisor', str(caught.exception))
        self.assertEqual(RESOURCE.cpu_isa_report(self.cpuinfo() + self.cpuinfo('', 3), {0})['checked_cpu_count'], 1)

    def test_cpu_probe_refuses_incomplete_duplicate_and_unbounded_evidence(self):
        for value, allowed in ((self.cpuinfo(), {0, 1}), (self.cpuinfo() * 2, {0}), ('', {0}),
                               (self.cpuinfo(), set()), ('x' * (32 * RESOURCE.MIB + 1), {0})):
            with self.subTest(length=len(value), allowed=allowed), self.assertRaises(RESOURCE.ResourceProbeError) as caught:
                RESOURCE.cpu_isa_report(value, allowed)
            self.assertEqual(caught.exception.code, 'cpu_isa_unavailable')

    def test_native_cpu_probe_uses_actual_affinity_and_redacts_unavailable_evidence(self):
        with patch.object(RESOURCE.platform, 'machine', return_value='x86_64'), \
             patch.object(RESOURCE.os, 'sched_getaffinity', return_value={7}), \
             patch('builtins.open', unittest.mock.mock_open(read_data=self.cpuinfo('', 0) + self.cpuinfo(processor=7))) as opened:
            self.assertEqual(RESOURCE.probe_cpu_isa()['checked_cpu_count'], 1)
        opened.assert_called_once_with('/proc/cpuinfo', 'r', encoding='ascii')
        for failure in (PermissionError('private fixture'), UnicodeError('private fixture')):
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(RESOURCE.os, 'sched_getaffinity', return_value={0}), \
                 patch('builtins.open', side_effect=failure), self.assertRaises(RESOURCE.ResourceProbeError) as caught:
                RESOURCE.probe_cpu_isa()
            self.assertEqual(caught.exception.code, 'cpu_isa_unavailable')
            self.assertNotIn('private fixture', str(caught.exception))

    def test_cpu_only_admission_does_not_read_configuration_phone_or_storage(self):
        expected = {'baseline': 'x86-64-v2', 'checked_cpu_count': 2, 'numpy_version': '2.4.6'}
        with patch.object(RESOURCE, 'probe_cpu_isa', return_value=expected), \
             patch.object(RESOURCE, 'configured_limits', side_effect=AssertionError('No config read')), \
             patch.object(RESOURCE, 'detect_internal_phones', side_effect=AssertionError('No CLI')), \
             patch.object(RESOURCE, 'probe_compute', side_effect=AssertionError('No later resources')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(RESOURCE.main(['--cpu-isa-only']), 0)
        self.assertEqual(json.loads(output.getvalue())['cpu_isa'], expected)

    def test_unsupported_cpu_refuses_before_phone_or_configuration_reads(self):
        failure = RESOURCE.ResourceProbeError('cpu_isa_unsupported', 'Missing ssse3; review hypervisor CPU configuration.')
        for arguments in (['--cpu-isa-only'], ['--check', '--auto-phone-limit', '--config', '/fixture/private']):
            with self.subTest(arguments=arguments), patch.object(RESOURCE, 'probe_cpu_isa', side_effect=failure), \
                 patch.object(RESOURCE, 'configured_limits', side_effect=AssertionError('No config read')), \
                 patch.object(RESOURCE, 'detect_internal_phones', side_effect=AssertionError('No CLI')), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(RESOURCE.main(arguments), 3)
            self.assertEqual(json.loads(output.getvalue())['errors'][0]['code'], 'cpu_isa_unsupported')

    def test_installer_cpu_failure_is_early_actionable_and_does_not_bootstrap_config(self):
        script = '''source "$1"
bootstrap_resource_capacity() {
  [[ "$*" == --cpu-isa-only ]] || return 99
  printf '%s\\n' '{"errors":[{"code":"cpu_isa_unsupported","message":"Missing ssse3; review hypervisor CPU configuration."}]}'
  return 3
}
preflight_python
'''
        result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'tools/install_release.sh')],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing ssse3', result.stdout + result.stderr)
        self.assertIn('hypervisor', result.stdout + result.stderr)

    def test_phone_inventory_drops_root_identity_and_inherited_environment_and_fds(self):
        account = SimpleNamespace(pw_uid=1001, pw_gid=1002, pw_dir='/var/lib/asterisk')
        with patch.object(RESOURCE.pwd, 'getpwnam', return_value=account), \
             patch.object(RESOURCE.os, 'geteuid', return_value=0), \
             patch.object(RESOURCE.os, 'getgrouplist', return_value=[1002, 1003]), \
             patch.dict(os.environ, {'GITHUB_TOKEN': 'private-fixture'}), \
             patch.object(RESOURCE.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='0 results found.\n')) as run:
            self.assertEqual(RESOURCE.detect_internal_phones()['detected_phone_contacts'], 0)
        options = run.call_args.kwargs
        self.assertEqual((options['user'], options['group'], options['extra_groups']), (1001, 1002, [1002, 1003]))
        self.assertTrue(options['close_fds'])
        self.assertEqual(options['stdin'], subprocess.DEVNULL)
        self.assertNotIn('GITHUB_TOKEN', options['env'])
        self.assertEqual(options['env']['LC_ALL'], 'C.UTF-8')
        self.assertEqual(options['cwd'], '/')

    def test_phone_inventory_refuses_root_account_or_an_unrelated_runtime_user(self):
        for uid, runtime_uid in ((0, 0), (1001, 1002)):
            with self.subTest(uid=uid, runtime_uid=runtime_uid), \
                 patch.object(RESOURCE.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=uid, pw_gid=1001, pw_dir='/private')), \
                 patch.object(RESOURCE.os, 'geteuid', return_value=runtime_uid), \
                 patch.object(RESOURCE.subprocess, 'run') as run, self.assertRaises(RESOURCE.ResourceProbeError):
                RESOURCE.detect_internal_phones()
            run.assert_not_called()

    def test_runtime_speech_workspace_is_checked_separately_from_installer_fallback(self):
        probe={'path':'/tmp','available_bytes':48 * RESOURCE.MIB,'required_free_bytes':203 * RESOURCE.MIB,
               'read_only':False,'inodes_exhausted':False}
        machine=hardware();machine['storage']=RESOURCE.storage_requirements(temporary_directory='/var/tmp')
        machine['runtime_speech_scratch']=probe
        report=RESOURCE.evaluate(machine,25)
        self.assertIn('runtime_speech_workspace_insufficient',[row['code'] for row in report['errors']])
        self.assertFalse(report['resource_checks']['runtime_temporary']['ok'])
        self.assertFalse(report['resource_checks']['temporary']['ok'])
        self.assertEqual(report['eligible_limit'],0)
        self.assertTrue(any('/tmp' in row['message'] for row in report['errors']))

    def test_runtime_preview_displays_the_enforced_audio_temporary_requirement(self):
        machine=hardware();machine['storage']=RESOURCE.storage_requirements(mode='runtime')
        machine['filesystems'][0]['paths'].append('/tmp')
        machine['runtime_speech_scratch']={'path':'/tmp','available_bytes':256 * RESOURCE.MIB,
            'required_free_bytes':221 * RESOURCE.MIB,'read_only':False,'inodes_exhausted':False}
        report=RESOURCE.evaluate(machine,25)
        self.assertEqual(report['requirements']['temporary_free_bytes'],221 * RESOURCE.MIB)
        self.assertTrue(report['resource_checks']['temporary']['ok'])

    def test_runtime_speech_workspace_preserves_the_configured_reserve_and_parallelism(self):
        with patch.object(RESOURCE,'trusted_temporary_directory',return_value=True), \
             patch.object(RESOURCE.os,'statvfs',return_value=SimpleNamespace(f_bavail=1024,f_frsize=RESOURCE.MIB)):
            small=RESOURCE.probe_runtime_speech_scratch('lite',{})
            larger=RESOURCE.probe_runtime_speech_scratch('standard',{'speech_synthesis_limit':4,'generated_media_min_free_mib':256})
        self.assertEqual(small['required_free_bytes'],128 * RESOURCE.MIB + 600 * 160000 + RESOURCE.MIB)
        self.assertEqual(larger['required_free_bytes'],256 * RESOURCE.MIB + 4 * (600 * 160000 + RESOURCE.MIB))
        for settings in ({'speech_synthesis_limit':True},{'generated_media_min_free_mib':63}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):RESOURCE.probe_runtime_speech_scratch('standard',settings)

    def test_runtime_scratch_requires_actual_pbx_write_and_traversal_access(self):
        with patch.object(RESOURCE,'trusted_temporary_directory',return_value=True), \
             patch.object(RESOURCE.os,'geteuid',return_value=1000), \
             patch.object(RESOURCE.os,'access',return_value=False):
            with self.assertRaises(RESOURCE.ResourceProbeError) as error:RESOURCE.probe_runtime_speech_scratch('lite',{})
        self.assertEqual(error.exception.code,'runtime_speech_workspace_unsafe')

    def test_runtime_scratch_root_access_probe_failure_is_bounded_and_redacted(self):
        for failure in (subprocess.TimeoutExpired('sensitive command detail',2),FileNotFoundError('sensitive path')):
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(RESOURCE,'trusted_temporary_directory',return_value=True), \
                 patch.object(RESOURCE.os,'geteuid',return_value=0), \
                 patch.object(RESOURCE.subprocess,'run',side_effect=failure):
                with self.assertRaises(RESOURCE.ResourceProbeError) as error:RESOURCE.probe_runtime_speech_scratch('lite',{})
                self.assertNotIn('sensitive',str(error.exception))

    def test_browser_shards_allow_simultaneous_atomic_replacements(self):
        storage = RESOURCE.storage_requirements()
        parts = storage['component_budgets_bytes'][RESOURCE.MANAGED_TREES['data']]
        # Receipts do not share a browser session lock. Each hexadecimal shard
        # can retain its old 4 MiB ledger while writing its replacement.
        shards = {digit: 4 * RESOURCE.MIB for digit in '0123456789abcdef'}
        maximum_existing = sum(shards.values())
        concurrent_replacements = sum(shards.values())
        self.assertGreaterEqual(parts['browser_evidence_and_atomic_write_headroom'],
                                maximum_existing + concurrent_replacements)

    def test_read_only_and_inode_exhausted_targets_fail_with_specific_diagnostics(self):
        for field, code in (('read_only', 'storage_read_only'), ('inodes_exhausted', 'storage_inodes_exhausted')):
            measured = hardware()
            measured['filesystems'][0][field] = True
            report = RESOURCE.evaluate(measured, 25)
            self.assertIn(code, [row['code'] for row in report['errors']])
            self.assertEqual((report['eligible_limit'], report['eligible_phone_limit']), (0, 0))

    def test_mount_probe_applies_read_only_and_inode_checks_only_to_write_destinations(self):
        with patch.object(RESOURCE, 'filesystem_types', return_value=[('/', 'ext4')]), \
             patch.object(RESOURCE.Path, 'exists', return_value=True), \
             patch.object(RESOURCE.Path, 'resolve', lambda path: path), \
             patch.object(RESOURCE.Path, 'stat', lambda path: SimpleNamespace(st_dev=2 if str(path) == '/tmp' else 1)), \
             patch.object(RESOURCE.os, 'statvfs', side_effect=lambda path: SimpleNamespace(
                 f_blocks=10, f_bavail=8, f_frsize=GIB, f_flag=0 if str(path) == '/tmp' else os.ST_RDONLY,
                 f_favail=100 if str(path) == '/tmp' else 0)):
            mounts = RESOURCE.probe_filesystems({'/tmp': 10})
        parent = next(row for row in mounts if row['device'] == '1')
        self.assertFalse(parent['read_only']); self.assertFalse(parent['inodes_exhausted'])
        scratch = next(row for row in mounts if row['device'] == '2')
        self.assertFalse(scratch['read_only']); self.assertFalse(scratch['inodes_exhausted'])

    def test_disk_failure_message_preserves_sub_gib_precision(self):
        measured = hardware()
        measured['filesystems'][0].update(required_free_bytes=103 * RESOURCE.MIB, available_bytes=102 * RESOURCE.MIB)
        message = RESOURCE.evaluate(measured, 25)['errors'][0]['message']
        self.assertIn('103.00 MiB', message); self.assertIn('102.00 MiB', message)

    def test_small_tmp_moves_scratch_without_weakening_target_mount_checks(self):
        storage = RESOURCE.storage_requirements()
        def filesystems(budgets, inode_budgets=None):
            scratch = '/tmp' if '/tmp' in budgets else '/var/tmp'
            return [{'device': 'data', 'paths': [p for p in budgets if p != scratch],
                     'available_bytes': 4 * GIB, 'required_free_bytes': sum(v for p, v in budgets.items() if p != scratch)},
                    {'device': 'scratch', 'paths': [scratch], 'available_bytes': (64 * RESOURCE.MIB if scratch == '/tmp' else 2 * GIB),
                     'required_free_bytes': budgets[scratch]}]
        with patch.object(RESOURCE, 'trusted_temporary_directory', return_value=True), \
             patch.object(RESOURCE, 'probe_filesystems', side_effect=filesystems), \
             patch.object(RESOURCE.os, 'statvfs', return_value=SimpleNamespace(f_frsize=4096)):
            selected, mounts = RESOURCE.probe_storage_filesystems(storage)
            self.assertEqual(selected['temporary_directory'], '/var/tmp')
            self.assertNotIn('/tmp', selected['free_budgets_bytes'])
            self.assertEqual(selected['sls_persistent_free_bytes'], storage['sls_persistent_free_bytes'])
            self.assertTrue(all(row['available_bytes'] >= row['required_free_bytes'] for row in mounts))
            # A staged install keeps its selected filesystem rather than moving recovery files.
            selected, mounts = RESOURCE.probe_storage_filesystems(storage, '/tmp')
            self.assertEqual(selected['temporary_directory'], '/tmp')
            self.assertTrue(any(row['available_bytes'] < row['required_free_bytes'] for row in mounts))
        def insufficient(budgets, inode_budgets=None):
            return [{'device': '1', 'paths': list(budgets), 'available_bytes': 64 * RESOURCE.MIB,
                     'required_free_bytes': sum(budgets.values())}]
        with patch.object(RESOURCE, 'trusted_temporary_directory', return_value=True), \
             patch.object(RESOURCE, 'probe_filesystems', side_effect=insufficient), \
             patch.object(RESOURCE.os, 'statvfs', return_value=SimpleNamespace(f_frsize=4096)):
            selected, mounts = RESOURCE.probe_storage_filesystems(storage)
            self.assertEqual(selected['temporary_directory'], '/tmp')
            self.assertIn('free_space_insufficient', [r['code'] for r in RESOURCE.evaluate(
                {'effective_cpu_count':2, 'effective_memory_bytes':4 * GIB, 'filesystems':mounts, 'storage':selected}, 25)['errors']])

    def test_dedicated_mounts_do_not_require_unused_parent_volume_headroom(self):
        budgets = {RESOURCE.MANAGED_TREES['runtime']: 250 * RESOURCE.MIB,
                   RESOURCE.MANAGED_TREES['data']: 600 * RESOURCE.MIB, '/tmp': 800 * RESOURCE.MIB}
        with patch.object(RESOURCE, 'filesystem_types', return_value=[('/', 'ext4')]), \
             patch.object(RESOURCE.Path, 'exists', return_value=True), \
             patch.object(RESOURCE.Path, 'resolve', lambda path: path), \
             patch.object(RESOURCE.Path, 'stat', lambda path: SimpleNamespace(st_dev=2 if str(path) in budgets else 1)), \
             patch.object(RESOURCE.os, 'statvfs', side_effect=lambda path: SimpleNamespace(
                 f_blocks=4000, f_bavail=2000 if str(path) in budgets else 8, f_frsize=RESOURCE.MIB)):
            mounts = RESOURCE.probe_filesystems(budgets)
        parents = next(row for row in mounts if row['device'] == '1')
        self.assertEqual(parents['required_free_bytes'], 0)
        self.assertEqual(RESOURCE.evaluate({'effective_cpu_count':2, 'effective_memory_bytes':4 * GIB,
            'filesystems':mounts}, 25)['errors'], [])
        installer = (ROOT/'tools/install_release.sh').read_text()
        platform = installer.split('preflight_platform() {',1)[1].split('\npreflight_python()',1)[0]
        self.assertNotIn('df -Pk', platform)

    def test_temporary_directory_validation_rejects_links_and_writable_nonsticky_roots(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o777):
            with patch.object(RESOURCE.Path,'lstat',return_value=SimpleNamespace(st_uid=0,st_mode=mode)):
                self.assertFalse(RESOURCE.trusted_temporary_directory('/var/tmp'))
        self.assertFalse(RESOURCE.trusted_temporary_directory('/home/asterisk'))

    @staticmethod
    def scratch_filesystems(available_mib=None, inodes=None, kinds=None):
        available_mib = available_mib or {'/tmp':300,'/var/tmp':4096}
        inodes = inodes or {'/tmp':50000,'/var/tmp':50000}
        kinds = kinds or {}
        def probe(budgets,inode_budgets=None):
            scratch=next(path for path in ('/tmp','/var/tmp',RESOURCE.PRIVATE_INSTALL_TEMP) if path in budgets)
            return [{'device':'scratch','paths':[scratch],'total_bytes':8*GIB,
                     'available_bytes':available_mib[scratch]*RESOURCE.MIB,
                     'required_free_bytes':budgets[scratch],'persistent':True,
                     'filesystem_type':kinds.get(scratch,'ext4'),
                     'available_inodes':inodes.get(scratch,50000),'required_inodes':(inode_budgets or {}).get(scratch,0)},
                    {'device':'persistent','paths':[path for path in budgets if path!=scratch],
                     'total_bytes':32*GIB,'available_bytes':16*GIB,'persistent':True,
                     'required_free_bytes':sum(value for path,value in budgets.items() if path!=scratch)}]
        return probe

    def test_install_scratch_reservation_keeps_inspection_and_persistent_prepare_budgets(self):
        prepare=RESOURCE.storage_requirements(mode='prepare')
        reserved=RESOURCE.storage_requirements(mode='prepare',reserve_install_workspace=True)
        install=RESOURCE.storage_requirements(mode='install')
        self.assertLess(prepare['temporary_free_bytes'],300*RESOURCE.MIB)
        self.assertGreater(reserved['temporary_free_bytes'],300*RESOURCE.MIB)
        self.assertEqual(reserved['component_budgets_bytes']['/tmp'],install['component_budgets_bytes']['/tmp'])
        self.assertEqual(reserved['inode_budgets']['/tmp'],20002)  # archives + two complete Piper trees/wheel metadata
        self.assertEqual(prepare['inode_budgets']['/tmp'],5028)
        self.assertEqual({p:n for p,n in reserved['free_budgets_bytes'].items() if p!='/tmp'},
                         {p:n for p,n in prepare['free_budgets_bytes'].items() if p!='/tmp'})
        with patch.object(RESOURCE,'trusted_temporary_directory',return_value=True), \
             patch.object(RESOURCE,'probe_filesystems',side_effect=self.scratch_filesystems()), \
             patch.object(RESOURCE.os,'statvfs',return_value=SimpleNamespace(f_frsize=4096)):
            self.assertEqual(RESOURCE.probe_storage_filesystems(prepare)[0]['temporary_directory'],'/tmp')
            self.assertEqual(RESOURCE.probe_storage_filesystems(prepare,reserve_install_workspace=True)[0]['temporary_directory'],'/var/tmp')

    def test_install_scratch_reservation_qualifies_future_inode_count(self):
        prepare=RESOURCE.storage_requirements(mode='prepare')
        with patch.object(RESOURCE,'trusted_temporary_directory',return_value=True), \
             patch.object(RESOURCE,'probe_filesystems',side_effect=self.scratch_filesystems(
                 {'/tmp':4096,'/var/tmp':4096},{'/tmp':7000,'/var/tmp':50000})), \
             patch.object(RESOURCE.os,'statvfs',return_value=SimpleNamespace(f_frsize=4096)):
            selected,mounts=RESOURCE.probe_storage_filesystems(prepare,reserve_install_workspace=True)
        self.assertEqual(selected['temporary_directory'],'/var/tmp')
        self.assertEqual(mounts[0]['required_inodes'],20002)

    def test_install_scratch_reservation_refuses_small_or_unsafe_alternates(self):
        for trust,space in ((lambda path:True,{'/tmp':300,'/var/tmp':350}),
                            (lambda path:path=='/tmp',{'/tmp':300,'/var/tmp':4096})):
            with self.subTest(alternate_mib=space['/var/tmp']), \
                 patch.object(RESOURCE,'trusted_temporary_directory',side_effect=trust), \
                 patch.object(RESOURCE,'probe_filesystems',side_effect=self.scratch_filesystems(space)), \
                 patch.object(RESOURCE.os,'statvfs',return_value=SimpleNamespace(f_frsize=4096)):
                selected,mounts=RESOURCE.probe_storage_filesystems(
                    RESOURCE.storage_requirements(mode='prepare'),reserve_install_workspace=True)
            report=RESOURCE.evaluate({'effective_cpu_count':2,'effective_memory_bytes':4*GIB,
                                      'filesystems':mounts,'storage':selected},25)
            self.assertEqual(selected['temporary_directory'],'/tmp')
            self.assertIn('free_space_insufficient',[row['code']for row in report['errors']])
            self.assertEqual(report['eligible_limit'],0)

    def test_install_scratch_reservation_preserves_tmpfs_and_runtime_audio_constraints(self):
        with patch.object(RESOURCE,'trusted_temporary_directory',return_value=True), \
             patch.object(RESOURCE,'probe_filesystems',side_effect=self.scratch_filesystems(
                 {'/tmp':4096,'/var/tmp':4096},kinds={'/tmp':'tmpfs'})), \
             patch.object(RESOURCE.os,'statvfs',return_value=SimpleNamespace(f_frsize=4096)):
            selected,mounts=RESOURCE.probe_storage_filesystems(
                RESOURCE.storage_requirements(mode='prepare'),reserve_install_workspace=True)
        self.assertEqual(selected['temporary_directory'],'/var/tmp')
        report=RESOURCE.evaluate({'effective_cpu_count':2,'effective_memory_bytes':4*GIB,
            'filesystems':mounts,'storage':selected,'runtime_speech_scratch':{'path':'/tmp',
            'available_bytes':100*RESOURCE.MIB,'required_free_bytes':221*RESOURCE.MIB,
            'read_only':False,'inodes_exhausted':False}},25)
        self.assertIn('runtime_speech_workspace_insufficient',[row['code']for row in report['errors']])
        self.assertEqual(report['eligible_limit'],0)

    def test_automatic_selection_skips_both_volatile_temporary_mounts_for_persistent_spool(self):
        private=RESOURCE.PRIVATE_INSTALL_TEMP
        with patch.object(RESOURCE,'trusted_temporary_directory',return_value=True), \
             patch.object(RESOURCE,'private_install_temporary_state',return_value={'exists':True,'allocation_unit':4096,'read_only':False}), \
             patch.object(RESOURCE,'probe_filesystems',side_effect=self.scratch_filesystems(
                 {'/tmp':4096,'/var/tmp':4096,private:4096},kinds={'/tmp':'tmpfs','/var/tmp':'tmpfs'})), \
             patch.object(RESOURCE.os,'statvfs',return_value=SimpleNamespace(f_frsize=4096)):
            selected,mounts=RESOURCE.probe_storage_filesystems(
                RESOURCE.storage_requirements(mode='prepare'),reserve_install_workspace=True)
        self.assertEqual(selected['temporary_directory'],private,
            'A nominal baseline host should use qualified persistent scratch before adding avoidable tmpfs RAM')

    def test_final_check_refuses_lost_capacity_without_rebinding_prepared_paths(self):
        with patch.object(RESOURCE,'trusted_temporary_directory',return_value=True), \
             patch.object(RESOURCE,'probe_filesystems',side_effect=self.scratch_filesystems(
                 {'/tmp':4096,'/var/tmp':200})), \
             patch.object(RESOURCE.os,'statvfs',return_value=SimpleNamespace(f_frsize=4096)):
            selected,mounts=RESOURCE.probe_storage_filesystems(
                RESOURCE.storage_requirements(temporary_directory='/var/tmp'),'/var/tmp')
        self.assertEqual(selected['temporary_directory'],'/var/tmp')
        report=RESOURCE.evaluate({'effective_cpu_count':2,'effective_memory_bytes':4*GIB,
                                  'filesystems':mounts,'storage':selected},25)
        self.assertIn('free_space_insufficient',[row['code']for row in report['errors']])

    def test_prepare_reservation_cannot_replace_runtime_or_install_admission(self):
        for mode in ('runtime','install'):
            with self.subTest(mode=mode),self.assertRaises(ValueError):
                RESOURCE.storage_requirements(mode=mode,reserve_install_workspace=True)
            with self.subTest(mode=mode),patch.object(RESOURCE,'probe_cpu_isa',side_effect=AssertionError('No probe')), \
                 contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit)as caught:
                RESOURCE.main(['--check','--mode',mode,'--reserve-install-workspace'])
            self.assertEqual(caught.exception.code,2)

    def test_permission_failure_identifies_the_unreadable_storage_root(self):
        with tempfile.TemporaryDirectory(prefix='sls-capacity-private-cache-') as name:
            cache = Path(name) / '__pycache__'
            cache.mkdir()
            original = RESOURCE.os.scandir
            def scan(path):
                if Path(path) == cache:
                    raise PermissionError(13, 'fixture permission denied', str(path))
                return original(path)
            with patch.object(RESOURCE.os, 'scandir', scan):
                with self.assertRaises(RESOURCE.ResourceProbeError) as caught:
                    RESOURCE.measure_tree(name, RESOURCE.time.monotonic() + 2)
            self.assertEqual(caught.exception.code, 'storage_directory_unreadable')
            self.assertIn(str(cache), str(caught.exception))
            self.assertIn('Repair Installation', str(caught.exception))
            output = io.StringIO()
            with patch.object(RESOURCE, 'probe_compute', return_value=(4, 8 * GIB)), \
                 patch.object(RESOURCE, 'probe_storage', side_effect=caught.exception), contextlib.redirect_stdout(output):
                status = RESOURCE.main(['--check'])
            report = json.loads(output.getvalue())
            self.assertEqual(status, 3)
            self.assertEqual(report['errors'][0]['code'], 'storage_directory_unreadable')
            self.assertIn(str(cache), report['errors'][0]['message'])
            self.assertEqual(report['eligible_limit'], 0)

    def test_probe_stage_is_actionable_without_raw_exception_disclosure(self):
        output = io.StringIO()
        with patch.object(RESOURCE, 'probe_compute', side_effect=ValueError('sensitive value')), contextlib.redirect_stdout(output):
            self.assertEqual(RESOURCE.main(['--check']), 3)
        message = json.loads(output.getvalue())['errors'][0]['message']
        self.assertIn('CPU and memory', message)
        self.assertNotIn('sensitive value', message)

    def test_storage_reference_matches_all_exact_dependency_pins(self):
        pins = {}
        for line in (SOURCE.parent / 'piper-requirements.txt').read_text().splitlines():
            if line and not line.startswith('#'):
                name, version = line.split('==')
                pins[name] = version
        self.assertEqual(RESOURCE.PINNED_VERSIONS, pins, 'Re-measure pinned wheels/runtime when requirements change.')
        self.assertEqual(RESOURCE.PINNED_WHEEL_BYTES, 77861012)

    def test_fresh_and_installed_storage_budgets_explain_every_component(self):
        fresh = RESOURCE.storage_requirements()
        measured = {'runtime': {'allocated_bytes': 167628800}, 'venv': {'allocated_bytes': 166916096},
                    'voices': {'allocated_bytes': 189452288}, 'module': {'allocated_bytes': 4317184},
                    'config_backups': {'allocated_bytes': 188416}}
        installed = RESOURCE.storage_requirements(measured, missing_voices=0)
        voice_path = RESOURCE.MANAGED_TREES['voices']
        self.assertEqual(fresh['free_budgets_bytes'][voice_path], sum(RESOURCE.rounded(value) for value in RESOURCE.VOICE_BYTES.values()))
        self.assertEqual(installed['free_budgets_bytes'][voice_path], RESOURCE.rounded(max(RESOURCE.VOICE_BYTES.values())))
        self.assertEqual(installed['measured_fixed_allocation_bytes'], sum(measured[key]['allocated_bytes'] for key in ('runtime', 'voices', 'module')))
        for report in (fresh, installed):
            self.assertEqual(report['additional_free_bytes'], sum(report['free_budgets_bytes'].values()))
            self.assertEqual(report['additional_free_bytes'], report['sls_persistent_free_bytes'] + report['temporary_free_bytes'])
            for path, parts in report['component_budgets_bytes'].items():
                self.assertEqual(report['free_budgets_bytes'][path], sum(parts.values()))
            self.assertFalse(report['retention_is_byte_bounded'])
            self.assertTrue(report['synthesis_concurrency_is_enforced'])
            self.assertTrue(report['generated_media_admission_is_byte_bounded'])
            self.assertNotIn('one_audio_pipeline', str(report['component_budgets_bytes']))

    def test_larger_managed_runtime_and_state_expand_recovery_space(self):
        baseline = RESOURCE.storage_requirements()
        large = RESOURCE.storage_requirements({'runtime': {'allocated_bytes': 3 * GIB},
                'venv': {'allocated_bytes': 2 * GIB}, 'schedule_ledger': {'allocated_bytes': 20 * RESOURCE.MIB}})
        self.assertEqual(large['free_budgets_bytes'][RESOURCE.MANAGED_TREES['runtime']], 3 * GIB)
        self.assertGreater(large['temporary_free_bytes'], baseline['temporary_free_bytes'])
        self.assertEqual(large['free_budgets_bytes'][RESOURCE.MANAGED_TREES['data']] - baseline['free_budgets_bytes'][RESOURCE.MANAGED_TREES['data']], 10 * RESOURCE.MIB)
        large_blocks = RESOURCE.storage_requirements(allocation_units={RESOURCE.MANAGED_TREES['runtime']: 65536})
        self.assertGreater(large_blocks['pinned_runtime_reference_bytes'], baseline['pinned_runtime_reference_bytes'])

    def test_storage_metadata_scan_is_bounded_and_does_not_follow_links(self):
        import time
        with tempfile.TemporaryDirectory(prefix='sls-storage-measure-') as name:
            root = Path(name)
            (root / 'file').write_bytes(b'private-content-not-returned')
            (root / 'link').symlink_to('/etc')
            os.mkfifo(root / 'pipe')
            report = RESOURCE.measure_tree(root, time.monotonic() + 2)
            self.assertEqual(report['files'], 1)
            self.assertEqual(report['logical_bytes'], len(b'private-content-not-returned'))
            self.assertNotIn('private', json.dumps(report))
            with self.assertRaises(ValueError):
                RESOURCE.measure_tree(root, time.monotonic() - 1)
            with self.assertRaises(ValueError):
                RESOURCE.measure_tree(root, time.monotonic() + 2, maximum_entries=1)
            with self.assertRaises(ValueError):
                RESOURCE.measure_tree(root / 'link', time.monotonic() + 2)

    def test_dangling_storage_root_is_rejected_instead_of_measured_as_absent(self):
        with tempfile.TemporaryDirectory(prefix='sls-storage-missing-') as name:
            root=Path(name)
            absent=root/'absent'
            self.assertEqual(RESOURCE.measure_tree(absent,RESOURCE.time.monotonic()+2)['files'],0)
            linked=root/'linked';linked.symlink_to(absent)
            with self.assertRaises(ValueError):
                RESOURCE.measure_tree(linked,RESOURCE.time.monotonic()+2)

    def test_actual_managed_mounts_get_independent_headroom(self):
        voices = RESOURCE.MANAGED_TREES['voices']
        budgets = {voices: 100, '/tmp': 200}
        with patch.object(RESOURCE, 'filesystem_types', return_value=[(voices, 'ext4'), ('/', 'ext4')]), \
             patch.object(RESOURCE.Path, 'exists', return_value=True), \
             patch.object(RESOURCE.Path, 'resolve', lambda path: path), \
             patch.object(RESOURCE.Path, 'stat', lambda path: SimpleNamespace(st_dev=2 if str(path) == voices else 1)), \
             patch.object(RESOURCE.os, 'statvfs', return_value=SimpleNamespace(f_blocks=80, f_bavail=30, f_frsize=GIB)):
            filesystems = RESOURCE.probe_filesystems(budgets)
        self.assertEqual({item['device']: item['required_free_bytes'] for item in filesystems}, {'1': 200, '2': 100})

    def test_tiers_and_intermediate_requests(self):
        for maximum, cpu, memory in RESOURCE.TIERS:
            with self.subTest(maximum=maximum):
                report = RESOURCE.evaluate(hardware(cpu, memory), maximum)
                self.assertEqual(report['errors'], [])
                self.assertEqual(report['eligible_limit'], maximum)
                if maximum < 1000:
                    self.assertTrue(RESOURCE.evaluate(hardware(cpu, memory), maximum + 1)['errors'])
        self.assertEqual(RESOURCE.evaluate(hardware(4, 6), 101)['requirements']['memory_bytes'], 6 * GIB)
        self.assertEqual(RESOURCE.evaluate(hardware(), 1)['eligible_limit'], 50)

    def test_nominal_memory_reporting_allowance_is_bounded(self):
        minimum = RESOURCE.minimum_reported_memory({}, 4 * GIB)
        measured = hardware()
        measured['effective_memory_bytes'] = minimum
        self.assertEqual(RESOURCE.evaluate(measured, 50)['errors'], [])
        measured['effective_memory_bytes'] -= 1
        report = RESOURCE.evaluate(measured, 50)
        self.assertEqual(report['errors'][0]['code'], 'memory_insufficient')
        self.assertEqual(report['eligible_limit'], 0)

    def test_reported_four_gib_host_passes_but_lower_container_quota_does_not(self):
        measured = hardware()
        measured['effective_memory_bytes'] = 4068581376
        self.assertEqual(RESOURCE.evaluate(measured, 25)['errors'], [])
        measured['memory_limit_bytes'] = 4068581376
        report = RESOURCE.evaluate(measured, 25)
        self.assertIn('memory_insufficient', [row['code'] for row in report['errors']])
        self.assertIn('baseline', report['errors'][0]['message'])
        self.assertEqual(16 * GIB - RESOURCE.minimum_reported_memory({}, 16 * GIB), 256 * RESOURCE.MIB)

    def test_runtime_capacity_does_not_reserve_another_installation(self):
        runtime = RESOURCE.storage_requirements(mode='runtime')
        prepare = RESOURCE.storage_requirements(mode='prepare')
        install = RESOURCE.storage_requirements(mode='install')
        self.assertEqual(runtime['temporary_free_bytes'], 0)
        self.assertLess(runtime['additional_free_bytes'], prepare['additional_free_bytes'])
        self.assertLess(prepare['additional_free_bytes'], install['additional_free_bytes'])
        sparse = RESOURCE.storage_requirements({'runtime': {'allocated_bytes': 4096, 'logical_bytes': 2 * GIB}})
        self.assertGreaterEqual(sparse['temporary_free_bytes'], GIB)
        journal=sparse['component_budgets_bytes'][RESOURCE.INSTALLER_JOURNAL]
        self.assertIn('prior_static_runtime_and_api_snapshot',journal)
        self.assertGreaterEqual(journal['prior_static_runtime_and_api_snapshot'],2*GIB)
        self.assertIn('saved_candidate_archive_and_metadata',journal)
        self.assertNotIn('prior_static_runtime_and_api_snapshot',sparse['component_budgets_bytes']['/tmp'])

    def test_inode_shortfall_and_volatile_data_are_rejected(self):
        measured = hardware()
        measured['filesystems'][0].update(available_inodes=20, required_inodes=21)
        self.assertIn('storage_inodes_insufficient', [row['code'] for row in RESOURCE.evaluate(measured, 25)['errors']])
        measured['filesystems'][0].update(available_inodes=100, persistent=False,
            filesystem_type='tmpfs', volatile_targets=[RESOURCE.MANAGED_TREES['data']])
        self.assertIn('storage_not_persistent', [row['code'] for row in RESOURCE.evaluate(measured, 25)['errors']])

    def test_cached_tree_scan_does_not_rescan_a_measured_child(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); child = root / 'child'; child.mkdir()
            (child / 'one').write_bytes(b'12345')
            cache = {}
            RESOURCE.measure_tree(root, RESOURCE.time.monotonic() + 2, cache=cache)
            with patch.object(RESOURCE.os, 'scandir', side_effect=AssertionError('duplicate scan')):
                report = RESOURCE.measure_tree(child, RESOURCE.time.monotonic() + 2, cache=cache)
            self.assertEqual(report['logical_bytes'], 5)

    def test_payload_budget_uses_actual_destination_sizes_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for relative, body in [('bin/helper.py', b'x'*100), ('api/sipnotify/index.php', b'x'*200),
                                   ('assets/icon.svg', b'x'*50), ('module.xml', b'<module/>')]:
                file = root/relative; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(body)
            payloads = RESOURCE.measure_release_payloads(root)
            self.assertEqual(payloads[RESOURCE.MANAGED_TREES['sip_api']]['bytes'], 200)
            self.assertEqual(payloads[RESOURCE.MANAGED_TREES['runtime']]['bytes'], 100)
            measured = RESOURCE.storage_requirements(payloads=payloads)
            self.assertLess(measured['free_budgets_bytes'][RESOURCE.MANAGED_TREES['sip_api']], RESOURCE.MIB)
            (root/'assets/link').symlink_to('/etc/passwd')
            with self.assertRaises(RESOURCE.ResourceProbeError): RESOURCE.measure_release_payloads(root)

    def test_pinned_dependency_payload_fits_but_entry_growth_remains_bounded(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for index in range(3000):
                (root / ('dependency-%04d.php' % index)).touch()
            measured = RESOURCE.measure_release_payloads(root)
            self.assertEqual(measured[RESOURCE.MANAGED_TREES['module']]['entries'], 3001)
            for index in range(3000, 5001):
                (root / ('dependency-%04d.php' % index)).touch()
            with self.assertRaises(RESOURCE.ResourceProbeError):
                RESOURCE.measure_release_payloads(root)

    def test_missing_aes_dependency_returns_a_specific_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root/'sls_config_crypto.py').write_text("raise ImportError('fixture-only detail')")
            config = root/'settings.config'
            config.write_text(json.dumps({'format':'sls-mass-notify-config-aes256gcm-v1', 'ciphertext':'fixture'}))
            with patch.object(RESOURCE, '__file__', str(root/'capacity.py')):
                with self.assertRaises(RESOURCE.ResourceProbeError) as caught: RESOURCE.configured_limits(config)
            self.assertEqual(caught.exception.code,'config_crypto_dependency_missing')
            self.assertNotIn('fixture-only detail',str(caught.exception))

    def test_sls_headroom_is_enforced_without_a_total_volume_floor(self):
        # A smaller existing PBX volume is acceptable when SLS has its own headroom.
        report = RESOURCE.evaluate(hardware(total=20, available=4), 50)
        self.assertEqual(report['errors'], [])
        self.assertFalse(report['assumptions']['whole_volume_size_is_enforced'])
        reference = RESOURCE.storage_requirements()
        self.assertEqual(report['requirements']['sls_persistent_free_bytes'], reference['sls_persistent_free_bytes'])
        self.assertEqual(report['requirements']['temporary_free_bytes'], reference['temporary_free_bytes'])
        measured = hardware(total=60, available=4)
        measured['filesystems'][0]['available_bytes'] -= 1
        report = RESOURCE.evaluate(measured, 50)
        self.assertIn('free_space_insufficient', [error['code'] for error in report['errors']])
        self.assertEqual((report['eligible_limit'], report['eligible_phone_limit']), (0, 0))

    def test_phone_growth_formula_and_continuous_eligibility(self):
        for phones, cpu, ram in ((1,2,4),(25,2,4),(50,2,4),(100,2,4),(101,3,4.25),(150,3,4.25),
                                (228,3,4.25),(229,3,4.5),(300,3,4.5),(301,4,4.5),(500,4,5),(1000,7,6)):
            report=RESOURCE.evaluate(hardware(cpu,ram),50,phones)
            self.assertEqual(report['errors'],[],(phones,report))
            self.assertEqual(report['requirements']['cpu_count'],cpu)
            self.assertEqual(report['requirements']['memory_bytes'],ram*GIB)
        self.assertEqual(RESOURCE.evaluate(hardware(3,4.25),50)['eligible_phone_limit'],300)
        self.assertEqual(RESOURCE.evaluate(hardware(3,4.5),50)['eligible_phone_limit'],300)
        self.assertEqual(RESOURCE.evaluate(hardware(4,5),50)['eligible_phone_limit'],500)
        self.assertEqual(RESOURCE.evaluate(hardware(7,6),50)['eligible_phone_limit'],1000)
        self.assertEqual(RESOURCE.evaluate(hardware(),50)['eligible_phone_limit'],100)

    def test_phone_and_desktop_capacities_share_the_resource_budget(self):
        report=RESOURCE.evaluate(hardware(4,5.8),250,101)
        self.assertEqual({error['code'] for error in report['errors']},{'cpu_insufficient','memory_insufficient'})
        self.assertEqual((report['eligible_limit'],report['eligible_phone_limit']),(100,100))
        combined=RESOURCE.evaluate(hardware(13,14),1000,1000)
        self.assertEqual(combined['errors'],[])
        parts=combined['requirements']['components']
        self.assertEqual(sum(x['cpu_count'] for x in parts.values()),13)
        self.assertEqual(sum(x['memory_bytes'] for x in parts.values()),14*GIB)
        self.assertFalse(combined['assumptions']['load_certified'])

    def test_phone_detection_rounding_and_limit(self):
        for count, limit in ((0,25),(24,25),(25,25),(26,50),(50,50),(51,100),(79,100),(89,100),
                             (100,100),(101,150),(125,150),(150,150),(151,200),(999,1000),(1000,1000)):
            self.assertEqual(RESOURCE.rounded_phone_capacity(count),limit)
        for value in (True,'79',-1,1001):
            with self.assertRaises(ValueError):
                RESOURCE.rounded_phone_capacity(value)

    def test_phone_inventory_offline_contacts_aliases_and_trunk_exclusion(self):
        devices = ('/DEVICE/1000/dial : PJSIP/1000\n/DEVICE/1001/dial : PJSIP/1001\n'
                   '/DEVICE/1002/dial : PJSIP/1000\n/DEVICE/1003/dial : PJSIP/desk-a\n'
                   '/DEVICE/1004/dial : SIP/1004\n/DEVICE/trunk/dial : PJSIP/trunk\n6 results found.\n')
        contacts = ('Contact: <Aor/ContactUri........> <Hash> <Status> <RTT(ms)>\n'
                    'Contact: 1000/sip:fixture-one 0123456789 Avail 1.000\n'
                    'Contact: 1000/sip:fixture-one abcdef0123 NonQual nan\n'
                    'Contact: desk-a/sip:fixture-two 0123abcdef Unavail nan\n'
                    'Contact: trunk/sip:provider ff01234567 Avail 2.000\nObjects found: 4\n')
        self.assertEqual(RESOURCE.internal_phone_inventory(devices,contacts),
                         {'configured_pjsip_devices':3,'registered_phone_contacts':3,'detected_phone_contacts':4})
        for bad_devices, bad_contacts in ((devices.replace('6 results','5 results'),contacts),
                  (devices.replace('PJSIP/desk-a','PJSIP/desk-a&arbitrary'),contacts),
                  (devices,contacts.replace('Objects found: 4','Objects found: 5')),
                  (devices,contacts.replace('abcdef0123','0123456789')),(devices,'No such command')):
            with self.assertRaises(ValueError):
                RESOURCE.internal_phone_inventory(bad_devices,bad_contacts)
        self.assertEqual(RESOURCE.internal_phone_inventory('0 results found.\n','')['detected_phone_contacts'],0)
        self.assertEqual(RESOURCE.internal_phone_inventory(devices,'No objects found.\n')['detected_phone_contacts'],3)

    def test_resource_indicators_match_actual_admission_and_shared_disks(self):
        measured=hardware()
        measured['filesystems'][0]['paths']=list(RESOURCE.FREE_BUDGETS)
        report=RESOURCE.evaluate(measured,50,100)
        self.assertTrue(all(check['ok'] is True for check in report['resource_checks'].values()))
        measured['effective_cpu_count']=1.9
        measured['effective_memory_bytes']=RESOURCE.minimum_reported_memory({}, 4 * GIB)-1
        measured['filesystems'][0]['available_bytes']=measured['filesystems'][0]['required_free_bytes']-1
        report=RESOURCE.evaluate(measured,50,100)
        self.assertTrue(all(check['ok'] is False for check in report['resource_checks'].values()))
        self.assertEqual({row['code'] for row in report['errors']},{'cpu_insufficient','memory_insufficient','free_space_insufficient'})
        # Separate temporary storage must not mark adequate persistent mounts red.
        measured['filesystems'][0]['paths'].remove('/tmp')
        measured['filesystems'][0]['available_bytes']=4*GIB
        measured['filesystems'].append({'device':'2','paths':['/tmp'],'available_bytes':1,
            'total_bytes':GIB,'required_free_bytes':100,'persistent':False})
        checks=RESOURCE.evaluate(measured,50,100)['resource_checks']
        self.assertTrue(checks['storage']['ok']);self.assertFalse(checks['temporary']['ok'])
        measured['filesystems'].pop()
        self.assertIsNone(RESOURCE.evaluate(measured,50,100)['resource_checks']['temporary']['ok'])

    def test_auto_detection_cli_preserves_saved_limits_and_rejects_unsafe_rounding(self):
        for count, cpu, expected_status, expected_limit in ((79,2,0,100),(89,2,0,100),(125,3,0,150),(125,2,2,150)):
            output=io.StringIO()
            with patch.object(RESOURCE,'detect_internal_phones',return_value={'detected_phone_contacts':count}), \
                 patch.object(RESOURCE,'probe_compute',return_value=(cpu,8*GIB)), \
                 patch.object(RESOURCE,'probe_storage',return_value=RESOURCE.storage_requirements()), \
                 patch.object(RESOURCE,'probe_filesystems',return_value=hardware()['filesystems']),contextlib.redirect_stdout(output):
                status=RESOURCE.main(['--check','--auto-phone-limit'])
            report=json.loads(output.getvalue())
            self.assertEqual((status,report['requested_phone_limit']),(expected_status,expected_limit))
            self.assertEqual(report['auto_phone_selection']['rounded_phone_capacity'],expected_limit)
        with patch.object(RESOURCE,'configured_limits',return_value={'desktop_client_limit':25,'phone_device_limit':79}), \
             patch.object(RESOURCE,'detect_internal_phones',side_effect=AssertionError('Upgrade must not re-detect')), \
             patch.object(RESOURCE,'probe_compute',return_value=(4,8*GIB)), \
             patch.object(RESOURCE,'probe_storage',return_value=RESOURCE.storage_requirements()), \
             patch.object(RESOURCE,'probe_filesystems',return_value=hardware()['filesystems']),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(RESOURCE.main(['--check','--config','/fixture/config','--auto-phone-limit']),0)
        self.assertEqual(json.loads(output.getvalue())['requested_phone_limit'],79)

    def test_phone_inventory_failure_is_actionable_and_redacted(self):
        for error in (OSError('private endpoint secret'),subprocess.TimeoutExpired('private route',3)):
            with patch.object(RESOURCE.subprocess,'run',side_effect=error):
                with self.assertRaises(RESOURCE.ResourceProbeError) as raised:
                    RESOURCE.detect_internal_phones()
                self.assertEqual(raised.exception.code,'phone_inventory_unavailable')
                self.assertNotIn('private',str(raised.exception))

    def test_invalid_phone_capacity_is_never_clamped(self):
        for phones in (True, '25', 0, 1001):
            with self.assertRaises(ValueError):
                RESOURCE.evaluate(hardware(), 50, phones)

    def test_cgroup_cpu_and_memory_limits_override_large_host(self):
        values = {'/cg/leaf/memory.max': str(12 * GIB), '/cg/leaf/cpu.max': '800000 100000',
                  '/cg/memory.max': str(8 * GIB), '/cg/cpu.max': '350000 100000'}
        with patch.object(RESOURCE.os, 'sched_getaffinity', return_value=set(range(32))), \
             patch.object(RESOURCE.Path, 'read_text', return_value='MemTotal:       134217728 kB\n'), \
             patch.object(RESOURCE, 'cgroup_directories', return_value=[(Path('/cg/leaf'), 'v2'), (Path('/cg'), 'v2')]), \
             patch.object(RESOURCE, 'read_limit', side_effect=lambda path: values.get(str(path))):
            self.assertEqual(RESOURCE.probe_compute(), (3.5, 8 * GIB))

    def test_affinity_remains_binding_when_cgroup_is_unlimited(self):
        with patch.object(RESOURCE.os, 'sched_getaffinity', return_value={0, 1}), \
             patch.object(RESOURCE.Path, 'read_text', return_value='MemTotal:       8388608 kB\n'), \
             patch.object(RESOURCE, 'cgroup_directories', return_value=[(Path('/cg'), 'v2')]), \
             patch.object(RESOURCE, 'read_limit', side_effect=lambda path: 'max' if path.name == 'memory.max' else 'max 100000'):
            self.assertEqual(RESOURCE.probe_compute(), (2.0, 8 * GIB))

    def test_cgroup_ancestor_limits_are_included(self):
        values = {'/proc/self/cgroup': '0::/service/worker\n',
                  '/proc/self/mountinfo': '31 20 0:28 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n'}
        with patch.object(RESOURCE.Path, 'read_text', lambda path, **kw: values[str(path)]), \
             patch.object(RESOURCE.Path, 'is_dir', return_value=True):
            paths = [str(path) for path, kind in RESOURCE.cgroup_directories()]
        self.assertEqual(paths, ['/sys/fs/cgroup/service/worker', '/sys/fs/cgroup/service', '/sys/fs/cgroup'])

    def test_subtree_cgroup_mount_enforces_the_leaf_cpu_and_memory_limits(self):
        # A container can expose /tenant/100 as the mount root. Appending the
        # whole membership would miss the enforced service leaf completely.
        values = {'/proc/self/cgroup': '0::/tenant/100/service\n',
                  '/proc/self/mountinfo': '31 20 0:28 /tenant/100 /sys/fs/cgroup rw - cgroup2 cgroup rw\n',
                  '/proc/meminfo': 'MemTotal:       8388608 kB\n',
                  '/sys/fs/cgroup/service/memory.max': str(GIB),
                  '/sys/fs/cgroup/service/cpu.max': '50000 100000',
                  '/sys/fs/cgroup/memory.max': 'max',
                  '/sys/fs/cgroup/cpu.max': 'max 100000'}
        def read(path, **kw):
            if str(path) not in values: raise FileNotFoundError(str(path))
            return values[str(path)]
        with patch.object(RESOURCE.Path, 'read_text', read), \
             patch.object(RESOURCE.Path, 'is_dir', lambda path: str(path) in ('/sys/fs/cgroup', '/sys/fs/cgroup/service')), \
             patch.object(RESOURCE.os, 'sched_getaffinity', return_value={0,1,2,3}):
            self.assertEqual(RESOURCE.probe_compute(), (0.5, GIB))
            self.assertEqual(RESOURCE.probe_memory_limit(), GIB)

    def test_v1_controller_mounts_use_their_actual_mountpoints_and_roots(self):
        values = {'/proc/self/cgroup': '4:cpu,cpuacct:/tenant/pbx\n5:memory:/tenant/pbx\n',
                  '/proc/self/mountinfo': '31 20 0:28 /tenant /limits/processor rw - cgroup cgroup rw,cpu,cpuacct\n'
                                          '32 20 0:29 /tenant /limits/memory rw - cgroup cgroup rw,memory\n'}
        with patch.object(RESOURCE.Path, 'read_text', lambda path, **kw: values[str(path)]), \
             patch.object(RESOURCE.Path, 'is_dir', return_value=True):
            rows = [(str(path), kind) for path,kind in RESOURCE.cgroup_directories()]
        self.assertEqual(rows, [('/limits/processor/pbx','cpu'),('/limits/processor','cpu'),
                                ('/limits/memory/pbx','memory'),('/limits/memory','memory')])

    def test_cgroup_mountpoint_kernel_escaping_is_decoded_before_limit_reads(self):
        values = {'/proc/self/cgroup': '0::/pbx\n',
                  '/proc/self/mountinfo': '31 20 0:28 / /limits/my\\040group rw - cgroup2 cgroup rw\n'}
        with patch.object(RESOURCE.Path, 'read_text', lambda path, **kw: values[str(path)]), \
             patch.object(RESOURCE.Path, 'is_dir', return_value=True):
            rows = [str(path) for path,kind in RESOURCE.cgroup_directories()]
        self.assertEqual(rows, ['/limits/my group/pbx','/limits/my group'])

    def test_unmapped_or_missing_current_cgroup_never_falls_back_to_host_capacity(self):
        for membership, root, present in [('/tenant/pbx','/other',True),('/tenant/pbx','/tenant',False)]:
            values = {'/proc/self/cgroup': '0::'+membership+'\n',
                      '/proc/self/mountinfo': '31 20 0:28 '+root+' /sys/fs/cgroup rw - cgroup2 cgroup rw\n'}
            with self.subTest(root=root,present=present), \
                 patch.object(RESOURCE.Path,'read_text',lambda path,**kw:values[str(path)]), \
                 patch.object(RESOURCE.Path,'is_dir',return_value=present), \
                 self.assertRaises(ValueError):
                list(RESOURCE.cgroup_directories())

    def test_same_filesystem_is_not_double_counted(self):
        usage = SimpleNamespace(f_blocks=80, f_bavail=13, f_frsize=GIB)
        with patch.object(RESOURCE, 'filesystem_types', return_value=[('/', 'ext4')]), \
             patch.object(RESOURCE.Path, 'exists', return_value=True), \
             patch.object(RESOURCE.Path, 'resolve', lambda path: path), \
             patch.object(RESOURCE.Path, 'stat', return_value=SimpleNamespace(st_dev=1)), \
             patch.object(RESOURCE.os, 'statvfs', return_value=usage):
            filesystems = RESOURCE.probe_filesystems()
        self.assertEqual(len(filesystems), 1)
        self.assertEqual(filesystems[0]['total_bytes'], 80 * GIB)
        self.assertEqual(filesystems[0]['required_free_bytes'], sum(RESOURCE.FREE_BUDGETS.values()))

    def test_tmpfs_is_not_counted_as_persistent_storage(self):
        with patch.object(RESOURCE, 'filesystem_types', return_value=[('/tmp', 'tmpfs'), ('/', 'ext4')]), \
             patch.object(RESOURCE.Path, 'exists', return_value=True), \
             patch.object(RESOURCE.Path, 'resolve', lambda path: path), \
             patch.object(RESOURCE.Path, 'stat', lambda path: SimpleNamespace(st_dev=2 if str(path) == '/tmp' else 1)), \
             patch.object(RESOURCE.os, 'statvfs', return_value=SimpleNamespace(f_blocks=80, f_bavail=30, f_frsize=GIB)):
            filesystems = RESOURCE.probe_filesystems()
        self.assertEqual(sum(item['total_bytes'] for item in filesystems if item['persistent']), 80 * GIB)
        self.assertEqual([item['required_free_bytes'] for item in filesystems], [sum(value for path, value in RESOURCE.FREE_BUDGETS.items() if path != '/tmp'), RESOURCE.FREE_BUDGETS['/tmp']])

    def test_overlay_volatile_mount_option_is_not_counted_as_durable_state(self):
        for module in (RESOURCE,):
            for option, persistent in (('volatile',False),('index=off',True),('xvolatile',True)):
                with self.subTest(option=option):
                    mountinfo='42 1 0:41 / / rw,relatime - overlay overlay rw,lowerdir=/lower,upperdir=/upper,workdir=/work,'+option+'\n'
                    with patch.object(module.Path,'read_text',return_value=mountinfo), \
                         patch.object(module.Path,'exists',return_value=True), \
                         patch.object(module.Path,'resolve',lambda path:path), \
                         patch.object(module.Path,'stat',return_value=SimpleNamespace(st_dev=41)), \
                         patch.object(module.os,'statvfs',return_value=SimpleNamespace(f_blocks=80,f_bavail=30,f_frsize=GIB)):
                        observed=module.probe_filesystems()
                    self.assertEqual(observed[0]['persistent'],persistent)
                    self.assertEqual(bool(observed[0]['volatile_targets']),not persistent)

    def test_protected_config_reads_only_valid_capacity(self):
        with tempfile.TemporaryDirectory(prefix='sls-capacity-config-') as name:
            path = Path(name) / 'config'
            for value in ({'secret': 'must-not-print'}, {'desktop_client_limit': 1000, 'phone_device_limit': 75}):
                path.write_text(json.dumps(value))
                self.assertEqual(RESOURCE.configured_limits(path), {
                    'desktop_client_limit': value.get('desktop_client_limit', 25),
                    'phone_device_limit': value.get('phone_device_limit', 25),
                    'deployment_profile': 'standard'})
            path.write_text(json.dumps({'deployment_profile': 'lite'}))
            self.assertEqual(RESOURCE.configured_limits(path), {
                'desktop_client_limit': 25, 'phone_device_limit': 25,
                'deployment_profile': 'lite'})
            for profile in (None, True, 'small', 'LITE'):
                path.write_text(json.dumps({'deployment_profile': profile}))
                with self.assertRaises(ValueError):
                    RESOURCE.configured_limits(path)
            for key in ('desktop_client_limit', 'phone_device_limit'):
                for value in (True, '100', 0, 1001):
                    path.write_text(json.dumps({key: value}))
                    with self.assertRaises(ValueError):
                        RESOURCE.configured_limits(path)
            path.chmod(0o666)
            with self.assertRaisesRegex(ValueError, 'private regular file'):
                RESOURCE.configured_limits(path)
            path.chmod(0o644)
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                RESOURCE.configured_limits(path)
            path.unlink()
            sentinel = Path(name) / 'sentinel'
            sentinel.write_text('{}')
            path.symlink_to(sentinel)
            with self.assertRaises(OSError):
                RESOURCE.configured_limits(path)

    def test_probe_failure_does_not_expose_config_exception(self):
        output = io.StringIO()
        with patch.object(RESOURCE, 'configured_limits', side_effect=ValueError('secret-token')), contextlib.redirect_stdout(output):
            status = RESOURCE.main(['--check', '--config', '/fixture/config'])
        self.assertEqual(status, 3)
        self.assertNotIn('secret-token', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['eligible_limit'], 0)

    def test_ambiguous_legacy_capacity_config_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='sls-capacity-ambiguous-') as name:
            path=Path(name)/'config'
            for raw in ('{"desktop_client_limit":25,"desktop_client_limit":1000}',
                        '{"phone_device_limit":25,"scope":{"id":1,"id":2}}',
                        '{"desktop_client_limit":25,"other":1e309}',
                        '{"desktop_client_limit":25,"other":NaN}'):
                with self.subTest(raw=raw):
                    path.write_text(raw)
                    with self.assertRaises(ValueError): RESOURCE.configured_limits(path)
                    self.assertEqual(path.read_text(),raw)

    def test_damaged_encryption_never_uses_default_capacity(self):
        envelopes = [
            {'format': 'unsupported', 'ciphertext': 'private-provider-secret'},
            {'format': None}, {'ciphertext': None}, {'key_id': 'missing'}, {'nonce': None},
        ]
        with tempfile.TemporaryDirectory(prefix='sls-capacity-envelope-') as name:
            path = Path(name) / 'config'
            for value in envelopes:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaisesRegex(ValueError, 'unsupported or damaged'):
                        RESOURCE.configured_limits(path)
                    output = io.StringIO()
                    with patch.object(RESOURCE, 'probe_compute', side_effect=AssertionError('Invalid configuration must stop admission')), \
                         contextlib.redirect_stdout(output):
                        self.assertEqual(RESOURCE.main(['--check', '--config', str(path)]), 3)
                    report = json.loads(output.getvalue())
                    self.assertEqual(report['eligible_limit'], 0)
                    self.assertNotIn('private-provider-secret', output.getvalue())

    @unittest.skipUnless(os.geteuid() == 0, 'Protected encryption helper fixtures require root')
    def test_authenticated_encrypted_capacity_and_tamper(self):
        with tempfile.TemporaryDirectory(prefix='sls-capacity-encrypted-') as name:
            folder = Path(name)
            keyring = folder / 'keys/config-keys.json'
            helper = folder / 'sls_config_crypto.py'
            helper.write_text((SOURCE.parent / helper.name).read_text().replace(
                'KEYRING_PATH = Path("/etc/sls-mass-notify/config-keys.json")',
                'KEYRING_PATH = Path(' + repr(str(keyring)) + ')'))
            helper.chmod(0o600)
            spec = importlib.util.spec_from_file_location('capacity_crypto_fixture', helper)
            crypto = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(crypto)
            crypto.initialize_keyring(keyring, os.getgid())
            path = folder / 'mass-notifications.config'
            path.write_bytes(crypto.encode_config({'desktop_client_limit': 100, 'phone_device_limit': 150}))
            path.chmod(0o640)
            with patch.object(RESOURCE, '__file__', str(folder / SOURCE.name)):
                self.assertEqual(RESOURCE.configured_limits(path), {
                    'desktop_client_limit': 100, 'phone_device_limit': 150,
                    'deployment_profile': 'standard'})
                damaged = json.loads(path.read_bytes())
                damaged['nonce'] = 'AAAAAAAAAAAAAAAA'
                path.write_text(json.dumps(damaged))
                with self.assertRaises(ValueError):
                    RESOURCE.configured_limits(path)

    def test_cli_override_preserves_the_other_saved_capacity(self):
        for arguments, expected in ((['--desktop-limit', '100'], (100, 75)),
                                    (['--phone-limit', '90'], (250, 90)),
                                    ([], (250, 75))):
            output = io.StringIO()
            with patch.object(RESOURCE, 'configured_limits', return_value={'desktop_client_limit': 250, 'phone_device_limit': 75}), \
                 patch.object(RESOURCE, 'probe_compute', return_value=(36, 48 * GIB)), \
                 patch.object(RESOURCE, 'probe_filesystems', return_value=hardware()['filesystems']), contextlib.redirect_stdout(output):
                status = RESOURCE.main(['--check', '--config', '/fixture/config', *arguments])
            report = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual((report['requested_limit'], report['requested_phone_limit']), expected)

    def test_lite_profile_is_a_bounded_two_gib_runtime_not_a_check_bypass(self):
        lite = RESOURCE.evaluate(hardware(cpu=2, memory=2), 25, 25, 'lite')
        self.assertEqual(lite['errors'], [])
        self.assertEqual(lite['deployment_profile'], 'lite')
        self.assertEqual((lite['eligible_limit'], lite['eligible_phone_limit']), (25, 25))
        self.assertEqual(lite['requirements']['memory_bytes'], 2 * GIB)
        self.assertEqual(lite['assumptions']['desktop_sse_limit'], 4)
        self.assertEqual(lite['assumptions']['maximum_synthesis_workers'], 1)
        self.assertEqual(lite['assumptions']['maximum_speech_queue'], 2)
        self.assertIn('memory_insufficient', [row['code'] for row in
            RESOURCE.evaluate(hardware(cpu=2, memory=2), 25, 25, 'standard')['errors']])
        for desktops, phones in ((26, 25), (25, 26)):
            with self.assertRaisesRegex(RESOURCE.ResourceProbeError, 'at most 25'):
                RESOURCE.capacity_requirements(desktops, phones, 'lite')
        with self.assertRaisesRegex(RESOURCE.ResourceProbeError, 'detected'):
            RESOURCE.rounded_phone_capacity(26, 'lite')

    def test_installer_profile_offer_uses_real_allocation_and_kernel_allowance(self):
        for memory, standard, lite in ((1, False, False), (2, False, True),
                (3, False, True), (3.8, True, False), (4, True, False), (8, True, False)):
            with self.subTest(memory=memory):
                report = RESOURCE.evaluate(hardware(memory=memory), 25, 25)
                self.assertEqual(report['profile_selection']['standard_memory_eligible'], standard)
                self.assertEqual(report['profile_selection']['lite_memory_eligible'], lite)
        constrained = hardware(memory=1.95)
        constrained['memory_limit_bytes'] = int(1.95 * GIB)
        self.assertFalse(RESOURCE.evaluate(constrained, 25, 25)['profile_selection']['lite_memory_eligible'])

    def test_explicit_profile_overrides_saved_profile_for_installer_conversion(self):
        output = io.StringIO()
        with patch.object(RESOURCE, 'configured_limits', return_value={
                'desktop_client_limit': 25, 'phone_device_limit': 25,
                'deployment_profile': 'standard'}), \
             patch.object(RESOURCE, 'probe_compute', return_value=(2, 2 * GIB)), \
             patch.object(RESOURCE, 'probe_filesystems', return_value=hardware(available=8)['filesystems']), \
             contextlib.redirect_stdout(output):
            status = RESOURCE.main(['--check', '--config', '/fixture/config', '--profile', 'lite'])
        report = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(report['deployment_profile'], 'lite')

    def test_standalone_bootstrap_matches_packaged_helper(self):
        installer = (ROOT / 'tools/install_release.sh').read_text()
        embedded = installer.split("<<'SLS_RESOURCE_CAPACITY_PY'\n", 1)[1].split('\nSLS_RESOURCE_CAPACITY_PY\n', 1)[0]
        self.assertEqual(embedded, SOURCE.read_text().rstrip())
        main = installer.split('main() {\n', 1)[1]
        self.assertLess(main.index('preflight_hardware_requirements'), main.index('require_freepbx'))
        self.assertLess(main.index('verify_staged_hardware_requirements'), main.index('activate_staged_module'))

    def test_installer_cannot_bypass_failed_preflight(self):
        with tempfile.TemporaryDirectory(prefix='sls-capacity-main-') as name:
            fixture = Path(name)
            framework = fixture / 'framework-module.xml'
            framework.write_text('<module><rawname>framework</rawname><version>17.0.1</version></module>')
            # Exercise the real profile validator against private prerequisite
            # evidence. CI has no installed FreePBX, and this fixture must not
            # depend on or modify the host's Framework module.
            source = (ROOT / 'tools/install_release.sh').read_text()
            framework_path = '/var/www/html/admin/modules/framework/module.xml'
            self.assertIn(framework_path, source)
            installer = fixture / 'install_release.sh'
            installer.write_text(source.replace(framework_path, str(framework)))
            script = r'''
source "$1"
LOG_FILE="$2/log"
ensure_installer_log_prerequisites() { :; }
acquire_update_coordination() { :; }
acquire_maintenance_coordination() { :; }
preflight_hardware_requirements() { return 2; }
record_install_failure() { :; }
require_freepbx() { printf 'unexpected\n' >"$2/forbidden"; }
main
'''
            result = subprocess.run(['bash', '-c', script, '_', str(installer), name],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((Path(name) / 'forbidden').exists())

    def test_installer_checks_saved_capacity_before_dependencies(self):
        with tempfile.TemporaryDirectory(prefix='sls-capacity-saved-') as name:
            fixture = Path(name)
            (fixture / 'config').write_text('{"desktop_client_limit":1000}')
            script = r'''
source "$1"
CONFIG_FILE="$2/config"
LOG_FILE="$2/log"
bootstrap_resource_capacity() {
  [[ "$*" == "--check --mode prepare --reserve-install-workspace --config $CONFIG_FILE" ]] || return 99
  printf '{"schema":1,"requested_limit":1000,"errors":[{"code":"cpu_insufficient","message":"More CPU cores are required for 1000 desktops."}]}\n'
  return 2
}
preflight_hardware_requirements
'''
            result = subprocess.run(['bash', '-c', script, '_', str(ROOT / 'tools/install_release.sh'), name],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('[cpu_insufficient] More CPU cores are required for 1000 desktops.', result.stdout)
            self.assertNotIn('"requested_limit":1000', result.stdout)
            self.assertIn('"requested_limit":1000', (fixture / 'log').read_text())

    def test_normal_prepare_chooses_install_sized_workspace_before_creating_release_workspaces(self):
        with tempfile.TemporaryDirectory(prefix='sls-prepare-install-workspace-') as name:
            fixture = Path(name)
            probe = fixture / 'probe.py'
            probe.write_text('''import contextlib, importlib.util, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('capacity', Path(sys.argv[1]))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
def filesystems(budgets,inodes=None):
    scratch=next(path for path in ('/tmp','/var/tmp',r.PRIVATE_INSTALL_TEMP) if path in budgets)
    return [{'device':'scratch','paths':[scratch],'total_bytes':8*r.GIB,
             'available_bytes':300*r.MIB if scratch=='/tmp' else 4*r.GIB,
             'required_free_bytes':budgets[scratch],'persistent':True,'filesystem_type':'ext4',
             'available_inodes':50000,'required_inodes':(inodes or {}).get(scratch,0)},
            {'device':'persistent','paths':[path for path in budgets if path!=scratch],
             'total_bytes':32*r.GIB,'available_bytes':16*r.GIB,'persistent':True,
             'required_free_bytes':sum(value for path,value in budgets.items() if path!=scratch)}]
with contextlib.ExitStack() as stack:
    for key,value in [('probe_cpu_isa',{}),('probe_compute',(2,4*r.GIB)),
                      ('probe_memory_limit',None),('detect_internal_phones',{'configured_pjsip_devices':0,'registered_phone_contacts':0,'detected_phone_contacts':0}),
                      ('probe_runtime_speech_scratch',{'path':'/tmp','available_bytes':300*r.MIB,'required_free_bytes':221*r.MIB,'read_only':False,'inodes_exhausted':False})]:
        stack.enter_context(patch.object(r,key,return_value=value))
    stack.enter_context(patch.object(r,'probe_storage',side_effect=lambda mode,payloads=None,**kw:r.storage_requirements(mode=mode,payloads=payloads)))
    stack.enter_context(patch.object(r,'trusted_temporary_directory',return_value=True))
    stack.enter_context(patch.object(r,'probe_filesystems',side_effect=filesystems))
    stack.enter_context(patch.object(r.os,'statvfs',return_value=SimpleNamespace(f_frsize=4096)))
    raise SystemExit(r.main(sys.argv[2:]))
''')
            script = r'''
source "$1"
CONFIG_FILE="$2/absent.config"
LOG_FILE="$2/installer.log"
bootstrap_resource_capacity() { /usr/bin/python3 -I "$PROBE" "$RESOURCE_SOURCE" "$@"; }
select_install_temp_root() {
  /usr/bin/python3 -I -c 'import json,sys;print(json.loads(sys.argv[1])["requirements"]["storage"]["temporary_directory"])' "$1" >"$SELECTED"
}
preflight_hardware_requirements
'''
            result = subprocess.run(['bash', '-c', script, '_', str(ROOT/'tools/install_release.sh'), name],
                env={**os.environ,'PROBE':str(probe),'RESOURCE_SOURCE':str(SOURCE),'SELECTED':str(fixture/'selected')},
                capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual((fixture/'selected').read_text().strip(),'/var/tmp',
                             'Preparation must not pin300MiB /tmp when full installation needs the sufficient /var/tmp.')

    def test_installer_carries_only_verified_fresh_rounding(self):
        with tempfile.TemporaryDirectory(prefix='sls-capacity-fresh-') as name:
            script=r'''
source "$1"
CONFIG_FILE="$2/absent.config"
LOG_FILE="$2/log"
bootstrap_resource_capacity() {
  [[ "$*" == "--check --mode prepare --reserve-install-workspace --desktop-limit 25 --auto-phone-limit" ]] || return 99
  printf '%s\n' "$FIXTURE_REPORT"
}
preflight_hardware_requirements || exit $?
[[ "$FRESH_PHONE_CAPACITY" == "$FIXTURE_LIMIT" ]]
'''
            for count,limit in ((4,25),(79,100),(89,100),(125,150)):
                report={'deployment_profile':'standard','profile_selection':{'standard_memory_eligible':True,'lite_memory_eligible':False},'requested_phone_limit':limit,'auto_phone_selection':{'detected_phone_contacts':count,
                        'rounded_phone_capacity':limit},'errors':[]}
                result=subprocess.run(['bash','-c',script,'fixture',str(ROOT/'tools/install_release.sh'),name],
                    env={**os.environ,'FIXTURE_REPORT':json.dumps(report),'FIXTURE_LIMIT':str(limit)},
                    capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            report['requested_phone_limit']=100
            result=subprocess.run(['bash','-c',script,'fixture',str(ROOT/'tools/install_release.sh'),name],
                env={**os.environ,'FIXTURE_REPORT':json.dumps(report),'FIXTURE_LIMIT':'100'},
                capture_output=True,text=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((Path(name)/'absent.config').exists())

            lite_script=script.replace(
                'source "$1"', 'source "$1" --lite').replace(
                '--auto-phone-limit"', '--auto-phone-limit --profile lite"')
            lite={'deployment_profile':'lite','profile_selection':{'standard_memory_eligible':False,'lite_memory_eligible':True},'requested_phone_limit':25,
                  'auto_phone_selection':{'detected_phone_contacts':25,'rounded_phone_capacity':25},'errors':[]}
            result=subprocess.run(['bash','-c',lite_script,'fixture',str(ROOT/'tools/install_release.sh'),name],
                env={**os.environ,'FIXTURE_REPORT':json.dumps(lite),'FIXTURE_LIMIT':'25'},
                capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_privileged_probe_ignores_writable_working_directory_modules(self):
        with tempfile.TemporaryDirectory(prefix='sls-capacity-imports-') as name:
            fixture = Path(name)
            marker = fixture / 'unexpected-import'
            (fixture / 'json.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\nraise RuntimeError("unsafe import")\n')
            result = subprocess.run(['bash', '-c', 'source "$1"; bootstrap_resource_capacity --check', '_',
                                     str(ROOT / 'tools/install_release.sh')], cwd=fixture,
                                    env={**os.environ, 'PYTHONPATH': str(fixture)}, capture_output=True, text=True, timeout=10)
            self.assertFalse(marker.exists())
            self.assertEqual(json.loads(result.stdout)['schema'], 1)



class InstallerSpoolWorkspaceTests(unittest.TestCase):
    PRIVATE = '/var/spool/sls-mass-notify-installer-tmp'

    def setUp(self):
        import pwd
        self.account = pwd.getpwnam('nobody')
        self.temp = tempfile.TemporaryDirectory(prefix='sls-private-workspace-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'filesystem'
        self.root.mkdir(mode=0o755)
        (self.root/'var').mkdir(mode=0o755)
        (self.root/'var/spool').mkdir(mode=0o755)
        for directory in (self.root,self.root/'var',self.root/'var/spool'):directory.chmod(0o755)
        self.path = self.root/self.PRIVATE.lstrip('/')
        self.account_patch = patch.object(RESOURCE.pwd, 'getpwnam', return_value=self.account)
        self.account_patch.start(); self.addCleanup(self.account_patch.stop)

    def functions(self):
        import ast
        source=(ROOT/'tools/install_release.sh').read_text()
        body=source.split("<<'PYSLSINSTALLTEMP'\n",1)[1].split('\nPYSLSINSTALLTEMP',1)[0]
        tree=ast.parse(body)
        keep=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef)) or isinstance(n,ast.Assign) and any(isinstance(a,ast.Name)and a.id=='PRIVATE_INSTALL_TEMP'for a in n.targets)]
        namespace={'__name__':'inert_workspace_functions'}
        exec(compile(ast.Module(body=keep,type_ignores=[]),'inert-workspace-functions','exec'),namespace)
        return namespace

    def report(self,state):
        return {'requirements':{'storage':{'temporary_directory':self.PRIVATE,'mode':'prepare','install_workspace_reserved':True,'temporary_directory_state':state}},
                'hardware':{'filesystems':[{'paths':[self.PRIVATE],'required_free_bytes':4096,'required_inodes':2,'filesystem_type':'ext4','read_only':False,'volatile_targets':[]}]}}

    def test_normal_reserved_prepare_can_use_spool_without_changing_inspection(self):
        def mounts(budgets,inode_budgets=None):
            scratch=next(p for p in('/tmp','/var/tmp',self.PRIVATE)if p in budgets)
            return [{'device':'scratch','paths':[scratch],'available_bytes':(8*GIB if scratch==self.PRIVATE else 300*RESOURCE.MIB),'required_free_bytes':budgets[scratch],
                     'persistent':True,'filesystem_type':'ext4','available_inodes':50000,'required_inodes':(inode_budgets or{}).get(scratch,0)}]
        state={'path':self.PRIVATE,'exists':False,'allocation_unit':4096}
        with patch.object(RESOURCE,'trusted_temporary_directory',return_value=True),patch.object(RESOURCE,'private_install_temporary_state',return_value=state,create=True),patch.object(RESOURCE,'probe_filesystems',side_effect=mounts),patch.object(RESOURCE.os,'statvfs',return_value=SimpleNamespace(f_frsize=4096)):
            normal,_=RESOURCE.probe_storage_filesystems(RESOURCE.storage_requirements(mode='prepare'),reserve_install_workspace=True)
            inspect,_=RESOURCE.probe_storage_filesystems(RESOURCE.storage_requirements(mode='prepare'))
        self.assertEqual(normal['temporary_directory'],self.PRIVATE)
        self.assertEqual(inspect['temporary_directory'],'/tmp')

    def test_absent_private_workspace_is_forecast_without_creation(self):
        state=RESOURCE.private_install_temporary_state(root=self.root,allow_missing=True)
        self.assertFalse(state['exists']);self.assertFalse(self.path.exists())
        self.assertEqual(state['gid'],self.account.pw_gid)

    def test_existing_private_workspace_requires_exact_role(self):
        for kind in ('valid','symlink','file','mode','owner','group'):
            with self.subTest(kind=kind):
                if kind=='symlink':self.path.symlink_to(self.root/'var')
                elif kind=='file':self.path.write_bytes(b'preserved')
                else:
                    self.path.mkdir(mode=0o710);os.chown(self.path,0,self.account.pw_gid);self.path.chmod(0o710)
                    if kind=='mode':self.path.chmod(0o770)
                    if kind=='owner':os.chown(self.path,self.account.pw_uid,self.account.pw_gid)
                    if kind=='group':os.chown(self.path,0,0)
                if kind=='valid':self.assertTrue(RESOURCE.private_install_temporary_state(root=self.root)['exists'])
                else:
                    before=self.path.lstat()
                    with self.assertRaises((ValueError,OSError,RESOURCE.ResourceProbeError)):RESOURCE.private_install_temporary_state(root=self.root,allow_missing=True)
                    self.assertEqual(before,self.path.lstat())
                if self.path.is_dir()and not self.path.is_symlink():self.path.rmdir()
                else:self.path.unlink()

    def test_admitted_creation_is_private_and_native_traversal_only(self):
        funcs=self.functions();state=RESOURCE.private_install_temporary_state(root=self.root,allow_missing=True)
        result=funcs['select_private_install_temporary'](self.report(state),root=self.root)
        self.assertEqual(self.path.stat().st_mode&0o777,0o710);self.assertEqual(self.path.stat().st_gid,self.account.pw_gid)
        self.assertEqual(result['identity']['ino'],self.path.stat().st_ino)
        self.root.parent.chmod(0o755)
        child=self.path/'probe';child.mkdir(mode=0o750);os.chown(child,self.account.pw_uid,self.account.pw_gid);(child/'owned').write_text('test');os.chown(child/'owned',self.account.pw_uid,self.account.pw_gid);(child/'owned').chmod(0o640)
        command=['/usr/bin/python3','-I','-c','import os,sys; assert open(sys.argv[1]).read()=="test";\ntry: os.listdir(sys.argv[2]); raise AssertionError("parent list allowed")\nexcept PermissionError: pass\ntry: open(sys.argv[2]+"/forbidden","w"); raise AssertionError("parent create allowed")\nexcept PermissionError: pass',str(child/'owned'),str(self.path)]
        result=subprocess.run(command,user=self.account.pw_uid,group=self.account.pw_gid,extra_groups=[],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_parent_change_after_admission_refuses(self):
        funcs=self.functions();state=RESOURCE.private_install_temporary_state(root=self.root,allow_missing=True)
        original=self.root/'var/spool';original.rename(self.root/'var/moved');original.symlink_to(self.root/'var/moved',target_is_directory=True)
        with self.assertRaises((ValueError,OSError)):funcs['select_private_install_temporary'](self.report(state),root=self.root)
        self.assertFalse((self.root/'var/moved'/self.path.name).exists())

    def test_cleanup_never_removes_unknown_or_other_invocation_contents(self):
        funcs=self.functions();state=RESOURCE.private_install_temporary_state(root=self.root,allow_missing=True)
        selected=funcs['select_private_install_temporary'](self.report(state),root=self.root)
        keep=self.path/'unknown';keep.write_bytes(b'retained evidence')
        self.assertFalse(funcs['cleanup_private_install_temporary'](selected['identity'],root=self.root));self.assertEqual(keep.read_bytes(),b'retained evidence')
        keep.unlink();self.assertTrue(funcs['cleanup_private_install_temporary'](selected['identity'],root=self.root));self.assertFalse(self.path.exists())

    def test_private_scratch_shares_actual_device_byte_and_inode_budgets(self):
        for separate in (False,True):
            with self.subTest(separate=separate),patch.object(RESOURCE,'filesystem_types',return_value=[('/','ext4')]),patch.object(RESOURCE.Path,'exists',return_value=True),patch.object(RESOURCE.Path,'resolve',lambda p:p),patch.object(RESOURCE.Path,'stat',lambda p:SimpleNamespace(st_dev=2 if separate and str(p)==self.PRIVATE else 1)),patch.object(RESOURCE.os,'statvfs',return_value=SimpleNamespace(f_blocks=100000,f_bavail=90000,f_frsize=4096,f_flag=0,f_files=10000,f_favail=9000)):
                rows=RESOURCE.probe_filesystems({self.PRIVATE:200,'/var/lib/asterisk':100},{self.PRIVATE:9,'/var/lib/asterisk':4})
            selected=next(row for row in rows if self.PRIVATE in row['paths'])
            self.assertEqual(selected['required_free_bytes'],200 if separate else 300)
            self.assertEqual(selected['required_inodes'],9 if separate else 13)

    def test_private_workspace_never_waives_runtime_or_persistent_refusals(self):
        storage=RESOURCE.storage_requirements(temporary_directory=self.PRIVATE)
        for change,code in (({'read_only':True},'storage_read_only'),({'available_inodes':0,'required_inodes':1,'inodes_exhausted':True},'storage_inodes_exhausted'),({'filesystem_type':'tmpfs','persistent':False,'volatile_targets':[self.PRIVATE]},'storage_not_persistent'),({},'runtime_speech_workspace_insufficient')):
            row={'device':'all','paths':list(storage['free_budgets_bytes']),'available_bytes':20*GIB,'required_free_bytes':sum(storage['free_budgets_bytes'].values()),'persistent':True,'filesystem_type':'ext4',**change}
            machine={'effective_cpu_count':2,'effective_memory_bytes':4*GIB,'storage':storage,'filesystems':[row],'runtime_speech_scratch':{'path':'/tmp','available_bytes':100*RESOURCE.MIB,'required_free_bytes':221*RESOURCE.MIB,'read_only':False,'inodes_exhausted':False}}
            report=RESOURCE.evaluate(machine,25);self.assertIn(code,[e['code']for e in report['errors']]);self.assertEqual(report['eligible_limit'],0)

    def test_lost_capacity_or_changed_native_identity_refuses_creation(self):
        funcs=self.functions();state=RESOURCE.private_install_temporary_state(root=self.root,allow_missing=True)
        for kind in ('bytes','inodes','readonly','uid'):
            with self.subTest(kind=kind):
                report=self.report(state)
                if kind=='uid':report['requirements']['storage']['temporary_directory_state']={**state,'uid':0}
                else:
                    row=report['hardware']['filesystems'][0]
                    if kind=='bytes':row['required_free_bytes']=state['available_bytes']+1
                    if kind=='inodes':row['required_inodes']=state['available_inodes']+1
                    if kind=='readonly':row['read_only']=True
                with self.assertRaises((ValueError,OSError)):funcs['select_private_install_temporary'](report,root=self.root)
                self.assertFalse(self.path.exists())

    def test_all_authenticated_consumers_keep_the_same_private_role(self):
        import ast
        expected=ast.dump(ast.parse((ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_resource_capacity.py').read_text()).body[next(i for i,n in enumerate(ast.parse((ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_resource_capacity.py').read_text()).body)if isinstance(n,ast.FunctionDef)and n.name=='private_install_temporary_state')],include_attributes=False)
        for name in ('sls_privileged_install.py','sls_upgrade_trust.py'):
            tree=ast.parse((ROOT/'slsmassnotifyserver/bin/sls_mass_notify'/name).read_text());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='private_install_temporary_state');self.assertEqual(ast.dump(node,include_attributes=False),expected)
        source=(ROOT/'tools/install_release.sh').read_text();body=source.split("<<'PYSLSINSTALLTEMP'\n",1)[1].split('\nPYSLSINSTALLTEMP',1)[0];node=next(n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)and n.name=='private_install_temporary_state');self.assertEqual(ast.dump(node,include_attributes=False),expected)

    def test_forced_prepared_private_root_cannot_be_forecast_after_loss(self):
        def state(*args,**kwargs):
            if not kwargs.get('allow_missing'):raise FileNotFoundError('prepared root lost')
            return {'exists':False,'allocation_unit':4096}
        with patch.object(RESOURCE,'private_install_temporary_state',side_effect=state),patch.object(RESOURCE,'probe_filesystems',return_value=[{'paths':[self.PRIVATE],'available_bytes':8*GIB,'required_free_bytes':4096}]):
            with self.assertRaises(RESOURCE.ResourceProbeError):RESOURCE.probe_storage_filesystems(RESOURCE.storage_requirements(temporary_directory=self.PRIVATE),self.PRIVATE)

class FreshReleaseStorageProofTests(unittest.TestCase):
    """A fresh budget needs authenticated review, never an absent module alone."""
    DATA = '/var/lib/asterisk/SLS_Mass_Notifications_Plugin'
    JOURNAL = '/var/lib/sls-mass-notify-installer'
    SETTINGS = ('RECOVERY_DIR', 'INSTALL_BOOTSTRAP_DIR', 'UPGRADE_TRUST_DIR',
                'CONFIG_SNAPSHOT', 'CONFIG_HASH_BEFORE', 'PENDING_CONFIG_STATE',
                'PENDING_CONFIG_PATH', 'PENDING_CONFIG_SNAPSHOT', 'PENDING_CONFIG_HASH',
                'MODULE_BACKUP_DIR', 'STAGING_DIR', 'HAD_EXISTING_MODULE',
                'MODULE_WAS_ENABLED', 'MODULE_ACTIVATED', 'STATIC_MUTATION_STARTED',
                'ORIGINAL_SYSTEM_TIMEZONE', 'SYSTEM_TIMEZONE_CHANGED')
    LOCKS = ('enterprise-worker.lock', 'phone-history-retention.lock',
             'schedule-runner.lock', 'schedule-worker.lock', 'announcement-send.lock',
             'announcement-activity.lock', 'weather-observation.lock',
             'weather-dispatch-worker.lock', 'weather-external-worker.lock',
             'xweather-poll.lock', 'sls_mass_notify_nws_poll.lock',
             'nws-audio-delivery.lock', 'test-cooldown.ts.lock',
             'audio-reservations.lock', 'mass-notifications.config.lock')

    def setUp(self):
        try:
            self.native = RESOURCE.pwd.getpwnam('asterisk')
        except KeyError:
            self.native = SimpleNamespace(pw_uid=999, pw_gid=996)
        self.lookup = patch.object(RESOURCE.pwd, 'getpwnam', return_value=self.native)
        self.lookup.start()
        self.addCleanup(self.lookup.stop)

    def api(self):
        capture = getattr(RESOURCE, 'capture_fresh_release_proof', None)
        reader = getattr(RESOURCE, 'read_fresh_release_proof', None)
        self.assertTrue(callable(capture), 'Authenticated fresh storage capture is missing')
        self.assertTrue(callable(reader), 'Authenticated fresh storage reader is missing')
        return capture, reader

    def fixture(self, root, after_abandon=False):
        root.mkdir(mode=0o700)
        def put(path, value, mode=0o600):
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(value if isinstance(value, bytes) else
                             (json.dumps(value, sort_keys=True) + '\n').encode())
            path.chmod(mode)
        review = root/'var/spool/sls-mass-notify-installer-tmp/review'
        candidate = root/'var/spool/sls-mass-notify-installer-tmp/stage/slsmassnotifyserver'
        body = b'<module><rawname>slsmassnotifyserver</rawname><version>0.2.0-beta</version></module>'
        put(candidate/'module.xml', body)
        inventory = {'schema': 1, 'module': 'slsmassnotifyserver', 'version': '0.2.0-beta',
                     'source': {'kind': 'publisher-ed25519', 'archive_sha256': 'a'*64},
                     'files': {'module.xml': {'sha256': hashlib.sha256(body).hexdigest(),
                              'target': 'admin/modules/slsmassnotifyserver/module.xml'}}}
        encoded = (json.dumps(inventory, sort_keys=True) + '\n').encode()
        digest = hashlib.sha256(encoded).hexdigest()
        generation = review/'registry'/('slsmassnotifyserver-' + digest)
        put(generation/'inventory.json', encoded)
        put(generation/'module/module.xml', body)
        put(review/'registry/slsmassnotifyserver.active.json',
            {'generation': generation.name, 'sha256': digest})
        put(review/'previous-web-approval.json', {'slsmassnotifyserver': None})
        put(review/'previous-root-approval.json',
            {'schema': 1, 'source': 'fresh-install', 'files': {}, 'root_jobs': []})
        if after_abandon:
            history = root/self.JOURNAL.lstrip('/')/('transaction-' + 'b'*24)
            put(history/'transaction.json', self.journal(history, 'abandoned'))
            history.parent.chmod(0o700)
            data = root/self.DATA.lstrip('/')
            for name in self.LOCKS:
                put(data/name, b'', 0o640)
            for index in range(16):
                put(data/'live-paging-slots'/('global-' + str(index) + '.lock'), b'', 0o640)
            diagnostic = {'version': 1, 'failed_at': '2026-11-14T21:17:46+00:00',
                          'stage': 'configuration coordination',
                          'message': 'SLL Mass Notify Server installation did not complete.',
                          'solution': 'Review the failed storage admission before retrying.',
                          'log': '/tmp/slsmassnotifyserver-install.log',
                          'error_category': 'install_command_failed', 'exit_code': 1}
            put(data/'install-failure.json', diagnostic, 0o640)
            for path in (data, *data.rglob('*')):
                os.chown(path, self.native.pw_uid, self.native.pw_gid)
                if path.is_dir(): path.chmod(0o750)
        review.chmod(0o700)
        return review, candidate, put

    def journal(self, path, phase='prepared'):
        settings = {key: '' for key in self.SETTINGS}
        settings.update({key: '0' for key in ('HAD_EXISTING_MODULE', 'MODULE_WAS_ENABLED',
                        'MODULE_ACTIVATED', 'STATIC_MUTATION_STARTED', 'SYSTEM_TIMEZONE_CHANGED')})
        settings.update(PENDING_CONFIG_STATE='absent', UPGRADE_TRUST_DIR=str(path/'approval'),
                        INSTALL_BOOTSTRAP_DIR=str(path/'bootstrap'))
        return {'schema': 1, 'directory': str(path), 'phase': phase, 'created_at': 1,
                'updated_at': 2, 'stage': 'configuration coordination', 'stage_at': 2,
                'settings': settings}

    def retain(self, root, review, proof, put):
        current = root/self.JOURNAL.lstrip('/')/('transaction-' + 'c'*24)
        current.mkdir(mode=0o700, parents=True)
        current.parent.chmod(0o700)
        moved = current/'approval'
        shutil.copytree(review, moved)
        shutil.rmtree(review)
        put(moved/'resource-relationship-proof.json', proof)
        put(current/'transaction.json', self.journal(current))
        return moved

    def test_actual_iso_geometry_excludes_only_proven_absent_previous_release_costs(self):
        import inspect
        self.assertIn('previous_release_required', inspect.signature(RESOURCE.storage_requirements).parameters,
                      'The default-conservative previous-release reservation decision is missing')
        old = RESOURCE.storage_requirements(mode='install')
        fresh = RESOURCE.storage_requirements(mode='install', previous_release_required=False)
        journal = RESOURCE.INSTALLER_JOURNAL
        excluded = 50*RESOURCE.MIB + 5000*4096 + 64*RESOURCE.MIB + 16384 + 4096
        self.assertEqual(excluded, 140038144)
        self.assertEqual(old['free_budgets_bytes'][journal] - fresh['free_budgets_bytes'][journal], excluded)
        for path, parts in old['component_budgets_bytes'].items():
            for name, value in parts.items():
                if path == journal and name == 'reviewed_previous_and_candidate_sources':
                    value -= 50*RESOURCE.MIB + 5000*4096
                elif path == journal and name == 'previous_release_download_and_metadata':
                    value = 0
                self.assertEqual(fresh['component_budgets_bytes'][path][name], value, (path, name))
        self.assertEqual(1911960841 - excluded, 1771922697)
        self.assertEqual(1805651968 - (1911960841 - excluded), 33729271)
        self.assertEqual(fresh['inode_budgets'], old['inode_budgets'])
        self.assertEqual(RESOURCE.storage_requirements(mode='prepare')['component_budgets_bytes'],
                         RESOURCE.storage_requirements(mode='prepare', previous_release_required=False)['component_budgets_bytes'])

    def test_current_abandoned_preparation_locks_and_diagnostic_are_preserved(self):
        capture, reader = self.api()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root'
            review, candidate, put = self.fixture(root, after_abandon=True)
            diagnostic = root/self.DATA.lstrip('/')/'install-failure.json'
            original = diagnostic.read_bytes()
            proof = capture(review, candidate, 'known_absent', prefix=root)
            self.assertIsInstance(proof, dict)
            moved = self.retain(root, review, proof, put)
            self.assertIsInstance(reader(moved, candidate, prefix=root), dict)
            self.assertEqual(diagnostic.read_bytes(), original)
            self.assertEqual(len(list((root/self.DATA.lstrip('/')).rglob('*.lock'))), 31)

    def test_established_unknown_and_nonterminal_states_keep_full_reservation(self):
        capture, reader = self.api()
        mutations = {
            'runtime': lambda root, review, put: put(root/'usr/local/bin/sls_mass_notify/old.py', b'old'),
            'keyring': lambda root, review, put: put(root/'etc/sls-mass-notify/config-keys.json', b'{}'),
            'trust': lambda root, review, put: put(root/'var/lib/sls-mass-notify-trust/publisher-trust.json', b'{}'),
            'config': lambda root, review, put: put(root/self.DATA.lstrip('/')/'mass-notifications.config', b'{}', 0o640),
            'pending': lambda root, review, put: put(root/self.DATA.lstrip('/')/'mass-notifications.pending.config', b'{}', 0o640),
            'unknown_DATA': lambda root, review, put: put(root/self.DATA.lstrip('/')/'unknown.lock', b'', 0o640),
            'prior_snapshot': lambda root, review, put: put(root/self.JOURNAL.lstrip('/')/('transaction-'+'b'*24)/'config.snapshot', b'old'),
            'nonterminal': lambda root, review, put: put(root/self.JOURNAL.lstrip('/')/('transaction-'+'b'*24)/'transaction.json', self.journal(root/self.JOURNAL.lstrip('/')/('transaction-'+'b'*24), 'prepared')),
            'upgrade_approval': lambda root, review, put: put(review/'previous-root-approval.json', {'schema':1,'source':'publisher-verified-previous-release','files':{},'root_jobs':[]}),
            'prior_download': lambda root, review, put: put(review/'previous-release/old.tgz', b'old'),
            'prior_console': lambda root, review, put: put(root/'usr/local/bin/slsconsole', b'old'),
            'prior_cron': lambda root, review, put: put(root/'etc/cron.d/old', b'* * * * * root /usr/local/bin/sls_mass_notify/old.sh\n', 0o644),
            'retained_generation': lambda root, review, put: put(root/'var/lib/sls-mass-notify-trust/slsmassnotifyserver-old/inventory.json', b'{}'),
            'unknown_trust': lambda root, review, put: put(root/'var/lib/sls-mass-notify-trust/unknown', b''),
            'public_API': lambda root, review, put: put(root/'var/www/html/api/sipnotify/index.php', b'old'),
            'piper': lambda root, review, put: put(root/'usr/local/bin/piper', b'old'),
            'recording': lambda root, review, put: put(root/'var/lib/asterisk/sounds/en/custom/NWS_alert.wav', b'old'),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)/'root';review, candidate, put = self.fixture(root, after_abandon=True)
                mutate(root, review, put)
                self.assertIsNone(capture(review, candidate, 'known_absent', prefix=root))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';review,candidate,put=self.fixture(root)
            self.assertIsNone(capture(review,candidate,'unknown',prefix=root))
            self.assertIsNone(capture(review,candidate,'known_present',prefix=root))
            self.assertIsNone(reader(review,candidate,prefix=root))

    def test_late_changes_and_unprotected_capsule_cannot_select_fresh_budget(self):
        capture, reader = self.api()
        for change in ('candidate', 'journal', 'snapshot', 'proof_mode', 'proof_symlink', 'proof_hardlink',
                       'review_parent_mode', 'history', 'unknown_lock', 'nonroot'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'root';review,candidate,put=self.fixture(root, after_abandon=True)
                proof=capture(review,candidate,'known_absent',prefix=root)
                self.assertIsInstance(proof,dict)
                moved=self.retain(root,review,proof,put)
                if change=='candidate':put(candidate/'module.xml',b'changed')
                elif change=='journal':put(moved.parent/'transaction.json',self.journal(moved.parent,'mutating'))
                elif change=='snapshot':put(moved.parent/'config.snapshot',b'old')
                elif change=='proof_mode':(moved/'resource-relationship-proof.json').chmod(0o644)
                elif change=='proof_symlink':
                    target=moved/'kept-proof.json';(moved/'resource-relationship-proof.json').rename(target)
                    (moved/'resource-relationship-proof.json').symlink_to(target)
                elif change=='proof_hardlink':os.link(moved/'resource-relationship-proof.json',moved/'second-proof.json')
                elif change=='review_parent_mode':moved.chmod(0o722)
                elif change=='history':put(root/self.JOURNAL.lstrip('/')/('transaction-'+'b'*24)/'transaction.json',self.journal(root/self.JOURNAL.lstrip('/')/('transaction-'+'b'*24),'committed'))
                elif change=='unknown_lock':put(root/self.DATA.lstrip('/')/'foreign.lock',b'',0o640)
                with patch.object(RESOURCE.os,'geteuid',return_value=1001 if change=='nonroot' else 0):
                    self.assertIsNone(reader(moved,candidate,prefix=root))

    def test_malformed_review_is_conservative_without_crashing(self):
        capture, unused = self.api()
        for malformed in ('web_list', 'root_bool_schema', 'inventory_bool_schema', 'inventory_version', 'inventory_source_list'):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'root';review,candidate,put=self.fixture(root)
                if malformed=='web_list': put(review/'previous-web-approval.json', [])
                elif malformed=='root_bool_schema':
                    put(review/'previous-root-approval.json',{'schema':True,'source':'fresh-install','files':{},'root_jobs':[]})
                else:
                    pointer=json.loads((review/'registry/slsmassnotifyserver.active.json').read_bytes())
                    generation=review/'registry'/pointer['generation']
                    inventory=json.loads((generation/'inventory.json').read_bytes())
                    if malformed=='inventory_bool_schema': inventory['schema']=True
                    elif malformed=='inventory_version': inventory['version']='0.1.9-beta'
                    else: inventory['source']=[]
                    encoded=(json.dumps(inventory,sort_keys=True)+'\n').encode()
                    digest=hashlib.sha256(encoded).hexdigest()
                    put(review/'registry'/('slsmassnotifyserver-'+digest)/'inventory.json',encoded)
                    put(review/'registry/slsmassnotifyserver.active.json',{'generation':'slsmassnotifyserver-'+digest,'sha256':digest})
                try:
                    result=capture(review,candidate,'known_absent',prefix=root)
                except Exception as error:
                    self.fail('Malformed review must retain full reserves, not crash: '+type(error).__name__)
                self.assertIsNone(result)

    def test_cli_uses_only_verified_prepared_review_for_install_budget(self):
        unused, reader = self.api()
        for proof in (None, {'schema':1,'fixture':'verified'}):
            def filesystems(budgets,inode_budgets=None):
                return [{'device':'fixture','paths':list(budgets),
                    'required_free_bytes':sum(budgets.values()),
                    'available_bytes':10*GIB,'persistent':True,'filesystem_type':'ext4'}]
            with self.subTest(proof_verified=proof is not None), \
                 patch.object(RESOURCE,'probe_cpu_isa',return_value={'baseline':'x86-64-v2'}), \
                 patch.object(RESOURCE,'probe_compute',return_value=(2,4*GIB)), \
                 patch.object(RESOURCE,'probe_memory_limit',return_value=4*GIB), \
                 patch.object(RESOURCE,'measure_release_payloads',return_value={}), \
                 patch.object(RESOURCE,'read_fresh_release_proof',return_value=proof) as checked, \
                 patch.object(RESOURCE,'probe_storage',side_effect=simulated_voice_storage) as measured, \
                 patch.object(RESOURCE,'private_install_temporary_state',return_value={
                     'exists':True,'allocation_unit':4096,'read_only':False}), \
                 patch.object(RESOURCE,'probe_filesystems',side_effect=filesystems), \
                 patch.object(RESOURCE,'probe_runtime_speech_scratch',return_value={
                     'required_free_bytes':0,'available_bytes':GIB,'read_only':False,'inodes_exhausted':False}), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(RESOURCE.main(['--mode','install','--candidate-source','/fixture/candidate',
                    '--prepared-release-review','/fixture/review','--temporary-directory',RESOURCE.PRIVATE_INSTALL_TEMP,'--check']),0)
                checked.assert_called_once_with(Path('/fixture/review'),Path('/fixture/candidate'))
                self.assertEqual(measured.call_args.kwargs.get('verify_voice_content',False),proof is not None)
                self.assertEqual(measured.call_args.kwargs.get('previous_release_required',True),proof is None)
                reported=json.loads(output.getvalue())['requirements']['storage']
                self.assertEqual(reported['previous_release_required'],proof is None)
                self.assertEqual(reported['temporary_directory'],RESOURCE.PRIVATE_INSTALL_TEMP)
                if proof is not None:
                    self.assertIn('fresh_release_proof_canonical_sha256',reported)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            RESOURCE.main(['--mode','prepare','--prepared-release-review','/fixture/review'])
        self.assertEqual(caught.exception.code,2)

    def test_absent_paths_require_safe_ancestors_and_legacy_cron_absence(self):
        capture, unused = self.api()
        for change in ('symlink_ancestor', 'writable_ancestor', 'unknown_web_group', 'legacy_data_cron',
                       'module_cron', 'bare_legacy_cron', 'bare_runner_cron'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'root';review,candidate,put=self.fixture(root,after_abandon=True)
                if change=='symlink_ancestor':
                    (root/'usr/local').mkdir(mode=0o755,parents=True)
                    (root/'empty').mkdir(mode=0o700)
                    (root/'usr/local/bin').symlink_to(root/'empty',target_is_directory=True)
                elif change=='writable_ancestor':
                    (root/'usr/local/bin').mkdir(mode=0o755,parents=True)
                    (root/'usr/local/bin').chmod(0o777)
                elif change=='unknown_web_group':
                    path=root/'var/www/html/admin/modules';path.mkdir(mode=0o755,parents=True)
                    os.chown(path,0,12345);path.chmod(0o775)
                elif change=='legacy_data_cron':
                    put(root/'etc/crontab',b'* * * * * root /var/lib/asterisk/SLS_Mass_Notifications_Plugin/worker.sh\n',0o644)
                elif change=='module_cron':
                    put(root/'etc/crontab',b'* * * * * root /var/www/html/admin/modules/slsmassnotifyserver/worker.php\n',0o644)
                elif change=='bare_legacy_cron':
                    put(root/'etc/crontab',b'* * * * * root /opt/nws_weather_alert.sh\n',0o644)
                else:
                    put(root/'etc/crontab',b'* * * * * root /opt/sls_cron_runner.py maintenance\n',0o644)
                self.assertIsNone(capture(review,candidate,'known_absent',prefix=root))

    def test_actual_native_web_775_and_data_750_parents_remain_eligible(self):
        capture, reader = self.api()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';review,candidate,put=self.fixture(root,after_abandon=True)
            for name in ('var/www/html','var/www/html/admin','var/www/html/admin/modules'):
                path=root/name;path.mkdir(mode=0o775,parents=True,exist_ok=True)
                os.chown(path,self.native.pw_uid,self.native.pw_gid);path.chmod(0o775)
            parent=root/'var/lib/asterisk';os.chown(parent,self.native.pw_uid,self.native.pw_gid);parent.chmod(0o755)
            proof=capture(review,candidate,'known_absent',prefix=root)
            self.assertIsInstance(proof,dict)
            moved=self.retain(root,review,proof,put)
            self.assertIsInstance(reader(moved,candidate,prefix=root),dict)
            target=root/'var/www/html'
            identity=(target.stat().st_dev,target.stat().st_ino)
            original=RESOURCE.os.listxattr
            for attribute in ('system.posix_acl_access','system.posix_acl_default'):
                def attributes(descriptor):
                    info=os.fstat(descriptor)
                    return [attribute] if (info.st_dev,info.st_ino)==identity else original(descriptor)
                with self.subTest(attribute=attribute), patch.object(RESOURCE.os,'listxattr',side_effect=attributes):
                    self.assertIsNone(reader(moved,candidate,prefix=root))


class PreparedInstallStorageProofTests(unittest.TestCase):
    """Capacity-only authority and complete prepared-resident role controls."""
    DATA = FreshReleaseStorageProofTests.DATA
    JOURNAL = FreshReleaseStorageProofTests.JOURNAL
    SETTINGS = FreshReleaseStorageProofTests.SETTINGS
    LOCKS = FreshReleaseStorageProofTests.LOCKS
    BOOTSTRAP = ('sls_module_trust.py', 'sls_release_trust.py', 'sls_privileged_install.py',
                 'sls_installer_recovery.py', 'sls_install_transaction.py', 'sls_install_idle.py',
                 'sls_install_guard.py', 'sls_audio_state.py', 'sls_config_crypto.py',
                 'sls_upgrade_trust.py', 'sls_legacy_permissions.py', 'freepbx-mirror-signing.pub')
    KIND = 'sll-prepared-release-storage-proof-v2'

    def setUp(self):
        FreshReleaseStorageProofTests.setUp(self)

    def journal(self, path, phase='prepared'):
        return FreshReleaseStorageProofTests.journal(self, path, phase)

    def api(self):
        capture = getattr(RESOURCE, 'capture_install_storage_proof', None)
        reader = getattr(RESOURCE, 'read_install_storage_proof', None)
        self.assertTrue(callable(capture), 'Capacity-only authenticated relationship capture is missing')
        self.assertTrue(callable(reader), 'Complete prepared storage-role reader is missing')
        return capture, reader

    def rebuild_registry(self, review, candidate, put, release_dict):
        """Rebind fixture archive/manifest and every authenticated candidate byte."""
        import gzip
        import tarfile
        compressed = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed, mode='wb', mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as archive:
                for path in [candidate, *sorted(candidate.rglob('*'))]:
                    relative = path.relative_to(candidate).as_posix()
                    name = 'slsmassnotifyserver' + ('' if relative == '.' else '/' + relative)
                    info = tarfile.TarInfo(name)
                    info.uid = info.gid = info.mtime = 0
                    info.mode = 0o700 if path.is_dir() else 0o600
                    if path.is_dir():
                        info.type = tarfile.DIRTYPE; archive.addfile(info)
                    else:
                        body = path.read_bytes(); info.size = len(body)
                        archive.addfile(info, io.BytesIO(body))
        release_dict['package'] = compressed.getvalue()
        try:
            manifest = json.loads(release_dict.get('manifest', b'{}'))
        except ValueError:
            manifest = {}
        manifest.update(schema=1, version='0.2.0-beta', tag='v0.2.0-beta',
                        package='slsmassnotifyserver-0.2.0-beta.tgz',
                        installer_sha256=hashlib.sha256(release_dict['installer']).hexdigest(),
                        package_sha256=hashlib.sha256(release_dict['package']).hexdigest())
        manifest.setdefault('signing', {'key_id': 'f'*64, 'issued_at': 1, 'expires_at': 2**31})
        release_dict['manifest'] = (json.dumps(manifest, sort_keys=True) + '\n').encode()
        release_dict.setdefault('sig', b's'*64)
        files = {p.relative_to(candidate).as_posix(): {
                    'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                    'target': 'admin/modules/slsmassnotifyserver/' + p.relative_to(candidate).as_posix()}
                 for p in sorted(candidate.rglob('*')) if p.is_file()}
        inventory = {'schema': 1, 'module': 'slsmassnotifyserver', 'version': '0.2.0-beta',
                     'source': {'kind': 'publisher-ed25519',
                                'archive_sha256': hashlib.sha256(release_dict['package']).hexdigest()},
                     'files': files}
        raw = (json.dumps(inventory, sort_keys=True) + '\n').encode()
        digest = hashlib.sha256(raw).hexdigest()
        registry = review/'registry'
        if registry.exists(): shutil.rmtree(registry)
        generation = registry/('slsmassnotifyserver-' + digest)
        put(generation/'inventory.json', raw)
        for name in files: put(generation/'module'/name, (candidate/name).read_bytes())
        put(generation/'release-manifest.json', release_dict['manifest'])
        put(generation/'release-manifest.sig', release_dict['sig'])
        put(registry/'slsmassnotifyserver.active.json', {'generation': generation.name, 'sha256': digest})
        if getattr(self, '_relationship_retained', False):
            trust = self._relationship_prefix/'var/lib/sls-mass-notify-trust'
            trust.mkdir(mode=0o700, parents=True, exist_ok=True)
            for child in list(trust.iterdir()):
                if child.is_dir(): shutil.rmtree(child)
                else: child.unlink()
            shutil.copytree(generation, trust/generation.name)
        return generation

    def relationship_fixture(self, root, retained=True):
        review, candidate, put = FreshReleaseStorageProofTests.fixture(self, root)
        (root/'var/lib').mkdir(mode=0o755, parents=True, exist_ok=True)
        self._relationship_prefix = root
        self._relationship_retained = retained
        for name in self.BOOTSTRAP:
            put(candidate/'bin/sls_mass_notify'/name, ('inert signed fixture ' + name + '\n').encode())
        release = {'installer': b'#!/bin/bash\n# inert authenticated installer fixture\n',
                   'sig': b's'*64}
        self.rebuild_registry(review, candidate, put, release)
        if retained:
            put(root/self.DATA.lstrip('/')/'mass-notifications.config',
                b'{"fixture":"retained protected configuration"}\n', 0o640)
            config = root/self.DATA.lstrip('/')/'mass-notifications.config'
            os.chown(config, self.native.pw_uid, self.native.pw_gid)
            data = config.parent; os.chown(data, self.native.pw_uid, self.native.pw_gid); data.chmod(0o750)
            put(root/'etc/sls-mass-notify/config-keys.json', b'{"fixture":"retained protected keyring"}\n', 0o640)
            os.chown(root/'etc/sls-mass-notify/config-keys.json', 0, self.native.pw_gid)
            old = root/self.JOURNAL.lstrip('/')/('transaction-' + 'b'*24)
            record = self.journal(old, 'rolled_back')
            record['stage'] = 'post-install verification'
            record['settings'].update(MODULE_ACTIVATED='1', STATIC_MUTATION_STARTED='1')
            put(old/'transaction.json', record)
            old.parent.chmod(0o700)
        return review, candidate, put, release

    def prepared_fixture(self, root, review, candidate, put, release, proof):
        current = root/self.JOURNAL.lstrip('/')/('transaction-' + 'c'*24)
        current.mkdir(mode=0o700, parents=True)
        current.parent.chmod(0o700)
        moved = current/'approval'
        shutil.copytree(review, moved); shutil.rmtree(review)
        put(moved/'resource-relationship-proof.json', proof)
        for name in self.BOOTSTRAP:
            put(current/'bootstrap'/name, (candidate/'bin/sls_mass_notify'/name).read_bytes(),
                0o600 if name.endswith('.pub') else 0o700)
        for key, name in [('installer', 'installer.sh'), ('package', 'package.tgz'),
                          ('manifest', 'release-manifest.json'), ('sig', 'release-manifest.sig')]:
            put(current/name, release[key])
        put(current/'transaction.json', self.journal(current))
        return moved

    def test_fixture_has_complete_authenticated_candidate_and_exact_twelve_bootstrap_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root'
            review, candidate, put, release = self.relationship_fixture(root)
            self.assertEqual(set(release), {'package', 'installer', 'manifest', 'sig'})
            self.assertTrue(all(isinstance(v, bytes) and v for v in release.values()))
            pointer = json.loads((review/'registry/slsmassnotifyserver.active.json').read_bytes())
            generation = review/'registry'/pointer['generation']
            raw = (generation/'inventory.json').read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pointer['sha256'])
            inventory = json.loads(raw)
            self.assertEqual(len(inventory['files']), 13)
            self.assertEqual(inventory['source']['archive_sha256'], hashlib.sha256(release['package']).hexdigest())
            for name, row in inventory['files'].items():
                self.assertEqual(hashlib.sha256((candidate/name).read_bytes()).hexdigest(), row['sha256'])
                self.assertEqual((generation/'module'/name).read_bytes(), (candidate/name).read_bytes())
            self.assertEqual(len(self.BOOTSTRAP), 12)
            self.assertFalse((root/'var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json').exists())

    def test_actual_after15_geometry_changes_only_three_resident_roles_and_absent_previous_costs(self):
        import inspect
        self.assertIn('prepared_release_resident', inspect.signature(RESOURCE.storage_requirements).parameters,
                      'Complete prepared-role accounting is missing')
        journal = RESOURCE.INSTALLER_JOURNAL
        payloads = {journal: {'bytes': 21951872, 'entries': 2989}}
        options = dict(mode='install', payloads=payloads, missing_voices=0)
        old = RESOURCE.storage_requirements(**options)
        new = RESOURCE.storage_requirements(**options, previous_release_required=False,
                                             prepared_release_resident=True)
        previous = 140038144
        resident = 122936064
        self.assertEqual(previous + resident, old['free_budgets_bytes'][journal] - new['free_budgets_bytes'][journal])
        roles = {'reviewed_previous_and_candidate_sources', 'saved_candidate_archive_and_metadata',
                 'authenticated_bootstrap_helpers'}
        for path, parts in old['component_budgets_bytes'].items():
            for name, value in parts.items():
                if path == journal and name in roles: value = 0
                elif path == journal and name == 'previous_release_download_and_metadata': value = 0
                self.assertEqual(new['component_budgets_bytes'][path][name], value, (path, name))
        self.assertEqual(new['inode_budgets'], old['inode_budgets'])
        self.assertEqual(new['free_budgets_bytes'][RESOURCE.MANAGED_TREES['data']], 611328000)
        self.assertEqual(new['free_budgets_bytes'][RESOURCE.MANAGED_TREES['voices']], 63205376)
        self.assertEqual(1470361733 - previous - resident, 1207387525)
        self.assertEqual(1301778432 - 1207387525, 94390907)
        for unknown in (False, None, 1, 'true'):
            self.assertEqual(RESOURCE.storage_requirements(**options, prepared_release_resident=unknown)['component_budgets_bytes'],
                             old['component_budgets_bytes'])
        self.assertEqual(RESOURCE.storage_requirements(mode='prepare')['component_budgets_bytes'],
                         RESOURCE.storage_requirements(mode='prepare', previous_release_required=False,
                                                       prepared_release_resident=True)['component_budgets_bytes'])
        retained = RESOURCE.storage_requirements(**options, prepared_release_resident=True)
        self.assertEqual(retained['component_budgets_bytes'][journal]['reviewed_previous_and_candidate_sources'],
                         72908800)
        self.assertEqual(retained['component_budgets_bytes'][journal]['previous_release_download_and_metadata'],
                         67129344)
        self.assertEqual(old['free_budgets_bytes'][journal] - retained['free_budgets_bytes'][journal],
                         122936064)

    def test_capacity_only_relationship_allows_retained_state_but_needs_prepared_verification(self):
        capture, reader = self.api()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root'; review, candidate, put, release = self.relationship_fixture(root)
            watched = [root/self.DATA.lstrip('/')/'mass-notifications.config',
                       root/'etc/sls-mass-notify/config-keys.json']
            original = {p: p.read_bytes() for p in watched}
            proof = capture(review, candidate, 'known_absent', prefix=root)
            self.assertIsInstance(proof, dict)
            self.assertEqual(proof.get('schema'), 2); self.assertEqual(proof.get('kind'), self.KIND)
            self.assertIs(proof.get('capacity_only'), True)
            self.assertIs(proof.get('prepared_verification_required'), True)
            self.assertIsNot(proof.get('prepared_release_resident'), True)
            self.assertIsNone(reader(review, candidate, prefix=root), 'An early capsule alone cannot zero resident roles')
            self.assertIsNone(RESOURCE.capture_fresh_release_proof(review, candidate, 'known_absent', prefix=root))
            moved = self.prepared_fixture(root, review, candidate, put, release, proof)
            self.assertIsInstance(reader(moved, candidate, prefix=root), dict)
            self.assertEqual({p: p.read_bytes() for p in watched}, original)

    def test_unknown_native_established_approval_active_pointer_or_history_keeps_full_budgets(self):
        capture, unused = self.api()
        for state in ('unknown', 'known_present', '', True):
            with self.subTest(native_state=state), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'root'; review,candidate,put,release=self.relationship_fixture(root)
                self.assertIsNone(capture(review,candidate,state,prefix=root))
        for change in ('module', 'runtime', 'previous_web', 'previous_root', 'prior_download',
                       'live_active', 'unknown_history', 'nonterminal', 'history_HAD1', 'history_bad_flag',
                       'unprotected_review', 'nonroot'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'root'; review,candidate,put,release=self.relationship_fixture(root)
                if change == 'module': put(root/'var/www/html/admin/modules/slsmassnotifyserver/module.xml', b'old')
                elif change == 'runtime': put(root/'usr/local/bin/sls_mass_notify/old.py', b'old')
                elif change == 'previous_web': put(review/'previous-web-approval.json', {'slsmassnotifyserver': {'schema':1}})
                elif change == 'previous_root': put(review/'previous-root-approval.json', {'schema':1,'source':'publisher-verified-previous-release','files':{},'root_jobs':[]})
                elif change == 'prior_download': put(review/'previous-release/old.tgz', b'old')
                elif change == 'live_active':
                    pointer=json.loads((review/'registry/slsmassnotifyserver.active.json').read_bytes())
                    put(root/'var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json', pointer)
                elif change in ('unknown_history', 'nonterminal'):
                    old=root/self.JOURNAL.lstrip('/')/('transaction-'+'b'*24)
                    put(old/'transaction.json', self.journal(old, 'unknown' if change=='unknown_history' else 'prepared'))
                elif change in ('history_HAD1', 'history_bad_flag'):
                    old=root/self.JOURNAL.lstrip('/')/('transaction-'+'b'*24)
                    value=self.journal(old,'rolled_back')
                    value['settings']['HAD_EXISTING_MODULE' if change=='history_HAD1' else 'STATIC_MUTATION_STARTED']='1' if change=='history_HAD1' else 'unknown'
                    put(old/'transaction.json',value)
                elif change == 'unprotected_review': review.chmod(0o722)
                with patch.object(RESOURCE.os,'geteuid',return_value=1001 if change=='nonroot' else 0):
                    self.assertIsNone(capture(review,candidate,'known_absent',prefix=root))

    def test_every_prepared_role_requires_complete_matching_private_candidate_artifacts(self):
        capture, reader = self.api()
        changes = ('missing_package', 'changed_package', 'changed_installer', 'changed_manifest', 'changed_signature',
                   'missing_bootstrap', 'changed_bootstrap', 'extra_bootstrap', 'bootstrap_mode',
                   'missing_approval_module', 'changed_approval_module', 'extra_approval_module',
                   'changed_inventory', 'changed_registry_manifest', 'changed_registry_signature',
                   'candidate_changed', 'current_HAD1', 'current_mutating', 'current_static',
                   'proof_mode', 'proof_symlink', 'proof_hardlink', 'archive_symlink', 'archive_hardlink',
                   'writable_current', 'changed_key', 'changed_config')
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'root';review,candidate,put,release=self.relationship_fixture(root)
                proof=capture(review,candidate,'known_absent',prefix=root);self.assertIsInstance(proof,dict)
                moved=self.prepared_fixture(root,review,candidate,put,release,proof);current=moved.parent
                pointer=json.loads((moved/'registry/slsmassnotifyserver.active.json').read_bytes())
                generation=moved/'registry'/pointer['generation']
                helper=current/'bootstrap/sls_install_guard.py'; capsule=moved/'resource-relationship-proof.json'
                if change == 'missing_package': (current/'package.tgz').unlink()
                elif change == 'changed_package': put(current/'package.tgz', b'changed')
                elif change == 'changed_installer': put(current/'installer.sh', b'changed')
                elif change == 'changed_manifest': put(current/'release-manifest.json', b'{}')
                elif change == 'changed_signature': put(current/'release-manifest.sig', b'x'*64)
                elif change == 'missing_bootstrap': helper.unlink()
                elif change == 'changed_bootstrap': put(helper, b'changed', 0o700)
                elif change == 'extra_bootstrap': put(current/'bootstrap/foreign.py', b'unknown', 0o700)
                elif change == 'bootstrap_mode': helper.chmod(0o644)
                elif change == 'missing_approval_module': (generation/'module/module.xml').unlink()
                elif change == 'changed_approval_module': put(generation/'module/module.xml', b'changed')
                elif change == 'extra_approval_module': put(generation/'module/unknown', b'unknown')
                elif change == 'changed_inventory': put(generation/'inventory.json', b'{}')
                elif change == 'changed_registry_manifest': put(generation/'release-manifest.json', b'{}')
                elif change == 'changed_registry_signature': put(generation/'release-manifest.sig', b'x'*64)
                elif change == 'candidate_changed': put(candidate/'module.xml', b'changed')
                elif change in ('current_HAD1', 'current_mutating', 'current_static'):
                    record=self.journal(current, 'mutating' if change=='current_mutating' else 'prepared')
                    if change=='current_HAD1':record['settings']['HAD_EXISTING_MODULE']='1'
                    if change=='current_static':record['settings']['STATIC_MUTATION_STARTED']='1'
                    put(current/'transaction.json', record)
                elif change == 'proof_mode': capsule.chmod(0o644)
                elif change == 'proof_symlink':
                    target=moved/'kept-proof';capsule.rename(target);capsule.symlink_to(target)
                elif change == 'proof_hardlink': os.link(capsule,moved/'second-proof')
                elif change == 'archive_symlink':
                    target=current/'kept-package';(current/'package.tgz').rename(target);(current/'package.tgz').symlink_to(target)
                elif change == 'archive_hardlink': os.link(current/'package.tgz',current/'second-package')
                elif change == 'writable_current': current.chmod(0o722)
                elif change == 'changed_key': put(root/'etc/sls-mass-notify/config-keys.json', b'changed', 0o640)
                elif change == 'changed_config': put(root/self.DATA.lstrip('/')/'mass-notifications.config', b'changed', 0o640)
                self.assertIsNone(reader(moved,candidate,prefix=root))

    def test_impossible_terminal_mutation_flags_keep_full_reservations(self):
        capture, unused = self.api()
        for phase,activated,static,timezone in (
                ('abandoned','1','1','0'),('abandoned','0','1','0'),
                ('rolled_back','1','0','0'),('rolled_back','0','0','1')):
            with self.subTest(phase=phase,activated=activated,static=static,timezone=timezone),tempfile.TemporaryDirectory()as tmp:
                root=Path(tmp)/'root';review,candidate,put,release=self.relationship_fixture(root)
                old=root/self.JOURNAL.lstrip('/')/('transaction-'+'b'*24)
                value=self.journal(old,phase)
                value['settings'].update(MODULE_ACTIVATED=activated,STATIC_MUTATION_STARTED=static,
                                         SYSTEM_TIMEZONE_CHANGED=timezone)
                put(old/'transaction.json',value)
                self.assertIsNone(capture(review,candidate,'known_absent',prefix=root))

    def test_malformed_capacity_proof_and_candidate_metadata_keep_conservative_accounting(self):
        capture, reader = self.api()
        for change in ('list_proof','bool_schema','duplicate_fields','list_manifest','bool_inventory_schema'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'root';review,candidate,put,release=self.relationship_fixture(root)
                proof=capture(review,candidate,'known_absent',prefix=root)
                self.assertIsInstance(proof,dict)
                moved=self.prepared_fixture(root,review,candidate,put,release,proof)
                capsule=moved/'resource-relationship-proof.json'
                if change=='list_proof': put(capsule,[])
                elif change=='bool_schema': put(capsule,{**proof,'schema':True})
                elif change=='duplicate_fields': put(capsule,b'{"schema":2,"schema":2}')
                else:
                    pointer=json.loads((moved/'registry/slsmassnotifyserver.active.json').read_bytes())
                    generation=moved/'registry'/pointer['generation']
                    if change=='list_manifest': put(generation/'release-manifest.json',[])
                    else: put(generation/'inventory.json',{'schema':True})
                self.assertIsNone(reader(moved,candidate,prefix=root))

    def test_default_unknown_and_legacy_fresh_v1_semantics_are_preserved(self):
        capture, reader = self.api()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';review,candidate,put,release=self.relationship_fixture(root,retained=False)
            legacy=RESOURCE.capture_fresh_release_proof(review,candidate,'known_absent',prefix=root)
            self.assertIsInstance(legacy,dict)
            moved=FreshReleaseStorageProofTests.retain(self,root,review,legacy,put)
            self.assertIsInstance(RESOURCE.read_fresh_release_proof(moved,candidate,prefix=root),dict)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';review,candidate,put,release=self.relationship_fixture(root)
            self.assertIsNone(reader(review,candidate,prefix=root))
            put(review/'resource-relationship-proof.json', {'schema':2,'kind':self.KIND,'capacity_only':True})
            self.assertIsNone(reader(review,candidate,prefix=root))

    def test_cli_verified_v2_decisions_and_neutral_provenance_survive_private_spool_selection(self):
        unused, reader = self.api()
        good={'schema':2,'kind':self.KIND,'capacity_only':True,
              'prepared_verification_required':True,'native_state':'known_absent'}
        for proof in (None,good):
            def filesystems(budgets,inode_budgets=None):
                return [{'device':'fixture','paths':list(budgets),'required_free_bytes':sum(budgets.values()),
                         'available_bytes':10*GIB,'persistent':True,'filesystem_type':'ext4'}]
            with self.subTest(proof_verified=proof is not None), \
                 patch.object(RESOURCE,'probe_cpu_isa',return_value={'baseline':'x86-64-v2'}), \
                 patch.object(RESOURCE,'probe_compute',return_value=(2,4*GIB)), \
                 patch.object(RESOURCE,'probe_memory_limit',return_value=4*GIB), \
                 patch.object(RESOURCE,'measure_release_payloads',return_value={}), \
                 patch.object(RESOURCE,'read_install_storage_proof',return_value=proof) as verified, \
                 patch.object(RESOURCE,'read_fresh_release_proof',return_value=None), \
                 patch.object(RESOURCE,'probe_storage',side_effect=simulated_voice_storage) as measured, \
                 patch.object(RESOURCE,'private_install_temporary_state',return_value={
                     'exists':True,'allocation_unit':4096,'read_only':False}), \
                 patch.object(RESOURCE,'probe_filesystems',side_effect=filesystems), \
                 patch.object(RESOURCE,'probe_runtime_speech_scratch',return_value={
                     'required_free_bytes':0,'available_bytes':GIB,'read_only':False,'inodes_exhausted':False}), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(RESOURCE.main(['--mode','install','--candidate-source','/fixture/candidate',
                    '--prepared-release-review','/fixture/review','--temporary-directory',RESOURCE.PRIVATE_INSTALL_TEMP,'--check']),0)
                verified.assert_called_once_with(Path('/fixture/review'),Path('/fixture/candidate'))
                self.assertEqual(measured.call_args.kwargs.get('verify_voice_content',False),proof is not None)
                self.assertEqual(measured.call_args.kwargs.get('previous_release_required',True),proof is None)
                self.assertEqual(measured.call_args.kwargs.get('prepared_release_resident',False),proof is not None)
                report=json.loads(output.getvalue())['requirements']['storage']
                self.assertEqual(report['previous_release_required'],proof is None)
                self.assertEqual(report.get('prepared_release_resident',False),proof is not None)
                self.assertEqual(report['temporary_directory'],RESOURCE.PRIVATE_INSTALL_TEMP)
                if proof is not None:
                    self.assertIn('release_storage_proof_canonical_sha256',report)
                    self.assertEqual(report['release_storage_proof_kind'],self.KIND)
                    self.assertNotIn('fresh_release_proof_canonical_sha256',report)
                else:
                    self.assertNotIn('release_storage_proof_canonical_sha256',report)


class PreparedUpgradeRemainingGrowthTests(unittest.TestCase):
    """The actual signed17 normal repeat needs future growth, not resident copies."""
    DATA = PreparedInstallStorageProofTests.DATA
    JOURNAL = PreparedInstallStorageProofTests.JOURNAL
    SETTINGS = PreparedInstallStorageProofTests.SETTINGS
    BOOTSTRAP = PreparedInstallStorageProofTests.BOOTSTRAP
    setUp = PreparedInstallStorageProofTests.setUp
    journal = PreparedInstallStorageProofTests.journal
    rebuild_registry = PreparedInstallStorageProofTests.rebuild_registry
    relationship_fixture = PreparedInstallStorageProofTests.relationship_fixture
    prepared_fixture = PreparedInstallStorageProofTests.prepared_fixture

    def upgrade_fixture(self, root):
        review,candidate,put,release=self.relationship_fixture(root,retained=False)
        pointer=json.loads((review/'registry/slsmassnotifyserver.active.json').read_bytes())
        generation=review/'registry'/pointer['generation'];inventory=json.loads((generation/'inventory.json').read_bytes())
        trust=root/'var/lib/sls-mass-notify-trust';trust.mkdir(mode=0o700,parents=True)
        shutil.copytree(generation,trust/generation.name)
        put(trust/'slsmassnotifyserver.active.json',pointer)
        files={RESOURCE.MANAGED_TREES['runtime']+'/'+name[len('bin/sls_mass_notify/'):]:row['sha256']
               for name,row in inventory['files'].items()if name.startswith('bin/sls_mass_notify/')}
        put(review/'previous-web-approval.json',{'slsmassnotifyserver':inventory})
        put(review/'previous-root-approval.json',{'schema':1,'source':'publisher-verified-previous-release',
            'version':inventory['version'],'archive_sha256':inventory['source']['archive_sha256'],
            'files':files,'missing_files':[],'quarantine_caches':{},'root_jobs':[]})
        for module in('dashboard','framework'):
            body=('inert independently signed '+module+' stock package').encode()
            name=module+'-17.0.33.4.tgz.gpg';put(trust/'stock-packages'/name,body)
            xml=('<module><rawname>'+module+'</rawname><version>17.0.33.4</version></module>').encode()
            put(root/'var/www/html/admin/modules'/module/'module.xml',xml,0o644)
            source={'kind':'reviewed-upstream-and-overlays','archive_sha256':'e'*64,
                'signed_archive_sha256':hashlib.sha256(body).hexdigest(),
                'upstream_signer':'456D051E9204C27C37D4811BB53D215A755231A3'}
            data={'schema':1,'module':module,'version':'17.0.33.4','source':source,
                  'files':{'module.xml':{'sha256':hashlib.sha256(xml).hexdigest(),
                           'target':'admin/modules/'+module+'/module.xml'}}}
            put(review/(module+'.json'),data)
        return review,candidate,put,release

    def test_complete_prepared_upgrade_roles_are_bound_without_operational_config_authority(self):
        capture=getattr(RESOURCE,'capture_prepared_upgrade_storage_proof',None)
        reader=getattr(RESOURCE,'read_prepared_upgrade_storage_proof',None)
        self.assertTrue(callable(capture));self.assertTrue(callable(reader))
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp)/'root';review,candidate,put,release=self.upgrade_fixture(root)
            # Storage authority is independent of settings/key/history contents.
            put(root/self.DATA.lstrip('/')/'mass-notifications.config',b'opaque preserved settings')
            self.assertIsInstance(RESOURCE._upgrade_storage_review(review,candidate),tuple)
            self.assertIsInstance(RESOURCE._upgrade_previous_binding(review,root),dict)
            self.assertIsInstance(RESOURCE._upgrade_stock_binding(review,root),dict)
            proof=capture(review,candidate,'established',prefix=root)
            self.assertIsInstance(proof,dict);self.assertEqual(proof['schema'],3)
            self.assertEqual(proof['kind'],'sll-prepared-upgrade-storage-proof-v3')
            self.assertIsNone(reader(review,candidate,prefix=root))
            moved=self.prepared_fixture(root,review,candidate,put,release,proof)
            journal=self.journal(moved.parent);journal['settings'].update(HAD_EXISTING_MODULE='1',MODULE_WAS_ENABLED='1')
            put(moved.parent/'transaction.json',journal)
            self.assertEqual(reader(moved,candidate,prefix=root),proof)
            self.assertEqual((root/self.DATA.lstrip('/')/'mass-notifications.config').read_bytes(),b'opaque preserved settings')

    def test_new_approved_native_package_reserves_its_actual_publication_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'root'
            review,candidate,put,release = self.upgrade_fixture(root)
            folder = root / 'var/lib/sls-mass-notify-trust/stock-packages'
            name = 'framework-17.0.33.4.tgz.gpg'
            body = (folder/name).read_bytes()
            (folder/name).rename(folder/'framework-17.0.33.2.tgz.gpg')
            put(review/name, body)
            proof = RESOURCE.capture_prepared_upgrade_storage_proof(review,candidate,'established',prefix=root)
            self.assertIsInstance(proof,dict)
            self.assertEqual(proof['stock_cache']['pending'][name]['bytes'],len(body))
            moved = self.prepared_fixture(root,review,candidate,put,release,proof)
            journal=self.journal(moved.parent)
            journal['settings'].update(HAD_EXISTING_MODULE='1',MODULE_WAS_ENABLED='1')
            put(moved.parent/'transaction.json',journal)
            self.assertEqual(RESOURCE.read_prepared_upgrade_storage_proof(moved,candidate,prefix=root),proof)
            path='/var/lib/sls-mass-notify-trust/stock-packages'
            report = RESOURCE.storage_requirements(mode='install',stock_cache_publication_sizes=[len(body)],
                allocation_units={path:65536})
            self.assertEqual(report['free_budgets_bytes'][path],2*65536)
            self.assertGreaterEqual(report['component_budgets_bytes']['/tmp']['upstream_package_verification'],4*64*RESOURCE.MIB)
            put(moved/name, b'changed pending file')
            self.assertIsNone(RESOURCE.read_prepared_upgrade_storage_proof(moved,candidate,prefix=root))

    def test_unqualified_stock_state_retains_full_cache_budget_and_independent_source_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'root'
            review,candidate,put,release = self.upgrade_fixture(root)
            (root/'var/lib/sls-mass-notify-trust/stock-packages/framework-17.0.33.4.tgz.gpg').unlink()
            proof = RESOURCE.capture_prepared_upgrade_storage_proof(review,candidate,'established',prefix=root)
            self.assertIsInstance(proof,dict)
            self.assertIsNone(proof['stock_cache'])
            moved = self.prepared_fixture(root,review,candidate,put,release,proof)
            journal=self.journal(moved.parent)
            journal['settings'].update(HAD_EXISTING_MODULE='1',MODULE_WAS_ENABLED='1')
            put(moved.parent/'transaction.json',journal)
            self.assertEqual(RESOURCE.read_prepared_upgrade_storage_proof(moved,candidate,prefix=root),proof)
            report = RESOURCE.storage_requirements(mode='install',previous_release_required=False,prepared_release_resident=True)
            self.assertEqual(report['free_budgets_bytes']['/var/lib/sls-mass-notify-trust/stock-packages'],320*RESOURCE.MIB)

    def test_upgrade_unknown_partial_tampered_roles_and_mutating_phase_keep_full_budget(self):
        capture=getattr(RESOURCE,'capture_prepared_upgrade_storage_proof',None)
        reader=getattr(RESOURCE,'read_prepared_upgrade_storage_proof',None)
        self.assertTrue(callable(capture));self.assertTrue(callable(reader))
        changes=('native_unknown','prior_missing','prior_source_changed','prior_manifest_changed','prior_pointer_changed',
                 'prior_download','prior_root_changed','cache_missing','cache_changed','cache_interrupted','cache_mode',
                 'native_version_changed','candidate_archive_changed','bootstrap_changed','phase_mutating','HAD0','stock_proof_changed')
        for change in changes:
            with self.subTest(change=change),tempfile.TemporaryDirectory()as tmp:
                root=Path(tmp)/'root';review,candidate,put,release=self.upgrade_fixture(root)
                if change=='native_unknown':
                    self.assertIsNone(capture(review,candidate,'unknown',prefix=root));continue
                proof=capture(review,candidate,'established',prefix=root);self.assertIsInstance(proof,dict)
                moved=self.prepared_fixture(root,review,candidate,put,release,proof);current=moved.parent
                journal=self.journal(current);journal['settings'].update(HAD_EXISTING_MODULE='1',MODULE_WAS_ENABLED='1');put(current/'transaction.json',journal)
                trust=root/'var/lib/sls-mass-notify-trust';pointer=json.loads((trust/'slsmassnotifyserver.active.json').read_bytes());generation=trust/pointer['generation']
                if change=='prior_missing':(generation/'module/module.xml').unlink()
                elif change=='prior_source_changed':put(generation/'module/module.xml',b'changed')
                elif change=='prior_manifest_changed':put(generation/'release-manifest.json',{})
                elif change=='prior_pointer_changed':put(trust/'slsmassnotifyserver.active.json',{'generation':'other','sha256':'a'*64})
                elif change=='prior_download':put(moved/'previous-release/old.tgz',b'old')
                elif change=='prior_root_changed':put(moved/'previous-root-approval.json',{})
                elif change=='cache_missing':(trust/'stock-packages/framework-17.0.33.4.tgz.gpg').unlink()
                elif change=='cache_changed':put(trust/'stock-packages/framework-17.0.33.4.tgz.gpg',b'changed')
                elif change=='cache_interrupted':put(trust/'stock-packages'/('.new-'+'f'*24),b'interrupted')
                elif change=='cache_mode':(trust/'stock-packages/framework-17.0.33.4.tgz.gpg').chmod(0o400)
                elif change=='native_version_changed':put(root/'var/www/html/admin/modules/framework/module.xml',b'<module><rawname>framework</rawname><version>17.0.99</version></module>',0o644)
                elif change=='candidate_archive_changed':put(current/'package.tgz',b'changed')
                elif change=='bootstrap_changed':put(current/'bootstrap/sls_install_guard.py',b'changed',0o700)
                elif change=='phase_mutating':journal['phase']='mutating';put(current/'transaction.json',journal)
                elif change=='HAD0':journal['settings']['HAD_EXISTING_MODULE']='0';put(current/'transaction.json',journal)
                elif change=='stock_proof_changed':proof['stock_cache']['pending']['unknown']={};put(moved/'resource-relationship-proof.json',proof)
                self.assertIsNone(reader(moved,candidate,prefix=root))

    def actual_options(self):
        runtime=RESOURCE.MANAGED_TREES['runtime']; journal=RESOURCE.INSTALLER_JOURNAL
        amounts={journal:34209937,runtime:3226625,'/var/lib/sls-mass-notify-trust':34209937,
                 RESOURCE.MANAGED_TREES['module']:34209937,RESOURCE.MANAGED_TREES['web']:1950276,
                 RESOURCE.MANAGED_TREES['sip_api']:101210,RESOURCE.MANAGED_TREES['control_api']:404873,
                 RESOURCE.MANAGED_TREES['operator_portal']:126814,RESOURCE.PRIVATE_INSTALL_TEMP:34209937}
        measured={'runtime':{'allocated_bytes':212883456,'logical_bytes':210467375,'files':4478,'directories':540},
                  'venv':{'allocated_bytes':210045952,'logical_bytes':207672147,'files':4383,'directories':538},
                  'assets':{'allocated_bytes':1912832,'logical_bytes':1892932,'files':11,'directories':3},
                  'sip_api':{'allocated_bytes':94208,'logical_bytes':88922,'files':2,'directories':1},
                  'control_api':{'allocated_bytes':339968,'logical_bytes':281993,'files':26,'directories':4},
                  'operator_portal':{'allocated_bytes':110592,'logical_bytes':89950,'files':8,'directories':1},
                  'recovery_recordings':{'allocated_bytes':507904,'logical_bytes':491088,'files':8}}
        return {'mode':'install','payloads':{p:{'bytes':n,'entries':0}for p,n in amounts.items()},
                'measured':measured,'missing_voices':0,'temporary_directory':RESOURCE.PRIVATE_INSTALL_TEMP}

    def test_actual_late_geometry_accepts_complete_authenticated_upgrade_roles_and_reuse(self):
        options=self.actual_options(); old=RESOURCE.storage_requirements(**options)
        self.assertGreaterEqual(old['free_budgets_bytes'][RESOURCE.MANAGED_TREES['runtime']],221436929)
        new=RESOURCE.storage_requirements(**options,previous_release_required=False,prepared_release_resident=True,
            stock_cache_publication_required=False,qualified_piper_reuse=True)
        var_paths=set(old['free_budgets_bytes'])-{RESOURCE.MANAGED_TREES['runtime'],'/var/log',RESOURCE.PRIVATE_INSTALL_TEMP}
        snapshot_delta=old['component_budgets_bytes'][RESOURCE.INSTALLER_JOURNAL]['prior_static_runtime_and_api_snapshot']-249403392
        self.assertGreaterEqual(snapshot_delta,0)
        self.assertEqual(sum(old['free_budgets_bytes'][p]for p in var_paths),1685763273+snapshot_delta)
        self.assertEqual(sum(new['free_budgets_bytes'][p]for p in var_paths),1087214503+snapshot_delta)
        self.assertLessEqual(sum(new['free_budgets_bytes'][p]for p in var_paths),1186611200)
        self.assertEqual(new['free_budgets_bytes'][RESOURCE.MANAGED_TREES['runtime']],3226625)
        self.assertLessEqual(new['free_budgets_bytes'][RESOURCE.MANAGED_TREES['runtime']],181364736)
        self.assertGreaterEqual(new['component_budgets_bytes'][RESOURCE.INSTALLER_JOURNAL]['prior_static_runtime_and_api_snapshot'],249403392)
        self.assertEqual(new['free_budgets_bytes'][RESOURCE.MANAGED_TREES['data']],611328000)
        self.assertEqual(new['free_budgets_bytes'][RESOURCE.MANAGED_TREES['voices']],63205376)
        self.assertEqual(new['free_budgets_bytes'][RESOURCE.MANAGED_TREES['config_backups']],62914560)
        self.assertEqual(new['inode_budgets'],old['inode_budgets'])
        self.assertEqual(new['component_budgets_bytes']['/var/lib/sls-mass-notify-trust']['new_authenticated_generation'],34209937)
        self.assertEqual(new['component_budgets_bytes'][RESOURCE.PRIVATE_INSTALL_TEMP]['upstream_package_verification'],268435456)

    def test_stock_publication_credit_is_independent_of_current_and_previous_release_roles(self):
        options=self.actual_options(); old=RESOURCE.storage_requirements(**options)
        new=RESOURCE.storage_requirements(**options,stock_cache_publication_required=False)
        changed=[]
        for path,parts in old['component_budgets_bytes'].items():
            for role,value in parts.items():
                if new['component_budgets_bytes'][path][role]!=value:changed.append((path,role))
        self.assertEqual(changed,[(RESOURCE.STOCK_CACHE,'bounded_signed_stock_cache'),
                                  (RESOURCE.STOCK_CACHE,'signed_stock_cache_atomic_write')])
        self.assertEqual(old['additional_free_bytes']-new['additional_free_bytes'],335544320)
        self.assertEqual(new['inode_budgets'],old['inode_budgets'])

    def test_qualified_reuse_changes_only_venv_replacement_and_pip_workspaces(self):
        options=self.actual_options(); old=RESOURCE.storage_requirements(**options)
        new=RESOURCE.storage_requirements(**options,qualified_piper_reuse=True)
        expected={(RESOURCE.MANAGED_TREES['runtime'],'replacement_runtime'),
                  (RESOURCE.PRIVATE_INSTALL_TEMP,'pinned_wheel_downloads'),
                  (RESOURCE.PRIVATE_INSTALL_TEMP,'wheel_unpack_workspace'),
                  (RESOURCE.PRIVATE_INSTALL_TEMP,'pip_old_package_recovery')}
        actual={(p,k)for p,parts in old['component_budgets_bytes'].items()for k,v in parts.items()
                if new['component_budgets_bytes'][p][k]!=v}
        self.assertEqual(actual,expected)
        self.assertEqual(new['inode_budgets'],old['inode_budgets'])

    def test_unknown_truthy_flags_and_prepare_mode_keep_full_conservative_budgets(self):
        options=self.actual_options(); old=RESOURCE.storage_requirements(**options)
        for unknown in(None,0,1,'true'):
            with self.subTest(unknown=unknown):
                actual=RESOURCE.storage_requirements(**options,stock_cache_publication_required=unknown,qualified_piper_reuse=unknown)
                self.assertEqual(actual['component_budgets_bytes'],old['component_budgets_bytes'])
        options['mode']='prepare';options['reserve_install_workspace']=True
        self.assertEqual(RESOURCE.storage_requirements(**options)['component_budgets_bytes'],
                         RESOURCE.storage_requirements(**options,stock_cache_publication_required=False,qualified_piper_reuse=True)['component_budgets_bytes'])

    def test_v3_cli_applies_only_verified_roles_and_keeps_runtime_mode_native_probe_free(self):
        good={'schema':3,'kind':'sll-prepared-upgrade-storage-proof-v3','capacity_only':True,'stock_cache':{'pending':{},'cached':{}}}
        for proof in(None,good):
            with self.subTest(proof=proof),patch.object(RESOURCE,'probe_cpu_isa',return_value={'baseline':'x86-64-v2'}), \
                 patch.object(RESOURCE,'probe_compute',return_value=(2,4*GIB)), \
                 patch.object(RESOURCE,'probe_memory_limit',return_value=4*GIB), \
                 patch.object(RESOURCE,'measure_release_payloads',return_value={}), \
                 patch.object(RESOURCE,'read_prepared_upgrade_storage_proof',return_value=proof), \
                 patch.object(RESOURCE,'read_install_storage_proof',return_value=None), \
                 patch.object(RESOURCE,'read_fresh_release_proof',return_value=None), \
                 patch.object(RESOURCE,'probe_storage',side_effect=simulated_voice_storage)as measured, \
                 patch.object(RESOURCE,'probe_storage_filesystems',side_effect=lambda storage,*a,**kw:(storage,hardware(available=8)['filesystems'])), \
                 patch.object(RESOURCE,'probe_runtime_speech_scratch',return_value={'required_free_bytes':0,'available_bytes':GIB,'read_only':False,'inodes_exhausted':False}), \
                 contextlib.redirect_stdout(io.StringIO())as out:
                self.assertEqual(RESOURCE.main(['--mode','install','--candidate-source','/inert/source','--prepared-release-review','/inert/review','--check']),0)
                storage=json.loads(out.getvalue())['requirements']['storage']
                self.assertEqual(storage['stock_cache_publication_required'],proof is None)
                self.assertEqual(storage['previous_release_required'],proof is None)
                self.assertEqual(storage['prepared_release_resident'],proof is not None)
                self.assertFalse(storage['qualified_piper_reuse'])
                if proof is not None:self.assertEqual(storage['release_storage_proof_kind'],good['kind'])

    def test_piper_credit_requires_verified_upgrade_and_never_probes_periodic_runtime(self):
        good={'schema':3,'kind':'sll-prepared-upgrade-storage-proof-v3','capacity_only':True,'stock_cache':{'pending':{},'cached':{}}}
        reuse={'schema':1,'kind':'sll-qualified-piper-reuse-v1','qualified':True}
        for mode,proof,qualified in(('runtime',None,None),('prepare',None,None),('install',None,reuse),('install',good,None),('install',good,reuse)):
            with self.subTest(mode=mode,proof=proof,reuse=qualified),patch.object(RESOURCE,'probe_cpu_isa',return_value={'baseline':'x86-64-v2'}), \
                 patch.object(RESOURCE,'probe_compute',return_value=(2,4*GIB)), \
                 patch.object(RESOURCE,'probe_memory_limit',return_value=4*GIB), \
                 patch.object(RESOURCE,'measure_release_payloads',return_value={}), \
                 patch.object(RESOURCE,'read_prepared_upgrade_storage_proof',return_value=proof), \
                 patch.object(RESOURCE,'read_install_storage_proof',return_value=None), \
                 patch.object(RESOURCE,'read_fresh_release_proof',return_value=None), \
                 patch.object(RESOURCE,'probe_prepared_piper_reuse',return_value=qualified)as qualification, \
                 patch.object(RESOURCE,'probe_storage',side_effect=simulated_voice_storage), \
                 patch.object(RESOURCE,'probe_storage_filesystems',side_effect=lambda storage,*a,**kw:(storage,hardware(available=8)['filesystems'])), \
                 patch.object(RESOURCE,'probe_runtime_speech_scratch',return_value={'required_free_bytes':0,'available_bytes':GIB,'read_only':False,'inodes_exhausted':False}), \
                 contextlib.redirect_stdout(io.StringIO())as out:
                args=['--mode',mode,'--check']
                if mode=='install':args+=['--candidate-source','/inert/source','--prepared-release-review','/inert/review']
                self.assertEqual(RESOURCE.main(args),0)
                storage=json.loads(out.getvalue())['requirements']['storage']
                expected=mode=='install'and proof is not None and qualified is not None
                self.assertEqual(storage['qualified_piper_reuse'],expected)
                self.assertEqual(storage['pending_voice_files'],[] if mode=='install' and proof is not None else None)
                if mode=='install'and proof is not None:qualification.assert_called_once_with(Path('/inert/review'),Path('/inert/source'),proof)
                else:qualification.assert_not_called()
                if expected:self.assertRegex(storage['piper_reuse_proof_canonical_sha256'],'^[a-f0-9]{64}$')

    def test_full_piper_calibration_counts_regular_files_aliases_and_directories(self):
        api=getattr(RESOURCE,'piper_environment_requirements',None)
        self.assertTrue(callable(api),'Shared complete Piper allocation model is missing')
        measured={'allocated_bytes':210045952,'logical_bytes':207672147,'files':4383,'directories':538}
        small=api(measured,4096);large=api(measured,65536)
        self.assertGreaterEqual(small['environment_bytes'],220450816)
        self.assertGreaterEqual(large['environment_bytes'],480575488)
        self.assertGreaterEqual(small['required_inodes'],4383+538+4)
        self.assertEqual(small['required_inodes'],large['required_inodes'])
        self.assertGreaterEqual(large['environment_bytes']-small['environment_bytes'],(4383+538)*(65536-4096))

    def test_insufficient_inodes_for_actual_piper_directory_nodes_is_not_admitted(self):
        storage=RESOURCE.storage_requirements(mode='install',payloads={RESOURCE.MANAGED_TREES['runtime']:{'bytes':1,'entries':0}},
            measured={'venv':{'allocated_bytes':210045952,'files':4383,'directories':538}})
        required=storage['inode_budgets'][RESOURCE.MANAGED_TREES['runtime']]
        self.assertGreater(required,4387+16,'Regular-file floor alone omits actual required directory nodes')
        machine=hardware(available=100);machine['storage']=storage
        machine['filesystems'][0].update(required_inodes=required,available_inodes=4500)
        result=RESOURCE.evaluate(machine,25)
        self.assertIn('storage_inodes_insufficient',[row['code']for row in result['errors']])

    def test_prior_static_recovery_models_destination_fragment_and_directory_growth(self):
        measured={'runtime':{'allocated_bytes':3*RESOURCE.MIB,'logical_bytes':3*RESOURCE.MIB,
                              'files':3000,'directories':500}}
        report=RESOURCE.storage_requirements(mode='install',measured=measured,
            allocation_units={RESOURCE.INSTALLER_JOURNAL:65536})
        actual=report['component_budgets_bytes'][RESOURCE.INSTALLER_JOURNAL]['prior_static_runtime_and_api_snapshot']
        minimum=3*RESOURCE.MIB+(3000+500)*65536+32*RESOURCE.MIB
        self.assertGreaterEqual(actual,minimum,'A large-fragment recovery destination needs its own per-entry allocation')

    def test_missing_voice_growth_retains_independent_target_replacement_peak(self):
        voice=RESOURCE.MANAGED_TREES['voices'];missing=RESOURCE.rounded(max(RESOURCE.VOICE_BYTES.values()))
        report=RESOURCE.storage_requirements(mode='install',missing_voices=missing)
        self.assertGreaterEqual(report['free_budgets_bytes'][voice],2*missing,
            'Promoted absent-model growth must not consume later corrupt-model atomic repair space')
        regional=max(RESOURCE.REGIONAL_VOICE_BYTES['en_GB-cori-high'].values())
        selected=RESOURCE.storage_requirements(mode='install',missing_voices=missing,optional_packs=('en_GB-cori-high',))
        self.assertGreaterEqual(selected['free_budgets_bytes'][voice],missing+RESOURCE.rounded(regional))

    def test_voice_probe_reserves_growth_for_sparse_and_multiply_linked_models(self):
        # Replacing a sparse inode can grow the target filesystem. Replacing
        # one name of a hard-linked inode leaves its old blocks occupied.
        size = 1024 * 1024
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            with (root / 'sparse').open('wb') as f:
                f.truncate(size)
            (root / 'linked').write_bytes(b'x' * size)
            os.link(root / 'linked', root / 'other-name')
            (root / 'ordinary').write_bytes(b'x' * size)
            trees = dict(RESOURCE.MANAGED_TREES, voices=name)
            with patch.object(RESOURCE, 'MANAGED_TREES', trees), \
                 patch.object(RESOURCE, 'VOICE_BYTES', dict.fromkeys(('sparse','linked','ordinary'), size)), \
                 patch.object(RESOURCE, 'FREE_BUDGETS', {name: 0}), \
                 patch.object(RESOURCE, 'measure_tree', return_value={}):
                result = RESOURCE.probe_storage()
            self.assertEqual(result['missing_voice_bytes'], 2 * size)
            self.assertEqual(result['free_budgets_bytes'][name], 3 * size)

    def test_piper_preparation_retains_future_floors_without_completed_source_copies(self):
        api=getattr(RESOURCE,'piper_preparation_requirements',None)
        self.assertTrue(callable(api),'Shared remaining Piper preparation obligations are missing')
        full=RESOURCE.storage_requirements(**self.actual_options());remaining=api(full,runtime_audio_bytes=231266304)
        for name in('data','config_backups','voices','module','web','sip_api','control_api','operator_portal'):
            path=RESOURCE.MANAGED_TREES[name]
            self.assertEqual(remaining['component_budgets_bytes'][path],full['component_budgets_bytes'][path])
        self.assertEqual(remaining['component_budgets_bytes']['/var/log'],full['component_budgets_bytes']['/var/log'])
        self.assertEqual(remaining['component_budgets_bytes'][RESOURCE.INSTALLER_JOURNAL],{
            'protected_config_snapshot':16*RESOURCE.MIB,'journal_metadata':4*RESOURCE.MIB})
        self.assertEqual(remaining['component_budgets_bytes']['/var/lib/sls-mass-notify-trust'],{
            'stock_and_release_manifests':8*RESOURCE.MIB})
        self.assertEqual(remaining['free_budgets_bytes'][RESOURCE.MANAGED_TREES['runtime']],
            full['piper_environment_requirements']['environment_bytes'])
        self.assertGreaterEqual(remaining['free_budgets_bytes']['/tmp'],231266304)
        self.assertIs(remaining['qualified_piper_reuse'],False)

    def test_replacement_admission_keeps_selected_profile_and_configured_or_detected_limits(self):
        storage = RESOURCE.storage_requirements(missing_voices=0)
        for saved, selected, contacts, admitted in (
            (None, 'lite', 0, True), (None, 'standard', 0, False),
            (None, None, 0, False), (None, 'lite', 26, False),
            ({'deployment_profile':'standard'}, 'lite', 0, True),
            ({'deployment_profile':'lite'}, None, 0, True),
            ({'deployment_profile':'lite'}, 'standard', 0, False),
            ({'deployment_profile':'standard','phone_device_limit':100}, 'lite', 0, False),
            (None, 'invalid', 0, False)):
            with self.subTest(saved=saved,selected=selected,contacts=contacts), contextlib.ExitStack() as mocks:
                def stub(name, value):
                    return mocks.enter_context(patch.object(RESOURCE,name,return_value=value))
                mocks.enter_context(patch.object(RESOURCE.os.path,'lexists',return_value=saved is not None))
                stub('configured_limits',saved)
                stub('detect_internal_phones',{'detected_phone_contacts':contacts})
                stub('probe_storage',storage)
                stub('_piper_preparation_payloads',None)
                stub('probe_compute',(2,2*GIB))
                stub('probe_cpu_isa',{})
                stub('probe_memory_limit',2*GIB)
                stub('probe_filesystems',hardware(available=100)['filesystems'])
                stub('probe_runtime_speech_scratch',{'required_free_bytes':1,'available_bytes':GIB})
                if admitted:
                    self.assertTrue(RESOURCE.admit_piper_preparation_storage('/tmp',profile=selected)['replacement_capacity_admitted'])
                else:
                    with self.assertRaises(ValueError):
                        RESOURCE.admit_piper_preparation_storage('/tmp',profile=selected)

    def test_capacity_upgrade_proof_api_is_separate_from_legacy_fresh_proofs(self):
        self.assertTrue(callable(getattr(RESOURCE,'capture_prepared_upgrade_storage_proof',None)),
                        'Prepared authenticated upgrade role capture is missing')
        self.assertTrue(callable(getattr(RESOURCE,'read_prepared_upgrade_storage_proof',None)),
                        'Prepared authenticated upgrade role validation is missing')


class RetainedVoiceCapacity(unittest.TestCase):
    def test_only_unverified_files_can_require_a_voice_write(self):
        voice = RESOURCE.MANAGED_TREES['voices']
        model = 'en_US-lessac-low.onnx'
        metadata = model + '.json'
        for pending, target, scratch in (
            ([], 0, 0),
            ([metadata], RESOURCE.rounded(RESOURCE.VOICE_BYTES[metadata], 65536), 8192),
            ([model], RESOURCE.rounded(RESOURCE.VOICE_BYTES[model], 65536),
             RESOURCE.rounded(RESOURCE.VOICE_BYTES[model], 8192)),
            ([model, metadata],sum(RESOURCE.rounded(RESOURCE.VOICE_BYTES[n],65536) for n in (model,metadata)),
             RESOURCE.rounded(RESOURCE.VOICE_BYTES[model],8192)),
        ):
            with self.subTest(pending=pending):
                result = RESOURCE.storage_requirements(missing_voices=0, pending_voice_files=pending,
                    allocation_units={voice:65536,'/tmp':8192})
                self.assertEqual(result['free_budgets_bytes'][voice], target)
                self.assertEqual(result['component_budgets_bytes']['/tmp']['one_voice_download'], scratch)
        unknown = RESOURCE.storage_requirements(missing_voices=0)
        self.assertGreater(unknown['free_budgets_bytes'][voice], 60*RESOURCE.MIB)
        fresh = RESOURCE.storage_requirements(pending_voice_files=list(RESOURCE.VOICE_BYTES))
        self.assertEqual(fresh['free_budgets_bytes'][voice],fresh['fresh_reference_voice_bytes'])
        for invalid in (['unknown'], [metadata,metadata], [False]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                RESOURCE.storage_requirements(pending_voice_files=invalid)

    def test_retained_voices_still_require_a_writable_persistent_mount_for_metadata(self):
        voice = RESOURCE.MANAGED_TREES['voices']
        usage = SimpleNamespace(f_blocks=100, f_bavail=50, f_frsize=4096, f_flag=os.ST_RDONLY)
        with patch.object(RESOURCE, 'filesystem_types', return_value=[(voice,'tmpfs',frozenset()),('/','ext4',frozenset())]), \
                patch.object(RESOURCE.Path, 'exists', return_value=True), \
                patch.object(RESOURCE.Path, 'resolve', lambda path:path), \
                patch.object(RESOURCE.Path, 'stat', lambda path:SimpleNamespace(st_dev=2 if str(path)==voice else 1)), \
                patch.object(RESOURCE.os, 'statvfs', return_value=usage):
            rows=RESOURCE.probe_filesystems({voice:0},{voice:0})
        actual=next(row for row in rows if voice in row['paths'])
        self.assertTrue(actual['read_only'])
        self.assertEqual(actual['volatile_targets'],[voice])
        self.assertEqual(actual['required_free_bytes'],0)
        self.assertEqual(actual['required_inodes'],0)

    def test_actual_checker_skips_only_the_exact_current_bytes(self):
        self.assertEqual(os.environ.get('SLS_TEST_NAMESPACE'),'entered')
        voices = Path(RESOURCE.MANAGED_TREES['voices'])
        voices.mkdir(parents=True,exist_ok=True)
        target = voices/'en_US-lessac-low.onnx.json'
        target.unlink(missing_ok=True)
        self.addCleanup(target.unlink,missing_ok=True)
        body = b'fixture pinned model metadata'
        digest = hashlib.sha256(body).hexdigest()
        def current():
            return RESOURCE.piper_voice_current(target,digest,len(body))
        self.assertFalse(current())
        target.write_bytes(body); target.chmod(0o644)
        self.assertTrue(current())
        result = subprocess.run(['/usr/bin/python3','-I',str(SOURCE),'--voice-current',str(target),digest,str(len(body))],capture_output=True,timeout=5)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))
        target.write_bytes(b'x'*len(body))
        self.assertFalse(current())
        target.write_bytes(body); target.chmod(0o666)
        self.assertFalse(current())
        target.chmod(0o644)
        link = voices/'fixture-other-file'
        self.addCleanup(link.unlink,missing_ok=True)
        os.link(target,link); self.assertFalse(current())
        target.unlink(); target.symlink_to(link); self.assertFalse(current())
        self.assertFalse(RESOURCE.piper_voice_current(link,digest,len(body)))
        target.unlink()
        os.replace(link, target)
        self.assertFalse(RESOURCE.piper_voice_current(target,digest,len(body),deadline=0))
        original_read = os.read
        def change_during_read(fd, size):
            data = original_read(fd, size)
            if size == len(body):
                target.write_bytes(b'x' * len(body))
            return data
        with patch.object(RESOURCE.os, 'read', side_effect=change_during_read):
            self.assertFalse(current())
        target.write_bytes(body)
        with patch.object(RESOURCE, '_voice_change_watch', return_value=None):
            self.assertTrue(current(), 'A stable verified voice can be reused without inotify')
            with patch.object(RESOURCE.os, 'read', side_effect=change_during_read):
                self.assertFalse(current(), 'Independent bounded read missed an overlapping rewrite')

    def test_default_and_selected_optional_hashes_match_the_writer_catalog(self):
        shell = (ROOT/'slsmassnotifyserver/bin/sls_mass_notify_install_piper_voices.sh').read_text()
        canonical=dict(re.findall(r'\["([^"\n]+\.onnx(?:\.json)?)"\]="([a-f0-9]{64})"',shell))
        catalog=json.loads((ROOT/'slsmassnotifyserver/bin/sls_mass_notify/piper-optional-voices.json').read_bytes())
        for pack in catalog['voices']:
            canonical.update({name:entry['sha256'] for name,entry in pack['files'].items()})
        self.assertEqual(RESOURCE.VOICE_SHA256,canonical)

    def test_hashing_is_scoped_to_authenticated_late_install_and_retained_across_scratch_choice(self):
        voice=RESOURCE.MANAGED_TREES['voices']
        with patch.object(RESOURCE,'measure_tree',return_value={}), \
                patch.object(RESOURCE,'piper_voice_current',return_value=True) as verifier:
            common=dict(mode='install',payloads={})
            unknown=RESOURCE.probe_storage(**common)
            verifier.assert_not_called()
            for mode in ('prepare','runtime'):
                RESOURCE.probe_storage(mode=mode,verify_voice_content=True)
                verifier.assert_not_called()
            proven=RESOURCE.probe_storage(**common,verify_voice_content=True)
            self.assertEqual(verifier.call_count,len(RESOURCE.VOICE_BYTES))
            self.assertEqual(proven['pending_voice_files'],[])
            self.assertEqual(proven['free_budgets_bytes'][voice],0)
            self.assertIsNone(unknown['pending_voice_files'])
            with patch.object(RESOURCE,'trusted_temporary_directory',return_value=True), \
                    patch.object(RESOURCE,'probe_filesystems',return_value=[]):
                changed,_=RESOURCE.probe_storage_filesystems(proven,'/var/tmp')
            self.assertEqual(changed['pending_voice_files'],[])
            self.assertEqual(changed['component_budgets_bytes']['/var/tmp']['one_voice_download'],0)

if __name__ == '__main__':
    unittest.main()
