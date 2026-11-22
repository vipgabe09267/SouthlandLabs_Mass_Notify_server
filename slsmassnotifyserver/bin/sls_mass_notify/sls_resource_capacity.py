#!/usr/bin/env python3
"""Read-only admission checks for provisional combined PBX/SLL resource tiers.

These engineering allocations do not certify delivery throughput. Desktop
transport retains its separate stream limit and requires JSON-poll fallback.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import pwd

import re
import stat
import subprocess
import sys
import time
import types
import xml.etree.ElementTree as ET

PRIVATE_INSTALL_TEMP = '/var/spool/sls-mass-notify-installer-tmp'
GIB = 1024 ** 3
MIB = 1024 ** 2
TIERS = ((50, 2, 4), (100, 3, 5), (250, 4, 6), (500, 6, 8), (1000, 8, 12))
LITE_TIERS = ((25, 2, 2),)
DEPLOYMENT_PROFILES = ('standard', 'lite')
LITE_MAX_DESKTOPS = 25
LITE_MAX_PHONES = 25
MAX_KERNEL_RESERVE = 256 * MIB
PHONE_BASELINE = 25
# 2026-10-02 private Asterisk: 25/50/100 PCM conference recipients used
# 0.058/0.133/0.242 cores and 35/41/52 MiB total RSS. Allow substantially more
# for SIP/SRTP, transcoding, caller setup bursts and normal PBX call traffic.
PHONE_RESOURCE_BASELINE = 100
PHONE_CONTACTS_PER_CPU = 200
PHONE_MEMORY_PER_CONTACT = 2 * MIB
PHONE_MEMORY_ROUNDING = 256 * MIB
# Reference measured 2026-10-23 on Debian12/CPython3.11/amd64 with every exact pin.
# The compressed wheel sizes are from the corresponding PyPI version JSON APIs.
PINNED_VENV_ALLOCATED = 218210304
PINNED_VENV_FILES = 4387
# Complete no-follow calibration of the unchanged pinned environment, 2026-11-15:
# 4,383 regular files, 538 directories and four standard interpreter/lib aliases.
# The 4 KiB projection includes every node, including directory/link allocation.
PINNED_VENV_REGULAR_FILES = 4383
PINNED_VENV_DIRECTORIES = 538
PINNED_VENV_SYMLINKS = 4
PINNED_VENV_TOTAL_REFERENCE_BYTES = 220450816
PINNED_WHEEL_BYTES = 77861012
PINNED_VERSIONS = {'pip': '26.2.1', 'setuptools': '84.2.1', 'wheel': '0.48.0',
                   'piper-tts': '1.8.0', 'onnxruntime': '1.30.0', 'numpy': '2.4.6',
                   'flatbuffers': '25.12.19', 'packaging': '26.3',
                   'pathvalidate': '3.3.1', 'protobuf': '7.36.2'}
VOICE_BYTES = {'en_US-lessac-low.onnx': 63201294, 'en_US-lessac-low.onnx.json': 4882,
               'en_US-lessac-medium.onnx': 63201294, 'en_US-lessac-medium.onnx.json': 4885,
               'en_US-amy-low.onnx': 63104526, 'en_US-amy-low.onnx.json': 4164,
               'en_US-ryan-low.onnx': 63104526, 'en_US-ryan-low.onnx.json': 4165,
               'es_ES-davefx-medium.onnx': 63201294,
               'es_ES-davefx-medium.onnx.json': 4817,
               'fr_FR-siwis-medium.onnx': 63201294,
               'fr_FR-siwis-medium.onnx.json': 4875,
               'de_DE-thorsten-low.onnx': 63104526,
               'de_DE-thorsten-low.onnx.json': 4159,
               'pt_BR-faber-medium.onnx': 63201294,
               'pt_BR-faber-medium.onnx.json': 4855}
REGIONAL_VOICE_BYTES = {'es_MX-ald-medium': {'es_MX-ald-medium.onnx.json': 4878, 'es_MX-ald-medium.onnx': 63201294}, 'en_GB-cori-high': {'en_GB-cori-high.onnx.json': 4963, 'en_GB-cori-high.onnx': 114219352}}
VOICE_SHA256 = {
    'de_DE-thorsten-low.onnx': '9ac27fad17cec5c1a791161976a64f026f16fc058b400b1fea62565b8b2cf375',
    'de_DE-thorsten-low.onnx.json': 'df38e892ed949f62d0c40978bc666de0b341c5f7921840ae7c72f4df8e8ffa05',
    'en_GB-cori-high.onnx': '470b4dd634c98f8a4850d7626ffc3dfc90774628eeef6605a6dd8f88f30a5903',
    'en_GB-cori-high.onnx.json': '9e7fb5b5671612c22f3c81cbe46c1ae87b031a4632bcb509e499dad6f1e2adec',
    'en_US-amy-low.onnx': 'a5a91abb7de0f104358a25aded480ddacf1ff0762886325886ec406a2e86aab3',
    'en_US-amy-low.onnx.json': '2250a9a605b8dc35a116717fadc5056695dd809e34a15d02f72a0f52d53d3ebb',
    'en_US-lessac-low.onnx': 'f7d01dde371555732c4c314111ac79672b1a5ce2fc19266ab42178fd8df7f375',
    'en_US-lessac-low.onnx.json': '45754dfdebb3b8661c3fc564713772deec6e064feeb5b4e9594857dc7305193a',
    'en_US-lessac-medium.onnx': '5efe09e69902187827af646e1a6e9d269dee769f9877d17b16b1b46eeaaf019f',
    'en_US-lessac-medium.onnx.json': 'efe19c417bed055f2d69908248c6ba650fa135bc868b0e6abb3da181dab690a0',
    'en_US-ryan-low.onnx': '8d21a085cc4c0010f1f3e91d5008c8691277ccfa744eb0d747becd33a3444baf',
    'en_US-ryan-low.onnx.json': 'b27147e56b0525962609f82f58171f4618cbf17c6fb043d7d724ff28cc4aed60',
    'es_ES-davefx-medium.onnx': '6658b03b1a6c316ee4c265a9896abc1393353c2d9e1bca7d66c2c442e222a917',
    'es_ES-davefx-medium.onnx.json': '0e0dda87c732f6f38771ff274a6380d9252f327dca77aa2963d5fbdf9ec54842',
    'es_MX-ald-medium.onnx': '019b3803293c93e34a206dd2e53a3889209a514e786fd7144f7b70196c579b63',
    'es_MX-ald-medium.onnx.json': '5a71498158e04afc8099bfd019c7e87c68eb9d042505a2b1a87e5c1ac2b1a61d',
    'fr_FR-siwis-medium.onnx': '641d1ab097da2b81128c076810edb052b385decc8be3381814802a64a73baf99',
    'fr_FR-siwis-medium.onnx.json': '39479916c2db192b5ac9764daddd0c744d83e023ad890c6976c0633ae4df8959',
    'pt_BR-faber-medium.onnx': '858555e3a064209c57088fe6bd70c4c3dc54d03eaa00c45d5ecaf43a33f95aa7',
    'pt_BR-faber-medium.onnx.json': '7e694de195ae3fc36dd732c445eb04fb49b649854893cb5506b978f0d50a1d6f',
}
MANAGED_TREES = {'runtime': '/usr/local/bin/sls_mass_notify',
                 'venv': '/usr/local/bin/sls_mass_notify/piper/venv',
                 'voices': '/var/lib/asterisk/SLS_Mass_Notifications_Plugin/piper/voices',
                 'data': '/var/lib/asterisk/SLS_Mass_Notifications_Plugin',
                 'config_backups': '/var/lib/asterisk/SLS_Mass_Notifications_Plugin/config-backups',
                 'audio': '/var/lib/asterisk/SLS_Mass_Notifications_Plugin/sounds/tts',
                 'module': '/var/www/html/admin/modules/slsmassnotifyserver',
                 'web': '/var/www/html/sls_mass_notify',
                 'assets': '/var/www/html/sls_mass_notify/assets',
                 'sip_api': '/var/www/html/api/sipnotify',
                 'control_api': '/var/www/html/api/sls-mass-notify', 'operator_portal': '/var/www/html/mass-notify'}
STATE_FILES = {'phone_ledger': 'phone-admission.json', 'weather_ledger': 'weather-delivery.json',
               'schedule_ledger': 'schedule-executions.json', 'config': 'mass-notifications.config'}
RECOVERY_RECORDINGS = tuple('/var/lib/asterisk/sounds/en/custom/' + name + '.wav' for name in (
    'SLS_Mass_Notify_Paging_Tone_Opening', 'SLS_Mass_Notify_Paging_Tone_Closing',
    'SLS_Mass_Notify_NWS_Alert', 'SLS_Mass_Notify_Lightning_Alert',
    'Paging_Tone_Opening', 'Paging_Tone_Closing', 'NWS_alert', 'Lightning_alert')) + tuple(
    MANAGED_TREES['data'] + '/sounds/tones/' + name + '.wav' for name in (
    'opening_Paging_Tone_Opening', 'closing_Paging_Tone_Closing', 'opening_NWS_alert', 'opening_Lightning_alert'))
PERSISTENT_PATHS = ('/', '/var/lib/asterisk', '/usr/local', '/var/www', '/var/log')
INSTALLER_JOURNAL = '/var/lib/sls-mass-notify-installer'
STOCK_CACHE = '/var/lib/sls-mass-notify-trust/stock-packages'
MAX_RELEASE_ENTRIES = 5000
BOOTSTRAP_HELPER_ENTRIES = 12
PREPARE_METADATA_ENTRIES = 16
JOURNAL_METADATA_ENTRIES = 128


def rounded(value, unit=4096):
    return (int(value) + unit - 1) // unit * unit


def piper_environment_requirements(measured=None, allocation_unit=4096):
    """One conservative file/directory model for admission and actual builders."""
    if type(allocation_unit) is not int or allocation_unit <= 0:
        raise ValueError('Qualified Piper allocation unit required')
    unit = max(4096, allocation_unit)
    if unit & (unit - 1):
        raise ValueError('Piper allocation unit must be a qualified power of two')
    measured = {} if measured is None else measured
    if type(measured) is not dict:
        raise ValueError('Piper measurement object required')
    for key in ('allocated_bytes', 'files', 'directories'):
        if type(measured.get(key, 0)) is not int or not 0 <= measured.get(key, 0) < 2**63:
            raise ValueError('Typed Piper allocation measurement required')
    files = max(PINNED_VENV_FILES, PINNED_VENV_REGULAR_FILES + PINNED_VENV_SYMLINKS,
                measured.get('files', 0) + PINNED_VENV_SYMLINKS)
    directories = max(PINNED_VENV_DIRECTORIES, measured.get('directories', 0))
    reference_nodes = PINNED_VENV_REGULAR_FILES + PINNED_VENV_DIRECTORIES + PINNED_VENV_SYMLINKS
    reference_bytes = PINNED_VENV_TOTAL_REFERENCE_BYTES + reference_nodes * (unit - 4096)
    observed_bytes = measured.get('allocated_bytes', 0) + (directories + PINNED_VENV_SYMLINKS) * unit
    # The lock, optional empty bind target, stage parent and retained-marker
    # publication each retain one inode/allocation-unit of control headroom.
    control_entries = 4
    return {'allocation_unit': unit, 'reference_bytes': reference_bytes,
            'reference_regular_files': PINNED_VENV_REGULAR_FILES,
            'reference_directories': PINNED_VENV_DIRECTORIES, 'reference_symlinks': PINNED_VENV_SYMLINKS,
            'environment_bytes': max(reference_bytes, observed_bytes) + control_entries * unit,
            'required_inodes': files + directories + control_entries,
            'control_entries': control_entries, 'control_bytes': control_entries * unit}


def storage_requirements(measured=None, missing_voices=None, allocation_units=None, temporary_directory='/tmp', *, mode='install', payloads=None, optional_packs=(), reserve_install_workspace=False, previous_release_required=True, prepared_release_resident=False, stock_cache_publication_required=True, qualified_piper_reuse=False, stock_cache_publication_sizes=None, pending_voice_files=None):
    """Explain each byte reservation; retained history is not a fixed quota.

    Installation workspaces may overlap bounded state updates/compaction.
    Shared synthesis admission and generated-media budgets are enforced by
    the runtime; audit/history retention still needs separate provisioning.
    """
    measured = measured or {}
    if mode not in ('runtime', 'prepare', 'install'):
        raise ValueError('Unsupported storage admission mode')
    if reserve_install_workspace and mode != 'prepare':
        raise ValueError('Install workspace reservation requires prepare mode')
    if temporary_directory not in ('/tmp', '/var/tmp', PRIVATE_INSTALL_TEMP) or (mode == 'runtime' and temporary_directory == PRIVATE_INSTALL_TEMP):
        raise ValueError('Unsupported installation workspace')
    units = allocation_units or {}
    size = lambda name: int(measured.get(name, {}).get('allocated_bytes', 0))
    unit = lambda path: max(4096, int(units.get(path, 4096)))
    def recovery_size(name):
        row = measured.get(name, {})
        aliases = PINNED_VENV_SYMLINKS if name == 'runtime' and size(name) else 0
        # Recovery copies allocate on the journal filesystem, whose fragments
        # may be larger than the source filesystem's allocated-file totals.
        entries = int(row.get('files', 0)) + int(row.get('directories', 0)) + aliases
        return max(size(name), int(row.get('logical_bytes', 0)) + entries * unit(INSTALLER_JOURNAL))
    # Accepted releases contain at most 5,000 entries and 50 MiB of regular-file data.
    payloads = payloads or {}
    payload = lambda path: (int(payloads[path]['bytes']) + int(payloads[path]['entries']) * unit(path)
                            if path in payloads else 50 * MIB + MAX_RELEASE_ENTRIES * unit(path))
    runtime, voices, data = (MANAGED_TREES[name] for name in ('runtime', 'voices', 'data'))
    piper_environment = piper_environment_requirements(measured.get('venv'), unit(runtime))
    piper_temporary = piper_environment_requirements(measured.get('venv'), unit(temporary_directory))
    reference_venv = piper_environment['reference_bytes']
    venv = piper_environment['environment_bytes']
    temporary_venv = piper_temporary['environment_bytes']
    voice_sizes=dict(VOICE_BYTES)
    for pack in optional_packs:
        if pack not in REGIONAL_VOICE_BYTES:raise ValueError('Unknown optional speech pack')
        voice_sizes.update(REGIONAL_VOICE_BYTES[pack])
    voice_total = sum(rounded(value, unit(voices)) for value in voice_sizes.values())
    if missing_voices is None:
        missing_voices = voice_total
    if type(missing_voices) is not int or not 0 <= missing_voices <= voice_total:
        raise ValueError('Typed missing voice allocation required')
    remaining = voice_sizes
    if pending_voice_files is not None:
        if (mode != 'install' or not isinstance(pending_voice_files, (tuple, list))
                or any(type(name) is not str or name not in voice_sizes for name in pending_voice_files)
                or len(set(pending_voice_files)) != len(pending_voice_files)):
            raise ValueError('Invalid authenticated remaining voice inventory')
        remaining = {name:voice_sizes[name] for name in pending_voice_files}
    largest_pending_voice = max(remaining.values(), default=0)
    if pending_voice_files is None:
        # Prior to checksum qualification keep the ordinary catalog growth and
        # largest atomic replacement allowance.
        voice_target_bytes = min(voice_total, missing_voices + rounded(largest_pending_voice, unit(voices)))
    else:
        # Each pending body can be published once. Credit only verified files
        # that the writer skips, never blocks a replaced file might release.
        voice_target_bytes = sum(rounded(n, unit(voices)) for n in remaining.values())
    # Phone and weather state reserve 16 MiB each; encrypted configuration
    # reserves 3 MiB; schedules reserve at least their 10 MiB backup limit or
    # their actual size. Up to 25 queued jobs may write 2 MiB records.
    atomic_state = sum(max(limit * MIB, size(name)) for name, limit in
                       (('phone_ledger', 16), ('weather_ledger', 16), ('schedule_ledger', 10), ('config', 3))) + 25 * 2 * MIB
    # Retain 20 encrypted configuration backups, each bounded to 3 MiB.
    backup_growth = max(0, 20 * 3 * MIB - size('config_backups'))
    # Each absent signed body is published once: TRUST.atomic creates it in
    # the destination directory and renames that inode into place. No obsolete
    # package deletion is needed to justify the credit.
    stock_sizes = stock_cache_publication_sizes if mode == 'install' else None
    if stock_sizes is not None:
        if (not isinstance(stock_sizes, (list,tuple)) or len(stock_sizes) > 2
                or any(type(n) is not int or not 0 < n <= 64*MIB for n in stock_sizes)):
            raise ValueError('Invalid authenticated stock publication sizes')
        stock_growth = sum(rounded(n,unit(STOCK_CACHE)) for n in stock_sizes)
        stock_peak = len(stock_sizes) * unit(STOCK_CACHE)  # directory-entry growth
    elif stock_cache_publication_required is False and mode == 'install':
        stock_growth = stock_peak = 0
    else:
        stock_growth, stock_peak = 4 * 64 * MIB, 64 * MIB
    components = {
        INSTALLER_JOURNAL: {
            'protected_config_snapshot': 16 * MIB,
            'reviewed_previous_and_candidate_sources': (0 if prepared_release_resident is True else payload(INSTALLER_JOURNAL)) + (50 * MIB + MAX_RELEASE_ENTRIES * unit(INSTALLER_JOURNAL) if previous_release_required is not False else 0),
            'previous_release_download_and_metadata': 64 * MIB + 16 * 1024 + 4096 if previous_release_required is not False else 0,
            'saved_candidate_archive_and_metadata': 0 if prepared_release_resident is True else 52 * MIB + 16 * 1024 + 4096,
            'authenticated_bootstrap_helpers': 0 if prepared_release_resident is True else payload(INSTALLER_JOURNAL),
            'prior_static_runtime_and_api_snapshot': sum(recovery_size(name) for name in
                ('runtime', 'assets', 'sip_api', 'control_api', 'operator_portal', 'recovery_recordings')) + 32 * MIB,
            'journal_metadata': 4 * MIB,
        },
        runtime: {'replacement_runtime': payload(runtime) if qualified_piper_reuse is True and mode == 'install' else max(size('runtime'), venv + payload(runtime))},
        # Promotions run one at a time. One voice-sized temporary can
        # overlap previously promoted growth, but every final body or its
        # temporary contributes at most once to the full catalog bound.
        voices: {'missing_or_replacement_voices': voice_target_bytes},
        data: {'bounded_atomic_state_writes': atomic_state,
               'desktop_delivery_history_headroom': 160 * MIB,
               # Sixteen independently locked 4 MiB ledgers may replace in parallel.
               'browser_evidence_and_atomic_write_headroom': 16 * 2 * 4 * MIB,
               'conditional_weather_cache_and_atomic_write_headroom': 64 * MIB,
               'desktop_feed_cache_and_atomic_write_headroom': 128 * MIB + 8192,
               'postfix_evidence_and_atomic_write_headroom': 8 * MIB},
        MANAGED_TREES['config_backups']: {'remaining_bounded_config_backups': backup_growth},
        MANAGED_TREES['module']: {'new_module_payload': payload(MANAGED_TREES['module'])},
        # Independent target mounts each need room for a legal package payload.
        MANAGED_TREES['web']: {'public_asset_payload': payload(MANAGED_TREES['web'])},
        MANAGED_TREES['sip_api']: {'sip_api_payload': payload(MANAGED_TREES['sip_api'])},
        MANAGED_TREES['control_api']: {'control_api_payload': payload(MANAGED_TREES['control_api'])},
        MANAGED_TREES['operator_portal']: {'operator_portal_payload': payload(MANAGED_TREES['operator_portal'])},
        # Maintenance compacts logs sequentially, using backup and retained temporary files.
        '/var/log': {'event_log_backup_and_retained_copy': 2 * 64 * MIB},
        '/var/lib/sls-mass-notify-trust': {'new_authenticated_generation': payload('/var/lib/sls-mass-notify-trust'),
                                         'stock_and_release_manifests': 8 * MIB},
        STOCK_CACHE: {'bounded_signed_stock_cache': stock_growth, 'signed_stock_cache_atomic_write': stock_peak},
        temporary_directory: {'release_download_and_metadata': 52 * MIB + 16 * 1024 + 4096,
                 'extracted_release': payload(temporary_directory), 'failed_release_recovery': payload(temporary_directory),
                 # Two retained signed upstream packages and one active GPG
                 # verification's signed/plain copies; each bounded to64MiB.
                 'upstream_package_verification': 4 * 64 * MIB,
                 'missing_signed_helper_repairs': payload(temporary_directory),
                 'quarantined_python_caches': 16 * MIB,
                 'pinned_wheel_downloads': 0 if qualified_piper_reuse is True and mode == 'install' else rounded(PINNED_WHEEL_BYTES, unit(temporary_directory)),
                 'wheel_unpack_workspace': 0 if qualified_piper_reuse is True and mode == 'install' else temporary_venv,
                 'pip_old_package_recovery': 0 if qualified_piper_reuse is True and mode == 'install' else temporary_venv,
                 'one_voice_download': rounded(largest_pending_voice, unit(temporary_directory))},
    }
    install_scratch = components[temporary_directory]
    if mode != 'install':
        components = {data: {'bounded_atomic_state_writes': atomic_state},
                      MANAGED_TREES['config_backups']: {'remaining_bounded_config_backups': backup_growth},
                      '/var/log': {'event_log_backup_and_retained_copy': 2 * 64 * MIB}}
        if mode == 'prepare':
            components[temporary_directory] = (install_scratch if reserve_install_workspace else {
                'release_download_and_metadata': 52 * MIB,
                'extracted_release': payload(temporary_directory)})
        else:
            components[temporary_directory] = {}
    budgets = {path: sum(parts.values()) for path, parts in components.items()}
    inode_budgets = {data: 128, MANAGED_TREES['config_backups']: 24, '/var/log': 8, temporary_directory: 0}
    if mode == 'prepare':
        inode_budgets[temporary_directory] = (
            2 * int(payloads.get(temporary_directory, {}).get('entries', MAX_RELEASE_ENTRIES)) + 128
            if reserve_install_workspace else MAX_RELEASE_ENTRIES + BOOTSTRAP_HELPER_ENTRIES + PREPARE_METADATA_ENTRIES)
    elif mode == 'install':
        for path in components:
            if path not in inode_budgets:
                inode_budgets[path] = int(payloads.get(path, {}).get('entries', MAX_RELEASE_ENTRIES)) + 16
        # Four retained packages, two interrupted writes and directory metadata.
        inode_budgets[STOCK_CACHE] = 8
        inode_budgets[runtime] += piper_environment['required_inodes']
        inode_budgets[voices] = len(remaining) + 4 if remaining else 0
        inode_budgets[temporary_directory] = 2 * int(payloads.get(temporary_directory, {}).get('entries', MAX_RELEASE_ENTRIES)) + 128
        inode_budgets[INSTALLER_JOURNAL] = (int(payloads.get(INSTALLER_JOURNAL, {}).get('entries', MAX_RELEASE_ENTRIES))
            + MAX_RELEASE_ENTRIES + BOOTSTRAP_HELPER_ENTRIES + JOURNAL_METADATA_ENTRIES) + sum(
            int(measured.get(name, {}).get('files', 0)) + int(measured.get(name, {}).get('directories', 0))
            for name in ('runtime', 'assets', 'sip_api', 'control_api', 'operator_portal', 'recovery_recordings'))
    if mode == 'install' or mode == 'prepare' and reserve_install_workspace:
        inode_budgets[temporary_directory] += 2 * piper_temporary['required_inodes'] + 16
    fixed_names = ('runtime', 'voices', 'module', 'assets', 'sip_api', 'control_api')
    fixed = sum(size(name) for name in fixed_names)
    mutable = max(0, size('data') - size('voices')) + max(0, size('web') - size('assets'))
    return {'basis': 'authenticated_payload_and_filesystem_recovery_2026-10-06', 'mode': mode,
            'previous_release_required': previous_release_required is not False,
            'prepared_release_resident': prepared_release_resident is True and mode == 'install',
            'stock_cache_publication_required': bool(stock_growth or stock_peak),
            'stock_cache_publication_sizes': stock_sizes,
            'qualified_piper_reuse': qualified_piper_reuse is True and mode == 'install',
            'install_workspace_reserved': reserve_install_workspace,
            'measured_fixed_allocation_bytes': fixed, 'measured_mutable_data_and_media_bytes': mutable,
            'measured_trees': measured, 'fresh_reference_voice_bytes': voice_total,
            'pinned_runtime_reference_bytes': reference_venv, 'pinned_wheel_download_bytes': PINNED_WHEEL_BYTES,
            'piper_environment_requirements': piper_environment, 'piper_temporary_requirements': piper_temporary,
            'component_budgets_bytes': components, 'free_budgets_bytes': budgets,
            'inode_budgets': inode_budgets, 'allocation_units': units, 'payloads': payloads,
            'missing_voice_bytes': missing_voices, 'optional_voice_packs':list(optional_packs),
            'pending_voice_files': None if pending_voice_files is None else sorted(remaining),
            'temporary_directory': temporary_directory,
            'sls_persistent_free_bytes': sum(value for path, value in budgets.items() if path != temporary_directory),
            'temporary_free_bytes': budgets[temporary_directory],
            'additional_free_bytes': sum(budgets.values()),
            'steady_state_reserve_bytes': atomic_state + backup_growth + 2 * 64 * MIB,
            'retention_is_byte_bounded': False, 'generated_media_admission_is_byte_bounded': True,
            'synthesis_concurrency_is_enforced': True,
            'render_workspace_formula': {'raw_pcm_bytes': 'duration_seconds * voice_sample_rate * 2 + WAV header',
                                         'pbx_pcm_bytes': 'duration_seconds * 8000 * 2 + WAV header',
                                         'provisioning': 'Reserve raw audio, converted speech, final sequence and temporary sequence for each simultaneously rendering job. Add retained output separately.'},
            'retention_provisioning': 'Generated-media admission respects its configured cache and free-space budgets; active referenced media is preserved. Audit/history retention needs measured provisioning over its chosen window. Speech workspace is reserved before synthesis.'}


_FRESH_KIND = 'sll-fresh-release-storage-proof-v1'
_FRESH_FILE = 'resource-relationship-proof.json'
_FRESH_SETTINGS = frozenset(('RECOVERY_DIR', 'INSTALL_BOOTSTRAP_DIR', 'UPGRADE_TRUST_DIR',
    'CONFIG_SNAPSHOT', 'CONFIG_HASH_BEFORE', 'PENDING_CONFIG_STATE', 'PENDING_CONFIG_PATH',
    'PENDING_CONFIG_SNAPSHOT', 'PENDING_CONFIG_HASH', 'MODULE_BACKUP_DIR', 'STAGING_DIR',
    'HAD_EXISTING_MODULE', 'MODULE_WAS_ENABLED', 'MODULE_ACTIVATED', 'STATIC_MUTATION_STARTED',
    'ORIGINAL_SYSTEM_TIMEZONE', 'SYSTEM_TIMEZONE_CHANGED'))
_FRESH_LOCKS = frozenset(('enterprise-worker.lock', 'phone-history-retention.lock',
    'schedule-runner.lock', 'schedule-worker.lock', 'announcement-send.lock',
    'announcement-activity.lock', 'weather-observation.lock', 'weather-dispatch-worker.lock',
    'weather-external-worker.lock', 'xweather-poll.lock', 'sls_mass_notify_nws_poll.lock',
    'nws-audio-delivery.lock', 'test-cooldown.ts.lock', 'audio-reservations.lock',
    'mass-notifications.config.lock', *(f'live-paging-slots/global-{n}.lock' for n in range(16))))
_FRESH_ABSENT = ('/var/www/html/admin/modules/slsmassnotifyserver', MANAGED_TREES['runtime'],
    MANAGED_TREES['data'] + '/mass-notifications.config',
    MANAGED_TREES['data'] + '/mass-notifications.pending.config', '/etc/sls-mass-notify/config-keys.json',
    '/var/lib/sls-mass-notify-trust/publisher-trust.json',
    '/var/lib/sls-mass-notify-trust/release-trust.initialized',
    '/var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json',
    '/usr/local/bin/slsconsole', '/usr/local/sbin/sign_sls_mass_notify_local_sig.sh',
    '/etc/systemd/system/sls-mass-notify-phone-events.service',
    '/etc/systemd/system/sls-mass-notify-phone-events.service.d',
    '/etc/apache2/conf-available/sls-mass-notify.conf', '/etc/apache2/conf-enabled/sls-mass-notify.conf',
    '/etc/logrotate.d/sls-mass-notify', '/usr/local/bin/piper',
    '/var/www/html/api/sipnotify', '/var/www/html/api/sls-mass-notify',
    '/var/www/html/mass-notify', '/var/www/html/sls_mass_notify',
    '/var/lib/asterisk/sounds/SLS_Mass_Notifications_Plugin',
    '/var/lib/asterisk/sounds/en/SLS_Mass_Notifications_Plugin',
    '/root/.gnupg-sls-mass-notify', *RECOVERY_RECORDINGS)


def _fresh_json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result: raise ValueError('ambiguous fresh storage proof')
            result[name] = value
        return result
    def invalid(unused): raise ValueError('nonfinite fresh storage proof')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def _fresh_directory(path, owners=(0,), private=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('noncanonical proof directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid not in owners or info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                raise ValueError('unprotected fresh proof directory')
        if private and os.fstat(fd).st_mode & 0o077: raise ValueError('private fresh proof directory required')
        return fd
    except BaseException:
        os.close(fd); raise


def _fresh_read(path, maximum=65536, *, private=True, owners=(0,)):
    path = Path(path); parent = _fresh_directory(path.parent, owners)
    fd = -1
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        stamp = lambda s: tuple(getattr(s, 'st_' + k) for k in ('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'))
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in owners or before.st_nlink != 1
                or before.st_mode & (0o077 if private else 0o022) or not 0 <= before.st_size <= maximum):
            raise ValueError('unprotected fresh proof file')
        with os.fdopen(os.dup(fd), 'rb') as stream: body = stream.read(maximum + 1)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if len(body) != before.st_size or stamp(before) != stamp(os.fstat(fd)) or stamp(before) != stamp(named):
            raise ValueError('fresh proof file changed')
        return body, before
    finally:
        if fd >= 0: os.close(fd)
        os.close(parent)


def _fresh_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _fresh_review_binding(review, candidate):
    descriptor = _fresh_directory(review, private=True); os.close(descriptor)
    previous, _ = _fresh_read(review / 'previous-root-approval.json')
    web, _ = _fresh_read(review / 'previous-web-approval.json', 8 * MIB)
    prior, prior_web = _fresh_json(previous), _fresh_json(web)
    if (not isinstance(prior, dict) or type(prior.get('schema')) is not int
            or prior != {'schema': 1, 'source': 'fresh-install', 'files': {}, 'root_jobs': []}
            or not isinstance(prior_web, dict) or prior_web.get('slsmassnotifyserver', 'unknown') is not None):
        raise ValueError('previous release is not independently absent')
    for name in ('previous-release', 'previous-registry', 'previous-runtime-repairs', 'runtime-cache-recovery'):
        if os.path.lexists(review / name): raise ValueError('previous release recovery evidence exists')
    reference, _ = _fresh_read(review / 'registry/slsmassnotifyserver.active.json', 1024)
    pointer = _fresh_json(reference)
    if (not isinstance(pointer, dict) or set(pointer) != {'generation', 'sha256'}
            or not re.fullmatch('[a-f0-9]{64}', str(pointer.get('sha256', '')))
            or pointer.get('generation') != 'slsmassnotifyserver-' + pointer['sha256']):
        raise ValueError('candidate generation reference differs')
    inventory, _ = _fresh_read(review / 'registry' / pointer['generation'] / 'inventory.json', 8 * MIB)
    value = _fresh_json(inventory)
    if (not isinstance(value, dict) or hashlib.sha256(inventory).hexdigest() != pointer['sha256']
            or type(value.get('schema')) is not int or value['schema'] != 1
            or value.get('module') != 'slsmassnotifyserver' or not isinstance(value.get('source'), dict)
            or value['source'].get('kind') != 'publisher-ed25519'
            or not re.fullmatch('[a-f0-9]{64}', str(value.get('source', {}).get('archive_sha256', '')))
            or not isinstance(value.get('version'), str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-beta)?', value['version'])
            or not isinstance(value.get('files'), dict) or not 1 <= len(value['files']) <= 5000):
        raise ValueError('authenticated candidate inventory differs')
    descriptor = _fresh_directory(candidate)
    try:
        if os.fstat(descriptor).st_mode & 0o022: raise ValueError('candidate source is writable')
    finally: os.close(descriptor)
    found = {}; count = total = 0
    for parent, directories, files in os.walk(candidate, followlinks=False):
        for name in (*directories, *files):
            count += 1
            if count > 5000: raise ValueError('candidate inventory bound')
            path = Path(parent) / name; info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                descriptor = _fresh_directory(path); os.close(descriptor)
            elif stat.S_ISREG(info.st_mode):
                body, _ = _fresh_read(path, 50 * MIB, private=False)
                total += len(body)
                if total > 50 * MIB: raise ValueError('candidate payload bound')
                found[path.relative_to(candidate).as_posix()] = hashlib.sha256(body).hexdigest()
            else: raise ValueError('linked candidate source')
    expected = value['files']
    if set(found) != set(expected): raise ValueError('candidate inventory changed')
    for name, digest in found.items():
        if expected[name] != {'sha256': digest, 'target': 'admin/modules/slsmassnotifyserver/' + name}:
            raise ValueError('candidate source changed')
    try:
        xml = ET.fromstring(_fresh_read(candidate / 'module.xml', MIB, private=False)[0])
    except ET.ParseError as error:
        raise ValueError('candidate module identity is unreadable') from error
    if xml.findtext('rawname') != 'slsmassnotifyserver' or xml.findtext('version') != value['version']:
        raise ValueError('candidate module identity differs')
    return {'candidate_source': str(candidate), 'candidate_files_sha256': _fresh_digest(found),
            'registry_reference_sha256': hashlib.sha256(reference).hexdigest(),
            'candidate_inventory_sha256': pointer['sha256'],
            'previous_root_approval_sha256': hashlib.sha256(previous).hexdigest(),
            'previous_web_approval_sha256': hashlib.sha256(web).hexdigest()}


def _fresh_journal(value, path, phase):
    allowed = {'schema','directory','phase','created_at','updated_at','settings','stage','stage_at'}
    if (not isinstance(value, dict) or set(value) - allowed or type(value.get('schema')) is not int
            or value['schema'] != 1 or value.get('directory') != str(path) or value.get('phase') != phase
            or type(value.get('created_at')) is not int or type(value.get('updated_at')) is not int
            or not 0 <= value['created_at'] <= value['updated_at'] <= 2**63 - 1):
        raise ValueError('unknown previous transaction')
    settings = value.get('settings')
    if (not isinstance(settings, dict) or set(settings) != _FRESH_SETTINGS
            or any(not isinstance(x, str) or len(x) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in x) for x in settings.values())):
        raise ValueError('unknown transaction settings')
    for name in ('HAD_EXISTING_MODULE','MODULE_WAS_ENABLED','MODULE_ACTIVATED','STATIC_MUTATION_STARTED','SYSTEM_TIMEZONE_CHANGED'):
        if settings[name] != '0': raise ValueError('previous established installation')
    for name in ('CONFIG_SNAPSHOT','CONFIG_HASH_BEFORE','PENDING_CONFIG_SNAPSHOT','PENDING_CONFIG_HASH','MODULE_BACKUP_DIR','RECOVERY_DIR','ORIGINAL_SYSTEM_TIMEZONE'):
        if settings[name]: raise ValueError('previous snapshot or mutation')
    if settings['PENDING_CONFIG_STATE'] not in ('', 'absent'): raise ValueError('previous pending configuration')
    if 'stage' in value or 'stage_at' in value:
        stages = {'initialization','hardware admission','platform validation','release download and validation',
                  'publisher and stock approval','FreePBX ownership protection','legacy configuration and runtime permissions',
                  'authenticated prerequisite validation','previous phone collector recovery','notification worker coordination','configuration coordination'}
        if value.get('stage') not in stages or type(value.get('stage_at')) is not int or not value['created_at'] <= value['stage_at'] <= value['updated_at']:
            raise ValueError('transaction reached unqualified mutation')
    return settings


def _fresh_history(prefix, exclude=None):
    root = prefix / INSTALLER_JOURNAL.lstrip('/')
    if not os.path.lexists(root): return {}
    descriptor = _fresh_directory(root, private=True)
    try: names = os.listdir(descriptor)
    finally: os.close(descriptor)
    if len(names) > 128: raise ValueError('transaction history bound')
    result = {}
    for name in names:
        path = root / name
        if path == exclude: continue
        if not re.fullmatch('transaction-[a-f0-9]{24}', name): raise ValueError('unknown transaction history')
        descriptor = _fresh_directory(path, private=True)
        try:
            if os.listdir(descriptor) != ['transaction.json']: raise ValueError('retained previous recovery evidence')
        finally: os.close(descriptor)
        raw, _ = _fresh_read(path / 'transaction.json')
        _fresh_journal(_fresh_json(raw), path, 'abandoned')
        result[name] = hashlib.sha256(raw).hexdigest()
    return result


def _fresh_absence(path, prefix, account):
    """Prove an absent name through qualified existing directory descriptors.

    FreePBX's fixed native web/data parents legitimately belong to Asterisk.
    Root runtime, key, trust and journal roles have no such ownership exception.
    """
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or len(path.parts) > 128:
        raise ValueError('unqualified absence path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    current = Path('/')
    try:
        for index, part in enumerate(path.parts[1:]):
            try: before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError: return True
            if index == len(path.parts) - 2: return False
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child; current /= part
            opened = os.fstat(fd)
            stamp = lambda info: (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
            if stamp(before) != stamp(opened): raise ValueError('absence ancestor changed')
            logical = Path('/') / current.relative_to(prefix) if current.is_relative_to(prefix) else current
            native = (logical.is_relative_to('/var/www/html') or logical.is_relative_to('/var/lib/asterisk'))
            root_safe = opened.st_uid == 0 and not opened.st_mode & 0o022
            native_safe = (native and opened.st_uid == account.pw_uid and opened.st_gid == account.pw_gid
                           and not opened.st_mode & 0o7002)
            temporary_parent = current == Path('/tmp') and opened.st_uid == 0 and bool(opened.st_mode & stat.S_ISVTX)
            if not (root_safe or native_safe or temporary_parent): raise ValueError('unprotected absence ancestor')
            attributes = os.listxattr(fd)
            if any(name in attributes for name in ('system.posix_acl_access', 'system.posix_acl_default')):
                raise ValueError('unqualified absence ACL')
        return False
    finally: os.close(fd)


def _fresh_live(prefix):
    account = pwd.getpwnam('asterisk'); owners = (0, account.pw_uid)
    if account.pw_uid <= 0 or account.pw_gid <= 0: raise ValueError('native account unavailable')
    for name in _FRESH_ABSENT:
        if not _fresh_absence(prefix / name.lstrip('/'), prefix, account):
            raise ValueError('established installation artifact')
    for name in ('var/lib/sls-mass-notify-trust', 'etc/sls-mass-notify'):
        path = prefix / name
        if os.path.lexists(path):
            descriptor = _fresh_directory(path)
            try:
                if os.listdir(descriptor): raise ValueError('retained installation authority')
            finally: os.close(descriptor)
    # Schedules are observed, never changed. Unknown/unreadable sources decline
    # the optimization, including a module-less prior installation's jobs.
    schedules = [prefix / p for p in ('etc/crontab','var/spool/cron/crontabs/root','var/spool/cron/crontabs/asterisk')]
    cron = prefix / 'etc/cron.d'
    if os.path.lexists(cron):
        descriptor = _fresh_directory(cron)
        try: names = os.listdir(descriptor)
        finally: os.close(descriptor)
        if len(names) > 256: raise ValueError('schedule inspection bound')
        schedules += [cron / name for name in names]
    for path in schedules:
        if os.path.lexists(path):
            raw, _ = _fresh_read(path, MIB, private=False, owners=owners)
            if (re.search(rb'sls[_-]mass[_-]notify|slsconsole|slsmassnotifyserver|SLS_Mass_Notifications_Plugin', raw, re.I)
                    or re.search(rb'(?:^|[\s/])(?:sls_cron_runner\.py|nws_weather_alert\.sh|nwsalerts_ensure_menu_patch\.sh)(?=$|[\s\"\'])', raw, re.M)):
                raise ValueError('previous SLL schedule')
    root = prefix / MANAGED_TREES['data'].lstrip('/')
    if not os.path.lexists(root): return {}
    descriptor = _fresh_directory(root, owners)
    try:
        info = os.fstat(descriptor)
        if info.st_mode & 0o027 or info.st_gid not in (0, account.pw_gid): raise ValueError('unsafe fresh data directory')
        names = os.listdir(descriptor)
    finally: os.close(descriptor)
    if len(names) > 17: raise ValueError('unknown fresh data')
    paths = []
    for name in names:
        if name == 'live-paging-slots':
            descriptor = _fresh_directory(root / name, owners)
            try:
                info = os.fstat(descriptor)
                if info.st_mode & 0o027 or info.st_gid not in (0, account.pw_gid): raise ValueError('unsafe paging lock directory')
                nested = os.listdir(descriptor)
            finally: os.close(descriptor)
            if len(nested) > 16: raise ValueError('paging lock bound')
            paths += [name + '/' + x for x in nested]
        else: paths.append(name)
    result = {}
    for name in paths:
        if name not in _FRESH_LOCKS and name != 'install-failure.json': raise ValueError('unknown fresh data entry')
        raw, info = _fresh_read(root / name, 4096, private=False, owners=owners)
        if info.st_gid not in (0, account.pw_gid) or info.st_mode & 0o027: raise ValueError('unsafe fresh data file')
        if name == 'install-failure.json':
            value = _fresh_json(raw)
            if (not isinstance(value, dict) or set(value) != {'version','failed_at','stage','message','solution','log','error_category','exit_code'}
                    or type(value['version']) is not int or value['version'] != 1
                    or value['message'] != 'SLL Mass Notify Server installation did not complete.'
                    or value['stage'] not in {'hardware admission','platform validation','release download and validation','publisher and stock approval','FreePBX ownership protection','legacy configuration and runtime permissions','authenticated prerequisite validation','previous phone collector recovery','notification worker coordination','configuration coordination'}
                    or type(value['exit_code']) is not int or not 1 <= value['exit_code'] <= 255
                    or not re.fullmatch('[a-z][a-z0-9_]{0,63}', str(value['error_category']))):
                raise ValueError('unknown failure diagnostic')
            for key, maximum in (('failed_at',40),('stage',80),('message',80),('solution',400),('log',500)):
                text = value[key]
                if not isinstance(text,str) or len(text) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in text): raise ValueError('unbounded diagnostic')
        elif raw: raise ValueError('operational data is not an empty preparation lock')
        result[name] = {'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'gid':info.st_gid,
                        'mode':stat.S_IMODE(info.st_mode),'bytes':info.st_size,'sha256':hashlib.sha256(raw).hexdigest()}
    return result


def capture_fresh_release_proof(review, candidate_source, native_state, *, prefix=Path('/')):
    """Read-only proof capsule, called only after authenticated normal review.

    Prefix is for isolated filesystem fixtures, never a CLI option. Missing,
    ambiguous or established state keeps the default previous-release budget.
    """
    try:
        if os.geteuid() != 0 or native_state != 'known_absent': return None
        review, candidate_source, prefix = Path(review), Path(candidate_source), Path(prefix)
        binding = _fresh_review_binding(review, candidate_source)
        history = _fresh_history(prefix); data = _fresh_live(prefix)
        if history != _fresh_history(prefix) or data != _fresh_live(prefix): return None
        return {'schema':1,'kind':_FRESH_KIND,'native_state':'known_absent','candidate':binding,
                'history':history,'data':data,'establishment_paths_absent':list(_FRESH_ABSENT)}
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def read_fresh_release_proof(review, candidate_source, *, prefix=Path('/')):
    """Validate captured authority again inside its prepared current transaction."""
    try:
        if os.geteuid() != 0: return None
        review, candidate_source, prefix = Path(review), Path(candidate_source), Path(prefix)
        current = review.parent
        if (review.name != 'approval' or current.parent != prefix / INSTALLER_JOURNAL.lstrip('/')
                or not re.fullmatch('transaction-[a-f0-9]{24}', current.name)): return None
        raw, _ = _fresh_read(review / _FRESH_FILE)
        value = _fresh_json(raw)
        if (not isinstance(value,dict) or set(value) != {'schema','kind','native_state','candidate','history','data','establishment_paths_absent'}
                or type(value['schema']) is not int or value['schema'] != 1 or value['kind'] != _FRESH_KIND
                or value['native_state'] != 'known_absent' or value['establishment_paths_absent'] != list(_FRESH_ABSENT)
                or value['candidate'] != _fresh_review_binding(review,candidate_source)): return None
        journal, _ = _fresh_read(current / 'transaction.json')
        settings = _fresh_journal(_fresh_json(journal), current, 'prepared')
        if settings['UPGRADE_TRUST_DIR'] != str(review) or settings['INSTALL_BOOTSTRAP_DIR'] != str(current / 'bootstrap'): return None
        if any(os.path.lexists(current / name) for name in ('config.snapshot','pending.snapshot','history-evidence.json')): return None
        history = _fresh_history(prefix, exclude=current); data = _fresh_live(prefix)
        if history != value['history'] or not isinstance(value['data'],dict): return None
        if any(data.get(name) != record for name,record in value['data'].items()): return None
        if 'install-failure.json' in data and 'install-failure.json' not in value['data']: return None
        if journal != _fresh_read(current / 'transaction.json')[0] or raw != _fresh_read(review / _FRESH_FILE)[0]: return None
        return value
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


_INSTALL_STORAGE_KIND = 'sll-prepared-release-storage-proof-v2'
_INSTALL_BOOTSTRAP = ('sls_module_trust.py', 'sls_release_trust.py', 'sls_privileged_install.py',
    'sls_installer_recovery.py', 'sls_install_transaction.py', 'sls_install_idle.py',
    'sls_install_guard.py', 'sls_audio_state.py', 'sls_config_crypto.py', 'sls_upgrade_trust.py',
    'sls_legacy_permissions.py', 'freepbx-mirror-signing.pub')
_INSTALL_SOURCE_ABSENT = ('/var/www/html/admin/modules/slsmassnotifyserver', MANAGED_TREES['runtime'],
    '/var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json')
_INSTALL_RETAINED = (MANAGED_TREES['data'] + '/mass-notifications.config',
    MANAGED_TREES['data'] + '/mass-notifications.pending.config', '/etc/sls-mass-notify/config-keys.json',
    '/var/lib/sls-mass-notify-trust/publisher-trust.json',
    '/var/lib/sls-mass-notify-trust/release-trust.initialized')


def _install_storage_review(review, candidate):
    """Bind already publisher-approved inputs; confer no executable authority."""
    binding = _fresh_review_binding(review, candidate)
    pointer = _fresh_json(_fresh_read(review / 'registry/slsmassnotifyserver.active.json', 1024)[0])
    generation = review / 'registry' / pointer['generation']
    inventory = _fresh_json(_fresh_read(generation / 'inventory.json', 8 * MIB)[0])
    manifest, _ = _fresh_read(generation / 'release-manifest.json', 16384)
    signature, _ = _fresh_read(generation / 'release-manifest.sig', 64)
    value = _fresh_json(manifest)
    version = inventory['version']
    if (not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 1
            or value.get('version') != version or value.get('tag') != 'v' + version
            or value.get('package') != 'slsmassnotifyserver-' + version + '.tgz'
            or value.get('package_sha256') != inventory['source']['archive_sha256']
            or not isinstance(value.get('installer_sha256'), str)
            or re.fullmatch('[a-f0-9]{64}', value['installer_sha256']) is None
            or len(signature) != 64):
        raise ValueError('approved candidate release inputs differ')
    binding.update(release_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        release_signature_sha256=hashlib.sha256(signature).hexdigest(),
        package_sha256=value['package_sha256'], installer_sha256=value['installer_sha256'])
    return binding, generation


def _install_storage_live(prefix):
    """Observe source absence separately from retained operational files.

    Retained settings, keys, history and inactive generations are never deleted
    or interpreted as permission to restore a runtime or configuration.
    """
    account = pwd.getpwnam('asterisk')
    if account.pw_uid <= 0 or account.pw_gid <= 0:
        raise ValueError('native account unavailable')
    for name in _INSTALL_SOURCE_ABSENT:
        if not _fresh_absence(prefix / name.lstrip('/'), prefix, account):
            raise ValueError('previous active release source exists')
    result = {}
    for name in _INSTALL_RETAINED:
        path = prefix / name.lstrip('/')
        if not os.path.lexists(path):
            result[name] = None
            continue
        owners = (0,) if name.startswith('/etc/') or name.startswith('/var/lib/sls-mass-notify-trust/') else (0, account.pw_uid)
        raw, info = _fresh_read(path, 3 * MIB if name.endswith('.config') else 65536,
                               private=False, owners=owners)
        if stat.S_IMODE(info.st_mode) not in (0o600, 0o640) or info.st_gid not in (0, account.pw_gid):
            raise ValueError('unqualified retained storage context')
        result[name] = {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'bytes': info.st_size,
            'sha256': hashlib.sha256(raw).hexdigest()}
    return result


def _install_storage_history(prefix, exclude=None):
    root = prefix / INSTALLER_JOURNAL.lstrip('/')
    if not os.path.lexists(root):
        return {}
    fd = _fresh_directory(root, private=True)
    try:
        names = sorted(os.listdir(fd))
    finally:
        os.close(fd)
    if len(names) > 128:
        raise ValueError('terminal storage history bound')
    result = {}
    for name in names:
        path = root / name
        if path == exclude:
            continue
        if re.fullmatch('transaction-[a-f0-9]{24}', name) is None:
            raise ValueError('unknown previous storage transaction')
        fd = _fresh_directory(path, private=True)
        try:
            if os.listdir(fd) != ['transaction.json']:
                raise ValueError('previous recovery sources remain')
        finally:
            os.close(fd)
        raw, _ = _fresh_read(path / 'transaction.json')
        value = _fresh_json(raw)
        allowed = {'schema', 'directory', 'phase', 'created_at', 'updated_at', 'settings', 'stage', 'stage_at'}
        if (not isinstance(value, dict) or set(value) - allowed or type(value.get('schema')) is not int
                or value['schema'] != 1 or value.get('directory') != str(path)
                or value.get('phase') not in ('abandoned', 'rolled_back')
                or type(value.get('created_at')) is not int or type(value.get('updated_at')) is not int
                or not 0 <= value['created_at'] <= value['updated_at'] <= 2 ** 63 - 1):
            raise ValueError('unknown terminal storage history')
        settings = value.get('settings')
        if (not isinstance(settings, dict) or set(settings) != _FRESH_SETTINGS
                or any(not isinstance(x, str) or len(x) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in x)
                       for x in settings.values())
                or settings['HAD_EXISTING_MODULE'] != '0' or settings['MODULE_WAS_ENABLED'] != '0'
                or any(settings[key] not in ('0', '1') for key in
                       ('MODULE_ACTIVATED', 'STATIC_MUTATION_STARTED', 'SYSTEM_TIMEZONE_CHANGED'))):
            raise ValueError('previous established release storage history')
        if (value['phase'] == 'abandoned' and any(settings[key] != '0' for key in
                ('MODULE_ACTIVATED', 'STATIC_MUTATION_STARTED', 'SYSTEM_TIMEZONE_CHANGED'))
                or any(settings[key] == '1' for key in ('MODULE_ACTIVATED', 'SYSTEM_TIMEZONE_CHANGED'))
                and settings['STATIC_MUTATION_STARTED'] != '1'):
            raise ValueError('impossible terminal storage mutation flags')
        if ('stage' in value or 'stage_at' in value) and (
                not isinstance(value.get('stage'), str) or len(value['stage']) > 80
                or any(ord(c) < 32 or ord(c) == 127 for c in value['stage'])
                or type(value.get('stage_at')) is not int
                or not value['created_at'] <= value['stage_at'] <= value['updated_at']):
            raise ValueError('invalid terminal storage stage')
        result[name] = hashlib.sha256(raw).hexdigest()
    return result


def capture_install_storage_proof(review, candidate_source, native_state, *, prefix=Path('/')):
    """Capture a capacity-only source relationship after normal approval.

    The early capsule cannot remove resident-role costs. Only its prepared
    reader can establish that the exact current inputs are durably present.
    """
    try:
        if os.geteuid() != 0 or native_state != 'known_absent':
            return None
        review, candidate_source, prefix = Path(review), Path(candidate_source), Path(prefix)
        binding, _ = _install_storage_review(review, candidate_source)
        history = _install_storage_history(prefix)
        retained = _install_storage_live(prefix)
        if history != _install_storage_history(prefix) or retained != _install_storage_live(prefix):
            return None
        return {'schema': 2, 'kind': _INSTALL_STORAGE_KIND, 'capacity_only': True,
            'prepared_verification_required': True, 'native_state': 'known_absent',
            'candidate': binding, 'history': history, 'retained': retained}
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def _install_storage_resident(current, review, candidate, binding, generation):
    # These inputs were copied/moved by begin_install_transaction before the
    # late admission. Existing free space already excludes their allocation.
    registered = _fresh_review_binding(review, generation / 'module')
    expected = {k: v for k, v in binding.items() if k in registered and k != 'candidate_source'}
    if {k: v for k, v in registered.items() if k != 'candidate_source'} != expected:
        raise ValueError('prepared candidate approval source differs')
    hashes = {'installer.sh': (binding['installer_sha256'], 2 * MIB),
        'package.tgz': (binding['package_sha256'], 52 * MIB),
        'release-manifest.json': (binding['release_manifest_sha256'], 16384),
        'release-manifest.sig': (binding['release_signature_sha256'], 64)}
    for name, (expected_hash, maximum) in hashes.items():
        body, info = _fresh_read(current / name, maximum)
        if stat.S_IMODE(info.st_mode) != 0o600 or hashlib.sha256(body).hexdigest() != expected_hash:
            raise ValueError('prepared release input differs')
    fd = _fresh_directory(current / 'bootstrap', private=True)
    try:
        if set(os.listdir(fd)) != set(_INSTALL_BOOTSTRAP):
            raise ValueError('prepared bootstrap membership differs')
    finally:
        os.close(fd)
    for name in _INSTALL_BOOTSTRAP:
        body, info = _fresh_read(current / 'bootstrap' / name, 50 * MIB)
        source, _ = _fresh_read(candidate / 'bin/sls_mass_notify' / name, 50 * MIB, private=False)
        if stat.S_IMODE(info.st_mode) != (0o600 if name.endswith('.pub') else 0o700) or body != source:
            raise ValueError('prepared bootstrap source differs')


def read_install_storage_proof(review, candidate_source, *, prefix=Path('/')):
    """Validate all prepared roles; unknown evidence retains every full reserve."""
    try:
        if os.geteuid() != 0:
            return None
        review, candidate_source, prefix = Path(review), Path(candidate_source), Path(prefix)
        current = review.parent
        if (review.name != 'approval' or current.parent != prefix / INSTALLER_JOURNAL.lstrip('/')
                or re.fullmatch('transaction-[a-f0-9]{24}', current.name) is None):
            return None
        raw, _ = _fresh_read(review / _FRESH_FILE)
        value = _fresh_json(raw)
        if (not isinstance(value, dict) or set(value) != {'schema', 'kind', 'capacity_only',
                'prepared_verification_required', 'native_state', 'candidate', 'history', 'retained'}
                or type(value.get('schema')) is not int or value['schema'] != 2
                or value['kind'] != _INSTALL_STORAGE_KIND or value['capacity_only'] is not True
                or value['prepared_verification_required'] is not True or value['native_state'] != 'known_absent'):
            return None
        binding, generation = _install_storage_review(review, candidate_source)
        if value['candidate'] != binding:
            return None
        journal, _ = _fresh_read(current / 'transaction.json')
        settings = _fresh_journal(_fresh_json(journal), current, 'prepared')
        if (settings['UPGRADE_TRUST_DIR'] != str(review)
                or settings['INSTALL_BOOTSTRAP_DIR'] != str(current / 'bootstrap')):
            return None
        history = _install_storage_history(prefix, exclude=current)
        retained = _install_storage_live(prefix)
        if history != value['history'] or retained != value['retained']:
            return None
        _install_storage_resident(current, review, candidate_source, binding, generation)
        if (journal != _fresh_read(current / 'transaction.json')[0]
                or raw != _fresh_read(review / _FRESH_FILE)[0]
                or history != _install_storage_history(prefix, exclude=current)
                or retained != _install_storage_live(prefix)
                or binding != _install_storage_review(review, candidate_source)[0]):
            return None
        return value
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def _stock_storage_binding(workspace, root, *, reader, directory):
    """Bind complete protected cache and pending package sizes for capacity only.

    The caller supplies protected, stable byte/directory readers. Only complete
    independently approved native versions qualify. A new pending package must
    match that version's signed archive digest. The writer re-verifies GPG.
    """
    import hashlib
    import json
    import os
    from pathlib import Path
    import re
    def require(ok):
        if not ok:
            raise ValueError('Incomplete or changed protected stock cache storage role')
    def strict(raw):
        def pairs(rows):
            result = {}
            for key, value in rows:
                require(key not in result); result[key] = value
            return result
        def invalid(unused):
            raise ValueError('Nonfinite stock storage metadata')
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    def names(path):
        descriptor = directory(path)
        try:
            result = sorted(os.listdir(descriptor))
        finally:
            os.close(descriptor)
        require(len(result) <= 512)
        return result
    workspace, root = Path(workspace), Path(root)
    pending_names = names(workspace)
    folder = root / 'stock-packages'
    cache_names = names(folder)
    require(2 <= len(cache_names) <= 4)
    require(all(sum(name.startswith(module + '-') for name in cache_names) <= 2 for module in ('dashboard', 'framework')))
    pattern = r'(dashboard|framework)-(17\.[0-9]+(?:\.[0-9]+){1,3})\.tgz\.gpg'
    cached = {}
    for name in cache_names:
        require(re.fullmatch(pattern, name) is not None)
        body = reader(folder / name, 64 * 1024**2)
        require(0 < len(body) <= 64 * 1024**2)
        cached[name] = {'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}
    pending = {}
    for name in pending_names:
        if not name.startswith(('dashboard-', 'framework-')) or not name.endswith('.tgz.gpg'):
            continue
        require(re.fullmatch(pattern, name) is not None and len(pending) < 4)
        body = reader(workspace / name, 64 * 1024**2)
        require(0 < len(body) <= 64 * 1024**2)
        row = {'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}
        require(name not in cached or row == cached[name])
        pending[name] = row
    approved = {}
    for module in ('dashboard', 'framework'):
        body = reader(workspace / (module + '.json'), 8 * 1024**2)
        value = strict(body)
        require(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
                and value.get('module') == module and type(value.get('version')) is str
                and re.fullmatch(r'17\.[0-9]+(?:\.[0-9]+){1,3}', value['version']) is not None)
        source = value.get('source')
        require(type(source) is dict and source.get('kind') == 'reviewed-upstream-and-overlays'
                and source.get('upstream_signer') == '456D051E9204C27C37D4811BB53D215A755231A3'
                and type(source.get('signed_archive_sha256')) is str
                and re.fullmatch('[a-f0-9]{64}', source['signed_archive_sha256']) is not None)
        name = module + '-' + value['version'] + '.tgz.gpg'
        available = pending.get(name, cached.get(name))
        require(available is not None and available['sha256'] == source['signed_archive_sha256'])
        approved[module] = {'version': value['version'], 'signed_archive_sha256': source['signed_archive_sha256'],
                            'inventory_sha256': hashlib.sha256(body).hexdigest()}
    new = set(pending) - set(cached)
    expected = {module + '-' + item['version'] + '.tgz.gpg' for module, item in approved.items()}
    require(new <= expected)
    return {'approved': approved, 'cached': cached, 'pending': pending}


def _upgrade_candidate_binding(review, candidate):
    descriptor = _fresh_directory(review, private=True); os.close(descriptor)
    previous, _ = _fresh_read(review / 'previous-root-approval.json')
    web, _ = _fresh_read(review / 'previous-web-approval.json', 8 * MIB)
    prior, prior_web = _fresh_json(previous), _fresh_json(web)
    if type(prior) is not dict or type(prior_web) is not dict:
        raise ValueError('independent previous approvals are incomplete')
    reference, _ = _fresh_read(review / 'registry/slsmassnotifyserver.active.json', 1024)
    pointer = _fresh_json(reference)
    if (not isinstance(pointer, dict) or set(pointer) != {'generation', 'sha256'}
            or not re.fullmatch('[a-f0-9]{64}', str(pointer.get('sha256', '')))
            or pointer.get('generation') != 'slsmassnotifyserver-' + pointer['sha256']):
        raise ValueError('candidate generation reference differs')
    inventory, _ = _fresh_read(review / 'registry' / pointer['generation'] / 'inventory.json', 8 * MIB)
    value = _fresh_json(inventory)
    if (not isinstance(value, dict) or hashlib.sha256(inventory).hexdigest() != pointer['sha256']
            or type(value.get('schema')) is not int or value['schema'] != 1
            or value.get('module') != 'slsmassnotifyserver' or not isinstance(value.get('source'), dict)
            or value['source'].get('kind') != 'publisher-ed25519'
            or not re.fullmatch('[a-f0-9]{64}', str(value.get('source', {}).get('archive_sha256', '')))
            or not isinstance(value.get('version'), str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-beta)?', value['version'])
            or not isinstance(value.get('files'), dict) or not 1 <= len(value['files']) <= 5000):
        raise ValueError('authenticated candidate inventory differs')
    descriptor = _fresh_directory(candidate)
    try:
        if os.fstat(descriptor).st_mode & 0o022: raise ValueError('candidate source is writable')
    finally: os.close(descriptor)
    found = {}; count = total = 0
    for parent, directories, files in os.walk(candidate, followlinks=False):
        for name in (*directories, *files):
            count += 1
            if count > 5000: raise ValueError('candidate inventory bound')
            path = Path(parent) / name; info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                descriptor = _fresh_directory(path); os.close(descriptor)
            elif stat.S_ISREG(info.st_mode):
                body, _ = _fresh_read(path, 50 * MIB, private=False)
                total += len(body)
                if total > 50 * MIB: raise ValueError('candidate payload bound')
                found[path.relative_to(candidate).as_posix()] = hashlib.sha256(body).hexdigest()
            else: raise ValueError('linked candidate source')
    expected = value['files']
    if set(found) != set(expected): raise ValueError('candidate inventory changed')
    for name, digest in found.items():
        if expected[name] != {'sha256': digest, 'target': 'admin/modules/slsmassnotifyserver/' + name}:
            raise ValueError('candidate source changed')
    try:
        xml = ET.fromstring(_fresh_read(candidate / 'module.xml', MIB, private=False)[0])
    except ET.ParseError as error:
        raise ValueError('candidate module identity is unreadable') from error
    if xml.findtext('rawname') != 'slsmassnotifyserver' or xml.findtext('version') != value['version']:
        raise ValueError('candidate module identity differs')
    return {'candidate_source': str(candidate), 'candidate_files_sha256': _fresh_digest(found),
            'registry_reference_sha256': hashlib.sha256(reference).hexdigest(),
            'candidate_inventory_sha256': pointer['sha256'],
            'previous_root_approval_sha256': hashlib.sha256(previous).hexdigest(),
            'previous_web_approval_sha256': hashlib.sha256(web).hexdigest()}

def _upgrade_storage_review(review, candidate):
    """Bind already publisher-approved inputs; confer no executable authority."""
    binding = _upgrade_candidate_binding(review, candidate)
    pointer = _fresh_json(_fresh_read(review / 'registry/slsmassnotifyserver.active.json', 1024)[0])
    generation = review / 'registry' / pointer['generation']
    inventory = _fresh_json(_fresh_read(generation / 'inventory.json', 8 * MIB)[0])
    manifest, _ = _fresh_read(generation / 'release-manifest.json', 16384)
    signature, _ = _fresh_read(generation / 'release-manifest.sig', 64)
    value = _fresh_json(manifest)
    version = inventory['version']
    if (not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 1
            or value.get('version') != version or value.get('tag') != 'v' + version
            or value.get('package') != 'slsmassnotifyserver-' + version + '.tgz'
            or value.get('package_sha256') != inventory['source']['archive_sha256']
            or not isinstance(value.get('installer_sha256'), str)
            or re.fullmatch('[a-f0-9]{64}', value['installer_sha256']) is None
            or len(signature) != 64):
        raise ValueError('approved candidate release inputs differ')
    binding.update(release_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        release_signature_sha256=hashlib.sha256(signature).hexdigest(),
        package_sha256=value['package_sha256'], installer_sha256=value['installer_sha256'])
    return binding, generation

def _upgrade_storage_resident(current, review, candidate, binding, generation):
    # These inputs were copied/moved by begin_install_transaction before the
    # late admission. Existing free space already excludes their allocation.
    registered = _upgrade_candidate_binding(review, generation / 'module')
    expected = {k: v for k, v in binding.items() if k in registered and k != 'candidate_source'}
    if {k: v for k, v in registered.items() if k != 'candidate_source'} != expected:
        raise ValueError('prepared candidate approval source differs')
    hashes = {'installer.sh': (binding['installer_sha256'], 2 * MIB),
        'package.tgz': (binding['package_sha256'], 52 * MIB),
        'release-manifest.json': (binding['release_manifest_sha256'], 16384),
        'release-manifest.sig': (binding['release_signature_sha256'], 64)}
    for name, (expected_hash, maximum) in hashes.items():
        body, info = _fresh_read(current / name, maximum)
        if stat.S_IMODE(info.st_mode) != 0o600 or hashlib.sha256(body).hexdigest() != expected_hash:
            raise ValueError('prepared release input differs')
    fd = _fresh_directory(current / 'bootstrap', private=True)
    try:
        if set(os.listdir(fd)) != set(_INSTALL_BOOTSTRAP):
            raise ValueError('prepared bootstrap membership differs')
    finally:
        os.close(fd)
    for name in _INSTALL_BOOTSTRAP:
        body, info = _fresh_read(current / 'bootstrap' / name, 50 * MIB)
        source, _ = _fresh_read(candidate / 'bin/sls_mass_notify' / name, 50 * MIB, private=False)
        if stat.S_IMODE(info.st_mode) != (0o600 if name.endswith('.pub') else 0o700) or body != source:
            raise ValueError('prepared bootstrap source differs')

_UPGRADE_STORAGE_KIND = 'sll-prepared-upgrade-storage-proof-v3'


def _upgrade_previous_binding(review, prefix):
    """The prior protected source is resident, not absent or newly downloaded."""
    trust = prefix / 'var/lib/sls-mass-notify-trust'
    descriptor = _fresh_directory(trust, private=True); os.close(descriptor)
    for name in ('previous-release', 'previous-registry'):
        if os.path.lexists(review / name):
            raise ValueError('previous release acquisition is not fully resident')
    pointer_raw, _ = _fresh_read(trust / 'slsmassnotifyserver.active.json', 1024)
    pointer = _fresh_json(pointer_raw)
    if (type(pointer) is not dict or set(pointer) != {'generation', 'sha256'}
            or type(pointer['sha256']) is not str or re.fullmatch('[a-f0-9]{64}', pointer['sha256']) is None
            or pointer['generation'] != 'slsmassnotifyserver-' + pointer['sha256']):
        raise ValueError('incomplete previous active generation')
    generation = trust / pointer['generation']
    descriptor = _fresh_directory(generation, private=True); os.close(descriptor)
    raw, _ = _fresh_read(generation / 'inventory.json', 8 * MIB)
    data = _fresh_json(raw)
    prior = _fresh_json(_fresh_read(review / 'previous-web-approval.json', 8 * MIB)[0])
    approval = _fresh_json(_fresh_read(review / 'previous-root-approval.json', 8 * MIB)[0])
    if (type(data) is not dict or hashlib.sha256(raw).hexdigest() != pointer['sha256']
            or type(data.get('schema')) is not int or data['schema'] != 1
            or data.get('module') != 'slsmassnotifyserver' or type(data.get('version')) is not str
            or re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-beta)?', data['version']) is None
            or type(data.get('source')) is not dict or data['source'].get('kind') != 'publisher-ed25519'
            or re.fullmatch('[a-f0-9]{64}', str(data['source'].get('archive_sha256', ''))) is None
            or type(data.get('files')) is not dict or not 1 <= len(data['files']) <= MAX_RELEASE_ENTRIES
            or type(prior) is not dict or prior.get('slsmassnotifyserver') != data
            or type(approval) is not dict or type(approval.get('schema')) is not int or approval['schema'] != 1
            or approval.get('source') != 'publisher-verified-previous-release'
            or approval.get('version') != data['version']
            or approval.get('archive_sha256') != data['source']['archive_sha256']):
        raise ValueError('previous source does not match independent approval')
    found = {}; total = count = 0
    for parent, directories, files in os.walk(generation / 'module', followlinks=False):
        for name in (*directories, *files):
            count += 1
            if count > MAX_RELEASE_ENTRIES:
                raise ValueError('previous source entry bound')
            path = Path(parent) / name
            if path.is_symlink():
                raise ValueError('linked previous source')
            if path.is_dir():
                descriptor = _fresh_directory(path); os.close(descriptor)
            elif path.is_file():
                body, _ = _fresh_read(path, 50 * MIB)
                total += len(body)
                if len(found) >= MAX_RELEASE_ENTRIES or total > 50 * MIB:
                    raise ValueError('previous source exceeds inventory bound')
                found[path.relative_to(generation / 'module').as_posix()] = hashlib.sha256(body).hexdigest()
            else:
                raise ValueError('special previous source')
    if set(found) != set(data['files']):
        raise ValueError('previous source membership differs')
    expected_runtime = {}
    for name, digest in found.items():
        if data['files'][name] != {'sha256': digest, 'target': 'admin/modules/slsmassnotifyserver/' + name}:
            raise ValueError('previous source bytes differ')
        if name == 'bin/sign_sls_mass_notify_local_sig.sh': target = '/usr/local/sbin/sign_sls_mass_notify_local_sig.sh'
        elif name == 'bin/slsconsole': target = '/usr/local/bin/slsconsole'
        elif name.startswith('bin/sls_mass_notify/'): target = MANAGED_TREES['runtime'] + '/' + name[len('bin/sls_mass_notify/'):]
        elif name.startswith('bin/') and '/' not in name[4:]: target = MANAGED_TREES['runtime'] + '/' + name[4:]
        else: continue
        expected_runtime[target] = digest
    if approval.get('files') != expected_runtime:
        raise ValueError('previous root source approval differs')
    manifest, _ = _fresh_read(generation / 'release-manifest.json', 16384)
    signature, _ = _fresh_read(generation / 'release-manifest.sig', 64)
    value = _fresh_json(manifest); version = data['version']
    tags = ('v' + version, 'slsmassnotifyserver-' + version) + (('V0.1.9-beta', 'release-0.1.9-beta') if version == '0.1.9-beta' else ())
    if (type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1
            or value.get('version') != version or value.get('tag') not in tags
            or value.get('package') != 'slsmassnotifyserver-' + version + '.tgz'
            or value.get('package_sha256') != data['source']['archive_sha256'] or len(signature) != 64):
        raise ValueError('previous signed inputs differ')
    try:
        xml = ET.fromstring(_fresh_read(generation / 'module/module.xml', MIB)[0])
    except ET.ParseError as error:
        raise ValueError('previous module identity is unreadable') from error
    if xml.findtext('rawname') != 'slsmassnotifyserver' or xml.findtext('version') != version:
        raise ValueError('previous module identity differs')
    return {'active_reference_sha256': hashlib.sha256(pointer_raw).hexdigest(),
            'inventory_sha256': pointer['sha256'], 'generation': pointer['generation'],
            'module_files_sha256': _fresh_digest(found),
            'release_manifest_sha256': hashlib.sha256(manifest).hexdigest(),
            'release_signature_sha256': hashlib.sha256(signature).hexdigest()}


def _upgrade_native_stock_versions(prefix):
    account = pwd.getpwnam('asterisk'); result = {}
    for module in ('dashboard', 'framework'):
        path = prefix / 'var/www/html/admin/modules' / module / 'module.xml'
        if path.resolve() != path:
            raise ValueError('native stock module identity is not canonical')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            stamp = lambda info: tuple(getattr(info, 'st_' + key) for key in
                ('dev','ino','uid','gid','mode','nlink','size','mtime_ns','ctime_ns'))
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid not in (0, account.pw_uid) or before.st_gid not in (0, account.pw_gid)
                    or before.st_mode & 0o7002 or not 0 < before.st_size <= MIB):
                raise ValueError('native stock module identity is unsafe')
            with os.fdopen(os.dup(descriptor), 'rb') as stream: body = stream.read(MIB + 1)
            if len(body) != before.st_size or stamp(before) != stamp(os.fstat(descriptor)) or stamp(before) != stamp(path.lstat()):
                raise ValueError('native stock module identity changed')
        finally:
            os.close(descriptor)
        if b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():
            raise ValueError('native stock module identity has unsupported declarations')
        try: xml = ET.fromstring(body)
        except ET.ParseError as error: raise ValueError('native stock module identity is unreadable') from error
        version = xml.findtext('version')
        if xml.findtext('rawname') != module or type(version) is not str or re.fullmatch(r'17\.[0-9]+(?:\.[0-9]+){1,3}', version) is None:
            raise ValueError('native stock module identity is unsupported')
        result[module] = version
    return result


def _upgrade_stock_read(path, maximum):
    body, info = _fresh_read(path, maximum)
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('private stock storage file mode differs')
    return body


def _upgrade_stock_directory(path):
    descriptor = _fresh_directory(path, private=True)
    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
        os.close(descriptor)
        raise ValueError('private stock storage directory mode differs')
    return descriptor


def _upgrade_stock_binding(review, prefix):
    first = _stock_storage_binding(review, prefix / 'var/lib/sls-mass-notify-trust',
        reader=_upgrade_stock_read,
        directory=_upgrade_stock_directory)
    if first != _stock_storage_binding(review, prefix / 'var/lib/sls-mass-notify-trust',
            reader=_upgrade_stock_read,
            directory=_upgrade_stock_directory):
        raise ValueError('stock storage roles changed')
    versions = _upgrade_native_stock_versions(prefix)
    if any(first['approved'][module]['version'] != version for module, version in versions.items()):
        raise ValueError('cached stock does not cover the exact native version')
    return first


def _possible_upgrade_stock_binding(review, prefix):
    try:
        return _upgrade_stock_binding(review, prefix)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        # Candidate and previous sources can be complete while cache growth
        # remains unknown. In that case no stock-specific discount is approved.
        return None


def capture_prepared_upgrade_storage_proof(review, candidate_source, native_state, *, prefix=Path('/')):
    """Capture only authenticated source/cache facts, never operational authority."""
    try:
        if os.geteuid() != 0 or native_state != 'established':
            return None
        review, candidate_source, prefix = Path(review), Path(candidate_source), Path(prefix)
        binding, _ = _upgrade_storage_review(review, candidate_source)
        previous = _upgrade_previous_binding(review, prefix)
        stock = _possible_upgrade_stock_binding(review, prefix)
        if (binding != _upgrade_storage_review(review, candidate_source)[0]
                or previous != _upgrade_previous_binding(review, prefix)
                or stock != _possible_upgrade_stock_binding(review, prefix)):
            return None
        return {'schema': 3, 'kind': _UPGRADE_STORAGE_KIND, 'capacity_only': True,
                'prepared_verification_required': True, 'native_state': 'established',
                'candidate': binding, 'previous': previous, 'stock_cache': stock}
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def _upgrade_current_journal(raw, current, review):
    value = _fresh_json(raw)
    allowed = {'schema', 'directory', 'phase', 'created_at', 'updated_at', 'settings', 'stage', 'stage_at'}
    if (type(value) is not dict or set(value) - allowed or type(value.get('schema')) is not int
            or value['schema'] != 1 or value.get('directory') != str(current) or value.get('phase') != 'prepared'
            or type(value.get('created_at')) is not int or type(value.get('updated_at')) is not int
            or not 0 <= value['created_at'] <= value['updated_at'] < 2**63):
        raise ValueError('unqualified prepared upgrade journal')
    settings = value.get('settings')
    if (type(settings) is not dict or set(settings) != _FRESH_SETTINGS
            or any(type(x) is not str or len(x) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in x) for x in settings.values())
            or settings['HAD_EXISTING_MODULE'] != '1' or settings['MODULE_WAS_ENABLED'] not in ('0', '1')
            or any(settings[name] != '0' for name in ('MODULE_ACTIVATED', 'STATIC_MUTATION_STARTED', 'SYSTEM_TIMEZONE_CHANGED'))
            or settings['UPGRADE_TRUST_DIR'] != str(review) or settings['INSTALL_BOOTSTRAP_DIR'] != str(current / 'bootstrap')):
        raise ValueError('upgrade journal phase or source roles differ')
    if ('stage' in value or 'stage_at' in value) and (type(value.get('stage')) is not str
            or len(value['stage']) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in value['stage'])
            or type(value.get('stage_at')) is not int or not value['created_at'] <= value['stage_at'] <= value['updated_at']):
        raise ValueError('unqualified prepared upgrade stage')
    return settings


def read_prepared_upgrade_storage_proof(review, candidate_source, *, prefix=Path('/')):
    """Recheck complete prepared upgrade roles; ambiguity keeps full reserves."""
    try:
        if os.geteuid() != 0:
            return None
        review, candidate_source, prefix = Path(review), Path(candidate_source), Path(prefix)
        current = review.parent
        if (review.name != 'approval' or current.parent != prefix / INSTALLER_JOURNAL.lstrip('/')
                or re.fullmatch('transaction-[a-f0-9]{24}', current.name) is None):
            return None
        raw, _ = _fresh_read(review / _FRESH_FILE, 4 * MIB); value = _fresh_json(raw)
        if (type(value) is not dict or set(value) != {'schema', 'kind', 'capacity_only', 'prepared_verification_required',
                'native_state', 'candidate', 'previous', 'stock_cache'}
                or type(value.get('schema')) is not int or value['schema'] != 3 or value['kind'] != _UPGRADE_STORAGE_KIND
                or value['capacity_only'] is not True or value['prepared_verification_required'] is not True
                or value['native_state'] != 'established'):
            return None
        binding, generation = _upgrade_storage_review(review, candidate_source)
        previous = _upgrade_previous_binding(review, prefix); stock = _possible_upgrade_stock_binding(review, prefix)
        if value['candidate'] != binding or value['previous'] != previous or value['stock_cache'] != stock:
            return None
        journal, _ = _fresh_read(current / 'transaction.json')
        _upgrade_current_journal(journal, current, review)
        _upgrade_storage_resident(current, review, candidate_source, binding, generation)
        if (journal != _fresh_read(current / 'transaction.json')[0]
                or raw != _fresh_read(review / _FRESH_FILE, 4 * MIB)[0]
                or binding != _upgrade_storage_review(review, candidate_source)[0]
                or previous != _upgrade_previous_binding(review, prefix) or stock != _possible_upgrade_stock_binding(review, prefix)):
            return None
        return value
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return None


def probe_prepared_piper_reuse(review, candidate_source, proof):
    """Invoke only candidate-authenticated validation after the full v3 proof.

    This returns capacity evidence, never execution/restoration authority. A
    missing, incompatible, changed or unhealthy runtime keeps replacement costs.
    Periodic runtime/Doctor checks never call this installation-only operation.
    """
    try:
        if (os.geteuid() != 0 or type(proof) is not dict or type(proof.get('schema')) is not int
                or proof['schema'] != 3 or proof.get('kind') != _UPGRADE_STORAGE_KIND
                or proof.get('capacity_only') is not True):
            return None
        review, candidate_source = Path(review), Path(candidate_source)
        expected = proof['candidate']['candidate_inventory_sha256']
        generation = 'slsmassnotifyserver-' + expected
        if re.fullmatch('[a-f0-9]{64}', expected) is None:
            return None
        inventory_raw, _ = _fresh_read(review / 'registry' / generation / 'inventory.json', 8 * MIB)
        if hashlib.sha256(inventory_raw).hexdigest() != expected:
            return None
        inventory = _fresh_json(inventory_raw)
        relative = 'bin/sls_mass_notify/sls_piper_environment.py'
        body, _ = _fresh_read(candidate_source / relative, 2 * MIB, private=False)
        if hashlib.sha256(body).hexdigest() != inventory['files'][relative]['sha256']:
            return None
        previous = proof['previous']['generation']
        if previous != 'slsmassnotifyserver-' + proof['previous']['inventory_sha256']:
            return None
        previous_contract = Path('/var/lib/sls-mass-notify-trust') / previous / 'module/bin/sls_mass_notify'
        module = types.ModuleType('authenticated_candidate_piper_reuse')
        module.__file__ = str(candidate_source / relative)
        exec(compile(body, module.__file__, 'exec'), module.__dict__)
        result = module.probe_runtime_reuse(Path(MANAGED_TREES['runtime']) / 'piper',
            candidate_source / 'bin/sls_mass_notify', previous_contract)
        if (type(result) is not dict or type(result.get('schema')) is not int or result['schema'] != 1
                or result.get('kind') != 'sll-qualified-piper-reuse-v1' or result.get('qualified') is not True
                or read_prepared_upgrade_storage_proof(review, candidate_source) != proof):
            return None
        return result
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, AttributeError, RecursionError):
        return None


def piper_preparation_requirements(full, *, runtime_audio_bytes=0):
    """Remaining Piper/writer effects, with all operational floors preserved.

    Already retained release inputs, source/cache publications and prior-static
    snapshots stay physically occupied; this writer does not create them again.
    This scope confers no installation, settings or recovery authority.
    """
    if type(full) is not dict or full.get('mode') != 'install' or type(runtime_audio_bytes) is not int or runtime_audio_bytes < 0:
        raise ValueError('Complete install allocation and runtime audio floor required')
    parts = full['component_budgets_bytes']; temporary = full['temporary_directory']
    components = {MANAGED_TREES[name]: dict(parts[MANAGED_TREES[name]]) for name in
        ('data','config_backups','voices','module','web','sip_api','control_api','operator_portal')}
    components['/var/log'] = dict(parts['/var/log'])
    components[INSTALLER_JOURNAL] = {name: parts[INSTALLER_JOURNAL][name] for name in
        ('protected_config_snapshot','journal_metadata')}
    components['/var/lib/sls-mass-notify-trust'] = {
        'stock_and_release_manifests': parts['/var/lib/sls-mass-notify-trust']['stock_and_release_manifests']}
    runtime = MANAGED_TREES['runtime']; environment = full['piper_environment_requirements']; scratch = full['piper_temporary_requirements']
    components[runtime] = {'replacement_runtime': environment['environment_bytes']}
    unit = scratch['allocation_unit']
    components[temporary] = {'pinned_wheel_downloads': rounded(PINNED_WHEEL_BYTES, unit),
        'wheel_unpack_workspace': scratch['environment_bytes'], 'pip_old_package_recovery': scratch['environment_bytes'],
        'one_voice_download': parts[temporary]['one_voice_download'],
        'quarantined_python_caches': parts[temporary]['quarantined_python_caches']}
    if runtime_audio_bytes:
        components.setdefault('/tmp', {})['runtime_audio_headroom'] = runtime_audio_bytes
    budgets = {path: sum(row.values()) for path, row in components.items()}
    inodes = {path: full['inode_budgets'].get(path, 0) for path in components}
    inodes[runtime] = environment['required_inodes']
    inodes[temporary] = 2 * scratch['required_inodes'] + 128
    if runtime_audio_bytes:
        inodes['/tmp'] = inodes.get('/tmp', 0) + 32
    result = {k: v for k, v in full.items() if k not in
        ('previous_release_required','prepared_release_resident','stock_cache_publication_required','stock_cache_publication_sizes')}
    result.update(basis='piper_dependency_remaining_effects_2026-11-15', piper_preparation_only=True,
        qualified_piper_reuse=False, component_budgets_bytes=components, free_budgets_bytes=budgets,
        inode_budgets=inodes, temporary_free_bytes=budgets[temporary], additional_free_bytes=sum(budgets.values()),
        sls_persistent_free_bytes=sum(value for path,value in budgets.items() if path not in ('/tmp','/var/tmp',temporary)))
    return result


def _piper_preparation_payloads():
    """Only a protected active generation matching this helper narrows payloads."""
    try:
        trust = Path('/var/lib/sls-mass-notify-trust')
        reference = _fresh_json(_fresh_read(trust / 'slsmassnotifyserver.active.json', 1024)[0])
        if (type(reference) is not dict or set(reference) != {'generation','sha256'}
                or type(reference['sha256']) is not str or re.fullmatch('[a-f0-9]{64}',reference['sha256']) is None
                or reference['generation'] != 'slsmassnotifyserver-' + reference['sha256']):
            return None
        generation = trust / reference['generation']
        raw, _ = _fresh_read(generation / 'inventory.json', 8 * MIB)
        inventory = _fresh_json(raw)
        if (hashlib.sha256(raw).hexdigest() != reference['sha256'] or type(inventory) is not dict
                or type(inventory.get('schema')) is not int or inventory['schema'] != 1
                or inventory.get('module') != 'slsmassnotifyserver'
                or inventory.get('source',{}).get('kind') != 'publisher-ed25519'):
            return None
        helper, _ = _fresh_read(Path(__file__), 2 * MIB, private=False)
        if hashlib.sha256(helper).hexdigest() != inventory['files']['bin/sls_mass_notify/sls_resource_capacity.py']['sha256']:
            return None
        return measure_release_payloads(generation / 'module')
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return None


def voice_write_budgets(full, name, temporary, stage, *, target_unit, scratch_unit, audio_floor):
    """Additional blocks and inodes while replacing one voice, including outstanding installation work."""
    catalog = dict(VOICE_BYTES)
    for pack in full['optional_voice_packs']:
        catalog.update(REGIONAL_VOICE_BYTES[pack])
    if name not in catalog or stage not in ('download', 'promote'):
        raise ValueError('Unknown voice artifact or write phase')
    voice = MANAGED_TREES['voices']
    paths = [MANAGED_TREES[role] for role in
             ('data', 'config_backups', 'module', 'web', 'sip_api', 'control_api', 'operator_portal')]
    paths.append('/var/log')
    budgets = {path: full['free_budgets_bytes'][path] for path in paths}
    inodes = {path: full['inode_budgets'][path] for path in paths}
    # The staged runtime and its recovery copies are already resident. The
    # configuration snapshot, manifests and module activation still lie ahead.
    parts = full['component_budgets_bytes']
    budgets[INSTALLER_JOURNAL] = sum(parts[INSTALLER_JOURNAL][key]
                                     for key in ('protected_config_snapshot', 'journal_metadata'))
    inodes[INSTALLER_JOURNAL] = JOURNAL_METADATA_ENTRIES
    trust = '/var/lib/sls-mass-notify-trust'
    budgets[trust] = parts[trust]['stock_and_release_manifests']
    inodes[trust] = PREPARE_METADATA_ENTRIES
    budgets[voice] = rounded(catalog[name], max(4096, target_unit))
    inodes[voice] = 1
    budgets[temporary] = rounded(catalog[name], max(4096, scratch_unit)) if stage == 'download' else 0
    inodes[temporary] = int(stage == 'download')
    budgets['/tmp'] = budgets.get('/tmp', 0) + audio_floor
    inodes['/tmp'] = inodes.get('/tmp', 0) + 32
    return budgets, inodes


def admit_voice_write(name, temporary, stage, profile=None):
    if os.geteuid() != 0:
        raise ValueError('Voice installation requires the protected writer')
    if temporary == PRIVATE_INSTALL_TEMP:
        private_install_temporary_state()
    elif not trusted_temporary_directory(temporary):
        raise ValueError('Voice installation workspace is unsafe')
    config = Path(MANAGED_TREES['data'], 'mass-notifications.config')
    saved = configured_limits(config) if os.path.lexists(config) else {}
    selected = profile or saved.get('deployment_profile', 'standard')
    audio = probe_runtime_speech_scratch(selected, saved)
    full = probe_storage('install', _piper_preparation_payloads(),
                         optional_packs=saved.get('speech_optional_voice_packs', ()))
    budgets, inodes = voice_write_budgets(full, name, temporary, stage,
        target_unit=os.statvfs(MANAGED_TREES['voices']).f_frsize,
        scratch_unit=os.statvfs(temporary).f_frsize, audio_floor=audio['required_free_bytes'])
    for fs in probe_filesystems(budgets, inodes):
        if not any(budgets.get(path, 0) or inodes.get(path, 0) for path in fs['paths']):
            continue
        if (fs['read_only'] or fs['volatile_targets'] or fs['inodes_exhausted']
                or fs['available_bytes'] < fs['required_free_bytes']
                or fs['available_inodes'] is not None and fs['available_inodes'] < fs['required_inodes']):
            raise ResourceProbeError('voice_write_capacity_refused',
                f"Voice {stage} refused for {name} on {', '.join(fs['paths'])}. "
                f"Available/required bytes {fs['available_bytes']}/{fs['required_free_bytes']}, "
                f"inodes {fs['available_inodes']}/{fs['required_inodes']}. "
                "Check available space, writable mounts and inode capacity.")


def admit_piper_preparation_storage(temporary_directory, *, profile=None):
    """Re-admit actual full replacement before its first stage/target write.

    The caller validates the selected temporary directory's protected identity.
    All target, data, media, backup, log, remaining module and metadata floors are
    grouped on their actual filesystems. No existing evidence is removed to fit.
    """
    if os.geteuid() != 0 or temporary_directory not in ('/tmp','/var/tmp',PRIVATE_INSTALL_TEMP):
        raise ResourceProbeError('piper_preparation_unqualified','Piper replacement requires the selected qualified installer workspace.')
    config = Path(MANAGED_TREES['data']) / 'mass-notifications.config'
    saved = configured_limits(config) if os.path.lexists(config) else {}
    if profile is None:
        profile = saved.get('deployment_profile', 'standard')
    if profile not in DEPLOYMENT_PROFILES:
        raise ValueError('Invalid Piper deployment profile')
    if saved:
        phone_limit = saved.get('phone_device_limit', PHONE_BASELINE)
    else:
        inventory = detect_internal_phones()
        phone_limit = rounded_phone_capacity(inventory['detected_phone_contacts'], profile)
    optional = saved.get('speech_optional_voice_packs',())
    full = probe_storage('install', _piper_preparation_payloads(), optional_packs=optional, verify_voice_content=True)
    # Rebind only the explicitly selected workspace, never silently choose a new
    # path after the builder has been given its TMPDIR role.
    if temporary_directory != full['temporary_directory']:
        units = {**full.get('allocation_units',{}), temporary_directory: os.statvfs(temporary_directory).f_frsize}
        payloads = dict(full.get('payloads',{}))
        if '/tmp' in payloads: payloads[temporary_directory] = payloads.pop('/tmp')
        full = storage_requirements(full.get('measured_trees'), full.get('missing_voice_bytes'), units,
            temporary_directory, mode='install', payloads=payloads, optional_packs=optional,
            pending_voice_files=full.get('pending_voice_files'))
    audio = probe_runtime_speech_scratch(profile,saved)
    storage = piper_preparation_requirements(full,runtime_audio_bytes=audio['required_free_bytes'])
    filesystems = probe_filesystems(storage['free_budgets_bytes'],storage['inode_budgets'])
    cpu,memory = probe_compute()
    hardware = {'effective_cpu_count':cpu,'effective_memory_bytes':memory,'cpu_isa':probe_cpu_isa(),
        'memory_limit_bytes':probe_memory_limit(),'filesystems':filesystems,'storage':storage,'runtime_speech_scratch':audio}
    result = evaluate(hardware, saved.get('desktop_client_limit', 25), phone_limit, profile)
    if result['errors']:
        failure = ResourceProbeError('piper_preparation_capacity_refused',
            'Full Piper replacement lacks required CPU/RAM, writable bytes, inodes or preserved operational headroom; active and recovery trees were preserved.')
        failure.capacity_details = {'schema':1,
            'errors':[{key:row.get(key) for key in ('code','actual','required')} for row in result['errors']],
            'filesystems':[{key:row.get(key) for key in ('paths','available_bytes','required_free_bytes',
                'available_inodes','required_inodes','read_only','filesystem_type')} for row in filesystems],
            'raw_configuration_or_ledger_emitted':False}
        raise failure
    return {'schema':1,'temporary_directory':temporary_directory,'replacement_capacity_admitted':True,
            'filesystems':filesystems,'storage_basis':storage['basis'],'storage_requirements':storage}


FREE_BUDGETS = storage_requirements()['free_budgets_bytes']


class ResourceProbeError(ValueError):
    """Only locally constructed, operator-safe diagnostics may reach the UI."""
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def cpu_isa_report(cpuinfo, allowed_cpus):
    """Check the exact pinned amd64 wheel baseline without importing native code.

    NumPy2.4.6's hash-locked cp311 wheel has X86_V2 as its baseline. Linux
    exposes SSE3 as pni and long-mode LAHF/SAHF as lahf_lm. AVX is optional
    dispatch, so it is deliberately absent from this requirement.
    """
    unavailable = ResourceProbeError('cpu_isa_unavailable',
        'The pinned speech runtime CPU instruction set could not be verified for every allowed CPU. Restore readable /proc/cpuinfo and CPU affinity information, then retry; no CPU capability was guessed.')
    if (not isinstance(cpuinfo, str) or len(cpuinfo) > 32 * MIB or not allowed_cpus
            or len(allowed_cpus) > 65536 or any(type(cpu) is not int or cpu < 0 for cpu in allowed_cpus)):
        raise unavailable
    processors = {}
    for block in re.split(r'\n\s*\n', cpuinfo.strip()):
        rows = {}
        for line in block.splitlines():
            name, separator, value = line.partition(':')
            if separator and name.strip() in ('processor', 'flags'):
                if name.strip() in rows:
                    raise unavailable
                rows[name.strip()] = value.strip()
        if not rows:
            continue
        if not re.fullmatch(r'[0-9]{1,9}', rows.get('processor', '')) or 'flags' not in rows:
            raise unavailable
        cpu = int(rows['processor'])
        if cpu in processors or len(processors) >= 65536:
            raise unavailable
        processors[cpu] = set(rows['flags'].split())
    if not set(allowed_cpus) <= processors.keys():
        raise unavailable
    required = {'sse', 'sse2', 'pni', 'ssse3', 'sse4_1', 'sse4_2', 'popcnt', 'cx16', 'lahf_lm'}
    missing = {cpu: required - processors[cpu] for cpu in sorted(allowed_cpus) if not required <= processors[cpu]}
    if missing:
        features = ', '.join(sorted(set().union(*missing.values())))
        cpus = ', '.join(map(str, list(missing)[:8])) + (' (and others)' if len(missing) > 8 else '')
        raise ResourceProbeError('cpu_isa_unsupported',
            'The pinned NumPy2.4.6 speech runtime requires x86-64-v2. Allowed CPU(s) ' + cpus +
            ' lack: ' + features + '. Have the PBX administrator review the hypervisor CPU model or use compatible hardware before retrying. Adding CPU cores or RAM does not add instructions; the installer will not change the VM CPU model or downgrade frozen dependencies.')
    return {'baseline': 'x86-64-v2', 'checked_cpu_count': len(allowed_cpus),
            'numpy_version': PINNED_VERSIONS['numpy'], 'avx_required': False}


def probe_cpu_isa():
    try:
        if platform.machine() not in ('x86_64', 'amd64'):
            raise ValueError('Unsupported wheel architecture')
        allowed_cpus = os.sched_getaffinity(0)
        with open('/proc/cpuinfo', 'r', encoding='ascii') as handle:
            cpuinfo = handle.read(32 * MIB + 1)
        return cpu_isa_report(cpuinfo, allowed_cpus)
    except ResourceProbeError:
        raise
    except (OSError, ValueError, AttributeError) as error:
        raise ResourceProbeError('cpu_isa_unavailable',
            'The pinned amd64 speech runtime CPU instruction set could not be verified. Check the supported architecture, readable /proc/cpuinfo and CPU affinity before retrying; no CPU capability was guessed.') from error



def _private_recovery_stage(parent, name, info):
    """Recognize only root-validated Piper evidence; never widen its access."""
    if os.geteuid() == 0 or not re.fullmatch(r'\.replacement-[a-f0-9]{24}', name):
        return False
    def identity(value):
        return {key: int(getattr(value, 'st_' + key)) for key in ('dev', 'ino', 'mode', 'uid', 'gid', 'ctime_ns')}
    parent = Path(parent)
    meta = parent.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o700): return False
    fd = parent_fd = stage_fd = None
    try:
        marker = parent / (name + '.retained.json')
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o644
                or not 1 <= before.st_size <= 1024): return False
        raw = os.read(fd, 1025)
        after = os.fstat(fd); named = marker.lstat()
        stamp = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                               value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(raw) != before.st_size or stamp(before) != stamp(after) or stamp(before) != stamp(named): return False
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {'schema', 'stage', 'identity'}
                or type(value['schema']) is not int or value['schema'] != 1 or value['stage'] != name
                or value['identity'] != identity(info)
                or not isinstance(value['identity'], dict)
                or any(type(item) is not int for item in value['identity'].values())): return False
        parent_fd = os.open(parent, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        stage_fd = os.open(parent / name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        def mount_id(descriptor):
            with open('/proc/self/fdinfo/' + str(descriptor), encoding='ascii') as stream:
                text = stream.read(4097)
            if len(text) > 4096: raise ValueError('Oversized directory descriptor metadata')
            return next(line.split()[1] for line in text.splitlines() if line.startswith('mnt_id:'))
        return identity(os.fstat(stage_fd)) == identity(info) and mount_id(parent_fd) == mount_id(stage_fd)
    except (OSError, ValueError, TypeError, KeyError, StopIteration):
        return False
    finally:
        for descriptor in (fd, parent_fd, stage_fd):
            if descriptor is not None: os.close(descriptor)


def measure_tree(path, deadline, maximum_entries=50000, *, cache=None):
    """Metadata only, without following directory/file links or printing names."""
    result = {'allocated_bytes': 0, 'logical_bytes': 0, 'files': 0, 'directories': 0, 'largest_file_bytes': 0}
    root = Path(path)
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        return result
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError('An SLL storage root is not a real directory')
    cache = {} if cache is None else cache
    if str(root) in cache: return dict(cache[str(root)])
    seen, seen_directories, examined, pending = set(), set(), 0, [(root, False)]
    reports, children = {}, {}
    while pending:
        if time.monotonic() > deadline:
            raise ResourceProbeError('storage_scan_timeout', 'SLL storage measurement exceeded its time limit. Reduce retained files or resolve storage latency, then retry.')
        directory, complete = pending.pop()
        key = str(directory)
        if complete:
            report = reports[key]
            for child in children[key]:
                nested = reports.get(str(child), result)
                for name in ('allocated_bytes', 'logical_bytes', 'files', 'directories'):
                    report[name] += nested[name]
                report['largest_file_bytes'] = max(report['largest_file_bytes'], nested['largest_file_bytes'])
            cache[key] = dict(report)
            continue
        if key in cache:
            reports[key] = dict(cache[key]); continue
        try:
            metadata = directory.lstat()
        except FileNotFoundError:
            # Another worker may retire an already enumerated terminal directory.
            continue
        identity = (metadata.st_dev, metadata.st_ino)
        if not stat.S_ISDIR(metadata.st_mode) or identity in seen_directories:
            continue
        seen_directories.add(identity)
        reports[key] = {**result, 'directories': 1}
        children[key] = []
        pending.append((directory, True))
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    examined += 1
                    if examined > maximum_entries:
                        raise ResourceProbeError('storage_scan_entry_limit', 'SLL storage measurement exceeded its ' + str(maximum_entries) + '-entry limit. Review retained files before retrying.')
                    if time.monotonic() > deadline:
                        raise ResourceProbeError('storage_scan_timeout', 'SLL storage measurement exceeded its time limit. Resolve storage latency or reduce retained files before retrying.')
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISDIR(metadata.st_mode):
                        if _private_recovery_stage(directory, entry.name, metadata):
                            reports[key]['directories'] += 1
                            continue
                        child = Path(entry.path)
                        children[key].append(child); pending.append((child, False))
                        continue
                    identity = (metadata.st_dev, metadata.st_ino)
                    if not stat.S_ISREG(metadata.st_mode) or identity in seen:
                        continue
                    seen.add(identity)
                    report = reports[key]
                    report['allocated_bytes'] += metadata.st_blocks * 512
                    report['logical_bytes'] += metadata.st_size
                    report['largest_file_bytes'] = max(report['largest_file_bytes'], metadata.st_size)
                    report['files'] += 1
        except PermissionError as error:
            relative = directory.relative_to(root).as_posix()
            detail = str(root)
            if re.fullmatch(r'[A-Za-z0-9_./-]{1,120}', relative) and relative != '.':
                detail += '/' + relative
            raise ResourceProbeError('storage_directory_unreadable',
                'The PBX account cannot read SLL storage at ' + detail +
                '. Run Repair Installation to restore directory traversal/read permissions, then retry the resource check.') from error
        except OSError as error:
            raise ValueError('Unable to measure an SLL storage directory safely') from error
    return dict(cache.get(str(root), result))


def _voice_change_watch(content_fd):
    """Observe modifications of the pinned inode without locking the media file."""
    try:
        import ctypes
        libc = ctypes.CDLL(None)
        initialize, add = libc.inotify_init1, libc.inotify_add_watch
        watch = initialize(os.O_NONBLOCK | os.O_CLOEXEC)
        if watch < 0:
            return None
        # Linux IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF.
        mask = 0x002 | 0x004 | 0x008 | 0x400 | 0x800
        if add(watch, os.fsencode('/proc/self/fd/' + str(content_fd)), mask) >= 0:
            return watch
        os.close(watch)
    except (ImportError, AttributeError, OSError):
        pass
    return None


def piper_voice_current(target, expected_sha, expected_bytes, *, deadline=None):
    """Hash a single approved model through a pinned ordinary-file descriptor."""
    path = Path(target)
    if (path.parent != Path(MANAGED_TREES['voices'])
            or re.fullmatch(r'[a-z]{2}_[A-Z]{2}-[A-Za-z0-9_-]+\.onnx(?:\.json)?', path.name) is None
            or not isinstance(expected_sha, str) or re.fullmatch(r'[a-f0-9]{64}', expected_sha) is None
            or type(expected_bytes) is not int or not 0 < expected_bytes <= 128*MIB):
        return False
    until = deadline if deadline is not None else time.monotonic() + 30
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    def mount_id(fd):
        with open('/proc/self/fdinfo/' + str(fd), encoding='ascii') as stream:
            return next(int(line.split()[1]) for line in stream if line.startswith('mnt_id:'))
    parent = pinned = content = watch = None
    try:
        account = pwd.getpwnam('asterisk')
        if account.pw_uid <= 0 or account.pw_gid <= 0 or time.monotonic() >= until:
            return False
        flags = os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_RDONLY
        parent = os.open('/', flags)
        for component in path.parts[1:-1]:
            child = os.open(component, flags, dir_fd=parent)
            os.close(parent); parent = child
            entry = os.fstat(parent)
            if (entry.st_uid not in (0, account.pw_uid) or entry.st_mode & 0o002
                    or entry.st_mode & 0o020 and entry.st_gid not in (0, account.pw_gid)):
                return False
        # O_PATH pins metadata first, without opening a device or a FIFO for I/O.
        pinned = os.open(path.name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(pinned)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != expected_bytes
                or before.st_uid not in (0,account.pw_uid) or before.st_mode & 0o022
                or mount_id(parent) != mount_id(pinned)):
            return False
        content = os.open('/proc/self/fd/' + str(pinned), os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        stamp = identity(before)
        if identity(os.fstat(content)) != stamp:
            return False
        watch = _voice_change_watch(content)
        # Coarse filesystem timestamps can hide a same-length write within
        # one clock tick. If no watch is available, verify two complete bounded
        # reads against the published digest before skipping the download.
        for attempt in range(2 if watch is None else 1):
            if attempt:
                os.lseek(content, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            remaining = expected_bytes
            while remaining:
                if time.monotonic() >= until:
                    return False
                data = os.read(content, min(1024*1024, remaining))
                if not data:
                    return False
                remaining -= len(data)
                digest.update(data)
            if os.read(content, 1) or digest.hexdigest() != expected_sha:
                return False
        if not (time.monotonic() < until and identity(os.fstat(content)) == stamp
                and identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == stamp
                and identity(path.lstat()) == stamp):
            return False
        if watch is not None:
            try:
                os.read(watch, 4096)
            except BlockingIOError:
                return True
            return False  # Includes changed content, invalidated watch or queue overflow.
        return True
    except (OSError, ValueError, KeyError, StopIteration):
        return False
    finally:
        for fd in (watch,content,pinned,parent):
            if fd is not None:
                os.close(fd)


def probe_storage(mode='install', payloads=None, optional_packs=(), previous_release_required=True, prepared_release_resident=False, stock_cache_publication_required=True, qualified_piper_reuse=False, stock_cache_publication_sizes=None, verify_voice_content=False):
    deadline = time.monotonic() + (3 if mode == 'runtime' else 15)
    cache = {}
    measured = {name: measure_tree(path, deadline, cache=cache) for name, path in
                sorted(MANAGED_TREES.items(), key=lambda item: len(Path(item[1]).parts))}
    measured['recovery_recordings'] = {'allocated_bytes': 0, 'logical_bytes': 0, 'files': 0}
    for name in RECOVERY_RECORDINGS:
        try:
            metadata = Path(name).lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(metadata.st_mode):
            measured['recovery_recordings']['allocated_bytes'] += metadata.st_blocks * 512
            measured['recovery_recordings']['logical_bytes'] += metadata.st_size
            measured['recovery_recordings']['files'] += 1
    for key, name in STATE_FILES.items():
        try:
            metadata = Path(MANAGED_TREES['data'], name).lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(metadata.st_mode):
            measured[key] = {'allocated_bytes': metadata.st_blocks * 512, 'logical_bytes': metadata.st_size}
    units = {}
    for path in FREE_BUDGETS:
        if path == STOCK_CACHE and mode != 'install':
            continue  # native runtime/doctor never needs the private stock package directory
        existing = Path(path)
        while not existing.exists():
            existing = existing.parent
        units[path] = os.statvfs(existing).f_frsize
    missing = 0
    voice_sizes=dict(VOICE_BYTES)
    for pack in optional_packs:
        if pack not in REGIONAL_VOICE_BYTES:raise ValueError('Unknown optional speech pack')
        voice_sizes.update(REGIONAL_VOICE_BYTES[pack])
    pending = [] if verify_voice_content is True and mode == 'install' else None
    checksum_deadline = time.monotonic() + 45
    for name, expected in voice_sizes.items():
        path = Path(MANAGED_TREES['voices'], name)
        if pending is not None and not piper_voice_current(path, VOICE_SHA256[name], expected, deadline=checksum_deadline):
            pending.append(name)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            metadata = None
        if (metadata is None or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1 or metadata.st_size != expected
                or metadata.st_blocks * 512 < expected):
            missing += rounded(expected, max(4096, units[MANAGED_TREES['voices']]))
    return storage_requirements(measured, missing, units, mode=mode, payloads=payloads, optional_packs=optional_packs,
                                previous_release_required=previous_release_required,
                                prepared_release_resident=prepared_release_resident,
                                stock_cache_publication_required=stock_cache_publication_required,
                                qualified_piper_reuse=qualified_piper_reuse,
                                stock_cache_publication_sizes=stock_cache_publication_sizes, pending_voice_files=pending)


def measure_release_payloads(source):
    """Measure an authenticated root-private staging tree without executing it."""
    root = Path(source)
    for parent in (root, *root.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise ResourceProbeError('candidate_source_unprotected', 'The authenticated candidate must be in a root-protected staging directory.')
    targets = [MANAGED_TREES[name] for name in ('module', 'runtime', 'web', 'sip_api', 'control_api', 'operator_portal')]
    targets += ['/tmp', '/var/lib/sls-mass-notify-trust', INSTALLER_JOURNAL]
    payloads = {target: {'bytes': 0, 'entries': 1} for target in targets}
    entries, total = 0, 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in (*dirs, *files):
            path = Path(directory, name); info = path.lstat(); entries += 1
            if (entries > 5000 or info.st_uid != 0 or info.st_mode & 0o022
                    or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1)):
                raise ResourceProbeError('candidate_source_unsafe', 'The authenticated candidate contains an unsafe entry or exceeds its 5000-entry bound.')
            relative = path.relative_to(root).as_posix()
            size = info.st_size if stat.S_ISREG(info.st_mode) else 0
            total += size
            if total > 50 * MIB: raise ResourceProbeError('candidate_source_oversized', 'The candidate exceeds the 50 MiB payload bound.')
            destinations = [MANAGED_TREES['module'], '/tmp', '/var/lib/sls-mass-notify-trust', INSTALLER_JOURNAL]
            if relative.startswith('bin/'): destinations.append(MANAGED_TREES['runtime'])
            elif relative.startswith('api/sipnotify/'): destinations.append(MANAGED_TREES['sip_api'])
            elif relative.startswith('api/sls-mass-notify/'): destinations.append(MANAGED_TREES['control_api'])
            elif relative.startswith('portal/'): destinations.append(MANAGED_TREES['operator_portal'])
            elif relative.startswith('assets/'): destinations.append(MANAGED_TREES['web'])
            for destination in destinations:
                payloads[destination]['bytes'] += size; payloads[destination]['entries'] += 1
    return payloads


def read_limit(path):
    try:
        return path.read_text(encoding='ascii').strip()
    except FileNotFoundError:
        return None


def cgroup_directories():
    """Map memberships through actual cgroup mount roots, including bind mounts.

    A container's mounted hierarchy need not start at its filesystem root or
    live under /sys/fs/cgroup. Missing mappings must not authorize the host's
    larger CPU/RAM budget instead of an enforced container limit.
    """
    membership = Path('/proc/self/cgroup').read_text(encoding='ascii')
    mounts = Path('/proc/self/mountinfo').read_text(encoding='utf-8')
    if len(membership) > 65536 or len(mounts) > 1048576:
        raise ValueError('Cgroup topology exceeds its inspection bound')

    def canonical(value):
        if (not re.fullmatch(r'/(?:[^/\x00-\x1f]+(?:/[^/\x00-\x1f]+)*)?', value)
                or any(part in ('.', '..') for part in value.split('/'))):
            raise ValueError('Invalid cgroup topology path')
        return Path(value)

    def unescape(value):
        return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), value)

    entries = []
    for line in membership.splitlines():
        fields = line.split(':', 2)
        if len(fields) != 3 or not fields[0].isdigit():
            raise ValueError('Invalid cgroup membership')
        _, controllers, relative = fields
        path = canonical(relative)
        for kind in (['v2'] if not controllers else
                     [item for item in controllers.split(',') if item in ('memory', 'cpu')]):
            entries.append((path, kind))
    mounted = []
    for line in mounts.splitlines():
        fields = line.split()
        if '-' not in fields:
            raise ValueError('Invalid mount topology')
        separator = fields.index('-')
        if separator < 6 or len(fields) < separator + 4:
            raise ValueError('Invalid mount topology')
        filesystem = fields[separator + 1]
        if filesystem not in ('cgroup', 'cgroup2'):
            continue
        root, target = canonical(unescape(fields[3])), canonical(unescape(fields[4]))
        kinds = {'v2'} if filesystem == 'cgroup2' else set(fields[separator + 3].split(',')) & {'cpu', 'memory'}
        mounted.append((root, target, kinds))
    yielded = set()
    for member, kind in entries:
        found = False
        for root, target, kinds in mounted:
            if kind not in kinds:
                continue
            try:
                relative = member.relative_to(root)
            except ValueError:
                continue
            current = target / relative
            if not current.is_dir():
                continue
            found = True
            while True:
                identity = (current, kind)
                if identity not in yielded:
                    yielded.add(identity)
                    yield current, kind
                if current == target:
                    break
                current = current.parent
        if not found:
            raise ResourceProbeError('cgroup_topology_unavailable',
                'The current container CPU/RAM hierarchy cannot be mapped to a visible cgroup mount. Expose its actual hierarchy and retry; host capacity cannot substitute for an unreadable enforced limit.')


def probe_compute():
    cpu = float(len(os.sched_getaffinity(0)))
    memory_text = Path('/proc/meminfo').read_text(encoding='ascii')
    match = re.search(r'^MemTotal:\s+(\d+)\s+kB$', memory_text, re.M)
    if not match or cpu < 1:
        raise ValueError('CPU or physical memory information is unavailable')
    memory = int(match.group(1)) * 1024
    for directory, kind in cgroup_directories():
        memory_value = read_limit(directory / ('memory.max' if kind == 'v2' else 'memory.limit_in_bytes')) if kind in {'v2', 'memory'} else None
        if memory_value is not None and memory_value != 'max':
            limit = int(memory_value)
            if 0 < limit < 2 ** 60:
                memory = min(memory, limit)
        if kind == 'v2':
            value = read_limit(directory / 'cpu.max')
            if value:
                quota, period = value.split()
                if quota != 'max':
                    cpu = min(cpu, int(quota) / int(period))
        elif kind == 'cpu':
            quota = read_limit(directory / 'cpu.cfs_quota_us')
            period = read_limit(directory / 'cpu.cfs_period_us')
            if quota is not None and period is not None and int(quota) > 0:
                cpu = min(cpu, int(quota) / int(period))
    if memory <= 0 or cpu <= 0:
        raise ValueError('Invalid effective resource limits')
    return cpu, memory


def filesystem_types():
    mounts = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        before, after = line.split(' - ', 1)
        mount = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match.group(1), 8)), before.split()[4])
        fields = after.split()
        options = frozenset(before.split()[5].split(',') + fields[2].split(','))
        mounts.append((mount.rstrip('/') or '/', fields[0], options))
    return sorted(mounts, key=lambda item: len(item[0]), reverse=True)


def probe_filesystems(free_budgets=None, inode_budgets=None):
    free_budgets = FREE_BUDGETS if free_budgets is None else free_budgets
    mounts = filesystem_types()
    devices = {}
    for path in dict.fromkeys((*PERSISTENT_PATHS, *free_budgets)):
        existing = Path(path)
        while not existing.exists():
            existing = existing.parent
        actual = str(existing.resolve())
        metadata = existing.stat()
        usage = os.statvfs(existing)
        matched = next((entry for entry in mounts if actual == entry[0] or actual.startswith(entry[0].rstrip('/') + '/')), ('', '', frozenset()))
        kind = matched[1]
        options = matched[2] if len(matched) > 2 else frozenset()
        # OverlayFS explicitly mounted volatile does not promise durable upper
        # state. Keep the real filesystem type in diagnostics and reject only
        # the exact option, without assuming every container overlay is unsafe.
        persistent = (path not in ('/tmp', '/var/tmp') and kind not in {'tmpfs', 'ramfs', 'devtmpfs'}
                      and not (kind == 'overlay' and 'volatile' in options))
        record = devices.setdefault(metadata.st_dev, {
            'device': str(metadata.st_dev), 'paths': [], 'total_bytes': usage.f_blocks * usage.f_frsize,
            'available_bytes': usage.f_bavail * usage.f_frsize, 'required_free_bytes': 0, 'persistent': False,
            'read_only': False, 'inodes_exhausted': False,
            'filesystem_type': kind, 'required_inodes': 0,
            'available_inodes': getattr(usage, 'f_favail', None) if getattr(usage, 'f_files', 0) > 0 else None,
            'volatile_targets': [],
        })
        record['paths'].append(path)
        # Shared mounts and bind mounts must not count the same bytes twice.
        record['available_bytes'] = min(record['available_bytes'], usage.f_bavail * usage.f_frsize)
        record['total_bytes'] = min(record['total_bytes'], usage.f_blocks * usage.f_frsize)
        if getattr(usage, 'f_files', 0) > 0:
            record['available_inodes'] = min(record['available_inodes'], usage.f_favail) if record['available_inodes'] is not None else usage.f_favail
        record['required_free_bytes'] += free_budgets.get(path, 0)
        record['required_inodes'] += (inode_budgets or {}).get(path, 0)
        # Even a complete voice catalog receives ownership/mode verification
        # and repair. Keep this specific mount writable and persistent when
        # hashing proves that its files need no additional data blocks.
        metadata_target = path == MANAGED_TREES['voices'] and path in free_budgets
        if free_budgets.get(path, 0) or metadata_target:
            if path not in ('/tmp', '/var/tmp') and not persistent:
                record['volatile_targets'].append(path)
            record['read_only'] = record['read_only'] or bool(getattr(usage, 'f_flag', 0) & os.ST_RDONLY)
        if free_budgets.get(path, 0):
            # Filesystems without a fixed inode table may report zero for both.
            record['inodes_exhausted'] = record['inodes_exhausted'] or (
                getattr(usage, 'f_files', 0) > 0 and getattr(usage, 'f_favail', None) == 0)
        record['persistent'] = record['persistent'] or persistent
    return list(devices.values())




def _private_spool_parent(root):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root = Path(root)
    if root.resolve() != root:
        raise ValueError('private installer workspace IO root is not canonical')
    descriptor = os.open(root, flags)
    try:
        for component in ('var', 'spool'):
            before = os.fstat(descriptor)
            if before.st_uid != 0 or before.st_mode & 0o022:
                raise ValueError('unsafe private installer workspace ancestor')
            named = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(component, flags, dir_fd=descriptor)
            opened = os.fstat(child)
            if (named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) != (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid, opened.st_mode):
                os.close(child)
                raise ValueError('private installer workspace ancestor changed')
            os.close(descriptor)
            descriptor = child
        parent = os.fstat(descriptor)
        if parent.st_uid != 0 or parent.st_mode & 0o022:
            raise ValueError('unsafe private installer workspace parent')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def private_install_temporary_state(root=Path('/'), *, allow_missing=False):
    """Read only the fixed scratch role; root is an IO root for namespace fixtures."""
    account = pwd.getpwnam('asterisk')
    if account.pw_uid <= 0 or account.pw_gid <= 0:
        raise ValueError('private installer workspace requires a nonroot native account')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    stamp = lambda info: {key: getattr(info, 'st_' + key) for key in ('dev', 'ino', 'uid', 'gid', 'mode')}
    descriptor = _private_spool_parent(root)
    leaf = None
    try:
        parent = os.fstat(descriptor)
        if parent.st_uid != 0 or parent.st_mode & 0o022:
            raise ValueError('unsafe private installer workspace parent')
        name = Path(PRIVATE_INSTALL_TEMP).name
        try:
            leaf = os.open(name, flags, dir_fd=descriptor)
        except FileNotFoundError:
            if not allow_missing:
                raise
        identity = None
        if leaf is not None:
            info = os.fstat(leaf)
            if (info.st_uid != 0 or info.st_gid != account.pw_gid
                    or stat.S_IMODE(info.st_mode) != 0o710
                    or stamp(info) != stamp(os.stat(name, dir_fd=descriptor, follow_symlinks=False))):
                raise ValueError('private installer workspace must be root:native-primary-GID mode0710')
            identity = stamp(info)
        capacity = os.fstatvfs(leaf if leaf is not None else descriptor)
        if stamp(parent) != stamp(os.fstat(descriptor)):
            raise ValueError('private installer workspace parent changed')
        return {'path': PRIVATE_INSTALL_TEMP, 'exists': leaf is not None,
                'uid': account.pw_uid, 'gid': account.pw_gid, 'identity': identity, 'parent_identity': stamp(parent),
                'allocation_unit': max(4096, capacity.f_frsize),
                'available_bytes': capacity.f_bavail * capacity.f_frsize,
                'available_inodes': capacity.f_favail if capacity.f_files else None,
                'read_only': bool(capacity.f_flag & os.ST_RDONLY)}
    finally:
        if leaf is not None:
            os.close(leaf)
        os.close(descriptor)

def trusted_temporary_directory(path):
    if path not in ('/tmp', '/var/tmp'):
        return False
    try:
        for directory in (Path(path), *Path(path).parents):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
                return False
        return True
    except OSError:
        return False


def probe_runtime_speech_scratch(profile, saved):
    """Installer scratch fallback does not move the runtime's /tmp audio files."""
    if profile not in DEPLOYMENT_PROFILES:
        raise ValueError('Invalid deployment profile')
    slots = saved.get('speech_synthesis_limit', 1)
    reserve = saved.get('generated_media_min_free_mib', 128)
    if type(slots) is not int or not 1 <= slots <= 4 or type(reserve) is not int or not 64 <= reserve <= 4096:
        raise ValueError('Invalid speech workspace settings')
    if profile == 'lite':
        if saved.get('deployment_profile', 'standard') == 'lite' and slots > 1:
            raise ValueError('Invalid Lite speech concurrency')
        slots = 1
    if not trusted_temporary_directory('/tmp'):
        raise ResourceProbeError('runtime_speech_workspace_unsafe',
            'Runtime audio requires the standard root-owned /tmp directory with safe sticky permissions. Restore its ownership and permissions before installing.')
    if os.geteuid() == 0:
        try:
            access = subprocess.run(['/usr/sbin/runuser', '-u', 'asterisk', '--', '/usr/bin/test',
                                     '-w', '/tmp', '-a', '-x', '/tmp'], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, cwd='/').returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            access = False
    else:
        access = os.access('/tmp', os.W_OK | os.X_OK)
    if not access:
        raise ResourceProbeError('runtime_speech_workspace_unsafe',
            'The PBX account cannot write and traverse /tmp for runtime audio. Restore that directory access before installing.')
    usage = os.statvfs('/tmp')
    # Match Admission.bytes at the supported 600-second bound and preserve
    # its configured free-space floor; this is a prerequisite, not a quota.
    required = reserve * MIB + slots * (600 * (48000 * 2 + 8000 * 2 * 4) + MIB)
    return {'path': '/tmp', 'available_bytes': usage.f_bavail * usage.f_frsize,
            'required_free_bytes': required, 'synthesis_workers': slots,
            'read_only': bool(getattr(usage, 'f_flag', 0) & os.ST_RDONLY),
            'inodes_exhausted': getattr(usage, 'f_files', 0) > 0 and getattr(usage, 'f_favail', None) == 0}


def probe_storage_filesystems(storage, temporary_directory=None, *, reserve_install_workspace=False):
    """Use persistent scratch space when a small /tmp cannot hold the install.

    All reservations still apply to their actual filesystem. Moving scratch
    cannot make an insufficient data/runtime filesystem eligible.
    """
    choices = (temporary_directory,) if temporary_directory else (('/tmp', '/var/tmp', PRIVATE_INSTALL_TEMP) if reserve_install_workspace or storage.get('mode') == 'install' else ('/tmp', '/var/tmp'))
    first = None
    for path in choices:
        private_state = None
        if path == PRIVATE_INSTALL_TEMP:
            try:
                private_state = private_install_temporary_state(allow_missing=reserve_install_workspace or (storage.get('mode') == 'install' and temporary_directory is None))
            except (OSError, ValueError, KeyError) as error:
                raise ResourceProbeError('private_install_workspace_unsafe', 'The fixed /var/spool installer workspace or its canonical native-account role is unsafe; no ownership or permissions were changed.') from error
            if private_state.get('read_only') and not private_state['exists']:
                continue
        elif not trusted_temporary_directory(path):
            continue
        if path == '/tmp' and not reserve_install_workspace:
            candidate = storage
        else:
            units = {**storage.get('allocation_units', {}), path: private_state['allocation_unit'] if private_state else os.statvfs(path).f_frsize}
            payloads = dict(storage.get('payloads', {}))
            if '/tmp' in payloads: payloads[path] = payloads.pop('/tmp')
            candidate = storage_requirements(storage.get('measured_trees'), storage.get('missing_voice_bytes'), units, path,
                mode=storage.get('mode', 'install'), payloads=payloads, optional_packs=storage.get('optional_voice_packs',()),
                reserve_install_workspace=reserve_install_workspace,
                previous_release_required=storage.get('previous_release_required', True),
                prepared_release_resident=storage.get('prepared_release_resident', False),
                stock_cache_publication_required=storage.get('stock_cache_publication_required', True),
                qualified_piper_reuse=storage.get('qualified_piper_reuse', False),
                stock_cache_publication_sizes=storage.get('stock_cache_publication_sizes'),
                pending_voice_files=storage.get('pending_voice_files'))
        if private_state is not None:
            candidate['temporary_directory_state'] = private_state
        filesystems = probe_filesystems(candidate['free_budgets_bytes'], candidate.get('inode_budgets'))
        if first is None:
            first = (candidate, filesystems)
        scratch_volatile = any(path in row['paths'] and row.get('filesystem_type') in {'tmpfs', 'ramfs', 'devtmpfs'} for row in filesystems)
        if scratch_volatile and temporary_directory is None and path in ('/tmp', '/var/tmp') and candidate['temporary_free_bytes']:
            continue
        if all(row['available_bytes'] >= row['required_free_bytes'] and not row.get('read_only')
               and not row.get('inodes_exhausted') and not row.get('volatile_targets')
               and (row.get('available_inodes') is None or row['available_inodes'] >= row.get('required_inodes', 0)) for row in filesystems):
            return candidate, filesystems
    if first is None:
        raise ResourceProbeError('temporary_directory_unavailable',
            'No qualified installer scratch filesystem is available. Restore the standard temporary directories or review the fixed private installer workspace; no permissions were changed.')
    return first


def configured_limits(path):
    """Read only the capacity fields; never echo configuration or credentials."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Configuration path must be absolute')
    account = pwd.getpwnam('asterisk')
    allowed_owners = {0, account.pw_uid}
    allowed_groups = {0, account.pw_gid}
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (info.st_uid not in allowed_owners or info.st_gid not in allowed_groups
                    or info.st_mode & 0o002 and not sticky_root
                    or info.st_mode & 0o020 and info.st_gid != account.pw_gid and not sticky_root):
                raise ValueError('Configuration parent ownership or permissions are unsafe')
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(descriptor, 'rb') as handle:
        metadata = os.fstat(handle.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid not in allowed_owners or metadata.st_gid not in allowed_groups
                or metadata.st_mode & 0o022 or metadata.st_size > 16 * 1024 * 1024):
            raise ValueError('Configuration is not a bounded private regular file')
        raw = handle.read(16 * 1024 * 1024 + 1)
        after = os.fstat(handle.fileno())
        if (len(raw) != metadata.st_size
                or (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
                != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('Configuration changed during inspection')
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError('Configuration exceeded its size limit')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Configuration contains duplicate JSON members')
            result[key] = value
        return result

    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError('Configuration contains a nonfinite number')
        return value

    def invalid_constant(text):
        raise ValueError('Configuration contains a nonfinite number')

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=finite_float, parse_constant=invalid_constant)
    except RecursionError:
        raise ValueError('Configuration exceeds JSON nesting limits') from None
    if isinstance(value, dict) and any(field in value for field in ('format', 'ciphertext', 'key_id', 'nonce')):
        if value.get('format') != 'sls-mass-notify-config-aes256gcm-v1':
            raise ValueError('The protected configuration encryption format is unsupported or damaged')
        helper = Path(__file__).resolve().with_name('sls_config_crypto.py')
        if not helper.is_file():
            helper = Path('/usr/local/bin/sls_mass_notify/sls_config_crypto.py')
        for protected in [helper, *helper.parents][:-1]:
            metadata = protected.lstat()
            if metadata.st_uid != 0 or (metadata.st_mode & 0o022 and not (stat.S_ISDIR(metadata.st_mode) and metadata.st_mode & stat.S_ISVTX)) or stat.S_ISLNK(metadata.st_mode):
                raise ValueError('Installed encryption helper is not protected')
        sys.dont_write_bytecode = True
        descriptor = os.open(helper, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_mode & 0o022 or opened.st_nlink != 1 or opened.st_size > 256 * 1024:
                raise ValueError('Installed encryption helper is unsafe')
            chunks = []
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk: break
                chunks.append(chunk)
                if sum(map(len, chunks)) > 256 * 1024: raise ValueError('Installed encryption helper exceeded its size limit')
            body = b''.join(chunks)
            after = os.fstat(descriptor)
            if len(body) != opened.st_size or (opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('Installed encryption helper changed during inspection')
        finally: os.close(descriptor)
        module = types.ModuleType('sls_config_crypto'); module.__file__ = str(helper)
        try: exec(compile(body, str(helper), 'exec'), module.__dict__)
        except ImportError as error:
            raise ResourceProbeError('config_crypto_dependency_missing', 'Encrypted settings require the system python3-cryptography package. Restore that prerequisite; existing settings and encryption keys must be preserved.') from error
        value = module.decode_config(raw)
    if not isinstance(value, dict):
        raise ValueError('Configuration must be an object')
    capacities = {key: value.get(key, default) for key, default in
                  (('desktop_client_limit', 25), ('phone_device_limit', PHONE_BASELINE))}
    if any(type(limit) is not int or not 1 <= limit <= 1000 for limit in capacities.values()):
        raise ValueError('Invalid notification capacity')
    optional=value.get('speech_optional_voice_packs',[])
    if not isinstance(optional,list) or len(optional)>2 or any(not isinstance(pack,str) or pack not in REGIONAL_VOICE_BYTES for pack in optional) or len(set(optional))!=len(optional):raise ValueError('Invalid optional speech packs')
    profile=value.get('deployment_profile','standard')
    if not isinstance(profile,str) or profile not in DEPLOYMENT_PROFILES:raise ValueError('Invalid deployment profile')
    capacities['deployment_profile']=profile
    if optional:capacities['speech_optional_voice_packs']=optional
    for key, minimum, maximum in (('speech_synthesis_limit', 1, 4), ('generated_media_min_free_mib', 64, 4096)):
        if key in value:
            field=value[key]
            if type(field) is not int or not minimum <= field <= maximum:raise ValueError('Invalid speech workspace settings')
            capacities[key]=field
    return capacities


def rounded_phone_capacity(count, profile='standard'):
    """Retain 25 for small installations, then round up in blocks of 50."""
    if type(count) is not int or count < 0:
        raise ValueError('Invalid detected phone count')
    if profile not in DEPLOYMENT_PROFILES:
        raise ValueError('Invalid deployment profile')
    maximum = LITE_MAX_PHONES if profile == 'lite' else 1000
    if count > maximum:
        raise ResourceProbeError('phone_inventory_exceeds_limit',
            f'{count} internal phone contacts were detected, but SLL {profile.title()} mode supports at most {maximum}. Use Standard mode with sufficient resources or reduce the configured phone inventory before installation.')
    return PHONE_BASELINE if count <= PHONE_BASELINE else rounded(count, 50)


def internal_phone_inventory(device_output, contact_output):
    """Count FreePBX PJSIP devices and their contacts, excluding trunk AORs.

    An offline configured device reserves one slot. Shared endpoint aliases do
    not count twice; several contacts on the same endpoint each count once.
    Complete CLI summaries are required so truncated output cannot undercount.
    Only aggregate counts leave this function, never addresses or device names.
    """
    lines = [line.strip() for line in device_output.splitlines() if line.strip()]
    rows = [line for line in lines if line.startswith('/DEVICE/')]
    if not lines or not re.fullmatch(r'[0-9]+ results found\.', lines[-1]) or int(lines[-1].split()[0]) != len(rows):
        raise ValueError('Incomplete FreePBX device inventory')
    endpoints = set()
    for line in rows:
        match = re.fullmatch(r'/DEVICE/[0-9]+/dial\s*:\s*(.*)', line)
        if not match or not match[1].startswith('PJSIP/'):
            continue
        endpoint = re.fullmatch(r'PJSIP/([A-Za-z0-9_.-]{1,80})', match[1])
        if not endpoint:
            raise ValueError('Unsupported internal PJSIP device route')
        endpoints.add(endpoint[1])
    if not endpoints:
        return {'configured_pjsip_devices': 0, 'registered_phone_contacts': 0, 'detected_phone_contacts': 0}
    contact_lines = [line.strip() for line in contact_output.splitlines() if line.strip()]
    summaries = [line for line in contact_lines if re.fullmatch(r'Objects found: [0-9]+', line)
                 or line in ('No objects found.', 'No Contacts found.')]
    if len(summaries) != 1:
        raise ValueError('Incomplete PJSIP contact inventory')
    expected = int(summaries[0].split()[-1]) if summaries[0].startswith('Objects found:') else 0
    contacts, counts = [], {endpoint: 0 for endpoint in endpoints}
    for line in contact_lines:
        if not line.startswith('Contact:'):
            continue
        fields = line.split()
        if len(fields) > 1 and fields[1].startswith('<'):
            continue
        if len(fields) != 5 or '/' not in fields[1] or not re.fullmatch(r'[a-fA-F0-9]{8,64}', fields[2]):
            raise ValueError('Unrecognized PJSIP contact inventory row')
        endpoint = fields[1].split('/', 1)[0]
        contacts.append((endpoint, fields[2]))
        if endpoint in counts:
            counts[endpoint] += 1
    if len(contacts) != expected or len(set(contacts)) != len(contacts):
        raise ValueError('Incomplete or duplicate PJSIP contact inventory')
    return {'configured_pjsip_devices': len(endpoints), 'registered_phone_contacts': sum(counts.values()),
            'detected_phone_contacts': sum(max(1, count) for count in counts.values())}


def detect_internal_phones():
    def command(value):
        result = subprocess.run(['/usr/sbin/asterisk', '-rx', value], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                text=True, timeout=3, check=False, close_fds=True, cwd='/', env=environment, **identity)
        if result.returncode != 0 or len(result.stdout) > 2 * MIB:
            raise ValueError('Asterisk inventory command failed')
        return result.stdout
    try:
        account = pwd.getpwnam('asterisk')
        if account.pw_uid <= 0 or os.geteuid() not in (0, account.pw_uid):
            raise ValueError('Asterisk inventory requires its configured runtime identity')
        identity = {'user': account.pw_uid, 'group': account.pw_gid,
                    'extra_groups': os.getgrouplist('asterisk', account.pw_gid)} if os.geteuid() == 0 else {}
        environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                       'HOME': account.pw_dir, 'USER': 'asterisk', 'LOGNAME': 'asterisk'}
        devices = command('database show DEVICE')
        # An empty DEVICE family needs no contact query. This also permits an
        # otherwise healthy new PBX whose PJSIP modules have no endpoints yet.
        empty = internal_phone_inventory(devices, 'Objects found: 0\n')
        return internal_phone_inventory(devices, command('pjsip show contacts')) if empty['configured_pjsip_devices'] else empty
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        raise ResourceProbeError('phone_inventory_unavailable',
            'The internal phone inventory could not be verified. Confirm Asterisk is running and its DEVICE database and PJSIP contact commands are available, then retry installation. No phone capacity was guessed.') from error


def capacity_requirements(requested, phone_requested, profile='standard'):
    if type(requested) is not int or not 1 <= requested <= 1000:
        raise ValueError('Desktop capacity must be between 1 and 1000')
    if type(phone_requested) is not int or not 1 <= phone_requested <= 1000:
        raise ValueError('Phone capacity must be between 1 and 1000')
    if profile not in DEPLOYMENT_PROFILES:
        raise ValueError('Invalid deployment profile')
    if profile == 'lite' and (requested > LITE_MAX_DESKTOPS or phone_requested > LITE_MAX_PHONES):
        raise ResourceProbeError('lite_capacity_exceeded',
            f'Lite mode supports at most {LITE_MAX_DESKTOPS} desktops and {LITE_MAX_PHONES} phone contacts. Lower both capacities or install in Standard mode on a host that meets the Standard resource requirements.')
    tiers = LITE_TIERS if profile == 'lite' else TIERS
    tier_limit, desktop_cpu, desktop_memory = next(tier for tier in tiers if requested <= tier[0])
    phone_resource_baseline = LITE_MAX_PHONES if profile == 'lite' else PHONE_RESOURCE_BASELINE
    extra_contacts = max(0, phone_requested - phone_resource_baseline)
    phone_cpu = (extra_contacts + PHONE_CONTACTS_PER_CPU - 1) // PHONE_CONTACTS_PER_CPU
    phone_memory = rounded(extra_contacts * PHONE_MEMORY_PER_CONTACT, PHONE_MEMORY_ROUNDING)
    return desktop_cpu + phone_cpu, desktop_memory * GIB + phone_memory, {
        'combined_baseline': {'cpu_count': 2, 'memory_bytes': (2 if profile == 'lite' else 4) * GIB,
                              'desktop_clients': LITE_MAX_DESKTOPS if profile == 'lite' else 50,
                              'phone_contacts': phone_resource_baseline,
                              'deployment_profile': profile},
        'desktop_growth': {'tier_limit': tier_limit, 'cpu_count': desktop_cpu - 2,
                           'memory_bytes': (desktop_memory - (2 if profile == 'lite' else 4)) * GIB},
        'phone_growth': {'contacts_over_baseline': extra_contacts, 'cpu_count': phone_cpu,
                         'memory_bytes': phone_memory},
    }


def minimum_reported_memory(hardware, nominal):
    """Allow bounded kernel reservations, never a lower enforced cgroup quota."""
    quota = hardware.get('memory_limit_bytes')
    if isinstance(quota, int) and 0 < quota < nominal:
        return nominal
    return nominal - min(MAX_KERNEL_RESERVE, nominal // 16)


def probe_memory_limit():
    limits = []
    for directory, kind in cgroup_directories():
        if kind not in {'v2', 'memory'}: continue
        value = read_limit(directory / ('memory.max' if kind == 'v2' else 'memory.limit_in_bytes'))
        if value not in (None, 'max'):
            limit = int(value)
            if 0 < limit < 2 ** 60: limits.append(limit)
    return min(limits) if limits else None


def evaluate(hardware, requested, phone_requested=PHONE_BASELINE, profile='standard'):
    cpu, memory_bytes, components = capacity_requirements(requested, phone_requested, profile)
    required_memory = minimum_reported_memory(hardware, memory_bytes)
    errors = []
    storage = hardware.get('storage', storage_requirements())
    scratch_memory = sum(item['required_free_bytes'] for item in hardware['filesystems']
        if item.get('filesystem_type') in {'tmpfs', 'ramfs', 'devtmpfs'}
        and storage.get('temporary_directory', '/tmp') in item['paths'])
    required_memory += scratch_memory

    def require(code, message, actual, required):
        if actual < required:
            errors.append({'code': code, 'message': message, 'actual': actual, 'required': required})

    require('cpu_insufficient',
            f'{cpu} effective CPU cores are required for {requested} desktops and {phone_requested} phone contacts; {hardware["effective_cpu_count"]:g} are allocated. Add CPU allocation or lower Desktop Capacity or Phone Capacity.',
            hardware['effective_cpu_count'], cpu)
    advice = ('This is the minimum combined PBX/SLL tier for the selected deployment profile; reducing device capacities will not lower its RAM baseline.'
              if memory_bytes == (2 if profile == 'lite' else 4) * GIB else 'Add RAM or lower Desktop Capacity or Phone Capacity.')
    require('memory_insufficient',
            f'{memory_bytes / GIB:g} GiB nominal RAM is required for {requested} desktops and {phone_requested} phone contacts; {hardware["effective_memory_bytes"] / GIB:.2f} GiB is usable and {required_memory / GIB:.2f} GiB is required after kernel reservations and scratch space. {advice}',
            hardware['effective_memory_bytes'], required_memory)
    disks_ok = True
    runtime_scratch = hardware.get('runtime_speech_scratch')
    if runtime_scratch is not None:
        before = len(errors)
        if runtime_scratch.get('read_only') or runtime_scratch.get('inodes_exhausted'):
            errors.append({'code':'runtime_speech_workspace_unavailable',
                'message':'Runtime audio requires writable /tmp storage with free file entries. Restore that filesystem before installing.',
                'actual':None,'required':None})
        require('runtime_speech_workspace_insufficient',
                f'Runtime speech requires {runtime_scratch["required_free_bytes"] / MIB:.2f} MiB free in /tmp, including its protected reserve; {runtime_scratch["available_bytes"] / MIB:.2f} MiB is available. Increase or free /tmp before installing. Installer fallback to /var/tmp does not move runtime audio workspace.',
                runtime_scratch['available_bytes'],runtime_scratch['required_free_bytes'])
        disks_ok = len(errors) == before
    for item in hardware['filesystems']:
        before = len(errors)
        destinations = [path for path in item['paths'] if storage['free_budgets_bytes'].get(path, 0)] or item['paths']
        location = ', '.join(destinations)
        if item.get('read_only'):
            errors.append({'code': 'storage_read_only', 'message': 'The filesystem containing ' + location + ' is read-only. Restore its writable mount before installing; available bytes cannot make a read-only target usable.', 'actual': None, 'required': None})
        if item.get('inodes_exhausted'):
            errors.append({'code': 'storage_inodes_exhausted', 'message': 'The filesystem containing ' + location + ' has no available file entries (inodes). Free file entries or expand that filesystem before installing.', 'actual': 0, 'required': 1})
        elif item.get('available_inodes') is not None:
            require('storage_inodes_insufficient', 'The filesystem containing ' + location + ' lacks the file entries required for this operation. Free inodes or expand the filesystem.',
                    item['available_inodes'], item.get('required_inodes', 0))
        volatile = item.get('volatile_targets') or (item.get('persistent') is False and any(path not in ('/tmp', '/var/tmp') and storage['free_budgets_bytes'].get(path, 0) for path in item['paths']))
        if volatile:
            errors.append({'code': 'storage_not_persistent', 'message': 'The filesystem containing ' + location + ' is volatile. Configuration, delivery history and installed runtime require persistent storage.', 'actual': None, 'required': None})
        require('free_space_insufficient',
                f'{item["required_free_bytes"] / MIB:.2f} MiB of additional SLL free space is required on the filesystem containing {location}; {item["available_bytes"] / MIB:.2f} MiB is available. Free space or expand this filesystem.',
                item['available_bytes'], item['required_free_bytes'])
        disks_ok = disks_ok and len(errors) == before
    eligible = 0
    eligible_phone = 0
    if disks_ok:
        tiers = LITE_TIERS if profile == 'lite' else TIERS
        maximum_phone = LITE_MAX_PHONES if profile == 'lite' else 1000
        for maximum, _, _ in tiers:
            tier_cpu, tier_memory, _ = capacity_requirements(maximum, phone_requested, profile)
            if hardware['effective_cpu_count'] >= tier_cpu and hardware['effective_memory_bytes'] >= minimum_reported_memory(hardware, tier_memory) + scratch_memory:
                eligible = maximum
        # Phone capacity is a continuous integer policy, not the desktop tiers.
        for phone_limit in range(1, maximum_phone + 1):
            phone_cpu, phone_memory, _ = capacity_requirements(requested, phone_limit, profile)
            if hardware['effective_cpu_count'] >= phone_cpu and hardware['effective_memory_bytes'] >= minimum_reported_memory(hardware, phone_memory) + scratch_memory:
                eligible_phone = phone_limit
    checks = {'cpu': {'ok': hardware['effective_cpu_count'] >= cpu,
                      'actual': hardware['effective_cpu_count'], 'required': cpu},
              'memory': {'ok': hardware['effective_memory_bytes'] >= required_memory,
                         'actual': hardware['effective_memory_bytes'], 'required': required_memory}}
    if runtime_scratch is not None:
        checks['runtime_temporary'] = {**runtime_scratch,
            'ok': runtime_scratch['available_bytes'] >= runtime_scratch['required_free_bytes']
                  and not runtime_scratch.get('read_only') and not runtime_scratch.get('inodes_exhausted')}
    temporary = storage.get('temporary_directory', '/tmp')
    for name, paths in (('storage', set(storage['free_budgets_bytes']) - {temporary}), ('temporary', {temporary})):
        filesystems = [item for item in hardware['filesystems'] if paths.intersection(item['paths'])]
        covered = set(path for item in filesystems for path in item['paths'])
        checks[name] = {'ok': all(item['available_bytes'] >= item['required_free_bytes'] and not item.get('read_only')
                                and not item.get('inodes_exhausted') and not item.get('volatile_targets')
                                and (item.get('available_inodes') is None or item['available_inodes'] >= item.get('required_inodes', 0))
                                and not (item.get('persistent') is False and any(path not in ('/tmp', '/var/tmp') and storage['free_budgets_bytes'].get(path, 0) for path in item['paths'])) for item in filesystems)
                       if paths <= covered else None,
                       'filesystems': [{'paths': item['paths'], 'actual': item['available_bytes'],
                                        'required': item['required_free_bytes']} for item in filesystems]}
    if runtime_scratch is not None:
        checks['temporary']['ok'] = checks['temporary']['ok'] is True and checks['runtime_temporary']['ok']
    displayed_temporary = storage['temporary_free_bytes']
    if runtime_scratch is not None and storage.get('mode') == 'runtime':
        displayed_temporary = max(displayed_temporary, runtime_scratch['required_free_bytes'])
    return {
        'schema': 1, 'deployment_profile': profile, 'requested_limit': requested, 'eligible_limit': eligible, 'hardware': hardware,
        'profile_selection': {
            'standard_memory_eligible': hardware['effective_memory_bytes'] >= minimum_reported_memory(hardware, 4 * GIB),
            'lite_memory_eligible': minimum_reported_memory(hardware, 2 * GIB) <= hardware['effective_memory_bytes'] < minimum_reported_memory(hardware, 4 * GIB)},
        'requested_phone_limit': phone_requested, 'eligible_phone_limit': eligible_phone,
        'requirements': {'cpu_count': cpu, 'memory_bytes': memory_bytes,
                         'minimum_reported_memory_bytes': required_memory,
                         'components': components, 'disk_policy': 'additional_sls_free_headroom',
                         'sls_persistent_free_bytes': storage['sls_persistent_free_bytes'], 'temporary_free_bytes': displayed_temporary,
                         'free_budgets_bytes': storage['free_budgets_bytes'], 'storage': storage,
                         'reporting_allowance_percent': (memory_bytes - minimum_reported_memory(hardware, memory_bytes)) * 100 / memory_bytes,
                         'kernel_reserve_bytes': memory_bytes - minimum_reported_memory(hardware, memory_bytes),
                         'temporary_memory_bytes': scratch_memory},
        'assumptions': {'load_certified': False, 'phone_baseline_contacts': PHONE_BASELINE,
                        'additional_phone_contacts_per_cpu_core': PHONE_CONTACTS_PER_CPU,
                        'additional_phone_memory_bytes_per_contact': PHONE_MEMORY_PER_CONTACT,
                        'phone_memory_rounding_bytes': PHONE_MEMORY_ROUNDING,
                        'included_phone_contacts': LITE_MAX_PHONES if profile == 'lite' else PHONE_RESOURCE_BASELINE,
                        'synthesis_concurrency_limited_by_this_check': profile == 'lite',
                        'maximum_synthesis_workers': 1 if profile == 'lite' else 4,
                        'maximum_speech_queue': 2 if profile == 'lite' else 32,
                        'desktop_sse_limit': 4 if profile == 'lite' else 32,
                        'whole_volume_size_is_enforced': False},
        'errors': errors,
        'resource_checks': checks,
        'warnings': [f'Provisional combined PBX/SLL {profile.title()} allocation; not load-certified. Phone growth reserves capacity for registered contacts and Local/Page overhead, not measured phones-per-core throughput. Runtime speech admission separately enforces its configured concurrency and media budget.',
                     f'SLL measured fixed files occupy {storage["measured_fixed_allocation_bytes"] / MIB:.1f} MiB. Additional {storage.get("mode", "install")} workspace requires {storage["additional_free_bytes"] / MIB:.1f} MiB across the listed filesystems, including {storage["steady_state_reserve_bytes"] / MIB:.1f} MiB for bounded writes/compaction. Retention and concurrent speech require additional measured provisioning; these are not storage quotas or a guarantee for an arbitrary workload.',
                     'Desktop clients above the stream limit require cursor-aware JSON polling. Existing PBX calls, codecs, recording, voicemail, backups, and long retention need separate resource budgets.'],
    }


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['--voice-current']:
        if len(argv) != 4 or not re.fullmatch(r'[1-9][0-9]{0,8}', argv[3]):
            return 1
        return 0 if piper_voice_current(argv[1], argv[2], int(argv[3])) else 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--cpu-isa-only', action='store_true', help='Check frozen wheel instructions before configuration or runtime preparation')
    parser.add_argument('--config', type=Path)
    parser.add_argument('--desktop-limit', type=int)
    parser.add_argument('--profile', choices=DEPLOYMENT_PROFILES)
    parser.add_argument('--temporary-directory', choices=('/tmp', '/var/tmp', PRIVATE_INSTALL_TEMP))
    parser.add_argument('--admit-voice-write', nargs=2, metavar=('FILE', 'STAGE'))
    parser.add_argument('--mode', choices=('runtime', 'prepare', 'install'), default='runtime')
    parser.add_argument('--reserve-install-workspace', action='store_true',
                        help='Choose preparation scratch with room for later install workspaces')
    parser.add_argument('--candidate-source', type=Path, help='Authenticated root-private candidate payload for installation budgets')
    parser.add_argument('--prepared-release-review', type=Path,
                        help='Protected prepared transaction review; unknown state retains conservative previous-release reserves')
    phone_options = parser.add_mutually_exclusive_group()
    phone_options.add_argument('--phone-limit', type=int)
    phone_options.add_argument('--auto-phone-limit', action='store_true',
                               help='Detect internal phones on a fresh install; retain saved capacities on upgrades')
    options = parser.parse_args(argv)
    if options.admit_voice_write is not None:
        name, stage = options.admit_voice_write
        try:
            admit_voice_write(name, options.temporary_directory, stage, options.profile)
        except ResourceProbeError as error:
            print(error, file=sys.stderr)
            return 2
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
            print('The voice writer could not verify the protected catalog, workspace or remaining capacity.', file=sys.stderr)
            return 2
        return 0
    if options.temporary_directory == PRIVATE_INSTALL_TEMP and options.mode == 'runtime':
        parser.error('private installer workspace cannot relocate runtime audio')
    if options.reserve_install_workspace and options.mode != 'prepare':
        parser.error('--reserve-install-workspace requires --mode prepare')
    if options.prepared_release_review is not None and options.mode != 'install':
        parser.error('--prepared-release-review requires --mode install')
    requested = options.desktop_limit
    phone_requested = options.phone_limit
    stage = 'configuration'
    selection = None
    try:
        stage = 'CPU instruction set'
        cpu_isa = probe_cpu_isa()
        if options.cpu_isa_only:
            print(json.dumps({'schema': 1, 'cpu_isa': cpu_isa, 'errors': []}, sort_keys=True))
            return 0
        stage = 'configuration'
        saved = configured_limits(options.config) if options.config else {}
        profile = options.profile or saved.get('deployment_profile', 'standard')
        if requested is None:
            requested = saved.get('desktop_client_limit', 25)
        if phone_requested is None:
            phone_requested = saved.get('phone_device_limit', PHONE_BASELINE)
        if options.auto_phone_limit and not saved:
            stage = 'internal phone inventory'
            selection = detect_internal_phones()
            phone_requested = rounded_phone_capacity(selection['detected_phone_contacts'], profile)
            selection.update({'source': 'internal_pjsip_inventory', 'rounded_phone_capacity': phone_requested})
        stage = 'CPU and memory'
        cpu, memory = probe_compute()
        stage = 'SLL storage'
        payloads = measure_release_payloads(options.candidate_source) if options.candidate_source else None
        upgrade_proof = (read_prepared_upgrade_storage_proof(options.prepared_release_review, options.candidate_source)
                         if options.prepared_release_review is not None and options.candidate_source is not None else None)
        proof = (read_install_storage_proof(options.prepared_release_review, options.candidate_source)
                 if upgrade_proof is None and options.prepared_release_review is not None and options.candidate_source is not None else None)
        fresh_proof = (read_fresh_release_proof(options.prepared_release_review, options.candidate_source)
                       if upgrade_proof is None and proof is None and options.prepared_release_review is not None
                       and options.candidate_source is not None else None)
        storage_options = ({'previous_release_required': False, 'prepared_release_resident': True}
                           if upgrade_proof is not None or proof is not None else {'previous_release_required': False}
                           if fresh_proof is not None else {})
        if upgrade_proof is not None and upgrade_proof.get('stock_cache') is not None:
            stock = upgrade_proof['stock_cache']
            storage_options['stock_cache_publication_sizes'] = [
                row['bytes'] for name, row in sorted(stock['pending'].items()) if name not in stock['cached']]
        piper_reuse = (probe_prepared_piper_reuse(options.prepared_release_review, options.candidate_source, upgrade_proof)
                       if upgrade_proof is not None else None)
        if (type(piper_reuse) is dict and type(piper_reuse.get('schema')) is int and piper_reuse['schema'] == 1
                and piper_reuse.get('kind') == 'sll-qualified-piper-reuse-v1' and piper_reuse.get('qualified') is True):
            storage_options['qualified_piper_reuse'] = True
        else:
            piper_reuse = None
        if (options.mode == 'install' and options.candidate_source is not None and options.prepared_release_review is not None
                and any(item is not None for item in (upgrade_proof, proof, fresh_proof))):
            storage_options['verify_voice_content'] = True
        if saved.get('speech_optional_voice_packs'): storage_options['optional_packs'] = saved['speech_optional_voice_packs']
        storage = probe_storage(options.mode, payloads, **storage_options)
        stage = 'filesystem free space'
        storage, filesystems = probe_storage_filesystems(storage, options.temporary_directory,
            reserve_install_workspace=options.reserve_install_workspace)
        if upgrade_proof is not None:
            storage['release_storage_proof_canonical_sha256'] = _fresh_digest(upgrade_proof)
            storage['release_storage_proof_kind'] = _UPGRADE_STORAGE_KIND
        elif proof is not None:
            storage['release_storage_proof_canonical_sha256'] = _fresh_digest(proof)
            storage['release_storage_proof_kind'] = _INSTALL_STORAGE_KIND
        elif fresh_proof is not None:
            storage['fresh_release_proof_canonical_sha256'] = _fresh_digest(fresh_proof)
        if piper_reuse is not None:
            storage['piper_reuse_proof_canonical_sha256'] = _fresh_digest(piper_reuse)
        stage = 'runtime audio temporary workspace'
        runtime_scratch = probe_runtime_speech_scratch(profile, saved)
        result = evaluate({'effective_cpu_count': cpu, 'effective_memory_bytes': memory,
                           'cpu_isa': cpu_isa,
                           'memory_limit_bytes': probe_memory_limit(), 'filesystems': filesystems, 'storage': storage,
                           'runtime_speech_scratch':runtime_scratch}, requested, phone_requested, profile)
        if selection is not None:
            result['auto_phone_selection'] = selection
    except (OSError, ValueError, ZeroDivisionError, StopIteration) as error:
        code = error.code if isinstance(error, ResourceProbeError) else 'resource_probe_failed'
        message = str(error) if isinstance(error, ResourceProbeError) else (
            'The ' + stage + ' resource check could not be completed. Check the protected configuration and storage permissions, then run Repair Installation before increasing capacity.')
        result = {'schema': 1, 'deployment_profile': locals().get('profile', options.profile or 'standard'), 'requested_limit': requested, 'eligible_limit': 0, 'hardware': {}, 'requirements': {},
                  'requested_phone_limit': phone_requested, 'eligible_phone_limit': 0,
                  'errors': [{'code': code, 'message': message, 'actual': None, 'required': None}], 'warnings': []}
        print(json.dumps(result, sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 2 if result['errors'] else 0


if __name__ == '__main__':
    sys.exit(main())
