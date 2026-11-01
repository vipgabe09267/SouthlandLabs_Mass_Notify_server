#!/usr/bin/python3
"""Read-only installation idle/history checks while the installer owns worker guards.

Never invokes installed Python/PHP, changes a ledger, clears a reservation, sends
an alert, hangs up a channel, or rewinds live state. The only PBX command is the
fixed read-only Asterisk channel inventory. Worker and paging-slot locks belong
to the installer and must remain held across the before/after inspections.
"""
from __future__ import annotations
import argparse
import fcntl
import importlib.util
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone

# Load the authenticated sibling even in isolated Python or copied installer bootstraps.
sys.dont_write_bytecode = True
_audio_spec = importlib.util.spec_from_file_location('sls_audio_state', Path(__file__).resolve().with_name('sls_audio_state.py'))
_audio_state = importlib.util.module_from_spec(_audio_spec)
_audio_spec.loader.exec_module(_audio_state)

DATA = Path('/var/lib/asterisk/SLS_Mass_Notifications_Plugin')
MODULE = Path('/var/www/html/admin/modules/slsmassnotifyserver/module.xml')
SPOOLS = (Path('/var/spool/asterisk/outgoing'), Path('/var/spool/asterisk/tmp'))
MAX_STATE = 16 * 1024 * 1024
MAX_BASELINE = 4 * 1024 * 1024
MAX_HISTORY = 10000
PHONE_HISTORY_SECONDS = 7 * 86400
MAX_PHONE_TARGETS = 1000
MAX_PHONE_CHANNELS = 4096
TOKEN = re.compile(r'[a-f0-9]{32}')
HASH = re.compile(r'[a-f0-9]{64}')
ACTIVE_SCRIPTS = {'sls_mass_notify_test.sh', 'sls_mass_notify_live_paging.php', 'sls_mass_notify_phone_agi.py'}
ENTERPRISE_SCRIPTS = {'sls_mass_notify_cluster_worker.php', 'sls_mass_notify_cluster_effect.php',
                      'sls_mass_notify_incident_response.php'}

class IdleError(RuntimeError): pass

def bounded_utf8(value, limit):
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode('utf-8')) <= limit
    except UnicodeError:
        return False

def json_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate inspection JSON field')
        value[key] = item
    return value

def json_constant(value):
    raise ValueError('Nonfinite inspection JSON value')

def json_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('Nonfinite inspection JSON number')
    return number


def directory(path, *, protected=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise IdleError('Inspection path must be absolute and canonical')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if protected and (info.st_uid != 0 or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise IdleError('Inspection baseline has an unprotected ancestor')
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0: os.close(fd)


def entries(fd, limit=20000, seconds=2):
    deadline = time.monotonic() + seconds
    with os.scandir(fd) as names:
        for index, entry in enumerate(names):
            if index >= limit or time.monotonic() > deadline:
                raise IdleError('Idle directory inspection exceeded its bounded limit; no state was changed')
            yield entry.name


def read_json(path, limit=MAX_STATE, *, optional=False, protected=False, private=False):
    parent = fd = -1
    try:
        parent = directory(Path(path).parent, protected=protected)
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise IdleError('Inspection state is linked, special, or oversized: ' + Path(path).name)
        account = pwd.getpwnam('asterisk')
        if info.st_uid not in (0, account.pw_uid) or protected and (info.st_uid != 0 or info.st_mode & 0o077):
            raise IdleError('Inspection state ownership or private baseline mode is unsafe: ' + Path(path).name)
        if private and (info.st_gid != account.pw_gid or stat.S_IMODE(info.st_mode) & 0o137):
            raise IdleError('Inspection heartbeat permissions are unsafe: ' + Path(path).name)
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        body = bytearray()
        while len(body) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(body)))
            if not block: break
            body.extend(block)
        after = os.fstat(fd)
        current = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
        def identity(value): return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink
        if len(body) > limit or identity(info) != identity(after) or identity(after) != identity(current):
            raise IdleError('Inspection state changed while being read; retry after the worker becomes idle')
        value = json.loads(body, object_pairs_hook=json_pairs, parse_constant=json_constant, parse_float=json_float)
        if not isinstance(value, dict): raise IdleError('Inspection state is not an object: ' + Path(path).name)
        return value
    except FileNotFoundError:
        if optional: return None
        raise IdleError('Required inspection state is missing: ' + Path(path).name) from None
    except (ValueError, RecursionError, BlockingIOError) as error:
        raise IdleError('Inspection state is corrupt or busy: ' + Path(path).name) from None
    finally:
        if fd >= 0: os.close(fd)
        if parent >= 0: os.close(parent)


def read_collector_json(path, lock_name, limit=MAX_STATE, *, optional=False, private=False):
    """Read under the writer's permanent mutex, rather than the replaced JSON inode."""
    path = Path(path)
    parent = lock = -1
    try:
        try:
            parent = directory(path.parent)
            lock = os.open(lock_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                           dir_fd=parent)
        except FileNotFoundError:
            # Older/fresh state may have no mutex yet. Keep the original
            # bounded identity checks; never create or repair state here.
            return read_json(path, limit, optional=optional, private=private)
        account = pwd.getpwnam('asterisk')
        marker = b'SLS_JSON_V1\n' if lock_name.endswith('.json.lock') else b''
        def valid(info):
            return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid in (0, account.pw_uid) and info.st_gid in (0, account.pw_gid)
                    and stat.S_IMODE(info.st_mode) in (0o600, 0o640, 0o644)
                    and 0 <= info.st_size <= len(marker))
        deadline = time.monotonic() + 2
        while True:
            info = os.fstat(lock)
            if not valid(info):
                raise IdleError('Collector inspection mutex metadata is unsafe: ' + lock_name)
            try:
                fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise IdleError('Collector state is busy; retry inspection after its transaction finishes') from None
                time.sleep(.01)
        opened = os.fstat(lock)
        named = os.stat(lock_name, dir_fd=parent, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                    value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (not valid(opened) or identity(opened) != identity(named)
                or not marker.startswith(os.read(lock, len(marker) + 1))):
            raise IdleError('Collector inspection mutex changed or has invalid contents')
        result = read_json(path, limit, optional=optional, private=private)
        if identity(opened) != identity(os.stat(lock_name, dir_fd=parent, follow_symlinks=False)):
            raise IdleError('Collector inspection mutex changed during the snapshot')
        return result
    finally:
        if lock >= 0:
            os.close(lock)
        if parent >= 0:
            os.close(parent)


def channel_inventory():
    """Bound both output pipes; only this read-only CLI child is stopped on timeout."""
    command = ['/usr/sbin/asterisk', '-rx', 'core show channels concise']
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'}, close_fds=True)
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + 5
    try:
        with selectors.DefaultSelector() as selected:
            for name in output:
                stream = getattr(process, name); os.set_blocking(stream.fileno(), False)
                selected.register(stream, selectors.EVENT_READ, name)
            while selected.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise IdleError('Read-only Asterisk channel inspection timed out')
                for key, event in selected.select(min(remaining, 1)):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selected.unregister(key.fileobj); key.fileobj.close(); continue
                    if len(output[key.data]) + len(data) > 1024 * 1024:
                        raise IdleError('Read-only Asterisk channel inventory exceeded its safe bound')
                    output[key.data].extend(data)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code or output['stderr'].strip(): raise IdleError('Read-only Asterisk channel inspection failed; check local PBX health')
        return bytes(output['stdout']).decode('utf-8', errors='strict')
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
        for stream in (process.stdout, process.stderr):
            if not stream.closed: stream.close()


class IdleCheck:
    def __init__(self, data=DATA, *, module=MODULE, proc=Path('/proc'), spools=SPOOLS,
                 channels=channel_inventory, boot_id=None, monotonic=time.monotonic, clock=time.time, subsystem_paths=None):
        self.data = Path(data); self.module = Path(module); self.proc = Path(proc)
        self.spools = tuple(map(Path, spools)); self.channels = channels
        self.boot_id = boot_id; self.monotonic = monotonic; self.clock = clock
        self.repair_pending = []; self.repair_missing = False
        self.subsystem_paths = tuple(map(Path, subsystem_paths)) if subsystem_paths is not None else (
            self.module.with_name('PhoneEventService.php'),
            Path('/etc/systemd/system/sls-mass-notify-phone-events.service'),
            Path('/usr/local/bin/sls_mass_notify/sls_phone_events.py'))

    def installed(self):
        try:
            parent = directory(self.module.parent)
        except FileNotFoundError: return False
        try:
            try: info = os.stat(self.module.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: return False
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise IdleError('Installed module identity file is unsafe')
            return True
        finally: os.close(parent)

    def phone_subsystem_present(self):
        # Genuine pre-collector releases can upgrade while idle. A partially
        # missing modern subsystem must not disguise an unhealthy collector.
        found = False
        for path in self.subsystem_paths:
            try: parent = directory(path.parent)
            except FileNotFoundError: continue
            try:
                try: info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise IdleError('Phone collector installation marker is unsafe')
                found = True
            finally: os.close(parent)
        return found

    def no_processes(self):
        root = directory(self.proc)
        try:
            for pid in entries(root, 32768, 3):
                if not pid.isdigit() or int(pid) == os.getpid(): continue
                child = fd = -1
                try:
                    child = os.open(pid, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
                    fd = os.open('cmdline', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=child)
                    raw = os.read(fd, 65537)
                    if len(raw) > 65536: raise IdleError('A process command line exceeded the inspection bound')
                    argv = raw.split(b'\0')
                    names = {value.rsplit(b'/', 1)[-1].decode('utf-8', errors='replace') for value in argv}
                    if ACTIVE_SCRIPTS.intersection(names):
                        raise IdleError('A manual weather test, phone AGI, or dial-in page is active; wait for it to finish')
                    if ENTERPRISE_SCRIPTS.intersection(names):
                        raise IdleError('An enterprise worker or response helper is active; stop its external supervisor and wait for cluster, edge, and incident-response work to finish before installation')
                    if 'sls_mass_notify_announcement_worker.php' in names and (
                            b'--supervise' in argv or any(re.fullmatch(rb'job_[a-f0-9]{32}', value) for value in argv)):
                        raise IdleError('An announcement worker or supervisor is active; allow delivery to finish')
                except (FileNotFoundError, ProcessLookupError): pass
                finally:
                    if fd >= 0: os.close(fd)
                    if child >= 0: os.close(child)
        finally: os.close(root)

    def no_pending(self):
        try: parent = directory(self.data / 'announcement-jobs')
        except FileNotFoundError: return
        try:
            if any(re.fullmatch(r'pending_job_[a-f0-9]{32}\.mark', name) for name in entries(parent)):
                raise IdleError('An announcement remains queued or running; allow delivery to finish before installation')
        finally: os.close(parent)

    def no_playback(self):
        for path in self.spools:
            try: fd = directory(path)
            except FileNotFoundError: continue
            try:
                if any(name.lower().startswith(('sls_', 'nws_', 'xweather_')) for name in entries(fd, 5000)):
                    raise IdleError('Notification call files remain in the Asterisk spool; allow them to drain and review stale files separately')
            finally: os.close(fd)
        try:
            with _audio_state.read_audio_state(self.data, nonblocking=True) as state:
                recipients, waiting = state.get('recipients', {}), state.get('waiting', {})
                if not isinstance(recipients, dict) or not isinstance(waiting, dict): raise IdleError('Audio reservation state is malformed')
                times = list(recipients.values())
                for row in waiting.values():
                    if not isinstance(row, dict): raise IdleError('Queued audio reservation state is malformed')
                    times.append(row.get('expires'))
                if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in times):
                    raise IdleError('Audio reservation timestamps are invalid')
                if any(value > self.clock() for value in times):
                    raise IdleError('Audio playback or a queued reservation is active; wait and retry')
        except FileNotFoundError as error:
            # A genuinely fresh installation can have no data directory yet.
            # Never turn a missing file inside an existing/installed tree into
            # an empty journal: that could discard established reservations.
            if self.installed() or self.data.exists() or self.data.is_symlink():
                raise IdleError('Audio reservation inspection state is missing') from error
        except (OSError, RuntimeError) as error:
            if isinstance(error, IdleError):
                raise
            raise IdleError('Audio reservation inspection failed: ' + str(error)) from error
        lines = [line for line in self.channels().splitlines() if line.strip()]
        if any(line.count('!') < 10 for line in lines): raise IdleError('Asterisk returned an unrecognized channel inventory')
        if any(re.search(r'sls[-_]|SLSPhone[:/]|nws[-_]|xweather|SLS_Mass_Notifications_Plugin', line, re.I) for line in lines):
            raise IdleError('A notification channel is active; allow it to finish before installation')

    def pending_voicemail(self, batch):
        # Older collectors did not take the outer worker lease. Refuse a
        # fallback they can still submit before replacing their runtime.
        fallback = batch.get('vm_fallback')
        if fallback is None:
            return False
        if not isinstance(fallback, dict):
            raise IdleError('Phone voicemail history is malformed; preserve it for review')
        sound = fallback.get('sound')
        if sound is None:
            return False
        if not isinstance(sound, str) or not sound:
            raise IdleError('Phone voicemail audio identity is invalid')
        for name in ('expires_at', 'expires_tick'):
            value = fallback.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise IdleError('Phone voicemail expiry cannot be inspected safely')
        if fallback['expires_at'] <= self.clock() or fallback['expires_tick'] <= self.monotonic():
            return False
        targets = fallback.get('targets')
        channels = batch.get('channels')
        failures = batch.get('voicemail_failures', {})
        if not isinstance(targets, dict) or not isinstance(channels, dict) or not isinstance(failures, dict):
            raise IdleError('Phone voicemail targets cannot be inspected safely')
        if (len(targets) > MAX_PHONE_TARGETS or len(failures) > MAX_PHONE_TARGETS
                or len(channels) > MAX_PHONE_CHANNELS):
            raise IdleError('Phone voicemail history exceeds its inspection bounds')
        contacts_by_dial = {}
        contact_count = 0
        for channel_name, channel in channels.items():
            if not isinstance(channel_name, str) or not isinstance(channel, dict):
                raise IdleError('Phone voicemail channel history is malformed')
            if channel.get('kind') != 'contact':
                continue
            dial = channel.get('dial')
            if not bounded_utf8(dial, 2048):
                raise IdleError('Phone voicemail channel contact is malformed')
            contact_count += 1
            if contact_count > MAX_PHONE_CHANNELS:
                raise IdleError('Phone voicemail history exceeds its inspection bounds')
            contacts_by_dial.setdefault(dial, []).append(channel)
        dial_count = 0
        for recipient, row in targets.items():
            if not isinstance(recipient, str) or not recipient or not isinstance(row, dict) or not isinstance(row.get('dials'), list):
                raise IdleError('Phone voicemail target is malformed')
            claimed = row.get('claimed_token')
            if claimed is not None and (not isinstance(claimed, str) or not TOKEN.fullmatch(claimed)):
                raise IdleError('Phone voicemail claim is invalid')
            if claimed is not None or recipient in failures:
                continue
            eligible = True
            for dial in row['dials']:
                dial_count += 1
                if dial_count > MAX_PHONE_CHANNELS:
                    raise IdleError('Phone voicemail history exceeds its inspection bounds')
                if not bounded_utf8(dial, 2048):
                    raise IdleError('Phone voicemail contact is malformed')
                contacts = contacts_by_dial.get(dial, [])
                if (len(contacts) != 1 or contacts[0].get('ended_at') is None
                        or contacts[0].get('answered_at') is not None or contacts[0].get('joined_at') is not None
                        or contacts[0].get('outcome_uncertain')
                        or contacts[0].get('dial_status') not in {'BUSY', 'NOANSWER', 'CANCEL', 'CONGESTION', 'CHANUNAVAIL', 'DONTCALL'}):
                    eligible = False
                    break
            if eligible:
                return True
        return False

    def phone_history(self, installed, repair_collector=False, *, allow_pending_voicemail=False):
        self.repair_pending = []; self.repair_missing = False
        self.closed_phone_times = {}; self.voicemail_sources = set()
        state = read_collector_json(self.data / 'phone-admission.json', 'phone-admission.lock',
                                    optional=not installed or repair_collector)
        if state is None:
            self.repair_missing = installed
            return {}
        batches = state.get('batches')
        if type(state.get('schema')) is not int or state.get('schema') != 1 \
                or not isinstance(batches, dict) or len(batches) > MAX_HISTORY:
            raise IdleError('Phone admission history cannot be inspected safely')
        history = {}
        for token, batch in batches.items():
            if not isinstance(token, str) or not TOKEN.fullmatch(token) or not isinstance(batch, dict):
                raise IdleError('Phone admission has an unclosed or invalid batch; allow it to drain')
            if batch.get('status') != 'closed':
                if batch.get('purpose') == 'voicemail':
                    proof = batch.get('voicemail')
                    source = proof.get('source_token') if isinstance(proof, dict) else None
                    if not isinstance(source, str) or not TOKEN.fullmatch(source):
                        raise IdleError('Phone voicemail source dependency is invalid')
                    self.voicemail_sources.add(hashlib.sha256(source.encode()).hexdigest())
                if not repair_collector or batch.get('status') not in ('active', 'reserved'):
                    raise IdleError('Phone admission has an unclosed or invalid batch; allow it to drain')
                # Independent process, spool, lease and complete channel checks
                # ran first under worker guards. Preserve the journal; require
                # authenticated collector reconciliation before completion.
                self.repair_pending.append(hashlib.sha256(token.encode()).hexdigest())
                continue
            if not allow_pending_voicemail and self.pending_voicemail(batch):
                raise IdleError('A voicemail fallback is pending; allow it to finish or expire and retry installation')
            key = hashlib.sha256(token.encode()).hexdigest()
            history[key] = hashlib.sha256(
                json.dumps(batch, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
            closed = batch.get('closed_at', batch.get('updated_at'))
            if closed is not None:
                if isinstance(closed, bool) or not isinstance(closed, (int, float)) or not math.isfinite(closed) or closed < 0:
                    raise IdleError('Phone closed-history timestamp is invalid')
                self.closed_phone_times[key] = closed
        if installed and not repair_collector:
            health = state.get('collector')
            if self.boot_id is None:
                self.boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            if not isinstance(health, dict) or health.get('boot_id') != self.boot_id or not TOKEN.fullmatch(str(health.get('generation', ''))):
                raise IdleError('Phone collector identity is unavailable; restore collector health before installation')
            anchor_tick = health.get('heartbeat_tick')
            if isinstance(anchor_tick, bool) or not isinstance(anchor_tick, (int, float)) or not math.isfinite(anchor_tick):
                raise IdleError('Phone collector heartbeat anchor is invalid; restore collector health before installation')
            pulse = read_collector_json(self.data / 'phone-collector-heartbeat.json',
                                         'phone-collector-heartbeat.json.lock', 1024, optional=True, private=True)
            if pulse is not None:
                fields = {'schema', 'generation', 'boot_id', 'anchor_tick', 'heartbeat_tick'}
                if set(pulse) != fields or type(pulse.get('schema')) is not int or pulse['schema'] != 1:
                    raise IdleError('Phone collector heartbeat file is invalid; restore collector health before installation')
                pulse_anchor = pulse.get('anchor_tick')
                if (not isinstance(pulse_anchor, bool) and isinstance(pulse_anchor, (int, float))
                        and math.isfinite(pulse_anchor) and pulse_anchor == anchor_tick
                        and pulse.get('generation') == health['generation'] and pulse.get('boot_id') == self.boot_id):
                    health = pulse
            tick = health.get('heartbeat_tick')
            if isinstance(tick, bool) or not isinstance(tick, (int, float)) or not math.isfinite(tick) or not 0 <= self.monotonic() - tick <= 15:
                raise IdleError('Phone collector heartbeat is stale or invalid; restore collector health before installation')
        return history

    def retirement_times(self, before, known, missing, evidence):
        """Use protected baseline facts, or hash-bound old records, never live guesses."""
        policy = before.get('phone_history_retention')
        times = {}
        if policy is not None:
            if (not isinstance(policy, dict) or set(policy) != {'schema', 'seconds', 'closed_at'}
                    or type(policy.get('schema')) is not int or policy['schema'] != 1
                    or type(policy.get('seconds')) is not int or policy['seconds'] != PHONE_HISTORY_SECONDS
                    or not isinstance(policy.get('closed_at'), dict) or set(policy['closed_at']) - set(known)
                    or any(isinstance(value, bool) or not isinstance(value, (int, float))
                           or not math.isfinite(value) or value < 0 for value in policy['closed_at'].values())):
                raise IdleError('Installation phone-retention baseline is invalid')
            times.update(policy['closed_at'])
        if evidence is not None:
            saved = evidence if isinstance(evidence, dict) else read_json(Path(evidence), MAX_STATE, protected=True)
            if (type(saved.get('schema')) is not int or saved['schema'] != 1
                    or not isinstance(saved.get('batches'), dict) or len(saved['batches']) > MAX_HISTORY):
                raise IdleError('Protected phone-history evidence is invalid')
            for token, batch in saved['batches'].items():
                if not isinstance(token, str) or not TOKEN.fullmatch(token) or not isinstance(batch, dict):
                    raise IdleError('Protected phone-history evidence contains an invalid batch')
                key = hashlib.sha256(token.encode()).hexdigest()
                if key not in missing:
                    continue
                digest = hashlib.sha256(json.dumps(batch, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
                if batch.get('status') != 'closed' or digest != known[key]:
                    raise IdleError('Protected phone-history evidence does not match the original baseline')
                closed = batch.get('closed_at', batch.get('updated_at'))
                if (isinstance(closed, bool) or not isinstance(closed, (int, float))
                        or not math.isfinite(closed) or closed < 0):
                    raise IdleError('Protected phone-history evidence has an invalid closed timestamp')
                if key in times and times[key] != closed:
                    raise IdleError('Phone-history evidence conflicts with the protected retention baseline')
                times[key] = closed
        return times

    def inspect(self, baseline=None, repair_collector=False, *, history_evidence=None):
        if history_evidence is not None and baseline is None:
            raise IdleError('Phone-history evidence requires the original protected installation baseline')
        self.no_processes(); self.no_pending(); self.no_playback()
        installed = self.installed()
        collector_required = installed and self.phone_subsystem_present()
        history = self.phone_history(collector_required, repair_collector)
        retired = 0
        if baseline is not None:
            before, known = history_baseline(baseline)
            if any(key in history and history[key] != value for key, value in known.items()):
                raise IdleError('Retained closed phone history changed or disappeared; preserve recovery evidence and never restore an old live ledger')
            missing = set(known) - set(history)
            times = self.retirement_times(before, known, missing, history_evidence)
            now = self.clock()
            if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now) or now < 0:
                raise IdleError('Phone-retention verification clock is invalid')
            for key in missing:
                if key not in times:
                    raise IdleError('Closed phone history is missing without retention evidence; preserve the original baseline and supply a protected pre-upgrade ledger copy for verification, never restore it over live state')
                if key in self.voicemail_sources or not times[key] < now - PHONE_HISTORY_SECONDS:
                    raise IdleError('Retained closed phone history changed or disappeared before expiry or while required for voicemail; preserve recovery evidence and never restore an old live ledger')
                retired += 1
            pending = before.get('pending_phone_reconciliation', [])
            if not isinstance(pending, list) or len(pending) > MAX_HISTORY or any(not isinstance(key, str) or not HASH.fullmatch(key) for key in pending):
                raise IdleError('Collector repair baseline is invalid')
            if not repair_collector and any(key not in history for key in pending):
                raise IdleError('Collector repair has not closed its independently idle batches; preserve the journal and inspect collector health')
        return {'schema': 1, 'ok': True, 'checked_at': datetime.now(timezone.utc).isoformat(), 'installed': installed,
                'phone_collector_required': collector_required, 'closed_phone_batches': len(history), 'phone_history': history,
                'phone_history_retention': {'schema': 1, 'seconds': PHONE_HISTORY_SECONDS, 'closed_at': self.closed_phone_times},
                'retired_phone_batches': retired,
                'pending_phone_reconciliation': self.repair_pending, 'missing_phone_ledger': self.repair_missing,
                'manual_test_active': False, 'notification_playback_active': False, 'pending_announcements': False}


def history_baseline(path):
    before = read_json(Path(path), MAX_BASELINE, protected=True)
    known = before.get('phone_history')
    if (type(before.get('schema')) is not int or before.get('schema') != 1
            or before.get('ok') is not True or not isinstance(known, dict)
            or len(known) > MAX_HISTORY or type(before.get('closed_phone_batches')) is not int
            or before.get('closed_phone_batches') != len(known)
            or any(not isinstance(key, str) or not HASH.fullmatch(key) or not isinstance(value, str)
                   or not HASH.fullmatch(value) for key, value in known.items())):
        raise IdleError('Installation phone-history baseline is invalid')
    return before, known


def retain_history_evidence(baseline, source, destination):
    """Accumulate only original hash-matching closed rows from protected backups."""
    before, known = history_baseline(baseline)
    proof = read_json(Path(source), MAX_STATE, protected=True)

    def proven_rows(value):
        if (type(value.get('schema')) is not int or value['schema'] != 1
                or not isinstance(value.get('batches'), dict) or len(value['batches']) > MAX_HISTORY):
            raise IdleError('Protected phone-history evidence is invalid')
        matched = {}
        for token, batch in value['batches'].items():
            if not isinstance(token, str) or not TOKEN.fullmatch(token) or not isinstance(batch, dict):
                raise IdleError('Protected phone-history evidence contains an invalid batch')
            key = hashlib.sha256(token.encode()).hexdigest()
            if key not in known or batch.get('status') != 'closed':
                continue
            digest = hashlib.sha256(json.dumps(batch, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
            if digest == known[key]:
                matched[token] = batch
        facts = {'schema': 1, 'batches': matched}
        # This also checks timestamp types and any richer protected baseline.
        # A backup can predate closure of unrelated, still-retained batches.
        IdleCheck(DATA).retirement_times(before, known, set(known), facts)
        return matched

    matched = proven_rows(proof)
    if known and not matched:
        raise IdleError('Protected phone-history evidence does not match the original baseline')
    destination = Path(destination)
    parent = directory(destination.parent, protected=True)
    temporary = '.history-evidence-' + os.urandom(12).hex()
    try:
        if stat.S_IMODE(os.fstat(parent).st_mode) != 0o700:
            raise IdleError('Retained phone-history evidence requires a root-private transaction directory')
        existing = read_json(destination, MAX_STATE, protected=True, optional=True)
        if existing is not None:
            retained = proven_rows(existing)
            if set(existing) != {'schema', 'batches'} or existing['batches'] != retained:
                raise IdleError('Retained recovery evidence contains unverified data; preserve it for review')
            for token, batch in retained.items():
                if token in matched and matched[token] != batch:
                    raise IdleError('Retained recovery evidence conflicts with another original record')
            merged = {**retained, **matched}
            if merged == retained:
                return
        else:
            merged = matched
        body = (json.dumps({'schema': 1, 'batches': merged}, sort_keys=True,
                           separators=(',', ':'), allow_nan=False) + '\n').encode()
        if len(body) > MAX_STATE:
            raise IdleError('Protected phone-history evidence exceeds its size bound')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        # The installer holds both root transaction coordination locks. Only
        # root can access this directory. New backups can add verified rows;
        # every previously retained row remains identical. Neither the original
        # baseline, the source backup nor the live ledger is written here.
        os.rename(temporary, destination.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=DATA)
    parser.add_argument('action', choices=('inspect', 'retain-history-evidence'))
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--history-evidence', type=Path, help='Root-private pre-upgrade ledger evidence; verified against original hashes and never restored')
    parser.add_argument('--retained-history-evidence', type=Path)
    parser.add_argument('--repair-collector', action='store_true', help='Inspect independent idleness for collector recovery without changing its journal')
    args = parser.parse_args()
    if os.geteuid() != 0: raise IdleError('Complete installation idle inspection requires root visibility')
    if args.action == 'retain-history-evidence':
        if args.baseline is None or args.history_evidence is None or args.retained_history_evidence is None or args.repair_collector:
            parser.error('Retaining evidence requires --baseline, --history-evidence and --retained-history-evidence')
        retain_history_evidence(args.baseline, args.history_evidence, args.retained_history_evidence)
        print(json.dumps({'ok': True, 'protected_history_evidence_retained': True}))
    else:
        if args.retained_history_evidence is not None:
            parser.error('--retained-history-evidence requires retain-history-evidence')
        print(json.dumps(IdleCheck(args.data).inspect(args.baseline, args.repair_collector, history_evidence=args.history_evidence), sort_keys=True))

if __name__ == '__main__':
    try: main()
    except (IdleError, OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        print('SLL installation idle check failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
