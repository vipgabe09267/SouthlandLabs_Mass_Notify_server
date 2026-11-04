#!/usr/bin/python3
"""Durable, root-only installer evidence; never authorizes observed live bytes."""
from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import shutil
import sys
import tarfile
import time
import types

sys.dont_write_bytecode = True
ROOT = Path('/var/lib/sls-mass-notify-installer')
FIELDS = ('RECOVERY_DIR', 'INSTALL_BOOTSTRAP_DIR', 'UPGRADE_TRUST_DIR',
          'CONFIG_SNAPSHOT', 'CONFIG_HASH_BEFORE', 'PENDING_CONFIG_STATE',
          'PENDING_CONFIG_PATH', 'PENDING_CONFIG_SNAPSHOT', 'PENDING_CONFIG_HASH',
          'MODULE_BACKUP_DIR', 'STAGING_DIR', 'HAD_EXISTING_MODULE',
          'MODULE_WAS_ENABLED', 'MODULE_ACTIVATED', 'STATIC_MUTATION_STARTED',
          'ORIGINAL_SYSTEM_TIMEZONE', 'SYSTEM_TIMEZONE_CHANGED')
TERMINAL = {'committed', 'rolled_back', 'abandoned'}
PHASES = {'preparing', 'prepared', 'mutating', 'recovering', 'recovery_failed'} | TERMINAL
STAGES = {'initialization', 'hardware admission', 'platform validation', 'release download and validation',
          'publisher and stock approval', 'FreePBX ownership protection',
          'legacy configuration and runtime permissions', 'authenticated prerequisite validation',
          'previous phone collector recovery', 'notification worker coordination',
          'configuration coordination', 'dependency installation', 'timezone validation',
          'protected runtime preparation', 'module activation', 'runtime integration',
          'post-install verification', 'interrupted installation recovery'}
NAME = re.compile(r'transaction-[0-9a-f]{24}\Z')
LIMIT = 65536
HISTORY_LIMIT = 4 * 1024 * 1024
HISTORY_CLASSIFICATION = 'administrator_accepted_unverified_history_loss'
HISTORY_REVIEW = 'history-loss-review.json'
HISTORY_APPROVAL = 'history-loss-approval.json'
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
BOOTSTRAP_FILES = {
    'sls_module_trust.py', 'sls_release_trust.py', 'sls_privileged_install.py',
    'sls_installer_recovery.py', 'sls_install_transaction.py',
    'sls_install_idle.py', 'sls_install_guard.py', 'sls_audio_state.py',
    'sls_config_crypto.py', 'sls_upgrade_trust.py',
    'sls_legacy_permissions.py', 'freepbx-mirror-signing.pub',
}


class TransactionError(RuntimeError):
    pass


def decode_json(body):
    """Decode one unambiguous, finite JSON document from private evidence."""
    def object_pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise TransactionError('Duplicate installer transaction metadata member')
            value[key] = item
        return value

    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            raise TransactionError('Nonfinite installer transaction metadata number')
        return value

    def invalid_constant(_text):
        raise TransactionError('Nonfinite installer transaction metadata number')

    try:
        return json.loads(body, object_pairs_hook=object_pairs,
                          parse_float=finite_float, parse_constant=invalid_constant)
    except (RecursionError, UnicodeDecodeError) as error:
        raise TransactionError('Invalid installer transaction metadata encoding') from error


def directory(path):
    """Inspect every component by descriptor; writable ancestors are rejected."""
    path = Path(path)
    if not path.is_absolute() or any(part in ('.', '..') for part in path.parts):
        raise TransactionError('Invalid installer evidence path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            # /tmp is permitted only for disposable tests, never the default root.
            if info.st_uid != 0 or info.st_mode & 0o022 and not (part == 'tmp' and info.st_mode & stat.S_ISVTX):
                raise TransactionError('Installer evidence has an unprotected parent: ' + str(path))
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, bound=LIMIT, *, private=True):
    parent = directory(Path(path).parent)
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != 0 or before.st_mode & (0o077 if private else 0o022) or before.st_size > bound:
                raise TransactionError('Unsafe installer evidence file: ' + str(path))
            body = bytearray()
            while len(body) <= bound:
                block = os.read(fd, min(65536, bound + 1 - len(body)))
                if not block: break
                body.extend(block)
            after = os.fstat(fd)
            if len(body) != before.st_size or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise TransactionError('Installer evidence changed during inspection')
            return bytes(body)
        finally: os.close(fd)
    finally: os.close(parent)


def atomic(path, value, bound=LIMIT):
    body = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(body) > bound: raise TransactionError('Installer transaction metadata exceeds its bound')
    parent = directory(path.parent)
    temporary = '.new-' + os.urandom(12).hex()
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as output:
            output.write(body); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try: os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError: pass
        os.close(parent)


def sync_recovery_inputs(transaction, recovery, config_snapshot='', pending_snapshot=''):
    """Flush protected rollback inputs before a journal may authorize mutation."""
    transaction = Path(transaction)
    parent = directory(transaction)
    handles = []; recovery_fd = -1
    try:
        info = os.fstat(parent)
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise TransactionError('Recovery input directory must remain root-private')
        inputs = []
        for value, name in ((config_snapshot, 'config.snapshot'), (pending_snapshot, 'pending.snapshot')):
            if value:
                if Path(value) != transaction / name:
                    raise TransactionError('Configuration recovery input is outside its transaction')
                inputs.append((parent, name, 16 * 1024 * 1024, False))
        if recovery:
            recovery = Path(recovery)
            if recovery.parent != transaction or not re.fullmatch(r'sls-mass-notify-recovery\.[A-Za-z0-9]{6}', recovery.name):
                raise TransactionError('Operational recovery input is outside its transaction')
            recovery_fd = directory(recovery)
            if stat.S_IMODE(os.fstat(recovery_fd).st_mode) != 0o700:
                raise TransactionError('Operational recovery input directory must remain root-private')
            # A complete allowed phone baseline can contain 10,000 record
            # hashes plus closure times. Match the idle reader's 4 MiB bound;
            # scoped native registration retains its separate 1 MiB limit.
            inputs.append((recovery_fd, 'idle-before.json', HISTORY_LIMIT, True))
            inputs.append((recovery_fd, 'module-registration.json', 1048576, True))
            try:
                os.stat('history-evidence.json', dir_fd=recovery_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass  # Older transactions can legitimately have hash-only evidence.
            else:
                inputs.append((recovery_fd, 'history-evidence.json', 16 * 1024 * 1024, True))
        def identity(meta):
            return (meta.st_dev, meta.st_ino, meta.st_uid, meta.st_gid, meta.st_mode,
                    meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)
        for location, name, bound, document in inputs:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=location)
            handles.append(fd); before = os.fstat(fd)
            named = os.stat(name, dir_fd=location, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= bound
                    or identity(before) != identity(named)):
                raise TransactionError('Unsafe or missing durable recovery input: ' + name)
            body = bytearray()
            while len(body) <= bound:
                block = os.read(fd, min(65536, bound + 1 - len(body)))
                if not block: break
                body.extend(block)
            if len(body) != before.st_size or document and not isinstance(decode_json(body), dict):
                raise TransactionError('Invalid durable recovery input: ' + name)
            if identity(os.fstat(fd)) != identity(before):
                raise TransactionError('Recovery input changed during durable inspection: ' + name)
            os.fsync(fd)
            if (identity(os.fstat(fd)) != identity(before)
                    or identity(os.stat(name, dir_fd=location, follow_symlinks=False)) != identity(before)):
                raise TransactionError('Recovery input changed during storage synchronization: ' + name)
        if recovery_fd >= 0:
            os.fsync(recovery_fd)
        os.fsync(parent)
    finally:
        for fd in handles: os.close(fd)
        if recovery_fd >= 0: os.close(recovery_fd)
        os.close(parent)


def configuration_intents(recovery, original_hash):
    """Read only hashes durably recorded before an installer settings write."""
    if not re.fullmatch(r'[0-9a-f]{64}', original_hash):
        raise TransactionError('Invalid original configuration hash')
    path = Path(recovery) / 'configuration-intents.json'
    try:
        value = decode_json(read(path))
    except FileNotFoundError:
        return {'schema': 1, 'original_sha256': original_hash, 'writes': []}
    if (type(value) is not dict or set(value) != {'schema', 'original_sha256', 'writes'}
            or type(value.get('schema')) is not int or value['schema'] != 1
            or value.get('original_sha256') != original_hash
            or type(value.get('writes')) is not list or len(value['writes']) > 8):
        raise TransactionError('Invalid protected configuration write intentions')
    previous = original_hash
    for item in value['writes']:
        if (type(item) is not dict or set(item) != {'before_sha256', 'after_sha256'}
                or item.get('before_sha256') != previous
                or not isinstance(item.get('after_sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', item['after_sha256'])):
            raise TransactionError('Broken protected configuration write intention chain')
        previous = item['after_sha256']
    return value


def record_configuration_intent(recovery, original_hash, before, after):
    """Publish and fsync the expected bytes before replacing central settings."""
    value = configuration_intents(recovery, original_hash)
    previous = value['writes'][-1]['after_sha256'] if value['writes'] else original_hash
    before_hash, after_hash = (hashlib.sha256(body).hexdigest() for body in (before, after))
    if previous != before_hash or len(value['writes']) >= 8:
        raise TransactionError('Configuration no longer matches this installer write transaction')
    configuration_image(Path(recovery), 'configuration-intent-', after)
    value['writes'].append({'before_sha256': before_hash, 'after_sha256': after_hash})
    atomic(Path(recovery) / 'configuration-intents.json', value)


def assert_configuration_recoverable(recovery, original_hash, current_hash,
                                     pending_state, pending_hash, current_pending_hash):
    if original_hash:
        value = configuration_intents(recovery, original_hash)
        approved = {original_hash, 'absent'} | {item['after_sha256'] for item in value['writes']}
        if current_hash not in approved:
            raise TransactionError('Central settings changed after the failed installation; preserve the live configuration and original snapshot for review')
    if pending_state == 'present':
        if (not re.fullmatch(r'[0-9a-f]{64}', pending_hash)
                or current_pending_hash not in (pending_hash, 'absent')):
            raise TransactionError('Pending settings changed after the failed installation; preserve both versions for review')
    elif pending_state == 'absent' and current_pending_hash != 'absent':
        raise TransactionError('New pending settings appeared after the failed installation; preserve them for review')


def configuration_image(recovery, prefix, body):
    """Publish exact root-private ciphertext before its authorizing journal."""
    if prefix not in ('configuration-intent-', 'configuration-mfa-') or not isinstance(body, bytes) or not 0 < len(body) <= 16 * 1024 * 1024:
        raise TransactionError('Invalid configuration recovery image')
    name = prefix + hashlib.sha256(body).hexdigest() + '.snapshot'
    parent = directory(recovery)
    temporary = None; descriptor = -1
    try:
        if stat.S_IMODE(os.fstat(parent).st_mode) != 0o700:
            raise TransactionError('Configuration recovery directory is not root-private')
        try: existing = read(recovery / name, 16 * 1024 * 1024)
        except FileNotFoundError: existing = None
        if existing is None:
            temporary = '.configuration-image-' + os.urandom(12).hex()
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            view = memoryview(body)
            while view:
                written = os.write(descriptor, view)
                if written <= 0: raise TransactionError('Incomplete configuration recovery image')
                view = view[written:]
            os.fsync(descriptor)
            if read(recovery / temporary, 16 * 1024 * 1024) != body:
                raise TransactionError('Configuration staging image changed')
            libc = ctypes.CDLL(None, use_errno=True)
            rename = libc.renameat2
            rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            rename.restype = ctypes.c_int
            if rename(parent, temporary.encode(), parent, name.encode(), 1):
                number = ctypes.get_errno()
                if number != errno.EEXIST:
                    raise OSError(number, 'Atomic configuration image publication failed')
            else:
                temporary = None
        if read(recovery / name, 16 * 1024 * 1024) != body:
            raise TransactionError('Configuration recovery image conflicts with retained evidence')
        published = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try: os.fsync(published)
        finally: os.close(published)
        os.fsync(parent)
    finally:
        try:
            if temporary is not None and descriptor >= 0:
                try:
                    staged = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
                    opened = os.fstat(descriptor)
                    if (staged.st_dev, staged.st_ino) != (opened.st_dev, opened.st_ino):
                        raise TransactionError('Configuration staging identity changed; preserve evidence')
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError: pass
        finally:
            if descriptor >= 0: os.close(descriptor)
            os.close(parent)
    return recovery / name


def configuration_canonical(value):
    # JSON equality is type-sensitive: Python considers True == 1 == 1.0.
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def configuration_revisions(settings):
    value = settings.get('immediate_config_revisions', {})
    if value == []: value = {}  # PHP encodes an empty revision map as [].
    if (type(value) is not dict or len(value) > 256 or any(
            not isinstance(key, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,79}', key)
            or key == 'immediate_config_revisions' or type(revision) is not int
            or not 0 <= revision <= 2 ** 63 - 2 for key, revision in value.items())):
        raise TransactionError('Invalid immediate configuration revisions')
    return value


def configuration_mfa_delta(before, after, *, require_progress=True):
    """Permit only counter consumption for otherwise identical enrolled logins."""
    left, right = copy.deepcopy(before), copy.deepcopy(after)
    if type(left) is not dict or type(right) is not dict:
        raise TransactionError('Invalid protected settings object')
    old_revisions, new_revisions = configuration_revisions(left), configuration_revisions(right)
    left.pop('immediate_config_revisions', None); right.pop('immediate_config_revisions', None)
    a, b = left.get('operator_access'), right.get('operator_access')
    if type(a) is not dict or type(b) is not dict or type(a.get('accounts')) is not list or type(b.get('accounts')) is not list or len(a['accounts']) != len(b['accounts']) or len(a['accounts']) > 100:
        raise TransactionError('Operator accounts changed during configuration recovery')
    counters = {}; progressed = False; identities = set()
    for old, new in zip(a['accounts'], b['accounts']):
        if type(old) is not dict or type(new) is not dict or not isinstance(old.get('id'), str) or not old['id'] or old['id'] in identities or old.get('id') != new.get('id'):
            raise TransactionError('Operator account identity or order changed')
        identities.add(old['id'])
        old_auth, new_auth = old.get('auth'), new.get('auth')
        if type(old_auth) is not dict or type(new_auth) is not dict:
            continue  # Unchanged non-portal account data is compared below.
        if 'totp_last_counter' not in old_auth and 'totp_last_counter' not in new_auth:
            continue
        previous, current = old_auth.get('totp_last_counter'), new_auth.get('totp_last_counter')
        if type(previous) is not int or type(current) is not int or not -1 <= previous <= current <= 2 ** 63 - 2:
            raise TransactionError('MFA consumption counters are invalid or decreased')
        if current > previous:
            secret = old_auth.get('totp_secret_enc')
            if a.get('portal_enabled') is not True or old.get('source') != 'portal' or old.get('enabled') is not True or not isinstance(secret, str) or not re.fullmatch(r'op1:[A-Za-z0-9+/]{80}', secret):
                raise TransactionError('MFA consumption is not bound to an enrolled enabled portal account')
            progressed = True
        counters[old['id']] = current
        new_auth['totp_last_counter'] = previous
    old_other, new_other = dict(old_revisions), dict(new_revisions)
    old_revision, new_revision = old_other.pop('operator_access', 0), new_other.pop('operator_access', 0)
    if (configuration_canonical(left) != configuration_canonical(right)
            or configuration_canonical(old_other) != configuration_canonical(new_other)
            or (new_revision <= old_revision if progressed else configuration_canonical(old_revisions) != configuration_canonical(new_revisions))
            or require_progress and not progressed):
        raise TransactionError('Settings changed beyond monotonic MFA consumption and its associated revision')
    return {'counters': counters, 'revision': new_revision}


def configuration_mfa_join(settings, states):
    result = copy.deepcopy(settings)
    for account in result['operator_access']['accounts']:
        auth = account.get('auth')
        if type(auth) is dict and 'totp_last_counter' in auth:
            auth['totp_last_counter'] = max([auth['totp_last_counter']] + [state['counters'].get(account['id'], auth['totp_last_counter']) for state in states])
    revisions = dict(configuration_revisions(result))
    revisions['operator_access'] = max([revisions.get('operator_access', 0)] + [state['revision'] for state in states])
    result['immediate_config_revisions'] = revisions
    return result


def prepare_configuration_recovery(recovery, original_hash, active_snapshot, active_path,
                                   pending_state, pending_hash, pending_snapshot, pending_path):
    """Derive durable rollback bytes without changing original transaction evidence.

    Caller holds the existing central-settings mutex and has passed history
    recovery admission. No observed hash becomes blanket recovery authority.
    """
    try:
        return _prepare_configuration_recovery(Path(recovery), original_hash, active_snapshot, active_path,
                                               pending_state, pending_hash, pending_snapshot, pending_path)
    except TransactionError:
        raise
    except Exception as error:
        raise TransactionError('Protected MFA configuration recovery could not be proved; preserve all settings and evidence') from error


def _prepare_configuration_recovery(recovery, original_hash, active_snapshot, active_path,
                                    pending_state, pending_hash, pending_snapshot, pending_path):
    active_path = Path(active_path)
    if (active_path.parent / '.sls-immediate-settings-transaction.json').exists() or (active_path.parent / '.sls-immediate-settings-transaction.json').is_symlink():
        raise TransactionError('An unresolved immediate-settings transaction requires coordinated recovery')
    crypto_path = Path(__file__).with_name('sls_config_crypto.py')
    crypto = None
    def decoder():
        nonlocal crypto
        if crypto is None:
            crypto = types.ModuleType('sll_recovery_config_crypto'); crypto.__file__ = str(crypto_path)
            exec(compile(crypto_path.read_bytes(), str(crypto_path), 'exec'), crypto.__dict__)
        return crypto
    def live(path):
        if not path.exists() and not path.is_symlink(): return None
        return decoder()._read_protected(path, 16 * 1024 * 1024)
    def digest(body): return hashlib.sha256(body).hexdigest() if body is not None else 'absent'
    if pending_state == '':
        # Preparation can stop before a pending snapshot exists. It grants no
        # semantic merge authority and must retain the original strict check.
        active = live(active_path)
        assert_configuration_recoverable(recovery, original_hash, digest(active), '', '', 'absent')
        if original_hash and digest(read(Path(active_snapshot), 16 * 1024 * 1024)) != original_hash:
            raise TransactionError('Original active configuration snapshot changed')
        return {'active_snapshot': str(active_snapshot), 'active_sha256': original_hash or 'absent',
                'pending_snapshot': '', 'pending_sha256': 'absent'}
    pending_path = Path(pending_path)
    if active_path.parent != pending_path.parent:
        raise TransactionError('Pending configuration does not share the protected settings directory')
    active, pending = live(active_path), live(pending_path)
    if pending_state not in ('present', 'absent') or pending_state == 'absent' and pending is not None:
        raise TransactionError('Pending configuration appeared or disappeared after the failed installation')
    fallback = {'active_snapshot': str(active_snapshot), 'active_sha256': original_hash or 'absent',
                'pending_snapshot': str(pending_snapshot), 'pending_sha256': pending_hash if pending_state == 'present' else 'absent'}
    intents = configuration_intents(recovery, original_hash) if original_hash else {'writes': []}
    approved = {original_hash, 'absent'} | {item['after_sha256'] for item in intents['writes']}
    journal_path = recovery / 'configuration-mfa-recovery.json'
    saved = None
    if journal_path.exists() or journal_path.is_symlink():
        saved = decode_json(read(journal_path))
        expected = {'schema', 'recovery', 'original_sha256', 'pending_state', 'pending_original_sha256', 'active', 'pending'}
        if type(saved) is not dict or set(saved) != expected or type(saved['schema']) is not int or saved['schema'] != 1 or saved['recovery'] != str(recovery) or saved['original_sha256'] != original_hash or saved['pending_state'] != pending_state or saved['pending_original_sha256'] != pending_hash:
            raise TransactionError('MFA recovery evidence is not bound to this transaction')
    original = read(Path(active_snapshot), 16 * 1024 * 1024) if original_hash else None
    if original_hash and digest(original) != original_hash:
        raise TransactionError('Original active configuration snapshot changed')
    original_pending = read(Path(pending_snapshot), 16 * 1024 * 1024) if pending_state == 'present' else None
    if original_pending is not None and digest(original_pending) != pending_hash:
        raise TransactionError('Original pending configuration snapshot changed')
    # A fresh installation can create active settings after recording prior
    # absence. With no original snapshot there is no active rollback authority:
    # preserve those live bytes without treating their hash as approved data.
    unchanged_or_no_active_authority = (digest(active) in approved
                                       or not original_hash and not active_snapshot)
    if not saved and unchanged_or_no_active_authority and (digest(pending) == fallback['pending_sha256'] or pending_state == 'present' and pending is None):
        return fallback
    if pending_state == 'present' and pending is None:
        raise TransactionError('Missing pending settings cannot supply a provable paired MFA update')
    if not original_hash:
        raise TransactionError('MFA recovery lacks an authenticated original configuration')
    base = decoder().decode_config(original)
    staged = decoder().decode_config(original_pending) if original_pending is not None else None
    if staged is not None and configuration_canonical(staged.get('operator_access')) != configuration_canonical(base.get('operator_access')):
        raise TransactionError('Staged operator policy differs from active policy; automatic MFA recovery is not applicable')
    states = []; stored = {}; known_active = set(approved); known_pending = {pending_hash, 'absent'}
    if saved:
        for label, before in [('active', base), ('pending', staged)]:
            item = saved[label]
            if before is None:
                if item is not None: raise TransactionError('Unexpected pending MFA recovery target')
                continue
            if type(item) is not dict or set(item) != {'snapshot', 'sha256'} or not isinstance(item['sha256'], str) or not SHA256.fullmatch(item['sha256']) or item['snapshot'] != 'configuration-mfa-' + item['sha256'] + '.snapshot':
                raise TransactionError('Invalid MFA recovery target identity')
            raw = read(recovery / item['snapshot'], 16 * 1024 * 1024)
            if digest(raw) != item['sha256']: raise TransactionError('MFA recovery target changed')
            decoded = decoder().decode_config(raw)
            states.append(configuration_mfa_delta(before, decoded)); stored[label] = (raw, decoded)
            (known_active if label == 'active' else known_pending).add(item['sha256'])
        if staged is not None and (configuration_canonical(stored['active'][1]['operator_access']) != configuration_canonical(stored['pending'][1]['operator_access']) or configuration_revisions(stored['active'][1]).get('operator_access') != configuration_revisions(stored['pending'][1]).get('operator_access')):
            raise TransactionError('Paired MFA recovery targets disagree')
    candidates = [original]
    for item in intents['writes']:
        path = recovery / ('configuration-intent-' + item['after_sha256'] + '.snapshot')
        if path.exists() or path.is_symlink():
            raw = read(path, 16 * 1024 * 1024)
            if digest(raw) != item['after_sha256']: raise TransactionError('Approved configuration afterimage changed')
            candidates.append(raw)
    current = {}; prior_states = list(states)
    for label, raw, before, known, options in [('active', active, base, known_active, candidates), ('pending', pending, staged, known_pending, [original_pending])]:
        if raw is None:
            if label == 'pending' and staged is None or label == 'active' and digest(raw) in known: continue
            raise TransactionError('Configuration vanished during MFA recovery')
        decoded = decoder().decode_config(raw); current[label] = (raw, decoded)
        if digest(raw) in known:
            # Known before/after states may survive a crash between two restores.
            continue
        matched = None
        for option in options:
            try:
                candidate = decoder().decode_config(option)
                if configuration_canonical(candidate.get('operator_access')) != configuration_canonical(base.get('operator_access')):
                    raise TransactionError('Approved installer settings changed operator authentication')
                candidate = configuration_mfa_join(candidate, prior_states) if prior_states else candidate
                # A crash can leave the exact approved installer semantics
                # plus the already-durable MFA cursor, before target restore.
                matched = configuration_mfa_delta(candidate, decoded, require_progress=not bool(prior_states))
                break
            except TransactionError:
                continue
        if matched is None:
            raise TransactionError('Live settings differ beyond provable monotonic MFA consumption')
        states.append(matched)
    if not states:
        raise TransactionError('Configuration changes lack MFA consumption evidence')
    if staged is not None and ('active' not in current or 'pending' not in current or configuration_canonical(current['active'][1]['operator_access']) != configuration_canonical(current['pending'][1]['operator_access']) or configuration_revisions(current['active'][1]).get('operator_access') != configuration_revisions(current['pending'][1]).get('operator_access')):
        if not saved or digest(active) not in known_active or digest(pending) not in known_pending:
            raise TransactionError('Active and pending MFA consumption are not a consistent commit')
    targets = {}; result = {}
    for label, before in [('active', base), ('pending', staged)]:
        if before is None:
            targets[label] = None; result[label + '_snapshot'] = ''; result[label + '_sha256'] = 'absent'; continue
        settings = configuration_mfa_join(before, states)
        raw = next((body for body, decoded in list(current.values()) + list(stored.values()) if configuration_canonical(decoded) == configuration_canonical(settings)), None)
        if raw is None: raw = decoder().encode_config(settings)
        path = configuration_image(recovery, 'configuration-mfa-', raw)
        targets[label] = {'snapshot': path.name, 'sha256': digest(raw)}
        result[label + '_snapshot'] = str(path); result[label + '_sha256'] = digest(raw)
    atomic(journal_path, {'schema': 1, 'recovery': str(recovery), 'original_sha256': original_hash,
                         'pending_state': pending_state, 'pending_original_sha256': pending_hash,
                         'active': targets['active'], 'pending': targets['pending']})
    return result


def state(path):
    if not NAME.fullmatch(path.name): raise TransactionError('Invalid installer transaction identity')
    try:
        value = decode_json(read(path / 'transaction.json'))
    except FileNotFoundError:
        handle = directory(path)
        try:
            info = os.fstat(handle)
            if stat.S_IMODE(info.st_mode) != 0o700 or os.listdir(handle):
                raise TransactionError('Missing transaction metadata has nonempty or unsafe evidence; preserve it for review')
            created = max(0, int(info.st_mtime))
        finally:
            os.close(handle)
        # begin() cannot return to its caller before publishing the first
        # record. An empty private directory grants no recovery authority.
        return {'schema': 1, 'directory': str(path), 'phase': 'abandoned',
                'created_at': created, 'updated_at': created, 'settings': {},
                'empty_preparation': True}
    if (not isinstance(value, dict) or type(value.get('schema')) is not int or value.get('schema') != 1
            or value.get('phase') not in PHASES
            or value.get('directory') != str(path) or not isinstance(value.get('settings'), dict)
            or set(value['settings']) - set(FIELDS) or type(value.get('created_at')) is not int
            or type(value.get('updated_at')) is not int or value['created_at'] < 0
            or value['updated_at'] < value['created_at'] or value['updated_at'] > 2 ** 63 - 1):
        raise TransactionError('Invalid installer transaction metadata')
    for field, item in value['settings'].items():
        if not isinstance(item, str) or len(item) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in item):
            raise TransactionError('Invalid transaction setting: ' + field)
    if ('stage' in value or 'stage_at' in value) and (value.get('stage') not in STAGES
            or type(value.get('stage_at')) is not int or not value['created_at'] <= value['stage_at'] <= value['updated_at']):
        raise TransactionError('Invalid installer stage metadata')
    return value


def legacy_sequence(root):
    """Recognize an old counter as bounded data, never recovery authority."""
    parent = directory(root)
    fd = -1
    try:
        fd = os.open('transaction-sequence', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in (0o600, 0o640, 0o644) or not 1 <= before.st_size <= 20):
            raise TransactionError('Unsafe legacy installer sequence metadata; preserve it for review')
        raw = os.read(fd, 21)
        after = os.fstat(fd)
        named = os.stat('transaction-sequence', dir_fd=parent, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                    value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (identity(before) != identity(after) or identity(after) != identity(named)
                or len(raw) != before.st_size or not re.fullmatch(rb'(?:0|[1-9][0-9]{0,18})\n?', raw)
                or int(raw) > 2 ** 63 - 1):
            raise TransactionError('Invalid legacy installer sequence metadata; preserve it for review')
    finally:
        if fd >= 0: os.close(fd)
        os.close(parent)


def pending(root):
    if not root.exists(): return []
    fd = directory(root)
    try:
        if os.fstat(fd).st_mode & 0o077: raise TransactionError('Installer evidence root must be mode 0700')
        names = os.listdir(fd)
    finally: os.close(fd)
    if len(names) > 100: raise TransactionError('Installer evidence directory needs administrator archival')
    result = []
    for name in sorted(names):
        if name == 'transaction-sequence':
            legacy_sequence(root)
            continue
        if not NAME.fullmatch(name): raise TransactionError('Unknown installer evidence directory: ' + name)
        value = state(root / name)
        if value['phase'] not in TERMINAL: result.append(value)
    return result


def clean_completed_evidence(value):
    # A durable terminal state already permits removal. A kill between commit
    # and normal shell cleanup must not accumulate complete package snapshots.
    # Never follow saved settings paths outside this protected generation.
    if preserve_completed_evidence(value):
        return
    path = Path(value['directory'])
    handle = directory(path)
    try:
        names = os.listdir(handle)
        if value.get('empty_preparation') and not (path / 'transaction.json').exists():
            if names:
                raise TransactionError('Empty preparation evidence changed before archival; preserve it for review')
            atomic(path / 'transaction.json', value)
            names = ['transaction.json']
        fixed = {'transaction.json', 'installer.sh', 'package.tgz', 'release-manifest.json',
                 'release-manifest.sig', 'bootstrap', 'approval', 'config.snapshot', 'pending.snapshot',
                 'history-evidence.json', HISTORY_REVIEW}
        if any(name not in fixed and not re.fullmatch(r'(?:sls-mass-notify-recovery|recovery-carrier)\.[A-Za-z0-9]{6,12}', name) for name in names):
            raise TransactionError('A completed installer generation has unknown evidence; preserve it for administrator review: ' + str(path))
        for name in names:
            if name == 'transaction.json': continue
            info = os.stat(name, dir_fd=handle, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                shutil.rmtree(name, dir_fd=handle)
            else:
                os.unlink(name, dir_fd=handle)
        os.fsync(handle)
    finally:
        os.close(handle)


def begin(root):
    if pending(root): raise TransactionError('An unfinished SLL installation must be recovered before a new installation')
    if root.exists():
        completed = sorted((state(path) for path in root.iterdir() if NAME.fullmatch(path.name)), key=lambda row: row['updated_at'])
        for value in completed:
            clean_completed_evidence(value)
        ordinary = [value for value in completed if not preserve_completed_evidence(value)]
        for value in ordinary[:-20]:
            # Every entry was validated by pending(); a terminal record is a
            # completion marker, never a rollback authority. Root-only parents
            # keep the cleanup separate from public FreePBX module paths.
            shutil.rmtree(Path(value['directory']))
    if not root.exists():
        parent = directory(root.parent)
        try: os.mkdir(root.name, 0o700, dir_fd=parent); os.fsync(parent)
        finally: os.close(parent)
    name = 'transaction-' + os.urandom(12).hex()
    parent = directory(root)
    try: os.mkdir(name, 0o700, dir_fd=parent); os.fsync(parent)
    finally: os.close(parent)
    path = root / name
    atomic(path / 'transaction.json', {'schema': 1, 'directory': str(path), 'phase': 'preparing',
                                      'created_at': int(time.time()), 'updated_at': int(time.time()), 'settings': {}})
    return path


def update(path, phase, settings, stage=None, *, preserve_recovery_evidence=False):
    if type(preserve_recovery_evidence) is not bool or preserve_recovery_evidence and phase != 'rolled_back':
        raise TransactionError('Original recovery evidence retention applies only to verified rollback completion')
    value = state(path)
    if value['phase'] in TERMINAL and phase != value['phase'] and not (value['phase']=='committed' and phase=='recovery_failed'):
        raise TransactionError('A finished transaction cannot return to an unfinished state')
    if (phase not in PHASES or type(settings) is not dict or set(settings) - set(FIELDS)
            or any(type(item) is not str for item in settings.values())):
        raise TransactionError('Invalid installer transition')
    if value['phase'] == 'preparing' and phase == 'prepared':
        if set(settings) != set(FIELDS) or settings.get('STATIC_MUTATION_STARTED') != '0' or settings.get('MODULE_ACTIVATED') != '0':
            raise TransactionError('Complete unmutated preparation settings are required before publishing recovery readiness')
        for filename, bound in (('installer.sh', 2097152), ('package.tgz', 54525952),
                                ('release-manifest.json', 16384), ('release-manifest.sig', 64)):
            if not read(path / filename, bound):
                raise TransactionError('Preparation artifact is empty: ' + filename)
        for field, name in (('INSTALL_BOOTSTRAP_DIR', 'bootstrap'), ('UPGRADE_TRUST_DIR', 'approval')):
            if settings.get(field) != str(path / name):
                raise TransactionError('Prepared evidence directory does not belong to this transaction')
            checked_directory = directory(path / name)
            os.close(checked_directory)
    if preserve_recovery_evidence and not _recovery_retention(value):
        if value['phase'] in TERMINAL:
            raise TransactionError('Atomic manual recovery completion requires an unfinished transaction')
        authenticate(path)
        value['recovery_evidence'] = {
            'schema': 1, 'reason': 'Manual authenticated interrupted installation recovery',
            'retained_at': max(0, int(time.time())),
            'original_artifacts': _original_artifact_binding(path), 'original_evidence_preserved': True}
    mfa_binding = _mfa_evidence_binding(path, settings) if phase == 'rolled_back' else None
    if phase == 'rolled_back' and mfa_binding is not None:
        if not preserve_recovery_evidence:
            raise TransactionError('Verified MFA recovery requires retained original authentication evidence')
        if value.get('mfa_recovery') is not None and configuration_canonical(value['mfa_recovery']) != configuration_canonical(mfa_binding):
            raise TransactionError('Completed MFA recovery evidence cannot be replaced')
        value['mfa_recovery'] = mfa_binding
    value['settings'] = dict(settings)
    value['phase'] = phase; value['updated_at'] = max(int(time.time()),value['created_at'],value['updated_at'])
    if stage is not None:
        if stage not in STAGES:raise TransactionError('Invalid installer stage')
        value['stage']=stage;value['stage_at']=value['updated_at']
    # Validate the complete serializable input before any replacement.
    for key, item in value['settings'].items():
        if len(item) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in item): raise TransactionError('Invalid installer setting: ' + key)
    atomic(path / 'transaction.json', value)


def authenticate(path):
    """Authorize saved executable bytes with publisher evidence, never journal hashes."""
    value = state(path)
    here = Path(__file__).absolute().parent
    source = read(here / 'sls_release_trust.py', 262144, private=False)
    module = types.ModuleType('transaction_publisher'); module.__file__ = str(here / 'sls_release_trust.py')
    exec(compile(source, module.__file__, 'exec'), module.__dict__)
    manifest = module.authenticate_manifest(read(path / 'release-manifest.json'), read(path / 'release-manifest.sig'))
    for filename, field, bound in (('installer.sh', 'installer_sha256', 2 * 1024 * 1024),
                                   ('package.tgz', 'package_sha256', 64 * 1024 * 1024)):
        if hashlib.sha256(read(path / filename, bound)).hexdigest() != manifest.get(field):
            raise TransactionError('Saved installer recovery artifact differs from its publisher signature: ' + filename)
    bootstrap = Path(value['settings'].get('INSTALL_BOOTSTRAP_DIR', ''))
    if bootstrap != path / 'bootstrap': raise TransactionError('Recovery bootstrap is outside the durable transaction')
    bootstrap_fd = directory(bootstrap)
    try:
        bootstrap_info = os.fstat(bootstrap_fd)
        names = set(os.listdir(bootstrap_fd))
        if bootstrap_info.st_uid != 0 or bootstrap_info.st_gid != 0 or stat.S_IMODE(bootstrap_info.st_mode) != 0o700:
            raise TransactionError('Recovery bootstrap directory permissions are unsafe')
        if names != BOOTSTRAP_FILES:
            raise TransactionError('Recovery bootstrap helper inventory is incomplete or contains unknown files')
        for name in names:
            info = os.stat(name, dir_fd=bootstrap_fd, follow_symlinks=False)
            expected_mode = 0o600 if name == 'freepbx-mirror-signing.pub' else 0o700
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != expected_mode):
                raise TransactionError('Recovery bootstrap helper metadata is unsafe: ' + name)
    finally:
        os.close(bootstrap_fd)
    with tarfile.open(path / 'package.tgz', 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) > 10000: raise TransactionError('Saved recovery package has too many entries')
        for child in sorted(bootstrap.iterdir(), key=lambda item: item.name):
            if child.name == 'freepbx-mirror-signing.pub':
                name = 'slsmassnotifyserver/bin/sls_mass_notify/freepbx-mirror-signing.pub'
            else:
                if not re.fullmatch(r'sls_[a-z_]+\.py', child.name): raise TransactionError('Unexpected recovery helper')
                name = 'slsmassnotifyserver/bin/sls_mass_notify/' + child.name
            matches = [member for member in members if member.name.rstrip('/') == name]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 2 * 1024 * 1024:
                raise TransactionError('Recovery helper is absent from the authenticated package')
            stream = archive.extractfile(matches[0])
            if stream is None or read(child, 2 * 1024 * 1024) != stream.read(2 * 1024 * 1024 + 1):
                raise TransactionError('Saved recovery helper differs from its authenticated package')
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _history_context(path, *, unfinished=False, authenticate_original=True):
    """Bind decisions to retained signed originals, never a new live baseline."""
    path = Path(path)
    value = authenticate(path) if authenticate_original else state(path)
    if unfinished and value['phase'] not in ('prepared', 'mutating', 'recovering', 'recovery_failed'):
        raise TransactionError('History review requires an unfinished authenticated transaction')
    recovery = Path(value['settings'].get('RECOVERY_DIR', ''))
    if recovery.parent != path or not re.fullmatch(r'sls-mass-notify-recovery\.[A-Za-z0-9]{6}', recovery.name):
        raise TransactionError('Original phone-history baseline is outside this transaction')
    baseline = recovery / 'idle-before.json'
    raw = read(baseline, HISTORY_LIMIT)
    before = decode_json(raw)
    known = before.get('phone_history') if isinstance(before, dict) else None
    if (type(before) is not dict or type(before.get('schema')) is not int or before['schema'] != 1 or before.get('ok') is not True
            or not isinstance(known, dict) or len(known) > 10000
            or type(before.get('closed_phone_batches')) is not int
            or before['closed_phone_batches'] != len(known)
            or any(not isinstance(key, str) or not SHA256.fullmatch(key)
                   or not isinstance(digest, str) or not SHA256.fullmatch(digest)
                   for key, digest in known.items())):
        raise TransactionError('Original phone-history baseline is invalid')
    manifest_raw = read(path / 'release-manifest.json', 16384)
    manifest = decode_json(manifest_raw)
    if not authenticate_original:
        # Retention of a completed forensic archive grants no execution or
        # history-loss authority. Key retirement/metadata expiry must neither
        # delete this evidence nor prevent installation of a newer release.
        # Still require unchanged private originals bound by its prior receipt.
        if not isinstance(manifest, dict):
            raise TransactionError('Retained original release manifest is invalid')
        for name, field, bound in (('installer.sh', 'installer_sha256', 2097152),
                                   ('package.tgz', 'package_sha256', 54525952)):
            if hashlib.sha256(read(path / name, bound)).hexdigest() != manifest.get(field):
                raise TransactionError('Retained original recovery artifact changed: ' + name)
    identity = {
        'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
        'signature_sha256': hashlib.sha256(read(path / 'release-manifest.sig', 64)).hexdigest(),
        'installer_sha256': manifest['installer_sha256'],
        'package_sha256': manifest['package_sha256'],
        'version': manifest.get('version'), 'package': manifest.get('package'),
        'tag': manifest.get('tag'),
    }
    binding = {'transaction': str(path), 'baseline_path': str(baseline),
               'baseline_sha256': hashlib.sha256(raw).hexdigest(), 'original_release': identity}
    return value, before, known, binding


def _hash_map(value):
    return (isinstance(value, dict) and len(value) <= 10000
            and all(isinstance(key, str) and SHA256.fullmatch(key)
                    and isinstance(digest, str) and SHA256.fullmatch(digest)
                    for key, digest in value.items()))


def _history_report(path, report, *, unfinished=False, recovery_review=False):
    value, before, known, binding = _history_context(path, unfinished=unfinished)
    names = ('unchanged_phone_history', 'verified_expired_phone_history',
             'missing_unexpired_phone_history', 'missing_unknown_phone_history',
             'voicemail_dependency_phone_history')
    if (type(report) is not dict or type(report.get('schema')) is not int or report['schema'] != 1
            or report.get('baseline_sha256') != binding['baseline_sha256']
            or type(report.get('baseline_phone_batches')) is not int
            or report['baseline_phone_batches'] != len(known)
            or type(report.get('live_closed_phone_batches')) is not int
            or not _hash_map(report.get('live_phone_history'))
            or report['live_closed_phone_batches'] != len(report['live_phone_history'])
            or type(report.get('missing_phone_ledger')) is not bool
            or type(report.get('safe_to_approve_unknown_loss')) is not bool
            or any(not _hash_map(report.get(name)) for name in names)
            or not isinstance(report.get('modified_phone_history'), dict)
            or not isinstance(report.get('pending_phone_reconciliation'), list)
            or len(report['pending_phone_reconciliation']) > 10000
            or any(not isinstance(key, str) or not SHA256.fullmatch(key)
                   for key in report['pending_phone_reconciliation'])):
        raise TransactionError('History-review report is malformed or belongs to another baseline')
    live = report['live_phone_history']
    classified = set()
    for name in (*names, 'modified_phone_history'):
        for key, digest in report[name].items():
            if key not in known or key in classified:
                raise TransactionError('History-review classifications overlap or name unrelated records')
            classified.add(key)
            if name == 'modified_phone_history':
                if (not isinstance(digest, dict) or set(digest) != {'expected_sha256', 'observed_sha256'}
                        or digest['expected_sha256'] != known[key]
                        or digest['observed_sha256'] != live.get(key)
                        or digest['observed_sha256'] == known[key]):
                    raise TransactionError('History-review modification facts are invalid')
            elif digest != known[key] or (name == 'unchanged_phone_history' and live.get(key) != digest) \
                    or (name != 'unchanged_phone_history' and key in live):
                raise TransactionError('History-review facts do not match the original record hashes')
    if classified != set(known):
        raise TransactionError('History review must classify every original record')
    original_pending = before.get('pending_phone_reconciliation', [])
    if (not isinstance(original_pending, list) or len(original_pending) > 10000
            or any(not isinstance(key, str) or not SHA256.fullmatch(key) for key in original_pending)
            or set(original_pending) - set(live) - set(report['pending_phone_reconciliation'])):
        raise TransactionError('Original collector reconciliation cannot be omitted from history review')
    reconciliation_pending = bool(report['pending_phone_reconciliation'] or report['missing_phone_ledger'])
    if (report['modified_phone_history'] or report['missing_unexpired_phone_history']
            or report['voicemail_dependency_phone_history']
            or reconciliation_pending and (not recovery_review or report['missing_unknown_phone_history'])):
        raise TransactionError('History-loss approval cannot waive changed, unexpired, voicemail-dependent, pending or missing-ledger safety checks')
    safe = bool(report['missing_unknown_phone_history'])
    if report['safe_to_approve_unknown_loss'] != safe:
        raise TransactionError('History-review approval eligibility does not match its facts')
    stable = {'schema': 1, 'kind': 'sll-installer-history-loss-review', **binding,
              'baseline_phone_batches': len(known),
              'unchanged_phone_history': report['unchanged_phone_history'],
              'verified_expired_phone_history': report['verified_expired_phone_history'],
              'missing_unknown_phone_history': report['missing_unknown_phone_history'],
              'missing_history_verified_expired': False}
    return value, stable


def history_review(path, report):
    """Prepare a root-private review; this grants no permission to lose history."""
    _, stable = _history_report(path, report, unfinished=True, recovery_review=True)
    summary = {'baseline_phone_batches': stable['baseline_phone_batches'],
               'unchanged_baseline_phone_batches': len(stable['unchanged_phone_history']),
               'verified_expired_phone_batches': len(stable['verified_expired_phone_history']),
               'unknown_missing_phone_batches': len(stable['missing_unknown_phone_history'])}
    if not stable['missing_unknown_phone_history']:
        # A no-loss preflight may precede collector reconciliation or restoration
        # of a fresh install's original absence. This grants no loss exception;
        # actual approval and final strict inspection still reject these states.
        return {'ok': True, 'review_required': False, 'summary': summary,
                'recovery_verification_deferred': bool(report['pending_phone_reconciliation'] or report['missing_phone_ledger']),
                'pending_phone_reconciliation': report['pending_phone_reconciliation'],
                'missing_phone_ledger': report['missing_phone_ledger']}
    challenge = hashlib.sha256(_canonical(stable)).hexdigest()
    target = Path(path) / HISTORY_REVIEW
    document = {**stable, 'review_sha256': challenge}
    try:
        previous = decode_json(read(target, HISTORY_LIMIT))
    except FileNotFoundError:
        previous = None
    if previous != document:
        # An accepted review is immutable. A changed live set needs a separate
        # administrator investigation, never replacement of its approved facts.
        if (Path(path) / HISTORY_APPROVAL).exists() or (Path(path) / HISTORY_APPROVAL).is_symlink():
            raise TransactionError('An approved history review cannot be replaced; preserve it for administrator review')
        atomic(target, document, HISTORY_LIMIT)
    return {'ok': True, 'review_required': True, 'review_sha256': challenge,
            'review_path': str(target), 'summary': summary}


def _review_document(path, *, authenticate_original=True):
    _, _, known, binding = _history_context(path, authenticate_original=authenticate_original)
    review = decode_json(read(Path(path) / HISTORY_REVIEW, HISTORY_LIMIT))
    fields = {'schema', 'kind', *binding, 'baseline_phone_batches', 'unchanged_phone_history',
              'verified_expired_phone_history', 'missing_unknown_phone_history',
              'missing_history_verified_expired', 'review_sha256'}
    if (type(review) is not dict or set(review) != fields or type(review.get('schema')) is not int
            or review['schema'] != 1 or review.get('kind') != 'sll-installer-history-loss-review'
            or any(review.get(key) != item for key, item in binding.items())
            or type(review.get('baseline_phone_batches')) is not int
            or review['baseline_phone_batches'] != len(known)
            or review.get('missing_history_verified_expired') is not False
            or not isinstance(review.get('review_sha256'), str) or not SHA256.fullmatch(review['review_sha256'])):
        raise TransactionError('Protected history review does not match this authenticated transaction')
    classified = set()
    for name in ('unchanged_phone_history', 'verified_expired_phone_history', 'missing_unknown_phone_history'):
        if not _hash_map(review[name]):
            raise TransactionError('Protected history review has invalid record hashes')
        for key, digest in review[name].items():
            if key not in known or known[key] != digest or key in classified:
                raise TransactionError('Protected history review includes unrelated or duplicate records')
            classified.add(key)
    if classified != set(known) or not review['missing_unknown_phone_history']:
        raise TransactionError('Protected history review does not account for its original missing records')
    stable = {key: item for key, item in review.items() if key != 'review_sha256'}
    if hashlib.sha256(_canonical(stable)).hexdigest() != review['review_sha256']:
        raise TransactionError('Protected history review challenge has changed')
    return review


def _approval_document(path, *, authenticate_original=True):
    value = state(Path(path))
    review = _review_document(path, authenticate_original=authenticate_original)
    receipt_raw = read(Path(path) / HISTORY_APPROVAL, HISTORY_LIMIT)
    receipt = decode_json(receipt_raw)
    fields = {'schema', 'kind', 'classification', 'transaction', 'baseline_path', 'baseline_sha256',
              'original_release', 'review_sha256', 'approved_unknown_phone_history', 'approved_at',
              'operator', 'reason', 'missing_history_verified_expired'}
    if (type(receipt) is not dict or set(receipt) != fields or type(receipt.get('schema')) is not int
            or receipt['schema'] != 1 or receipt.get('kind') != 'sll-installer-history-loss-approval'
            or receipt.get('classification') != HISTORY_CLASSIFICATION
            or receipt.get('missing_history_verified_expired') is not False
            or type(receipt.get('approved_at')) is not int or not 0 <= receipt['approved_at'] <= 2 ** 63 - 1
            or any(receipt.get(key) != review.get(key) for key in (
                'transaction', 'baseline_path', 'baseline_sha256', 'original_release', 'review_sha256'))
            or receipt.get('approved_unknown_phone_history') != review['missing_unknown_phone_history']):
        raise TransactionError('Protected history-loss approval differs from its exact original review')
    _approval_text(receipt.get('operator'), 'operator', 256)
    _approval_text(receipt.get('reason'), 'reason', 2048)
    summary = value.get('history_loss')
    expected = {'classification': HISTORY_CLASSIFICATION,
                'accepted_missing_phone_batches': len(receipt['approved_unknown_phone_history']),
                'approval_sha256': hashlib.sha256(receipt_raw).hexdigest(),
                'review_sha256': review['review_sha256'], 'original_evidence_preserved': True}
    if summary is not None and summary != expected:
        raise TransactionError('History-loss receipt differs from its durable transaction summary')
    return receipt, expected


def _approval_text(value, name, bound):
    try:
        valid = (isinstance(value, str) and bool(value.strip()) and value == value.strip()
                 and len(value.encode('utf-8')) <= bound
                 and not any(ord(character) < 32 or ord(character) == 127 for character in value))
    except UnicodeError:
        valid = False
    if not valid:
        raise TransactionError('History-loss approval requires a bounded, single-line administrator ' + name)
    return value


def approve_history_loss(path, report, confirmation, operator, reason):
    """Separate, explicit acceptance of unknown loss; never call it expiry."""
    value, stable = _history_report(path, report, unfinished=True)
    review = _review_document(path)
    if (not isinstance(confirmation, str) or not SHA256.fullmatch(confirmation)
            or confirmation != review['review_sha256']
            or stable != {key: item for key, item in review.items() if key != 'review_sha256'}):
        raise TransactionError('Explicit approval must match the saved review and the current exact missing history set')
    operator = _approval_text(operator, 'operator', 256)
    reason = _approval_text(reason, 'reason', 2048)
    target = Path(path) / HISTORY_APPROVAL
    if target.exists() or target.is_symlink():
        receipt, summary = _approval_document(path)
        if receipt['operator'] != operator or receipt['reason'] != reason:
            raise TransactionError('Existing administrator history-loss approval cannot be replaced')
    else:
        receipt = {'schema': 1, 'kind': 'sll-installer-history-loss-approval',
                   'classification': HISTORY_CLASSIFICATION,
                   **{key: review[key] for key in ('transaction', 'baseline_path', 'baseline_sha256', 'original_release', 'review_sha256')},
                   'approved_unknown_phone_history': review['missing_unknown_phone_history'],
                   'approved_at': max(0, int(time.time())), 'operator': operator, 'reason': reason,
                   'missing_history_verified_expired': False}
        atomic(target, receipt, HISTORY_LIMIT)
        receipt, summary = _approval_document(path)
    # The receipt is fsynced first. Its mere presence forbids ordinary cleanup
    # even if a crash occurs before this small journal annotation is durable.
    value['history_loss'] = summary
    atomic(Path(path) / 'transaction.json', value)
    return receipt


def load_history_loss_approval(receipt_path, baseline_path, current_report):
    """Return only unknown missing hashes covered by this explicit decision."""
    receipt_path = Path(receipt_path)
    if receipt_path.name != HISTORY_APPROVAL:
        raise TransactionError('Use the protected approval retained in the exact installer transaction')
    path = receipt_path.parent
    receipt, _ = _approval_document(path)
    if Path(baseline_path) != Path(receipt['baseline_path']):
        raise TransactionError('History-loss approval names another original baseline')
    _, stable = _history_report(path, current_report)
    unknown = stable['missing_unknown_phone_history']
    accepted = receipt['approved_unknown_phone_history']
    expired = stable['verified_expired_phone_history']
    if (stable['baseline_sha256'] != receipt['baseline_sha256']
            or any(accepted.get(key) != digest for key, digest in unknown.items())
            or any(key not in unknown and expired.get(key) != digest for key, digest in accepted.items())):
        raise TransactionError('History-loss approval does not cover the current exact unknown missing records')
    # A subsequently found genuine backup can prove some originally unknown
    # rows expired. It can only narrow the loss exception. New missing rows,
    # reappearing rows, changed rows and known unexpired loss still fail.
    return dict(unknown)


def _original_artifact_binding(path):
    """Passive integrity only; never authorizes executing a retained program."""
    path = Path(path)
    raw = read(path / 'release-manifest.json', 16384)
    manifest = decode_json(raw)
    if not isinstance(manifest, dict):
        raise TransactionError('Retained recovery manifest is invalid')
    signature = read(path / 'release-manifest.sig', 64)
    if len(signature) != 64:
        raise TransactionError('Retained recovery signature is incomplete')
    binding = {'manifest_sha256': hashlib.sha256(raw).hexdigest(),
               'signature_sha256': hashlib.sha256(signature).hexdigest()}
    for name, field, bound in (('installer.sh', 'installer_sha256', 2097152),
                               ('package.tgz', 'package_sha256', 54525952)):
        digest = hashlib.sha256(read(path / name, bound)).hexdigest()
        if digest != manifest.get(field):
            raise TransactionError('Retained original recovery artifact changed: ' + name)
        binding[field] = digest
    return binding


def _mfa_evidence_binding(path, settings):
    """Passive archive binding; never grants permission to restore settings."""
    try:
        return _read_mfa_evidence_binding(path, settings)
    except TransactionError:
        raise
    except Exception as error:
        raise TransactionError('MFA preservation archive is incomplete or changed; preserve the entire transaction') from error


def _read_mfa_evidence_binding(path, settings):
    location = settings.get('RECOVERY_DIR')
    if not location: return None
    recovery = Path(location); receipt = recovery / 'configuration-mfa-recovery.json'
    if not receipt.exists() and not receipt.is_symlink(): return None
    if recovery.parent != path or not re.fullmatch(r'sls-mass-notify-recovery\.[A-Za-z0-9]{6}', recovery.name):
        raise TransactionError('MFA recovery evidence is outside its original transaction')
    body = read(receipt); document = decode_json(body)
    if (type(document) is not dict or set(document) != {'schema', 'recovery', 'original_sha256', 'pending_state', 'pending_original_sha256', 'active', 'pending'}
            or type(document['schema']) is not int or document['schema'] != 1
            or document['recovery'] != location or document['original_sha256'] != settings.get('CONFIG_HASH_BEFORE')
            or document['pending_state'] != settings.get('PENDING_CONFIG_STATE')
            or document['pending_original_sha256'] != settings.get('PENDING_CONFIG_HASH')):
        raise TransactionError('MFA preservation receipt does not bind the original transaction')
    binding = {'schema': 1, 'kind': 'preserved_monotonic_mfa_consumption', 'recovery': location,
               'journal_sha256': hashlib.sha256(body).hexdigest()}
    for label, field, name, original_hash in [
            ('active', 'CONFIG_SNAPSHOT', 'config.snapshot', document['original_sha256']),
            ('pending', 'PENDING_CONFIG_SNAPSHOT', 'pending.snapshot', document['pending_original_sha256'])]:
        present = label == 'active' or document['pending_state'] == 'present'
        if not present:
            if document[label] is not None: raise TransactionError('Unexpected pending MFA preservation evidence')
            binding[label + '_sha256'] = 'absent'; binding['original_' + label + '_sha256'] = 'absent'; continue
        if settings.get(field) != str(path / name) or hashlib.sha256(read(path / name, 16 * 1024 * 1024)).hexdigest() != original_hash:
            raise TransactionError('Original configuration evidence changed after MFA preservation')
        target = document[label]
        if type(target) is not dict or set(target) != {'snapshot', 'sha256'} or not isinstance(target['sha256'], str) or not SHA256.fullmatch(target['sha256']) or target['snapshot'] != 'configuration-mfa-' + target['sha256'] + '.snapshot':
            raise TransactionError('Invalid retained MFA target')
        if hashlib.sha256(read(recovery / target['snapshot'], 16 * 1024 * 1024)).hexdigest() != target['sha256']:
            raise TransactionError('Retained MFA target changed')
        binding[label + '_sha256'] = target['sha256']; binding['original_' + label + '_sha256'] = original_hash
    intentions = configuration_intents(recovery, document['original_sha256'])
    intents = recovery / 'configuration-intents.json'
    binding['intent_chain_sha256'] = hashlib.sha256(read(intents)).hexdigest() if intents.exists() or intents.is_symlink() else 'absent'
    binding['intent_images'] = {}
    for item in intentions['writes']:
        image = recovery / ('configuration-intent-' + item['after_sha256'] + '.snapshot')
        digest = hashlib.sha256(read(image, 16 * 1024 * 1024)).hexdigest() if image.exists() or image.is_symlink() else 'absent'
        if digest not in ('absent', item['after_sha256']):
            raise TransactionError('Retained installer configuration afterimage changed')
        binding['intent_images'][item['after_sha256']] = digest
    return binding


def _recovery_retention(value):
    marker = value.get('recovery_evidence')
    if marker is None:
        return False
    if (type(marker) is not dict or set(marker) != {
            'schema', 'reason', 'retained_at', 'original_artifacts', 'original_evidence_preserved'}
            or type(marker.get('schema')) is not int or marker['schema'] != 1
            or type(marker.get('retained_at')) is not int or not 0 <= marker['retained_at'] <= 2 ** 63 - 1
            or marker.get('original_evidence_preserved') is not True
            or marker.get('original_artifacts') != _original_artifact_binding(Path(value['directory']))):
        raise TransactionError('Manual recovery evidence-retention marker or original artifacts changed')
    _approval_text(marker.get('reason'), 'retention reason', 256)
    return True


def retain_recovery_evidence(path, reason='Manual authenticated interrupted installation recovery'):
    """Keep a manual recovery's originals; this marker grants no execution."""
    path = Path(path)
    value = state(path)
    if value['phase'] != 'rolled_back':
        raise TransactionError('Manual recovery evidence can be retained only after durable verified rollback')
    reason = _approval_text(reason, 'retention reason', 256)
    if _recovery_retention(value):
        if value['recovery_evidence']['reason'] != reason:
            raise TransactionError('Existing manual recovery retention facts cannot be replaced')
        return value['recovery_evidence']
    authenticate(path)
    marker = {'schema': 1, 'reason': reason, 'retained_at': max(0, int(time.time())),
              'original_artifacts': _original_artifact_binding(path), 'original_evidence_preserved': True}
    value['recovery_evidence'] = marker
    value['updated_at'] = max(value['updated_at'], marker['retained_at'])
    atomic(path / 'transaction.json', value)
    return marker


def preserve_completed_evidence(value):
    """Manual recoveries and accepted historical losses keep every original."""
    path = Path(value['directory'])
    manual_recovery = _recovery_retention(value)
    if value['phase'] in TERMINAL:
        binding = _mfa_evidence_binding(path, value['settings'])
        if (value.get('mfa_recovery') is not None or binding is not None) and (
                binding is None or type(value.get('mfa_recovery')) is not dict
                or configuration_canonical(value['mfa_recovery']) != configuration_canonical(binding)
                or not manual_recovery):
            raise TransactionError('MFA preservation archive binding or original authentication evidence changed')
    target = path / HISTORY_APPROVAL
    if not target.exists() and not target.is_symlink():
        if value.get('history_loss') is not None:
            raise TransactionError('History-loss transaction lost its receipt; preserve all remaining evidence')
        return manual_recovery
    # Any unreadable/tampered receipt is an error, never permission to delete.
    _approval_document(path, authenticate_original=False)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--transaction', type=Path)
    parser.add_argument('--phase', choices=sorted(PHASES))
    parser.add_argument('--stage', choices=sorted(STAGES))
    parser.add_argument('--confirmation')
    parser.add_argument('--operator')
    parser.add_argument('--reason')
    parser.add_argument('--preserve-recovery-evidence', action='store_true')
    parser.add_argument('action', choices=('pending', 'begin', 'update', 'stage', 'authenticate', 'values',
                                         'history-review', 'approve-history-loss', 'history-approval', 'preserve-evidence',
                                         'retain-recovery-evidence'))
    args = parser.parse_args()
    if os.geteuid() != 0: raise TransactionError('Installer transaction inspection requires root')
    if args.preserve_recovery_evidence and (args.action != 'update' or args.phase != 'rolled_back'):
        raise TransactionError('Recovery evidence retention requires a rolled_back update')
    if args.action == 'pending':
        records = pending(args.root)
        print(json.dumps({'ok': not records, 'unfinished': records}))
        return 0 if not records else 3
    if args.action == 'begin': print(begin(args.root)); return 0
    if args.transaction is None: parser.error('--transaction is required')
    if args.transaction.parent != args.root: raise TransactionError('Transaction must belong to its protected evidence root')
    if args.action in ('history-review', 'approve-history-loss', 'history-approval'):
        raw = sys.stdin.buffer.read(HISTORY_LIMIT + 1)
        if len(raw) > HISTORY_LIMIT:
            raise TransactionError('History-review report exceeds its bounded size')
        report = decode_json(raw)
        if args.action == 'history-review':
            result = history_review(args.transaction, report)
        elif args.action == 'approve-history-loss':
            if args.confirmation is None or args.operator is None or args.reason is None:
                parser.error('Approval requires --confirmation, --operator and --reason')
            result = approve_history_loss(args.transaction, report, args.confirmation, args.operator, args.reason)
        else:
            baseline = _history_context(args.transaction)[3]['baseline_path']
            approved = load_history_loss_approval(args.transaction / HISTORY_APPROVAL, baseline, report)
            result = {'ok': True, 'classification': HISTORY_CLASSIFICATION,
                      'accepted_missing_phone_batches': len(approved), 'missing_history_verified_expired': False}
        print(json.dumps(result, sort_keys=True))
    elif args.action == 'retain-recovery-evidence':
        options = {'reason': args.reason} if args.reason is not None else {}
        print(json.dumps(retain_recovery_evidence(args.transaction, **options), sort_keys=True))
    elif args.action == 'preserve-evidence':
        preserved = preserve_completed_evidence(state(args.transaction))
        print(json.dumps({'ok': True, 'original_evidence_preserved': preserved}))
        return 0 if preserved else 3
    elif args.action == 'update':
        raw = sys.stdin.buffer.read(LIMIT + 1)
        if len(raw) > LIMIT: raise TransactionError('Transition input exceeds its size limit')
        settings = decode_json(raw)
        if type(settings) is not dict or args.phase is None: raise TransactionError('Transition requires a phase and settings object')
        update(args.transaction, args.phase, settings, args.stage,
               preserve_recovery_evidence=args.preserve_recovery_evidence)
    elif args.action == 'stage':
        value=state(args.transaction)
        if value['phase'] in TERMINAL or args.stage is None:raise TransactionError('A current stage requires an unfinished transaction')
        update(args.transaction,value['phase'],value['settings'],args.stage)
    elif args.action == 'authenticate':
        authenticate(args.transaction); print('Saved installer, package and recovery helpers match publisher-authenticated evidence.')
    else:
        value = authenticate(args.transaction)
        if value['phase'] not in ('prepared', 'mutating', 'recovering', 'recovery_failed'):
            raise TransactionError('Only an unfinished installation can supply operational recovery settings')
        for field in FIELDS: print(value['settings'].get(field, ''))
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (TransactionError, OSError, ValueError, KeyError, tarfile.TarError) as error:
        raise SystemExit('SLL installer transaction: ' + str(error)) from None
