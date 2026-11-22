#!/usr/bin/python3
"""Coordinate installation leases and bounded central-settings recovery.

The inherited-descriptor protocol retains the same leases in the root caller;
no PBX code, service operation, notification or delivery-state mutation occurs.
"""
import argparse
import contextlib
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import select
import socket
import stat
import signal
import subprocess
import sys
import time
import types


def settings_metadata(fd, parent, account):
    name = 'mass-notifications.config.lock'
    info = os.fstat(fd)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in (0, account.pw_uid) or info.st_gid not in (0, account.pw_gid)
            or stat.S_IMODE(info.st_mode) not in (0o600, 0o640) or info.st_size != 0
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
        raise RuntimeError('configuration lock has unsafe ownership, mode, contents or identity')


def check_current_directory(data, parent, account=None):
    account = account or pwd.getpwnam('asterisk')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current = os.open('/', flags)
    try:
        for part in data.split('/'):
            if not part: continue
            child = os.open(part, flags, dir_fd=current)
            os.close(current); current = child
            info = os.fstat(current)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (info.st_uid not in (0, account.pw_uid) or info.st_gid not in (0, account.pw_gid)
                    or info.st_mode & 0o022 and not sticky_root):
                raise RuntimeError('unsafe live worker lock parent')
        opened = os.fstat(parent); named = os.fstat(current)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise RuntimeError('worker data directory changed before configuration coordination')
    finally:
        os.close(current)


def paging_metadata(paging, parent, account):
    info = os.fstat(paging)
    named = os.stat('live-paging-slots', dir_fd=parent, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, account.pw_uid)
            or info.st_gid not in (0, account.pw_gid)
            or stat.S_IMODE(info.st_mode) not in (0o700, 0o750, 0o755)
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
        raise RuntimeError('unsafe live paging slot directory')


def acquire_settings(parent, account, locks, timeout, descriptor=None):
    name = 'mass-notifications.config.lock'
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if descriptor is None:
        try:
            fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o640, dir_fd=parent)
        except FileExistsError:
            fd = os.open(name, flags, dir_fd=parent)
            created = False
        else:
            created = True
        locks.append(fd)
    else:
        fd = descriptor
        created = False
    if created:
        settings_metadata(fd, parent, account)
        os.fchown(fd, account.pw_uid, account.pw_gid)
        os.fchmod(fd, 0o640)
        os.fsync(fd); os.fsync(parent)
    settings_metadata(fd, parent, account)
    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise RuntimeError('active configuration editor did not become idle') from None
            time.sleep(.05)
    settings_metadata(fd, parent, account)
    return fd


def own_children(descriptor):
    """Read this process's pinned direct-child list, never a host PID scan."""
    os.lseek(descriptor, 0, os.SEEK_SET)
    body = os.read(descriptor, 262145)
    if len(body) > 262144 or any(not value.isdigit() for value in body.split()):
        raise RuntimeError('Native child inventory is unavailable')
    return {int(value) for value in body.split()}


@contextlib.contextmanager
def native_child_scope():
    """Adopt/reap only this invocation's children before any root lease closes."""
    library = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if library.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'Native child supervision is unavailable')
    descriptor = os.open('/proc/self/task/%d/children' % os.getpid(), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        baseline = own_children(descriptor)
        if library.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'Native child adoption is unavailable')
        try:
            yield
        finally:
            handlers = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
            for number in handlers: signal.signal(number, lambda *_: None)
            reported = False
            try:
                # A killed intermediate waiter reparents its actual children to
                # this subreaper. Detached sessions are still our descendants.
                # Never abandon cleanup on a time/count bound with writers live.
                while True:
                    try:
                        children = own_children(descriptor) - baseline
                        if not children:
                            break
                        for pid in children:
                            try:
                                pidfd = os.pidfd_open(pid)
                            except ProcessLookupError:
                                continue
                            try:
                                # Confirm parentage after pidfd_open to avoid
                                # signaling a PID recycled outside our subtree.
                                if pid not in own_children(descriptor) - baseline:
                                    continue
                                try: signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                                except ProcessLookupError: pass
                                try: os.waitpid(pid, 0)
                                except ChildProcessError: pass
                            finally:
                                os.close(pidfd)
                    except (OSError, ValueError, RuntimeError):
                        if not reported:
                            print('Native cleanup is incomplete; root worker leases remain held until owned children are reaped.', file=sys.stderr, flush=True)
                            reported = True
                        time.sleep(.05)
            finally:
                for number, handler in handlers.items(): signal.signal(number, handler)
            if library.prctl(36, previous.value, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), 'Native child supervision could not restore its previous state')
    finally:
        os.close(descriptor)


def native_exec_gate(descriptor, command):
    """Only immutable Python runs before the parent acknowledges child identity."""
    if (not 3 <= descriptor <= 9999999 or not stat.S_ISFIFO(os.fstat(descriptor).st_mode)
            or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY):
        raise RuntimeError('Invalid native execution gate')
    try:
        if os.read(descriptor, 16) != b'go\n':
            return 125
    finally:
        os.close(descriptor)
    os.execvpe(command[0], command, os.environ)


def wait_native(command, timeout, control_descriptor):
    """Retain root leases until the actual bounded native child is reaped."""
    saved = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    for number in saved: signal.signal(number, lambda *_: None)
    try:
        with native_child_scope(), socket.socket(fileno=control_descriptor) as control:
            control.settimeout(5)
            read_gate, write_gate = os.pipe2(os.O_CLOEXEC)
            try:
                child = subprocess.Popen(['/usr/bin/python3', '-I', str(Path(__file__).resolve()),
                    '--native-exec-gate', str(read_gate), '--', *command],
                    close_fds=True, pass_fds=(read_gate,), start_new_session=True)
                os.close(read_gate); read_gate = None
                control.send(json.dumps({'schema': 1, 'waiter_pid': os.getpid(), 'native_pid': child.pid},
                                        separators=(',', ':')).encode())
                if control.recv(17) != b'start':
                    raise RuntimeError('Native execution was not acknowledged; no mutable command started')
                control.close()
                os.write(write_gate, b'go\n')
                os.close(write_gate); write_gate = None
                try:
                    result = child.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                    return 124
                return result if result >= 0 else 128 - result
            finally:
                for descriptor in (read_gate, write_gate):
                    if descriptor is not None: os.close(descriptor)
    finally:
        for number, handler in saved.items(): signal.signal(number, handler)


def hold(data, timeout=120, settings=False, inherited=None, prepare=False, native_command=None, command_timeout=30, native_control=None):
    account = pwd.getpwnam('asterisk')
    if account.pw_uid == 0: raise SystemExit('Asterisk UID must be nonzero')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open('/', flags)
    locks = []
    held = []
    settings_fd = None
    paging = -1
    try:
        for part in data.split('/'):
            if not part: continue
            if part in ('.', '..'): raise RuntimeError('unsafe data directory')
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent); parent = child
            info = os.fstat(parent)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (info.st_uid not in (0, account.pw_uid)
                    or info.st_gid not in (0, account.pw_gid)
                    or (info.st_mode & 0o022 and not sticky_root)):
                raise RuntimeError('unsafe worker lock parent')
        names = os.listdir(parent)
        if len(names) > 20000: raise RuntimeError('worker guard inventory exceeds limit')
        legacy = [name for name in ('weather-poll-cycle.lock', 'sls_mass_notify_xweather_poll.lock') if name in names]
        zones = sorted(name for name in names if re.fullmatch(r'nws-poll-[A-Za-z0-9_-]{1,64}\.lock', name))
        if len(zones) > 1000: raise RuntimeError('weather worker guard count exceeds limit')
        # Preserve the established outer-to-inner worker ordering.
        required = ['schedule-runner.lock', 'schedule-worker.lock', 'announcement-send.lock', 'announcement-activity.lock',
                    'weather-observation.lock', 'weather-dispatch-worker.lock', 'weather-external-worker.lock', 'xweather-poll.lock']
        tail = ['sls_mass_notify_nws_poll.lock', 'nws-audio-delivery.lock', 'test-cooldown.ts.lock']
        try:
            os.mkdir('live-paging-slots', 0o750, dir_fd=parent)
            paging = os.open('live-paging-slots', flags, dir_fd=parent)
            os.fchown(paging, account.pw_uid, account.pw_gid)
        except FileExistsError:
            paging = os.open('live-paging-slots', flags, dir_fd=parent)
        paging_metadata(paging, parent, account)
        deadline = time.monotonic() + timeout
        # Workers take this shared lease before module bootstrap and retain it
        # through exit. Acquire its exclusive lease FIRST so a supervisor cannot
        # load mutable code after the ordinary activity guard was established.
        entries = [(parent, 'enterprise-worker.lock', fcntl.LOCK_EX, True)]
        entries += [(parent, 'phone-history-retention.lock', fcntl.LOCK_EX, True)]
        entries += [(parent, name, fcntl.LOCK_EX, True) for name in legacy + required + zones + tail]
        entries += [(paging, 'global-' + str(slot) + '.lock', fcntl.LOCK_EX, True) for slot in range(16)]
        # Both generations of audio writers are excluded during installation.
        # Shared leases allow the independent idle inspector to read, while
        # blocking writers that require an exclusive lease. Never create the
        # operational JSON here or replace either locked inode.
        entries += [(parent, 'audio-reservations.lock', fcntl.LOCK_SH, True),
                    (parent, 'audio-reservations.json', fcntl.LOCK_SH, False)]
        # Open the settings anchor even when its lease must wait for fresh
        # initialization. Later settings admission flocks this exact retained
        # open-file description rather than reopening a mutable pathname.
        if settings or prepare or inherited is not None:
            entries.append((parent, 'mass-notifications.config.lock', fcntl.LOCK_EX, True))
        bounded_entries = []
        for entry in entries:
            lock_parent, name, _, create = entry
            if not create:
                try: os.stat(name, dir_fd=lock_parent, follow_symlinks=False)
                except FileNotFoundError: continue
            bounded_entries.append(entry)
        entries = bounded_entries
        if inherited is not None and len(inherited) != len(entries):
            raise RuntimeError('retained worker descriptor inventory does not match current anchors')
        for index, (lock_parent, name, lock_mode, create) in enumerate(entries):
            if inherited is not None:
                fd = inherited[index]
                if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
                    raise RuntimeError('retained worker descriptors must be opened read-only')
                os.set_inheritable(fd, False)
            elif not create:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=lock_parent)
            else:
                try:
                    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o640, dir_fd=lock_parent)
                    owner = os.fstat(parent) if name == 'audio-reservations.lock' else None
                    os.fchown(fd, owner.st_uid if owner else account.pw_uid, owner.st_gid if owner else account.pw_gid)
                except FileExistsError:
                    fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=lock_parent)
            locks.append(fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (0, account.pw_uid):
                raise RuntimeError('unsafe worker lock: ' + name)
            if name == 'enterprise-worker.lock' and (info.st_mode & 0o7027 or info.st_size > 4096):
                raise RuntimeError('enterprise worker lock permissions or size are unsafe')
            if name == 'phone-history-retention.lock' and (info.st_size != 0
                    or info.st_gid not in (0, account.pw_gid)
                    or stat.S_IMODE(info.st_mode) not in (0o600, 0o640, 0o644)):
                raise RuntimeError('phone history retention lock is unsafe')
            if name == 'mass-notifications.config.lock':
                settings_metadata(fd, lock_parent, account)
            if name in ('audio-reservations.lock', 'audio-reservations.json'):
                if info.st_uid != os.fstat(parent).st_uid:
                    raise RuntimeError('audio state owner must match the runtime data directory: ' + name)
                if info.st_mode & 0o7022:
                    raise RuntimeError('audio state permissions are unsafe: ' + name)
                maximum = len(b'SLS_AUDIO_STATE_V1\n') if name.endswith('.lock') else 1048576
                if info.st_size > maximum:
                    raise RuntimeError('audio state exceeds its safe size limit: ' + name)
            entry = os.stat(name, dir_fd=lock_parent, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino): raise RuntimeError('worker lock identity changed')
            if name == 'mass-notifications.config.lock': settings_fd = fd
            if prepare or name == 'mass-notifications.config.lock' and not settings:
                continue
            while True:
                try: fcntl.flock(fd, lock_mode | fcntl.LOCK_NB); break
                except BlockingIOError:
                    if time.monotonic() >= deadline: raise RuntimeError('active worker did not become idle: ' + name)
                    time.sleep(0.1)
            entry = os.stat(name, dir_fd=lock_parent, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino): raise RuntimeError('worker lock identity changed')
            if name == 'phone-history-retention.lock':
                # Normalize only this verified, empty mutex under its exclusive
                # lease. Existing busy lock metadata is never changed.
                if info.st_uid != account.pw_uid or info.st_gid != account.pw_gid:
                    os.fchown(fd, account.pw_uid, account.pw_gid)
                if stat.S_IMODE(info.st_mode) != 0o640:
                    os.fchmod(fd, 0o640)
            if name == 'mass-notifications.config.lock':
                settings_metadata(fd, lock_parent, account)
            held.append((fd, lock_parent, name, os.fstat(fd)))
        check_current_directory(data, parent, account)
        if prepare:
            # Anchors stay open while the root caller copies them through
            # /proc/PID/fd. These are not yet leased, and this process never
            # supplies filename authority or unlocks another owner's lease.
            print('prepared ' + json.dumps({'schema': 1, 'pid': os.getpid(), 'fds': locks}, separators=(',', ':')), flush=True)
            command = sys.stdin.buffer.readline(17)
            if command not in (b'', b'release\n'):
                raise RuntimeError('unknown worker descriptor preparation command')
            return
        def check_held():
            check_current_directory(data, parent, account)
            paging_metadata(paging, parent, account)
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink')
            for descriptor, lock_parent, name, original in held:
                current = os.fstat(descriptor)
                named = os.stat(name, dir_fd=lock_parent, follow_symlinks=False)
                if any(getattr(original, field) != getattr(current, field) or
                       getattr(current, field) != getattr(named, field) for field in fields):
                    raise RuntimeError('held worker lease identity or metadata changed: ' + name)
        if native_command is not None:
            check_held()
            result = wait_native(native_command, command_timeout, native_control)
            check_held()
            return result
        print('ready', flush=True)
        settings_held = settings
        while True:
            command = sys.stdin.buffer.readline(65537)
            if len(command) > 65536:
                raise RuntimeError('installer guard command exceeds its bound')
            if command in (b'', b'release\n'):
                break
            if command == b'check\n':
                check_held()
                print('checked', flush=True)
                continue
            if command.startswith((b'restore-settings ', b'transform-settings ')):
                if not command.endswith(b'\n'):
                    raise RuntimeError('incomplete configuration recovery command')
                restore = command.startswith(b'restore-settings ')
                prefix = b'restore-settings ' if restore else b'transform-settings '
                arguments = json.loads(command[len(prefix):])
                if (type(arguments) is not list or len(arguments) != (8 if restore else 6)
                        or any(type(value) is not str or len(value) > 4096 for value in arguments)):
                    raise RuntimeError('invalid bounded settings command')
                if (restore and (arguments[3] != str(Path(data) / 'mass-notifications.config')
                                 or arguments[7] != str(Path(data) / 'mass-notifications.pending.config'))
                        or not restore and (arguments[0] not in ('profile', 'branding')
                                            or arguments[1] != str(Path(data) / 'mass-notifications.config'))):
                    raise RuntimeError('configuration recovery is not bound to this guarded data directory')
                if not settings_held:
                    fd = acquire_settings(parent, account, locks, timeout, settings_fd)
                    held.append((fd, parent, 'mass-notifications.config.lock', os.fstat(fd)))
                    settings_held = True
                check_held()
                helper = Path(__file__).with_name('sls_install_transaction.py')
                descriptor = os.open(helper, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                try:
                    info = os.fstat(descriptor)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                            or info.st_mode & 0o022 or not 0 < info.st_size <= 2 * 1024 * 1024):
                        raise RuntimeError('configuration recovery helper is not a protected sibling')
                    source = bytearray()
                    while len(source) <= 2 * 1024 * 1024:
                        chunk = os.read(descriptor, 65536)
                        if not chunk: break
                        source.extend(chunk)
                    after = os.fstat(descriptor)
                    named = helper.lstat()
                    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns, item.st_nlink)
                    if len(source) != info.st_size or identity(info) != identity(after) or identity(after) != identity(named):
                        raise RuntimeError('configuration recovery helper changed during admission')
                finally: os.close(descriptor)
                recovery = types.ModuleType('keeper_configuration_recovery'); recovery.__file__ = str(helper)
                exec(compile(source, str(helper), 'exec'), recovery.__dict__)
                try:
                    targets = (recovery.restore_configuration_recovery(arguments, check_held) if restore else
                               recovery.transform_installer_configuration(arguments, check_held))
                except recovery.TransactionError as error:
                    # A recognized policy conflict is a refused operation,
                    # not permission to release exclusion while the parent
                    # is still deciding how to preserve failed evidence.
                    check_held()
                    reason = ''.join(char for char in str(error) if 32 <= ord(char) < 127)[:512]
                    print('rejected-settings ' + json.dumps({'reason': reason}, separators=(',', ':')), flush=True)
                    continue
                check_held()
                print(('restored-settings ' if restore else 'transformed-settings ') + json.dumps(targets, separators=(',', ':')), flush=True)
                continue
            if command != b'settings\n':
                raise RuntimeError('unknown installer guard command')
            check_held()
            if not settings_held:
                fd = acquire_settings(parent, account, locks, timeout, settings_fd)
                held.append((fd, parent, 'mass-notifications.config.lock', os.fstat(fd)))
                settings_held = True
            check_held()
            print('settings-ready', flush=True)
    finally:
        for fd in locks: os.close(fd)
        if paging >= 0: os.close(paging)
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True)
    parser.add_argument('--settings', action='store_true')
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--inherited-fds')
    parser.add_argument('--command-timeout', type=float, default=30)
    parser.add_argument('--native-control-fd', type=int)
    parser.add_argument('action', choices=['hold', 'prepare', 'run'])
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 0.1 <= args.timeout <= 120:
        parser.error('Timeout must be between 0.1 and 120 seconds')
    if not args.data.startswith('/'):
        parser.error('Data directory must be absolute')
    descriptors = None
    if args.inherited_fds is not None:
        values = args.inherited_fds.split(',')
        if (args.action not in ('hold', 'run') or not 1 <= len(values) <= 1100
                or any(not re.fullmatch(r'[1-9][0-9]{0,6}', value) for value in values)):
            parser.error('Invalid retained worker descriptor inventory')
        descriptors = list(map(int, values))
        if min(descriptors) < 3 or len(set(descriptors)) != len(descriptors):
            parser.error('Retained worker descriptors must be distinct nonstandard descriptors')
    if args.action == 'prepare' and args.settings:
        parser.error('Preparation opens anchors without acquiring settings')
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if args.action == 'run':
        if (descriptors is None or not 0.1 <= args.command_timeout <= 600 or not 1 <= len(command) <= 128
                or sum(len(item) for item in command) > 65536 or any(len(item) > 8192 for item in command)
                or args.native_control_fd is None or not 3 <= args.native_control_fd <= 9999999
                or args.native_control_fd in descriptors or not stat.S_ISSOCK(os.fstat(args.native_control_fd).st_mode)):
            parser.error('Native waiter requires retained descriptors, a bounded command and timeout')
    elif command or args.native_control_fd is not None:
        parser.error('Only the retained native waiter accepts a command')
    return hold(args.data, args.timeout, args.settings, inherited=descriptors, prepare=args.action == 'prepare',
                native_command=command if args.action == 'run' else None, command_timeout=args.command_timeout,
                native_control=args.native_control_fd)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--native-exec-gate']:
        values = sys.argv[2:]
        if (len(values) < 3 or not values[0].isdigit() or values[1] != '--' or not 1 <= len(values[2:]) <= 128
                or sum(map(len, values[2:])) > 65536 or any(len(value) > 8192 for value in values[2:])):
            raise SystemExit('Invalid native execution gate request')
        raise SystemExit(native_exec_gate(int(values[0]), values[2:]))
    raise SystemExit(main())
