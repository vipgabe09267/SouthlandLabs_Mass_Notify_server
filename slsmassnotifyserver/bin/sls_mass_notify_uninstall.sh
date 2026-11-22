#!/usr/bin/env bash
set -euo pipefail

umask 027
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
# Removal is local and never needs publisher download credentials.
unset GITHUB_TOKEN GH_TOKEN SLS_MASS_NOTIFY_GITHUB_TOKEN

MODULE="slsmassnotifyserver"
if [ -n "${SLS_MASS_NOTIFY_MODULE:-}" ] \
  && [ "${SLS_MASS_NOTIFY_MODULE}" != "$MODULE" ]; then
  printf '%s\n' \
    "SLS_MASS_NOTIFY_MODULE is fixed to the FreePBX raw module name '$MODULE'; refusing an alternate value." >&2
  exit 2
fi
DATA_DIR="/var/lib/asterisk/SLS_Mass_Notifications_Plugin"
SIGN_HOME="/root/.gnupg-sls-mass-notify"
PURGE_CONFIG="${SLS_MASS_NOTIFY_PURGE_CONFIG:-0}"
case "$PURGE_CONFIG" in
  0|1) ;;
  *)
    printf '%s\n' 'SLS_MASS_NOTIFY_PURGE_CONFIG must be 0 or 1.' >&2
    exit 2
    ;;
esac
SIGNING_FINGERPRINT=""
KEEP_SIGNING_TRUST=0
RECOVERY_SIGNER_DIR=""
RECOVERY_SIGNER=""
UNINSTALL_APPROVED_SOURCE=""
UNINSTALL_TRANSACTION_DIR=""
CONFIGURED_AMI_USERNAME=""
CONFIGURED_AMI_SECRET_HASH=""
RECOVERY_DECODER_DIR=""
RECOVERY_CONFIG_DECODER="/usr/local/bin/sls_mass_notify/sls_config_crypto.php"
RECOVERY_AMI_OWNERSHIP_HELPER=""
RECOVERY_COLLECTOR_HELPER=""
UNINSTALL_MAINTENANCE_LOCK_FD=""
STOCK_RESTORE_LOG_PATH="/tmp/slsmassnotifyserver-uninstall-stock-modules.log"
MODULE_UNINSTALL_LOG_PATH="/tmp/slsmassnotifyserver-uninstall-module.log"
STOCK_RESTORE_LOG="$STOCK_RESTORE_LOG_PATH"
MODULE_UNINSTALL_LOG="$MODULE_UNINSTALL_LOG_PATH"
STOCK_RESTORE_LOG_FD=""
MODULE_UNINSTALL_LOG_FD=""
MODULE_REGISTRY_PRESENT=0
PBX_RUNNING=0
UNINSTALL_AMI_CLASSIFICATION=pending_unverified
UNINSTALL_WORKER_PID=""
declare -a UNINSTALL_WORKER_LEASE_FDS=()

sls_native_completion_record() {
  /usr/bin/python3 -I - "$@" <<'PYSLSNATIVEACK'
import json, os, re, stat, sys, tempfile, secrets

def completion_directory(name):
    if os.geteuid() != 0 or not re.fullmatch(r'/run/sls-native-command-[a-z0-9_]{8}', name):
        raise ValueError('Invalid root native completion directory')
    run = os.open('/run', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parent = os.fstat(run)
        if parent.st_uid != 0 or parent.st_mode & 0o022: raise ValueError('Unprotected native completion parent')
        descriptor = os.open(name.rsplit('/', 1)[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=run)
    finally: os.close(run)
    info = os.fstat(descriptor)
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(descriptor); raise ValueError('Unprotected native completion directory')
    return descriptor

def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def read_record(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1 or not 0 < before.st_size <= 2048): raise ValueError('Unsafe native completion record')
        body = os.read(descriptor, 2049)
        if (len(body) != before.st_size or identity(before) != identity(os.fstat(descriptor))
                or identity(before) != identity(os.stat(name, dir_fd=directory, follow_symlinks=False))):
            raise ValueError('Native completion record changed')
        return json.loads(body)
    finally: os.close(descriptor)

def write_record(directory, name, value):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        body = memoryview((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())
        while body:
            count = os.write(descriptor, body)
            if count <= 0: raise OSError('Native completion publication failed')
            body = body[count:]
        os.fsync(descriptor)
    finally: os.close(descriptor)

def scope_record(directory, nonce):
    value = read_record(directory, 'scope.json')
    fields = {'schema','magic','nonce','forked','waiter_pid','waiter_start','supervisor_pid','supervisor_start'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema']) is not int or value['schema'] != 1
            or value['magic'] != 'sls-native-scope-v1' or value['nonce'] != nonce or type(value['forked']) is not bool
            or any(type(value[key]) is not int or value[key] <= 0 for key in ('waiter_pid','waiter_start'))):
        raise ValueError('Invalid native scope binding')
    if value['forked']:
        if (any(type(value[key]) is not int or value[key] <= 0 for key in ('supervisor_pid','supervisor_start'))
                or value['waiter_pid'] == value['supervisor_pid']): raise ValueError('Invalid forked native scope')
    elif (type(value['supervisor_pid']) is not int or value['supervisor_pid'] != 0
            or type(value['supervisor_start']) is not int or value['supervisor_start'] != 0):
        raise ValueError('Invalid refused native scope')
    return value

def completion_record(directory, nonce):
    scope = scope_record(directory, nonce)
    value = read_record(directory, 'completed.json')
    if (not isinstance(value, dict) or set(value) != {'schema','magic','nonce','status','pid'}
            or type(value['schema']) is not int or value['schema'] != 1 or value['magic'] != 'sls-native-completion-v1'
            or value['nonce'] != nonce or type(value['status']) is not int or not 0 <= value['status'] <= 255
            or type(value['pid']) is not int or value['pid'] <= 0 or value['pid'] not in (scope['waiter_pid'],scope['supervisor_pid'])
            or (not scope['forked'] and value['status'] == 0)):
        raise ValueError('Invalid native completion binding')
    return value['status']

def complete(directory, nonce, status):
    try: return completion_record(directory, nonce)
    except FileNotFoundError: pass
    write_record(directory, 'completed.json', {'schema':1,'magic':'sls-native-completion-v1',
        'nonce':nonce,'status':status,'pid':os.getpid()})
    return completion_record(directory, nonce)

try:
    if os.geteuid() != 0: raise ValueError('Root native completion metadata is required')
    operation, *arguments = sys.argv[1:]
    if operation == 'prepare' and not arguments:
        parent = os.open('/run', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(parent)
            if info.st_uid != 0 or info.st_mode & 0o022: raise ValueError('Unprotected native completion parent')
        finally: os.close(parent)
        name = tempfile.mkdtemp(prefix='sls-native-command-', dir='/run')
        descriptor = completion_directory(name); os.close(descriptor)
        print(name); print(secrets.token_hex(32))
    elif operation in ('verify', 'cancel') and len(arguments) in ((2,3) if operation == 'verify' else (3,)):
        name, nonce, *extra = arguments
        if not re.fullmatch(r'[a-f0-9]{64}', nonce): raise ValueError('Invalid native invocation binding')
        descriptor = completion_directory(name)
        try:
            if operation == 'verify':
                status = completion_record(descriptor, nonce)
                if extra and (not re.fullmatch(r'[0-9]{1,3}',extra[0]) or status != int(extra[0])): raise ValueError('Native completion status changed')
                print(status)
            else:
                if extra[0] not in ('1','2','15'): raise ValueError('Invalid native cancellation signal')
                # One Bash owner sends requests synchronously. Preserve its
                # first accepted cancellation as an immutable record so a
                # repeated signal cannot invalidate an active strict reader.
                try: existing = read_record(descriptor, 'cancel.json')
                except FileNotFoundError:
                    temporary = 'cancel-' + secrets.token_hex(12)
                    write_record(descriptor, temporary, {'schema':1,'magic':'sls-native-cancel-v1','nonce':nonce,'signal':int(extra[0])})
                    os.replace(temporary, 'cancel.json', src_dir_fd=descriptor, dst_dir_fd=descriptor)
                else:
                    if (not isinstance(existing, dict) or set(existing) != {'schema','magic','nonce','signal'}
                            or type(existing['schema']) is not int or existing['schema'] != 1
                            or existing['magic'] != 'sls-native-cancel-v1' or existing['nonce'] != nonce
                            or type(existing['signal']) is not int or existing['signal'] not in (1,2,15)):
                        raise ValueError('Invalid retained native cancellation binding')
        finally: os.close(descriptor)
    else: raise ValueError('Invalid fixed native completion operation')
except (OSError, ValueError, RuntimeError, TypeError):
    sys.exit(1)
PYSLSNATIVEACK
}

sls_cancel_native_scope() {
  native_cancel_signal="$1"
  if [ -n "${native_completion_directory:-}" ]; then
    sls_native_completion_record cancel "$native_completion_directory" "$native_completion_nonce" "$1" || true
  fi
}

sls_bounded_native_command() {
  # Only these immutable root stages retain lease copies. Actual mutable
  # FreePBX/PHP children receive none through Popen(close_fds=True).
  /usr/bin/python3 -I /dev/fd/3 "${native_completion_directory:?}" "${native_completion_nonce:?}" "$@" 3<<'PYSLSBOUNDEDNATIVE'
import ctypes, errno, fcntl, json, math, os, re, select, signal, socket, stat, subprocess, sys, time

import json, os, re, stat, sys, tempfile, secrets

def completion_directory(name):
    if os.geteuid() != 0 or not re.fullmatch(r'/run/sls-native-command-[a-z0-9_]{8}', name):
        raise ValueError('Invalid root native completion directory')
    run = os.open('/run', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parent = os.fstat(run)
        if parent.st_uid != 0 or parent.st_mode & 0o022: raise ValueError('Unprotected native completion parent')
        descriptor = os.open(name.rsplit('/', 1)[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=run)
    finally: os.close(run)
    info = os.fstat(descriptor)
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(descriptor); raise ValueError('Unprotected native completion directory')
    return descriptor

def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def read_record(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1 or not 0 < before.st_size <= 2048): raise ValueError('Unsafe native completion record')
        body = os.read(descriptor, 2049)
        if (len(body) != before.st_size or identity(before) != identity(os.fstat(descriptor))
                or identity(before) != identity(os.stat(name, dir_fd=directory, follow_symlinks=False))):
            raise ValueError('Native completion record changed')
        return json.loads(body)
    finally: os.close(descriptor)

def write_record(directory, name, value):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        body = memoryview((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode())
        while body:
            count = os.write(descriptor, body)
            if count <= 0: raise OSError('Native completion publication failed')
            body = body[count:]
        os.fsync(descriptor)
    finally: os.close(descriptor)

def scope_record(directory, nonce):
    value = read_record(directory, 'scope.json')
    fields = {'schema','magic','nonce','forked','waiter_pid','waiter_start','supervisor_pid','supervisor_start'}
    if (not isinstance(value, dict) or set(value) != fields or type(value['schema']) is not int or value['schema'] != 1
            or value['magic'] != 'sls-native-scope-v1' or value['nonce'] != nonce or type(value['forked']) is not bool
            or any(type(value[key]) is not int or value[key] <= 0 for key in ('waiter_pid','waiter_start'))):
        raise ValueError('Invalid native scope binding')
    if value['forked']:
        if (any(type(value[key]) is not int or value[key] <= 0 for key in ('supervisor_pid','supervisor_start'))
                or value['waiter_pid'] == value['supervisor_pid']): raise ValueError('Invalid forked native scope')
    elif (type(value['supervisor_pid']) is not int or value['supervisor_pid'] != 0
            or type(value['supervisor_start']) is not int or value['supervisor_start'] != 0):
        raise ValueError('Invalid refused native scope')
    return value

def completion_record(directory, nonce):
    scope = scope_record(directory, nonce)
    value = read_record(directory, 'completed.json')
    if (not isinstance(value, dict) or set(value) != {'schema','magic','nonce','status','pid'}
            or type(value['schema']) is not int or value['schema'] != 1 or value['magic'] != 'sls-native-completion-v1'
            or value['nonce'] != nonce or type(value['status']) is not int or not 0 <= value['status'] <= 255
            or type(value['pid']) is not int or value['pid'] <= 0 or value['pid'] not in (scope['waiter_pid'],scope['supervisor_pid'])
            or (not scope['forked'] and value['status'] == 0)):
        raise ValueError('Invalid native completion binding')
    return value['status']

def complete(directory, nonce, status):
    try: return completion_record(directory, nonce)
    except FileNotFoundError: pass
    write_record(directory, 'completed.json', {'schema':1,'magic':'sls-native-completion-v1',
        'nonce':nonce,'status':status,'pid':os.getpid()})
    return completion_record(directory, nonce)


cancel_signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
cancelled_number = 0
def cancelled(number, frame):
    global cancelled_number
    if not cancelled_number: cancelled_number = number
for number in cancel_signals: signal.signal(number, cancelled)

completion_name, completion_nonce = sys.argv[1:3]
if not re.fullmatch(r'[a-f0-9]{64}', completion_nonce): raise ValueError('Invalid native invocation binding')
completion_fd = completion_directory(completion_name)
def start_tick(pid):
    with open('/proc/%d/stat' % pid, 'rb') as stream: return int(stream.read(65536).rsplit(b')', 1)[1].split()[19])
def own_children(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, 262145)
    if len(raw) > 262144 or any(not item.isdigit() for item in raw.split()): raise RuntimeError('Native child inventory is unavailable')
    return {int(item) for item in raw.split()}
def diagnostic(body):
    channel = None
    descriptor = None
    try:
        mode = os.fstat(2).st_mode
        if stat.S_ISSOCK(mode):
            channel = socket.socket(fileno=os.dup(2))
            channel.send(body, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        else:
            descriptor = os.dup(2) if stat.S_ISREG(mode) else os.open('/proc/self/fd/2',
                os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
            os.write(descriptor, body)
    except OSError: pass
    finally:
        if channel is not None: channel.close()
        if descriptor is not None: os.close(descriptor)

try:
    duration, grace = map(float, sys.argv[3:5])
    if not (math.isfinite(duration) and 0 < duration <= 1200 and math.isfinite(grace) and 0 < grace <= 5):
        raise ValueError('Invalid fixed native command budget')
    scope_deadline = time.monotonic() + duration
    caller_pidfd = os.pidfd_open(os.getppid())
    library = ctypes.CDLL(None, use_errno=True)
    if os.getsid(0) != os.getpid(): os.setsid()
    waiter_pid = os.getpid()
    waiter_start = start_tick(waiter_pid)
    waiter_children = os.open('/proc/self/task/%d/children' % os.getpid(), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    waiter_baseline = own_children(waiter_children)
    if library.prctl(36, 1, 0, 0, 0) != 0: raise OSError(ctypes.get_errno(), 'Native waiter adoption is unavailable')

    read_gate, write_gate = os.pipe2(os.O_CLOEXEC)
    supervisor_pid = os.fork()
except (OSError, ValueError, RuntimeError):
    write_record(completion_fd, 'scope.json', {'schema':1,'magic':'sls-native-scope-v1','nonce':completion_nonce,
        'forked':False,'waiter_pid':os.getpid(),'waiter_start':start_tick(os.getpid()),'supervisor_pid':0,'supervisor_start':0})
    diagnostic(b'Native root supervision is unavailable before admission; no mutable command was started.\n')
    sys.exit(complete(completion_fd, completion_nonce, 1))

def cancellation_record(directory, nonce):
    try: value = read_record(directory, 'cancel.json')
    except FileNotFoundError: return 0
    if (not isinstance(value, dict) or set(value) != {'schema','magic','nonce','signal'}
            or type(value['schema']) is not int or value['schema'] != 1 or value['magic'] != 'sls-native-cancel-v1'
            or value['nonce'] != nonce or type(value['signal']) is not int or value['signal'] not in cancel_signals):
        raise ValueError('Invalid native cancellation binding')
    return value['signal']

def retire_waiter_children():
    while True:
        try:
            owned = own_children(waiter_children) - waiter_baseline
            if not owned: return
            for pid in owned:
                try: descriptor = os.pidfd_open(pid)
                except ProcessLookupError: continue
                try:
                    if pid not in own_children(waiter_children) - waiter_baseline: continue
                    try: signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    except ProcessLookupError: pass
                    try: os.waitpid(pid, 0)
                    except ChildProcessError: pass
                finally: os.close(descriptor)
        except (OSError, ValueError, RuntimeError): time.sleep(.05)

def contain_scope():
    # No mutable writer can obtain this root-only completion capability. Keep
    # the independent root leases if a valid semantic result is unavailable.
    diagnostic(('CRITICAL: Native completion is unverified; independent root waiter %d retains leases. Preserve %s and transaction evidence.\n' % (os.getpid(), completion_name)).encode())
    for number in cancel_signals: signal.signal(number, signal.SIG_IGN)
    while True: time.sleep(1)

if supervisor_pid:
    os.close(read_gate)
    child_pidfd = None
    try:
        child_pidfd = os.pidfd_open(supervisor_pid)
        if supervisor_pid not in own_children(waiter_children) - waiter_baseline: raise RuntimeError('Native supervisor parentage changed')
        scope = {'schema':1,'magic':'sls-native-scope-v1','nonce':completion_nonce,'forked':True,
            'waiter_pid':waiter_pid,'waiter_start':waiter_start,
            'supervisor_pid':supervisor_pid,'supervisor_start':start_tick(supervisor_pid)}
        write_record(completion_fd, 'scope.json', scope)
        requested = cancelled_number or cancellation_record(completion_fd, completion_nonce)
        if not requested and select.select([caller_pidfd], [], [], 0)[0]: requested = signal.SIGTERM
        os.write(write_gate, ('cancel:%d\n' % requested).encode() if requested else b'go\n')
        os.close(write_gate); write_gate = None
        sent = 0
        while True:
            waited, raw = os.waitpid(supervisor_pid, os.WNOHANG)
            if waited: break
            requested = cancelled_number or cancellation_record(completion_fd, completion_nonce)
            if not requested and select.select([caller_pidfd], [], [], 0)[0]: requested = signal.SIGTERM
            if requested and requested != sent:
                try: signal.pidfd_send_signal(child_pidfd, requested)
                except ProcessLookupError: pass
                sent = requested
            # The inner stage owns the nominal deadline and TERM grace. This
            # independent watchdog retires it if that same total bound fails.
            if time.monotonic() >= scope_deadline + grace:
                try: signal.pidfd_send_signal(child_pidfd, signal.SIGKILL)
                except ProcessLookupError: pass
            time.sleep(.01)
        try: result = completion_record(completion_fd, completion_nonce)
        except FileNotFoundError:
            retire_waiter_children()
            result = complete(completion_fd, completion_nonce, os.waitstatus_to_exitcode(raw) if os.WIFEXITED(raw) and os.WEXITSTATUS(raw) else (128 + os.WTERMSIG(raw) if os.WIFSIGNALED(raw) else 1))
        if result: retire_waiter_children()
        os.close(child_pidfd); child_pidfd = None
        os.close(waiter_children); os.close(caller_pidfd); os.close(completion_fd)
        sys.exit(result)
    except (OSError, ValueError, RuntimeError):
        retire_waiter_children()
        contain_scope()
    finally:
        if write_gate is not None: os.close(write_gate)
        if child_pidfd is not None: os.close(child_pidfd)
else:
    os.close(write_gate)
    # The inherited descriptor belongs to the ancestor, not this fork role.
    # The supervisor below opens its own child inventory and baseline.
    os.close(waiter_children)
    gate = os.read(read_gate, 64)
    os.close(read_gate)
    if gate != b'go\n':
        try: scope_record(completion_fd, completion_nonce)
        except FileNotFoundError:
            write_record(completion_fd, 'scope.json', {'schema':1,'magic':'sls-native-scope-v1','nonce':completion_nonce,'forked':True,
                'waiter_pid':waiter_pid,'waiter_start':waiter_start,'supervisor_pid':os.getpid(),'supervisor_start':start_tick(os.getpid())})
        number = int(gate[7:-1]) if re.fullmatch(rb'cancel:(?:1|2|15)\n', gate) else 0
        sys.exit(complete(completion_fd, completion_nonce, 128 + number if number else 125))

import ctypes, errno, fcntl, math, os, signal, socket, stat, subprocess, sys, time

cancel_signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
cancelled_number = globals().get("cancelled_number", 0)
def cancelled(number, frame):
    global cancelled_number
    if not cancelled_number: cancelled_number = number

class Output:
    def __init__(self, target):
        self.socket = None
        mode = os.fstat(target).st_mode
        if stat.S_ISSOCK(mode):
            self.socket = socket.socket(fileno=os.dup(target))
            self.fd = self.socket.fileno()
        elif stat.S_ISREG(mode):
            # Share the original file offset; reopening an ordinary log file
            # could let the shell overwrite output after this command returns.
            self.fd = os.dup(target)
        else:
            # A separate open description avoids changing the shell's flags.
            self.fd = os.open('/proc/self/fd/%d' % target,
                os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
        self.pending = bytearray()
    def write(self, body):
        try:
            if self.socket is not None:
                return self.socket.send(body, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            return os.write(self.fd, body)
        except BlockingIOError: return 0
    def flush(self):
        if not self.pending: return False
        count = self.write(self.pending[:65536])
        if count: del self.pending[:count]
        return bool(count)
    def close(self):
        if self.socket is not None: self.socket.close()
        else: os.close(self.fd)

library = ctypes.CDLL(None, use_errno=True)
previous = ctypes.c_int()
if library.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'Native child supervision is unavailable')
children_fd = os.open('/proc/self/task/%d/children' % os.getpid(), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
def children():
    os.lseek(children_fd, 0, os.SEEK_SET)
    raw = os.read(children_fd, 262145)
    if len(raw) > 262144 or any(not value.isdigit() for value in raw.split()):
        raise RuntimeError('Native child inventory is unavailable')
    return {int(value) for value in raw.split()}
baseline = children()
if library.prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), 'Native child adoption is unavailable')
for number in cancel_signals: signal.signal(number, cancelled)
process = None
outputs = []
pipes = []
status = 1
cleanup = True
try:
    duration, grace = map(float, sys.argv[3:5])
    if not (math.isfinite(duration) and 0 < duration <= 1200
            and math.isfinite(grace) and 0 < grace <= 5):
        raise ValueError('Invalid fixed native command budget')
    # Start before the privilege transition, including runuser/PAM startup.
    deadline = scope_deadline
    outputs = [Output(1), Output(2)]
    process = subprocess.Popen(sys.argv[5:], stdin=None, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True, start_new_session=True, cwd='/')
    for stream, output in zip((process.stdout, process.stderr), outputs):
        os.set_blocking(stream.fileno(), False)
        pipes.append([stream, output, None])
    expired = None
    draining = False
    while True:
        now = time.monotonic()
        if not cancelled_number: cancelled_number = cancellation_record(completion_fd, completion_nonce)
        if not cancelled_number and select.select([caller_pidfd], [], [], 0)[0]: cancelled_number = signal.SIGTERM
        if cancelled_number: break
        result = process.poll()
        if now >= deadline and expired is None:
            expired = now
            status = 124
            if result is None:
                # Popen's unreaped session leader anchors this owned group.
                descriptor = os.pidfd_open(process.pid)
                try:
                    if process.pid in children() - baseline:
                        try: os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError: pass
                finally: os.close(descriptor)
        if expired is not None and now >= expired + grace:
            if result is None: status = 137
            break
        if result is not None and not draining:
            if expired is None: status = 128 - result if result < 0 else result
            draining = True
            # A successful service may outlive the CLI. Drain only bytes
            # already bounded by each actual pipe capacity, then close the
            # read ends. Such services are not explicitly killed on success.
            for pipe in pipes: pipe[2] = fcntl.fcntl(pipe[0].fileno(), fcntl.F_GETPIPE_SZ)
        progress = False
        for pipe in list(pipes):
            stream, output, remaining = pipe
            available = 131072 - len(output.pending)
            if available:
                count = min(65536, available, remaining if remaining is not None else 65536)
                try: body = os.read(stream.fileno(), count) if count else b''
                except BlockingIOError: body = None
                if body:
                    output.pending.extend(body)
                    if remaining is not None: pipe[2] -= len(body)
                    progress = True
                elif body == b'' or draining:
                    stream.close(); pipes.remove(pipe)
            progress = output.flush() or progress
        for output in outputs: progress = output.flush() or progress
        if draining and not pipes and not any(output.pending for output in outputs): break
        if expired is not None and result is not None and not progress: break
        if not progress: time.sleep(.01)
    cleanup = status != 0
except (OSError, ValueError, RuntimeError):
    status = 1
    cleanup = True
    if len(outputs) == 2:
        try: outputs[1].write(b'Native PBX command supervision failed; preserve transaction evidence.\n')
        except OSError: pass
finally:
    # A record-only handler cannot escape this boundary. Capture signals
    # pending before finalization, then make owned retirement noninterruptible.
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, cancel_signals)
    pending = signal.sigpending()
    cancellation = cancelled_number or next((number for number in cancel_signals if number in pending), 0)
    if cancellation:
        status = 128 + cancellation
        cleanup = True
    for number in cancel_signals: signal.signal(number, signal.SIG_IGN)
    if cleanup:
        # Reap only this invocation's adopted descendants, including setsid
        # hooks. Keep root leases fenced if retirement cannot be confirmed.
        reported = False
        while True:
            try:
                owned = children() - baseline
                if not owned: break
                for pid in owned:
                    try: descriptor = os.pidfd_open(pid)
                    except ProcessLookupError: continue
                    try:
                        if pid not in children() - baseline: continue
                        try: signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        except ProcessLookupError: pass
                        try: os.waitpid(pid, 0)
                        except ChildProcessError: pass
                    finally: os.close(descriptor)
            except (OSError, ValueError, RuntimeError):
                status = status or 1
                if not reported and len(outputs) == 2:
                    try: outputs[1].write(b'Native cleanup is incomplete; root worker leases remain held until owned children are reaped.\n')
                    except OSError: pass
                    reported = True
                time.sleep(.05)
    for stream in (getattr(process, 'stdout', None), getattr(process, 'stderr', None)):
        if stream is not None: stream.close()
    for output in outputs: output.close()
    os.close(children_fd)
    if library.prctl(36, previous.value, 0, 0, 0) != 0:
        status = 1
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
status = complete(completion_fd, completion_nonce, status)
os.close(caller_pidfd); os.close(completion_fd)
sys.exit(status)
PYSLSBOUNDEDNATIVE
}

run_as_asterisk() ( run_runtime_account bounded "$@"; )
run_supervised_as_asterisk() ( run_runtime_account supervised "$@"; )
run_bounded_as_asterisk() ( run_runtime_account bounded "$@"; )

run_runtime_account() (
  local mode="$1"; shift
  case "$mode" in bounded|supervised) ;; *) return 64 ;; esac
  local uid gid
  uid="$(id -u asterisk 2>/dev/null)" || { log 'The asterisk service account is missing.'; return 1; }
  [[ "$uid" =~ ^[0-9]+$ ]] && [ "$uid" -ne 0 ] || { log 'The asterisk service account must have a nonzero UID.'; return 1; }
  gid="$(id -g asterisk 2>/dev/null)" || { log 'The asterisk primary group is unavailable.'; return 1; }
  [[ "$gid" =~ ^[0-9]+$ ]] && [ "$gid" -ne 0 ] || { log 'The asterisk service account must have a nonzero primary GID.'; return 1; }
  local -a child_environment=(
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    "LANG=C.UTF-8"
    "LC_ALL=C.UTF-8"
  )
  while [ "$#" -gt 0 ] && [[ "$1" == *=* ]]; do
    case "$1" in
      SLS_MODULE_NAME=*|SLS_CONFIG=*|SLS_UNINSTALL_CONFIG_DECODER=*|SLS_CONFIGURED_AMI_USERNAME=*|SLS_AMI_SECRET_HASH=*|SLS_AMI_OWNERSHIP_HELPER=*|SLS_FILE_AMI_USERNAME=*|SLS_DATA_DIR=*|SLS_VERIFY_MODULE=*)
        child_environment+=("$1")
        ;;
      *)
        printf '%s\n' "Refusing an unapproved runtime-account environment variable." >&2
        return 64
        ;;
    esac
    shift
  done
  [ "$#" -gt 0 ] || return 64
  cd / || return 1
  local -a native_deadline=()
  if [ "$mode" = bounded ]; then native_deadline=(/usr/bin/timeout --signal=TERM --kill-after=5 1200); fi
  local -a native_operation=("${native_deadline[@]}" "$@")
  [ "${native_operation[0]:-}" = /usr/bin/timeout ] && \
    [ "${native_operation[1]:-}" = --signal=TERM ] && \
    [[ "${native_operation[2]:-}" = --kill-after=* ]] || return 64
  run_without_uninstall_worker_descriptors sls_bounded_native_command \
    "${native_operation[3]}" "${native_operation[2]#--kill-after=}" \
    /usr/bin/env -i "${child_environment[@]}" /usr/sbin/runuser -u asterisk -- \
    "${native_operation[@]}"
)

run_without_uninstall_worker_descriptors() (
  # Keep a root waiter alive with the shared worker descriptions while the
  # actual native hook runs. Mutable PHP gets no unlock-capable descriptor.
  local native_completion_directory="" native_completion_nonce="" native_cancel_signal=0
  if [ "${1:-}" = sls_bounded_native_command ]; then
    local details
    local -a completion_fields=()
    trap 'sls_cancel_native_scope 15' TERM
    trap 'sls_cancel_native_scope 2' INT
    trap 'sls_cancel_native_scope 1' HUP
    details="$(sls_native_completion_record prepare)" || return 1
    mapfile -t completion_fields <<<"$details"
    [ "${#completion_fields[@]}" -eq 2 ] || return 1
    native_completion_directory="${completion_fields[0]}"
    native_completion_nonce="${completion_fields[1]}"
    if [ "$native_cancel_signal" -ne 0 ]; then sls_cancel_native_scope "$native_cancel_signal"; fi
  else
    trap ':' TERM INT HUP
  fi
  (
    trap - TERM INT HUP
    if [ -z "$native_completion_directory" ]; then
      close_inherited_maintenance_lock_fds
      close_inherited_uninstall_worker_fds
    fi
    if [ -n "${UNINSTALL_WORKER_PIPE:-}" ]; then exec {UNINSTALL_WORKER_PIPE}>&-; fi
    if [ -n "${UNINSTALL_WORKER_RESPONSE_FD:-}" ]; then exec {UNINSTALL_WORKER_RESPONSE_FD}<&-; fi
    "$@"
  ) <&0 &
  child=$!; status=0
  while true; do
    if wait "$child"; then status=0; break; else status=$?; fi
    kill -0 "$child" 2>/dev/null || break
  done
  if [ -n "$native_completion_directory" ]; then
    local completed_status warned=0
    while true; do
      if completed_status="$(sls_native_completion_record verify "$native_completion_directory" "$native_completion_nonce")"; then
        # Semantic completion, not an intermediate waiter's exit, governs
        # progress. A dead root waiter must not start rollback prematurely.
        status="$completed_status"
        rm -f -- "$native_completion_directory/completed.json" "$native_completion_directory/scope.json" "$native_completion_directory/cancel.json"
        rmdir -- "$native_completion_directory" 2>/dev/null || true
        break
      fi
      if [ "$warned" -eq 0 ]; then
        printf 'CRITICAL: Native completion is unverified; root waiter PID %s retains leases and will not begin recovery. Preserve %s and transaction/log evidence.\n' "$BASHPID" "$native_completion_directory" >&2
        warned=1
      fi
      sleep .05
    done
  fi
  exit "$status"
)
asterisk() { run_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 20 /usr/sbin/asterisk "$@"; }
UNINSTALL_WORKER_PIPE=""
UNINSTALL_WORKER_RESPONSE_FD=""
UNINSTALL_GUARD_REQUIRED=0

# Open only a root-owned regular file through trusted directories. Creation is
# exclusive; an existing file is never truncated or written before fd identity
# verification. Sticky root-owned /tmp and /run/lock are permitted. Only log
# callers may adopt a legacy asterisk-owned regular file; locks remain strict.
open_root_owned_file() {
  local output_variable="$1" protected_path="$2" file_purpose="${3:-lock}"
  local protected_identity opened_identity protected_fd
  protected_identity="$(/usr/bin/python3 -I - "$protected_path" "$file_purpose" <<'PY'
import os
import pwd
import stat
import sys

path = sys.argv[1]
purpose = sys.argv[2]
if purpose not in {"lock", "log"}:
    raise SystemExit("Unknown protected file purpose.")
parts = path.split("/")[1:]
if not path.startswith("/") or not parts or any(part in {"", ".", ".."} for part in parts):
    raise SystemExit(1)
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
parent = os.open("/", directory_flags)
try:
    for component in parts[:-1]:
        child = os.open(component, directory_flags, dir_fd=parent)
        os.close(parent)
        parent = child
        metadata = os.fstat(parent)
        if metadata.st_uid != 0 or (metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX):
            raise SystemExit(1)
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(parts[-1], flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
    except FileExistsError:
        descriptor = os.open(parts[-1], flags, dir_fd=parent)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SystemExit("Refusing a linked or non-regular protected file.")
        if purpose == "log":
            allowed_owners = {0}
            try:
                allowed_owners.add(pwd.getpwnam("asterisk").pw_uid)
            except KeyError:
                pass
            if metadata.st_uid not in allowed_owners:
                raise SystemExit("Protected logs must be owned by root or the Asterisk service account.")
            # Old installers/FreePBX chown can leave service-owned logs in
            # sticky /tmp. O_CREAT would fail even as root on Debian. The
            # existing file was opened without it; secure this exact inode
            # before Bash reopens it, without following or replacing links.
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o600)
        elif metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise SystemExit(1)
        current = os.fstat(descriptor)
        entry = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (entry.st_dev, entry.st_ino) or current.st_nlink != 1 or current.st_uid != 0 or current.st_mode & 0o022:
            raise SystemExit("Protected file changed while it was being opened.")
        print(f"{metadata.st_dev}:{metadata.st_ino}")
    finally:
        os.close(descriptor)
finally:
    os.close(parent)
PY
)" || return 1
  exec {protected_fd}>>"$protected_path" || return 1
  opened_identity="$(stat -Lc '%d:%i' "/proc/${BASHPID}/fd/$protected_fd" 2>/dev/null)" || opened_identity=""
  if [ "$opened_identity" != "$protected_identity" ]; then
    exec {protected_fd}>&-
    return 1
  fi
  chmod 0600 "/proc/${BASHPID}/fd/$protected_fd" || {
    exec {protected_fd}>&-
    return 1
  }
  printf -v "$output_variable" '%s' "$protected_fd"
}

prepare_uninstall_logs() {
  open_root_owned_file MODULE_UNINSTALL_LOG_FD "$MODULE_UNINSTALL_LOG_PATH" log || {
    log "The uninstall log could not be opened safely: $MODULE_UNINSTALL_LOG_PATH. No uninstall changes were made."
    return 1
  }
  open_root_owned_file STOCK_RESTORE_LOG_FD "$STOCK_RESTORE_LOG_PATH" log || {
    log "The stock-module restore log could not be opened safely: $STOCK_RESTORE_LOG_PATH. No uninstall changes were made."
    return 1
  }
  # Keep writes attached to the checked inode even if FreePBX changes its
  # ownership or a log rotation replaces the original pathname during removal.
  MODULE_UNINSTALL_LOG="/proc/${BASHPID}/fd/$MODULE_UNINSTALL_LOG_FD"
  STOCK_RESTORE_LOG="/proc/${BASHPID}/fd/$STOCK_RESTORE_LOG_FD"
  : >"$MODULE_UNINSTALL_LOG"
  : >"$STOCK_RESTORE_LOG"
}

log() {
  printf '%s\n' "$*"
}

require_freepbx() {
  local required_command
  [ "${EUID:-$(id -u)}" -eq 0 ] || {
    log "Run the uninstaller as root."
    exit 1
  }
  for required_command in /usr/sbin/fwconsole /usr/sbin/asterisk /usr/sbin/runuser /usr/bin/php /usr/bin/python3 /usr/bin/gpg /usr/bin/crontab /usr/bin/flock /usr/bin/readlink /usr/bin/timeout /usr/bin/base64 /usr/bin/sha256sum /usr/bin/systemctl /usr/bin/su; do
    [ -x "$required_command" ] || {
      log "Required uninstall prerequisite is unavailable: $required_command. No uninstall changes were made."
      exit 1
    }
  done
  [ -d /var/www/html/admin/modules ] || {
    log "/var/www/html/admin/modules not found. This does not look like a FreePBX server."
    exit 1
  }
  [ -r /etc/freepbx.conf ] || {
    log "/etc/freepbx.conf is missing or unreadable."
    exit 1
  }
  run_bounded_as_asterisk /usr/bin/php -d pcre.jit=0 -r '
$bootstrap_settings = ["freepbx_auth" => false, "skip_astman" => true];
require "/etc/freepbx.conf";
\FreePBX::Database()->query("SELECT 1");
exit(0);
' >/dev/null || {
    log "FreePBX bootstrap or database access failed. No uninstall changes were made."
    exit 1
  }
}

acquire_maintenance_coordination() {
  local lock_file="${SLS_MASS_NOTIFY_MAINTENANCE_LOCK:-/run/lock/sls-mass-notify-maintenance.lock}"
  local descriptor descriptor_path descriptor_target lock_parent

  [[ "$lock_file" = /* ]] && [ "$lock_file" != "/" ] || {
    log "Unsafe maintenance lock path."
    return 1
  }
  lock_parent="$(dirname -- "$lock_file")"
  [ -d "$lock_parent" ] && [ ! -L "$lock_parent" ] || {
    log "The maintenance lock parent must already exist as a real directory: $lock_parent"
    return 1
  }
  [ ! -L "$lock_file" ] || {
    log "Refusing a symbolic-link maintenance lock: $lock_file"
    return 1
  }

  # UI uninstalls are launched by the maintenance worker while it holds this
  # lock. Reuse that inherited lock; direct CLI uninstalls acquire their own.
  for descriptor_path in "/proc/${BASHPID}/fd/"*; do
    [ -e "$descriptor_path" ] || continue
    descriptor_target="$(readlink -f -- "$descriptor_path" 2>/dev/null || true)"
    [ "$descriptor_target" = "$lock_file" ] || continue
    descriptor="${descriptor_path##*/}"
    if [[ "$descriptor" =~ ^[0-9]+$ ]] && flock -n "$descriptor"; then
      UNINSTALL_MAINTENANCE_LOCK_FD="$descriptor"
      return 0
    fi
  done

  open_root_owned_file UNINSTALL_MAINTENANCE_LOCK_FD "$lock_file" || {
    log "The protected maintenance lock could not be opened safely."
    return 1
  }
  flock -w 120 "$UNINSTALL_MAINTENANCE_LOCK_FD" || {
    log "Another Mass Notify maintenance, update, repair, or uninstall operation is still running."
    return 1
  }
}

uninstall_recovery_workspace() {
  /usr/bin/python3 -I - "$1" <<'PYUNINSTALLSPACE'
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import tempfile
prefix = sys.argv[1]
if not re.fullmatch(r'sls-uninstall-(?:signer|decoder|transaction|stock-review)', prefix):
    raise SystemExit('Invalid uninstall recovery workspace.')
parent = Path('/var/lib/sls-mass-notify-uninstaller')
account = pwd.getpwnam('asterisk')
fd = os.open(parent.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    pm = os.fstat(fd)
    if pm.st_uid != 0 or pm.st_mode & 0o022:
        raise SystemExit('Uninstall recovery parent is unsafe.')
    try:
        os.mkdir(parent.name, 0o750, dir_fd=fd)
        created = True
    except FileExistsError:
        created = False
    child = os.open(parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        if created:
            os.fchown(child, 0, account.pw_gid)
            os.fchmod(child, 0o750)
        info = os.fstat(child)
        if info.st_uid != 0 or info.st_gid != account.pw_gid or stat.S_IMODE(info.st_mode) != 0o750:
            raise SystemExit('Existing uninstall recovery storage requires review; it was not adopted.')
        os.fsync(child); os.fsync(fd)
        workspace = Path(tempfile.mkdtemp(prefix=prefix+'.', dir=parent))
        workspace_fd = os.open(workspace.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=child)
        try:
            info = os.fstat(workspace_fd)
            named = os.stat(workspace.name, dir_fd=child, follow_symlinks=False)
            if ((info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                    or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
                raise SystemExit('New uninstall recovery directory changed during creation.')
            os.fsync(workspace_fd)
        finally:
            os.close(workspace_fd)
        os.fsync(child)
    finally:
        os.close(child)
finally:
    os.close(fd)
print(workspace)
PYUNINSTALLSPACE
}

seal_uninstall_recovery_inputs() {
  /usr/bin/timeout 60 /usr/bin/python3 -I - "$UNINSTALL_TRANSACTION_DIR" "${RECOVERY_SIGNER_DIR:-}" "${RECOVERY_DECODER_DIR:-}" <<'PYSYNCUNINSTALL'
import os, pathlib, stat, sys
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
count = total = 0
def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
def directory(path):
    path = pathlib.Path(path)
    if not path.is_absolute() or any(part in ('.', '..') for part in str(path).split('/')):
        raise RuntimeError('Invalid private recovery evidence path')
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise RuntimeError('Unprotected recovery evidence parent')
        return fd
    except BaseException:
        os.close(fd); raise
def sync_tree(fd, depth=0):
    global count, total
    if depth > 32:
        raise RuntimeError('Private recovery evidence nesting exceeds its bound')
    for name in os.listdir(fd):
        count += 1
        if count > 100000:
            raise RuntimeError('Private recovery evidence inventory exceeds its bound')
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if before.st_uid != 0 or before.st_mode & 0o022:
            raise RuntimeError('Unprotected private recovery evidence entry')
        if stat.S_ISDIR(before.st_mode):
            child = os.open(name, flags, dir_fd=fd)
        elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
            total += before.st_size
            if total > 2 * 1024 ** 3:
                raise RuntimeError('Private recovery evidence size exceeds its bound')
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        else:
            raise RuntimeError('Unsupported private recovery evidence entry')
        try:
            if identity(os.fstat(child)) != identity(before):
                raise RuntimeError('Private recovery evidence changed before synchronization')
            if stat.S_ISDIR(before.st_mode):
                sync_tree(child, depth + 1)
            else:
                os.fsync(child)
            if (identity(os.fstat(child)) != identity(before)
                    or identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != identity(before)):
                raise RuntimeError('Private recovery evidence changed during synchronization')
        finally:
            os.close(child)
    os.fsync(fd)
for value in sys.argv[1:]:
    if not value: continue
    path = pathlib.Path(value)
    fd = directory(path)
    try:
        info = os.fstat(fd)
        if info.st_mode & 0o027:
            raise RuntimeError('Recovery evidence must remain private')
        sync_tree(fd)
    finally:
        os.close(fd)
    parent = directory(path.parent)
    try: os.fsync(parent)
    finally: os.close(parent)
PYSYNCUNINSTALL
}

record_uninstall_stage() {
  [ -n "$UNINSTALL_TRANSACTION_DIR" ] || return 1
  if [ "$1" = prepared ]; then seal_uninstall_recovery_inputs || return $?; fi
  /usr/bin/python3 -I - "$UNINSTALL_TRANSACTION_DIR" "$1" "$UNINSTALL_APPROVED_SOURCE" "$RECOVERY_SIGNER_DIR" "$RECOVERY_DECODER_DIR" "$PURGE_CONFIG" <<'PYREMOVALSTATE'
import json, os, secrets, stat, sys, time
from pathlib import Path
path=Path(sys.argv[1]);phase=sys.argv[2]
if os.geteuid()!=0 or phase not in {'prepared','services','module','integration','runtime','verification','complete','failed'}:
    raise SystemExit('Invalid uninstall transaction stage.')
if path.resolve()!=path:
    raise SystemExit('Uninstall transaction path is not canonical.')
fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
temporary='.state-'+secrets.token_hex(12)
try:
    info=os.fstat(fd)
    if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
        raise SystemExit('Uninstall transaction directory is unsafe.')
    before=None
    try:
        handle=os.open('transaction.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    except FileNotFoundError:
        state={'schema':1,'created_at':int(time.time()),'history':[]}
    else:
        try:
            before=os.fstat(handle)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1 or before.st_mode&0o077 or before.st_size>16384:
                raise SystemExit('Uninstall transaction file is unsafe.')
            def unique_object(pairs):
                result={}
                for key,value in pairs:
                    if key in result: raise ValueError('duplicate JSON member')
                    result[key]=value
                return result
            state=json.loads(os.read(handle,16385), object_pairs_hook=unique_object,
                             parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON number')))
        finally:os.close(handle)
        if not isinstance(state,dict) or state.get('schema')!=1 or not isinstance(state.get('history'),list) or len(state['history'])>=64:
            raise SystemExit('Uninstall transaction is damaged or full; preserve it for review.')
    state.update(phase=phase,updated_at=max(int(time.time()),state['created_at']),approved_source=sys.argv[3],
                 recovery_signer=sys.argv[4],recovery_decoder=sys.argv[5],configuration_snapshot='',purge=sys.argv[6]=='1')
    state['history'].append({'phase':phase,'at':state['updated_at']})
    body=(json.dumps(state,separators=(',',':'))+'\n').encode()
    if len(body)>16384:raise SystemExit('Uninstall transaction exceeds its bound.')
    output=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
    with os.fdopen(output,'wb') as target:target.write(body);target.flush();os.fsync(target.fileno())
    try:current=os.stat('transaction.json',dir_fd=fd,follow_symlinks=False)
    except FileNotFoundError:current=None
    if (before is None)!=(current is None) or (before is not None and (before.st_dev,before.st_ino)!=(current.st_dev,current.st_ino)):
        raise SystemExit('Uninstall transaction changed during its commit.')
    os.replace(temporary,'transaction.json',src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd)
finally:
    try:
        os.unlink(temporary,dir_fd=fd)
        os.fsync(fd)
    except FileNotFoundError:pass
    os.close(fd)
PYREMOVALSTATE
}

snapshot_local_signer() {
  local candidate=""
  local trust_helper="${SLS_MASS_NOTIFY_TRUST_HELPER_SOURCE:-/usr/local/bin/sls_mass_notify/sls_module_trust.py}"
  local -a candidates=()

  if [ -n "$UNINSTALL_APPROVED_SOURCE" ]; then
    RECOVERY_SIGNER_DIR="$(uninstall_recovery_workspace sls-uninstall-signer)" || return 1
    chmod 0700 "$RECOVERY_SIGNER_DIR" || return 1
    RECOVERY_DECODER_DIR="$(uninstall_recovery_workspace sls-uninstall-decoder)" || return 1
    chown root:asterisk "$RECOVERY_DECODER_DIR" && chmod 0750 "$RECOVERY_DECODER_DIR" || return 1
    /usr/bin/python3 -I - "$UNINSTALL_APPROVED_SOURCE/bin/sls_mass_notify/sls_module_trust.py" "$UNINSTALL_APPROVED_SOURCE" "$RECOVERY_SIGNER_DIR" "$RECOVERY_DECODER_DIR" <<'PYAPPROVEDSNAPSHOT' || return 1
from pathlib import Path
import ast, os, pwd, re, sys, types
path, source, target, decoder = map(Path, sys.argv[1:])
module = types.ModuleType('sls_uninstall_snapshot_trust'); module.__file__ = str(path)
exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
data, generation = module.load(Path('/var/lib/sls-mass-notify-trust'), 'slsmassnotifyserver')
if source != generation / 'module' or data['source']['kind'] != 'publisher-ed25519':
    raise SystemExit('Uninstall source is not the approved publisher generation')
names = {'bin/sign_sls_mass_notify_local_sig.sh':'sign_sls_mass_notify_local_sig.sh',
         'bin/sls_mass_notify/sls_module_trust.py':'sls_module_trust.py',
         'bin/sls_mass_notify/sls_install_guard.py':'sls_install_guard.py',
         'bin/sls_mass_notify/sls_install_idle.py':'sls_install_idle.py',
         'bin/sls_mass_notify/sls_installer_recovery.py':'sls_installer_recovery.py',
         'bin/sls_mass_notify/sls_audio_state.py':'sls_audio_state.py',
         'bin/sls_mass_notify/sls_config_crypto.py':'sls_config_crypto.py',
         'PhoneEventService.php':'PhoneEventService.php'}
optional = 'bin/sls_mass_notify/sls_legacy_permissions.py'
if optional in data['files']: names[optional] = 'sls_legacy_permissions.py'
for filename in ('sls_upgrade_trust.py','sls_release_trust.py','freepbx-mirror-signing.pub'):
    name='bin/sls_mass_notify/'+filename
    if name in data['files']:names[name]=filename
for name, filename in names.items():
    entry = data['files'].get(name)
    if not entry: raise SystemExit('Signed uninstall helper is missing: ' + name)
    body = module.read(source / name, 2 * 1024 * 1024, protected=True)
    if module.digest(body) != entry['sha256']:
        raise SystemExit('Signed uninstall helper changed: ' + name)
    fd = os.open(target / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, 'wb') as output:
        output.write(body); output.flush(); os.fsync(output.fileno())
service = (target / 'PhoneEventService.php').read_bytes()
templates = re.findall(rb"return <<<'UNIT'\n(.*?)\nUNIT;", service, re.S)
if len(templates) != 1 or not templates[0].startswith(b'# Managed by SLS Mass Notify Server\n[Unit]\n'):
    raise SystemExit('The signed collector unit template is unavailable or ambiguous')
fd = os.open(target / 'collector-unit.txt', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as output:
    # PHP excludes the line break introducing its heredoc terminator.
    output.write(templates[0]); output.flush(); os.fsync(output.fileno())
approval = {'schema': 1, 'source': 'publisher-verified-previous-release', 'version': data['version'],
            'archive_sha256': data['source']['archive_sha256'],
            'files': {str(source / name): entry['sha256'] for name, entry in data['files'].items()}}
fd = os.open(target / 'uninstall-approval.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(__import__('json').dumps(approval, separators=(',', ':')).encode()); output.flush(); os.fsync(output.fileno())
name = 'bin/sls_mass_notify/sls_config_crypto.php'
entry = data['files'].get(name)
if not entry: raise SystemExit('Signed configuration decoder is missing')
body = module.read(source / name, 2 * 1024 * 1024, protected=True)
if module.digest(body) != entry['sha256']: raise SystemExit('Signed configuration decoder changed')
fd = os.open(decoder / 'sls_config_crypto.php', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
with os.fdopen(fd, 'wb') as output:
    os.fchown(output.fileno(), 0, pwd.getpwnam('asterisk').pw_gid)
    output.write(body); output.flush(); os.fsync(output.fileno())
name = 'AmiUserOwnership.php'
entry = data['files'].get(name)
if not entry: raise SystemExit('The current local uninstaller requires its signed AMI ownership helper. Preserve the approved generation; no teardown was started.')
body = module.read(source / name, 2 * 1024 * 1024, protected=True)
if module.digest(body) != entry['sha256']: raise SystemExit('Signed AMI ownership helper changed')
fd = os.open(decoder / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
with os.fdopen(fd, 'wb') as output:
    os.fchown(output.fileno(), 0, pwd.getpwnam('asterisk').pw_gid)
    output.write(body); output.flush(); os.fsync(output.fileno())
# Older signed generations have no stop-only admission command. Their source
# may establish an already-offline result, but must never perform this write.
admission = 'bin/sls_mass_notify/sls_phone_admission.py'
entry = data['files'].get(admission)
if entry is not None:
    body = module.read(source / admission, 2 * 1024 * 1024, protected=True)
    if module.digest(body) != entry['sha256']:
        raise SystemExit('Signed phone admission helper changed')
    supported = any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'add_argument' and node.args
                    and isinstance(node.args[0], ast.Constant) and node.args[0].value == '--retire-stopped-collector'
                    for node in ast.walk(ast.parse(body)))
    if supported:
        for filename in ('sls_phone_admission.py', 'sls_nws_delivery_claims.py', 'sls_cluster_guard.py',
                         'sls_config_crypto.py', 'sls_atomic_json.py'):
            name = 'bin/sls_mass_notify/' + filename
            source_entry = data['files'].get(name)
            if not source_entry: raise SystemExit('Missing signed collector teardown input: ' + name)
            contents = module.read(source / name, 2 * 1024 * 1024, protected=True)
            if module.digest(contents) != source_entry['sha256']:
                raise SystemExit('Changed signed collector teardown input: ' + name)
            fd = os.open(decoder / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, 'wb') as output:
                os.fchown(output.fileno(), 0, pwd.getpwnam('asterisk').pw_gid)
                output.write(contents); output.flush(); os.fsync(output.fileno())
PYAPPROVEDSNAPSHOT
    RECOVERY_SIGNER="$RECOVERY_SIGNER_DIR/sign_sls_mass_notify_local_sig.sh"
    RECOVERY_CONFIG_DECODER="$RECOVERY_DECODER_DIR/sls_config_crypto.php"
    RECOVERY_AMI_OWNERSHIP_HELPER="$RECOVERY_DECODER_DIR/AmiUserOwnership.php"
    if [ -f "$RECOVERY_DECODER_DIR/sls_phone_admission.py" ]; then
      RECOVERY_COLLECTOR_HELPER="$RECOVERY_DECODER_DIR/sls_phone_admission.py"
    fi
    bash -n "$RECOVERY_SIGNER" || return 1
    return 0
  fi

  if [ -n "${SLS_MASS_NOTIFY_SIGNER_SOURCE:-}" ]; then
    candidates+=("$SLS_MASS_NOTIFY_SIGNER_SOURCE")
  fi
  candidates+=(
    "/usr/local/sbin/sign_sls_mass_notify_local_sig.sh"
    )

  for candidate in "${candidates[@]}"; do
    [ -e "$candidate" ] || continue
    [ -f "$candidate" ] && [ ! -L "$candidate" ] || {
      log "Refusing an unsafe local signer while preparing uninstall: $candidate"
      return 1
    }
    # Snapshot only an inventory-aware signer. Older permissive signers must
    # never become a fallback authorization path after removing the module.
    grep -Fq 'publish_candidate_transactionally' "$candidate" \
      && grep -Fq 'acquire_signing_lock' "$candidate" \
      && grep -Fq 'approved_module_hashes' "$candidate" || continue
    [ "$(stat -c '%U:%G' "$candidate" 2>/dev/null || true)" = "root:root" ] \
      && [ "$(stat -c '%a' "$candidate" 2>/dev/null || true)" = "755" ] || {
      log "The transactional local signer has unsafe ownership or permissions: $candidate"
      return 1
    }
    bash -n "$candidate" || {
      log "The installed PBX-local signer is not valid Bash: $candidate"
      return 1
    }
    RECOVERY_SIGNER_DIR="$(uninstall_recovery_workspace sls-uninstall-signer)" || return 1
    chmod 0700 "$RECOVERY_SIGNER_DIR"
    RECOVERY_SIGNER="$RECOVERY_SIGNER_DIR/sign_sls_mass_notify_local_sig.sh"
    install -m 0700 -o root -g root "$candidate" "$RECOVERY_SIGNER" || return 1
    cmp -s "$candidate" "$RECOVERY_SIGNER" || {
      log "Unable to snapshot the PBX-local signer exactly."
      return 1
    }
    /usr/bin/python3 -I - "$trust_helper" "$RECOVERY_SIGNER_DIR/sls_module_trust.py" <<'PYTRUSTCOPY' || return 1
import os
from pathlib import Path
import stat
import sys
source, target = map(Path, sys.argv[1:])
for item in [source] + list(source.parents)[:-1]:
    info = item.lstat()
    if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 and not (item != source and info.st_mode & stat.S_ISVTX)):
        raise SystemExit("Protected module trust helper has an unsafe path")
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
with os.fdopen(fd, "rb") as handle:
    info = os.fstat(handle.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 256 * 1024:
        raise SystemExit("Protected module trust helper is unsafe")
    body = handle.read(256 * 1024 + 1)
    after = os.fstat(handle.fileno())
    if len(body) != info.st_size or len(body) > 256 * 1024 or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise SystemExit("Protected module trust helper changed during snapshot")
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
with os.fdopen(fd, "wb") as handle:
    handle.write(body); handle.flush(); os.fsync(handle.fileno())
PYTRUSTCOPY
    return 0
  done
  return 0
}

cleanup_recovery_signer() {
  release_uninstall_workers
  if [ -n "$RECOVERY_SIGNER_DIR" ] && [ -d "$RECOVERY_SIGNER_DIR" ]; then
    find "$RECOVERY_SIGNER_DIR" -depth -delete 2>/dev/null || true
  fi
  RECOVERY_SIGNER_DIR=""
  RECOVERY_SIGNER=""
  if [ -n "$RECOVERY_DECODER_DIR" ] && [ -d "$RECOVERY_DECODER_DIR" ]; then
    find "$RECOVERY_DECODER_DIR" -depth -delete 2>/dev/null || true
  fi
  RECOVERY_DECODER_DIR=""
  RECOVERY_COLLECTOR_HELPER=""
}

release_uninstall_workers() {
  if [ -n "${UNINSTALL_WORKER_PIPE:-}" ]; then
    # A rejected/dead child may have already closed its pipe. Contain SIGPIPE
    # in this subshell so EXIT cleanup still preserves the original result.
    ( trap '' PIPE; printf 'release\n' >&"$UNINSTALL_WORKER_PIPE" ) 2>/dev/null || true
    exec {UNINSTALL_WORKER_PIPE}>&-
    UNINSTALL_WORKER_PIPE=""
  fi
  if [ -n "${UNINSTALL_WORKER_PID:-}" ]; then
    wait "$UNINSTALL_WORKER_PID" 2>/dev/null || true
    UNINSTALL_WORKER_PID=""
  fi
  if [ -n "${UNINSTALL_WORKER_RESPONSE_FD:-}" ]; then
    exec {UNINSTALL_WORKER_RESPONSE_FD}<&-
    UNINSTALL_WORKER_RESPONSE_FD=""
  fi
  # Closing only this caller's descriptions cannot unlock an actual native
  # writer still protected by its own root waiter. Never use LOCK_UN here.
  close_inherited_uninstall_worker_fds
}

close_inherited_uninstall_worker_fds() {
  local descriptor
  for descriptor in "${UNINSTALL_WORKER_LEASE_FDS[@]}"; do exec {descriptor}>&-; done
  UNINSTALL_WORKER_LEASE_FDS=()
}

prepare_uninstall_worker_descriptors() {
  local helper="$1" prepare_pid prepare_input prepare_output response mapping descriptor remote status=0
  local -a remote_fds=()
  coproc SLS_UNINSTALL_WORKER_PREPARE {
    exec /usr/bin/python3 -I "$helper" --data "$DATA_DIR" --timeout 120 prepare
  }
  prepare_pid="${SLS_UNINSTALL_WORKER_PREPARE_PID:-}"
  prepare_input="${SLS_UNINSTALL_WORKER_PREPARE[1]:-}"; prepare_output="${SLS_UNINSTALL_WORKER_PREPARE[0]:-}"
  if [ -z "$prepare_pid" ] || [ -z "$prepare_input" ] || [ -z "$prepare_output" ] \
    || ! exec {prepare_input}>&"$prepare_input" || ! exec {prepare_output}<&"$prepare_output"; then
    status=1
  elif ! IFS= read -r -t 120 response <&"$prepare_output" || [[ "$response" != 'prepared '* ]]; then
    status=1
  else
    mapping="$(/usr/bin/python3 -I - "$prepare_pid" "${response#prepared }" <<'PYPREPAREUNINSTALLFDS'
import json, sys
if len(sys.argv[2]) > 16384: raise SystemExit('Prepared descriptor response exceeds bound')
value=json.loads(sys.argv[2])
if (type(value) is not dict or set(value)!={'schema','pid','fds'} or type(value['schema']) is not int or value['schema']!=1
        or type(value['pid']) is not int or value['pid']!=int(sys.argv[1]) or type(value['fds']) is not list
        or not 1<=len(value['fds'])<=1100 or any(type(fd) is not int or not 3<=fd<=9999999 for fd in value['fds'])
        or len(set(value['fds']))!=len(value['fds'])):
    raise SystemExit('Invalid prepared worker descriptor inventory')
for fd in value['fds']: print(fd)
PYPREPAREUNINSTALLFDS
    )" || status=1
    if [ "$status" -eq 0 ]; then
      mapfile -t remote_fds <<<"$mapping"
      for remote in "${remote_fds[@]}"; do
        if ! exec {descriptor}<"/proc/$prepare_pid/fd/$remote"; then status=1; break; fi
        UNINSTALL_WORKER_LEASE_FDS+=("$descriptor")
      done
    fi
  fi
  if [ -n "$prepare_input" ]; then
    ( trap '' PIPE; printf 'release\n' >&"$prepare_input" ) 2>/dev/null || true
    exec {prepare_input}>&-
  fi
  if [ -n "$prepare_output" ]; then exec {prepare_output}<&-; fi
  [ -z "$prepare_pid" ] || wait "$prepare_pid" 2>/dev/null || status=1
  if [ "$status" -ne 0 ]; then
    close_inherited_uninstall_worker_fds
    log 'The authenticated uninstall guard could not prepare retained worker descriptors; older helpers are not an unfenced fallback. No teardown was started.'
    return 1
  fi
}

assert_uninstall_workers() {
  local status
  [ "$UNINSTALL_GUARD_REQUIRED" != 1 ] || {
    [ -n "$UNINSTALL_WORKER_PID" ] && [ -n "$UNINSTALL_WORKER_PIPE" ] \
      && [ -n "$UNINSTALL_WORKER_RESPONSE_FD" ] && kill -0 "$UNINSTALL_WORKER_PID" 2>/dev/null \
      && ( trap '' PIPE; printf 'check\n' >&"$UNINSTALL_WORKER_PIPE" ) 2>/dev/null \
      && IFS= read -r -t 5 status <&"$UNINSTALL_WORKER_RESPONSE_FD" && [ "$status" = checked ] || {
      log 'The protected uninstall worker lease could not be confirmed. Teardown stopped; preserve the signed recovery evidence and review changed locks or unsafe parent metadata.'
      return 1
    }
  }
}

acquire_uninstall_workers() {
  local guard_input guard_output status inherited helper="$RECOVERY_SIGNER_DIR/sls_install_guard.py"
  UNINSTALL_GUARD_REQUIRED=0
  if [ -e "$DATA_DIR" ] || [ -L "$DATA_DIR" ]; then
    # The optional narrow migration uses authenticated retained sources and
    # changes only recognized legacy modes; bytes and lock inodes are retained.
    if [ -f "$RECOVERY_SIGNER_DIR/sls_legacy_permissions.py" ]; then
      /usr/bin/python3 -I "$RECOVERY_SIGNER_DIR/sls_legacy_permissions.py" --data "$DATA_DIR" \
        --approval "$RECOVERY_SIGNER_DIR/uninstall-approval.json" repair || return 1
    fi
    UNINSTALL_GUARD_REQUIRED=1
    prepare_uninstall_worker_descriptors "$helper" || return 1
    inherited="$(IFS=,; printf '%s' "${UNINSTALL_WORKER_LEASE_FDS[*]}")"
    coproc SLS_UNINSTALL_GUARD {
      exec /usr/bin/python3 -I "$helper" --data "$DATA_DIR" --timeout 120 --inherited-fds "$inherited" hold
    }
    UNINSTALL_WORKER_PID="${SLS_UNINSTALL_GUARD_PID:-}"
    guard_input="${SLS_UNINSTALL_GUARD[1]:-}"; guard_output="${SLS_UNINSTALL_GUARD[0]:-}"
    if [ -z "$UNINSTALL_WORKER_PID" ] || [ -z "$guard_input" ] || [ -z "$guard_output" ] \
      || ! exec {UNINSTALL_WORKER_PIPE}>&"$guard_input" \
      || ! exec {UNINSTALL_WORKER_RESPONSE_FD}<&"$guard_output" \
      || ! IFS= read -r -t 125 status <&"$UNINSTALL_WORKER_RESPONSE_FD" || [ "$status" != ready ]; then
      release_uninstall_workers
      log 'Unable to drain SLL workers safely. Wait for announcements/pages to finish, stop external SLL supervisors and review the named unsafe lock before retrying. No teardown was started.'
      return 1
    fi
    assert_uninstall_workers || return 1
  else
    # A late explicit-purge retry has no locks to acquire. Require the already
    # removed module/registry and public runtime before allowing this state.
    inspect_module_registry || return 1
    [ "$MODULE_REGISTRY_PRESENT" != 1 ] || {
      log 'SLL data is missing while its module registry entry remains. Preserve the signed evidence and review this incomplete teardown; no removal was started.'
      return 1
    }
    local entry
    for entry in /var/www/html/admin/modules/slsmassnotifyserver /usr/local/bin/sls_mass_notify \
      /var/www/html/api/sipnotify /var/www/html/api/sls-mass-notify /var/www/html/mass-notify; do
      if [ -e "$entry" ] || [ -L "$entry" ]; then
        log 'SLL data is missing while delivery entry points remain. Preserve the signed evidence and review this incomplete teardown; no removal was started.'
        return 1
      fi
    done
  fi
}

inspect_uninstall_idle() (
  if [ -n "${UNINSTALL_WORKER_PIPE:-}" ]; then exec {UNINSTALL_WORKER_PIPE}>&-; fi
  /usr/bin/python3 -I - "$RECOVERY_SIGNER_DIR/sls_install_idle.py" "$DATA_DIR" "$PBX_RUNNING" <<'PYUNINSTALLIDLE'
from pathlib import Path
import importlib.util, inspect, os, sys
path, data, running = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
spec = importlib.util.spec_from_file_location('sls_uninstall_idle', path)
idle = importlib.util.module_from_spec(spec); spec.loader.exec_module(idle)
try:
    check = idle.IdleCheck(data)
    if running == '0':
        # Failed CLI access is not evidence that an existing Asterisk is idle.
        # Only a genuinely absent Asterisk process permits the empty inventory.
        proc = idle.directory(Path('/proc'))
        try:
            for name in idle.entries(proc, 32768, 3):
                if not name.isdigit(): continue
                try:
                    executable = os.readlink('/proc/' + name + '/exe')
                except (FileNotFoundError, ProcessLookupError): continue
                if Path(executable.removesuffix(' (deleted)')).name == 'asterisk':
                    raise idle.IdleError('Asterisk is running but its channel inventory is unavailable. Restore local control-socket access before removing SLL.')
        finally: os.close(proc)
        check.channels = lambda: ''
    check.no_processes(); check.no_pending(); check.no_playback()
    # Teardown does not require a healthy collector. Existing admission state
    # still must be valid and closed; unknown/live batches are not erased.
    # Prior signed helpers have no pending-voicemail keyword and already
    # perform the strict batch check without requiring collector health.
    parameters = inspect.signature(check.phone_history).parameters
    options = {'allow_pending_voicemail': True} if 'allow_pending_voicemail' in parameters else {}
    check.phone_history(False, False, **options)
except (idle.IdleError, OSError, ValueError, TypeError) as error:
    raise SystemExit('SLL uninstall safety check: ' + str(error) + '. No teardown was started; allow delivery to finish and preserve unknown state for review.')
PYUNINSTALLIDLE
)

close_inherited_maintenance_lock_fds() {
  local lock_file="${SLS_MASS_NOTIFY_MAINTENANCE_LOCK:-/run/lock/sls-mass-notify-maintenance.lock}"
  local descriptor descriptor_path descriptor_target close_fd

  for descriptor_path in "/proc/${BASHPID}/fd/"*; do
    [ -e "$descriptor_path" ] || continue
    descriptor="${descriptor_path##*/}"
    [[ "$descriptor" =~ ^[0-9]+$ ]] && [ "$descriptor" -gt 2 ] || continue
    descriptor_target="$(readlink -f -- "$descriptor_path" 2>/dev/null || true)"
    [ "$descriptor_target" = "$lock_file" ] || continue
    close_fd="$descriptor"
    exec {close_fd}>&-
  done
}

run_fwconsole() (
  # Immutable root stages retain the maintenance and worker lease copies.
  # Their Popen(close_fds=True) keeps mutable vendor children descriptor-free.
  if [ -n "${UNINSTALL_WORKER_PIPE:-}" ]; then exec {UNINSTALL_WORKER_PIPE}>&-; fi
  # PCRE JIT allocation can be denied by otherwise healthy unprivileged LXC
  # containers. Limit this compatibility override to the uninstall process.
  run_bounded_as_asterisk /usr/bin/php -d pcre.jit=0 /usr/sbin/fwconsole "$@"
)

module_registry_exists() {
  run_bounded_as_asterisk "SLS_MODULE_NAME=$MODULE" /usr/bin/php -d pcre.jit=0 -r '
$bootstrap_settings = ["freepbx_auth" => false, "skip_astman" => true];
require "/etc/freepbx.conf";
$statement = \FreePBX::Database()->prepare("SELECT COUNT(*) FROM modules WHERE modulename = ?");
$statement->execute([(string)getenv("SLS_MODULE_NAME")]);
exit((int)$statement->fetchColumn() > 0 ? 0 : 1);
'
}

inspect_module_registry() {
  local result=0
  module_registry_exists || result=$?
  case "$result" in
    0) MODULE_REGISTRY_PRESENT=1 ;;
    1) MODULE_REGISTRY_PRESENT=0 ;;
    *) log "FreePBX module registry could not be read. Module files were not deleted; restore database access and retry."; return 1 ;;
  esac
}

remove_module_registration() {
  inspect_module_registry || return 1
  if [ "$MODULE_REGISTRY_PRESENT" = 1 ]; then
    if ! run_fwconsole ma uninstall "$MODULE" >"$MODULE_UNINSTALL_LOG" 2>&1; then
      log "FreePBX reported an error while uninstalling $MODULE; checking whether its registry row was removed."
    fi
  fi
  inspect_module_registry || return 1
  if [ "$MODULE_REGISTRY_PRESENT" = 1 ]; then
    run_fwconsole ma disable "$MODULE" >>"$MODULE_UNINSTALL_LOG" 2>&1 || true
    run_fwconsole ma delete "$MODULE" >>"$MODULE_UNINSTALL_LOG" 2>&1 || true
  fi
  inspect_module_registry || return 1
  if [ "$MODULE_REGISTRY_PRESENT" = 1 ]; then
    log "FreePBX left the $MODULE registry row behind; removing that single stale row before deleting module files."
    run_bounded_as_asterisk "SLS_MODULE_NAME=$MODULE" /usr/bin/php -d pcre.jit=0 -r '
$bootstrap_settings = ["freepbx_auth" => false, "skip_astman" => true];
require "/etc/freepbx.conf";
$statement = \FreePBX::Database()->prepare("DELETE FROM modules WHERE modulename = ?");
$statement->execute([(string)getenv("SLS_MODULE_NAME")]);
exit(0);
'
  fi
  inspect_module_registry || return 1
  if [ "$MODULE_REGISTRY_PRESENT" = 1 ]; then
    log "Unable to remove the $MODULE registry row. Module files were not deleted."
    return 1
  fi
  remove_managed_path "/var/www/html/admin/modules/$MODULE"
}

capture_signing_fingerprint() {
  [ -d "$SIGN_HOME" ] || return 0
  SIGNING_FINGERPRINT="$(GNUPGHOME="$SIGN_HOME" gpg --batch --with-colons --list-keys 2>/dev/null | awk -F: '/^fpr:/ && !found {print $10; found=1}')" || {
    log "The existing signing keyring could not be inspected safely. Preserve it for review before uninstalling."
    return 1
  }
}

capture_pbx_running_state() {
  local response=""
  PBX_RUNNING=0
  if response="$(asterisk -rx 'core show uptime' 2>/dev/null)" \
    && grep -Fq 'System uptime:' <<<"$response"; then
    PBX_RUNNING=1
  fi
}

reload_removed_pbx_integration() {
  if [ "$PBX_RUNNING" != 1 ]; then
    log "SLL software removal checks passed. Asterisk is stopped or its control socket is unavailable; run fwconsole reload after PBX service is available. No PBX service was started."
    return 0
  fi
  if ! run_fwconsole reload >>"$MODULE_UNINSTALL_LOG" 2>&1; then
    log "SLL software removal checks passed, but the PBX integration reload failed. Review $MODULE_UNINSTALL_LOG_PATH, resolve the PBX reload error, and run fwconsole reload."
  fi
}

capture_configured_ami_username() {
  local ownership snapshot="$RECOVERY_DECODER_DIR/central-config.snapshot"
  /usr/bin/python3 -I - "$DATA_DIR/mass-notifications.config" "$snapshot" <<'PYAMISNAPSHOT' || return 1
import fcntl
import os
import pwd
import stat
import sys

source, target = sys.argv[1:]
account = pwd.getpwnam('asterisk')
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def parent(path, allowed_owners, allowed_groups):
    parts = path.split('/')[1:]
    if not path.startswith('/') or not parts or any(part in ('', '.', '..') for part in parts):
        raise RuntimeError('invalid configuration snapshot path')
    descriptor = os.open('/', directory_flags)
    try:
        for component in parts[:-1]:
            child = os.open(component, directory_flags, dir_fd=descriptor)
            metadata = os.fstat(child)
            sticky_root = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in allowed_owners
                    or metadata.st_gid not in allowed_groups
                    or metadata.st_mode & 0o022 and not sticky_root):
                os.close(child)
                raise RuntimeError('unsafe configuration snapshot parent')
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise

source_parent, source_name = parent(source, {0, account.pw_uid}, {0, account.pw_gid})
try:
    try:
        descriptor = os.open(source_name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=source_parent)
    except FileNotFoundError:
        raise SystemExit(0)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in (0, account.pw_uid)
                or before.st_gid not in (0, account.pw_gid)
                or stat.S_IMODE(before.st_mode) not in (0o600, 0o640, 0o644)
                or before.st_size > 3 * 1024 * 1024):
            raise RuntimeError('central configuration is unsafe')
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        body = bytearray()
        while len(body) <= 3 * 1024 * 1024:
            chunk = os.read(descriptor, min(65536, 3 * 1024 * 1024 + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_uid, row.st_gid,
                                row.st_mode, row.st_size, row.st_mtime_ns,
                                row.st_ctime_ns, row.st_nlink)
        if len(body) > 3 * 1024 * 1024 or len(body) != before.st_size \
                or identity(before) != identity(after) or identity(after) != identity(named):
            raise RuntimeError('central configuration changed while being snapshotted')
    finally:
        os.close(descriptor)
finally:
    os.close(source_parent)

target_parent, target_name = parent(target, {0}, {0, account.pw_gid})
try:
    output = os.open(target_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=target_parent)
    try:
        view = memoryview(body)
        while view:
            written = os.write(output, view)
            if written <= 0:
                raise OSError('short configuration snapshot write')
            view = view[written:]
        os.fchown(output, 0, account.pw_gid)
        os.fchmod(output, 0o640)
        os.fsync(output)
    finally:
        os.close(output)
    os.fsync(target_parent)
finally:
    os.close(target_parent)
PYAMISNAPSHOT
  if [ ! -f "$snapshot" ] || [ -L "$snapshot" ]; then
    CONFIGURED_AMI_USERNAME=""
    CONFIGURED_AMI_SECRET_HASH=""
    return 0
  fi
  ownership="$(run_as_asterisk "SLS_CONFIG=$snapshot" "SLS_UNINSTALL_CONFIG_DECODER=$RECOVERY_CONFIG_DECODER" /usr/bin/php -d pcre.jit=0 <<'PHPAMI'
<?php
$path = (string)getenv('SLS_CONFIG');
if ($path === '' || !file_exists($path)) { exit(0); }
$metadata = lstat($path);
if (is_link($path) || !is_file($path) || !is_array($metadata) || $metadata['nlink'] !== 1
    || ($metadata['mode'] & 0022) !== 0 || $metadata['size'] > 3 * 1024 * 1024) {
    fwrite(STDERR, "The central configuration is unsafe; preserve it for review before uninstalling.\n"); exit(1);
}
require_once (string)getenv('SLS_UNINSTALL_CONFIG_DECODER');
$body = file_get_contents($path);
clearstatcache(true, $path);
$after = lstat($path);
if (!is_string($body) || !is_array($after) || strlen($body) !== $metadata['size']
    || array_intersect_key($metadata, array_flip(['dev', 'ino', 'size', 'mtime', 'ctime'])) !== array_intersect_key($after, array_flip(['dev', 'ino', 'size', 'mtime', 'ctime']))) {
    fwrite(STDERR, "The central configuration changed while being read; no manager account was removed.\n"); exit(1);
}
$settings = \FreePBX\modules\SlsConfigCrypto::decode($body);
$username = (string)($settings['ami']['username'] ?? '');
if ($username !== '' && !preg_match('/^[A-Za-z0-9_.-]{1,80}$/D', $username)) {
    fwrite(STDERR, "The configured SLL AMI username is invalid; no manager account was removed.\n"); exit(1);
}
echo $username, "\t", hash('sha256', (string)($settings['ami']['password'] ?? ''));
PHPAMI
)" || return 1
  rm -f -- "$snapshot"
  IFS=$'\t' read -r CONFIGURED_AMI_USERNAME CONFIGURED_AMI_SECRET_HASH <<<"$ownership"
}

validate_retained_user_data() {
  /usr/bin/python3 -I - "$DATA_DIR" <<'PYRETAIN'
from pathlib import Path
import os, pwd, stat, sys
path = Path(sys.argv[1]); account = pwd.getpwnam('asterisk')
if not path.is_absolute() or '..' in path.parts:
    raise SystemExit('Invalid retained SLL data path')
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
fd = os.open('/', flags)
try:
    for part in path.parts[1:]:
        try: child = os.open(part, flags, dir_fd=fd)
        except FileNotFoundError: raise SystemExit(0)
        os.close(fd); fd = child
        info = os.fstat(fd)
        if info.st_uid not in (0, account.pw_uid) or info.st_gid not in (0, account.pw_gid) or info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise SystemExit('Retained SLL data has an unsafe owner or writable parent; no data was deleted')
finally: os.close(fd)
PYRETAIN
}

handle_uninstall_exit() {
  local status=$?
  trap - EXIT
  if [ -n "$UNINSTALL_TRANSACTION_DIR" ] && [ "$status" != 0 ]; then
    record_uninstall_stage failed || log "Uninstall transaction could not record failure; preserve $UNINSTALL_TRANSACTION_DIR."
  fi
  if [ "$status" = 0 ]; then
    cleanup_recovery_signer
  else
    log "Uninstall transaction retained: ${UNINSTALL_TRANSACTION_DIR:-not created}."
    log "Uninstall recovery evidence retained: ${RECOVERY_SIGNER_DIR:-not created}; ${RECOVERY_DECODER_DIR:-not created}."
    if [ -n "${UNINSTALL_APPROVED_SOURCE:-}" ]; then
      log "Local authenticated retry entry: $UNINSTALL_APPROVED_SOURCE/bin/sls_mass_notify_uninstall.sh. Preserve the trust generation; no download is required."
    fi
  fi
  exit "$status"
}

rewrite_managed_text_file() {
  local path="$1" operation="$2" name="${3:-}" action="${4:-apply}"
  run_as_asterisk /usr/bin/python3 -I - "$path" "$operation" "$name" "$action" "${RECOVERY_AMI_OWNERSHIP_HELPER:-}" "${CONFIGURED_AMI_USERNAME:-}" "${CONFIGURED_AMI_SECRET_HASH:-}" <<'PYREWRITE'
import fcntl
import os
import pwd
import re
import secrets
import stat
import sys

path, operation, name, action, ami_helper, configured, proof = sys.argv[1:]
ami_block = operation == 'managed-block' and name == 'SLS Mass Notifications AMI'
parts = path.split('/')[1:]
if (not path.startswith('/') or not parts or any(part in ('', '.', '..') for part in parts)
        or operation not in ('menu', 'legacy-dashboard', 'managed-block')
        or action not in ('apply', 'check', 'ami-name') or action == 'ami-name' and not ami_block):
    raise SystemExit('Invalid managed text rewrite request')
account = pwd.getpwnam('asterisk')
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
parent = os.open('/', directory_flags)
descriptor = -1
temporary = None
try:
    for component in parts[:-1]:
        child = os.open(component, directory_flags, dir_fd=parent)
        metadata = os.fstat(child)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in (0, account.pw_uid)
                or metadata.st_gid not in (0, account.pw_gid) or metadata.st_mode & 0o002):
            os.close(child)
            raise RuntimeError('managed text parent is unsafe')
        os.close(parent)
        parent = child
    try:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
    except FileNotFoundError:
        raise SystemExit(0)
    before = os.fstat(descriptor)
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid not in (0, account.pw_uid)
            or before.st_gid not in (0, account.pw_gid)
            or before.st_mode & 0o002
            or before.st_size > 8 * 1024 * 1024):
        raise RuntimeError('managed text file is unsafe or oversized')
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    body = bytearray()
    while len(body) <= 8 * 1024 * 1024:
        chunk = os.read(descriptor, min(65536, 8 * 1024 * 1024 + 1 - len(body)))
        if not chunk:
            break
        body.extend(chunk)
    after = os.fstat(descriptor)
    named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
    identity = lambda row: (row.st_dev, row.st_ino, row.st_uid, row.st_gid,
                            row.st_mode, row.st_size, row.st_mtime_ns,
                            row.st_ctime_ns, row.st_nlink)
    if len(body) > 8 * 1024 * 1024 or identity(before) != identity(after) or identity(after) != identity(named):
        raise RuntimeError('managed text file changed during inspection')
    try:
        data = bytes(body).decode('utf-8')
    except UnicodeDecodeError:
        raise RuntimeError('managed text file is not valid UTF-8')

    if operation == 'menu':
        # Retired SLL releases added this exact 695-byte ASCII block. Refuse
        # partial/edited markers and leave unmarked site PHP untouched.
        import hashlib
        marker = "\t// SLS Mass Notifications menu placement:"
        updated = data
        if marker in data:
            start = data.index(marker)
            block = data[start:start + 695]
            if (data.count(marker) != 1 or hashlib.sha256(block.encode('utf-8')).hexdigest()
                    != 'b95a902541a9d115b06ef70ccb9fd7557db5c011d3838ee0f381bdc11987b257'):
                raise RuntimeError('The previous SLL menu integration was edited. Preserve the Framework file for review.')
            updated = data[:start] + data[start + len(block):]
    elif operation == 'legacy-dashboard':
        updated = re.sub(
            r"\n\s*\$final\[\$i\]\s*=\s*\$this->checkSlsMassNotify\(\);\s*"
            r"\$final\[\$i\]\['title'\]\s*=\s*_\(\"Mass Notifications (?:Plugin|Module)\"\);\s*\$i\+\+;\s*",
            "\n", data, flags=re.S)
        updated = re.sub(
            r"\n\s*private function checkSlsMassNotify\(\)\s*\{.*?"
            r"(?=\n\s*private function genAlertGlyphicon\(\))",
            "\n", updated, flags=re.S)
    else:
        if not name or len(name.encode('utf-8')) > 160 or any(character in name for character in '\r\n\x00'):
            raise RuntimeError('invalid managed block name')
        updated = data
        def remove_complete_block(value, start_marker, end_marker):
            opened = False
            for line in value.splitlines():
                if start_marker in line or end_marker in line:
                    if line == start_marker and not opened:
                        opened = True
                    elif line == end_marker and opened:
                        opened = False
                    else:
                        raise RuntimeError('managed block has malformed, nested or unmatched markers; preserve the file for review')
            if opened:
                raise RuntimeError('managed block has an unmatched beginning; preserve the file for review')
            pattern = (r'(?m)^' + re.escape(start_marker) + r'\r?\n'
                       + r'(?s:.*?)^' + re.escape(end_marker) + r'(?:\r?\n|\Z)')
            return re.sub(pattern, '', value)
        for prefix in (';', '#'):
            updated = remove_complete_block(
                updated, prefix + ' BEGIN ' + name, prefix + ' END ' + name)
        updated = remove_complete_block(
            updated, ';-- BEGIN ' + name + ' --', ';-- END ' + name + ' --')

    if ami_block and action in ('apply', 'ami-name') and updated != data:
        import subprocess
        checker = r'''require $argv[1];
$name=\SLS\MassNotify\AmiUserOwnership::fileAccount(stream_get_contents(STDIN),$argv[2],$argv[3]);
if ($name === null || $name !== $argv[2]) { exit(1); } echo $name;'''
        if not os.path.isabs(ami_helper) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', configured) or not re.fullmatch(r'[a-f0-9]{64}', proof):
            raise RuntimeError('The protected configured AMI identity is needed to verify its managed file section')
        result = subprocess.run(['/usr/bin/php', '-d', 'display_errors=0', '-r', checker, ami_helper, configured, proof],
                                input=body, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        if result.returncode or result.stdout != configured.encode('ascii'):
            raise RuntimeError('The managed AMI file identity, credential or policy could not be verified; preserve the file')
        if action == 'ami-name': print(configured)
    if updated == data or action == 'ami-name':
        raise SystemExit(0)
    encoded = updated.encode('utf-8')
    temporary = '.sls-uninstall-rewrite-' + secrets.token_hex(12)
    output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     stat.S_IMODE(before.st_mode) & 0o777, dir_fd=parent)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(output, view)
            if written <= 0:
                raise OSError('short managed text write')
            view = view[written:]
        os.fchmod(output, stat.S_IMODE(before.st_mode) & 0o777)
        # Preserve the exact existing owner/group. The unprivileged rewrite
        # aborts rather than silently adopting a root-owned local file.
        os.fchown(output, before.st_uid, before.st_gid)
        os.fsync(output)
    finally:
        os.close(output)
    current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
    if identity(current) != identity(after):
        raise RuntimeError('managed text file changed before replacement')
    if action == 'check':
        raise SystemExit(0)
    os.replace(temporary, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
    temporary = None
    os.fsync(parent)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    if temporary is not None:
        try:
            os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
        except FileNotFoundError:
            pass
    os.close(parent)
PYREWRITE
}

remove_menu_patch() {
  rewrite_managed_text_file "/var/www/html/admin/views/menu_items.php" menu
}

remove_legacy_dashboard_patch() {
  rewrite_managed_text_file "/var/www/html/admin/modules/dashboard/sections/Overview.class.php" legacy-dashboard
}

remove_managed_block() {
  local path="$1"
  local name="$2"
  rewrite_managed_text_file "$path" managed-block "$name"
}

verify_uninstall_collector_unit() {
  /usr/bin/python3 -I - "$1" "$RECOVERY_SIGNER_DIR/collector-unit.txt" <<'PY'
import os, stat, sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
with os.fdopen(fd, 'rb') as handle:
    before = os.fstat(handle.fileno())
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != 0
            or before.st_mode & 0o022 or before.st_size > 65536):
        raise SystemExit('Refusing an unsafe collector service file; no service was changed.')
    body = handle.read(65537); after = os.fstat(handle.fileno()); named = os.lstat(sys.argv[1])
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns, row.st_nlink)
    if identity(before) != identity(after) or identity(after) != identity(named) or body != open(sys.argv[2], 'rb').read():
        raise SystemExit('Collector service differs from its retained signed template. Preserve custom changes for review; no service was changed.')
PY
}

restore_uninstall_collector() {
  local unit="$1" previous="$2" enabled="$3" current
  if ! verify_uninstall_collector_unit "$unit"; then
    log 'Uninstall stopped before removing module files, but the collector service changed during recovery. Preserve its definition and history for review.'
    return 1
  fi
  current="$(/usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl show --property=UnitFileState --value sls-mass-notify-phone-events.service)" || return 1
  if [ "$enabled" = enabled ] && [ "$current" = disabled ]; then
    /usr/bin/timeout --kill-after=2 20 /usr/bin/systemctl enable sls-mass-notify-phone-events.service || {
      log 'Uninstall stopped before removing module files, but the collector enablement could not be restored. Preserve its unit/history and restore its previous enabled state after reviewing systemd.'
      return 1
    }
  elif [ "$current" != "$enabled" ]; then
    log 'Collector enablement changed unexpectedly; no further service state was adopted. Preserve the unit and review systemd before retrying.'
    return 1
  fi
  [ "$previous" = active ] || return 0
  if ! /usr/bin/timeout --kill-after=2 20 /usr/bin/systemctl start sls-mass-notify-phone-events.service \
    || [ "$(/usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl show --property=ActiveState --value sls-mass-notify-phone-events.service)" != active ]; then
    log 'Uninstall stopped before removing module files, but the previously active collector could not be restored. Preserve its service definition and history; review systemctl status/journalctl and restart the approved collector after resolving the named fault.'
    return 1
  fi
  log 'Uninstall stopped before removing module files; the previously active collector was restored without changing its enablement.'
}

verify_legacy_collector_offline() {
  /usr/bin/python3 -I -B - "$RECOVERY_SIGNER_DIR/sls_install_idle.py" "$DATA_DIR" "$1" <<'PYLEGACYCOLLECTOR'
import fcntl, importlib.util, os, pathlib, pwd, stat, sys
source, data, phase = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
if phase not in ('before-stop', 'stopped'): raise SystemExit(1)
spec = importlib.util.spec_from_file_location('signed_uninstall_idle', source)
idle = importlib.util.module_from_spec(spec); spec.loader.exec_module(idle)
try:
    parent = idle.directory(data)
except FileNotFoundError:
    raise SystemExit(0)
failure = 'The approved prior release cannot retire ambiguous or still-active collector evidence. Preserve history and use an authenticated upgrade before uninstalling.'
try:
    def present(name):
        try: os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: return False
        return True
    ledger = 'phone-admission.json'
    display = 'phone-collector-display.json'
    if present(ledger):
        state = idle.read_collector_json(data / ledger, 'phone-admission.lock', private=True)
        if state.get('collector') is not None: raise ValueError()
    elif any(present(name) for name in ('.phone-admission-required', display, 'phone-collector-heartbeat.json')):
        raise ValueError()
    if present(display):
        view = idle.read_collector_json(data / display, display + '.lock', 1024, private=True)
        if view.get('connected') is not False: raise ValueError()
    if phase == 'stopped' and present('phone-events.lock'):
        fd = os.open('phone-events.lock', os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd); account = pwd.getpwnam('asterisk')
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size
                    or info.st_uid not in (0, account.pw_uid) or info.st_gid not in (0, account.pw_gid)
                    or stat.S_IMODE(info.st_mode) not in (0o600, 0o640, 0o644)): raise ValueError()
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not os.path.samestat(info, os.stat('phone-events.lock', dir_fd=parent, follow_symlinks=False)):
                raise ValueError()
        finally: os.close(fd)
except (AttributeError, OSError, ValueError, RuntimeError):
    raise SystemExit(failure) from None
finally: os.close(parent)
PYLEGACYCOLLECTOR
}

retire_stopped_uninstall_collector() {
  if [ -n "$RECOVERY_COLLECTOR_HELPER" ]; then
    run_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 15 /usr/bin/python3 -I -B \
      "$RECOVERY_COLLECTOR_HELPER" --retire-stopped-collector
  else
    verify_legacy_collector_offline stopped
  fi
}

uninstall_collector_property() {
  local value status=0
  value="$(/usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl show --property="$1" --value sls-mass-notify-phone-events.service)" || status=$?
  # Some systemd versions return LSB 4 for a missing unit but still report
  # its state. Accept that result only for the explicit absent state values.
  if [ "$status" != 0 ]; then
    [ "$status" = 4 ] || return 1
    case "$1:$value" in LoadState:not-found|ActiveState:inactive) ;; *) return 1 ;; esac
  fi
  printf '%s\n' "$value"
}

absent_uninstall_collector_is_stopped() {
  local unit="$1" load active fragment dropins
  load="$(uninstall_collector_property LoadState)" || return 1
  active="$(uninstall_collector_property ActiveState)" || return 1
  if [ "$load:$active" = not-found:inactive ]; then return 0; fi
  # Retry interruption between unlinking the signed fragment and daemon-reload.
  # A foreign, active, overridden or recreated definition is preserved.
  if [ "$load:$active" = loaded:inactive ]; then
    fragment="$(uninstall_collector_property FragmentPath)" || return 1
    dropins="$(uninstall_collector_property DropInPaths)" || return 1
    if [ "$fragment" = "$unit" ] && [ -z "$dropins" ] && [ ! -e "$unit" ] && [ ! -L "$unit" ]; then
      /usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl daemon-reload || return 1
      load="$(uninstall_collector_property LoadState)" || return 1
      active="$(uninstall_collector_property ActiveState)" || return 1
      if [ "$load:$active" = not-found:inactive ] && [ ! -e "$unit" ] && [ ! -L "$unit" ]; then return 0; fi
    fi
  fi
  log 'The managed collector unit file is absent but systemd cannot certify it is unloaded and inactive. Check the loaded unit and its overrides before retrying.'
  return 1
}

remove_phone_collector_service() {
  local unit="/etc/systemd/system/sls-mass-notify-phone-events.service" active_state previous_state fragment dropins enabled_state
  if [ ! -e "$unit" ] && [ ! -L "$unit" ]; then
    absent_uninstall_collector_is_stopped "$unit" || return 1
    assert_uninstall_workers && inspect_uninstall_idle && retire_stopped_uninstall_collector
    return $?
  fi
  verify_uninstall_collector_unit "$unit" || return 1
  if [ -z "$RECOVERY_COLLECTOR_HELPER" ]; then
    verify_legacy_collector_offline before-stop || return 1
  fi
  previous_state="$(/usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl show --property=ActiveState --value sls-mass-notify-phone-events.service)" || return 1
  fragment="$(/usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl show --property=FragmentPath --value sls-mass-notify-phone-events.service)" || return 1
  dropins="$(/usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl show --property=DropInPaths --value sls-mass-notify-phone-events.service)" || return 1
  enabled_state="$(/usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl show --property=UnitFileState --value sls-mass-notify-phone-events.service)" || return 1
  case "$previous_state:$enabled_state" in active:enabled|active:disabled|inactive:enabled|inactive:disabled|failed:enabled|failed:disabled) ;; *) log 'Collector enablement or process state is unsupported. No service was changed; review masks or custom supervision before retrying.'; return 1 ;; esac
  if [ "$fragment" != "$unit" ] || [ -n "$dropins" ]; then
    log 'Collector systemd fragments or overrides differ from the signed service. No service was changed; preserve custom supervision for review.'
    return 1
  fi
  if ! /usr/bin/timeout --kill-after=2 20 /usr/bin/systemctl stop sls-mass-notify-phone-events.service; then
    restore_uninstall_collector "$unit" "$previous_state" "$enabled_state" || true
    return 1
  fi
  active_state="$(/usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl show --property=ActiveState --value sls-mass-notify-phone-events.service)" || {
    restore_uninstall_collector "$unit" "$previous_state" "$enabled_state" || true
    return 1
  }
  case "$active_state" in inactive|failed) ;; *) log "The phone collector has not stopped; its service file was preserved."; restore_uninstall_collector "$unit" "$previous_state" "$enabled_state" || true; return 1 ;; esac
  # Confirm shutdown did not leave a last voicemail call. Keep the service
  # definition and all runtime/history available if this final check fails.
  if ! assert_uninstall_workers || ! inspect_uninstall_idle || ! retire_stopped_uninstall_collector; then
    restore_uninstall_collector "$unit" "$previous_state" "$enabled_state" || true
    return 1
  fi
  if ! /usr/bin/timeout --kill-after=2 20 /usr/bin/systemctl disable sls-mass-notify-phone-events.service; then
    log 'The collector stopped but its enablement could not be removed. Its service and module files remain; review systemd and retry.'
    restore_uninstall_collector "$unit" "$previous_state" "$enabled_state" || true
    return 1
  fi
  if ! rm -- "$unit"; then
    restore_uninstall_collector "$unit" "$previous_state" "$enabled_state" || true
    return 1
  fi
  /usr/bin/timeout --kill-after=2 10 /usr/bin/systemctl daemon-reload || {
    log 'The collector service was removed but systemd reload failed. Module and history remain; preserve signed recovery evidence, resolve systemd and retry the included uninstaller.'
    return 1
  }
}

remove_managed_root_file() {
  local path="$1" kind="$2" action="${3:-remove}"
  /usr/bin/python3 -I - "$path" "$kind" "$action" "$UNINSTALL_APPROVED_SOURCE/bin/sls_mass_notify/sls_privileged_install.py" <<'PYMANAGEDROOT'
import ast
import os
from pathlib import Path
import stat
import sys

path, kind, action, approved_helper = sys.argv[1:]
if kind not in ('apache-enabled', 'apache-available', 'logrotate') or action not in ('check', 'remove'):
    raise SystemExit('Unknown managed root-file type')

def protected_read(name, maximum):
    item = Path(name)
    for parent in reversed(item.parents):
        metadata = parent.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX):
            raise RuntimeError('managed source has an unsafe parent')
    descriptor = os.open(item, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & 0o022 or before.st_size > maximum):
            raise RuntimeError('managed source is unsafe')
        body = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        if (len(body) != before.st_size or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
            raise RuntimeError('managed source changed during inspection')
        return body
    finally:
        os.close(descriptor)

parts = path.split('/')[1:]
if not path.startswith('/') or not parts or any(part in ('', '.', '..') for part in parts):
    raise RuntimeError('invalid managed root-file path')
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
parent = os.open('/', flags)
try:
    for component in parts[:-1]:
        child = os.open(component, flags, dir_fd=parent)
        metadata = os.fstat(child)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            os.close(child)
            raise RuntimeError('managed root-file parent is unsafe')
        os.close(parent)
        parent = child
    try:
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        raise SystemExit(0)
    if kind == 'apache-enabled':
        expected = '../conf-available/sls-mass-notify.conf'
        if (not stat.S_ISLNK(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or os.readlink(parts[-1], dir_fd=parent) != expected):
            raise RuntimeError('Apache enablement path is not the managed SLL link')
    else:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        try:
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_gid != 0
                    or opened.st_nlink != 1 or opened.st_mode & 0o022 or opened.st_size > 1024 * 1024):
                raise RuntimeError('managed root file is unsafe')
            body = os.read(descriptor, 1024 * 1024 + 1)
            after = os.fstat(descriptor)
            named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            identity = lambda row: (row.st_dev, row.st_ino, row.st_uid, row.st_gid,
                                    row.st_mode, row.st_size, row.st_mtime_ns,
                                    row.st_ctime_ns, row.st_nlink)
            if len(body) != opened.st_size or identity(before) != identity(opened) \
                    or identity(opened) != identity(after) or identity(after) != identity(named):
                raise RuntimeError('managed root file changed during inspection')
        finally:
            os.close(descriptor)
        if kind == 'apache-available':
            tree = ast.parse(protected_read(approved_helper, 2 * 1024 * 1024), filename=approved_helper)
            expected = None
            for node in tree.body:
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if any(isinstance(target, ast.Name) and target.id == 'APACHE' for target in targets):
                        expected = ast.literal_eval(node.value).encode()
                        break
            if expected is None or body != expected:
                raise RuntimeError('Apache configuration differs from the authenticated SLL template')
        else:
            match = __import__('re').fullmatch(
                rb'/var/log/sls_mass_notify\.log \{\n'
                rb'    daily\n'
                rb'    maxsize 2M\n'
                rb'    rotate ([0-9]{1,3})\n'
                rb'    maxage \1\n'
                rb'    missingok\n'
                rb'    notifempty\n'
                rb'    compress\n'
                rb'    delaycompress\n'
                rb'    copytruncate\n'
                rb'    su root asterisk\n'
                rb'\}\n', body)
            if match is None or not 1 <= int(match.group(1)) <= 365:
                raise RuntimeError('Logrotate configuration differs from an SLL-managed template')
    current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
    if (before.st_dev, before.st_ino, before.st_ctime_ns) != (current.st_dev, current.st_ino, current.st_ctime_ns):
        raise RuntimeError('managed root file changed before removal')
    if action == 'check':
        raise SystemExit(0)
    os.unlink(parts[-1], dir_fd=parent)
    os.fsync(parent)
finally:
    os.close(parent)
PYMANAGEDROOT
}

disable_apache_conf() {
  remove_managed_root_file /etc/logrotate.d/sls-mass-notify logrotate check
  remove_managed_root_file /etc/apache2/conf-enabled/sls-mass-notify.conf apache-enabled check
  remove_managed_root_file /etc/apache2/conf-available/sls-mass-notify.conf apache-available check
  remove_managed_root_file /etc/logrotate.d/sls-mass-notify logrotate
  remove_managed_root_file /etc/apache2/conf-enabled/sls-mass-notify.conf apache-enabled
  remove_managed_root_file /etc/apache2/conf-available/sls-mass-notify.conf apache-available
  rm -f /var/lib/apache2/conf/enabled_by_admin/sls-mass-notify
  rm -f /var/lib/apache2/conf/disabled_by_admin/sls-mass-notify
  /usr/bin/systemctl reload apache2 >/dev/null 2>&1 || log "Apache configuration was removed, but Apache reload failed. Reload Apache after reviewing its configuration."
}

preflight_uninstall_integrations() {
  local unit="/etc/systemd/system/sls-mass-notify-phone-events.service"
  if [ -e "$unit" ] || [ -L "$unit" ]; then
    verify_uninstall_collector_unit "$unit"
  fi
  rewrite_managed_text_file /var/www/html/admin/views/menu_items.php menu "" check
  rewrite_managed_text_file /var/www/html/admin/modules/dashboard/sections/Overview.class.php legacy-dashboard "" check
  rewrite_managed_text_file /etc/asterisk/sip_notify_custom.conf managed-block "SLS Mass Notifications SIP NOTIFY Templates" check
  rewrite_managed_text_file /etc/asterisk/extensions_custom.conf managed-block "SLS Mass Notifications Dialplan" check
  rewrite_managed_text_file /etc/asterisk/manager_custom.conf managed-block "SLS Mass Notifications AMI" check
  remove_managed_root_file /etc/logrotate.d/sls-mass-notify logrotate check
  remove_managed_root_file /etc/apache2/conf-enabled/sls-mass-notify.conf apache-enabled check
  remove_managed_root_file /etc/apache2/conf-available/sls-mass-notify.conf apache-available check
}

remove_freepbx_manager_users() {
  run_bounded_as_asterisk "SLS_CONFIGURED_AMI_USERNAME=$CONFIGURED_AMI_USERNAME" "SLS_AMI_SECRET_HASH=$CONFIGURED_AMI_SECRET_HASH" "SLS_AMI_OWNERSHIP_HELPER=$RECOVERY_AMI_OWNERSHIP_HELPER" /usr/bin/php -d pcre.jit=0 <<'PHP'
<?php
$bootstrap_settings = ['freepbx_auth' => false, 'skip_astman' => true];
require '/etc/freepbx.conf';
$candidates = ['slsmassnotify', 'sls_mass_notify', 'nws_push'];
$configured = (string)getenv('SLS_CONFIGURED_AMI_USERNAME');
if ($configured !== '') { $candidates[] = $configured; }
$candidates = array_values(array_unique(array_filter($candidates)));
require_once (string)getenv('SLS_AMI_OWNERSHIP_HELPER');
\SLS\MassNotify\AmiUserOwnership::remove(\FreePBX::Database(), $candidates,
    (string)getenv('SLS_AMI_SECRET_HASH'), (string)\FreePBX::Config()->get('AMPMGRUSER'));
exit(0);
PHP
  remove_managed_path /etc/asterisk/slsmassnotify
}

remove_bundled_system_recordings() {
  run_as_asterisk "SLS_DATA_DIR=$DATA_DIR" /usr/bin/php -d pcre.jit=0 <<'PHP'
<?php
// Native recording IDs and audio can be shared by IVRs, ring groups, compound
// recordings and other modules. Labels and matching audio hashes do not prove
// exclusive ownership. Preserve the native rows/audio; SLL references are removed
// with its module/configuration rather than guessing a complete usage graph.
exit(0);
PHP
  log "Preserved native System Recordings and audio for any independent PBX references."
}

verify_freepbx_cleanup() {
  inspect_module_registry || return 1
  if [ "$MODULE_REGISTRY_PRESENT" = 1 ]; then
    log "Uninstall verification failed; the $MODULE FreePBX registry row remains."
    return 1
  fi
  run_bounded_as_asterisk "SLS_CONFIGURED_AMI_USERNAME=$CONFIGURED_AMI_USERNAME" "SLS_AMI_SECRET_HASH=$CONFIGURED_AMI_SECRET_HASH" "SLS_AMI_OWNERSHIP_HELPER=$RECOVERY_AMI_OWNERSHIP_HELPER" /usr/bin/php -d pcre.jit=0 <<'PHP'
<?php
$bootstrap_settings = ['freepbx_auth' => false, 'skip_astman' => true];
require '/etc/freepbx.conf';
$candidates = ['slsmassnotify', 'sls_mass_notify', 'nws_push'];
$configured = (string)getenv('SLS_CONFIGURED_AMI_USERNAME');
if ($configured !== '') { $candidates[] = $configured; }
$candidates = array_values(array_unique(array_filter($candidates)));
$database = \FreePBX::Database();
require_once (string)getenv('SLS_AMI_OWNERSHIP_HELPER');
$remaining = \SLS\MassNotify\AmiUserOwnership::ownedNames($database, $candidates,
    (string)getenv('SLS_AMI_SECRET_HASH'), (string)\FreePBX::Config()->get('AMPMGRUSER'));
if ($remaining) { fwrite(STDERR, "An owned FreePBX AMI user remains after uninstall.\n"); exit(1); }
exit(0);
PHP
  local stock_module
  for stock_module in dashboard framework; do
    [ -d "/var/www/html/admin/modules/$stock_module" ] || continue
    if ! verify_stock_module "$stock_module"; then
      log "Uninstall verification failed; FreePBX did not trust the restored $stock_module module."
      return 1
    fi
  done
  local artifact
  for artifact in \
    /etc/apache2/conf-enabled/sls-mass-notify.conf \
    /etc/apache2/conf-available/sls-mass-notify.conf \
    /var/lib/apache2/conf/enabled_by_admin/sls-mass-notify \
    /var/lib/apache2/conf/disabled_by_admin/sls-mass-notify \
    /etc/asterisk/slsmassnotify \
    /etc/systemd/system/sls-mass-notify-phone-events.service \
    /usr/local/bin/sls_mass_notify \
    /usr/local/sbin/sign_sls_mass_notify_local_sig.sh \
    /var/www/html/api/sipnotify \
    /var/www/html/api/sls-mass-notify \
    /var/www/html/mass-notify \
    /var/www/html/sls_mass_notify \
    /var/www/html/admin/modules/dashboard/sections/SlsMassNotifyAnnouncement.class.php \
    /var/www/html/admin/modules/dashboard/views/sections/sls-mass-notify-announcement.php; do
    if [ -e "$artifact" ] || [ -L "$artifact" ]; then
      log "Uninstall verification failed; managed artifact remains: $artifact"
      return 1
    fi
  done
  verify_managed_sound_link_removed /var/lib/asterisk/sounds/SLS_Mass_Notifications_Plugin || return 1
  verify_managed_sound_link_removed /var/lib/asterisk/sounds/en/SLS_Mass_Notifications_Plugin || return 1
  local managed_file managed_name managed_marker
  while IFS='|' read -r managed_file managed_name; do
    for managed_marker in "; BEGIN $managed_name" "# BEGIN $managed_name" ";-- BEGIN $managed_name --"; do
      if grep -Fq "$managed_marker" "$managed_file" 2>/dev/null; then
        log "Uninstall verification failed; a managed Asterisk block remains in $managed_file."
        return 1
      fi
    done
  done <<'SLSMANAGEDFILES'
/etc/asterisk/sip_notify_custom.conf|SLS Mass Notifications SIP NOTIFY Templates
/etc/asterisk/extensions_custom.conf|SLS Mass Notifications Dialplan
/etc/asterisk/manager_custom.conf|SLS Mass Notifications AMI
SLSMANAGEDFILES
  verify_removed_cron || return 1
  if grep -Fq 'SLS Mass Notifications menu placement:' /var/www/html/admin/views/menu_items.php 2>/dev/null; then
    log "Uninstall verification failed; the managed FreePBX menu placement remains."
    return 1
  fi
  return 0
}

verify_stock_module() {
  local stock_module="$1"
  run_bounded_as_asterisk "SLS_VERIFY_MODULE=$stock_module" /usr/bin/php -d pcre.jit=0 -r '
$bootstrap_settings = ["freepbx_auth" => false, "skip_astman" => true];
require "/etc/freepbx.conf";
$gpg = \FreePBX::GPG();
$gpg->timeout = 30;
$result = $gpg->verifyModule((string)getenv("SLS_VERIFY_MODULE"));
$valid = is_array($result)
    && array_key_exists("status", $result)
    && is_int($result["status"])
    && $result["status"] === 129
    && array_key_exists("details", $result)
    && is_array($result["details"])
    && count($result["details"]) === 0;
exit($valid ? 0 : 1);
'
}

locally_sign_stock_module() {
  local stock_module="$1"

  if [ -n "$RECOVERY_SIGNER" ]; then
    [ -f "$RECOVERY_SIGNER" ] && [ ! -L "$RECOVERY_SIGNER" ] || {
      log "The protected uninstall signer snapshot is missing or unsafe."
      return 1
    }
    /usr/bin/python3 -I - "$RECOVERY_SIGNER" "$RECOVERY_SIGNER_DIR" <<'PYSIGNERSOURCE' || return 1
import os, stat, sys
from pathlib import Path
path, directory = map(Path, sys.argv[1:])
if path != directory / 'sign_sls_mass_notify_local_sig.sh' or not path.is_absolute():
    raise SystemExit('The retained uninstall signer path differs from its protected snapshot.')
for item in (path, *path.parents):
    info = item.lstat()
    expected = stat.S_ISREG if item == path else stat.S_ISDIR
    if (not expected(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 and not (item != path and info.st_mode & stat.S_ISVTX)):
        raise SystemExit('The retained uninstall signer is not root-protected.')
info = path.lstat()
if info.st_nlink != 1 or not 0 < info.st_size <= 1048576 or directory.lstat().st_mode & 0o077:
    raise SystemExit('The retained uninstall signer is not bounded root-private source.')
PYSIGNERSOURCE
    /bin/bash -n "$RECOVERY_SIGNER" || return 1
    if ! run_without_uninstall_worker_descriptors sls_bounded_native_command 360 5 \
      /usr/bin/timeout --signal=TERM --kill-after=5 360 /usr/bin/env \
      "SLS_LOCAL_SIGN_HOME=$SIGN_HOME" \
      'SLS_LOCAL_SIGN_LOCK=/run/lock/sls-mass-notify-signing.lock' \
      "SLS_LOCAL_TRUST_HELPER=$RECOVERY_SIGNER_DIR/sls_module_trust.py" \
      'SLS_LOCAL_TRUST_MODE=uninstalled' \
      /bin/bash "$RECOVERY_SIGNER" "$stock_module" \
        >>"$STOCK_RESTORE_LOG" 2>&1; then
      log "The protected local signer could not verify the cleaned $stock_module module."
      return 1
    fi
    verify_stock_module "$stock_module" || return 1
    return 0
  fi

  # Older signers inventory the current web tree and would authorize unrelated
  # modifications. Never weaken trust when repository recovery is unavailable.
  log "No protected inventory-aware local signer is available for $stock_module. Preserve recovery files and restore a verified upstream module or reviewed baseline."
  return 1
}

remove_piper_wrapper() {
  /usr/bin/python3 -I - "/usr/local/bin/piper" "$UNINSTALL_APPROVED_SOURCE/bin/sls_mass_notify_install_piper_voices.sh" "$DATA_DIR/piper/venv/bin/piper" <<'PYPIPERREMOVE'
import fcntl
import os
import re
import stat
import sys

wrapper, approved_installer, legacy_target = sys.argv[1:]
runtime_target = '/usr/local/bin/sls_mass_notify/piper/venv/bin/piper'

def protected_read(path, maximum):
    for parent in reversed(__import__('pathlib').Path(path).parents):
        metadata = parent.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX):
            raise RuntimeError('approved Piper source has an unsafe parent')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > maximum):
            raise RuntimeError('approved Piper source is unsafe')
        body = bytearray()
        while len(body) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        after = os.fstat(descriptor)
        if (len(body) != before.st_size or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns):
            raise RuntimeError('approved Piper source changed during inspection')
        return bytes(body)
    finally:
        os.close(descriptor)

parent = os.open('/usr/local/bin', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    try:
        before = os.stat('piper', dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        raise SystemExit(0)
    if stat.S_ISLNK(before.st_mode):
        target = os.readlink('piper', dir_fd=parent)
        if before.st_uid == 0 and before.st_nlink == 1 and target in (runtime_target, legacy_target):
            current = os.stat('piper', dir_fd=parent, follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_ctime_ns) != (current.st_dev, current.st_ino, current.st_ctime_ns):
                raise RuntimeError('Piper wrapper link changed before removal')
            os.unlink('piper', dir_fd=parent)
            os.fsync(parent)
        else:
            print('Leaving unrelated Piper symbolic link unchanged.', file=sys.stderr)
        raise SystemExit(0)
    match = re.search(rb"expected=\"\$\(cat <<'EOF'\n(.*?)\nEOF\n\)\"", protected_read(approved_installer, 2 * 1024 * 1024), re.S)
    if match is None:
        raise RuntimeError('approved Piper wrapper template is unavailable')
    descriptor = os.open('piper', os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_gid != 0
                or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o755
                or opened.st_size > 16384):
            print('Leaving unrelated Piper wrapper unchanged.', file=sys.stderr)
            raise SystemExit(0)
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        body = os.read(descriptor, 16385)
        after = os.fstat(descriptor)
        current = os.stat('piper', dir_fd=parent, follow_symlinks=False)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_uid, row.st_gid,
                                row.st_mode, row.st_size, row.st_mtime_ns,
                                row.st_ctime_ns, row.st_nlink)
        if identity(before) != identity(opened) or identity(opened) != identity(after) or identity(after) != identity(current):
            raise RuntimeError('Piper wrapper changed during inspection')
        if body != match.group(1) + b'\n':
            print('Leaving modified Piper wrapper unchanged.', file=sys.stderr)
            raise SystemExit(0)
    finally:
        os.close(descriptor)
    os.unlink('piper', dir_fd=parent)
    os.fsync(parent)
finally:
    os.close(parent)
PYPIPERREMOVE
}

remove_managed_sound_link() {
  remove_managed_path "$1"
}

verify_managed_sound_link_removed() {
  local link_path="$1"
  if [ -L "$link_path" ] && [ "$(readlink -- "$link_path" 2>/dev/null || true)" = "$DATA_DIR/sounds" ]; then
    log "Uninstall verification failed; managed sound link remains: $link_path"
    return 1
  fi
}

remove_managed_path() {
  /usr/bin/python3 -I - "$1" "$DATA_DIR" "${2:-remove}" <<'PYMANAGEDREMOVE'
import errno
import os
from pathlib import Path
import pwd
import stat
import sys

path = Path(sys.argv[1])
data = Path(sys.argv[2])
action = sys.argv[3]
account = pwd.getpwnam('asterisk')
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
kinds = {
    '/usr/local/bin/sls_mass_notify': 'tree',
    '/usr/local/bin/slsconsole': 'entry',
    '/usr/local/bin/nwsalerts_ensure_menu_patch.sh': 'entry',
    '/usr/local/sbin/sign_sls_mass_notify_local_sig.sh': 'entry',
    '/etc/freepbx.secure/slsmassnotifyserver.sig': 'entry',
    '/etc/asterisk/slsmassnotify': 'entry',
    '/var/lib/asterisk/bin/sls_mass_notify': 'entry',
    '/var/lib/asterisk/bin/sls_mass_notify_test.sh': 'entry',
    '/var/www/html/admin/modules/slsmassnotifyserver': 'tree',
    '/var/www/html/admin/modules/dashboard/sections/SlsMassNotifyAnnouncement.class.php': 'entry',
    '/var/www/html/admin/modules/dashboard/views/sections/sls-mass-notify-announcement.php': 'entry',
    '/var/www/html/api/sls-mass-notify': 'tree',
    '/var/www/html/api/sipnotify': 'tree',
    '/var/www/html/mass-notify': 'tree',
    '/var/www/html/sls_mass_notify': 'tree',
    '/var/lib/asterisk/sounds/SLS_Mass_Notifications_Plugin': 'sound-link',
    '/var/lib/asterisk/sounds/en/SLS_Mass_Notifications_Plugin': 'sound-link',
    '/var/log/sls_mass_notify.log': 'entry',
    '/var/log/sls_mass_notify_events.jsonl': 'entry',
    '/var/log/sls_mass_notify_push.log': 'entry',
    '/var/tmp/nws_last_clear.ts': 'entry',
    str(data): 'tree',
    str(data / 'piper/venv/bin/piper'): 'entry',
    str(data / 'piper/venv/bin'): 'empty-directory',
    str(data / 'piper/venv'): 'empty-directory',
}
if (not path.is_absolute() or str(path) != sys.argv[1] or '..' in path.parts
        or str(data) != sys.argv[2] or data != Path('/var/lib/asterisk/SLS_Mass_Notifications_Plugin')
        or str(path) not in kinds
        or action not in ('check', 'remove')):
    raise SystemExit('Refusing an unsupported managed removal path.')
kind = kinds[str(path)]
protected = (str(path).startswith(('/usr/', '/etc/', '/var/log/'))
             and not str(path).startswith('/etc/asterisk/'))

def identity(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
            info.st_uid, info.st_gid, info.st_nlink)

def stable_identity(info):
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
            info.st_uid, info.st_gid)

def mount_id(descriptor):
    try:
        with open('/proc/self/fdinfo/' + str(descriptor), encoding='ascii') as details:
            for line in details:
                if line.startswith('mnt_id:'):
                    value = line.split(':', 1)[1].strip()
                    if value.isdigit(): return int(value)
    except OSError as error:
        raise RuntimeError('Managed removal mount boundary could not be verified.') from error
    raise RuntimeError('Managed removal mount boundary could not be verified.')

def parent():
    descriptor = os.open('/', flags)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            owners = (0,) if protected else (0, account.pw_uid)
            if (info.st_uid not in owners or info.st_gid not in (0, account.pw_gid)
                    or info.st_mode & (0o022 if protected else 0o002) and not sticky_root):
                raise RuntimeError('Managed removal ancestor has unsafe ownership or permissions.')
        result, descriptor = descriptor, -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)

visited = 0

def validate_file(descriptor, name, before, tree_mount):
    child = os.open(name, file_flags, dir_fd=descriptor)
    try:
        if identity(before) != identity(os.fstat(child)):
            raise RuntimeError('Managed removal file changed during inspection.')
        if mount_id(child) != tree_mount:
            raise RuntimeError('Managed removal tree crosses a mount boundary.')
    finally:
        os.close(child)

def validate_tree(descriptor, tree_mount, depth=0):
    global visited
    if depth > 128:
        raise RuntimeError('Managed removal tree exceeds its depth bound.')
    with os.scandir(descriptor) as entries:
        for entry in entries:
            visited += 1
            if visited > 100000:
                raise RuntimeError('Managed removal tree exceeds its entry bound.')
            before = entry.stat(follow_symlinks=False)
            if (before.st_uid not in (0, account.pw_uid)
                    or not (stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode)
                            or stat.S_ISREG(before.st_mode) and before.st_nlink == 1)):
                raise RuntimeError('Managed removal tree contains an unsafe entry.')
            if stat.S_ISDIR(before.st_mode):
                child = os.open(entry.name, flags, dir_fd=descriptor)
                try:
                    if identity(before) != identity(os.fstat(child)):
                        raise RuntimeError('Managed removal directory changed during inspection.')
                    if mount_id(child) != tree_mount:
                        raise RuntimeError('Managed removal tree crosses a mount boundary.')
                    validate_tree(child, tree_mount, depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(before.st_mode):
                validate_file(descriptor, entry.name, before, tree_mount)

def remove_tree(descriptor, tree_mount, depth=0):
    if depth > 128:
        raise RuntimeError('Managed removal tree exceeds its depth bound.')
    names = os.listdir(descriptor)
    if len(names) > 100000:
        raise RuntimeError('Managed removal tree exceeds its entry bound.')
    for name in names:
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if (before.st_uid not in (0, account.pw_uid)
                or not (stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode)
                        or stat.S_ISREG(before.st_mode) and before.st_nlink == 1)):
            raise RuntimeError('Managed removal tree contains an unsafe entry.')
        if stat.S_ISDIR(before.st_mode):
            child = os.open(name, flags, dir_fd=descriptor)
            try:
                if identity(before) != identity(os.fstat(child)):
                    raise RuntimeError('Managed removal directory changed before deletion.')
                if mount_id(child) != tree_mount:
                    raise RuntimeError('Managed removal tree crosses a mount boundary.')
                remove_tree(child, tree_mount, depth + 1)
            finally:
                os.close(child)
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stable_identity(before) != stable_identity(current):
                raise RuntimeError('Managed removal directory changed before deletion.')
            os.rmdir(name, dir_fd=descriptor)
        else:
            if stat.S_ISREG(before.st_mode):
                validate_file(descriptor, name, before, tree_mount)
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if identity(before) != identity(current):
                raise RuntimeError('Managed removal entry changed before deletion.')
            os.unlink(name, dir_fd=descriptor)

try:
    anchor = parent()
except FileNotFoundError:
    raise SystemExit(0)
opened = -1
try:
    try:
        before = os.stat(path.name, dir_fd=anchor, follow_symlinks=False)
    except FileNotFoundError:
        raise SystemExit(0)
    if (before.st_uid not in (0, account.pw_uid)
            or not (stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode)
                    or stat.S_ISREG(before.st_mode) and before.st_nlink == 1)):
        raise RuntimeError('Managed removal destination has unsafe type or ownership.')
    if kind == 'sound-link':
        if not stat.S_ISLNK(before.st_mode) or os.readlink(path.name, dir_fd=anchor) != str(data / 'sounds'):
            print('Leaving a non-module sound path unchanged: ' + str(path))
            raise SystemExit(0)
    elif kind == 'entry' and stat.S_ISDIR(before.st_mode):
        raise RuntimeError('Managed single-file removal destination is a directory.')
    anchor_mount = mount_id(anchor)
    if stat.S_ISDIR(before.st_mode):
        opened = os.open(path.name, flags, dir_fd=anchor)
        if identity(before) != identity(os.fstat(opened)):
            raise RuntimeError('Managed removal root changed during inspection.')
        if mount_id(opened) != anchor_mount:
            raise RuntimeError('Managed removal root crosses a mount boundary.')
        if kind == 'tree': validate_tree(opened, anchor_mount)
    elif stat.S_ISREG(before.st_mode):
        validate_file(anchor, path.name, before, anchor_mount)
    current_anchor = parent()
    try:
        if identity(os.fstat(anchor)) != identity(os.fstat(current_anchor)):
            raise RuntimeError('Managed removal parent changed before removal.')
    finally:
        os.close(current_anchor)
    current = os.stat(path.name, dir_fd=anchor, follow_symlinks=False)
    if identity(before) != identity(current):
        raise RuntimeError('Managed removal destination changed before removal.')
    if action == 'check':
        raise SystemExit(0)
    if stat.S_ISDIR(current.st_mode):
        if kind == 'empty-directory':
            if opened < 0 or identity(before) != identity(os.fstat(opened)) or mount_id(opened) != anchor_mount:
                raise RuntimeError('Managed empty directory changed before removal.')
            try:
                os.rmdir(path.name, dir_fd=anchor)
            except OSError as error:
                if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                    raise
        elif kind == 'tree':
            if opened < 0 or identity(before) != identity(os.fstat(opened)) or mount_id(opened) != anchor_mount:
                raise RuntimeError('Managed removal root changed before deletion.')
            validate_tree(opened, anchor_mount)
            remove_tree(opened, anchor_mount)
            current = os.stat(path.name, dir_fd=anchor, follow_symlinks=False)
            if stable_identity(before) != stable_identity(current):
                raise RuntimeError('Managed removal root changed before deletion.')
            os.rmdir(path.name, dir_fd=anchor)
        else:
            raise RuntimeError('Unsupported managed directory removal.')
    else:
        if kind == 'empty-directory':
            raise RuntimeError('Managed empty-directory destination has changed type.')
        os.unlink(path.name, dir_fd=anchor)
    os.fsync(anchor)
finally:
    if opened >= 0: os.close(opened)
    os.close(anchor)
PYMANAGEDREMOVE
}

preflight_managed_removals() {
  local path
  local -a paths=(
    "/var/www/html/admin/modules/$MODULE"
    /etc/asterisk/slsmassnotify
    /var/www/html/admin/modules/dashboard/sections/SlsMassNotifyAnnouncement.class.php
    /var/www/html/admin/modules/dashboard/views/sections/sls-mass-notify-announcement.php
    /usr/local/bin/sls_mass_notify /usr/local/bin/slsconsole
    /usr/local/bin/nwsalerts_ensure_menu_patch.sh
    /usr/local/sbin/sign_sls_mass_notify_local_sig.sh
    /etc/freepbx.secure/slsmassnotifyserver.sig
    /var/lib/asterisk/bin/sls_mass_notify /var/lib/asterisk/bin/sls_mass_notify_test.sh
    /var/www/html/api/sls-mass-notify /var/www/html/api/sipnotify
    /var/www/html/mass-notify /var/www/html/sls_mass_notify
    /var/lib/asterisk/sounds/SLS_Mass_Notifications_Plugin
    /var/lib/asterisk/sounds/en/SLS_Mass_Notifications_Plugin
    "$DATA_DIR/piper/venv/bin/piper" "$DATA_DIR/piper/venv/bin" "$DATA_DIR/piper/venv"
    /var/tmp/nws_last_clear.ts
  )
  if [ "$PURGE_CONFIG" = 1 ]; then
    paths+=("$DATA_DIR" /var/log/sls_mass_notify.log /var/log/sls_mass_notify_events.jsonl /var/log/sls_mass_notify_push.log)
  fi
  for path in "${paths[@]}"; do
    remove_managed_path "$path" check || return 1
  done
}


remove_runtime_files() {
  remove_piper_wrapper
  if [ -L "$DATA_DIR/piper/venv/bin/piper" ] && [ "$(readlink "$DATA_DIR/piper/venv/bin/piper")" = "/usr/local/bin/piper" ]; then
    remove_managed_path "$DATA_DIR/piper/venv/bin/piper"
    remove_managed_path "$DATA_DIR/piper/venv/bin"
    remove_managed_path "$DATA_DIR/piper/venv"
  fi
  remove_managed_path /usr/local/bin/sls_mass_notify
  remove_managed_path /usr/local/bin/slsconsole
  remove_managed_path /usr/local/bin/nwsalerts_ensure_menu_patch.sh
  remove_managed_path /usr/local/sbin/sign_sls_mass_notify_local_sig.sh
  remove_managed_path /etc/freepbx.secure/slsmassnotifyserver.sig
  remove_managed_sound_link /var/lib/asterisk/sounds/SLS_Mass_Notifications_Plugin
  remove_managed_sound_link /var/lib/asterisk/sounds/en/SLS_Mass_Notifications_Plugin
  remove_managed_path /var/lib/asterisk/bin/sls_mass_notify
  remove_managed_path /var/lib/asterisk/bin/sls_mass_notify_test.sh
  remove_managed_path /var/www/html/api/sls-mass-notify
  remove_managed_path /var/www/html/api/sipnotify
  remove_managed_path /var/www/html/mass-notify
  remove_managed_path /var/www/html/sls_mass_notify
  if [ "$PURGE_CONFIG" = 1 ]; then
    remove_managed_path /var/log/sls_mass_notify.log
    remove_managed_path /var/log/sls_mass_notify_events.jsonl
    remove_managed_path /var/log/sls_mass_notify_push.log
  fi
  # Leave downloaded installers and unrelated recovery directories untouched;
  # remove only the obsolete SLL weather-poller timestamp.
  remove_managed_path /var/tmp/nws_last_clear.ts
}

purge_uninstall_data() {
  # Keep named worker anchors available for every native verification and
  # final lease check. Explicit purge runs only once those writers are done;
  # no missing-directory exception weakens earlier admission.
  if [ "$PURGE_CONFIG" = 1 ]; then remove_managed_path "$DATA_DIR"; fi
}

uninstall_cron_action() {
  local action="$1" helper="$RECOVERY_SIGNER_DIR/sls_installer_recovery.py"
  local -a arguments=(--cron-action "$action")
  if [ -z "$RECOVERY_SIGNER_DIR" ] || [ ! -f "$helper" ] || [ -L "$helper" ]; then
    log "The authenticated native cron recovery helper is unavailable. Preserve the uninstall evidence; no cron replacement was authorized."
    return 1
  fi
  if [ "$action" = remove ]; then
    if [ -z "$UNINSTALL_TRANSACTION_DIR" ]; then
      log "A persistent uninstall transaction is required before removing scheduled jobs."
      return 1
    fi
    arguments+=(--cron-evidence "$UNINSTALL_TRANSACTION_DIR")
  fi
  /usr/bin/python3 -I "$helper" "${arguments[@]}"
}

remove_cron() {
  uninstall_cron_action remove
}

verify_uninstall_cron_access() {
  uninstall_cron_action preflight
}

verify_removed_cron() {
  uninstall_cron_action verify
}

restore_stock_modules() {
  remove_managed_path /var/www/html/admin/modules/dashboard/sections/SlsMassNotifyAnnouncement.class.php
  remove_managed_path /var/www/html/admin/modules/dashboard/views/sections/sls-mass-notify-announcement.php
  remove_legacy_dashboard_patch
  local stock_module
  for stock_module in dashboard framework; do
    [ -d "/var/www/html/admin/modules/$stock_module" ] || continue
    # Preserve independently reviewed branding and dependency hardening.
    # Only the approved uninstall variant may be signed; never replace the
    # whole Framework/Dashboard tree or learn a new baseline from live files.
    if ! locally_sign_stock_module "$stock_module"; then
      log "The cleaned $stock_module module differs from its reviewed uninstall inventory. Preserved review artifacts and log: $STOCK_RESTORE_LOG_PATH"
      return 1
    fi
    KEEP_SIGNING_TRUST=1
    log "Preserved and verified approved $stock_module files after removing SLL integration."
  done
}

refresh_dashboard_hook_index() {
  run_bounded_as_asterisk /usr/bin/php -d pcre.jit=0 <<'PHP'
<?php
$bootstrap_settings = ['freepbx_auth' => false, 'skip_astman' => true];
require '/etc/freepbx.conf';
$hooksFile = '/var/www/html/admin/modules/dashboard/classes/DashboardHooks.class.php';
if (!is_readable($hooksFile)) {
    file_put_contents("php://stderr", "Dashboard hook loader is missing after uninstall.\n");
    exit(1);
}
require_once $hooksFile;
$dashboard = \FreePBX::Dashboard();
$visualOrder = $dashboard->getConfig('visualorder');
$hooks = \DashboardHooks::genHooks(is_array($visualOrder) ? $visualOrder : []);
foreach ((array)$hooks as $page) {
    foreach ((array)($page['entries'] ?? []) as $entry) {
        if (($entry['rawname'] ?? '') === 'SlsMassNotifyAnnouncement') {
            file_put_contents("php://stderr", "Removed Mass Notify Dashboard hook is still discoverable.\n");
            exit(1);
        }
    }
}
$dashboard->setConfig('allhooks', $hooks);
exit(0);
PHP
}

remove_trusted_signing_key() {
  if [ "$KEEP_SIGNING_TRUST" = "1" ]; then
    # Reviewed stock modules retain approved branding and hardening overlays.
    # Delete private signing material but retain the public verification key.
    rm -rf "$SIGN_HOME"
    log "The temporary private signing key was removed; only its public verification key was retained."
    return 0
  fi
  [ -n "$SIGNING_FINGERPRINT" ] || {
    rm -rf "$SIGN_HOME"
    return 0
  }
  local home
  local -a root_native_deadline=(/usr/bin/timeout --signal=TERM --kill-after=5 1200)
  for home in /root/.gnupg /home/asterisk/.gnupg /var/lib/asterisk/.gnupg; do
    [ -d "$home" ] || continue
    if [ "$home" = "/root/.gnupg" ]; then
      run_without_uninstall_worker_descriptors sls_bounded_native_command \
        "${root_native_deadline[3]}" "${root_native_deadline[2]#--kill-after=}" \
        "${root_native_deadline[@]}" /usr/bin/env "GNUPGHOME=$home" /usr/bin/gpg --batch --yes --delete-key "$SIGNING_FINGERPRINT" >/dev/null 2>&1 || true
      printf '%s:2:\n' "$SIGNING_FINGERPRINT" | run_without_uninstall_worker_descriptors sls_bounded_native_command \
        "${root_native_deadline[3]}" "${root_native_deadline[2]#--kill-after=}" \
        "${root_native_deadline[@]}" /usr/bin/env "GNUPGHOME=$home" /usr/bin/gpg --import-ownertrust >/dev/null 2>&1 || true
    else
      run_as_asterisk /usr/bin/env "GNUPGHOME=$home" /usr/bin/gpg --batch --yes --delete-key "$SIGNING_FINGERPRINT" >/dev/null 2>&1 || true
      printf '%s:2:\n' "$SIGNING_FINGERPRINT" | run_as_asterisk /usr/bin/env "GNUPGHOME=$home" /usr/bin/gpg --import-ownertrust >/dev/null 2>&1 || true
    fi
  done
  rm -rf "$SIGN_HOME"
}

admit_root_runtime() {
  UNINSTALL_APPROVED_SOURCE="$(/usr/bin/python3 -I - <<'PYGUARD'
import hashlib, json, os, re, stat, sys, types
from pathlib import Path
sys.dont_write_bytecode = True
root = Path('/var/lib/sls-mass-notify-trust')
def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise RuntimeError('Duplicate uninstall evidence member')
        result[key] = value
    return result
def decode(body):
    return json.loads(body, object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(RuntimeError('Non-finite uninstall evidence number')))
def read(path, maximum):
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise RuntimeError('Uninstall evidence has an unprotected parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > maximum:
            raise RuntimeError('Uninstall evidence is unsafe: ' + str(path))
        body = stream.read(maximum + 1); after = os.fstat(stream.fileno())
        if len(body) != info.st_size or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('Uninstall evidence changed during inspection')
        return body
reference = decode(read(root / 'slsmassnotifyserver.active.json', 1024))
if not isinstance(reference, dict): raise SystemExit('Invalid protected SLL publisher reference')
digest = reference.get('sha256', '')
if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest) or reference.get('generation') != 'slsmassnotifyserver-' + digest:
    raise SystemExit('Invalid protected SLL publisher generation')
generation = root / reference['generation']
raw = read(generation / 'inventory.json', 8 * 1024 * 1024)
if hashlib.sha256(raw).hexdigest() != digest: raise SystemExit('Protected SLL publisher inventory changed')
inventory = decode(raw)
if not isinstance(inventory, dict) or not isinstance(inventory.get('files'), dict): raise SystemExit('Invalid protected SLL publisher inventory')
name = 'bin/sls_mass_notify/sls_module_trust.py'
entry = inventory.get('files', {}).get(name)
path = generation / 'module' / name
body = read(path, 2 * 1024 * 1024)
if not isinstance(entry, dict) or hashlib.sha256(body).hexdigest() != entry.get('sha256'):
    raise SystemExit('Protected SLL trust helper changed')
trust = types.ModuleType('sls_uninstall_trust'); trust.__file__ = str(path)
exec(compile(body, str(path), 'exec'), trust.__dict__)
data, approved_generation = trust.load(root, 'slsmassnotifyserver')
if approved_generation != generation or data['source']['kind'] != 'publisher-ed25519':
    raise SystemExit('Uninstall requires an existing publisher-approved generation')
required = {
    'bin/sls_mass_notify_uninstall.sh':'/usr/local/bin/sls_mass_notify/sls_mass_notify_uninstall.sh',
    'bin/sign_sls_mass_notify_local_sig.sh':'/usr/local/sbin/sign_sls_mass_notify_local_sig.sh',
    'bin/sls_mass_notify/sls_module_trust.py':'/usr/local/bin/sls_mass_notify/sls_module_trust.py',
    'bin/sls_mass_notify/sls_config_crypto.php':'/usr/local/bin/sls_mass_notify/sls_config_crypto.php',
    'bin/sls_mass_notify/sls_install_guard.py':'/usr/local/bin/sls_mass_notify/sls_install_guard.py',
    'bin/sls_mass_notify/sls_install_idle.py':'/usr/local/bin/sls_mass_notify/sls_install_idle.py',
    'bin/sls_mass_notify/sls_audio_state.py':'/usr/local/bin/sls_mass_notify/sls_audio_state.py',
    'bin/sls_mass_notify/sls_config_crypto.py':'/usr/local/bin/sls_mass_notify/sls_config_crypto.py',
    'bin/slsconsole':'/usr/local/bin/slsconsole',
}
optional = 'bin/sls_mass_notify/sls_legacy_permissions.py'
if optional in data['files']: required[optional] = '/usr/local/bin/sls_mass_notify/sls_legacy_permissions.py'
for name, installed in required.items():
    entry = data['files'].get(name)
    if not entry: raise SystemExit('Required signed uninstall helper is absent: ' + name)
    approved = trust.read(generation / 'module' / name, 2 * 1024 * 1024, protected=True)
    if trust.digest(approved) != entry['sha256']: raise SystemExit('Required signed uninstall helper changed: ' + name)
    try: actual = read(Path(installed), 2 * 1024 * 1024)
    except FileNotFoundError: continue
    if actual != approved: raise SystemExit('Installed uninstall helper differs from its signed release: ' + installed)
print(generation / 'module')
PYGUARD
)" || return 1
}

remove_sls_chown_exclusion() {
  # The required teardown helpers were publisher-verified before mutation. Remove
  # only this module's exact managed native exclusion before deleting its helper.
  local helper="$RECOVERY_SIGNER_DIR/sls_legacy_permissions.py"
  if [ -f "$helper" ] && [ ! -L "$helper" ]; then
    /usr/bin/python3 -I "$helper" --chown-config /etc/asterisk/freepbx_chown.conf remove-chown
  elif grep -Fq 'BEGIN SLS MASS NOTIFY DATA PERMISSIONS' /etc/asterisk/freepbx_chown.conf 2>/dev/null; then
    log 'The installed release does not approve a helper for this newer chown exclusion. Preserve the native configuration for review.'
    return 1
  fi
}

refresh_uninstall_stock_approvals() {
  local module helper="$RECOVERY_SIGNER_DIR/sls_upgrade_trust.py" workspace
  local trust="$RECOVERY_SIGNER_DIR/sls_module_trust.py"
  for module in dashboard framework; do
    if /usr/bin/python3 -I "$trust" --root /var/lib/sls-mass-notify-trust check --module "$module" --web-root /var/www/html >/dev/null 2>&1 \
      || /usr/bin/python3 -I "$trust" --root /var/lib/sls-mass-notify-trust check --module "$module" --web-root /var/www/html --uninstalled >/dev/null 2>&1 \
      || /usr/bin/python3 -I "$trust" --root /var/lib/sls-mass-notify-trust check --module "$module" --web-root /var/www/html --uninstalling >/dev/null 2>&1; then
      continue
    fi
    [ -f "$helper" ] && [ ! -L "$helper" ] || return 0
    workspace="$(uninstall_recovery_workspace sls-uninstall-stock-review)" || return 1
    log "Reviewing changed FreePBX stock using retained local signed packages. Evidence: $workspace"
    /usr/bin/python3 -I "$helper" --workspace "$workspace" --reconcile-stock \
      --coordination-fd "$UNINSTALL_MAINTENANCE_LOCK_FD" \
      --coordination-lock "${SLS_MASS_NOTIFY_MAINTENANCE_LOCK:-/run/lock/sls-mass-notify-maintenance.lock}" || {
      log "Offline stock reconciliation could not approve the changed source. Unknown local differences were preserved. Use sudo slsconsole reconcile-stock --online while online, or provide independently signed local packages; the uninstaller does not download software."
      return 1
    }
    break
  done
}

verify_uninstall_inventories() {
  local module_dir='/var/www/html/admin/modules/slsmassnotifyserver' reviewed_module
  local helper="$RECOVERY_SIGNER_DIR/sls_module_trust.py"
  inspect_module_registry || return 1
  if [ -e "$module_dir" ] || [ -L "$module_dir" ]; then
    /usr/bin/python3 -I "$helper" --root /var/lib/sls-mass-notify-trust check --module slsmassnotifyserver --web-root /var/www/html || {
      log "The installed SLL module differs from its signed inventory. Preserve the changed files for review before retrying."
      return 1
    }
  elif [ "$MODULE_REGISTRY_PRESENT" = 1 ]; then
    log "The SLL directory is missing but its FreePBX registry row remains. Preserve the signed release evidence and repair this incomplete removal before retrying."
    return 1
  fi
  for reviewed_module in dashboard framework; do
    if /usr/bin/python3 -I "$helper" --root /var/lib/sls-mass-notify-trust check --module "$reviewed_module" --web-root /var/www/html >/dev/null 2>&1; then
      continue
    fi
    /usr/bin/python3 -I "$helper" --root /var/lib/sls-mass-notify-trust check --module "$reviewed_module" --web-root /var/www/html --uninstalling || {
      log "The $reviewed_module files match neither their approved installed nor approved uninstall inventory. Preserve local changes for independent review."
      return 1
    }
  done
}

uninstall_ami_evidence() {
  /usr/bin/python3 -I /dev/fd/3 "$@" 3<<'PYUNINSTALLAMIEVIDENCE'
import errno, hashlib, json, os, re, stat, sys, time
from pathlib import Path
ROOT=Path('/var/lib/sls-mass-notify-uninstaller')
TRUST=Path('/var/lib/sls-mass-notify-trust')
PLAN='ami-removal-plan.json'; RESULT='ami-revocation.json'
STATES={'verified_absent','daemon_absent','pending_unverified'}
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def decode(raw):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('Duplicate evidence field')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique)
def identity(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def directory(path):
    path=Path(path)
    if path.resolve()!=path:raise ValueError('Noncanonical evidence directory')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=child;s=os.fstat(fd)
            if s.st_uid!=0 or s.st_mode&0o022 and not s.st_mode&stat.S_ISVTX:raise ValueError('Unprotected evidence directory')
        return fd
    except BaseException:os.close(fd);raise
def transaction(path):
    path=Path(path)
    if path.parent!=ROOT or not re.fullmatch(r'sls-uninstall-transaction\.[A-Za-z0-9_-]{6,16}',path.name):raise ValueError('Exact retained uninstall transaction required')
    fd=directory(path)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode)!=0o700:raise ValueError('Transaction is not root-private')
    finally:os.close(fd)
    return path
def read(path,maximum=262144):
    parent=directory(path.parent)
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        try:
            s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or s.st_mode&0o077 or s.st_size>maximum:raise ValueError('Unsafe evidence file')
            with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(maximum+1)
            if len(raw)!=s.st_size or identity(s)!=identity(os.fstat(fd)) or identity(s)!=identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)):raise ValueError('Evidence changed')
            return raw
        finally:os.close(fd)
    finally:os.close(parent)
def write_new(path,value):
    parent=directory(path.parent)
    try:
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as stream:stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())
        os.fsync(parent)
    finally:os.close(parent)
def valid_name(name):return type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',name) is not None
def source(value):
    if type(value) is not str or not re.fullmatch(re.escape(str(TRUST))+r'/slsmassnotifyserver-[a-f0-9]{64}/module',value):raise ValueError('Protected approved generation required')
    return value
def load_plan(path):
    path=transaction(path);raw=read(path/PLAN);value=decode(raw)
    fields={'schema','kind','transaction','approved_source','credential_sha256','owned_names','created_at'}
    if (type(value) is not dict or set(value)!=fields or type(value['schema']) is not int or value['schema']!=1
            or value['kind']!='sll-uninstall-owned-ami-plan' or value['transaction']!=str(path)
            or type(value['owned_names']) is not list or len(value['owned_names'])>4
            or any(not valid_name(name) for name in value['owned_names']) or len(set(value['owned_names']))!=len(value['owned_names'])
            or type(value['created_at']) is not int or value['created_at']<0
            or value['credential_sha256'] is not None and not re.fullmatch(r'[a-f0-9]{64}',str(value['credential_sha256']))):raise ValueError('Invalid owned-name plan')
    source(value['approved_source']);record=decode(read(path/'transaction.json',16384))
    if record.get('schema')!=1 or record.get('approved_source')!=value['approved_source']:raise ValueError('Plan and protected transaction disagree')
    return {'transaction':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'owned_names':value['owned_names']}
def load_result(path,plan):
    value=decode(read(path/RESULT))
    if (type(value) is not dict or value.get('schema')!=1 or value.get('kind')!='sll-uninstall-ami-revocation'
            or value.get('transaction')!=str(path) or value.get('plan_sha256')!=plan['sha256']
            or value.get('classification') not in STATES or type(value.get('plans')) is not list or len(value['plans'])>128):raise ValueError('Invalid prior native revocation result')
    if any(type(item) is not dict or set(item)!={'transaction','sha256'} or type(item['transaction']) is not str
           or not re.fullmatch(r'[a-f0-9]{64}',str(item['sha256'])) for item in value['plans']):raise ValueError('Invalid prior owned-plan reference')
    return value
def plans(path,mode):
    own=load_plan(path);found={str(path):own}
    if mode=='followup':
        try:prior=load_result(path,own)
        except FileNotFoundError:prior=None
        if prior is not None:
            for item in prior['plans']:
                actual=load_plan(Path(item['transaction']))
                if actual['sha256']!=item.get('sha256'):raise ValueError('Retained follow-up plan changed')
                found[actual['transaction']]=actual
    elif mode=='normal':
        fd=directory(ROOT)
        try:names=os.listdir(fd)
        finally:os.close(fd)
        if len(names)>1000:raise ValueError('Uninstall evidence needs private archival')
        for name in sorted(names):
            if not re.fullmatch(r'sls-uninstall-transaction\.[A-Za-z0-9_-]{6,16}',name) or ROOT/name==path:continue
            other=ROOT/name
            try:plan=load_plan(other)
            except FileNotFoundError:
                # Older releases had no owned-name plan; no live name becomes authority.
                if any(item.exists() or item.is_symlink() for item in (other/PLAN,other/RESULT)):raise
                continue
            try:result=load_result(other,plan)
            except FileNotFoundError:result=None
            if result is None or result['classification']!='verified_absent':
                found[str(other)]=plan
                if result is not None:
                    for item in result['plans']:
                        referenced=load_plan(Path(item['transaction']))
                        if referenced['sha256']!=item['sha256']:raise ValueError('Referenced pending owned-name plan changed')
                        found[referenced['transaction']]=referenced
    else:raise ValueError('Unknown evidence mode')
    if len(found)>128:raise ValueError('Too many unresolved native removal plans; archive reviewed evidence')
    rows=sorted(found.values(),key=lambda item:item['transaction'])
    return {'schema':1,'transaction':str(path),'plans':rows,'names':sorted({name for row in rows for name in row['owned_names']})}
def daemon_absent():
    # Same conservative native /proc check as inspect_uninstall_idle: failed CLI
    # access alone never proves a stopped daemon. Unknown inspection stays pending.
    deadline=time.monotonic()+3
    try:
        with os.scandir(Path('/proc')) as entries:
            for index,entry in enumerate(entries):
                if index>=32768 or time.monotonic()>deadline:return None
                if not entry.name.isdigit():continue
                try:executable=os.readlink(Path('/proc')/entry.name/'exe')
                except OSError as error:
                    if error.errno in (errno.ENOENT,errno.ESRCH):continue
                    return None
                if Path(executable.removesuffix(' (deleted)')).name=='asterisk':return False
        return True
    except OSError:return None
try:
    action,*args=sys.argv[1:]
    if action=='prepare':
        path=transaction(args[0]);approved=source(args[1]);value=decode(sys.stdin.buffer.read(16385))
        record=decode(read(path/'transaction.json',16384))
        if record.get('schema')!=1 or record.get('approved_source')!=approved:raise ValueError('Durable transaction must precede its owned-name plan')
        if (type(value) is not dict or set(value)!={'owned_names','credential_sha256'} or type(value['owned_names']) is not list
                or len(value['owned_names'])>4 or any(not valid_name(name) for name in value['owned_names'])
                or len(set(value['owned_names']))!=len(value['owned_names'])
                or value['credential_sha256'] is not None and not re.fullmatch(r'[a-f0-9]{64}',str(value['credential_sha256']))):raise ValueError('Invalid bounded owned-name input')
        write_new(path/PLAN,{'schema':1,'kind':'sll-uninstall-owned-ami-plan','transaction':str(path),
            'approved_source':approved,'created_at':int(time.time()),**value});print('Owned-name plan retained')
    elif action=='plans':print(json.dumps(plans(transaction(args[0]),args[1]),separators=(',',':')))
    elif action=='probe':
        name,status=args;raw=sys.stdin.buffer.read(8193);state='unverified'
        if not valid_name(name) or not re.fullmatch(r'[0-9]{1,3}',status):raise ValueError('Invalid native probe identity')
        if status=='0' and len(raw)<=8192:
            text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw.decode('utf-8','strict')).strip()
            # Native CLI startup emits this exact utils.c warning on a private
            # host without Ethernet. It carries no Manager response or authority.
            notice='No ethernet interface found for seeding global EID. You will have to set it manually.'
            text='\n'.join(line for line in text.splitlines() if line.strip()!=notice).strip()
            if text=='There is no manager called '+name:state='absent'
            elif re.search(r'^\s*username:\s*'+re.escape(name)+r'\s*$',text,re.M):state='present'
        print(json.dumps({'name':name,'state':state},separators=(',',':')))
    elif action=='finish':
        path=transaction(args[0]);expected=decode(args[1]);mode=args[2]
        if mode not in ('readonly','write') or type(expected) is not dict or set(expected)!={'schema','transaction','plans','names'} or expected['schema']!=1 or expected['transaction']!=str(path) or type(expected['plans']) is not list or not 1<=len(expected['plans'])<=128:raise ValueError('Invalid native verification plan')
        current=[load_plan(Path(item['transaction'])) for item in expected['plans']]
        if current!=expected['plans'] or str(path) not in {row['transaction'] for row in current}:raise ValueError('Owned-name evidence changed before verification')
        names=sorted({name for row in current for name in row['owned_names']})
        if expected['names']!=names:raise ValueError('Native probe names differ from protected plans')
        body=sys.stdin.buffer.read(65537)
        if len(body)>65536:raise ValueError('Native result bound exceeded')
        rows=[decode(line) for line in body.splitlines() if line.strip()];observed={}
        for row in rows:
            if type(row) is not dict or set(row)!={'name','state'} or row['name'] not in names or row['name'] in observed or row['state'] not in ('absent','present','unverified'):raise ValueError('Native result does not match owned names')
            observed[row['name']]=row['state']
        absent=all(observed.get(name)=='absent' for name in names)
        stopped=daemon_absent() if not absent else None
        result={'schema':1,'kind':'sll-uninstall-ami-revocation','transaction':str(path),
            'plan_sha256':next(row['sha256'] for row in current if row['transaction']==str(path)),
            'plans':[{'transaction':row['transaction'],'sha256':row['sha256']} for row in current],
            'classification':'verified_absent' if absent else 'daemon_absent' if stopped is True else 'pending_unverified',
            'checked_at':int(time.time()),'owned_names_checked':len(names),'verified_absent_names':sum(value=='absent' for value in observed.values()),
            'daemon_absent':stopped,'raw_manager_output_retained':False,'existing_sessions_inspected':False,'read_only_followup':mode=='readonly'}
        if mode=='write':write_new(path/RESULT,result)
        print(json.dumps(result,separators=(',',':')))
    else:raise ValueError('Unknown evidence action')
except (OSError,ValueError,TypeError,KeyError,IndexError):
    raise SystemExit('Protected native AMI removal evidence could not be verified; preserve the retained uninstall transaction.') from None
PYUNINSTALLAMIEVIDENCE
}

prepare_uninstall_ami_plan() {
  local ownership file_account
  file_account="$(rewrite_managed_text_file /etc/asterisk/manager_custom.conf managed-block "SLS Mass Notifications AMI" ami-name)" || return 1
  ownership="$(run_bounded_as_asterisk "SLS_FILE_AMI_USERNAME=$file_account" "SLS_CONFIGURED_AMI_USERNAME=$CONFIGURED_AMI_USERNAME" "SLS_AMI_SECRET_HASH=$CONFIGURED_AMI_SECRET_HASH" "SLS_AMI_OWNERSHIP_HELPER=$RECOVERY_AMI_OWNERSHIP_HELPER" /usr/bin/php -d pcre.jit=0 <<'PHPAMIPLAN'
<?php
$bootstrap_settings = ['freepbx_auth'=>false,'skip_astman'=>true]; require '/etc/freepbx.conf';
require_once (string)getenv('SLS_AMI_OWNERSHIP_HELPER');
$names = array_values(array_unique(array_filter(['slsmassnotify','sls_mass_notify','nws_push',(string)getenv('SLS_CONFIGURED_AMI_USERNAME')])));
$hash=(string)getenv('SLS_AMI_SECRET_HASH');
$file=(string)getenv('SLS_FILE_AMI_USERNAME');
$owned=\SLS\MassNotify\AmiUserOwnership::ownedNames(\FreePBX::Database(),$names,$hash,
    (string)\FreePBX::Config()->get('AMPMGRUSER'),$file === '' ? null : $file);
echo json_encode(['owned_names'=>$owned,'credential_sha256'=>$hash === '' ? null : $hash],JSON_THROW_ON_ERROR);
exit(0);
PHPAMIPLAN
)" || return 1
  printf '%s' "$ownership" | uninstall_ami_evidence prepare "$UNINSTALL_TRANSACTION_DIR" "$UNINSTALL_APPROVED_SOURCE" >/dev/null
}

verify_uninstall_runtime_ami() {
  local transaction="$1" mode="${2:-normal}" plans names name output status rows='' result deadline=$((SECONDS+120))
  plans="$(uninstall_ami_evidence plans "$transaction" "$mode")" || return 1
  names="$(/usr/bin/python3 -I -c 'import json,sys;print("\n".join(json.loads(sys.argv[1])["names"]))' "$plans")" || return 1
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    output=''; status=124
    if [ "$SECONDS" -lt "$deadline" ]; then
      if output="$(asterisk -rx "manager show user $name" 2>/dev/null | /usr/bin/head -c 8193)"; then status=0; else status=$?; fi
    fi
    result="$(printf '%s' "$output" | uninstall_ami_evidence probe "$name" "$status")" || return 1
    rows+="$result"$'\n'
  done <<<"$names"
  local evidence_mode=write
  [ "$mode" != followup ] || evidence_mode=readonly
  result="$(printf '%s' "$rows" | uninstall_ami_evidence finish "$transaction" "$plans" "$evidence_mode")" || return 1
  UNINSTALL_AMI_CLASSIFICATION="$(/usr/bin/python3 -I -c 'import json,sys;print(json.loads(sys.argv[1])["classification"])' "$result")" || return 1
  if [ "$mode" = followup ]; then printf '%s\n' "$result"; return 0; fi
  case "$UNINSTALL_AMI_CLASSIFICATION" in
    verified_absent) log 'Native AMI account-absence checks passed: every protected owned name is absent from the running Manager user inventory. Existing authenticated sessions were not inspected or disconnected.' ;;
    daemon_absent) log 'Asterisk is absent. No current daemon credential is active; verify native AMI removal after the desired PBX startup and reload.' ;;
    pending_unverified) log 'WARNING: native AMI removal is unverified. A loaded SLL Manager account may remain until a successful native PBX reload; software removal does not certify credential revocation.' ;;
    *) return 1 ;;
  esac
  if [ "$UNINSTALL_AMI_CLASSIFICATION" != verified_absent ]; then
    log "Preserved native removal evidence: $transaction. After the desired fwconsole reload, run: /bin/bash $UNINSTALL_APPROVED_SOURCE/bin/sls_mass_notify_uninstall.sh --verify-runtime $transaction"
  fi
}

uninstall_usage() {
  printf '%s\n' \
    'Usage: sls_mass_notify_uninstall.sh' \
    '       sls_mass_notify_uninstall.sh --help' \
    '       sls_mass_notify_uninstall.sh --verify-runtime RETAINED_UNINSTALL_TRANSACTION' \
    'Normal removal preserves SLL settings, media and delivery history.' \
    'For deliberate removal of retained data, use sudo slsconsole uninstall --purge.'
}

main() {
  if [ "$#" -eq 2 ] && [ "$1" = --verify-runtime ]; then
    [ "${EUID:-$(id -u)}" -eq 0 ] || { log 'Run native removal verification as root.'; return 1; }
    admit_root_runtime || return 1
    verify_uninstall_runtime_ami "$2" followup
    return $?
  fi
  if [ "$#" -gt 0 ]; then
    if [ "$#" -eq 1 ] && { [ "$1" = --help ] || [ "$1" = -h ]; }; then
      uninstall_usage
      return 0
    fi
    printf '%s\n' 'Unsupported uninstaller arguments. No removal was started.' >&2
    uninstall_usage >&2
    return 64
  fi
  require_freepbx
  admit_root_runtime || { log "Signed uninstall evidence is missing or changed. Preserve the trust store and review the named file; no uninstall changes were made. Missing stock inventories require independently verified local packages, not approval of live hashes."; return 1; }
  acquire_maintenance_coordination
  prepare_uninstall_logs
  trap handle_uninstall_exit EXIT
  snapshot_local_signer
  [ -n "$RECOVERY_SIGNER" ] || { log "An approved-inventory signer is required before uninstall can preserve the reviewed FreePBX modules."; return 1; }
  refresh_uninstall_stock_approvals
  verify_uninstall_inventories
  verify_uninstall_cron_access
  capture_signing_fingerprint
  validate_retained_user_data
  preflight_uninstall_integrations
  preflight_managed_removals
  capture_pbx_running_state
  acquire_uninstall_workers
  inspect_uninstall_idle
  capture_configured_ami_username
  UNINSTALL_TRANSACTION_DIR="$(uninstall_recovery_workspace sls-uninstall-transaction)"
  record_uninstall_stage prepared
  prepare_uninstall_ami_plan
  log "Persistent uninstall transaction: $UNINSTALL_TRANSACTION_DIR"
  assert_uninstall_workers
  record_uninstall_stage services
  remove_phone_collector_service
  assert_uninstall_workers
  remove_freepbx_manager_users
  assert_uninstall_workers
  record_uninstall_stage module
  remove_module_registration
  assert_uninstall_workers
  remove_bundled_system_recordings
  remove_cron
  record_uninstall_stage integration
  remove_menu_patch
  remove_legacy_dashboard_patch
  remove_managed_block /etc/asterisk/sip_notify_custom.conf "SLS Mass Notifications SIP NOTIFY Templates"
  remove_managed_block /etc/asterisk/extensions_custom.conf "SLS Mass Notifications Dialplan"
  remove_managed_block /etc/asterisk/manager_custom.conf "SLS Mass Notifications AMI"
  disable_apache_conf
  restore_stock_modules
  refresh_dashboard_hook_index
  remove_sls_chown_exclusion
  assert_uninstall_workers
  record_uninstall_stage runtime
  remove_runtime_files
  remove_trusted_signing_key
  record_uninstall_stage verification
  verify_freepbx_cleanup
  reload_removed_pbx_integration
  remove_freepbx_manager_users
  if [ "$PBX_RUNNING" = 1 ]; then
    asterisk -rx "manager reload" >/dev/null 2>&1 || true
  fi
  verify_freepbx_cleanup
  assert_uninstall_workers
  verify_uninstall_runtime_ami "$UNINSTALL_TRANSACTION_DIR"
  purge_uninstall_data
  record_uninstall_stage complete
  cleanup_recovery_signer
  trap - EXIT
  if [ "$PURGE_CONFIG" = "1" ]; then
    log "SLL Mass Notify Server software removal finished. Configuration and user data were purged. Native AMI result: $UNINSTALL_AMI_CLASSIFICATION."
  else
    log "SLL Mass Notify Server software removal finished. Central config, media, delivery history and audit logs were preserved. Native AMI result: $UNINSTALL_AMI_CLASSIFICATION."
  fi
  if [ -e /etc/sls-mass-notify/config-keys.json ] || [ -L /etc/sls-mass-notify/config-keys.json ]; then
    log "Configuration recovery keys were retained at /etc/sls-mass-notify/config-keys.json, including after a data purge. Keep this protected keyring while older encrypted configurations or backups may still be needed."
  fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
