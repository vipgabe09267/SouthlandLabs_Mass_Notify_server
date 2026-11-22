#!/usr/bin/python3
"""Build Piper at its canonical path in a private mount namespace, then swap it.

No package installation targets the host's active venv. A directory exchange
retains the previous environment until post-activation validation succeeds.
"""
import argparse
import hashlib
import pwd
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import types

sys.dont_write_bytecode = True
RUNTIME = Path('/usr/local/bin/sls_mass_notify')
DATA = '/var/lib/asterisk/SLS_Mass_Notifications_Plugin'
STAGE = re.compile(r'\.replacement-[a-f0-9]{24}')
FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
CHECKED_WORKER_DESCRIPTORS = ()


class EnvironmentError(RuntimeError):
    pass


def protected_directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise EnvironmentError('Piper replacement requires canonical absolute directories.')
    fd = os.open('/', FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, FLAGS, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise EnvironmentError('Piper replacement refused an unprotected ancestor: ' + str(path))
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise EnvironmentError('Piper replacement directory must be root-owned and not group/world writable.')
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(parent, name):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise EnvironmentError('Unsafe Piper environment directory: ' + name)
    return info.st_dev, info.st_ino


def exchange(parent, name, other, other_name):
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, 'renameat2', None)
    if function is None:
        raise EnvironmentError('This libc lacks atomic directory exchange; the existing Piper environment was preserved.')
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(parent, name.encode(), other, other_name.encode(), 2) != 0:
        number = ctypes.get_errno()
        raise EnvironmentError('Atomic Piper directory exchange failed (errno %d). Check filesystem support and free space; no in-place upgrade is attempted.' % number)


def system_python(path):
    for _ in range(8):
        if not re.fullmatch(r'/usr/bin/python3(?:\.[0-9]{1,2})?', path):
            raise EnvironmentError('Unexpected distribution interpreter link.')
        parent = protected_directory('/usr/bin')
        try:
            name = Path(path).name
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
                raise EnvironmentError('Distribution Python is not root protected.')
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(name, dir_fd=parent)
                path = target if target.startswith('/') else '/usr/bin/' + target
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise EnvironmentError('Unsafe distribution Python executable.')
            return
        finally: os.close(parent)
    raise EnvironmentError('Distribution Python link cycle.')



def mount_identity(descriptor):
    with open('/proc/self/fdinfo/' + str(descriptor), encoding='ascii') as stream:
        text = stream.read(4097)
    if len(text) > 4096: raise EnvironmentError('Directory descriptor metadata is oversized.')
    try: return next(line.split()[1] for line in text.splitlines() if line.startswith('mnt_id:'))
    except StopIteration: raise EnvironmentError('Directory mount identity is unavailable.') from None


def retain_stage_marker(stage, parent):
    """Publish nonsecret identity evidence only after root validates a stage."""
    stage_fd = protected_directory(stage)
    try:
        info = os.fstat(stage_fd)
        if (stat.S_IMODE(info.st_mode) != 0o700 or info.st_gid != 0
                or os.listdir(stage_fd) != ['venv'] or mount_identity(stage_fd) != mount_identity(parent)):
            raise EnvironmentError('Retained Piper stage shape or mount identity is unqualified.')
        validate_tree(stage / 'venv')
        identity_fields = {key: int(getattr(info, 'st_' + key)) for key in ('dev', 'ino', 'mode', 'uid', 'gid', 'ctime_ns')}
        body = (json.dumps({'schema': 1, 'stage': stage.name, 'identity': identity_fields}, sort_keys=True, separators=(',', ':')) + '\n').encode()
        if len(body) > 1024: raise EnvironmentError('Retained Piper marker exceeded its bound.')
        try: marker = os.open(stage.name + '.retained.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        except FileExistsError:
            existing = os.open(stage.name + '.retained.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            try:
                metadata = os.fstat(existing)
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0
                        or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o644
                        or metadata.st_size != len(body) or os.read(existing, 1025) != body):
                    raise EnvironmentError('Existing retained Piper metadata does not match its stage; preserve it for review.')
            finally: os.close(existing)
            return  # Never replace unrelated or earlier evidence.
        try:
            os.fchown(marker, 0, 0); os.fchmod(marker, 0o644)
            offset = 0
            while offset < len(body):
                count = os.write(marker, body[offset:])
                if count <= 0: raise EnvironmentError('Retained Piper marker write was incomplete.')
                offset += count
            os.fsync(marker); os.fsync(parent)
        finally: os.close(marker)
    finally: os.close(stage_fd)



def mark_retained_stages(root):
    """Qualify earlier protected stages under the permanent replacement lock."""
    if os.geteuid() != 0:
        raise EnvironmentError('Only authenticated root runtime preparation may qualify Piper recovery metadata.')
    root = Path(root); parent = protected_directory(root); lock = None
    try:
        lock = os.open('.replacement.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        metadata = os.fstat(lock)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise EnvironmentError('Retained Piper evidence lacks its protected permanent lock.')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        names = os.listdir(parent)
        if len(names) > 50000: raise EnvironmentError('Piper recovery inventory exceeds its inspection bound.')
        stages = sorted(name for name in names if STAGE.fullmatch(name))
        if len(stages) > 3: raise EnvironmentError('Too many retained Piper stages require explicit review.')
        for name in stages:
            retain_stage_marker(root / name, parent)
        return {'ok': True, 'qualified_retained_stages': len(stages)}
    except BlockingIOError:
        raise EnvironmentError('Another Piper replacement is running; retained evidence was not changed.') from None
    finally:
        if lock is not None: os.close(lock)
        os.close(parent)


def validate_tree(path, synchronize=False):
    """Only ordinary root files and standard venv interpreter/lib64 links."""
    parent = protected_directory(path); tree_mount = mount_identity(parent); count = 0; deadline = time.monotonic() + 60
    def walk(fd, relative=''):
        nonlocal count
        for name in os.listdir(fd):
            count += 1
            if count > 50000 or time.monotonic() > deadline:
                raise EnvironmentError('Piper environment inspection exceeded its file/time bound.')
            rel = relative + '/' + name if relative else name
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if before.st_uid != 0 or (not stat.S_ISLNK(before.st_mode) and before.st_mode & 0o022):
                raise EnvironmentError('Piper environment contains unprotected entries.')
            if stat.S_ISLNK(before.st_mode):
                target = os.readlink(name, dir_fd=fd)
                if rel == 'lib64' and target == 'lib':
                    continue
                if (re.fullmatch(r'bin/python(?:3(?:\.[0-9]{1,2})?)?', rel)
                        and re.fullmatch(r'(?:/usr/bin/)?python3(?:\.[0-9]{1,2})?', target)):
                    if target.startswith('/'): system_python(target)
                    continue
                raise EnvironmentError('Piper environment contains an unexpected symbolic link.')
            directory = stat.S_ISDIR(before.st_mode)
            if not directory and (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1):
                raise EnvironmentError('Piper environment contains a hard link or special file.')
            child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
                            | (os.O_DIRECTORY if directory else 0), dir_fd=fd)
            try:
                opened = os.fstat(child)
                if mount_identity(child) != tree_mount:
                    raise EnvironmentError('Piper environment crosses a mount boundary.')
                if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink) != (
                        before.st_dev, before.st_ino, before.st_mode, before.st_nlink):
                    raise EnvironmentError('Piper environment changed during inspection.')
                if directory: walk(child, rel)
                if synchronize: os.fsync(child)
            finally:
                os.close(child)
        if synchronize: os.fsync(fd)
    try: walk(parent)
    finally: os.close(parent)


DOWNLOAD_SETTINGS = ('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy','ALL_PROXY','all_proxy',
                     'NO_PROXY','no_proxy','SSL_CERT_FILE','PIP_CERT','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE')


def runtime_environment():
    # The privileged launcher validates these operator-supplied network/CA
    # controls. Preserve them for pinned downloads without forwarding loader,
    # shell, Python, GPG or alternate package-index configuration to children.
    environment = {'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                   'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','HOME':'/root',
                   'TMPDIR':os.environ.get('TMPDIR','/tmp'),'ORT_DISABLE_TELEMETRY':'1'}
    for name in DOWNLOAD_SETTINGS:
        if name in os.environ: environment[name] = os.environ[name]
    return environment


def native_guard_supervision(directory=None):
    """Load only protected immutable guard source; never a cached bytecode file."""
    directory = RUNTIME if directory is None else Path(directory)
    parent = protected_directory(directory)
    descriptor = None
    try:
        name = 'sls_install_guard.py'
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & 0o022 or not 1 <= before.st_size <= 262144):
            raise EnvironmentError('Native supervision source is not protected; no native command started.')
        body = os.read(descriptor, 262145)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(body) != before.st_size or any(getattr(before, key) != getattr(after, key)
                or getattr(after, key) != getattr(named, key) for key in fields):
            raise EnvironmentError('Native supervision source changed; no native command started.')
        module = types.ModuleType('sls_piper_guard_supervision')
        module.__file__ = str(directory / name)
        exec(compile(body, module.__file__, 'exec'), module.__dict__)
        return module
    finally:
        if descriptor is not None: os.close(descriptor)
        os.close(parent)


def checked(command, timeout=30, *, environment=None, quiet=False, supervisor_directory=None):
    original = command
    options = {'stdin': subprocess.DEVNULL, 'check': False, 'env': runtime_environment() if environment is None else dict(environment)}
    if quiet:options.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if environment is not None:options['cwd']='/'
    supervisor_root = RUNTIME if supervisor_directory is None else Path(supervisor_directory)
    if CHECKED_WORKER_DESCRIPTORS:
        # subprocess.run kills its child on KeyboardInterrupt. That child is
        # our lease-retaining root waiter, so it must outlive and reap the
        # native validator before cancellation can release the parent's FDs.
        supervisor = native_guard_supervision() if supervisor_directory is None else native_guard_supervision(supervisor_root)
        with supervisor.native_child_scope():
            control, remote = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            child = None
            native_pidfd = None
            try:
                options.pop('check')
                options['pass_fds'] = (*CHECKED_WORKER_DESCRIPTORS, remote.fileno())
                command = ['/usr/bin/python3', '-I', str(supervisor_root / 'sls_install_guard.py'), '--data', DATA,
                    '--inherited-fds', ','.join(map(str, CHECKED_WORKER_DESCRIPTORS)),
                    '--native-control-fd', str(remote.fileno()), '--command-timeout', str(timeout), 'run', '--', *command]
                child = subprocess.Popen(command, **options)
                remote.close()
                control.settimeout(5)
                raw = control.recv(1025)
                if not raw or len(raw) > 1024:
                    raise EnvironmentError('Native child identity was not established; no command acknowledged.')
                identity = json.loads(raw)
                if (type(identity) is not dict or set(identity) != {'schema', 'waiter_pid', 'native_pid'}
                        or type(identity['schema']) is not int or identity['schema'] != 1
                        or type(identity['waiter_pid']) is not int or identity['waiter_pid'] != child.pid
                        or type(identity['native_pid']) is not int or identity['native_pid'] <= 1
                        or identity['native_pid'] in (os.getpid(), child.pid)):
                    raise EnvironmentError('Native child identity is invalid; no command acknowledged.')
                native = identity['native_pid']
                native_pidfd = os.pidfd_open(native)
                status = Path('/proc/%d/status' % native).read_text()
                parent = int(next(line.split()[1] for line in status.splitlines() if line.startswith('PPid:')))
                if (parent != child.pid or os.getpgid(native) != native or os.getsid(native) != native
                        or select.select([native_pidfd], [], [], 0)[0]):
                    raise EnvironmentError('Native child ownership changed; no command acknowledged.')
                control.send(b'start')
                control.close()
                returncode = child.wait()
            finally:
                control.close(); remote.close()
                # A cancelled parent never SIGKILLs its root waiter. Reap it
                # first, then the surrounding subreaper cleans only adopted
                # invocation descendants if that waiter died independently.
                if child is not None:
                    while True:
                        try:
                            child.wait()
                            break
                        except KeyboardInterrupt:
                            continue
                if native_pidfd is not None: os.close(native_pidfd)
        result = subprocess.CompletedProcess(original, returncode)
    else:
        options['timeout'] = timeout
        if environment is not None:
            # A bounded runuser may exit/timeout while its native descendants
            # remain. Adopt and reap only this invocation's children before
            # returning to an outer installer/worker lease holder.
            supervisor = native_guard_supervision() if supervisor_directory is None else native_guard_supervision(supervisor_root)
            options['start_new_session'] = True
            with supervisor.native_child_scope():
                result = subprocess.run(command, **options)
        else:
            result = subprocess.run(command, **options)
    if result.returncode:
        raise EnvironmentError('Piper replacement command failed (exit %d): %s. Review the preceding installer output.'
                               % (result.returncode, Path(original[0]).name))


_REUSE_DATA=('piper-requirements.txt','piper-requirements.lock','piper-packaging.lock')

_REUSE_CHECKER='sls_piper_dependencies.py'

_PTH_PROFILE=b"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n"

_PTH_REL='lib/python3.11/site-packages/distutils-precedence.pth'

def _reuse_stamp(s):
    return tuple(getattr(s,'st_'+k)for k in('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'))

def _reuse_read(path,maximum=262144):
    path=Path(path)
    if path.resolve()!=path:raise EnvironmentError('Piper contract/file alias is not qualified.')
    parent=protected_directory(path.parent)
    try:fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
    finally:os.close(parent)
    try:
        before=os.fstat(fd)
        if(not stat.S_ISREG(before.st_mode)or before.st_uid!=0 or before.st_nlink!=1
                or before.st_mode&0o7022 or not 0<=before.st_size<=maximum):
            raise EnvironmentError('Piper contract/file is not root-protected and bounded.')
        with os.fdopen(os.dup(fd),'rb')as stream:body=stream.read(maximum+1)
        if len(body)!=before.st_size or _reuse_stamp(before)!=_reuse_stamp(os.fstat(fd))or _reuse_stamp(before)!=_reuse_stamp(path.lstat()):
            raise EnvironmentError('Piper contract/file changed during qualification.')
        return body,_reuse_stamp(before)
    finally:os.close(fd)

def _reuse_contract(directory,*,candidate_code=True):
    directory=Path(directory)
    if directory.resolve()!=directory:raise EnvironmentError('Piper contract directory alias is not qualified.')
    fd=protected_directory(directory)
    try:anchor=_reuse_stamp(os.fstat(fd))[:5]
    finally:os.close(fd)
    bodies={};stamps={}
    names=(*_REUSE_DATA,_REUSE_CHECKER,'sls_install_guard.py')if candidate_code else _REUSE_DATA
    for name in names:bodies[name],stamps[name]=_reuse_read(directory/name)
    return bodies,{'root':str(directory),'anchor':anchor,'files':stamps,'sha256':{k:hashlib.sha256(v).hexdigest()for k,v in bodies.items()}}

def _reuse_python(venv):
    current=Path(venv)/'bin/python';seen=set()
    for unused in range(10):
        name=str(current)
        if name in seen:raise EnvironmentError('Piper interpreter alias cycle is not qualified.')
        seen.add(name);parent=protected_directory(current.parent)
        try:
            info=os.stat(current.name,dir_fd=parent,follow_symlinks=False)
            if info.st_uid!=0 or(not stat.S_ISLNK(info.st_mode)and info.st_mode&0o7022):raise EnvironmentError('Piper interpreter is not root-protected.')
            if stat.S_ISLNK(info.st_mode):
                target=os.readlink(current.name,dir_fd=parent)
                if target.startswith('/'):
                    if not re.fullmatch(r'/usr/bin/python3(?:[.][0-9]{1,2})?',target):raise EnvironmentError('Piper external interpreter target is not qualified.')
                    current=Path(target)
                else:
                    if not re.fullmatch(r'python3(?:[.][0-9]{1,2})?',target):raise EnvironmentError('Piper relative interpreter target is not qualified.')
                    current=current.parent/target
                continue
            if current.parent!=Path('/usr/bin')or not re.fullmatch(r'python3(?:[.][0-9]{1,2})?',current.name):raise EnvironmentError('Piper interpreter must resolve to qualified distribution Python.')
        finally:os.close(parent)
        body,stamp=_reuse_read(current,64*1024**2)
        return {'path':str(current),'stamp':stamp,'sha256':hashlib.sha256(body).hexdigest()}
    raise EnvironmentError('Piper interpreter resolution exceeded its bound.')

def _reuse_snapshot(root,*,whole=True):
    root=Path(root);venv=root/'venv'
    validate_tree(venv)
    scan=root if whole else venv
    if scan.resolve()!=scan:raise EnvironmentError('Piper root alias is not qualified.')
    fd=protected_directory(scan)
    try:
        mount=mount_identity(fd);root_info=os.fstat(fd);anchor=_reuse_stamp(root_info)[:5]
        if root_info.st_mode&0o7022:raise EnvironmentError('Piper root has unqualified permission bits.')
        if whole and set(os.listdir(fd))!={'venv','.replacement.lock'}:raise EnvironmentError('Retained or unknown Piper-root entries keep full replacement reserves.')
    finally:os.close(fd)
    rows={};total=0;deadline=time.monotonic()+60
    def walk(path,relative='',depth=0):
        nonlocal total
        if depth>64:raise EnvironmentError('Piper qualification depth bound exceeded.')
        parent=protected_directory(path)
        try:
            initial=_reuse_stamp(os.fstat(parent));names=sorted(os.listdir(parent))
            for name in names:
                if len(rows)>=50000 or time.monotonic()>deadline:raise EnvironmentError('Piper qualification resource bound exceeded.')
                rel=relative+'/'+name if relative else name;entry=path/name;info=os.stat(name,dir_fd=parent,follow_symlinks=False)
                if info.st_uid!=0 or(not stat.S_ISLNK(info.st_mode)and info.st_mode&0o7022):raise EnvironmentError('Piper qualification found unprotected entries.')
                row={'stamp':_reuse_stamp(info)};rows[rel]=row
                active_rel=rel[len('venv/'):]if whole and rel.startswith('venv/')else rel if not whole else None
                if active_rel is not None and name in('sitecustomize','usercustomize'):raise EnvironmentError('Piper site-hook package is not qualified.')
                if stat.S_ISDIR(info.st_mode):
                    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                    try:
                        if mount_identity(child)!=mount or _reuse_stamp(os.fstat(child))!=_reuse_stamp(info):raise EnvironmentError('Piper qualification crossed or changed a directory.')
                    finally:os.close(child)
                    walk(entry,rel,depth+1)
                elif stat.S_ISREG(info.st_mode):
                    body,stamp=_reuse_read(entry,256*1024**2);total+=len(body)
                    if total>2*1024**3:raise EnvironmentError('Piper qualification byte bound exceeded.')
                    row.update(stamp=stamp,sha256=hashlib.sha256(body).hexdigest())
                    active_rel=rel[len('venv/'):]if whole and rel.startswith('venv/')else rel if not whole else None
                    if active_rel is not None:
                        leaf=entry.name
                        if leaf.startswith(('sitecustomize.','usercustomize.')):raise EnvironmentError('Piper site customization is not qualified.')
                        if leaf.endswith('.pth')and(active_rel!=_PTH_REL or body!=_PTH_PROFILE):raise EnvironmentError('Piper .pth profile is not qualified.')
                elif stat.S_ISLNK(info.st_mode):
                    target=os.readlink(name,dir_fd=parent);row['target']=target
                    normalized=re.sub(r'^[.]replacement-[a-f0-9]{24}/','',rel)
                    if whole:
                        if not normalized.startswith('venv/'):raise EnvironmentError('Piper symbolic link is outside the qualified venv profile.')
                        normalized=normalized[len('venv/'):]
                    if normalized=='lib64'and target=='lib':continue
                    if not re.fullmatch(r'bin/python(?:3(?:[.][0-9]{1,2})?)?',normalized)or not re.fullmatch(r'(?:/usr/bin/)?python3(?:[.][0-9]{1,2})?',target):raise EnvironmentError('Piper symbolic link is not qualified.')
                else:raise EnvironmentError('Piper special file is not qualified.')
            if names!=sorted(os.listdir(parent))or initial!=_reuse_stamp(os.fstat(parent)):raise EnvironmentError('Piper tree changed during qualification.')
        finally:os.close(parent)
    walk(scan)
    cfg,_=_reuse_read(venv/'pyvenv.cfg',16384);settings={}
    for line in cfg.decode('utf-8').splitlines():
        if '='in line:
            k,v=line.split('=',1);k=k.strip()
            if not re.fullmatch('[a-z][a-z-]*',k)or k not in('home','include-system-site-packages','version','executable','command','prompt'):raise EnvironmentError('Piper venv configuration key is not qualified.')
            if k in settings:raise EnvironmentError('Piper venv configuration has duplicate keys.')
            settings[k]=v.strip()
    if settings.get('include-system-site-packages','').lower()!='false'or settings.get('home')!='/usr/bin'or re.fullmatch(r'3[.]11[.][0-9]+',settings.get('version',''))is None:raise EnvironmentError('Piper venv inheritance profile is not qualified.')
    if not (venv/_PTH_REL).is_file():raise EnvironmentError('Pinned setuptools .pth profile is missing.')
    python=_reuse_python(venv)
    return {'root':str(scan),'anchor':anchor,'mount':mount,'entries_sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'entries':len(rows),'logical_bytes':total,'python':python}

def _reuse_validation_environment():
    return {'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','ORT_DISABLE_TELEMETRY':'1','PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1'}

def _reuse_as_native(command,timeout=25,*,contract=None):
    try:account=pwd.getpwnam('asterisk')
    except KeyError:raise EnvironmentError('Piper native validation account is unavailable.')from None
    if account.pw_uid<=0 or account.pw_gid<=0:raise EnvironmentError('Piper validation requires the qualified native unprivileged account.')
    clean=_reuse_validation_environment()
    # Clean waiter/runuser environment too; clearing only the final env command
    # would leave loader variables able to affect root runuser before exec.
    native=['/usr/bin/env','-i',*[key+'='+value for key,value in clean.items()],*command]
    checked(['/usr/sbin/runuser','-u',account.pw_name,'--',*native],timeout=timeout,environment=clean,quiet=True,supervisor_directory=RUNTIME if contract is None else Path(contract))

def _reuse_checker_program(checker,requirements):
    return "import os,sys,fcntl; fd=os.memfd_create('sll-piper-contract',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING); body="+repr(requirements)+"; os.write(fd,body); os.lseek(fd,0,0); fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL); __file__='<candidate-authenticated-piper-checker>'; __name__='__main__'; sys.argv=['candidate-checker','--requirements','/proc/self/fd/'+str(fd),'--quiet']; exec(compile("+repr(checker)+",'<candidate-authenticated-piper-checker>','exec'))"

def validate_runtime(root,*,contract=None):
    """One candidate-owned static/ABI/functional predicate for reuse and build."""
    root=Path(root);contract=RUNTIME if contract is None else Path(contract)
    bodies,_=_reuse_contract(contract);before=_reuse_snapshot(root,whole=False);python=str(root/'venv/bin/python')
    abi="import os,sys,sysconfig; assert sys.implementation.name=='cpython' and sys.version_info[:2]==(3,11); assert os.uname().machine in ('x86_64','amd64'); assert sysconfig.get_config_var('MULTIARCH')=='x86_64-linux-gnu'; assert str(sysconfig.get_config_var('SOABI')).startswith('cpython-311-'); assert os.path.realpath(sys.executable)==sys.argv[1]"
    _reuse_as_native([python,'-I','-B','-S','-c',abi,before['python']['path']],contract=contract)
    prefix="import os,sys; assert sys.prefix!=sys.base_prefix and os.path.realpath(sys.prefix)==os.path.realpath(sys.argv[1])"
    _reuse_as_native([python,'-I','-B','-c',prefix,str(root/'venv')],contract=contract)
    # Requirements/checker are authenticated PUBLIC source bytes. A memfd lets
    # the native user read them without making a private source generation public.
    program=_reuse_checker_program(bodies[_REUSE_CHECKER],bodies['piper-requirements.txt'])
    _reuse_as_native([python,'-I','-B','-c',program],contract=contract)
    expected=[]
    for line in bodies['piper-requirements.txt'].decode('utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]*)==([0-9]+(?:[.][0-9]+)*)',line)
        if not match:raise EnvironmentError('Piper requirement profile is not qualified.')
        expected.append(re.sub('[-_.]+','-',match.group(1)).lower())
    distributions="import importlib.metadata,re; actual=[re.sub('[-_.]+','-',d.metadata['Name']).lower()for d in importlib.metadata.distributions()]; assert len(actual)==len(set(actual)) and set(actual)==set("+repr(expected)+")"
    _reuse_as_native([python,'-I','-B','-c',distributions],contract=contract)
    _reuse_as_native([python,'-I','-B','-m','pip','--version'],contract=contract)
    _reuse_as_native([python,'-I','-B','-m','pip','check'],contract=contract)
    _reuse_as_native([python,'-I','-B','-m','piper','-h'],contract=contract)
    _reuse_as_native([str(root/'venv/bin/piper'),'-h'],contract=contract)
    if before!=_reuse_snapshot(root,whole=False):raise EnvironmentError('Piper runtime changed during validation.')

def probe_runtime_reuse(root,candidate_contract,previous_contract):
    """Caller must first authenticate both source-generation directories."""
    root=Path(root);parent=lock=None
    try:
        candidate,cs=_reuse_contract(candidate_contract);previous,ps=_reuse_contract(previous_contract,candidate_code=False)
        if any(candidate[name]!=previous[name]for name in _REUSE_DATA):return None
        parent=protected_directory(root)
        lock=os.open('.replacement.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        info=os.fstat(lock)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_size!=0 or stat.S_IMODE(info.st_mode)!=0o600:return None
        fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
        before=_reuse_snapshot(root)
        validate_runtime(root,contract=Path(candidate_contract))
        after=_reuse_snapshot(root);_,ca=_reuse_contract(candidate_contract);_,pa=_reuse_contract(previous_contract,candidate_code=False)
        if before!=after or cs!=ca or ps!=pa:return None
        return {'schema':1,'kind':'sll-qualified-piper-reuse-v1','runtime':after,'candidate_contract':cs,'previous_contract':ps,'qualified':True}
    except (OSError,RuntimeError,ValueError,UnicodeError,KeyError,subprocess.SubprocessError):return None
    finally:
        if lock is not None:os.close(lock)
        if parent is not None:os.close(parent)



def _replacement_temporary_state(directory=None,*,io_root=Path('/')):
    selected=str(directory if directory is not None else os.environ.get('TMPDIR','/tmp'))
    private='/var/spool/sls-mass-notify-installer-tmp'
    if selected not in('/tmp','/var/tmp',private):raise EnvironmentError('Piper replacement temporary role is not qualified.')
    io_root=Path(io_root)
    if not io_root.is_absolute()or io_root.resolve()!=io_root:raise EnvironmentError('Piper replacement IO root is not canonical.')
    target=io_root/selected.lstrip('/')
    if target.resolve()!=target:raise EnvironmentError('Piper replacement temporary role may not be an alias.')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    descriptor=protected_directory(io_root);parent_identity=None
    try:
        for component in Path(selected).parts[1:]:
            before=os.fstat(descriptor)
            if before.st_uid!=0 or(before.st_mode&0o022 and not before.st_mode&stat.S_ISVTX):raise EnvironmentError('Piper replacement temporary ancestor is unprotected.')
            if selected==private and before.st_mode&0o022:raise EnvironmentError('Private Piper replacement ancestor is writable.')
            named=os.stat(component,dir_fd=descriptor,follow_symlinks=False)
            child=os.open(component,flags,dir_fd=descriptor)
            opened=os.fstat(child)
            if (named.st_dev,named.st_ino,named.st_uid,named.st_gid,named.st_mode)!=(opened.st_dev,opened.st_ino,opened.st_uid,opened.st_gid,opened.st_mode):
                os.close(child);raise EnvironmentError('Piper replacement temporary role changed while opening.')
            parent_identity=(before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode)
            os.close(descriptor);descriptor=child
        info=os.fstat(descriptor)
        if selected==private:
            try:account=pwd.getpwnam('asterisk')
            except KeyError:raise EnvironmentError('Piper native temporary-role account is unavailable.')from None
            if account.pw_uid<=0 or account.pw_gid<=0 or info.st_uid!=0 or info.st_gid!=account.pw_gid or stat.S_IMODE(info.st_mode)!=0o710:
                raise EnvironmentError('Private Piper replacement workspace must remain root:native-primary-GID mode0710.')
        elif info.st_uid!=0 or(info.st_mode&0o022 and not info.st_mode&stat.S_ISVTX):raise EnvironmentError('Piper replacement temporary role is not protected or sticky.')
        current=target.lstat()
        if(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)!=(current.st_dev,current.st_ino,current.st_uid,current.st_gid,current.st_mode):raise EnvironmentError('Piper replacement temporary role changed during observation.')
        return {'path':selected,'actual_path':str(target),'identity':{name:getattr(info,'st_'+name)for name in('dev','ino','uid','gid','mode')},'parent_identity':parent_identity,'statvfs':os.fstatvfs(descriptor)}
    finally:os.close(descriptor)

def admit_replacement_capacity(root, *, temporary_directory=None, profile=None):
    selected = str(temporary_directory if temporary_directory is not None else os.environ.get('TMPDIR', '/tmp'))
    _replacement_temporary_state(selected)
    body, _ = _reuse_read(RUNTIME / 'sls_resource_capacity.py', 2 * 1024 ** 2)
    resource = types.ModuleType('sls_piper_candidate_replacement_capacity')
    resource.__file__ = str(RUNTIME / 'sls_resource_capacity.py')
    try:
        exec(compile(body, resource.__file__, 'exec'), resource.__dict__)
        result = resource.admit_piper_preparation_storage(selected, profile=profile)
        if (type(result) is not dict or type(result.get('schema')) is not int or result['schema'] != 1
                or result.get('temporary_directory') != selected or result.get('replacement_capacity_admitted') is not True
                or type(result.get('filesystems')) is not list or not result['filesystems']):
            raise ValueError('Common replacement admission returned an invalid result')
        return result
    except (OSError, RuntimeError, ValueError, AttributeError, SyntaxError, UnicodeError) as error:
        # Only the common candidate helper's explicit closed numeric refusal
        # may be copied into the private installer stderr/log. Probe stdout
        # stays a single JSON object and configuration/ledger bodies stay private.
        details = getattr(error, 'capacity_details', None)
        if (getattr(error, 'code', None) == 'piper_preparation_capacity_refused'
                and type(details) is dict and set(details) == {'schema','errors','filesystems','raw_configuration_or_ledger_emitted'}
                and type(details.get('schema')) is int and details['schema'] == 1
                and details.get('raw_configuration_or_ledger_emitted') is False):
            try:
                body = json.dumps(details, sort_keys=True, allow_nan=False)
                if len(body.encode()) <= 65536: print(body, file=sys.stderr)
            except (TypeError, ValueError): pass
        raise EnvironmentError('Full Piper replacement storage admission failed; active and recovery environments were preserved.') from error


def build_private(stage, root, wheelhouse=None):
    # A direct invocation must never hide/overwrite the host's active venv.
    if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/%d/ns/mnt' % os.getppid()):
        raise EnvironmentError('Piper construction requires a separate private mount namespace.')
    for path in (stage, stage / 'venv', root, root / 'venv'):
        fd = protected_directory(path); os.close(fd)
    checked(['/usr/bin/mount', '--bind', str(stage / 'venv'), str(root / 'venv')])
    os.umask(0o022)
    checked(['/usr/bin/python3', '-I', '-m', 'venv', str(root / 'venv')], 120)
    python = str(root / 'venv/bin/python')
    source = ['--index-url', 'https://pypi.org/simple']
    if wheelhouse is not None:
        fd = protected_directory(wheelhouse); os.close(fd)
        source = ['--no-index', '--find-links', str(wheelhouse)]
    # pip --isolated ignores PIP_CERT configuration. The privileged launcher
    # has independently validated each canonical root-protected CA selector.
    # Explicit pip precedence: PIP_CERT > REQUESTS_CA_BUNDLE > SSL_CERT_FILE > CURL_CA_BUNDLE.
    certificate = next((os.environ[name] for name in ('PIP_CERT','REQUESTS_CA_BUNDLE','SSL_CERT_FILE','CURL_CA_BUNDLE')
                        if os.environ.get(name)), None)
    certificate_args = ['--cert', certificate] if certificate is not None else []
    private_download_settings = any(os.environ.get(name) for name in DOWNLOAD_SETTINGS)
    for lock in ('piper-packaging.lock', 'piper-requirements.lock'):
        try:
            checked([python, '-I', '-m', 'pip', '--isolated', *certificate_args, 'install', '--no-cache-dir', '--only-binary=:all:',
                     '--require-hashes', '--no-input', *source, '-r', str(RUNTIME / lock)], 180,
                    quiet=private_download_settings)
        except subprocess.TimeoutExpired:
            raise EnvironmentError('Timed out installing the pinned wheels from ' + lock) from None
    validate_runtime(root)
    validate_tree(root / 'venv', synchronize=True)


def guard_workers():
    tool = str(RUNTIME / 'sls_install_guard.py')
    descriptors = []
    prepare = subprocess.Popen(['/usr/bin/python3', '-I', tool, '--data', DATA, 'prepare'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    process = None
    try:
        ready, _, _ = select.select([prepare.stdout], [], [], 125)
        response = prepare.stdout.readline(16385) if ready else ''
        if not response.startswith('prepared ') or not response.endswith('\n') or len(response) > 16384:
            raise EnvironmentError('Worker guard cannot prepare retained descriptors; no older-helper fallback is permitted.')
        mapping = json.loads(response[len('prepared '):])
        if (type(mapping) is not dict or set(mapping) != {'schema', 'pid', 'fds'}
                or type(mapping['schema']) is not int or mapping['schema'] != 1
                or type(mapping['pid']) is not int or mapping['pid'] != prepare.pid
                or type(mapping['fds']) is not list or not 1 <= len(mapping['fds']) <= 1100
                or any(type(fd) is not int or not 3 <= fd <= 9999999 for fd in mapping['fds'])
                or len(set(mapping['fds'])) != len(mapping['fds'])):
            raise EnvironmentError('Invalid retained worker descriptor preparation.')
        for remote in mapping['fds']:
            descriptors.append(os.open('/proc/%d/fd/%d' % (prepare.pid, remote),
                                       os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC))
        prepare.communicate('release\n', timeout=5)
        if prepare.returncode != 0:
            raise EnvironmentError('Worker anchor preparation did not finish safely.')
        process = subprocess.Popen(['/usr/bin/python3', '-I', tool, '--data', DATA, '--timeout', '120',
                                    '--inherited-fds', ','.join(map(str, descriptors)), 'hold'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, pass_fds=descriptors)
        ready, _, _ = select.select([process.stdout], [], [], 125)
        if not ready or process.stdout.readline().strip() != 'ready':
            raise EnvironmentError('Notification workers did not become idle; the active Piper environment was preserved.')
        process.sls_retained_descriptors = tuple(descriptors)
        return process
    except BaseException:
        for child in (prepare, process):
            if child is None: continue
            if child.poll() is None: child.terminate()
            try: child.communicate(timeout=5)
            except subprocess.TimeoutExpired: child.kill(); child.communicate()
        for descriptor in descriptors: os.close(descriptor)
        raise


def replace_environment(root, builder, validator, workers_paused=False, *, profile=None):
    """Injectable builder/validator allow private fault tests without package I/O."""
    global CHECKED_WORKER_DESCRIPTORS
    previous_descriptors = CHECKED_WORKER_DESCRIPTORS
    parent = protected_directory(root); lock = stage_fd = None; stage = None; guard = None
    exchanged = False; committed = False; original = replacement = None
    try:
        lock = os.open('.replacement.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                       0o600, dir_fd=parent)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise EnvironmentError('Unsafe Piper replacement lock; no interpreter was executed.')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        leftovers = [name for name in os.listdir(parent) if STAGE.fullmatch(name)]
        if len(leftovers) >= 3:
            raise EnvironmentError('Three Piper recovery directories remain under ' + str(root) + '. Review them before creating another replacement; the active environment was preserved.')
        # Reuse credit never authorizes a later fallback allocation. Admit the
        # full shared requirement before any target/stage/builder write.
        admit_replacement_capacity(root, profile=profile)
        # A fresh installation needs an empty bind target. Existing content is
        # never removed or passed to pip on the host.
        try: original = identity(parent, 'venv')
        except FileNotFoundError:
            os.mkdir('venv', 0o755, dir_fd=parent); os.fsync(parent); original = identity(parent, 'venv')
        validate_tree(root / 'venv')
        stage = root / ('.replacement-' + secrets.token_hex(12))
        os.mkdir(stage.name, 0o700, dir_fd=parent)
        stage_fd = os.open(stage.name, FLAGS, dir_fd=parent)
        os.fchown(stage_fd, 0, 0); os.fchmod(stage_fd, 0o700)
        os.mkdir('venv', 0o755, dir_fd=stage_fd)
        candidate_fd = os.open('venv', FLAGS, dir_fd=stage_fd)
        try: os.fchown(candidate_fd, 0, 0); os.fchmod(candidate_fd, 0o755)
        finally: os.close(candidate_fd)
        os.fsync(stage_fd); os.fsync(parent)
        replacement = identity(stage_fd, 'venv')
        builder(stage, lock)
        validate_tree(stage / 'venv', synchronize=True)
        if not workers_paused: guard = guard_workers()
        if guard is not None:
            CHECKED_WORKER_DESCRIPTORS = getattr(guard, 'sls_retained_descriptors', ())
        if CHECKED_WORKER_DESCRIPTORS: checked(['/usr/bin/true'], timeout=5)
        if identity(parent, 'venv') != original or identity(stage_fd, 'venv') != replacement:
            raise EnvironmentError('A Piper environment changed during preparation; no directory was activated.')
        exchange(parent, 'venv', stage_fd, 'venv'); exchanged = True
        os.fsync(parent); os.fsync(stage_fd)
        validator(root)
        if CHECKED_WORKER_DESCRIPTORS: checked(['/usr/bin/true'], timeout=5)
        # Check both inode identities again before removing the old tree.
        if identity(parent, 'venv') != replacement or identity(stage_fd, 'venv') != original:
            raise EnvironmentError('Piper activation identities changed; preserve the recovery directory.')
        if not shutil.rmtree.avoids_symlink_attacks:
            raise EnvironmentError('Safe Piper recovery cleanup is unavailable; preserve the recovery directory.')
        validate_tree(stage / 'venv')
        committed = True
        shutil.rmtree('venv', dir_fd=stage_fd)
        os.fsync(stage_fd); os.rmdir(stage.name, dir_fd=parent); os.fsync(parent)
        stage = None
        return {'ok': True, 'replaced': True}
    except BaseException as error:
        # Once cleanup has started, the original may be incomplete. Never swap
        # a partially deleted old tree back into service.
        if committed:
            return {'ok': True, 'replaced': True, 'cleanup_pending': True,
                    'recovery_directory': str(stage),
                    'warning': 'The new Piper environment passed validation. Old-environment cleanup was incomplete; preserve the recovery directory for review.'}
        if exchanged and stage is not None:
            try:
                if identity(parent, 'venv') != replacement or identity(stage_fd, 'venv') != original:
                    raise EnvironmentError('Piper rollback identities changed.')
                exchange(parent, 'venv', stage_fd, 'venv')
                os.fsync(parent); os.fsync(stage_fd)
            except (OSError, EnvironmentError):
                raise EnvironmentError('Piper rollback could not be verified. Preserve recovery directory ' + str(stage) + '.') from error
        if isinstance(error, BlockingIOError):
            detail = 'Another Piper replacement is running; retry after it finishes.'
        elif isinstance(error, OSError):
            detail = 'Piper filesystem operation failed (errno %s): %s.' % (error.errno, error.strerror)
        else:
            detail = str(error) if isinstance(error, EnvironmentError) else type(error).__name__
        if stage is not None:
            try: retain_stage_marker(stage, parent)
            except (OSError, EnvironmentError): pass  # Unknown evidence stays private and unqualified.
            detail += ' Recovery directory: ' + str(stage) + '.'
        raise EnvironmentError(detail) from error
    finally:
        CHECKED_WORKER_DESCRIPTORS = previous_descriptors
        if guard is not None:
            try: guard.communicate('release\n', timeout=5)
            except subprocess.TimeoutExpired:
                guard.terminate()
                try: guard.communicate(timeout=5)
                except subprocess.TimeoutExpired: guard.kill(); guard.communicate()
            finally:
                for descriptor in getattr(guard, 'sls_retained_descriptors', ()): os.close(descriptor)
        for fd in (stage_fd, lock, parent):
            if fd is not None: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers-paused', action='store_true', help='Authenticated installer/repair already owns worker leases.')
    parser.add_argument('--probe-reuse', action='store_true', help='Read-only current runtime qualification; never creates replacement state.')
    parser.add_argument('--wheelhouse', type=Path)
    parser.add_argument('--resource-profile', choices=('lite', 'standard'))
    parser.add_argument('--mark-retained', action='store_true', help='Qualify protected retained metadata without modifying the active environment.')
    parser.add_argument('--build-private', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Piper replacement requires root.')
    root = RUNTIME / 'piper'
    try:
        if args.resource_profile is not None and (args.probe_reuse or args.mark_retained or args.build_private):
            raise EnvironmentError('The resource profile applies only to replacement storage admission.')
        if args.probe_reuse:
            if args.build_private is not None or args.wheelhouse is not None or args.mark_retained or args.workers_paused:
                raise EnvironmentError('Read-only Piper qualification is a separate fixed operation.')
            result = probe_runtime_reuse(root, RUNTIME, RUNTIME)
            print(json.dumps({'schema': 1, 'qualified': result is not None}, sort_keys=True))
            return 0 if result is not None else 1
        if args.mark_retained:
            if args.build_private is not None or args.wheelhouse is not None:
                raise EnvironmentError('Retained metadata qualification is a separate fixed operation.')
            print(json.dumps(mark_retained_stages(root), sort_keys=True))
            return 0
        if args.build_private is not None:
            stage = args.build_private
            if stage.parent != root or not STAGE.fullmatch(stage.name):
                raise EnvironmentError('Invalid private Piper build directory.')
            build_private(stage, root, args.wheelhouse)
        else:
            def builder(stage, lock):
                command = ['/usr/bin/unshare', '--mount', '--propagation', 'private', '/usr/bin/python3', '-I',
                           str(Path(__file__).resolve()), '--build-private', str(stage)]
                if args.wheelhouse is not None: command += ['--wheelhouse', str(args.wheelhouse)]
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, pass_fds=(lock,), start_new_session=True,
                                           env=runtime_environment())
                try:
                    process.wait(timeout=600)
                except BaseException:
                    try: os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError: pass
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try: os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        process.wait()
                    raise
                if process.returncode:
                    raise EnvironmentError('Private Piper construction failed. Check mount namespace permission, Python venv support, wheel hashes, network/offline source and free space. The existing environment was preserved.')
            print(json.dumps(replace_environment(root, builder, validate_runtime, args.workers_paused, profile=args.resource_profile)))
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
