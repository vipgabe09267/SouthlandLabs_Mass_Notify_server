#!/usr/bin/python3
"""Prepare upgrade approvals from signed packages, without changing live trust.

Only authenticated upstream bytes, authenticated SLL overlays and explicitly
reviewed protected inventories establish expectations. Unknown live differences
are reported for review; their hashes never become an approval automatically.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import fcntl
import types
import io
import json
import os
import pwd
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import tarfile

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
WEB = Path('/var/www/html')
RUNTIME = '/usr/local/bin/sls_mass_notify'
UPSTREAM_SIGNER = '456D051E9204C27C37D4811BB53D215A755231A3'
UPSTREAM_KEY_SHA256 = '41f5c332ca0e667db72ac4c4500f3d5ad9f010f43f51a19bf07b01c9741ebd7a'
VERSION = re.compile(r'17\.[0-9]+(?:\.[0-9]+){1,3}\Z')
SLS_VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+(?:-beta)?\Z')
DOWNLOAD_DEADLINE_SECONDS = 180
WIDGETS = ('sections/SlsMassNotifyAnnouncement.class.php', 'views/sections/sls-mass-notify-announcement.php')
MENU_NAME = 'amp_conf/htdocs/admin/views/menu_items.php'
SPINNER = 'amp_conf/htdocs/admin/images/spinner.gif'
# The native layout was observed on FreePBX 17. These signed Framework
# packages have the same tooling and init file with the same inventory rules.
NATIVE_FRAMEWORK_VERSIONS = frozenset((
    '17.0.33', '17.0.33.1', '17.0.33.2', '17.0.33.3',
    '17.0.33.4', '17.0.33.5', '17.0.34',
))
NATIVE_FRAMEWORK_INIT = 'amp_conf/etc/init.d/freepbx.init'
NATIVE_FRAMEWORK_INIT_SHA256 = '8d6af9b7278b78ce4d10faf142a6e62ae0d72e746d0f303cce429f6ca768cbe0'
NATIVE_FRAMEWORK_INIT_BYTES = 1619
NATIVE_FRAMEWORK_TOOLING = frozenset((
    '.gitattributes', '.langignore', '.vscode/settings.json',
    'utests/API/GQL/ModuleAdminGqlApiTest.php', 'utests/API/GQL/SystemAdminGglApiTest.php',
    'utests/AstmanTest.php', 'utests/CronTest.php', 'utests/DBHelperTest.php',
    'utests/DoctrineTest.php', 'utests/FwconsoleTest.php', 'utests/GPGTest.php',
    'utests/InstallerTest.php', 'utests/LoadConfigTest.php', 'utests/MailTest.php',
    'utests/ModulesTest.php', 'utests/PHPTest.php', 'utests/PKCSTest.php',
    'utests/RealtimeTest.php', 'utests/RequestTest.php', 'utests/UpdatesTest.php',
    'utests/ViewsTest.php', 'utests/WebTest.php', 'utests/genaccts.php'))
MENU = b'''\t// SLS Mass Notifications menu placement: keep Mass Notify after UCP/User Panel.
\telse if (in_array($a, ['mass notifications', 'mass notify'], true) && $b == 'other')
\t\treturn -1;
\telse if ($a == 'other' && in_array($b, ['mass notifications', 'mass notify'], true))
\t\treturn 1;
\telse if (in_array($a, ['mass notifications', 'mass notify'], true) && in_array($b, ['user panel', 'ucp'], true))
\t\treturn 1;
\telse if (in_array($a, ['user panel', 'ucp'], true) && in_array($b, ['mass notifications', 'mass notify'], true))
\t\treturn -1;
\telse if (in_array($a, ['mass notifications', 'mass notify'], true))
\t\treturn 1;
\telse if (in_array($b, ['mass notifications', 'mass notify'], true))
\t\treturn -1;
'''
ROOT_JOB = re.compile(rb'(?:\* \* \* \* \* /usr/bin/timeout 900 ' + RUNTIME.encode() +
                      rb'/sls_mass_notify_maintenance\.sh|17 (?:\*|\*/6) \* \* \* /usr/bin/timeout 1800 ' +
                      RUNTIME.encode() + rb'/sls_mass_notify_update\.sh|(?:\* \* \* \* \* /usr/bin/python3 -I ' +
                      RUNTIME.encode() + rb'/sls_cron_runner\.py maintenance|17 \* \* \* \* /usr/bin/python3 -I ' +
                      RUNTIME.encode() + rb'/sls_cron_runner\.py update) >/dev/null 2>&1)\Z')


class UpgradeError(RuntimeError):
    pass


class RuntimeReviewError(UpgradeError):
    def __init__(self, differences):
        self.differences = differences
        names = ', '.join(row['path'] + ' (' + row['reason'] + ')' for row in differences[:12])
        super().__init__('Previous root runtime contains unapproved files or changes: ' + names)


def helper(name):
    path = HERE / (name + '.py')
    module = types.ModuleType('_sls_upgrade_' + name); module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


TRUST = helper('sls_module_trust')


def write_json(path, data):
    body = (json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n').encode()
    TRUST.atomic(path, body)
    return TRUST.digest(body)


def identity(web, module):
    body = TRUST.read(web / 'admin/modules' / module / 'module.xml', 1024 * 1024)
    return module_identity(body, module)


def module_identity(body, module):
    class NoDocumentTypes(ET.TreeBuilder):
        def doctype(self, name, public_id, system_id):
            raise UpgradeError('Unsupported module XML declarations: ' + module)
    if b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper():
        raise UpgradeError('Unsupported module XML declarations: ' + module)
    xml = ET.fromstring(body, parser=ET.XMLParser(target=NoDocumentTypes()))
    value = xml.findtext('version', '')
    pattern = SLS_VERSION if module == 'slsmassnotifyserver' else VERSION
    if xml.findtext('rawname') != module or not pattern.fullmatch(value):
        raise UpgradeError('Unsupported installed module identity: ' + module)
    return value


class Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, request, response, code, message, headers, new_url):
        target = urllib.parse.urlsplit(new_url)
        if (target.scheme != 'https' or target.username or target.password or target.port not in (None, 443)
                or target.fragment or target.hostname not in {'mirror.freepbx.org', 'github.com',
                                                            'objects.githubusercontent.com', 'release-assets.githubusercontent.com'}
                or request.host == 'mirror.freepbx.org' and target.hostname != 'mirror.freepbx.org'):
            raise UpgradeError('Upgrade package redirected outside its approved HTTPS host')
        return super().redirect_request(request, response, code, message, headers, new_url)


def sls_release_url(version, name):
    if (not isinstance(version,str) or not SLS_VERSION.fullmatch(version)
            or name not in ('slsmassnotifyserver-'+version+'.tgz','release-manifest.json','release-manifest.sig')):
        raise UpgradeError('Unsupported signed SLL release asset identity')
    prefix='release-' if version=='0.1.9-beta' else 'slsmassnotifyserver-' if tuple(map(int,version.removesuffix('-beta').split('.'))) < (0,1,9) else 'v'
    return 'https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/'+prefix+version+'/'+name


def _validate_download_url(url):
    upstream = r'https://mirror\.freepbx\.org/modules/packages/(dashboard|framework)/\1-(17\.[0-9]+(?:\.[0-9]+){1,3})\.tgz\.gpg'
    sls = (r'https://github\.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/'
           r'(?:(?:slsmassnotifyserver-|v)([0-9]+\.[0-9]+\.[0-9]+(?:-beta)?)/(?:slsmassnotifyserver-\1\.tgz|release-manifest\.(?:json|sig))|(?:V0\.1\.9-beta|release-0\.1\.9-beta)/(?:slsmassnotifyserver-0\.1\.9-beta\.tgz|release-manifest\.(?:json|sig)))')
    if not re.fullmatch(upstream, url) and not re.fullmatch(sls, url):
        raise UpgradeError('Unsupported upgrade package URL')


def _download_worker(url, destination, limit, writer, owner):
    """Own no inherited PBX descriptors and die if the controlling helper dies."""
    try:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            raise OSError(ctypes.get_errno(), 'Cannot bind download worker lifetime to its helper')
        if os.getppid() != owner:
            os.kill(os.getpid(), signal.SIGKILL)
        # fork copies close-on-exec descriptors too. Keep only the owned result
        # pipe; root coordination leases, native sockets and lifetime pipes must
        # not acquire an accidental second owner during network I/O.
        for name in os.listdir('/proc/self/fd'):
            descriptor = int(name)
            if descriptor > 2 and descriptor != writer:
                try: os.close(descriptor)
                except OSError: pass
        null = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC)
        try:
            for descriptor in (0, 1, 2):
                if descriptor != writer:
                    os.dup2(null, descriptor)
        finally:
            if null > 2 and null != writer:
                os.close(null)
        _download_to_file(url, destination, limit)
        result = ('ok', '')
    except BaseException as error:
        result = ('error', str(error)[:2048] or 'Signed-source download worker failed')
    try:
        body = memoryview(json.dumps(result, ensure_ascii=True).encode('ascii'))
        while body:
            written = os.write(writer, body)
            if written <= 0: break
            body = body[written:]
    except OSError:
        pass
    finally:
        os.close(writer)
    os._exit(0 if result[0] == 'ok' else 1)


def _reap_download_worker(pid):
    def exited():
        try: return os.waitpid(pid, os.WNOHANG)[0] == pid
        except ChildProcessError: return True
    if exited():
        return
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try: os.kill(pid, signum)
        except ProcessLookupError: pass
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if exited(): return
            time.sleep(0.01)


def download(url, destination, limit):
    _validate_download_url(url)
    deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
    reader, writer = os.pipe2(os.O_CLOEXEC)
    owner = os.getpid()
    try:
        worker = os.fork()
    except BaseException:
        os.close(reader); os.close(writer)
        raise
    if worker == 0:
        _download_worker(url, destination, limit, writer, owner)
        os._exit(1)
    os.close(writer)
    try:
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([reader], [], [], remaining)[0]:
                raise UpgradeError('Upgrade package download exceeded its total deadline (three minutes)')
            chunk = os.read(reader, 4096)
            if not chunk: break
            body.extend(chunk)
            if len(body) > 32768:
                raise UpgradeError('Signed-source download worker exceeded its result bound')
        try:
            result = json.loads(body)
            if (not isinstance(result, list) or len(result) != 2
                    or result[0] not in ('ok', 'error') or not isinstance(result[1], str)):
                raise ValueError('Invalid download worker result')
            state, message = result
        except ValueError:
            raise UpgradeError('Signed-source download worker stopped before completing its bounded transfer') from None
        if state != 'ok':
            raise UpgradeError(message)
    finally:
        os.close(reader)
        _reap_download_worker(worker)


def _download_to_file(url, destination, limit):
    _validate_download_url(url)
    request = urllib.request.Request(url, headers={'User-Agent': 'SLL-Upgrade-Inventory', 'Accept-Encoding': 'identity'})
    opener = urllib.request.build_opener(Redirects())
    deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'wb') as output, opener.open(request, timeout=20) as response:
            length = response.headers.get('Content-Length')
            if length is not None and (not length.isdigit() or int(length) > limit):
                raise UpgradeError('Upgrade package exceeds its size limit')
            total = 0
            while True:
                if time.monotonic() >= deadline:
                    raise UpgradeError('Upgrade package download exceeded three minutes')
                chunk = response.read(min(65536, limit - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise UpgradeError('Upgrade package exceeds its size limit')
                output.write(chunk)
            if not total or length is not None and total != int(length):
                raise UpgradeError('Upgrade package was empty or incomplete')
            output.flush()
            os.fsync(output.fileno())
    except (OSError, ValueError) as error:
        raise UpgradeError('Unable to download the required signed package. Check HTTPS access or supply the offline packages documented in INSTALL.md.') from error


PRIVATE_INSTALL_TEMP = '/var/spool/sls-mass-notify-installer-tmp'


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


def upstream_contents(package, module, version, workspace):
    """Verify a whole official GPG package in an isolated keyring, then parse it."""
    signed = TRUST.read(package, TRUST.MAX_ARCHIVE, protected=True)
    key = TRUST.read(HERE / 'freepbx-mirror-signing.pub', 16384, protected=True)
    if TRUST.digest(key) != UPSTREAM_KEY_SHA256:
        raise UpgradeError('Bundled FreePBX mirror verification key changed')
    # Persistent transaction paths can exceed GPG's Unix-socket path limit.
    # Keep its isolated keyring in a short, root-controlled temporary tree;
    # the authenticated recovery workspace and all signature checks stay intact.
    temporary_root = Path(os.environ.get('TMPDIR') or '/tmp')
    if str(temporary_root) not in ('/tmp', '/var/tmp', PRIVATE_INSTALL_TEMP):
        raise UpgradeError('GPG verification requires a qualified short /tmp or /var/tmp directory')
    if str(temporary_root) == PRIVATE_INSTALL_TEMP:
        try:
            private_install_temporary_state()
        except (OSError, ValueError, KeyError) as error:
            raise UpgradeError('unsafe fixed private installation workspace') from error
    else:
        temporary_meta = temporary_root.lstat()
        if (temporary_root.resolve() != temporary_root or not stat.S_ISDIR(temporary_meta.st_mode)
                or temporary_meta.st_uid != 0
                or temporary_meta.st_mode & 0o022 and not temporary_meta.st_mode & stat.S_ISVTX):
            raise UpgradeError('GPG verification requires a canonical root-controlled temporary directory')
    with tempfile.TemporaryDirectory(prefix='sls-upstream-gpg-', dir=temporary_root) as temporary:
        private = Path(temporary)
        (private / 'key.asc').write_bytes(key)
        (private / 'package.gpg').write_bytes(signed)
        command = ['/usr/bin/gpg', '--no-options', '--homedir', str(private), '--batch', '--no-tty', '--no-auto-key-retrieve', '--no-autostart']
        subprocess.run(command + ['--import', str(private / 'key.asc')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        plain = private / 'package.tgz'
        # Compressed OpenPGP can expand before GPG authenticates its signature.
        # Enforce the package limit while writing, not after decryption ends.
        result = subprocess.run(command + ['--max-output', str(TRUST.MAX_ARCHIVE), '--status-fd', '1', '--output', str(plain), '--decrypt', str(private / 'package.gpg')],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=90)
        lines = result.stdout.decode('ascii', errors='strict').splitlines()
        valid = [line.split() for line in lines if line.startswith('[GNUPG:] VALIDSIG ')]
        if (result.returncode or len(valid) != 1 or valid[0][2] != UPSTREAM_SIGNER or valid[0][-1] != UPSTREAM_SIGNER
                or any(re.match(r'\[GNUPG:\] (?:BADSIG|ERRSIG|EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED)\b', line) for line in lines)):
            raise UpgradeError('Official ' + module + ' package signature is invalid, expired, revoked or signed by an unsupported key')
        body = TRUST.read(plain, TRUST.MAX_ARCHIVE, protected=True)
    contents = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as archive:
        count = 0
        for member in archive:
            count += 1
            if count > TRUST.MAX_FILES * 2:
                raise UpgradeError('Upstream archive has too many members')
            name = member.name.rstrip('/') if member.isdir() else member.name
            TRUST.relative(name)
            if name == module and member.isdir():
                continue
            if not name.startswith(module + '/') or not (member.isdir() or member.isfile()) or member.mode & 0o6000:
                raise UpgradeError('Unsafe upstream archive entry')
            if not member.isfile():
                continue
            name = name[len(module) + 1:]
            total += member.size
            if name in contents or member.size > TRUST.MAX_ARCHIVE or total > 512 * 1024 * 1024:
                raise UpgradeError('Duplicate or oversized upstream archive entry')
            contents[name] = archive.extractfile(member).read(member.size + 1)
    xml = ET.fromstring(contents.get('module.xml', b''))
    if xml.findtext('rawname') != module or xml.findtext('version') != version:
        raise UpgradeError('Signed upstream package does not match the installed ' + module + ' version')
    return contents, {'kind': 'reviewed-upstream-and-overlays', 'archive_sha256': TRUST.digest(body),
                      'signed_archive_sha256': TRUST.digest(signed), 'upstream_signer': UPSTREAM_SIGNER}


def menu_overlay(body):
    needles = [b"\telse if ($a == 'other')\n\t\treturn " + value + b';\n' for value in (b'1', b'true')]
    found = [needle for needle in needles if body.count(needle) == 1]
    if len(found) != 1 or b'SLS Mass Notifications menu placement:' in body:
        raise UpgradeError('Framework menu layout needs review; no menu bytes were changed')
    return body.replace(found[0], MENU + found[0], 1)


def deployed_framework(name):
    return not (name.startswith(('amp_conf/astetc/', 'amp_conf/moh/', 'upgrades/', 'installlib/'))
                or name in ('install', 'start_asterisk')
                or name.startswith('amp_conf/') and not name.startswith('amp_conf/htdocs/'))


def _authenticated_native_framework(source, version):
    return (version in NATIVE_FRAMEWORK_VERSIONS
            and source.get('kind') == 'reviewed-upstream-and-overlays'
            and source.get('upstream_signer') == UPSTREAM_SIGNER
            and all(isinstance(source.get(key), str) and TRUST.DIGEST.fullmatch(source[key])
                    for key in ('archive_sha256', 'signed_archive_sha256')))


def _read_native_framework_init(path):
    """Read the retained web-tree source copy, never an active root init file."""
    parent = TRUST.directory(path.parent)
    descriptor = -1
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                             info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not mode & 0o400 or mode & ~0o664
                or before.st_size != NATIVE_FRAMEWORK_INIT_BYTES
                or identity(before) != identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))):
            raise UpgradeError('Unsafe retained native Framework source companion')
        owner_ok = before.st_uid == 0 and before.st_gid == 0
        if not owner_ok:
            try:
                account = pwd.getpwnam('asterisk')
                owner_ok = (account.pw_uid > 0 and account.pw_gid > 0
                            and before.st_uid in (0, account.pw_uid) and before.st_gid == account.pw_gid)
            except KeyError:
                owner_ok = False
        if not owner_ok:
            raise UpgradeError('Unsafe retained native Framework source companion owner')
        try:
            os.getxattr(descriptor, 'system.posix_acl_access')
        except OSError as error:
            # Unsupported/failed inspection is not evidence of ACL absence.
            # An independently reviewed inventory remains available instead.
            if error.errno != errno.ENODATA:
                raise UpgradeError('Retained native Framework source companion ACL needs review') from error
        else:
            raise UpgradeError('Retained native Framework source companion ACL needs review')
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = -1
            body = stream.read(NATIVE_FRAMEWORK_INIT_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (len(body) != NATIVE_FRAMEWORK_INIT_BYTES or identity(before) != identity(after)
                or identity(before) != identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))):
            raise UpgradeError('Retained native Framework source companion changed while reading')
        return body
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def native_framework_source_projection(contents, source, version, web):
    """Cover the one vendor manual-copy artifact only when already present.

    The qualified bytes must be in the authenticated whole upstream package.
    Its embedded module.sig does not cover this source-only fallback copy.
    Live bytes are inspected for safety, never used to create expectations.
    """
    body = contents.get(NATIVE_FRAMEWORK_INIT)
    if (not _authenticated_native_framework(source, version) or not isinstance(body, bytes)
            or len(body) != NATIVE_FRAMEWORK_INIT_BYTES or TRUST.digest(body) != NATIVE_FRAMEWORK_INIT_SHA256):
        return None
    path = web / 'admin/modules/framework' / NATIVE_FRAMEWORK_INIT
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    _read_native_framework_init(path)
    return {'schema': 1, 'authority': 'authenticated-whole-upstream-package',
            'files': {NATIVE_FRAMEWORK_INIT: {'sha256': TRUST.digest(body), 'bytes': len(body)}}}


def native_framework_source_files(data):
    """Revalidate persisted projection schema before every stock comparison."""
    source = data.get('source', {})
    projection = source.get('native_framework_source_files')
    # Independently reviewed/enrolled inventories already establish their own
    # exact file authority. Do not retag, extend or reinterpret those entries.
    # Only a new automatic source-copy projection carries this role policy.
    if 'native_framework_source_files' not in source:
        return set()
    expected = {'schema': 1, 'authority': 'authenticated-whole-upstream-package',
                'files': {NATIVE_FRAMEWORK_INIT: {'sha256': NATIVE_FRAMEWORK_INIT_SHA256,
                                                'bytes': NATIVE_FRAMEWORK_INIT_BYTES}}}
    if (data.get('module') != 'framework' or not _authenticated_native_framework(source, data.get('version'))
            or not isinstance(projection, dict) or projection != expected
            or type(projection.get('schema')) is not int
            or type(projection.get('files', {}).get(NATIVE_FRAMEWORK_INIT, {}).get('bytes')) is not int
            or data.get('files', {}).get(NATIVE_FRAMEWORK_INIT) != {
                'sha256': NATIVE_FRAMEWORK_INIT_SHA256,
                'target': 'admin/modules/framework/' + NATIVE_FRAMEWORK_INIT}):
        raise UpgradeError('Native Framework source companion provenance needs review')
    return {NATIVE_FRAMEWORK_INIT}


def native_framework_projection(contents, source, version, web):
    """Allow only authenticated, qualified native-fresh tooling absences.

    The outer official package signature authenticates its embedded inventory.
    Validate every embedded path/hash against that same package before using an
    absence from the inventory as a deployment fact. Present tooling keeps exact
    byte coverage; this does not change any previously enrolled inventory.
    """
    if (version not in NATIVE_FRAMEWORK_VERSIONS
            or source.get('upstream_signer') != UPSTREAM_SIGNER
            or not TRUST.DIGEST.fullmatch(str(source.get('archive_sha256', '')))
            or not TRUST.DIGEST.fullmatch(str(source.get('signed_archive_sha256', '')))):
        return set(), None
    body = contents.get('module.sig', b'')
    if not body or len(body) > TRUST.MAX_MANIFEST:
        return set(), None
    try:
        text = body.decode('utf-8')
        if (not text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n')
                or text.count('[hashes]\n') != 1
                or text.count('-----BEGIN PGP SIGNATURE-----') != 1):
            return set(), None
        header, hashes = text.split('[hashes]\n', 1)
        if not re.search(r'(?m)^hash=sha256$', header):
            return set(), None
        hashes = hashes.split('-----BEGIN PGP SIGNATURE-----', 1)[0]
        covered = set()
        for line in hashes.splitlines():
            # FreePBX's authenticated INI inventory ends with ";# End".
            # Comments carry no paths; every actual hash record stays strict.
            if not line or line.startswith(';'):
                continue
            match = re.fullmatch(r'(.+) = ([a-f0-9]{64})', line)
            if not match:
                raise UpgradeError('Authenticated Framework embedded inventory needs review')
            name = TRUST.relative(match[1])
            if name in covered or name not in contents or TRUST.digest(contents[name]) != match[2]:
                raise UpgradeError('Authenticated Framework embedded inventory differs from its package')
            covered.add(name)
        if not covered:
            return set(), None
    except (UnicodeError, TRUST.TrustError) as error:
        raise UpgradeError('Authenticated Framework embedded inventory needs review') from error
    omitted = set()
    for name in NATIVE_FRAMEWORK_TOOLING - covered:
        if name not in contents:
            continue
        try:
            (web / 'admin/modules/framework' / name).lstat()
        except FileNotFoundError:
            omitted.add(name)
    return omitted, {'kind': 'qualified-native-framework-v1', 'version': version,
                     'embedded_inventory_sha256': TRUST.digest(body),
                     'omitted_paths': sorted(omitted)}


def upstream_inventory(contents, source, module, version, candidate, previous, web):
    files = {}
    omitted = []
    tooling, projection = native_framework_projection(contents, source, version, web) if module == 'framework' else (set(), None)
    companions = native_framework_source_projection(contents, source, version, web) if module == 'framework' else None
    for name, body in contents.items():
        if name == 'module.sig':
            continue
        if module == 'framework' and ((not deployed_framework(name) and name not in (companions or {}).get('files', {})) or name in tooling):
            omitted.append(name)
            continue
        target = name[16:] if module == 'framework' and name.startswith('amp_conf/htdocs/') else 'admin/modules/' + module + '/' + name
        files[name] = {'sha256': TRUST.digest(body), 'target': target}
    data = {'schema': 1, 'module': module, 'version': version, 'source': {**source, 'intentionally_unmapped_upstream_paths': sorted(omitted)},
            'files': files, 'uninstall': {'remove': [], 'replace': {}}}
    if projection is not None:
        data['source']['installed_projection'] = projection
    if companions is not None:
        data['source']['native_framework_source_files'] = companions
    prior = copy.deepcopy(data)
    if module == 'dashboard':
        for name in WIDGETS:
            target = 'admin/modules/dashboard/' + name
            files[name] = {'sha256': TRUST.digest(candidate['dashboard/' + name]), 'target': target}
            if previous and 'dashboard/' + name in previous:
                prior['files'][name] = {'sha256': TRUST.digest(previous['dashboard/' + name]), 'target': target}
        data['uninstall']['remove'] = list(WIDGETS)
    else:
        # Both a plain asset and FreePBX's single supported Core alias are valid;
        # choosing the alias still requires its target's upstream GIF digest.
        if SPINNER in files and (web / files[SPINNER]['target']).is_symlink():
            files[SPINNER]['link_target'] = 'admin/modules/core/images/spinner.gif'
        if source.get('upstream_signer') == UPSTREAM_SIGNER and contents.get('module.sig'):
            data['source']['vendor_signature'] = {'sha256': TRUST.digest(contents['module.sig']),
                                                   'stock_files_sha256': TRUST.file_table_digest(files)}
    return data, prior


def bootstrap_dashboard(workspace, version):
    """Stage only an absent Dashboard from an independently signed stock package.

    FreePBX registration/hooks are subsequently run as its service account by
    the shell installer. This is a stock prerequisite, not SLL trust enrollment.
    """
    if not VERSION.fullmatch(version): raise UpgradeError('Choose an exact supported 17.x Dashboard version')
    modules = WEB / 'admin/modules'
    parent = TRUST.directory(modules)
    try:
        try: os.stat('dashboard', dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise UpgradeError('Dashboard bootstrap only supports an absent module; existing files must be reviewed, never replaced')
    finally: os.close(parent)
    TRUST.prepare_root(workspace)
    package = workspace / ('dashboard-' + version + '.tgz.gpg')
    offline = os.environ.get('SLS_MASS_NOTIFY_UPSTREAM_PACKAGES', '')
    if offline: TRUST.atomic(package, TRUST.read(Path(offline) / package.name, TRUST.MAX_ARCHIVE, protected=True))
    else: download('https://mirror.freepbx.org/modules/packages/dashboard/' + package.name, package, TRUST.MAX_ARCHIVE)
    contents, provenance = upstream_contents(package, 'dashboard', version, workspace)
    # Persist authenticated package provenance before exposing any stock files.
    write_json(workspace / 'stock-bootstrap.json', {'schema': 1, 'module': 'dashboard', 'version': version, 'source': provenance})
    import pwd
    account = pwd.getpwnam('asterisk')
    if account.pw_uid == 0: raise UpgradeError('FreePBX service account must be unprivileged')
    parent = TRUST.directory(modules)
    temporary = '.sls-stock-dashboard-' + os.urandom(12).hex()
    container = descriptor = -1
    try:
        os.mkdir(temporary, 0o700, dir_fd=parent)
        container = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        container_identity = os.fstat(container)
        named = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISDIR(container_identity.st_mode) or container_identity.st_uid != 0
                or stat.S_IMODE(container_identity.st_mode) != 0o700
                or (named.st_dev, named.st_ino) != (container_identity.st_dev, container_identity.st_ino)):
            raise UpgradeError('Stock bootstrap staging is not root-private; preserve the evidence and review')
        # Prepare the final tree behind a root-private ancestor. Its metadata
        # can become readable before publication without exposing partial files.
        os.mkdir('tree', 0o700, dir_fd=container)
        descriptor = os.open('tree', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=container)
        for relative, body in sorted(contents.items()):
            parts = TRUST.relative(relative).split('/')
            current = os.dup(descriptor)
            try:
                for part in parts[:-1]:
                    try: os.mkdir(part, 0o700, dir_fd=current)
                    except FileExistsError: pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    os.close(current); current = child
                fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=current)
                with os.fdopen(fd, 'wb') as output: output.write(body); output.flush(); os.fsync(output.fileno())
                os.fsync(current)
            finally: os.close(current)
        # Ownership changes apply only to descriptor-checked newly created files.
        def expose(fd):
            for name in os.listdir(fd):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try: expose(child)
                    finally: os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                    try: os.fchown(child, account.pw_uid, account.pw_gid); os.fchmod(child, 0o644); os.fsync(child)
                    finally: os.close(child)
                else: raise UpgradeError('Unexpected stock bootstrap file type')
            os.fchown(fd, account.pw_uid, account.pw_gid); os.fchmod(fd, 0o755); os.fsync(fd)
        expose(descriptor)
        os.fsync(container)
        try: os.stat('dashboard', dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise UpgradeError('Dashboard appeared during bootstrap; preserve the authenticated source and review')
        # Atomic non-replacing rename prevents an intervening local module from
        # being overwritten, even if the public parent is writable by FreePBX.
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.renameat2(container, b'tree', parent, b'dashboard', 1):
            raise OSError(ctypes.get_errno(), 'Dashboard bootstrap destination changed')
        os.fsync(container)
        os.fsync(parent)
        current = os.stat(temporary, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (container_identity.st_dev, container_identity.st_ino):
            raise UpgradeError('Stock bootstrap staging identity changed; preserve the evidence and review')
        os.rmdir(temporary, dir_fd=parent)
        os.fsync(parent)
    finally:
        if descriptor >= 0: os.close(descriptor)
        if container >= 0: os.close(container)
        os.close(parent)
    print(json.dumps({'ok': True, 'stock_bootstrap': 'dashboard', 'version': version, 'evidence': str(workspace)}))


def authenticated_generation(root, *, authority_directory=None, retained=False, now=None):
    data, generation = TRUST.load(root, 'slsmassnotifyserver')
    if data['source']['kind'] != 'publisher-ed25519':
        raise UpgradeError('Previous SLL generation lacks publisher authentication')
    publisher = helper('sls_release_trust')
    authority = root if authority_directory is None else authority_directory
    if retained and Path(root) != Path(authority):
        raise UpgradeError('Retained continuity requires the protected active authority generation')
    try:
        manifest = publisher.authenticate_manifest(TRUST.read(generation / 'release-manifest.json', 16384, protected=True),
                                                   TRUST.read(generation / 'release-manifest.sig', 64, protected=True),
                                                   anchor=TRUST.PUBLIC_KEY, directory=authority, now=now)
    except ValueError:
        if not retained:
            raise
        return approved_retained_generation(root, now=now)
    return data, generation_contents(data, generation, manifest)


def generation_contents(data, generation, manifest):
    if manifest.get('package_sha256') != data['source']['archive_sha256'] or manifest.get('version') != data['version']:
        raise UpgradeError('Previous signed release metadata does not match its protected generation')
    source = generation / 'module'
    if TRUST.inventory_tree(source, 'slsmassnotifyserver') != set(data['files']):
        raise UpgradeError('Authenticated source generation has missing or unexpected files')
    contents = {}
    total = 0
    for name, entry in data['files'].items():
        body = TRUST.read(source / name, TRUST.MAX_ARCHIVE, protected=True)
        total += len(body)
        if total > TRUST.MAX_ARCHIVE:
            raise UpgradeError('Authenticated source generation exceeds its inspection byte bound')
        if TRUST.digest(body) != entry['sha256']:
            raise UpgradeError('Authenticated source generation changed: ' + name)
        contents[name] = body
    return contents


RETAINED_APPROVAL_SECONDS = 7 * 86400


def retained_timestamp(now):
    now = int(time.time()) if now is None else now
    if type(now) is not int or not 0 < now <= 4102444800:
        raise UpgradeError('Retained continuity requires a valid current UTC timestamp')
    return now


def retained_metadata(operator, reason):
    for value, minimum, maximum in ((operator, 1, 128), (reason, 10, 500)):
        if (not isinstance(value, str) or not minimum <= len(value) <= maximum
                or value != value.strip() or any(ord(character) < 32 or ord(character) == 127 for character in value)):
            raise UpgradeError('Retained approval requires a bounded operator and review reason')


def retained_evidence(root, now):
    """Prove protected source bytes and current authority before a root review."""
    publisher = helper('sls_release_trust')
    store = publisher.TrustStore(root, TRUST.PUBLIC_KEY)
    state, initialized = store.load()
    policy = publisher.canonical({'initialized': initialized, **state})
    reference = TRUST.read(root / 'slsmassnotifyserver.active.json', 1024, protected=True)
    data, generation = TRUST.load(root, 'slsmassnotifyserver')
    if data['source']['kind'] != 'publisher-ed25519':
        raise UpgradeError('Retained approval requires independent publisher provenance')
    body = TRUST.read(generation / 'release-manifest.json', 16384, protected=True)
    signature = TRUST.read(generation / 'release-manifest.sig', 64, protected=True)
    manifest = publisher._authenticate_manifest(body, signature, anchor=TRUST.PUBLIC_KEY,
                                                directory=root, now=now, retained_review=True)
    signing = manifest.get('signing')
    expiration = signing.get('expires_at') if isinstance(signing, dict) else None
    if type(expiration) is not int or expiration > now:
        raise UpgradeError('Retained review applies only to expired signed release metadata')
    contents = generation_contents(data, generation, manifest)
    inventory = TRUST.read(generation / 'inventory.json', TRUST.MAX_MANIFEST, protected=True)
    if generation.name != 'slsmassnotifyserver-' + TRUST.digest(inventory):
        raise UpgradeError('Retained inventory changed during review')
    current, current_initialized = store.load()
    if (policy != publisher.canonical({'initialized': current_initialized, **current})
            or reference != TRUST.read(root / 'slsmassnotifyserver.active.json', 1024, protected=True)):
        raise UpgradeError('Retained authority changed during review; start a new review')
    evidence = {'generation': generation.name, 'reference_sha256': TRUST.digest(reference),
                'inventory_sha256': TRUST.digest(inventory), 'manifest_sha256': TRUST.digest(body),
                'signature_sha256': TRUST.digest(signature), 'policy_sha256': TRUST.digest(policy),
                'release_expires_at': expiration}
    challenge = TRUST.digest(publisher.canonical({'schema': 1, 'evidence': evidence}))
    return data, contents, evidence, challenge


def review_retained(root, *, approval=None, operator='', reason='', now=None,
                    lifetime=RETAINED_APPROVAL_SECONDS):
    """Root explicitly approves one exact expired active generation for <=7 days."""
    if os.geteuid() != 0:
        raise UpgradeError('Retained release review and approval require root')
    root = Path(root); now = retained_timestamp(now)
    _, _, evidence, challenge = retained_evidence(root, now)
    if approval is None:
        return {'schema': 1, 'challenge': challenge, 'evidence': evidence,
                'maximum_approval_seconds': RETAINED_APPROVAL_SECONDS, 'approval_required': True}
    retained_metadata(operator, reason)
    if (not isinstance(approval, str) or not TRUST.DIGEST.fullmatch(approval)
            or approval != challenge or type(lifetime) is not int or not 1 <= lifetime <= RETAINED_APPROVAL_SECONDS):
        raise UpgradeError('Retained approval requires the exact current review challenge and a <=7-day lifetime')
    publisher = helper('sls_release_trust')
    lock = publisher.TrustStore(root, TRUST.PUBLIC_KEY)._lock()
    try:
        _, _, current, current_challenge = retained_evidence(root, now)
        if evidence != current or challenge != current_challenge:
            raise UpgradeError('Retained evidence changed after review; no approval was written')
        path = root / 'retained-release-approval.json'
        if path.exists() or path.is_symlink():
            publisher.bounded_read(path, protected=True)
        receipt = {'schema': 1, 'challenge': challenge, 'evidence': evidence, 'issued_at': now,
                   'expires_at': now + lifetime, 'operator': operator, 'reason': reason}
        TRUST.atomic(path, publisher.canonical(receipt))
        return {'approved': True, **receipt}
    finally:
        os.close(lock)


def approved_retained_generation(root, *, now=None):
    now = retained_timestamp(now)
    data, contents, evidence, challenge = retained_evidence(root, now)
    publisher = helper('sls_release_trust')
    receipt = publisher.strict_json(publisher.bounded_read(root / 'retained-release-approval.json', protected=True))
    if (not isinstance(receipt, dict)
            or set(receipt) != {'schema', 'challenge', 'evidence', 'issued_at', 'expires_at', 'operator', 'reason'}
            or type(receipt['schema']) is not int or receipt['schema'] != 1
            or receipt['challenge'] != challenge or receipt['evidence'] != evidence
            or type(receipt['issued_at']) is not int or type(receipt['expires_at']) is not int
            or not 0 < receipt['issued_at'] <= now < receipt['expires_at'] <= receipt['issued_at'] + RETAINED_APPROVAL_SECONDS):
        raise UpgradeError('Retained approval is stale, changed, expired or invalid for the current protected generation')
    retained_metadata(receipt['operator'], receipt['reason'])
    return data, contents


def runtime_sources(contents):
    result = {}
    for name in contents:
        if name == 'bin/sign_sls_mass_notify_local_sig.sh':
            target = '/usr/local/sbin/sign_sls_mass_notify_local_sig.sh'
        elif name == 'bin/slsconsole':
            target = '/usr/local/bin/slsconsole'
        elif name.startswith('bin/sls_mass_notify/'):
            target = RUNTIME + '/' + name[len('bin/sls_mass_notify/'):]
        elif name.startswith('bin/') and '/' not in name[4:]:
            target = RUNTIME + '/' + name[4:]
        else:
            continue
        if target in result:
            raise UpgradeError('Signed package has conflicting runtime destinations: ' + target)
        result[target] = name
    return result


def runtime_files(contents):
    return {target: TRUST.digest(contents[name]) for target, name in runtime_sources(contents).items()}


def runtime_cache_source(relative):
    """Recognize only CPython cache names; their contents never grant execution."""
    path = Path(relative)
    match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\.cpython-[0-9]{2,3}(?:\.opt-[12])?\.pyc', path.name)
    if path.parent.name != '__pycache__' or not match:
        return None
    return str(path.parent.parent / (match[1] + '.py'))


def runtime_inventory(root):
    """Inspect root code separately from the existing protected Piper venv."""
    found = set()
    try:
        parent = TRUST.directory(root, protected=True)
    except FileNotFoundError:
        return found
    if os.fstat(parent).st_mode & 0o022:
        os.close(parent)
        raise UpgradeError('Previous runtime directory is writable by other accounts: ' + str(root))
    count = 0
    def visit(descriptor, prefix=''):
        nonlocal count
        for name in os.listdir(descriptor):
            count += 1
            if count > TRUST.MAX_FILES:
                raise UpgradeError('Root runtime exceeds its inspection limit')
            relative = TRUST.relative(prefix + name)
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
                raise UpgradeError('Unsafe link or special previous root runtime file: ' + relative)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise UpgradeError('Unprotected previous root runtime entry: ' + relative)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
                try:
                    if (os.fstat(child).st_dev, os.fstat(child).st_ino) != (info.st_dev, info.st_ino):
                        raise UpgradeError('Root runtime directory changed during inspection')
                    if relative != 'piper': visit(child, relative + '/')
                finally: os.close(child)
            else:
                found.add(relative)
    try: visit(parent)
    finally: os.close(parent)
    return found


def previous_root_approval(data, contents, *, prefix=Path('/'), cron=None):
    """Authorize restoration of exact authenticated prior root code, never hooks."""
    expected = runtime_files(contents)
    runtime = prefix / RUNTIME[1:]
    actual = runtime_inventory(runtime)
    own = {name[len(RUNTIME) + 1:] for name in expected if name.startswith(RUNTIME + '/')}
    # The root-owned dependency tree has separate validation; no other
    # executable leftovers may become part of a recovered root environment.
    cache_names = {name for name in actual - own if runtime_cache_source(name) in own}
    unknown = sorted(actual - own - cache_names)
    if unknown:
        raise RuntimeReviewError([{'path': RUNTIME + '/' + name, 'reason': 'not in the previous signed runtime or a recognized source cache'} for name in unknown])
    missing = []
    for name, digest in expected.items():
        target = prefix / name[1:]
        try:
            body = TRUST.read(target, TRUST.MAX_ARCHIVE, protected=True)
        except FileNotFoundError:
            missing.append(name)
            continue
        if TRUST.digest(body) != digest:
            raise RuntimeReviewError([{'path': name, 'reason': 'differs from its signed release'}])
    caches = {}
    total = 0
    for name in sorted(cache_names):
        body = TRUST.read(runtime / name, 1024 * 1024, protected=True)
        total += len(body)
        if total > 16 * 1024 * 1024:
            raise UpgradeError('Previous Python caches exceed the 16 MiB recovery limit; review before upgrading')
        caches[RUNTIME + '/' + name] = TRUST.digest(body)
    recovery = helper('sls_installer_recovery')
    if cron is None:
        try:
            with recovery.native_cron_lock(('root',)) as lease:
                cron = recovery.Recovery.system_cron(user='root')
                if lease is not None:lease.check()
        except recovery.RecoveryError as error:
            raise UpgradeError('Unable to inspect the coordinated previous root maintenance schedule: '+str(error)) from error
    if len(cron) > 1024 * 1024:
        raise UpgradeError('Root schedule exceeds its inspection limit')
    try:
        jobs = [line for line in cron.splitlines() if recovery.sls_cron_job(line,'root')]
    except recovery.RecoveryError as error:
        raise UpgradeError('Previous SLL root schedule needs independent review: '+str(error)) from error
    if any(not ROOT_JOB.fullmatch(line) for line in jobs) or len(jobs) != len(set(jobs)):
        raise UpgradeError('Previous SLL root schedule needs independent review; no maintenance was disabled')
    if any(b'/sls_cron_runner.py ' in line for line in jobs) and RUNTIME + '/sls_cron_runner.py' not in expected:
        raise UpgradeError('Previous SLL cron runner lacks publisher-authenticated source approval')
    return {'schema': 1, 'source': 'publisher-verified-previous-release', 'version': data['version'],
            'archive_sha256': data['source']['archive_sha256'], 'files': expected,
            'missing_files': sorted(missing), 'quarantine_caches': caches,
            'root_jobs': [line.decode('ascii') for line in jobs]}


def normalize_previous_runtime(workspace, *, prefix=Path('/')):
    """Restore absent signed helpers and retire bytecode before recovery approval.

    Cache hashes identify evidence to quarantine, never executable approval.
    Existing source files must still match their authenticated expectations.
    """
    approval = json.loads(TRUST.read(workspace / 'previous-root-approval.json', TRUST.MAX_MANIFEST, protected=True))
    expected = approval['files']
    sources = workspace / 'previous-runtime-repairs'
    missing = set(approval.get('missing_files', []))
    caches = approval.get('quarantine_caches', {})
    if approval.get('source') == 'fresh-install' and not expected and not missing and not caches:
        return
    runtime = prefix / RUNTIME[1:]
    own = {name[len(RUNTIME) + 1:] for name in expected if name.startswith(RUNTIME + '/')}
    actual = runtime_inventory(runtime)
    cache_paths = {name[len(RUNTIME) + 1:] for name in caches}
    if (actual - own) - cache_paths:
        raise UpgradeError('Previous runtime changed after preflight; no additional files were approved')
    # Verify every input and existing destination before modifying any live file.
    payloads = {}
    for name, digest in expected.items():
        target = prefix / name[1:]
        try:
            body = TRUST.read(target, TRUST.MAX_ARCHIVE, protected=True)
        except FileNotFoundError:
            if name not in missing:
                raise UpgradeError('Previous runtime file disappeared after preflight: ' + name)
            body = TRUST.read(sources / TRUST.digest(name.encode()), TRUST.MAX_ARCHIVE, protected=True)
            payloads[name] = body
        if TRUST.digest(body) != digest:
            raise UpgradeError('Previous runtime changed after preflight: ' + name)
    evidence = workspace / 'runtime-cache-recovery'
    absent_caches = cache_paths - actual
    if absent_caches:
        try:
            TRUST.private_generation(evidence)
            recovered = json.loads(TRUST.read(evidence / 'inventory.json', TRUST.MAX_MANIFEST, protected=True))
        except (OSError, ValueError, TRUST.TrustError) as error:
            raise UpgradeError('Previous Python cache is absent without valid private quarantine evidence; preserve the review directory') from error
        if (not isinstance(recovered, dict) or type(recovered.get('schema')) is not int
                or recovered != {'schema': 1, 'execution_approved': False, 'files': caches}
                or recovered.get('execution_approved') is not False):
            raise UpgradeError('Previous Python cache quarantine inventory differs from its original approval; preserve the review directory')
    cache_bodies = {}
    for name, digest in caches.items():
        relative = name[len(RUNTIME) + 1:]
        if runtime_cache_source(relative) not in own:
            raise UpgradeError('Invalid runtime cache recovery path')
        if relative in absent_caches:
            try:
                body = TRUST.read(evidence / TRUST.digest(name.encode()), 1024 * 1024, protected=True)
            except (OSError, TRUST.TrustError) as error:
                raise UpgradeError('Previous Python cache quarantine bytes are missing or unsafe; preserve the review directory: ' + name) from error
        else:
            body = TRUST.read(prefix / name[1:], 1024 * 1024, protected=True)
            cache_bodies[name] = body
        if TRUST.digest(body) != digest:
            raise UpgradeError('Previous Python cache changed after preflight: ' + name)
    if cache_bodies:
        TRUST.prepare_root(evidence)
        for name, body in cache_bodies.items():
            TRUST.atomic(evidence / TRUST.digest(name.encode()), body)
        write_json(evidence / 'inventory.json', {'schema': 1, 'execution_approved': False, 'files': caches})
    for name, body in payloads.items():
        target = prefix / name[1:]
        if target.parent == runtime or target.parent.is_relative_to(runtime):
            # Create only missing directories under the fixed runtime root.
            # Existing ancestry is checked without following links.
            parent = TRUST.directory(runtime.parent, protected=True)
            try:
                for part in target.parent.relative_to(runtime.parent).parts:
                    try:
                        os.mkdir(part, 0o755, dir_fd=parent)
                    except FileExistsError:
                        pass
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    os.close(parent)
                    parent = child
                    info = os.fstat(parent)
                    if info.st_uid != 0 or info.st_mode & 0o022:
                        raise UpgradeError('Unsafe previous runtime repair directory')
            finally:
                os.close(parent)
        parent = TRUST.directory(target.parent, protected=True)
        descriptor = -1
        temporary = '.previous-runtime-' + os.urandom(12).hex()
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            with os.fdopen(descriptor, 'wb') as stream:
                descriptor = -1
                stream.write(body)
                stream.flush()
                os.fchmod(stream.fileno(), 0o755)
                os.fsync(stream.fileno())
            # link() publishes only to an absent name; never replace a new file.
            os.link(temporary, target.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)
    for name, body in cache_bodies.items():
        target = prefix / name[1:]
        parent = TRUST.directory(target.parent, protected=True)
        try:
            before = os.stat(target.name, dir_fd=parent, follow_symlinks=False)
            if TRUST.read(target, 1024 * 1024, protected=True) != body:
                raise UpgradeError('Python cache changed before quarantine')
            after = os.stat(target.name, dir_fd=parent, follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_ctime_ns):
                raise UpgradeError('Python cache changed before quarantine')
            os.unlink(target.name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
    if runtime_inventory(runtime) != own:
        raise UpgradeError('Previous runtime normalization is incomplete; preserve the review evidence')
    print(json.dumps({'ok': True, 'restored_signed_helpers': len(payloads), 'quarantined_caches': len(cache_bodies),
                      'already_quarantined_caches': len(absent_caches), 'review_directory': str(workspace)}))


def restored_web_inventory(data, old, web):
    """Select the already verified prior/candidate/clean transition, never extras."""
    result = copy.deepcopy(data)
    for name, entry in list(result['files'].items()):
        target = web / entry['target']
        if data['module'] == 'dashboard' and name in WIDGETS and not target.exists():
            del result['files'][name]
            continue
        observed = TRUST.digest(TRUST.read(web / entry.get('link_target', entry['target']), TRUST.MAX_ARCHIVE))
        allowed = {entry['sha256']}
        if name in WIDGETS or data['module'] == 'framework' and name == MENU_NAME:
            allowed.add(old.get('files', {}).get(name, {}).get('sha256'))
            allowed.add(data.get('uninstall', {}).get('replace', {}).get(name))
        if observed not in allowed:
            raise UpgradeError('Stock file changed after approved preflight: ' + name)
        entry['sha256'] = observed
    result.pop('uninstall', None)
    return result


def verify_previous(workspace):
    path = workspace / 'previous-web-approval.json'
    approved = json.loads(TRUST.read(path, TRUST.MAX_MANIFEST * 4, protected=True))
    store = workspace / 'rollback-registry'
    for module in ('slsmassnotifyserver', 'dashboard', 'framework'):
        data = approved.get(module)
        if data is None:
            if (WEB / 'admin/modules' / module).exists():
                raise UpgradeError('Unexpected recovered module: ' + module)
            continue
        body = (json.dumps(data, sort_keys=True, separators=(',', ':')) + '\n').encode()
        TRUST.parse_manifest(body)
        # This private registry consumes pre-install approvals only. Publisher
        # provenance is already authenticated; no executable generation is used.
        TRUST.store_manifest(store, data, body)
        TRUST.check(store, module, WEB)
    print(json.dumps({'ok': True, 'previous_web_approval_verified': True}))


def previous_sls_approval(workspace):
    approved = json.loads(TRUST.read(workspace / 'previous-web-approval.json',
                                    TRUST.MAX_MANIFEST * 4, protected=True))
    if type(approved) is not dict or 'slsmassnotifyserver' not in approved:
        raise UpgradeError('The prior SLL module approval is unavailable')
    data = approved['slsmassnotifyserver']
    if data is not None:
        TRUST.parse_manifest(json.dumps(data).encode())
        if data['module'] != 'slsmassnotifyserver':
            raise UpgradeError('The prior SLL module approval has the wrong identity')
    return data


def verify_previous_sls_tree(data, path):
    """Verify a moved SLL tree against prior approval, never observed live hashes."""
    actual = TRUST.inventory_tree(path, 'slsmassnotifyserver')
    if actual != set(data['files']):
        raise TRUST.TrustError('Previous SLL module inventory differs from its approval')
    total = 0
    for name, entry in data['files'].items():
        if entry['target'] != 'admin/modules/slsmassnotifyserver/' + name or 'link_target' in entry:
            raise UpgradeError('The prior SLL module approval contains an external target')
        body = TRUST.read(path / name, TRUST.MAX_ARCHIVE)
        total += len(body)
        if total > 1024 * 1024 * 1024:
            raise UpgradeError('Previous SLL module exceeds the inspection byte limit')
        if TRUST.digest(body) != entry['sha256']:
            raise TRUST.TrustError('Previous SLL module differs from its approval: ' + name)


def recover_native_backup_permissions(data, backup, backup_fd):
    """Reseal only the old public-filesystem layout after approved-byte checks.

    FreePBX boot-time chown can normalize an older installer's private sibling
    directory. Its changed metadata grants no authority: the original module
    must first match the protected pre-install inventory. No observed digest is
    enrolled, and no program from this directory is executed as root.
    """
    info = os.fstat(backup_fd)
    if info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700:
        return
    account = pwd.getpwnam('asterisk')
    if (backup.parent != WEB / 'admin/modules'
            or not re.fullmatch(r'\.sls-mass-notify-recovery\.[A-Za-z0-9]{6}', backup.name)
            or info.st_uid not in (0, account.pw_uid) or info.st_gid not in (0, account.pw_gid)
            or stat.S_IMODE(info.st_mode) not in (0o755, 0o775)):
        raise UpgradeError('Unsafe module recovery directory')
    names = set(os.listdir(backup_fd))
    if names - {'slsmassnotifyserver', 'failed-module', 'candidate', 'module-swap-complete'}:
        raise UpgradeError('Unknown contents in native-normalized module recovery directory')
    for name in names:
        entry = os.stat(name, dir_fd=backup_fd, follow_symlinks=False)
        if name == 'module-swap-complete':
            valid = (stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1 and entry.st_size == 0
                     and stat.S_IMODE(entry.st_mode) in (0o600, 0o640, 0o644, 0o664))
        else:
            valid = stat.S_ISDIR(entry.st_mode) and not entry.st_mode & 0o7002
        if not valid or entry.st_uid not in (0, account.pw_uid) or entry.st_gid not in (0, account.pw_gid):
            raise UpgradeError('Unsafe native-normalized module recovery entry: ' + name)
    if 'slsmassnotifyserver' in names:
        if data is None:
            raise UpgradeError('Unexpected prior module backup')
        verify_previous_sls_tree(data, backup / 'slsmassnotifyserver')
    elif data is not None:
        verify_previous_sls_tree(data, WEB / 'admin/modules/slsmassnotifyserver')
    parent = TRUST.directory(backup.parent)
    try:
        def same_name():
            named = os.stat(backup.name, dir_fd=parent, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise UpgradeError('Module recovery directory changed during native permission recovery')
        same_name()
        os.fchown(backup_fd, 0, 0)
        os.fchmod(backup_fd, 0o700)
        os.fsync(backup_fd); os.fsync(parent)
        same_name()
        # The normal restore below checks approved bytes again after sealing,
        # including a writer which already held an open file descriptor.
    finally:
        os.close(parent)


def restore_previous_module(workspace, backup, existed):
    """Resume either directory move without replacing recovery evidence."""
    data = previous_sls_approval(workspace)
    if type(existed) is not bool or existed != (data is not None):
        raise UpgradeError('The prior module existence flag disagrees with its approval')
    # FreePBX owns the public modules parent. The recovery directory itself is
    # root-only, and all restored bytes must match the protected prior approval.
    # Reject path links without requiring FreePBX's ancestors to be root-owned.
    backup_fd = TRUST.directory(backup)
    web_fd = -1
    try:
        recover_native_backup_permissions(data, backup, backup_fd)
        web_fd = TRUST.directory(WEB / 'admin/modules')

        def present(parent, name):
            try:
                value = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if not stat.S_ISDIR(value.st_mode):
                raise UpgradeError('Unsafe module recovery tree: ' + name)
            return True

        original = present(backup_fd, 'slsmassnotifyserver')
        failed = present(backup_fd, 'failed-module')
        live = present(web_fd, 'slsmassnotifyserver')
        if original:
            if not existed:
                raise UpgradeError('Unexpected prior module backup')
            verify_previous_sls_tree(data, backup / 'slsmassnotifyserver')
            if live and failed:
                raise UpgradeError('Module recovery is ambiguous; preserve all three trees')
            if live:
                os.rename('slsmassnotifyserver', 'failed-module', src_dir_fd=web_fd, dst_dir_fd=backup_fd)
                # Persist each move separately so recovery can resume after a
                # power loss between moving the failed and previous releases.
                os.fsync(web_fd)
                os.fsync(backup_fd)
            os.rename('slsmassnotifyserver', 'slsmassnotifyserver', src_dir_fd=backup_fd, dst_dir_fd=web_fd)
        elif existed:
            if not live:
                raise UpgradeError('Both the previous module and its restored tree are missing')
            verify_previous_sls_tree(data, WEB / 'admin/modules/slsmassnotifyserver')
        elif live:
            if failed:
                raise UpgradeError('Fresh module recovery is ambiguous; preserve both trees')
            os.rename('slsmassnotifyserver', 'failed-module', src_dir_fd=web_fd, dst_dir_fd=backup_fd)
        os.fsync(web_fd)
        os.fsync(backup_fd)
        if existed:
            verify_previous_sls_tree(data, WEB / 'admin/modules/slsmassnotifyserver')
        print(json.dumps({'ok': True, 'previous_sls_module_restored': True}))
    finally:
        if web_fd >= 0:
            os.close(web_fd)
        os.close(backup_fd)


def compare_stock(data, prior, web, candidate, *, transitioning_from=None):
    """Return all mismatches, keeping observed hashes out of expected inventories."""
    module = data['module']
    companions = native_framework_source_files(data)
    actual = TRUST.inventory_tree(web / 'admin/modules' / module, module)
    widgets = set(WIDGETS) if module == 'dashboard' else set()
    expected = {name for name, entry in data['files'].items() if entry['target'].startswith('admin/modules/' + module + '/')}
    old_files = transitioning_from['files'] if transitioning_from else {}
    issues = []
    def difference(name, reason, previous_state=False):
        row = {'module': module, 'path': name, 'reason': reason}
        if transitioning_from and previous_state:
            # Scheduling evidence only. This still fails the full comparison.
            row['possible_update_in_progress'] = True
        issues.append(row)
    for name in sorted(actual - expected):
        difference(name, 'unexpected file', name in old_files)
    for name in sorted(expected - actual - widgets):
        difference(name, 'missing file', name not in old_files)
    try:
        TRUST.check_reviewed_omissions(data, web)
    except (OSError, TRUST.TrustError) as error:
        issues.append({'module': module, 'path': module, 'reason': str(error)})
    total = 0
    for name, entry in data['files'].items():
        if name in widgets and name not in actual:
            continue
        try:
            target = web / entry['target']
            if 'link_target' in entry:
                before = target.lstat()
                if not stat.S_ISLNK(before.st_mode) or before.st_nlink != 1 or os.readlink(target) != str(web / entry['link_target']):
                    raise UpgradeError('unsupported asset link')
                body = TRUST.read(web / entry['link_target'], TRUST.MAX_ARCHIVE)
                after = target.lstat()
                if (before.st_dev, before.st_ino, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_ctime_ns):
                    raise UpgradeError('asset link changed during inspection')
            else:
                body = _read_native_framework_init(target) if name in companions else TRUST.read(target, TRUST.MAX_ARCHIVE)
            total += len(body)
            if total > 1024 * 1024 * 1024:
                raise UpgradeError('stock inspection exceeds 1 GiB')
            allowed = {entry['sha256']}
            if name in widgets or module == 'framework' and name == MENU_NAME:
                old = prior.get('files', {}).get(name, {}).get('sha256')
                if old:
                    allowed.add(old)
                clean = data.get('uninstall', {}).get('replace', {}).get(name)
                if clean:
                    allowed.add(clean)
            actual_hash = TRUST.digest(body)
            if actual_hash not in allowed:
                difference(name, 'bytes differ from signed/reviewed source',
                           actual_hash == old_files.get(name, {}).get('sha256'))
        except (OSError, UpgradeError, TRUST.TrustError) as error:
            difference(name, 'unsafe, missing or changing file', isinstance(error, FileNotFoundError) and name not in old_files)
    for name in widgets:
        if data['files'].get(name, {}).get('sha256') != TRUST.digest(candidate['dashboard/' + name]):
            raise UpgradeError('Candidate Dashboard overlay does not match its approval')
    return issues


def prepare_native_menu(data, prior, web):
    """Retire the known legacy menu insertion while preserving the exact rollback bytes."""
    menu = data['files'].get(MENU_NAME)
    if menu is None:
        try:
            (web / 'admin/views/menu_items.php').lstat()
        except FileNotFoundError:
            return
        raise UpgradeError('An unreviewed menu remains at the former Framework path; preserve it for review')
    if menu['target'] != 'admin/views/menu_items.php':
        raise UpgradeError('Unexpected reviewed Framework menu destination')
    replacements = data.get('uninstall', {}).get('replace', {})
    if MENU_NAME in replacements:
        menu['sha256'] = replacements.pop(MENU_NAME)
    prior['files'][MENU_NAME] = dict(menu)
    try:
        live = TRUST.read(web / menu['target'], TRUST.MAX_ARCHIVE)
    except FileNotFoundError:
        # The full stock comparison records the missing path in review-required.json.
        return
    if live.count(MENU) != 1:
        return
    clean = live.replace(MENU, b'', 1)
    if TRUST.digest(clean) == menu['sha256'] and menu_overlay(clean) == live:
        prior['files'][MENU_NAME]['sha256'] = TRUST.digest(live)


def prepare(args):
    workspace = args.workspace
    TRUST.prepare_root(workspace)
    registry = workspace / 'registry'
    TRUST.enroll_sls(registry, args.archive, args.manifest, args.signature, authority_directory=args.trust_root)
    candidate_data, candidate = authenticated_generation(registry, authority_directory=args.trust_root)
    previous_data = previous = None
    sls_path = WEB / 'admin/modules/slsmassnotifyserver'
    if sls_path.exists() or sls_path.is_symlink():
        version = identity(WEB, 'slsmassnotifyserver')
        pointer = args.trust_root / 'slsmassnotifyserver.active.json'
        if pointer.exists() or pointer.is_symlink():
            previous_data, previous = authenticated_generation(args.trust_root, retained=True)
            if previous_data['version'] != version:
                raise UpgradeError('Installed SLL version differs from protected prior approval; retain recovery files and review before retrying')
        else:
            release = workspace / 'previous-release'
            release.mkdir(mode=0o700)
            paths = [os.environ.get('SLS_MASS_NOTIFY_PREVIOUS_' + key, '') for key in ('TGZ', 'MANIFEST', 'MANIFEST_SIGNATURE')]
            names = ['slsmassnotifyserver-' + version + '.tgz', 'release-manifest.json', 'release-manifest.sig']
            if any(paths) and not all(paths):
                raise UpgradeError('Supply all three previous SLL package, manifest and signature paths')
            for source, name, limit in zip(paths, names, (TRUST.MAX_ARCHIVE, 16384, 64)):
                if source:
                    TRUST.atomic(release / name, TRUST.read(Path(source), limit, protected=True))
                else:
                    download(sls_release_url(version,name), release / name, limit)
            prior_registry = workspace / 'previous-registry'
            TRUST.enroll_sls(prior_registry, release / names[0], release / names[1], release / names[2],
                             authority_directory=args.trust_root)
            previous_data, previous = authenticated_generation(prior_registry, authority_directory=args.trust_root)
            if previous_data['version'] != version:
                raise UpgradeError('Previous signed SLL package has the wrong installed version')
        actual = TRUST.inventory_tree(sls_path, 'slsmassnotifyserver')
        if actual != set(previous_data['files']):
            raise UpgradeError('Installed previous SLL file list differs from its signed release; review local changes before upgrading')
        for name, entry in previous_data['files'].items():
            if TRUST.digest(TRUST.read(sls_path / name, TRUST.MAX_ARCHIVE)) != entry['sha256']:
                raise UpgradeError('Installed previous SLL file differs from its signed release: ' + name + '. Review the change before upgrading; no maintenance was disabled.')
    approved = {}
    prior = {}
    issues = []
    for module in ('dashboard', 'framework'):
        version = identity(WEB, module)
        path = os.environ.get('SLS_MASS_NOTIFY_' + module.upper() + '_INVENTORY', '')
        digest = os.environ.get('SLS_MASS_NOTIFY_' + module.upper() + '_INVENTORY_SHA256', '')
        pointer = args.trust_root / (module + '.active.json')
        retained = TRUST.load(args.trust_root, module)[0] if pointer.exists() or pointer.is_symlink() else None
        if path or digest:
            body = TRUST.read(Path(path), TRUST.MAX_MANIFEST, protected=True)
            if not TRUST.DIGEST.fullmatch(digest) or TRUST.digest(body) != digest:
                raise UpgradeError('Reviewed ' + module + ' inventory digest mismatch')
            data = TRUST.parse_manifest(body)
            old = copy.deepcopy(retained) if retained and retained['version'] == version else copy.deepcopy(data)
        elif retained and retained['version'] == version:
            data = copy.deepcopy(retained)
            old = copy.deepcopy(data)
        else:
            offline = os.environ.get('SLS_MASS_NOTIFY_UPSTREAM_PACKAGES')
            package = stock_package(module, version, workspace, args.trust_root, packages=offline, online=not offline)
            contents, source = upstream_contents(package, module, version, workspace)
            data, old = upstream_inventory(contents, source, module, version, candidate, previous, WEB)
            if retained:
                carry_from_signed_base(retained, data, candidate, WEB, workspace, args.trust_root, offline, not offline)
        if data['module'] != module or data['version'] != version or data['source']['kind'] != 'reviewed-upstream-and-overlays':
            raise UpgradeError('Approved inventory must match the installed ' + module + ' version')
        if module == 'dashboard':
            for name in WIDGETS:
                target = 'admin/modules/dashboard/' + name
                if previous and 'dashboard/' + name in previous:
                    old['files'][name] = {'sha256': TRUST.digest(previous['dashboard/' + name]), 'target': target}
                data['files'][name] = {'sha256': TRUST.digest(candidate['dashboard/' + name]), 'target': target}
            data['uninstall'] = {'remove': list(WIDGETS), 'replace': {}}
        else:
            prepare_native_menu(data, old, WEB)
        TRUST.parse_manifest(json.dumps(data).encode())
        approved[module], prior[module] = data, old
        issues += compare_stock(data, old, WEB, candidate)
    if issues:
        report = workspace / 'review-required.json'
        write_json(report, {'schema': 1, 'approved': False, 'differences': issues})
        raise UpgradeError('Unreviewed PBX differences: ' + str(len(issues)) + '. Review ' + str(report) + ' and supply independently reviewed inventories; local files and maintenance were preserved. See docs/privileged-trust.md.')
    write_json(workspace / 'approvals.json', {'prior': prior, 'approved': approved})
    write_json(workspace / 'previous-web-approval.json',
               {'slsmassnotifyserver': previous_data,
                **{module: restored_web_inventory(approved[module], prior[module], WEB) for module in ('dashboard', 'framework')}})
    for module in ('dashboard', 'framework'):
        path = workspace / (module + '.json')
        digest = write_json(path, approved[module])
        TRUST.enroll_reviewed(registry, path, digest)
    if previous_data:
        try:
            root_approval = previous_root_approval(previous_data, previous)
        except RuntimeReviewError as error:
            report = workspace / 'runtime-review-required.json'
            write_json(report, {'schema': 1, 'approved': False, 'differences': error.differences})
            raise UpgradeError(str(error) + '. Review ' + str(report) + '; no runtime or maintenance was changed. Do not remove unknown files or approve live hashes blindly. See docs/privileged-trust.md.') from error
        if root_approval['missing_files']:
            repairs = workspace / 'previous-runtime-repairs'
            TRUST.prepare_root(repairs)
            sources = runtime_sources(previous)
            for name in root_approval['missing_files']:
                TRUST.atomic(repairs / TRUST.digest(name.encode()), previous[sources[name]])
        write_json(workspace / 'previous-root-approval.json', root_approval)
    else:
        write_json(workspace / 'previous-root-approval.json', {'schema': 1, 'source': 'fresh-install', 'files': {}, 'root_jobs': []})
    print(json.dumps({'ok': True, 'review_directory': str(workspace), 'previous_version': previous_data['version'] if previous_data else None,
                      'candidate_version': candidate_data['version'], 'live_trust_changed': False}))


def stock_package(module, version, workspace, root, *, packages=None, online=False):
    name=module+'-'+version+'.tgz.gpg'
    destination=workspace/name
    candidates=[destination]
    if packages is not None:candidates.append(Path(packages)/name)
    candidates.append(root/'stock-packages'/name)
    for path in candidates:
        try:body=TRUST.read(path,TRUST.MAX_ARCHIVE,protected=True)
        except FileNotFoundError:continue
        if path!=destination:TRUST.atomic(destination,body)
        return destination
    if not online:
        raise UpgradeError('A verified local '+name+' is required. Use slsconsole reconcile-stock --online while online, or supply its independently signed package with --upstream-packages. Live hashes were not approved.')
    download('https://mirror.freepbx.org/modules/packages/'+module+'/'+name,destination,TRUST.MAX_ARCHIVE)
    return destination


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
                and source.get('upstream_signer') == UPSTREAM_SIGNER
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


def _capacity_storage_read(path, maximum):
    body = TRUST.read(Path(path), maximum, protected=True)
    info = Path(path).lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError('Private protected stock storage file required')
    return body


def _capacity_storage_directory(path):
    descriptor = TRUST.directory(Path(path), protected=True)
    if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700:
        os.close(descriptor)
        raise ValueError('Private protected stock storage directory required')
    return descriptor


def stock_cache_storage_binding(workspace, root, *, web=None):
    try:
        web = WEB if web is None else Path(web)
        versions = {module: identity(web, module) for module in ('dashboard', 'framework')}
        first = _stock_storage_binding(workspace, root, reader=_capacity_storage_read,
                                       directory=_capacity_storage_directory)
        if first != _stock_storage_binding(workspace, root, reader=_capacity_storage_read,
                                           directory=_capacity_storage_directory):
            return None
        if (any(first['approved'][module]['version'] != version for module, version in versions.items())
                or versions != {module: identity(web, module) for module in ('dashboard', 'framework')}):
            return None
        return first
    except (OSError, ValueError, TypeError, KeyError, TRUST.TrustError, UpgradeError, ET.ParseError, RecursionError):
        return None


def _verify_capacity_stock_proof(workspace, root, path, expected):
    try:
        import hashlib
        if Path(path) != Path(workspace) / 'resource-relationship-proof.json' or not TRUST.DIGEST.fullmatch(expected or ''):
            raise ValueError('Unbound stock capacity storage proof')
        raw = _capacity_storage_read(path, 4 * 1024**2)
        def pairs(rows):
            result = {}
            for key, item in rows:
                if key in result: raise ValueError('Duplicate capacity proof field')
                result[key] = item
            return result
        def invalid(unused): raise ValueError('Nonfinite capacity proof')
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if (not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 3
                or value.get('kind') != 'sll-prepared-upgrade-storage-proof-v3' or value.get('capacity_only') is not True
                or hashlib.sha256(encoded).hexdigest() != expected
                or not isinstance(value.get('stock_cache'), dict)
                or value['stock_cache'] != stock_cache_storage_binding(workspace, root)):
            raise ValueError('Credited stock cache storage role changed')
        return raw
    except (OSError, ValueError, TypeError, KeyError, TRUST.TrustError, RecursionError) as error:
        raise UpgradeError('Stock cache capacity proof changed; no cache publication was attempted. Preserve the transaction and retry full storage admission.') from error


def _admit_stock_writes(root, cache_fd, new_packages, interrupted):
    """Check actual cache and recovery writes together when their mounts coincide."""
    if not new_packages and not interrupted:
        return
    root_fd = TRUST.directory(root, protected=True)
    try:
        filesystems = {}
        for fd, sizes, evidence in ((cache_fd, new_packages, False), (root_fd, interrupted, True)):
            if not sizes:
                continue
            usage = os.fstatvfs(fd)
            unit = max(4096, usage.f_frsize)
            # The destination temporary is renamed to the final package name.
            # Recovery also creates a directory and an origin record. Reserve
            # file data plus a fragment for directory growth on the destination.
            bytes_needed = sum((n + unit - 1) // unit * unit for n in sizes)
            bytes_needed += len(sizes) * unit * (4 if evidence else 1)
            nodes = len(sizes) * (3 if evidence else 1)
            device = os.fstat(fd).st_dev
            available = usage.f_bavail * usage.f_frsize
            available_nodes = usage.f_favail if usage.f_files else None
            row = filesystems.setdefault(device, [0, 0, available, available_nodes])
            row[0] += bytes_needed
            row[1] += nodes
            row[2] = min(row[2], available)
            if available_nodes is not None:
                row[3] = available_nodes if row[3] is None else min(row[3], available_nodes)
            if usage.f_flag & os.ST_RDONLY:
                raise UpgradeError('Stock package or recovery filesystem is read-only; preserve existing packages.')
        if any(free < needed or (inodes is not None and inodes < nodes)
               for needed, nodes, free, inodes in filesystems.values()):
            raise UpgradeError('Insufficient space or inodes for signed stock packages and interrupted recovery evidence; preserve existing packages.')
    finally:
        os.close(root_fd)


def cache_stock_packages(workspace, root, *, capacity_proof=None, capacity_proof_sha256=None):
    """Retain at most two signed package versions per module for offline removal."""
    capacity_raw = None
    if capacity_proof is not None or capacity_proof_sha256 is not None:
        capacity_raw = _verify_capacity_stock_proof(workspace, root, capacity_proof, capacity_proof_sha256)
    folder=root/'stock-packages';TRUST.prepare_root(root);TRUST.prepare_root(folder)
    pending={}
    for module in ('dashboard','framework'):
        for path in workspace.glob(module+'-*.tgz.gpg'):
            match=re.fullmatch(module+r'-(17\.[0-9]+(?:\.[0-9]+){1,3})\.tgz\.gpg',path.name)
            if not match:raise UpgradeError('Unsafe stock cache source name')
            upstream_contents(path,module,match[1],workspace)
            pending[path.name]=TRUST.read(path,TRUST.MAX_ARCHIVE,protected=True)
    descriptor=TRUST.directory(folder,protected=True)
    try:
        cached={};interrupted=[]
        with os.scandir(descriptor) as entries:
            for index,entry in enumerate(entries):
                if index>=6:raise UpgradeError('The stock package cache exceeds its bounded interrupted-update allowance; preserve it for review')
                if re.fullmatch(r'\.new-[a-f0-9]{24}',entry.name):
                    info=entry.stat(follow_symlinks=False)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1
                            or stat.S_IMODE(info.st_mode)!=0o600):
                        raise UpgradeError('Unsafe interrupted stock cache entry; preserve it for review')
                    body=TRUST.read(folder/entry.name,TRUST.MAX_ARCHIVE,protected=True)
                    if not any(body==approved for approved in pending.values()):
                        raise UpgradeError('Interrupted stock cache entry lacks a matching authenticated pending package; preserve it for review')
                    interrupted.append((entry.name,body,(info.st_dev,info.st_ino,info.st_ctime_ns)))
                    continue
                match=re.fullmatch(r'(dashboard|framework)-(17\.[0-9]+(?:\.[0-9]+){1,3})\.tgz\.gpg',entry.name)
                if not match:raise UpgradeError('Unknown stock cache entry; preserve it for review')
                body=TRUST.read(folder/entry.name,TRUST.MAX_ARCHIVE,protected=True)
                upstream_contents(folder/entry.name,match[1],match[2],workspace)
                cached[entry.name]=body
        for name,body in pending.items():
            if name in cached and cached[name]!=body:raise UpgradeError('A signed stock version has conflicting cached packages; preserve both for review')
        keep=set()
        for module in ('dashboard','framework'):
            names=[name for name in set(cached)|set(pending) if name.startswith(module+'-')]
            pointer=root/(module+'.active.json')
            active=TRUST.load(root,module)[0]['version'] if pointer.exists() or pointer.is_symlink() else None
            required={module+'-'+active+'.tgz.gpg'} if active else set()
            required.update(name for name in pending if name.startswith(module+'-'))
            if len(required)>2:raise UpgradeError('Too many active stock package versions for bounded caching')
            keep.update(required)
            for name in sorted(names,key=lambda value:tuple(map(int,value[len(module)+1:-8].split('.'))),reverse=True):
                if len([item for item in keep if item.startswith(module+'-')])>=2:break
                keep.add(name)
        if capacity_raw is not None:
            if capacity_raw != _verify_capacity_stock_proof(workspace, root, capacity_proof, capacity_proof_sha256):
                raise UpgradeError('Stock cache capacity proof changed before publication; preserve recovery evidence')
        _admit_stock_writes(root, descriptor,
            [len(body) for name,body in pending.items() if name not in cached],
            [len(body) for _,body,_ in interrupted])
        # Pending bytes have already passed independent signature verification.
        # Retire only reviewed, obsolete packages before adding replacements;
        # the active installed version always remains in keep.
        for name,body,identity in interrupted:
            current=os.stat(name,dir_fd=descriptor,follow_symlinks=False)
            if (current.st_dev,current.st_ino,current.st_ctime_ns)!=identity or TRUST.read(folder/name,TRUST.MAX_ARCHIVE,protected=True)!=body:
                raise UpgradeError('Interrupted stock cache entry changed; preserve it for review')
            evidence=Path(tempfile.mkdtemp(prefix='.stock-cache-recovery-',dir=root))
            TRUST.atomic(evidence/'package.tgz.gpg',body)
            write_json(evidence/'origin.json',{'schema':1,'source':'authenticated_pending_atomic_publication',
                       'original_temporary':name,'sha256':TRUST.digest(body)})
            current=os.stat(name,dir_fd=descriptor,follow_symlinks=False)
            if (current.st_dev,current.st_ino,current.st_ctime_ns)!=identity:
                raise UpgradeError('Interrupted stock cache entry changed after evidence retention; preserve both for review')
            os.unlink(name,dir_fd=descriptor);os.fsync(descriptor)
            print('Interrupted stock publication evidence retained at '+str(evidence),file=sys.stderr)
        for name in set(cached)-keep:
            current=TRUST.read(folder/name,TRUST.MAX_ARCHIVE,protected=True)
            if current!=cached[name]:raise UpgradeError('Stock cache changed during retention; no further recovery files were deleted')
            os.unlink(name,dir_fd=descriptor)
        for name,body in pending.items():
            if name not in cached:TRUST.atomic(folder/name,body)
        os.fsync(descriptor)
    finally:os.close(descriptor)


def carry_reviewed_overlays(previous, previous_base, candidate):
    """Carry a reviewed local file only when its independent upstream base did not change."""
    omissions = []
    for name in sorted(previous_base['files'].keys() - previous['files'].keys()):
        if name in WIDGETS or name in NATIVE_FRAMEWORK_TOOLING or name == NATIVE_FRAMEWORK_INIT:
            continue
        replacement = candidate['files'].get(name)
        if replacement is None:
            continue
        if replacement != previous_base['files'][name]:
            raise UpgradeError('A reviewed omission intersects changed upstream source: ' + name)
        del candidate['files'][name]
        omissions.append(name)
    if omissions:
        candidate['source']['carried_stock_omissions'] = omissions
    for name,entry in previous['files'].items():
        if name in WIDGETS:continue
        if name == MENU_NAME:
            clean = previous.get('uninstall', {}).get('replace', {}).get(name)
            if clean:
                entry = {**entry, 'sha256': clean}
        base=previous_base['files'].get(name)
        if base==entry:continue
        if previous.get('module') == 'framework' and name == SPINNER and base is not None:
            # Rebuilding the old signed archive observes today's deployment path.
            # Each native representation has the same vendor-authenticated GIF.
            plain = {'target': 'admin/images/spinner.gif', 'sha256': base['sha256']}
            native = (plain, {**plain, 'link_target': 'admin/modules/core/images/spinner.gif'})
            if base in native and entry in native:
                continue
        replacement=candidate['files'].get(name)
        if base is None and replacement is None:
            candidate['files'][name]=copy.deepcopy(entry)
        elif base is not None and replacement==base:
            candidate['files'][name]=copy.deepcopy(entry)
        else:
            raise UpgradeError('A reviewed local overlay intersects changed upstream source: '+name+'. Preserve it and review the merge independently.')


def carry_from_signed_base(previous, candidate, contents, web, workspace, root, packages, online):
    module, version = previous['module'], previous['version']
    package = stock_package(module, version, workspace, root, packages=packages, online=online)
    stock, source = upstream_contents(package, module, version, workspace)
    if previous['source'].get('archive_sha256') != source['archive_sha256']:
        raise UpgradeError('The previous reviewed ' + module + ' inventory does not identify this signed upstream base; independent review is required')
    base, _ = upstream_inventory(stock, source, module, version, contents, contents, web)
    carry_reviewed_overlays(previous, base, candidate)


def reconcile_stock(workspace, root, *, web=WEB, packages=None, online=False, schedule_signature_check=False):
    """Approve independent current stock plus authenticated SLL overlays, never observed hashes."""
    TRUST.prepare_root(workspace)
    sls,contents=authenticated_generation(root, retained=True)
    TRUST.check(root,'slsmassnotifyserver',web)
    approvals={};changed=[];references={}
    for module in ('dashboard','framework'):
        previous,_=TRUST.load(root,module);version=identity(web,module)
        references[module]=TRUST.read(root/(module+'.active.json'),1024,protected=True)
        if previous['version']==version:
            approvals[module]=copy.deepcopy(previous)
        else:
            package=stock_package(module,version,workspace,root,packages=packages,online=online)
            stock,source=upstream_contents(package,module,version,workspace)
            candidate,_=upstream_inventory(stock,source,module,version,contents,contents,web)
            carry_from_signed_base(previous, candidate, contents, web, workspace, root, packages, online)
            approvals[module]=candidate;changed.append(module)
        issues=compare_stock(approvals[module],approvals[module],web,contents,
                             transitioning_from=previous if module in changed else None)
        if issues:
            write_json(workspace/'review-required.json',{'schema':1,'approved':False,'differences':issues})
            raise UpgradeError('Unreviewed '+module+' differences remain. Review '+str(workspace/'review-required.json')+'; no active approval was replaced.')
    # Detect an intervening SLS/stock update before publishing any authority.
    if authenticated_generation(root, retained=True)[0]!=sls:raise UpgradeError('SLL changed during stock review; retry without approving new live hashes')
    for module in approvals:
        if identity(web,module)!=approvals[module]['version'] or TRUST.read(root/(module+'.active.json'),1024,protected=True)!=references[module]:
            raise UpgradeError('Stock installation or approval changed during review; retry')
        if compare_stock(approvals[module],approvals[module],web,contents):raise UpgradeError('Stock files changed during final review; prior authority retained')
    cache_stock_packages(workspace,root)
    if authenticated_generation(root, retained=True)[0]!=sls:raise UpgradeError('SLL changed while retaining recovery packages; prior stock authority retained')
    TRUST.check(root,'slsmassnotifyserver',web)
    for module in approvals:
        if identity(web,module)!=approvals[module]['version'] or TRUST.read(root/(module+'.active.json'),1024,protected=True)!=references[module] or compare_stock(approvals[module],approvals[module],web,contents):
            raise UpgradeError('Stock files or approvals changed while retaining signed recovery packages; prior authority retained')
    committed=[]
    try:
        for module in changed:
            path=workspace/(module+'.json');digest=write_json(path,approvals[module]);committed.append(module);TRUST.enroll_reviewed(root,path,digest)
    except BaseException:
        failures=[]
        for module in reversed(committed):
            try:TRUST.atomic(root/(module+'.active.json'),references[module])
            except BaseException:failures.append(module)
        if failures:
            write_json(workspace/'previous-stock-references.json',{'schema':1,'references':{key:json.loads(value) for key,value in references.items()}})
            raise UpgradeError('Stock approval rollback was incomplete for '+', '.join(failures)+'. Preserve '+str(workspace)+' for reviewed recovery.')
        raise
    if schedule_signature_check:
        # The explicit console caller still holds the installer/maintenance lock.
        # Restoring an approved file may leave both active pointers unchanged.
        stock_maintenance(root, 'request', web=web)
    return {'ok':True,'changed_modules':changed,'source':'independently_signed_upstream_and_authenticated_overlays','network_allowed':online}


def stock_observation(root, web):
    """Read eight bounded control files for scheduling. No digest grants signing authority."""
    missing = object()
    def body(path, limit, *, protected=False):
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                return None
            return TRUST.read(path, limit, protected=protected)
        except FileNotFoundError:
            return missing
        except (OSError, TRUST.TrustError):
            return None

    def fingerprint(raw):
        if raw is missing:
            return 'missing'
        return 'unavailable' if raw is None else TRUST.digest(raw)

    approvals = {module: fingerprint(body(root/(module+'.active.json'), 1024, protected=True))
                 for module in ('slsmassnotifyserver', 'dashboard', 'framework')}
    xml = {}
    versions = {}
    signatures = {}
    for module in ('dashboard', 'framework'):
        directory = web / 'admin/modules' / module
        raw = body(directory/'module.xml', 1024 * 1024)
        xml[module] = fingerprint(raw)
        try:
            versions[module] = module_identity(raw, module) if isinstance(raw, bytes) else None
        except (UpgradeError, ET.ParseError, LookupError, ValueError):
            versions[module] = None
        signatures[module] = fingerprint(body(directory/'module.sig', TRUST.MAX_MANIFEST))
    return {'approvals': approvals, 'versions': versions, 'xml': xml, 'signatures': signatures,
            'menu': fingerprint(body(web/'admin/views/menu_items.php', 1024 * 1024))}


def approved_stock_controls(root, sls_approval):
    """Pin the exact reviewed projections and the three protected references."""
    controls = {'approvals': {'slsmassnotifyserver': sls_approval}, 'versions': {}, 'xml': {}, 'menu': 'missing'}
    for module in ('dashboard','framework'):
        data, generation = TRUST.load(root, module)
        reference = TRUST.read(root/(module+'.active.json'), 1024, protected=True)
        if json.loads(reference)['generation'] != generation.name:
            raise UpgradeError('Protected stock approval changed during verification')
        controls['approvals'][module] = TRUST.digest(reference)
        controls['versions'][module] = data['version']
        controls['xml'][module] = data['files']['module.xml']['sha256']
        if module == 'framework' and MENU_NAME in data['files']:
            controls['menu'] = data['files'][MENU_NAME]['sha256']
    return controls


def stock_maintenance(root, action, *, web=WEB, requested=False, now=None, packages=None, verified_signatures=None):
    """Schedule automatic review under the same exclusive lock as the installer."""
    stamp = int(time.time()) if now is None else now
    record = root / 'stock-maintenance.json'
    report = root / 'stock-maintenance-review.json'
    seen = stock_observation(root, web)
    try:
        state = json.loads(TRUST.read(record, 16384, protected=True))
    except FileNotFoundError:
        state = {}
    phase = state.get('phase')
    if action == 'request':
        # Keep the prior review report and ownership of interrupted workspaces.
        # Only a subsequent guarded verification can mark this request complete.
        if phase and phase != 'requested':
            state['phase'] = 'requested'
            write_json(record, state)
        return 'due'
    previous = state.get('seen', {})
    same_approvals = previous.get('approvals') == seen['approvals']
    same_versions = previous.get('versions') == seen['versions']
    age = stamp - state.get('time', 0)
    retry_delays = (300, 900, 3600, 21600, 86400)
    if action == 'probe':
        if state.get('schema') != 3:
            return 'due'
        if previous == seen and phase == 'complete' and not requested:
            return 'current'
        if same_approvals and age >= 0:
            if phase in ('attempting', 'transition'):
                delay = retry_delays[state['retry_index']] if same_versions else retry_delays[0]
                if age < delay:
                    return 'waiting'
            elif phase == 'failed':
                # Stable review evidence gets one daily retry. A new module
                # version can retry sooner than unrelated signature churn.
                interval = 86400
                if previous != seen:
                    interval = 3600 if same_versions else 300
                if age < interval:
                    return 'waiting'
            elif phase == 'complete' and same_versions and state.get('same_version_retry') and age < 3600:
                return 'waiting'
        return 'due'
    if action == 'reserve':
        # A schema-1 pending receipt conflated failed and interrupted reviews.
        # Give that state one new attempt under the restartable protocol.
        retry_index = 0
        if phase in ('attempting','transition') and same_versions and same_approvals:
            retry_index = min(state['retry_index'] + 1, len(retry_delays)-1)
        state.update(schema=3, phase='attempting', attempted=seen, seen=seen, reviewed=None, time=stamp,
                     retry_index=retry_index, partial_update=False,
                     same_version_retry=same_versions and same_approvals)
        write_json(record, state)
        return 'reserved'
    if phase != 'attempting':
        raise UpgradeError('No stock maintenance review is in progress')
    if action == 'reconcile':
        # A killed run can leave one bounded workspace. The inode recorded
        # before downloads started owns only the finite private scratch files.
        workspace = root / 'stock-maintenance-work'
        try:
            workspace.mkdir(mode=0o700)
        except FileExistsError:
            retire_stock_workspace(workspace, state.get('workspace'))
            workspace.mkdir(mode=0o700)
        info = workspace.lstat()
        state['workspace'] = [info.st_dev, info.st_ino]
        write_json(record, state)
        try:
            reconcile_stock(workspace, root, web=web, packages=packages, online=packages is None)
            state['reviewed'] = approved_stock_controls(root, state['attempted']['approvals']['slsmassnotifyserver'])
            write_json(record, state)
        except Exception as error:
            details = workspace / 'review-required.json'
            issue = {'schema': 1, 'time': stamp, 'message': str(error).split('. Review ')[0][:600]}
            if details.is_file():
                issue['differences'] = json.loads(TRUST.read(details, TRUST.MAX_MANIFEST, protected=True))['differences']
                state['partial_update'] = bool(issue['differences']) and all(
                    row.get('possible_update_in_progress') for row in issue['differences'])
                write_json(record, state)
            write_json(report, issue)
            raise UpgradeError('Stock reconciliation requires review. See ' + str(report)) from error
        finally:
            # Incomplete restoration may need the original pointers. Keep their
            # complete protected workspace until an administrator resolves it.
            if not (workspace / 'previous-stock-references.json').exists():
                retire_stock_workspace(workspace, state['workspace'])
        return 'reconciled'
    if action == 'complete':
        modules = ('dashboard','framework')
        if (not state.get('reviewed') or not isinstance(verified_signatures, dict) or set(verified_signatures) != set(modules)
                or any(not isinstance(v, str) or not TRUST.DIGEST.fullmatch(v) for v in verified_signatures.values())):
            raise UpgradeError('Both verified stock signatures and a successful reconciliation are required')
        verified = {**state['reviewed'], 'signatures': verified_signatures}
        issues = []
        for module in modules:
            if verified['signatures'][module] != seen['signatures'][module]:
                issues.append({'module': module, 'path': 'module.sig', 'reason': 'changed after verification'})
            if (verified['xml'][module] != seen['xml'][module] or verified['versions'][module] != seen['versions'][module]
                    or state['attempted']['xml'][module] != seen['xml'][module]):
                issues.append({'module': module, 'path': 'module.xml', 'reason': 'changed during verification'})
        if verified['menu'] != seen['menu']:
            issues.append({'module': 'framework', 'path': MENU_NAME, 'reason': 'changed after verification'})
        for module, approval in verified['approvals'].items():
            if approval != seen['approvals'][module]:
                issues.append({'module': module, 'path': module+'.active.json', 'reason': 'approval changed after verification'})
        if issues:
            write_json(report, {'schema': 1, 'time': stamp, 'message': 'Verified stock changed before completion', 'differences': issues})
            state['partial_update'] = all(row['path'] == 'module.sig' for row in issues)
            write_json(record, state)
            raise UpgradeError('Verified stock changed before completion. See '+str(report))
        # Save the proof, so a write after the final comparison is visible to
        # the next probe even if it happens before this record reaches disk.
        seen = verified
        report.unlink(missing_ok=True)
    elif action != 'failed':
        raise UpgradeError('Invalid stock maintenance action')
    phase = action
    if action == 'failed' and (not same_versions or not same_approvals or state['partial_update']):
        phase = 'transition'
        # The reservation only tried its original version. New stock appearing
        # during that attempt receives the first short retry even after backoff.
        if not same_versions or not same_approvals:
            state['retry_index'] = 0
    state.update(phase=phase, seen=seen, time=stamp)
    write_json(record, state)
    return phase


def retire_stock_workspace(workspace, owner):
    info = workspace.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise UpgradeError('Unsafe stock maintenance workspace; preserve it for review: ' + str(workspace))
    allowed = re.compile(r'(?:(?:dashboard|framework)(?:-17\.[0-9]+(?:\.[0-9]+){1,3}\.tgz\.gpg|\.json)|review-required\.json|\.new-[a-f0-9]{24})\Z')
    with os.scandir(workspace) as entries:
        for index, entry in enumerate(entries):
            leaf = entry.stat(follow_symlinks=False)
            if (owner != [info.st_dev, info.st_ino] or index >= 10 or not allowed.fullmatch(entry.name)
                    or not stat.S_ISREG(leaf.st_mode) or leaf.st_uid != 0 or leaf.st_mode & 0o022 or leaf.st_nlink != 1):
                raise UpgradeError('Unrecognized stock maintenance workspace material; preserve it for review: ' + str(workspace))
    shutil.rmtree(workspace)


def coordination_lock(path, inherited=None):
    """Join the existing root maintenance fence without replacing its inode."""
    if not path.is_absolute() or '..' in path.parts:raise UpgradeError('Unsafe stock-reconciliation lock path')
    for parent in reversed(path.parents):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or (info.st_mode&0o022 and not info.st_mode&stat.S_ISVTX):
            raise UpgradeError('Unprotected stock-reconciliation lock directory')
    descriptor=os.dup(inherited) if inherited is not None else os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,0o600)
    try:
        opened=os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_uid!=0 or opened.st_mode&0o077 or opened.st_size:
            raise UpgradeError('Unsafe stock-reconciliation coordination lock')
        try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise UpgradeError('SLL installation or maintenance is active. Retry stock reconciliation after it finishes.') from None
        current=path.lstat()
        if (opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid,opened.st_nlink)!=(current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_nlink):
            raise UpgradeError('Stock-reconciliation coordination lock changed')
        return descriptor
    except BaseException:os.close(descriptor);raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--trust-root', type=Path, default=Path('/var/lib/sls-mass-notify-trust'))
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--signature', type=Path)
    parser.add_argument('--verify-previous', action='store_true')
    parser.add_argument('--restore-previous-module', action='store_true')
    parser.add_argument('--module-backup', type=Path)
    parser.add_argument('--had-existing-module', choices=('0', '1'))
    parser.add_argument('--normalize-runtime', action='store_true')
    parser.add_argument('--bootstrap-dashboard-version')
    parser.add_argument('--cache-stock',action='store_true')
    parser.add_argument('--cache-storage-proof',type=Path)
    parser.add_argument('--cache-storage-proof-sha256')
    parser.add_argument('--reconcile-stock',action='store_true')
    parser.add_argument('--maintenance-stock', choices=('probe','reserve','reconcile','complete','failed'))
    parser.add_argument('--verified-signatures', nargs=2, metavar=('DASHBOARD_SHA256','FRAMEWORK_SHA256'))
    parser.add_argument('--integration-drift', action='store_true')
    parser.add_argument('--review-retained',action='store_true',help='Review one byte-exact active generation whose signed release metadata expired')
    parser.add_argument('--approve-retained',metavar='SHA256',help='Approve the exact previously reviewed retained-generation challenge for seven days')
    parser.add_argument('--operator')
    parser.add_argument('--reason')
    parser.add_argument('--upstream-packages',type=Path)
    parser.add_argument('--online',action='store_true',help='Explicitly allow verified FreePBX stock package downloads for reconciliation')
    parser.add_argument('--coordination-fd',type=int)
    parser.add_argument('--coordination-lock',type=Path,default=Path('/run/lock/sls-mass-notify-maintenance.lock'))
    args = parser.parse_args()
    if args.workspace is None and not args.maintenance_stock:
        parser.error('This action requires --workspace')
    if os.geteuid() != 0:
        raise UpgradeError('Upgrade trust preparation requires root')
    TRUST.read(HERE / 'sls_upgrade_trust.py', TRUST.MAX_ARCHIVE, protected=True)
    if sum(bool(item) for item in (args.verify_previous, args.restore_previous_module, args.normalize_runtime, args.bootstrap_dashboard_version,args.cache_stock,args.reconcile_stock,args.maintenance_stock,args.review_retained,args.approve_retained)) > 1:
        parser.error('Select only one recovery action')
    if args.restore_previous_module != (args.module_backup is not None and args.had_existing_module is not None):
        parser.error('Module restoration requires --module-backup and --had-existing-module')
    if not args.restore_previous_module and (args.module_backup is not None or args.had_existing_module is not None):
        parser.error('Module restoration options require --restore-previous-module')
    if (args.online or args.upstream_packages) and not args.reconcile_stock:parser.error('Stock package options require --reconcile-stock')
    if args.integration_drift and args.maintenance_stock != 'probe':
        parser.error('--integration-drift is only used to schedule a stock maintenance review')
    if (args.maintenance_stock == 'complete') != (args.verified_signatures is not None):
        parser.error('Stock maintenance completion requires both verified signature digests')
    if (args.cache_storage_proof is not None or args.cache_storage_proof_sha256 is not None) and (not args.cache_stock or args.cache_storage_proof is None or args.cache_storage_proof_sha256 is None):
        parser.error('A stock capacity proof and hash require the coordinated --cache-stock action')
    if (args.operator is not None or args.reason is not None) and not args.approve_retained:
        parser.error('Operator and reason require --approve-retained')
    if args.approve_retained and (args.operator is None or args.reason is None):
        parser.error('Retained approval requires --operator and --reason after a separate review')
    if args.coordination_fd is not None and (not (args.reconcile_stock or args.cache_stock or args.maintenance_stock or args.approve_retained) or not 3<=args.coordination_fd<=65535):parser.error('A coordinated action requires a valid inherited descriptor')
    if args.maintenance_stock:
        lock = coordination_lock(args.coordination_lock, args.coordination_fd)
        try:
            proofs = dict(zip(('dashboard','framework'), args.verified_signatures)) if args.verified_signatures else None
            print(stock_maintenance(args.trust_root, args.maintenance_stock, requested=args.integration_drift, verified_signatures=proofs))
        finally:
            os.close(lock)
    elif args.review_retained:
        print(json.dumps(review_retained(args.trust_root)))
    elif args.approve_retained:
        lock=coordination_lock(args.coordination_lock,args.coordination_fd)
        try:print(json.dumps(review_retained(args.trust_root,approval=args.approve_retained,operator=args.operator,reason=args.reason)))
        finally:os.close(lock)
    elif args.cache_stock:
        lock=coordination_lock(args.coordination_lock,args.coordination_fd)
        try:cache_stock_packages(args.workspace,args.trust_root,capacity_proof=args.cache_storage_proof,capacity_proof_sha256=args.cache_storage_proof_sha256)
        finally:os.close(lock)
    elif args.reconcile_stock:
        lock=coordination_lock(args.coordination_lock,args.coordination_fd)
        try:print(json.dumps(reconcile_stock(args.workspace,args.trust_root,packages=args.upstream_packages,online=args.online)))
        finally:os.close(lock)
    elif args.bootstrap_dashboard_version:
        bootstrap_dashboard(args.workspace, args.bootstrap_dashboard_version)
    elif args.normalize_runtime:
        normalize_previous_runtime(args.workspace)
    elif args.verify_previous:
        verify_previous(args.workspace)
    elif args.restore_previous_module:
        restore_previous_module(args.workspace, args.module_backup, args.had_existing_module == '1')
    else:
        if args.archive is None or args.manifest is None or args.signature is None:
            parser.error('Signed candidate archive, manifest and signature are required')
        prepare(args)


if __name__ == '__main__':
    try:
        main()
    except (UpgradeError, TRUST.TrustError, OSError, ValueError, KeyError, ET.ParseError, tarfile.TarError, subprocess.SubprocessError) as error:
        print('SLL upgrade preflight: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
