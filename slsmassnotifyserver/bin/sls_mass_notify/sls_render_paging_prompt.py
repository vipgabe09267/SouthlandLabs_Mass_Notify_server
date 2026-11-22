#!/usr/bin/python3
"""Render and publish a paging prompt as the native PBX account."""
import argparse
import ctypes
from contextlib import contextmanager
import errno
import fcntl
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import wave

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sls_resource_capacity import VOICE_BYTES, REGIONAL_VOICE_BYTES, VOICE_SHA256, piper_voice_current
from sls_speech_admission import Admission, DATA, PIPER, SpeechAdmissionError, SpeechCapacityError, synthesize
from sls_phone_admission import read_private_json
from sls_storage_maintenance import open_directory

PAGING = DATA / 'sounds/paging'
MAX_SECONDS = 600
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2


class PromptChanged(ValueError):
    """Another publisher changed the expected prompt while this render ran."""


@contextmanager
def report_write_capacity(role, location):
    try:
        yield
    except OSError as error:
        if error.errno not in (errno.EDQUOT, errno.ENOSPC, errno.EROFS):
            raise
        detail = f'Generated-media write refused. role={role} kernel_errno={error.errno}'
        try:
            capacity = os.statvfs(location)
            detail += f' available_bytes={capacity.f_bavail * capacity.f_frsize} read_only={int(bool(capacity.f_flag & os.ST_RDONLY))}'
            if capacity.f_files > 0:
                detail += f' available_inodes={capacity.f_favail}'
        except OSError:
            pass
        raise SpeechCapacityError(detail) from error


def previous_info(directory, name):
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022):
        raise ValueError('Unsafe previous prompt')
    return info


def previous_identity(directory, name):
    info = previous_info(directory, name)
    return 'missing' if info is None else f'{info.st_dev}:{info.st_ino}'


def file_state(info):
    if info is None:
        return None
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns)


def rename_prompt(directory, source, destination, flags):
    # Linux NOREPLACE prevents a new file from being overwritten. EXCHANGE
    # preserves the old inode until the replacement directory entry is durable.
    rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    if rename is not None:
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(directory, os.fsencode(source), directory, os.fsencode(destination), flags) == 0:
            return
        number = ctypes.get_errno()
        if number not in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            raise OSError(number, os.strerror(number))
    if flags != RENAME_NOREPLACE:
        raise OSError(errno.EOPNOTSUPP, 'This filesystem cannot exchange an existing prompt atomically')
    os.link(source, destination, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    try:
        os.unlink(source, dir_fd=directory)
    except BaseException:
        if os.path.samestat(os.stat(source, dir_fd=directory, follow_symlinks=False),
                            os.stat(destination, dir_fd=directory, follow_symlinks=False)):
            os.unlink(destination, dir_fd=directory)
        raise


def commit(directory, temporary, name, staged, before):
    current_directory = open_directory(PAGING)
    try:
        current = os.fstat(current_directory)
        if not os.path.samestat(current, os.fstat(directory)) or current.st_uid != os.geteuid() or current.st_mode & 0o022:
            raise ValueError('Paging directory changed before publication')
    finally:
        os.close(current_directory)
    current = previous_info(directory, name)
    if (file_state(before) != file_state(current)
            or (before is not None and before.st_ctime_ns != current.st_ctime_ns)):
        raise PromptChanged('Prompt changed before publication')
    if not os.path.samestat(staged, os.stat(temporary, dir_fd=directory, follow_symlinks=False)):
        raise ValueError('Prompt staging changed before publication')
    rename_prompt(directory, temporary, name, RENAME_NOREPLACE if before is None else RENAME_EXCHANGE)
    try:
        if before is not None and file_state(before) != file_state(previous_info(directory, temporary)):
            raise PromptChanged('A different prompt was displaced before publication')
        if file_state(staged) != file_state(previous_info(directory, name)):
            raise ValueError('Published prompt changed before completion')
        os.fsync(directory)
    except BaseException:
        # Only undo our own published entry. A displaced file stays available if
        # an independent writer has already taken ownership of the public name.
        if os.path.samestat(staged, os.stat(name, dir_fd=directory, follow_symlinks=False)):
            if before is None:
                os.unlink(name, dir_fd=directory)
            else:
                rename_prompt(directory, temporary, name, RENAME_EXCHANGE)
            os.fsync(directory)
        raise
    if before is not None:
        # The new entry is already durable. Retain the displaced inode if its
        # name changed, otherwise remove the no-longer-needed recovery link.
        if file_state(before) != file_state(previous_info(directory, temporary)):
            raise ValueError('Displaced prompt changed after publication')
        os.unlink(temporary, dir_fd=directory)


def publish(directory, name, previous, raw, volume, expected=None):
    before = previous_info(directory, name)
    if previous != ('missing' if before is None else f'{before.st_dev}:{before.st_ino}'):
        raise PromptChanged('Unexpected previous prompt')
    if expected is not None and (file_state(before) != file_state(expected) or before.st_ctime_ns != expected.st_ctime_ns):
        raise PromptChanged('Previous prompt changed during synthesis')

    temporary = '.prompt-' + secrets.token_hex(16)
    fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        subprocess.run(['/usr/bin/sox', '-v', f'{volume / 100:.2f}', str(raw), '-r', '8000', '-c', '1',
                        '-b', '16', '-t', 'wav', f'/proc/self/fd/{fd}'], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=(fd,), timeout=30, check=True)
        if not 44 < os.fstat(fd).st_size <= MAX_SECONDS * 16000 + 65536:
            raise ValueError('Invalid converted prompt size')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            stream.seek(0)
            with wave.open(stream, 'rb') as audio:
                frames = audio.getnframes()
                if ((audio.getframerate(), audio.getnchannels(), audio.getsampwidth()) != (8000, 1, 2)
                        or not 0 < frames <= MAX_SECONDS * 8000):
                    raise ValueError('Invalid converted prompt')
                audio.setpos(frames - 1)
                if len(audio.readframes(1)) != 2:
                    raise ValueError('Incomplete converted prompt')
        group = pwd.getpwnam('asterisk').pw_gid
        if os.fstat(fd).st_gid != group:
            os.fchown(fd, -1, group)
        os.fchmod(fd, 0o640)
        os.fsync(fd)
        staged = os.fstat(fd)
        if not stat.S_ISREG(staged.st_mode) or staged.st_nlink != 1 or staged.st_uid != os.geteuid():
            raise ValueError('Invalid converted prompt staging file')
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            commit(directory, temporary, name, staged, before)
        finally:
            fcntl.flock(directory, fcntl.LOCK_UN)
    finally:
        try:
            named = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
            if os.path.samestat(named, os.fstat(fd)):
                os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        finally:
            os.close(fd)


def render(name, model, previous, volume, text):
    if (os.geteuid() <= 0 or os.geteuid() != pwd.getpwnam('asterisk').pw_uid
            or not re.fullmatch(r'[0-9a-f]{64}\.wav', name)
            or not re.fullmatch(r'missing|[0-9]{1,20}:[0-9]{1,20}', previous)
            or not 1 <= volume <= 200 or not 0 < len(text) <= 65536 or b'\0' in text):
        raise ValueError('Invalid paging prompt request')
    text.decode('utf-8', 'strict')
    config = read_private_json('mass-notifications.config')
    sizes = dict(VOICE_BYTES)
    packs = config.get('speech_optional_voice_packs', [])
    if not isinstance(packs, list) or any(not isinstance(pack, str) or pack not in REGIONAL_VOICE_BYTES for pack in packs):
        raise ValueError('Invalid paging voice configuration')
    for pack in packs:
        sizes.update(REGIONAL_VOICE_BYTES[pack])
    if model.parent != DATA / 'piper/voices' or not model.name.endswith('.onnx'):
        raise ValueError('Invalid paging voice')
    for path in (model, model.with_suffix('.onnx.json')):
        if path.name not in sizes or not piper_voice_current(path, VOICE_SHA256[path.name], sizes[path.name]):
            raise ValueError('Unverified paging voice')
    directory = open_directory(PAGING)
    try:
        named = os.fstat(directory)
        prior = previous_info(directory, name)
        if named.st_uid != os.geteuid() or named.st_mode & 0o022:
            raise ValueError('Unexpected paging directory')
        if ('missing' if prior is None else f'{prior.st_dev}:{prior.st_ino}') != previous:
            raise PromptChanged('Unexpected previous prompt')
        admission = Admission(config, MAX_SECONDS, additional_media_directory_fd=directory)
        try:
            with report_write_capacity('data', DATA):
                admission.acquire()
            with report_write_capacity('temporary', '/tmp'), tempfile.TemporaryDirectory(dir='/tmp', prefix='sls_announcement_') as workspace:
                message, raw = Path(workspace) / 'message.txt', Path(workspace) / 'speech.wav'
                with os.fdopen(os.open(message, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600), 'wb') as stream:
                    stream.write(text)
                code = synthesize([PIPER, '--model', str(model), '--volume', '1.00',
                                   '--input-file', str(message), '--output-file', str(raw)],
                                  MAX_SECONDS, 900, admission.slot_number)
                if code:
                    if code == 73:
                        return 77  # A worker exit alone cannot establish a measured capacity refusal.
                    return code if code in (65, 74, 75, 78, 124) else 69
                with report_write_capacity('destination', directory):
                    publish(directory, name, previous, raw, volume, expected=prior)
            with report_write_capacity('data', DATA):
                admission.complete()
        finally:
            with report_write_capacity('data', DATA):
                admission.close()
    finally:
        os.close(directory)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('name')
    parser.add_argument('model', type=Path)
    parser.add_argument('previous')
    parser.add_argument('volume', type=int)
    args = parser.parse_args()
    os.umask(0o027)
    try:
        return render(args.name, args.model, args.previous, args.volume, sys.stdin.buffer.read(65537))
    except SpeechCapacityError as error:
        print(str(error), flush=True)
        return 73
    except SpeechAdmissionError as error:
        return 77 if error.code == 73 else error.code
    except (BlockingIOError, FileExistsError, PromptChanged):
        return 75
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return 69
    except OSError as error:
        if error.errno in (errno.ENOSYS, errno.EOPNOTSUPP):
            return 69
        return 77
    except (RuntimeError, ValueError, KeyError, EOFError, wave.Error):
        return 77


if __name__ == '__main__':
    raise SystemExit(main())
