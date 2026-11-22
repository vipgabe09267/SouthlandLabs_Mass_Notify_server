#!/bin/bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Read-only bootstrap recovery may use only these independently pinned bytes.
CONFIG_CRYPTO_BOOTSTRAP_SHA256="e944ceec47e3db62ae2071aac6d4368f40447764976d554ba4662c620b46a215"

umask 027

if ! command -v readlink >/dev/null 2>&1; then
  printf 'The installer requires coreutils readlink before bootstrap. Install coreutils, then retry. No PBX state was changed.\n' >&2
  exit 2
fi
INSTALLER_SOURCE_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
REQUESTED_RECOVERY=""
REQUESTED_HISTORY_EVIDENCE=""
REQUESTED_HISTORY_REVIEW=0
REQUESTED_HISTORY_LOSS_APPROVAL=""
REQUESTED_HISTORY_LOSS_OPERATOR=""
REQUESTED_HISTORY_LOSS_REASON=""
REQUESTED_DEPLOYMENT_PROFILE=""
REQUESTED_RETAINED_MODE=""
REQUESTED_RETAINED_APPROVAL=""
REQUESTED_RETAINED_OPERATOR=""
REQUESTED_RETAINED_REASON=""
case "${1:-}" in
  --lite) REQUESTED_DEPLOYMENT_PROFILE=lite; shift ;;
  --standard) REQUESTED_DEPLOYMENT_PROFILE=standard; shift ;;
esac
if [ "${1:-}" = '--recover' ]; then
  REQUESTED_RECOVERY="${2:-}"
  [ -n "$REQUESTED_RECOVERY" ] || { printf 'Usage: %s --recover /var/lib/sls-mass-notify-installer/transaction-ID\n' "$0" >&2; exit 2; }
  shift 2
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --history-evidence)
        [ -z "$REQUESTED_HISTORY_EVIDENCE" ] && [[ "${2:-}" = /* ]] && [ "$2" != / ] || {
          printf 'Use --history-evidence once with an absolute root-private pre-upgrade phone ledger path.\n' >&2; exit 2;
        }
        REQUESTED_HISTORY_EVIDENCE="$2"; shift 2 ;;
      --review-history)
        [ "$REQUESTED_HISTORY_REVIEW" -eq 0 ] || { printf 'Use --review-history only once.\n' >&2; exit 2; }
        REQUESTED_HISTORY_REVIEW=1; shift ;;
      --approve-history-loss)
        [ -z "$REQUESTED_HISTORY_LOSS_APPROVAL" ] && [[ "${2:-}" =~ ^[a-f0-9]{64}$ ]] || {
          printf 'Use --approve-history-loss once with the exact SHA256 challenge from the protected history review.\n' >&2; exit 2;
        }
        REQUESTED_HISTORY_LOSS_APPROVAL="$2"; shift 2 ;;
      --history-loss-operator|--history-loss-reason)
        history_argument="$1"; history_value="${2:-}"
        [ -n "$history_value" ] && [[ "$history_value" != *[$'\001'-$'\037'$'\177']* ]] && [ "${#history_value}" -le 2048 ] || {
          printf 'History-loss operator and reason must be nonempty text without control characters (at most 2048 characters).\n' >&2; exit 2;
        }
        if [ "$history_argument" = --history-loss-operator ]; then
          [ -z "$REQUESTED_HISTORY_LOSS_OPERATOR" ] || { printf 'Use --history-loss-operator only once.\n' >&2; exit 2; }
          REQUESTED_HISTORY_LOSS_OPERATOR="$history_value"
        else
          [ -z "$REQUESTED_HISTORY_LOSS_REASON" ] || { printf 'Use --history-loss-reason only once.\n' >&2; exit 2; }
          REQUESTED_HISTORY_LOSS_REASON="$history_value"
        fi
        shift 2 ;;
      *) break ;;
    esac
  done
  if [ "$REQUESTED_HISTORY_REVIEW" -eq 1 ] && [ -n "$REQUESTED_HISTORY_LOSS_APPROVAL" ]; then
    printf 'Generate and review the history report before a separate explicit approval command.\n' >&2; exit 2
  fi
  if [ -n "$REQUESTED_HISTORY_LOSS_APPROVAL" ]; then
    [ -n "$REQUESTED_HISTORY_LOSS_OPERATOR" ] && [ -n "$REQUESTED_HISTORY_LOSS_REASON" ] || {
      printf 'History-loss approval requires --history-loss-operator and --history-loss-reason.\n' >&2; exit 2;
    }
  elif [ -n "$REQUESTED_HISTORY_LOSS_OPERATOR" ] || [ -n "$REQUESTED_HISTORY_LOSS_REASON" ]; then
    printf 'History-loss operator and reason require --approve-history-loss and its exact review challenge.\n' >&2; exit 2
  fi
fi
case "${1:-}" in
  --review-retained)
    REQUESTED_RETAINED_MODE=review
    shift ;;
  --approve-retained)
    REQUESTED_RETAINED_MODE=approve
    [[ "${2:-}" =~ ^[a-f0-9]{64}$ ]] || {
      printf 'Retained approval requires the exact SHA256 challenge from a separate --review-retained command.\n' >&2; exit 2;
    }
    REQUESTED_RETAINED_APPROVAL="$2"
    shift 2
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --operator|--reason)
          retained_argument="$1"; retained_value="${2:-}"
          [ -n "$retained_value" ] && [[ "$retained_value" != *[$'\001'-$'\037'$'\177']* ]] \
            && [[ "$retained_value" != [[:space:]]* && "$retained_value" != *[[:space:]] ]] || {
              printf 'Retained-review operator and reason must be bounded nonempty text without control characters or surrounding whitespace.\n' >&2; exit 2;
            }
          if [ "$retained_argument" = --operator ]; then
            [ -z "$REQUESTED_RETAINED_OPERATOR" ] && [ "${#retained_value}" -le 128 ] || {
              printf 'Use --operator once with at most 128 characters.\n' >&2; exit 2;
            }
            REQUESTED_RETAINED_OPERATOR="$retained_value"
          else
            [ -z "$REQUESTED_RETAINED_REASON" ] && [ "${#retained_value}" -ge 10 ] && [ "${#retained_value}" -le 500 ] || {
              printf 'Use --reason once with 10 through 500 characters.\n' >&2; exit 2;
            }
            REQUESTED_RETAINED_REASON="$retained_value"
          fi
          shift 2 ;;
        *) break ;;
      esac
    done
    [ -n "$REQUESTED_RETAINED_OPERATOR" ] && [ -n "$REQUESTED_RETAINED_REASON" ] || {
      printf 'Retained approval requires --operator and --reason after its exact review challenge.\n' >&2; exit 2;
    } ;;
esac
if [ "${1:-}" = '--inspect' ]; then
  SLS_MASS_NOTIFY_INVENTORY_ONLY=1
  shift
fi

# Invocation modes are intentionally small and mutually exclusive.  Reject
# misspelled flags and surplus arguments before any host inspection or package
# operation.  Tests source this file to exercise individual helpers, so only an
# executed installer owns and validates the caller's positional arguments.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  if [ -n "$REQUESTED_RETAINED_MODE" ] && { [ -n "$REQUESTED_RECOVERY" ] \
      || [ -n "$REQUESTED_DEPLOYMENT_PROFILE" ] || [ "${SLS_MASS_NOTIFY_INVENTORY_ONLY:-0}" = 1 ]; }; then
    printf 'Retained-source review/approval is separate from --inspect, --recover and deployment-profile changes.\n' >&2
    exit 2
  fi
  if [ -n "$REQUESTED_RECOVERY" ] && [ "${SLS_MASS_NOTIFY_INVENTORY_ONLY:-0}" = 1 ]; then
    printf 'Use either --recover TRANSACTION or --inspect [TGZ_URL], not both.\n' >&2
    exit 2
  fi
  if [ -n "$REQUESTED_RECOVERY" ] && [ -n "$REQUESTED_DEPLOYMENT_PROFILE" ]; then
    printf 'Recovery restores the original profile. Run --lite or --standard only after recovery completes.\n' >&2
    exit 2
  fi
  if [ -n "$REQUESTED_RECOVERY" ]; then
    [ "$#" -eq 0 ] || {
      printf 'Usage: %s --recover /var/lib/sls-mass-notify-installer/transaction-ID [--history-evidence /root/pre-upgrade-phone-admission.json] [--review-history | --approve-history-loss REVIEW_SHA256 --history-loss-operator NAME --history-loss-reason TEXT]\n' "$0" >&2
      exit 2
    }
  else
    [ "$#" -le 1 ] || {
      printf 'Usage: %s [--lite|--standard] [--inspect] [SIGNED_GITHUB_TGZ_URL]; or --review-retained [SIGNED_GITHUB_TGZ_URL]; or --approve-retained SHA256 --operator NAME --reason TEXT [SIGNED_GITHUB_TGZ_URL]\n' "$0" >&2
      exit 2
    }
    case "${1:-}" in
      --*) printf 'Unknown installer option: %s\n' "$1" >&2; exit 2 ;;
    esac
    if [ "$#" -eq 1 ] && [ -n "${SLS_MASS_NOTIFY_TGZ_URL:-}" ]; then
      printf 'Supply the release URL either as SLS_MASS_NOTIFY_TGZ_URL or as one positional argument, not both.\n' >&2
      exit 2
    fi
  fi
fi

MODULE="slsmassnotifyserver"
if [ -n "${SLS_MASS_NOTIFY_MODULE:-}" ] \
  && [ "${SLS_MASS_NOTIFY_MODULE}" != "$MODULE" ]; then
  printf '%s\n' \
    "SLS_MASS_NOTIFY_MODULE is fixed to the FreePBX raw module name '$MODULE'; refusing an alternate value." >&2
  exit 2
fi
TGZ="${SLS_MASS_NOTIFY_TGZ:-/tmp/slsmassnotifyserver-0.2.0-beta.tgz}"
URL="${SLS_MASS_NOTIFY_TGZ_URL:-${1:-}}"
SHA256="${SLS_MASS_NOTIFY_SHA256:-}"
TOKEN="${SLS_MASS_NOTIFY_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
LOG_FILE="${SLS_MASS_NOTIFY_INSTALL_LOG:-/tmp/slsmassnotifyserver-install.log}"
EXPECTED_TGZ_SHA256="0def77274d45beae009e09aeea45271baa50bd64637019b6a5fa2da34114b693"
DATA_DIR="/var/lib/asterisk/SLS_Mass_Notifications_Plugin"
CONFIG_FILE="$DATA_DIR/mass-notifications.config"
CONFIG_SNAPSHOT=""
CONFIG_HASH_BEFORE=""
CONFIG_HASH_EXPECTED=""
CONFIG_EXPECTED_SNAPSHOT=""
CONFIG_RECOVERY_SNAPSHOT=""
CONFIG_RECOVERY_HASH=""
PENDING_RECOVERY_SNAPSHOT=""
PENDING_RECOVERY_HASH=""
FRESH_CONFIG_INITIALIZED=0
FRESH_PHONE_CAPACITY=25
FRESH_DEPLOYMENT_PROFILE="${REQUESTED_DEPLOYMENT_PROFILE:-standard}"
PENDING_CONFIG_STATE=""
PENDING_CONFIG_PATH=""
PENDING_CONFIG_SNAPSHOT=""
PENDING_CONFIG_HASH=""
WORKER_LOCK_RESPONSE_FD=""
WORKER_COORDINATION_REQUIRED=0
declare -a WORKER_LEASE_FDS=()
SETTINGS_LOCK="$DATA_DIR/mass-notifications.config.lock"
STAGING_DIR=""
INSTALL_TEMP_ROOT="/tmp"
DOWNLOAD_DIR=""
MODULE_BACKUP_DIR=""
ROLLBACK_FAILED=0
ROLLBACK_ATTEMPTED=0
ROLLBACK_VERIFIED=0
MODULE_ACTIVATED=0
INSTALL_COMMITTED=0
HAD_EXISTING_MODULE=0
MODULE_WAS_ENABLED=0
# Zero-valued legacy flags alone do not establish a native absence observation.
INITIAL_NATIVE_MODULE_REGISTRY_STATE=unknown
APT_METADATA_REFRESHED=0
ASTERISK_PACKAGE_REPAIR_ATTEMPTS=""
REPAIR_ASTERISK_PACKAGES="${SLS_MASS_NOTIFY_REPAIR_ASTERISK_PACKAGES:-0}"
INSTALL_MAINTENANCE_LOCK_FD=""
FREEPBX_CONFIRMED=0
REQUESTED_SYSTEM_TIMEZONE="${SLS_MASS_NOTIFY_TIMEZONE:-}"
ORIGINAL_SYSTEM_TIMEZONE=""
SYSTEM_TIMEZONE_CHANGED=0
CONFIRMED_SYSTEM_TIMEZONE=""
# Regression tests source this installer so they can exercise its protected
# filesystem helpers.  Keep their fixture failure markers from creating or
# deleting real FreePBX Dashboard notifications on the host running the test.
INSTALL_NOTIFICATION_SIDE_EFFECTS=1
INSTALL_STAGE="initialization"
INSTALL_SOLUTION="Review /tmp/slsmassnotifyserver-install.log, correct the reported prerequisite, then run the same installer again."
INSTALL_FAILURE_FILE="$DATA_DIR/install-failure.json"
INSTALL_ERROR_CATEGORY="install_command_failed"
INSTALL_EXIT_CODE=1
PRIVILEGED_INSTALL_BOOTSTRAP=""
TRUST_TOOL=""
TRUST_ROOT="/var/lib/sls-mass-notify-trust"
INSTALL_BOOTSTRAP_DIR=""
OFFLINE_ASSET_DIR="$(dirname "$TGZ")"
WORKER_GUARD_TOOL=""
IDLE_TOOL=""
RECOVERY_TOOL=""
RECOVERY_DIR=""
STATIC_MUTATION_STARTED=0
UPGRADE_TRUST_DIR=""
AUTHENTICATED_INSTALLER_APPROVED=0
CAPACITY_STOCK_CACHE_PROOF_SHA256=""
LEGACY_PERMISSION_TOOL=""
FREEPBX_CHOWN_CONFIG="/etc/asterisk/freepbx_chown.conf"
INSTALL_TRANSACTION_ROOT="/var/lib/sls-mass-notify-installer"
INSTALL_TRANSACTION_DIR=""
TRANSACTION_TOOL=""
RECOVERY_REQUEST_MODE=0
RECOVERY_PROGRAM_DIR=""
RECOVERY_HISTORY_EVIDENCE=""
RECOVERY_HISTORY_LOSS_APPROVAL=""
SERVED_PHP_PROFILES=""

# A successful child exit does not turn an interrupted shell into a successful
# installation. Recovery is coordinated by the parent, before locks are released.
handle_install_signal() {
  trap '' TERM INT HUP
  log "Installation interrupted by $1; preserving evidence and restoring the approved previous state."
  terminate_install_children
  exit "$2"
}

terminate_install_children() {
  /usr/bin/python3 -I - "$$" "${WORKER_LOCK_PID:-}" <<'PYSIGNAL' || true
import os, signal, sys, time
parent = int(sys.argv[1]); protected = int(sys.argv[2] or 0)
def children(pid):
    try:
        return [int(item) for item in open('/proc/' + str(pid) + '/task/' + str(pid) + '/children').read().split()]
    except (OSError, ValueError): return []
def descendants(pid):
    result = []
    for child in children(pid):
        if child in (protected, os.getpid()): continue
        result.extend(descendants(child)); result.append(child)
    return result
owned = descendants(parent)
for pid in owned:
    try: os.kill(pid, signal.SIGTERM)
    except ProcessLookupError: pass
deadline = time.monotonic() + 2
while time.monotonic() < deadline and any(os.path.exists('/proc/' + str(pid)) for pid in owned): time.sleep(.05)
# Re-check ancestry: never kill a recycled PID or an unrelated PBX service.
remaining = set(descendants(parent))
for pid in owned:
    if pid in remaining:
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
PYSIGNAL
}

check_interrupted_installation() {
  /usr/bin/python3 -I - "$INSTALL_TRANSACTION_ROOT" <<'PYDISCOVER'
import json, math, os, pathlib, re, stat, sys, time
root = pathlib.Path(sys.argv[1])
FIELDS = {'RECOVERY_DIR', 'INSTALL_BOOTSTRAP_DIR', 'UPGRADE_TRUST_DIR',
          'CONFIG_SNAPSHOT', 'CONFIG_HASH_BEFORE', 'PENDING_CONFIG_STATE',
          'PENDING_CONFIG_PATH', 'PENDING_CONFIG_SNAPSHOT', 'PENDING_CONFIG_HASH',
          'MODULE_BACKUP_DIR', 'STAGING_DIR', 'HAD_EXISTING_MODULE',
          'MODULE_WAS_ENABLED', 'MODULE_ACTIVATED', 'STATIC_MUTATION_STARTED',
          'ORIGINAL_SYSTEM_TIMEZONE', 'SYSTEM_TIMEZONE_CHANGED'}
PHASES = {'preparing', 'prepared', 'mutating', 'recovering', 'recovery_failed',
          'committed', 'rolled_back', 'abandoned'}
STAGES = {'initialization', 'hardware admission', 'platform validation',
          'release download and validation', 'publisher and stock approval',
          'FreePBX ownership protection', 'legacy configuration and runtime permissions',
          'authenticated prerequisite validation', 'previous phone collector recovery',
          'notification worker coordination', 'configuration coordination',
          'dependency installation', 'timezone validation', 'protected runtime preparation',
          'module activation', 'runtime integration', 'post-install verification',
          'interrupted installation recovery'}
def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError('Duplicate transaction metadata member')
        value[key] = item
    return value
def finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise RuntimeError('Nonfinite transaction metadata number')
    return value
def invalid_constant(text):
    raise RuntimeError('Nonfinite transaction metadata number')
def legacy_sequence(parent):
    item = os.open('transaction-sequence', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(item)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in (0o600, 0o640, 0o644) or not 1 <= before.st_size <= 20):
            raise RuntimeError('Unsafe legacy installer sequence metadata; preserve it for review')
        raw = os.read(item, 21)
        after = os.fstat(item)
        named = os.stat('transaction-sequence', dir_fd=parent, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                    value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (identity(before) != identity(after) or identity(after) != identity(named)
                or len(raw) != before.st_size or not re.fullmatch(rb'(?:0|[1-9][0-9]{0,18})\n?', raw)
                or int(raw) > 2 ** 63 - 1):
            raise RuntimeError('Invalid legacy installer sequence metadata; preserve it for review')
    finally:
        os.close(item)
def initial_temporary(parent, name):
    staged = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(staged)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 65536):
            raise RuntimeError('Unsafe interrupted first journal; preserve it for review')
        raw = os.read(staged, 65537)
        after = os.fstat(staged); named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        def identity(info):
            return {'name': name, 'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
                    'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'nlink': info.st_nlink,
                    'size': info.st_size, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
        binding = identity(before)
        if len(raw) != before.st_size or binding != identity(after) or binding != identity(named):
            raise RuntimeError('Interrupted first journal changed; preserve it for review')
        return raw, binding if not raw else None
    finally: os.close(staged)
def validate_empty_marker(value, parent):
    binding = value.get('empty_preparation_temporary')
    if (set(value) != {'schema','directory','phase','created_at','updated_at','settings',
                       'empty_preparation','empty_preparation_temporary'}
            or value['phase'] != 'abandoned' or value['settings'] != {} or value['empty_preparation'] is not True
            or not isinstance(binding, dict) or not isinstance(binding.get('name'), str)
            or not re.fullmatch(r'\.new-[a-f0-9]{24}', binding['name'])
            or stat.S_IMODE(os.fstat(parent).st_mode) != 0o700
            or set(os.listdir(parent)) != {'transaction.json', binding['name']}):
        raise RuntimeError('Invalid unwritten preparation layout; preserve it for review')
    raw, actual = initial_temporary(parent, binding['name'])
    if (raw or actual is None or set(binding) != set(actual)
            or any(type(binding[key]) is not type(item) or binding[key] != item for key, item in actual.items())
            or set(os.listdir(parent)) != {'transaction.json', binding['name']}):
        raise RuntimeError('Original unwritten journal identity changed; preserve it for review')
if not root.exists() and not root.is_symlink(): raise SystemExit(0)
fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
try:
    for part in root.parts[1:]:
        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(fd); fd = child
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022: raise RuntimeError('Unsafe installer evidence directory')
    if os.fstat(fd).st_mode & 0o077: raise RuntimeError('Installer evidence directory must be root-only')
    names = os.listdir(fd)
    if len(names) > 100: raise RuntimeError('Installer evidence needs administrator archival')
    for name in names:
        if name == 'transaction-sequence':
            legacy_sequence(fd)
            continue
        if not re.fullmatch(r'transaction-[a-f0-9]{24}', name): raise RuntimeError('Unknown installer evidence directory')
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            info = os.fstat(child)
            if info.st_uid != 0 or info.st_mode & 0o077: raise RuntimeError('Unsafe transaction evidence')
            try:
                item = os.open('transaction.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=child)
            except FileNotFoundError:
                evidence = os.listdir(child)
                initial = None
                empty = None
                if len(evidence) == 1 and re.fullmatch(r'\.new-[a-f0-9]{24}', evidence[0]):
                    raw, empty = initial_temporary(child, evidence[0])
                    if set(os.listdir(child)) != set(evidence):
                        raise RuntimeError('Interrupted first journal layout changed; preserve it for review')
                    if raw:
                        initial = json.loads(raw, object_pairs_hook=unique_object,
                                             parse_float=finite_float, parse_constant=invalid_constant)
                    if raw and (type(initial) is not dict or set(initial) != {'schema','directory','phase','settings','created_at','updated_at'}
                            or type(initial['schema']) is not int or initial['schema'] != 1
                            or initial['directory'] != str(root/name) or initial['phase'] != 'preparing' or initial['settings'] != {}
                            or type(initial['created_at']) is not int or type(initial['updated_at']) is not int
                            or not 0 <= initial['created_at'] <= initial['updated_at'] <= 2 ** 63 - 1):
                        raise RuntimeError('Unknown interrupted first journal; preserve it for review')
                if stat.S_IMODE(info.st_mode) != 0o700 or evidence and initial is None and empty is None:
                    raise RuntimeError('Missing transaction metadata has unknown evidence; preserve it for review')
                created=initial['created_at'] if initial is not None else max(0,int(info.st_mtime))
                value={'schema':1,'directory':str(root/name),'phase':'preparing','settings':{},
                       'created_at':created,'updated_at':created,'empty_preparation':True}
                if empty is not None: value['empty_preparation_temporary'] = empty
            else:
                with os.fdopen(item, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 65536: raise RuntimeError('Unsafe transaction journal')
                    value = json.loads(stream.read(65537), object_pairs_hook=unique_object,
                                       parse_float=finite_float, parse_constant=invalid_constant)
            if (type(value) is not dict or type(value.get('schema')) is not int or value.get('schema') != 1
                    or type(value.get('directory')) is not str or value.get('directory') != str(root / name)
                    or value.get('phase') not in PHASES
                    or type(value.get('created_at')) is not int or value.get('created_at') < 0
                    or type(value.get('updated_at')) is not int or value.get('updated_at') < value.get('created_at')
                    or value.get('updated_at') > 2 ** 63 - 1
                    or type(value.get('settings')) is not dict
                    or set(value.get('settings', {})) - FIELDS):
                raise RuntimeError('Invalid transaction journal')
            for key, setting in value['settings'].items():
                if (type(setting) is not str or len(setting) > 4096
                        or any(ord(character) < 32 or ord(character) == 127 for character in setting)):
                    raise RuntimeError('Invalid transaction journal setting: ' + key)
            if (('stage' in value or 'stage_at' in value)
                    and (value.get('stage') not in STAGES or type(value.get('stage_at')) is not int
                         or not value['created_at'] <= value['stage_at'] <= value['updated_at'])):
                raise RuntimeError('Invalid transaction journal stage')
            if value.get('phase') == 'preparing':
                settings=value.get('settings')
                if not isinstance(settings,dict) or any(settings.get(key,'0') not in ('','0') for key in ('STATIC_MUTATION_STARTED','MODULE_ACTIVATED','SYSTEM_TIMEZONE_CHANGED')):
                    raise RuntimeError('Preparation record claims a live mutation; preserve it for administrator review')
                value['phase']='abandoned';value['updated_at']=max(int(time.time()),value.get('created_at',0),value.get('updated_at',0))
                temporary='.new-'+os.urandom(12).hex()
                record=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=child)
                try:
                    with os.fdopen(record,'wb') as output:
                        output.write((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode())
                        output.flush();os.fsync(output.fileno())
                    os.replace(temporary,'transaction.json',src_dir_fd=child,dst_dir_fd=child);os.fsync(child)
                finally:
                    try:os.unlink(temporary,dir_fd=child)
                    except FileNotFoundError:pass
                print('Archived incomplete preparation; no SLL mutation had started. Evidence: '+str(root/name))
            if 'empty_preparation_temporary' in value:
                validate_empty_marker(value, child)
            if value.get('phase') not in ('committed', 'rolled_back', 'abandoned'):
                print('An interrupted SLL installation requires recovery before retrying. Evidence: ' + str(root / name), file=sys.stderr)
                print('Run the publisher-authenticated installer with --recover ' + str(root / name) + '; preserve this directory.', file=sys.stderr)
                raise SystemExit(3)
        finally: os.close(child)
finally: os.close(fd)
PYDISCOVER
}

preflight_profile_identity() {
  /usr/bin/python3 -I - <<'PYPROFILE'
from pathlib import Path
import re, xml.etree.ElementTree as ET
release=Path('/etc/os-release').read_text()
fields=dict(re.findall(r'^([A-Z_]+)=["\']?([^\n"\']*)',release,re.M))
if fields.get('ID')!='debian' or fields.get('VERSION_ID')!='12':
    raise SystemExit('This release qualifies FreePBX 17 on Debian 12. A different operating system requires an explicit tested platform adapter; no package repair was started.')
path=Path('/var/www/html/admin/modules/framework/module.xml')
if path.is_symlink() or not path.is_file() or path.stat().st_size>1048576:
    raise SystemExit('A bounded standard-path Framework module identity is required before package repair.')
body=path.read_bytes()
if b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper(): raise SystemExit('Unsupported Framework XML declarations.')
xml=ET.fromstring(body)
if xml.findtext('rawname')!='framework' or not xml.findtext('version','').startswith('17.'):
    raise SystemExit('The installer requires FreePBX Framework 17 before package repair.')
PYPROFILE
}

persist_install_transaction() {
  [ -n "$INSTALL_TRANSACTION_DIR" ] || return 0
  local phase="$1" field
  local -a completion_options=()
  if [ "$phase" = rolled_back ] && { [ "$RECOVERY_REQUEST_MODE" -eq 1 ] \
      || { [ -n "$RECOVERY_DIR" ] && [ -f "$RECOVERY_DIR/configuration-mfa-recovery.json" ]; }; }; then
    # Publish terminal state and its forensic-retention binding together. A
    # crash must never expose a completed manual recovery without its archive.
    completion_options+=(--preserve-recovery-evidence)
  fi
  local -a fields=(RECOVERY_DIR INSTALL_BOOTSTRAP_DIR UPGRADE_TRUST_DIR CONFIG_SNAPSHOT CONFIG_HASH_BEFORE PENDING_CONFIG_STATE PENDING_CONFIG_PATH PENDING_CONFIG_SNAPSHOT PENDING_CONFIG_HASH MODULE_BACKUP_DIR STAGING_DIR HAD_EXISTING_MODULE MODULE_WAS_ENABLED MODULE_ACTIVATED STATIC_MUTATION_STARTED ORIGINAL_SYSTEM_TIMEZONE SYSTEM_TIMEZONE_CHANGED)
  local -a values=()
  for field in "${fields[@]}"; do values+=("$field" "${!field}"); done
  /usr/bin/python3 -I - "${values[@]}" <<'PYJOURNAL' | /usr/bin/python3 -I "$TRANSACTION_TOOL" --root "$INSTALL_TRANSACTION_ROOT" --transaction "$INSTALL_TRANSACTION_DIR" --phase "$phase" --stage "$INSTALL_STAGE" "${completion_options[@]}" update
import json, sys
print(json.dumps(dict(zip(sys.argv[1::2], sys.argv[2::2]))))
PYJOURNAL
}

sync_private_installer_tree() {
  /usr/bin/timeout 60 /usr/bin/python3 -I - "$@" <<'PYSYNCPRIVATETREE'
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
PYSYNCPRIVATETREE
}

begin_install_transaction() {
  TRANSACTION_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_install_transaction.py"
  INSTALL_TRANSACTION_DIR="$(/usr/bin/python3 -I "$TRANSACTION_TOOL" --root "$INSTALL_TRANSACTION_ROOT" begin)" || return 1
  # Retain authenticated executable sources, approvals and settings across a
  # reboot. Candidate downloads and general extraction workspace remain temporary.
  copy_private_release_asset "$INSTALLER_SOURCE_PATH" "$INSTALL_TRANSACTION_DIR/installer.sh" 2097152 || return 1
  copy_private_release_asset "$TGZ" "$INSTALL_TRANSACTION_DIR/package.tgz" 54525952 || return 1
  copy_private_release_asset "$DOWNLOAD_DIR/release-manifest.json" "$INSTALL_TRANSACTION_DIR/release-manifest.json" 16384 || return 1
  copy_private_release_asset "$DOWNLOAD_DIR/release-manifest.sig" "$INSTALL_TRANSACTION_DIR/release-manifest.sig" 64 || return 1
  mv -- "$INSTALL_BOOTSTRAP_DIR" "$INSTALL_TRANSACTION_DIR/bootstrap" || return 1
  INSTALL_BOOTSTRAP_DIR="$INSTALL_TRANSACTION_DIR/bootstrap"
  TRANSACTION_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_install_transaction.py"
  WORKER_GUARD_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_install_guard.py"; IDLE_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_install_idle.py"
  RECOVERY_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_installer_recovery.py"; TRUST_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_module_trust.py"
  PRIVILEGED_INSTALL_BOOTSTRAP="$INSTALL_BOOTSTRAP_DIR/sls_privileged_install.py"
  LEGACY_PERMISSION_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_legacy_permissions.py"
  mv -- "$UPGRADE_TRUST_DIR" "$INSTALL_TRANSACTION_DIR/approval" || return 1
  UPGRADE_TRUST_DIR="$INSTALL_TRANSACTION_DIR/approval"
  retain_configuration_snapshots || return 1
  sync_private_installer_tree "$INSTALL_TRANSACTION_DIR" || return 1
  persist_install_transaction prepared || return 1
  log "Persistent installer recovery evidence: $INSTALL_TRANSACTION_DIR"
}

retain_configuration_snapshots() {
  local original_config="$CONFIG_SNAPSHOT" original_pending="$PENDING_CONFIG_SNAPSHOT"
  if [ -n "$CONFIG_SNAPSHOT" ] && [ "$CONFIG_SNAPSHOT" != "$INSTALL_TRANSACTION_DIR/config.snapshot" ]; then
    copy_private_release_asset "$CONFIG_SNAPSHOT" "$INSTALL_TRANSACTION_DIR/config.snapshot" 16777216 || return 1
    CONFIG_SNAPSHOT="$INSTALL_TRANSACTION_DIR/config.snapshot"
  fi
  if [ -n "$PENDING_CONFIG_SNAPSHOT" ] && [ "$PENDING_CONFIG_SNAPSHOT" != "$INSTALL_TRANSACTION_DIR/pending.snapshot" ]; then
    copy_private_release_asset "$PENDING_CONFIG_SNAPSHOT" "$INSTALL_TRANSACTION_DIR/pending.snapshot" 16777216 || return 1
    PENDING_CONFIG_SNAPSHOT="$INSTALL_TRANSACTION_DIR/pending.snapshot"
  fi
  seal_install_recovery_inputs || return 1
  # Keep the original, already-flushed temporary until both retained contents
  # and their directory entries have reached durable storage.
  if [ -n "$original_config" ] && [ "$original_config" != "$CONFIG_SNAPSHOT" ]; then rm -- "$original_config" || return 1; fi
  if [ -n "$original_pending" ] && [ "$original_pending" != "$PENDING_CONFIG_SNAPSHOT" ]; then rm -- "$original_pending" || return 1; fi
}

seal_install_recovery_inputs() {
  /usr/bin/python3 -I - "$TRANSACTION_TOOL" "$INSTALL_TRANSACTION_DIR" "$RECOVERY_DIR" \
      "$CONFIG_SNAPSHOT" "$PENDING_CONFIG_SNAPSHOT" <<'PYSYNCRECOVERY'
import pathlib, sys, types
path = pathlib.Path(sys.argv[1]); journal = types.ModuleType('durable_recovery_inputs'); journal.__file__ = str(path)
exec(compile(path.read_bytes(), str(path), 'exec'), journal.__dict__)
journal.sync_recovery_inputs(*sys.argv[2:])
PYSYNCRECOVERY
}

admit_recovery_carrier_capacity() {
  /usr/bin/python3 -I - "$@" <<'PYRECOVERYCARRIERCAPACITY'
import hashlib, io, json, os, stat, sys, tarfile
from pathlib import Path, PurePosixPath

BOOTSTRAP = ('sls_module_trust.py', 'sls_release_trust.py', 'sls_privileged_install.py',
    'sls_installer_recovery.py', 'sls_install_transaction.py', 'sls_install_idle.py',
    'sls_install_guard.py', 'sls_audio_state.py', 'sls_config_crypto.py', 'sls_upgrade_trust.py',
    'sls_legacy_permissions.py', 'freepbx-mirror-signing.pub')
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def stamp(info):
    return tuple(getattr(info, 'st_' + key) for key in
                 ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns'))

def directory(path, private=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path.resolve() != path:
        raise ValueError('Recovery carrier requires canonical protected directories')
    fd = os.open('/', DIR)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIR, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise ValueError('Recovery carrier directory has an unauthorized writer')
        if private and stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
            raise ValueError('Recovery carrier target and bootstrap must be root-private')
        return os.dup(fd)
    finally:
        os.close(fd)

def read(path, maximum, mode):
    path = Path(path); parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != mode or not 0 < before.st_size <= maximum):
                raise ValueError('Recovery carrier input is incomplete or unsafe')
            chunks = []; count = 0
            while True:
                block = os.read(fd, min(65536, maximum + 1 - count))
                if not block:
                    break
                chunks.append(block); count += len(block)
                if count > maximum:
                    raise ValueError('Recovery carrier input exceeds its bound')
            body = b''.join(chunks)
            if (len(body) != before.st_size or stamp(before) != stamp(os.fstat(fd))
                    or stamp(before) != stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False))):
                raise ValueError('Recovery carrier input changed during measurement')
            return body, stamp(before)
        finally:
            os.close(fd)
    finally:
        os.close(parent)

def unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Recovery carrier manifest has duplicate fields')
        result[key] = value
    return result

def bootstrap_sources(package):
    names = set(); found = {}; total = 0
    prefix = 'slsmassnotifyserver/bin/sls_mass_notify/'
    with tarfile.open(fileobj=io.BytesIO(package), mode='r:gz') as archive:
        for member in archive:
            name = member.name.rstrip('/'); path = PurePosixPath(name)
            if (len(names) >= 5000 or name in names or str(path) != name or path.is_absolute()
                    or '..' in path.parts or not path.parts or path.parts[0] != 'slsmassnotifyserver'
                    or not (member.isdir() or member.isreg())):
                raise ValueError('Recovery carrier archive shape is unsafe')
            names.add(name)
            if member.isreg():
                total += member.size
                if member.size < 0 or total > 50 * 1024 ** 2:
                    raise ValueError('Recovery carrier module exceeds its bound')
            if name.startswith(prefix) and name[len(prefix):] in BOOTSTRAP:
                if not member.isreg() or not 0 < member.size <= 2 * 1024 ** 2:
                    raise ValueError('Recovery bootstrap source is incomplete or unsafe')
                with archive.extractfile(member) as source:
                    body = source.read(2 * 1024 ** 2 + 1)
                if len(body) != member.size:
                    raise ValueError('Recovery bootstrap source changed')
                found[name[len(prefix):]] = body
    if set(found) != set(BOOTSTRAP):
        raise ValueError('Recovery bootstrap source is incomplete')
    return found

def measure_recovery_carrier(target, installer, package, manifest, signature, bootstrap):
    if os.geteuid() != 0:
        raise ValueError('Recovery carrier admission requires root')
    target = Path(target); bootstrap = Path(bootstrap)
    target_fd = directory(target, private=True); bootstrap_fd = None
    try:
        original = stamp(os.fstat(target_fd))
        bootstrap_fd = directory(bootstrap, private=True)
        if set(os.listdir(bootstrap_fd)) != set(BOOTSTRAP):
            raise ValueError('Recovery bootstrap membership differs')
        bodies = {}; identities = {}
        for path, maximum in ((installer, 2 * 1024 ** 2), (package, 52 * 1024 ** 2),
                              (manifest, 16384), (signature, 64)):
            body, identity = read(path, maximum, 0o600)
            bodies[str(path)] = body; identities[str(path)] = identity
        value = json.loads(bodies[str(manifest)], object_pairs_hook=unique)
        digest = lambda body: hashlib.sha256(body).hexdigest()
        if (not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 1
                or value.get('installer_sha256') != digest(bodies[str(installer)])
                or value.get('package_sha256') != digest(bodies[str(package)])
                or len(bodies[str(signature)]) != 64):
            raise ValueError('Recovery inputs differ from the authenticated manifest')
        expected = bootstrap_sources(bodies[str(package)])
        for name in BOOTSTRAP:
            path = bootstrap / name
            body, identity = read(path, 2 * 1024 ** 2, 0o600 if name.endswith('.pub') else 0o700)
            if body != expected[name]:
                raise ValueError('Recovery bootstrap differs from the authenticated package')
            bodies[str(path)] = body; identities[str(path)] = identity
        usage = os.fstatvfs(target_fd); unit = max(4096, usage.f_frsize)
        # Four release files, twelve helpers, two directories and four metadata
        # slots. Charge the actual corrected carrier, not a future release cap.
        required_inodes = len(bodies) + 2 + 4
        required = sum((len(body) + unit - 1) // unit * unit for body in bodies.values()) + required_inodes * unit
        available = usage.f_bavail * usage.f_frsize
        inodes = usage.f_favail if usage.f_files > 0 else None
        if usage.f_flag & os.ST_RDONLY:
            raise ValueError('Recovery carrier filesystem is read-only; preserve the existing transaction')
        if available < required:
            raise ValueError('Recovery carrier needs %d free bytes; %d are available. Preserve the existing transaction.' % (required, available))
        if inodes is not None and inodes < required_inodes:
            raise ValueError('Recovery carrier needs %d free inodes; %d are available. Preserve the existing transaction.' % (required_inodes, inodes))
        if (original != stamp(os.fstat(target_fd)) or original != stamp(target.lstat())
                or set(os.listdir(bootstrap_fd)) != set(BOOTSTRAP)
                or any(identity != stamp(Path(path).lstat()) for path, identity in identities.items())):
            raise ValueError('Recovery carrier inputs or target changed during admission')
        return {'required_free_bytes': required, 'available_bytes': available,
                'required_inodes': required_inodes, 'available_inodes': inodes,
                'scope': 'actual authenticated corrected recovery carrier only'}
    finally:
        if bootstrap_fd is not None:
            os.close(bootstrap_fd)
        os.close(target_fd)

if __name__ == '__main__':
    try:
        print(json.dumps(measure_recovery_carrier(*sys.argv[1:]), sort_keys=True))
    except (OSError, ValueError, tarfile.TarError) as error:
        print('Corrected recovery carrier admission failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
PYRECOVERYCARRIERCAPACITY
}

prepare_recovery_carrier() {
  local requested="$1" carrier
  local DOWNLOAD_DIR="" STAGING_DIR="" INSTALL_BOOTSTRAP_DIR="" TGZ="$TGZ"
  # A corrected signed installer may repair earlier recovery logic. Authenticate its
  # own package and installer before loading helpers; retain both generations
  # separately so the original approval evidence never changes authority.
  download_tgz || return 1
  verify_tgz || return 1
  STAGING_DIR="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-recovery-stage.XXXXXX")" || return 1
  chmod 0700 "$STAGING_DIR" || return 1
  tar -xzf "$TGZ" -C "$STAGING_DIR" || return 1
  prepare_installer_bootstrap || return 1
  # Keep the running installer bytes private and match them to the already
  # authenticated manifest before measuring or changing the old transaction.
  copy_private_release_asset "$INSTALLER_SOURCE_PATH" "$DOWNLOAD_DIR/recovery-installer.sh" 2097152 || return 1
  admit_recovery_carrier_capacity "$requested" "$DOWNLOAD_DIR/recovery-installer.sh" "$TGZ" \
    "$DOWNLOAD_DIR/release-manifest.json" "$DOWNLOAD_DIR/release-manifest.sig" "$INSTALL_BOOTSTRAP_DIR" || {
    log 'Corrected recovery inputs could not be admitted on the transaction filesystem. Preserve the original transaction and review the reported space, inode or protected-input check.'
    return 1
  }
  carrier="$(mktemp -d "$requested/recovery-carrier.XXXXXX")" || return 1
  chmod 0700 "$carrier" || return 1
  copy_private_release_asset "$DOWNLOAD_DIR/recovery-installer.sh" "$carrier/installer.sh" 2097152 || return 1
  copy_private_release_asset "$TGZ" "$carrier/package.tgz" 54525952 || return 1
  copy_private_release_asset "$DOWNLOAD_DIR/release-manifest.json" "$carrier/release-manifest.json" 16384 || return 1
  copy_private_release_asset "$DOWNLOAD_DIR/release-manifest.sig" "$carrier/release-manifest.sig" 64 || return 1
  mv -- "$INSTALL_BOOTSTRAP_DIR" "$carrier/bootstrap" || return 1
  sync_private_installer_tree "$carrier" || return 1
  RECOVERY_PROGRAM_DIR="$carrier/bootstrap"
  rm -rf -- "$STAGING_DIR" "$DOWNLOAD_DIR" || return 1
  log "Authenticated recovery carrier retained: $carrier"
}

preflight_recovery_history() {
  # Discover an impossible history comparison before restoring static files
  # again. A report is evidence, never permission to accept unexplained loss.
  local report review required
  local -a inspection=(--data "$DATA_DIR" review-history --baseline "$RECOVERY_DIR/idle-before.json" --repair-collector)
  local -a journal=(/usr/bin/python3 -I "$TRANSACTION_TOOL" --root "$INSTALL_TRANSACTION_ROOT" --transaction "$INSTALL_TRANSACTION_DIR")
  if [ -n "$RECOVERY_HISTORY_EVIDENCE" ]; then inspection+=(--history-evidence "$RECOVERY_HISTORY_EVIDENCE"); fi
  report="$(/usr/bin/python3 -I "$IDLE_TOOL" "${inspection[@]}")" || return 1
  if [ -n "$REQUESTED_HISTORY_LOSS_APPROVAL" ]; then
    printf '%s\n' "$report" | "${journal[@]}" approve-history-loss \
      --confirmation "$REQUESTED_HISTORY_LOSS_APPROVAL" --operator "$REQUESTED_HISTORY_LOSS_OPERATOR" \
      --reason "$REQUESTED_HISTORY_LOSS_REASON" || return 1
  fi
  if [ -e "$INSTALL_TRANSACTION_DIR/history-loss-approval.json" ] || [ -L "$INSTALL_TRANSACTION_DIR/history-loss-approval.json" ]; then
    printf '%s\n' "$report" | "${journal[@]}" history-approval || return 1
    RECOVERY_HISTORY_LOSS_APPROVAL="$INSTALL_TRANSACTION_DIR/history-loss-approval.json"
    log 'The exact missing history has an explicit administrator acceptance. It has not been verified expired. Original recovery evidence will be retained.'
    return 0
  fi
  review="$(printf '%s\n' "$report" | "${journal[@]}" history-review)" || return 1
  printf '%s\n' "$review"
  required="$(/usr/bin/python3 -I -c 'import json,sys; value=json.load(sys.stdin); required=value.get("review_required"); assert type(required) is bool; print(int(required))' <<<"$review")" || return 1
  if [ "$required" -eq 1 ]; then
    log "Recovery requires administrator history review: $INSTALL_TRANSACTION_DIR/history-loss-review.json. Seek matching complete pre-upgrade ledger evidence first; supply it with --history-evidence."
    log 'If matching evidence cannot be found, a separate --approve-history-loss REVIEW_SHA256 command with --history-loss-operator and --history-loss-reason records acceptance of only the reviewed unknown loss. It cannot waive changed records, known nonexpired loss or voicemail dependencies.'
    [ "$REQUESTED_HISTORY_REVIEW" -eq 1 ] || return 4
  fi
}

recover_interrupted_installation() {
  local requested="$1" field i
  acquire_update_coordination || return 1
  acquire_maintenance_coordination || return 1
  # Verify saved programs before executing any of them. The durable journal is
  # a locator, not a new signing authority or a baseline of live installed files.
  /usr/bin/python3 -I - "$INSTALL_TRANSACTION_ROOT" "$requested" <<'PYRECOVERYAUTH' || return 1
import hashlib, json, os, pathlib, re, stat, subprocess, sys, tarfile, tempfile, types
root, path = map(pathlib.Path, sys.argv[1:])
if path.parent != root or not re.fullmatch(r'transaction-[0-9a-f]{24}', path.name): raise SystemExit('Use the exact protected transaction directory printed in the installer log.')
def read(item, limit):
    for parent in reversed(item.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise RuntimeError('Unprotected recovery evidence parent')
    fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > limit: raise RuntimeError('Unsafe recovery evidence')
        body = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if len(body) != info.st_size or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise RuntimeError('Recovery evidence changed')
        return body
manifest_body = read(path / 'release-manifest.json', 16384)
signature = read(path / 'release-manifest.sig', 64)
verifier = pathlib.Path('/usr/local/bin/sls_mass_notify/sls_release_trust.py')
if verifier.exists() or verifier.is_symlink():
    module = types.ModuleType('protected_recovery_publisher'); module.__file__ = str(verifier)
    exec(compile(read(verifier, 262144), str(verifier), 'exec'), module.__dict__)
    manifest = module.authenticate_manifest(manifest_body, signature)
else:
    if any(item.exists() or item.is_symlink() for item in
           (pathlib.Path('/var/lib/sls-mass-notify-trust') / name for name in ('publisher-trust.json', 'release-trust.initialized'))):
        raise RuntimeError('Restore the protected publisher verifier before recovery')
    with tempfile.TemporaryDirectory(prefix='sls-recovery-signature-') as name:
        scratch = pathlib.Path(name)
        (scratch / 'pub').write_bytes(b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=\n-----END PUBLIC KEY-----\n')
        (scratch / 'body').write_bytes(manifest_body); (scratch / 'sig').write_bytes(signature)
        subprocess.run(['/usr/bin/openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',str(scratch / 'pub'),'-in',str(scratch / 'body'),'-sigfile',str(scratch / 'sig')], check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    manifest = json.loads(manifest_body)
for name, field, limit in (('installer.sh','installer_sha256',2097152),('package.tgz','package_sha256',54525952)):
    if hashlib.sha256(read(path / name, limit)).hexdigest() != manifest.get(field): raise RuntimeError('Recovery bytes do not match the signed release: ' + name)
with tarfile.open(path / 'package.tgz', 'r:gz') as archive:
    for helper in (path / 'bootstrap').iterdir():
        member = archive.getmember('slsmassnotifyserver/bin/sls_mass_notify/' + helper.name)
        if not member.isfile() or member.size > 2097152: raise RuntimeError('Unsafe authenticated recovery helper')
        if read(helper,2097152) != archive.extractfile(member).read(2097153): raise RuntimeError('Recovery helper does not match its signed package')
transaction = json.loads(read(path / 'transaction.json', 65536))
if (not isinstance(transaction, dict) or transaction.get('schema') != 1
        or transaction.get('directory') != str(path)
        or transaction.get('phase') not in ('prepared', 'mutating', 'recovering', 'recovery_failed')):
    raise RuntimeError('Only an unfinished installation can supply operational recovery settings; completed evidence cannot be recovered again')
print('Recovery programs authenticated. No live hashes were approved.')
PYRECOVERYAUTH
  if ! cmp -s -- "$INSTALLER_SOURCE_PATH" "$requested/installer.sh"; then
    prepare_recovery_carrier "$requested" || return 1
  else
    RECOVERY_PROGRAM_DIR="$requested/bootstrap"
  fi
  INSTALL_TRANSACTION_DIR="$requested"
  RECOVERY_REQUEST_MODE=1
  TRANSACTION_TOOL="$RECOVERY_PROGRAM_DIR/sls_install_transaction.py"
  local -a fields=(RECOVERY_DIR INSTALL_BOOTSTRAP_DIR UPGRADE_TRUST_DIR CONFIG_SNAPSHOT CONFIG_HASH_BEFORE PENDING_CONFIG_STATE PENDING_CONFIG_PATH PENDING_CONFIG_SNAPSHOT PENDING_CONFIG_HASH MODULE_BACKUP_DIR STAGING_DIR HAD_EXISTING_MODULE MODULE_WAS_ENABLED MODULE_ACTIVATED STATIC_MUTATION_STARTED ORIGINAL_SYSTEM_TIMEZONE SYSTEM_TIMEZONE_CHANGED)
  local -a values=()
  local recovered_values
  recovered_values="$(/usr/bin/python3 -I "$TRANSACTION_TOOL" --root "$INSTALL_TRANSACTION_ROOT" --transaction "$requested" values)" || return 1
  mapfile -t values <<<"$recovered_values"
  [ "${#values[@]}" -eq "${#fields[@]}" ] || { log 'The recovery settings are incomplete; evidence remains protected.'; return 1; }
  for i in "${!fields[@]}"; do printf -v "${fields[$i]}" '%s' "${values[$i]}"; done
  RECOVERY_TOOL="$RECOVERY_PROGRAM_DIR/sls_installer_recovery.py"; IDLE_TOOL="$RECOVERY_PROGRAM_DIR/sls_install_idle.py"
  WORKER_GUARD_TOOL="$RECOVERY_PROGRAM_DIR/sls_install_guard.py"
  LEGACY_PERMISSION_TOOL="$RECOVERY_PROGRAM_DIR/sls_legacy_permissions.py"
  PRIVILEGED_INSTALL_BOOTSTRAP="$RECOVERY_PROGRAM_DIR/sls_privileged_install.py"
  TRUST_TOOL="$RECOVERY_PROGRAM_DIR/sls_module_trust.py"
  INSTALL_LOG_FD=""; open_root_owned_file INSTALL_LOG_FD "$LOG_FILE" log || return 1
  INSTALL_LOG_OUTPUT="/proc/${BASHPID}/fd/$INSTALL_LOG_FD"
  # Signed recovery programs and their retained approvals were authenticated
  # above. Tighten the same recognized legacy metadata before acquiring a
  # guard that deliberately rejects permissive old modes.
  if [ "$REQUESTED_HISTORY_REVIEW" -eq 0 ]; then
    run_logged /usr/bin/python3 -I "$LEGACY_PERMISSION_TOOL" --data "$DATA_DIR" \
      --approval "$UPGRADE_TRUST_DIR/previous-root-approval.json" repair || return 1
  fi
  acquire_worker_coordination || return 1
  acquire_settings_coordination || { release_worker_coordination; return 1; }
  if [ -n "$REQUESTED_HISTORY_EVIDENCE" ]; then
    /usr/bin/python3 -I "$IDLE_TOOL" retain-history-evidence \
      --baseline "$RECOVERY_DIR/idle-before.json" --history-evidence "$REQUESTED_HISTORY_EVIDENCE" \
      --retained-history-evidence "$RECOVERY_DIR/history-evidence.json" || { release_worker_coordination; return 1; }
  fi
  if [ -e "$RECOVERY_DIR/history-evidence.json" ] || [ -L "$RECOVERY_DIR/history-evidence.json" ]; then
    RECOVERY_HISTORY_EVIDENCE="$RECOVERY_DIR/history-evidence.json"
  fi
  # A preparation interrupted before the operational snapshot has no history
  # baseline to adjudicate; its bounded metadata-only recovery is unchanged.
  if [ "$STATIC_MUTATION_STARTED" -eq 1 ]; then
    # Old collectors do not honor the newer retention lease. Preserve only
    # current complete rows which still match the original hashes, so their
    # later legitimate expiry has evidence. Missing rows remain unexplained.
    /usr/bin/python3 -I "$IDLE_TOOL" --data "$DATA_DIR" retain-current-history-evidence \
      --baseline "$RECOVERY_DIR/idle-before.json" \
      --retained-history-evidence "$RECOVERY_DIR/history-evidence.json" || { release_worker_coordination; return 1; }
    RECOVERY_HISTORY_EVIDENCE="$RECOVERY_DIR/history-evidence.json"
    local history_status=0
    preflight_recovery_history || history_status=$?
    if [ "$history_status" -ne 0 ] || [ "$REQUESTED_HISTORY_REVIEW" -eq 1 ]; then
      release_worker_coordination
      return "$history_status"
    fi
  elif [ "$REQUESTED_HISTORY_REVIEW" -eq 1 ] || [ -n "$REQUESTED_HISTORY_LOSS_APPROVAL" ]; then
    log 'This transaction stopped before its operational history snapshot; no history-loss acceptance is applicable. Run ordinary authenticated recovery.'
    release_worker_coordination
    return 2
  fi
  set_install_stage 'interrupted installation recovery' 'Preserve persistent transaction evidence and correct the specific failed restoration check before retrying recovery.'
  trap guard_config_on_exit EXIT
  trap 'handle_install_signal TERM 143' TERM
  trap 'handle_install_signal INT 130' INT
  trap 'handle_install_signal HUP 129' HUP
  # Reuse the original approved restoration, configuration and verification
  # sequence. An uncommitted static transaction always rolls back on EXIT.
  exit 1
}

# PHP/FreePBX code is maintained by the web account. It must never become a
# root program merely because this installer is root. Privileged operations
# use the authenticated fixed-operation helper below, not a PHP module hook.
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

sls_as_asterisk() { sls_runtime_account bounded "$@"; }
sls_bounded_as_asterisk() { sls_runtime_account bounded "$@"; }
sls_supervised_as_asterisk() { sls_runtime_account supervised "$@"; }

sls_runtime_account() {
  local mode="$1"; shift
  case "$mode" in bounded|supervised) ;; *) return 64 ;; esac
  local uid gid runtime_input_name
  local -a child_environment=(
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    'HOME=/var/lib/asterisk' 'USER=asterisk' 'LOGNAME=asterisk'
    'LANG=C.UTF-8' 'LC_ALL=C.UTF-8'
  )
  uid="$(id -u asterisk 2>/dev/null)" || { log 'The asterisk service account is missing.'; return 1; }
  [[ "$uid" =~ ^[0-9]+$ ]] && [ "$uid" -ne 0 ] || { log 'The asterisk service account must have a nonzero UID.'; return 1; }
  gid="$(id -g asterisk 2>/dev/null)" || { log 'The asterisk primary group is unavailable.'; return 1; }
  [[ "$gid" =~ ^[0-9]+$ ]] && [ "$gid" -ne 0 ] || { log 'The asterisk service account must have a nonzero primary GID.'; return 1; }
  for runtime_input_name in \
    CONFIG_PATH SLS_CONFIG_CRYPTO_PHP SLS_INIT_DEPLOYMENT_PROFILE SLS_INIT_PHONE_CAPACITY \
    SLS_MASS_NOTIFY_MODULE SLS_NATIVE_INSTALL_ACTION SLS_NATIVE_INSTALL_MODULE \
    SLS_NATIVE_REGISTRY_MODULE SLS_RECOVERY_AMI_NAMES \
    SLS_MASS_NOTIFY_DEFER_SIGNING SLS_MASS_NOTIFY_PRESERVE_PENDING \
    SLS_LOCAL_WEB_VHOST_DUMP SLS_LOCAL_WEB_CONFIG_DUMP; do
    if [[ -v "$runtime_input_name" ]]; then
      child_environment+=("$runtime_input_name=${!runtime_input_name}")
    fi
  done
  (
    cd / || return 1
    # Clean both the privilege-transition process and its final child. PAM or
    # runuser defaults cannot reintroduce caller credentials or change the
    # fixed runtime environment. Approved explicit env arguments follow this.
    local -a native_deadline=()
    if [ "$mode" = bounded ]; then native_deadline=(/usr/bin/timeout --signal=TERM --kill-after=5 1200); fi
    local -a native_operation=("${native_deadline[@]}" "$@")
    # Supervised short probes retain their declared timeout and kill grace.
    [ "${native_operation[0]:-}" = /usr/bin/timeout ] && \
      [ "${native_operation[1]:-}" = --signal=TERM ] && \
      [[ "${native_operation[2]:-}" = --kill-after=* ]] || return 64
    run_without_install_maintenance_lock sls_bounded_native_command \
      "${native_operation[3]}" "${native_operation[2]#--kill-after=}" \
      /usr/bin/env -i "${child_environment[@]}" /usr/sbin/runuser -u asterisk -- \
      /usr/bin/env -i "${child_environment[@]}" "${native_operation[@]}"
  )
}

php() { sls_bounded_as_asterisk /usr/bin/php "$@"; }

asterisk() { sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 20 /usr/sbin/asterisk "$@"; }
soxi() { sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 10 /usr/bin/soxi "$@"; }
identify() { sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 10 /usr/bin/identify "$@"; }

fwconsole() {
  case "${1:-}" in
    chown|start|stop|restart)
      log "Root-dependent fwconsole action '$1' is not permitted inside this installer. Use the fixed protected service/permission phases."
      return 1 ;;
  esac
  sls_bounded_as_asterisk /usr/sbin/fwconsole "$@"
}

protected_install_phase() {
  [ -n "$PRIVILEGED_INSTALL_BOOTSTRAP" ] && [ -f "$PRIVILEGED_INSTALL_BOOTSTRAP" ] || {
    log 'The authenticated privileged installer has not been prepared. No root module hook will be used as a fallback.'
    return 1
  }
  local -a dependency_options=()
  if [ "${1:-}" = dependencies ]; then
    [ -z "${SLS_MASS_NOTIFY_OFFLINE_ASSETS:-}" ] || dependency_options+=(--offline-assets "$SLS_MASS_NOTIFY_OFFLINE_ASSETS")
    [ -z "$REQUESTED_DEPLOYMENT_PROFILE" ] || dependency_options+=(--resource-profile "$REQUESTED_DEPLOYMENT_PROFILE")
  fi
  [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination || return 1
  run_logged /usr/bin/python3 -I "$PRIVILEGED_INSTALL_BOOTSTRAP" --trust-root "$TRUST_ROOT" "$@" "${dependency_options[@]}" || return 1
  [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination
}

initialize_configuration_keyring() {
  /usr/bin/python3 -I "$INSTALL_BOOTSTRAP_DIR/sls_config_crypto.py" init >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1
}

prepare_installer_bootstrap() {
  local module_name
  INSTALL_BOOTSTRAP_DIR="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-mass-notify-bootstrap.XXXXXX")" || return 1
  chmod 0700 "$INSTALL_BOOTSTRAP_DIR" || return 1
  for module_name in sls_module_trust.py sls_release_trust.py sls_privileged_install.py sls_installer_recovery.py sls_install_transaction.py sls_install_idle.py sls_install_guard.py sls_audio_state.py sls_config_crypto.py sls_upgrade_trust.py sls_legacy_permissions.py; do
    install -o root -g root -m 0700 "$STAGING_DIR/$MODULE/bin/sls_mass_notify/$module_name" "$INSTALL_BOOTSTRAP_DIR/$module_name" || return 1
  done
  install -o root -g root -m 0600 "$STAGING_DIR/$MODULE/bin/sls_mass_notify/freepbx-mirror-signing.pub" "$INSTALL_BOOTSTRAP_DIR/freepbx-mirror-signing.pub" || return 1
  sync_private_installer_tree "$INSTALL_BOOTSTRAP_DIR" || return 1
  export SLS_CONFIG_CRYPTO_PHP="$STAGING_DIR/$MODULE/api/sls-mass-notify/config-crypto.php"
  WORKER_GUARD_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_install_guard.py"
  IDLE_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_install_idle.py"
  RECOVERY_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_installer_recovery.py"
  TRUST_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_module_trust.py"
  PRIVILEGED_INSTALL_BOOTSTRAP="$INSTALL_BOOTSTRAP_DIR/sls_privileged_install.py"
  LEGACY_PERMISSION_TOOL="$INSTALL_BOOTSTRAP_DIR/sls_legacy_permissions.py"
  # Bootstrap helpers are private; keyring initialization follows approval.
  # Public code, user settings, trust pointers and root schedules are unchanged.
}

prepare_authenticated_installer() {
  local manifest signature module_name inventory digest
  [ -n "$PRIVILEGED_INSTALL_BOOTSTRAP" ] && [ -f "$PRIVILEGED_INSTALL_BOOTSTRAP" ] || return 1
  manifest="$DOWNLOAD_DIR/release-manifest.json"
  signature="$DOWNLOAD_DIR/release-manifest.sig"
  [ -f "$manifest" ] && [ ! -L "$manifest" ] && [ -f "$signature" ] && [ ! -L "$signature" ] || {
    log 'The release manifest and Ed25519 signature are required for protected installation, including offline candidates. Supply SLS_MASS_NOTIFY_MANIFEST and SLS_MASS_NOTIFY_MANIFEST_SIGNATURE alongside the archive.'
    return 1
  }
  UPGRADE_TRUST_DIR="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-mass-notify-upgrade-review.XXXXXX")" || return 1
  chmod 0700 "$UPGRADE_TRUST_DIR" || return 1
  log "Upgrade trust and review evidence: $UPGRADE_TRUST_DIR"
  run_logged /usr/bin/python3 -I "$INSTALL_BOOTSTRAP_DIR/sls_upgrade_trust.py" \
    --workspace "$UPGRADE_TRUST_DIR" --trust-root "$TRUST_ROOT" \
    --archive "$TGZ" --manifest "$manifest" --signature "$signature" || return 1
  # This only loads already approved protected inventories. It does not learn
  # expected bytes from the installed Dashboard or Framework tree.
  run_logged /usr/bin/python3 -I - "$TRUST_TOOL" "$TRUST_ROOT" "$STAGING_DIR/$MODULE" "$UPGRADE_TRUST_DIR/approvals.json" <<'PY' || return 1
from pathlib import Path
import sys
import types
sys.dont_write_bytecode = True
path = Path(sys.argv[1])
trust = types.ModuleType('sls_installer_trust'); trust.__file__ = str(path)
exec(compile(path.read_bytes(), str(path), 'exec'), trust.__dict__)
# Inventory every stock module before prepare/dependencies. Only the two
# publisher-authenticated Dashboard overlays and the explicitly reviewed menu
# transition may differ; no live hashes become new approval evidence.
import os, stat
candidate = Path(sys.argv[3])
web = Path('/var/www/html')
import json
approvals = json.loads(trust.read(Path(sys.argv[4]), trust.MAX_MANIFEST * 4, protected=True))
prior = approvals['prior']
for module in ('dashboard', 'framework'):
    data = approvals['approved'][module]
    trust.check_reviewed_omissions(data, web)
    overlays = {
        'sections/SlsMassNotifyAnnouncement.class.php': candidate / 'dashboard/sections/SlsMassNotifyAnnouncement.class.php',
        'views/sections/sls-mass-notify-announcement.php': candidate / 'dashboard/views/sections/sls-mass-notify-announcement.php',
    } if module == 'dashboard' else {}
    for name, path in overlays.items():
        if name not in data['files'] or trust.digest(trust.read(path, trust.MAX_ARCHIVE)) != data['files'][name]['sha256']:
            raise SystemExit('Reviewed Dashboard integration does not match this signed candidate: ' + name)
    actual = trust.inventory_tree(web / 'admin/modules' / module, module)
    expected = {name for name, entry in data['files'].items() if entry['target'].startswith('admin/modules/' + module + '/')}
    if actual - set(overlays) != expected - set(overlays):
        raise SystemExit('Installed ' + module + ' file inventory is not covered by independent approval')
    total = 0
    for name, entry in data['files'].items():
        if name in overlays:
            if name not in actual: continue
            observed = trust.digest(trust.read(web / entry['target'], trust.MAX_ARCHIVE))
            previous = prior.get(module, {}).get('files', {}).get(name, {}).get('sha256')
            if observed not in {entry['sha256'], previous}:
                raise SystemExit('Existing SLL Dashboard overlay lacks prior approval: ' + name)
            continue
        if 'link_target' in entry:
            path = web / entry['target']
            parent = trust.directory(path.parent)
            try:
                before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                target = str(web / entry['link_target'])
                if not stat.S_ISLNK(before.st_mode) or before.st_nlink != 1 or os.readlink(path.name, dir_fd=parent) != target:
                    raise SystemExit('Reviewed Framework asset link changed')
                body = trust.read(Path(target), trust.MAX_ARCHIVE)
                after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if (before.st_dev, before.st_ino, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_ctime_ns):
                    raise SystemExit('Reviewed Framework asset link changed during inspection')
            finally: os.close(parent)
        else:
            body = trust.read(web / entry['target'], trust.MAX_ARCHIVE)
        total += len(body)
        if total > 1024 * 1024 * 1024: raise SystemExit('Stock inventory exceeds verification size bound')
        allowed = {entry['sha256']}
        if module == 'framework' and name == 'amp_conf/htdocs/admin/views/menu_items.php':
            previous = data.get('uninstall', {}).get('replace', {}).get(name)
            if previous: allowed.add(previous)
            previous_overlay = prior.get(module, {}).get('files', {}).get(name, {}).get('sha256')
            if previous_overlay: allowed.add(previous_overlay)
        if trust.digest(body) not in allowed:
            raise SystemExit('Stock file differs from independently approved inventory: ' + module + '/' + name)
PY
  AUTHENTICATED_INSTALLER_APPROVED=1
  if [ "${SLS_MASS_NOTIFY_INVENTORY_ONLY:-0}" = 1 ]; then
    preflight_authenticated_prerequisites || return 1
    log "Inventory preflight passed. Review $UPGRADE_TRUST_DIR; no module, trust pointers or maintenance schedules were changed."
    return 0
  fi
}

preflight_authenticated_prerequisites() {
  run_logged /usr/bin/python3 -I "$PRIVILEGED_INSTALL_BOOTSTRAP" --trust-root "$UPGRADE_TRUST_DIR/registry" preflight || return 1
  /usr/bin/python3 -I "$RECOVERY_TOOL" --snapshot "$UPGRADE_TRUST_DIR/service-preview" preflight-services || return 1
  /usr/bin/python3 -I "$RECOVERY_TOOL" --snapshot "$UPGRADE_TRUST_DIR/static-preview" preflight-inventory || return 1
}

capture_install_resource_proof() {
  # This normal-install-only fact is captured before the new journal and worker
  # locks are created. Missing or inapplicable evidence keeps the full budget.
  [ "$AUTHENTICATED_INSTALLER_APPROVED" -eq 1 ] || return 0
  case "$INITIAL_NATIVE_MODULE_REGISTRY_STATE" in known_absent|established) ;; *) return 0 ;; esac
  /usr/bin/python3 -I - "$STAGING_DIR/$MODULE/bin/sls_mass_notify/sls_resource_capacity.py" \
      "$UPGRADE_TRUST_DIR" "$STAGING_DIR/$MODULE" "$INITIAL_NATIVE_MODULE_REGISTRY_STATE" <<'PYRESOURCERELATIONSHIP'
from pathlib import Path
import json, os, stat, sys, types
source, review, candidate = map(Path, sys.argv[1:4])
module = types.ModuleType('authenticated_resource_relationship'); module.__file__ = str(source)
exec(compile(source.read_bytes(), str(source), 'exec'), module.__dict__)
proof = None
if sys.argv[4] == 'established' and hasattr(module, 'capture_prepared_upgrade_storage_proof'):
    proof = module.capture_prepared_upgrade_storage_proof(review, candidate, sys.argv[4])
if proof is None and sys.argv[4] == 'known_absent' and hasattr(module, 'capture_install_storage_proof'):
    proof = module.capture_install_storage_proof(review, candidate, sys.argv[4])
if proof is None and sys.argv[4] == 'known_absent':
    proof = module.capture_fresh_release_proof(review, candidate, sys.argv[4])
if proof is None:
    raise SystemExit(0)
if not isinstance(proof, dict):
    raise RuntimeError('Resource relationship proof is invalid')
raw = (json.dumps(proof, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
if len(raw) > 4 * 1024 * 1024:
    raise RuntimeError('Resource relationship proof exceeds its bound')
parent = os.open(review, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    info = os.fstat(parent)
    if review.resolve() != review or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError('Private authenticated review required')
    fd = os.open('resource-relationship-proof.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o600); output.write(raw); output.flush(); os.fsync(output.fileno())
    os.fsync(parent)
finally:
    os.close(parent)
PYRESOURCERELATIONSHIP
}

repair_authenticated_legacy_permissions() {
  [ "$AUTHENTICATED_INSTALLER_APPROVED" -eq 1 ] && [ "${SLS_MASS_NOTIFY_INVENTORY_ONLY:-0}" != 1 ] || {
    log 'Legacy permission recovery requires approved previous and candidate releases; inspection cannot perform repairs.'
    return 1
  }
  # Restore only missing signed prior helpers and retire verified generated
  # caches before checking the previous collector. Existing executable bytes
  # have already been matched against the publisher-authenticated release.
  run_logged /usr/bin/python3 -I "$INSTALL_BOOTSTRAP_DIR/sls_upgrade_trust.py" \
    --workspace "$UPGRADE_TRUST_DIR" --normalize-runtime || return 1
  run_logged /usr/bin/python3 -I "$LEGACY_PERMISSION_TOOL" --data "$DATA_DIR" \
    --approval "$UPGRADE_TRUST_DIR/previous-root-approval.json" repair
}

protect_freepbx_chown_permissions() {
  [ "$AUTHENTICATED_INSTALLER_APPROVED" -eq 1 ] && [ "${SLS_MASS_NOTIFY_INVENTORY_ONLY:-0}" != 1 ] || return 1
  # This fixed installer-private area remains protected across reboot and
  # runtime rollback. Snapshot the runtime exclusion only after that permanent
  # infrastructure protection exists, so restoring it cannot expose backups.
  run_logged /usr/bin/python3 -I "$LEGACY_PERMISSION_TOOL" --data "$DATA_DIR" \
    --approval "$UPGRADE_TRUST_DIR/previous-root-approval.json" \
    --chown-config "$FREEPBX_CHOWN_CONFIG" --snapshot "$UPGRADE_TRUST_DIR/freepbx-module-recovery-chown.snapshot" protect-recovery-chown || return 1
  run_logged /usr/bin/python3 -I "$LEGACY_PERMISSION_TOOL" --data "$DATA_DIR" \
    --approval "$UPGRADE_TRUST_DIR/previous-root-approval.json" \
    --chown-config "$FREEPBX_CHOWN_CONFIG" --snapshot "$UPGRADE_TRUST_DIR/freepbx-chown.snapshot" protect-chown
}

restore_freepbx_chown_permissions() {
  [ -n "$UPGRADE_TRUST_DIR" ] || return 0
  local snapshot="$UPGRADE_TRUST_DIR/freepbx-chown.snapshot"
  [ -e "$snapshot" ] || [ -L "$snapshot" ] || return 0
  run_logged /usr/bin/python3 -I "$LEGACY_PERMISSION_TOOL" --data "$DATA_DIR" \
    --chown-config "$FREEPBX_CHOWN_CONFIG" --snapshot "$snapshot" restore-chown
}

restore_previous_phone_collector() {
  [ "$AUTHENTICATED_INSTALLER_APPROVED" -eq 1 ] && [ "${SLS_MASS_NOTIFY_INVENTORY_ONLY:-0}" != 1 ] || return 1
  local requirement state loaded active
  requirement="$(/usr/bin/python3 -I - "$UPGRADE_TRUST_DIR/previous-root-approval.json" <<'PYCOLLECTORAPPROVAL'
import json, pathlib, sys
approval = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
if approval.get('source') == 'fresh-install' and approval.get('files') == {}:
    print('absent')
elif approval.get('source') == 'publisher-verified-previous-release' and isinstance(approval.get('files'), dict):
    names = approval['files']
    required = ['/usr/local/bin/sls_mass_notify/sls_phone_events.py', '/usr/local/bin/sls_mass_notify/sls_phone_admission.py']
    present = [name in names for name in required]
    if any(present) and not all(present): raise SystemExit('Previous phone runtime approval is incomplete')
    print('required' if all(present) else 'absent')
else:
    raise SystemExit('Previous release approval is missing or invalid')
PYCOLLECTORAPPROVAL
)" || return 1
  [ "$requirement" = required ] || return 0
  # This verifies the exact fixed unit and rejects masks and administrator
  # drop-ins before any service operation. Disabled services stay disabled.
  state="$(/usr/bin/python3 -I "$RECOVERY_TOOL" --snapshot "$UPGRADE_TRUST_DIR/service-preview" preflight-services)" || return 1
  active="$(/usr/bin/python3 -I - "$state" <<'PYCOLLECTORSTATE'
import json, sys
value = json.loads(sys.argv[1])
state = value.get('service_state', {})
if value.get('ok') is not True or state.get('enabled') != 'enabled' or state.get('active') not in ('active', 'inactive', 'failed'):
    raise SystemExit('The approved previous phone collector must be enabled. Restore its supported service before upgrading; administrator-disabled or missing services are not enabled automatically.')
print(state['active'])
PYCOLLECTORSTATE
)" || return 1
  loaded="$(systemctl show sls-mass-notify-phone-events.service --property=User,Group,FragmentPath,DropInPaths)" || return 1
  /usr/bin/python3 -I - "$loaded" <<'PYCOLLECTORIDENTITY' || return 1
import sys
values = dict(line.split('=', 1) for line in sys.argv[1].splitlines() if '=' in line)
if values != {'User':'asterisk', 'Group':'asterisk', 'FragmentPath':'/etc/systemd/system/sls-mass-notify-phone-events.service', 'DropInPaths':''}:
    raise SystemExit('The loaded previous phone collector does not match its approved unprivileged service. Review systemd configuration before upgrading.')
PYCOLLECTORIDENTITY
  if [ "$active" != active ]; then
    run_logged systemctl start sls-mass-notify-phone-events.service || return 1
  fi
  verify_phone_collector || {
    log 'Previous phone collector recovery failed after permission repair. No candidate runtime or maintenance schedule was activated. Review the collector journal and approved service configuration before retrying.'
    return 1
  }
}

commit_authenticated_installer() {
  local manifest="$DOWNLOAD_DIR/release-manifest.json" signature="$DOWNLOAD_DIR/release-manifest.sig"
  local module_name inventory digest
  local -a cache_capacity_arguments=()
  if [ -n "$CAPACITY_STOCK_CACHE_PROOF_SHA256" ]; then
    cache_capacity_arguments=(--cache-storage-proof "$UPGRADE_TRUST_DIR/resource-relationship-proof.json"
      --cache-storage-proof-sha256 "$CAPACITY_STOCK_CACHE_PROOF_SHA256")
  fi
  # Retire untrusted generated bytecode and restore only absent authenticated
  # prior helpers before the rollback snapshot can authorize prior root jobs.
  run_logged /usr/bin/python3 -I "$INSTALL_BOOTSTRAP_DIR/sls_upgrade_trust.py" \
    --workspace "$UPGRADE_TRUST_DIR" --normalize-runtime || return 1
  prepare_install_recovery || return 1
  STATIC_MUTATION_STARTED=1
  persist_install_transaction mutating || return 1
  /usr/bin/python3 -I "$TRUST_TOOL" --root "$TRUST_ROOT" enroll-sls \
    --archive "$TGZ" --manifest "$manifest" --signature "$signature" || return 1
  for module_name in dashboard framework; do
    inventory="$UPGRADE_TRUST_DIR/$module_name.json"
    digest="$(sha256sum "$inventory" | cut -d ' ' -f 1)" || return 1
    /usr/bin/python3 -I "$TRUST_TOOL" --root "$TRUST_ROOT" enroll-reviewed --inventory "$inventory" --sha256 "$digest" || return 1
  done
  run_logged /usr/bin/python3 -I "$INSTALL_BOOTSTRAP_DIR/sls_upgrade_trust.py" \
    --workspace "$UPGRADE_TRUST_DIR" --trust-root "$TRUST_ROOT" --cache-stock "${cache_capacity_arguments[@]}" \
    --coordination-fd "$INSTALL_MAINTENANCE_LOCK_FD" \
    --coordination-lock "${SLS_MASS_NOTIFY_MAINTENANCE_LOCK:-/run/lock/sls-mass-notify-maintenance.lock}" || return 1
  protected_install_phase plan
}

# The protected log opener requires Python before the ordinary dependency pass.
# Bootstrap only that missing package on an identified Debian 12 FreePBX host;
# no log pathname is opened or written until the safe opener can run.
ensure_installer_log_prerequisites() {
  local python_probe='import os, pwd, stat, sys; assert all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK")); assert callable(os.fstat)'
  local platform_id="" platform_version="" platform_key platform_value
  if [ -x /usr/bin/python3 ]; then
    if /usr/bin/python3 -I -c "$python_probe" >/dev/null 2>&1; then
      return 0
    fi
    printf 'The existing /usr/bin/python3 cannot load the standard library required for secure installer logging. Repair the system Python installation, then retry; no binary was replaced.\n' >&2
    return 1
  fi
  if [ -e /usr/bin/python3 ] || [ -L /usr/bin/python3 ]; then
    printf '/usr/bin/python3 exists but is not executable or its link is broken. Repair the system Python installation, then retry; no binary was replaced.\n' >&2
    return 1
  fi
  if [ -r /etc/os-release ]; then
    while IFS='=' read -r platform_key platform_value; do
      platform_value="${platform_value#\"}"
      platform_value="${platform_value%\"}"
      platform_value="${platform_value#\'}"
      platform_value="${platform_value%\'}"
      case "$platform_key" in
        ID) platform_id="$platform_value" ;;
        VERSION_ID) platform_version="$platform_value" ;;
      esac
    done </etc/os-release
  fi
  if [ "$platform_id" != "debian" ] || [ "$platform_version" != "12" ] \
    || [ ! -x /usr/sbin/fwconsole ] || [ ! -x /usr/sbin/asterisk ] \
    || [ ! -r /etc/freepbx.conf ] || [ ! -d /var/www/html/admin/modules ] \
    || [ ! -x /usr/bin/apt-get ]; then
    printf 'Python 3 is required for secure installer logging. Automatic bootstrap requires a recognized Debian 12 FreePBX host and apt-get; no packages were changed.\n' >&2
    return 1
  fi
  printf 'Installing missing Python 3 for secure installer logging. Package-manager output follows on this console.\n'
  if ! DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get update; then
    printf 'Unable to refresh Debian package metadata for the missing Python prerequisite. Correct repository access, then retry.\n' >&2
    return 1
  fi
  APT_METADATA_REFRESHED=1
  if ! DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -y --no-install-recommends --no-remove python3; then
    printf 'Unable to install the missing Python prerequisite. Review the package-manager error above, then retry.\n' >&2
    return 1
  fi
  if [ ! -x /usr/bin/python3 ] || ! /usr/bin/python3 -I -c "$python_probe" >/dev/null 2>&1; then
    printf 'Python installation returned but its executable or required standard library is unavailable. Repair the system Python installation before retrying.\n' >&2
    return 1
  fi
}

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

log() {
  printf '%s\n' "$*"
  if [ -n "${INSTALL_LOG_FD:-}" ]; then
    printf '%s\n' "$*" >&"$INSTALL_LOG_FD"
  fi
}

run_logged() {
  local output status
  local -a pipeline_status=()
  # Stream child output instead of retaining it in a shell variable. Package
  # managers and FreePBX repair commands can be verbose, and buffering their
  # complete output makes a recoverable host problem an installer memory spike.
  if "$@" 2>&1 | while IFS= read -r output || [ -n "$output" ]; do
    printf '%s\n' "$output"
    if [ -n "${INSTALL_LOG_FD:-}" ]; then
      printf '%s\n' "$output" >&"$INSTALL_LOG_FD"
    fi
  done; then
    return 0
  else
    pipeline_status=("${PIPESTATUS[@]}")
    status="${pipeline_status[0]:-1}"
    # A log/console write failure is also fatal even if the child succeeded.
    if [ "$status" -eq 0 ]; then
      status="${pipeline_status[1]:-1}"
    fi
    return "$status"
  fi
}

set_install_stage() {
  local next_stage="$1" next_solution="$2" status
  if [ -n "$INSTALL_TRANSACTION_DIR" ] && [ -n "$TRANSACTION_TOOL" ]; then
    if /usr/bin/python3 -I "$TRANSACTION_TOOL" --root "$INSTALL_TRANSACTION_ROOT" --transaction "$INSTALL_TRANSACTION_DIR" --stage "$next_stage" stage; then
      :
    else
      status=$?
      INSTALL_ERROR_CATEGORY="installer_stage_recording_failed"
      INSTALL_SOLUTION="The authenticated installer could not record stage '$next_stage'. Preserve the transaction directory and installer log, and use a corrected signed installer before retrying."
      log "$INSTALL_SOLUTION"
      return "$status"
    fi
  fi
  # A rejected transition must not poison rollback's last valid journal stage.
  INSTALL_STAGE="$next_stage"
  INSTALL_SOLUTION="$next_solution"
}

ensure_data_directory() {
  DATA_DIRECTORY_PATH="$DATA_DIR" /usr/bin/python3 -I - <<'PY'
import os
import pwd
import stat

path = os.environ["DATA_DIRECTORY_PATH"]
parts = path.split("/")[1:]
if not path.startswith("/") or not parts or any(part in {'', '.', '..'} for part in parts) or "\x00" in path:
    raise SystemExit(2)
account = pwd.getpwnam("asterisk")
owners = {0, account.pw_uid}
groups = {0, account.pw_gid}
flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
parent_fd = os.open("/", flags)
try:
    for component in parts[:-1]:
        next_fd = os.open(component, flags, dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = next_fd
        metadata = os.fstat(parent_fd)
        sticky_root = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        if metadata.st_uid not in owners or metadata.st_gid not in groups or (metadata.st_mode & 0o022 and not sticky_root):
            raise RuntimeError('The SLL data directory has an unreviewed parent; no ownership was changed')
    try:
        directory_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
    except FileNotFoundError:
        os.mkdir(parts[-1], 0o750, dir_fd=parent_fd)
        directory_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
    try:
        metadata = os.fstat(directory_fd)
        named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in owners
                or metadata.st_gid not in groups or stat.S_IMODE(metadata.st_mode) not in (0o700, 0o750, 0o755)
                or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)):
            raise RuntimeError('The existing SLL data directory has unreviewed ownership or permissions; preserve it for review')
        os.fchmod(directory_fd, 0o750)
        os.fchown(directory_fd, account.pw_uid, account.pw_gid)
    finally:
        os.close(directory_fd)
finally:
    os.close(parent_fd)
PY
}

record_install_failure() {
  local marker_tmp
  [ "$FREEPBX_CONFIRMED" -eq 1 ] || return 0
  ensure_data_directory 2>/dev/null || return 0
  marker_tmp="$(mktemp "$INSTALL_TEMP_ROOT/slsmassnotifyserver-install-failure.XXXXXX" 2>/dev/null || true)"
  [ -n "$marker_tmp" ] || return 0
  if ! /usr/bin/php -r '
$payload = [
    "version" => 1,
    "failed_at" => gmdate("c"),
    "stage" => substr(preg_replace("/[^A-Za-z0-9 ._\/-]/", "", (string)$argv[1]), 0, 80),
    "message" => "SLL Mass Notify Server installation did not complete.",
    "solution" => substr(preg_replace("/[[:cntrl:]]/", " ", (string)$argv[2]), 0, 400),
    "log" => substr(preg_replace("/[[:cntrl:]]/", "", (string)$argv[6]), 0, 500),
    "error_category" => preg_match("/^[a-z][a-z0-9_]{0,63}$/", $argv[4]) ? $argv[4] : "install_command_failed",
    "exit_code" => max(1, min(255, (int)$argv[5])),
];
$json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
if (!is_string($json) || file_put_contents($argv[3], $json . PHP_EOL, LOCK_EX) === false) {
    exit(1);
}
' "$INSTALL_STAGE" "$INSTALL_SOLUTION" "$marker_tmp" "$INSTALL_ERROR_CATEGORY" "$INSTALL_EXIT_CODE" "$LOG_FILE" 2>/dev/null; then
    rm -f "$marker_tmp"
    return 0
  fi
  safe_config_restore "$marker_tmp" "$INSTALL_FAILURE_FILE" 2>/dev/null || {
    rm -f "$marker_tmp"
    return 0
  }
  rm -f "$marker_tmp"
  [ "${INSTALL_NOTIFICATION_SIDE_EFFECTS:-1}" -eq 1 ] || return 0
  php -r '
require "/etc/freepbx.conf";
$detail = "Stage: " . $argv[1] . ". " . $argv[2] . " Installer log: " . htmlspecialchars($argv[3], ENT_QUOTES, "UTF-8");
\FreePBX::Notifications()->add_error(
    "slsmassnotifyserver",
    "INSTALLFAILED",
    "SLL Mass Notify Server installation failed",
    $detail,
    "",
    true,
    true
);
exit(0);
' "$INSTALL_STAGE" "$INSTALL_SOLUTION" "$LOG_FILE" >/dev/null 2>&1 || true
}

clear_install_failure() {
  if [ ! -L "$INSTALL_FAILURE_FILE" ]; then
    rm -f "$INSTALL_FAILURE_FILE" 2>/dev/null || true
  fi
  [ "${INSTALL_NOTIFICATION_SIDE_EFFECTS:-1}" -eq 1 ] || return 0
  php -r '
require "/etc/freepbx.conf";
\FreePBX::Notifications()->delete("slsmassnotifyserver", "INSTALLFAILED");
exit(0);
' >/dev/null 2>&1 || true
}

capture_local_web_probe_authority() {
  local authority
  authority="$(/usr/bin/timeout --signal=TERM --kill-after=1 8 /usr/sbin/apache2ctl -t \
    -D DUMP_VHOSTS -D DUMP_CONFIG -C 'LoadModule info_module /usr/lib/apache2/modules/mod_info.so' \
    2>>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" | /usr/bin/python3 -I -c '
import json,re,shlex,sys
raw=sys.stdin.buffer.read(1048577)
if len(raw)>1048576: raise SystemExit("Apache route authority exceeds its bound")
text=raw.decode("utf-8","strict");before,marker,config=text.partition("# In file:")
if not marker: raise SystemExit("Native Apache effective route authority is unavailable")
allowed={"listen","servername","serveralias","documentroot","alias","aliasmatch","scriptalias","redirect","redirectmatch","sslengine","sethandler","addhandler","proxypass","proxypassmatch","balancermember","rewriterule"}
lines=[]
pending_conditions=False
def selector(token):
    if len(token)>=2 and token.startswith("\"") and token.endswith("\""):
        token=token[1:-1]
    return token if re.fullmatch(r"[A-Za-z0-9_./\\^$|()*+!?:-]{1,256}",token) else None
def sanitized_flags(tokens, allowed_flags):
    if not tokens: return ""
    if len(tokens)==1 and re.fullmatch(r"\[[A-Za-z0-9,=]+\]",tokens[0]):
        items=tokens[0][1:-1].upper().split(",")
        if len(set(items))==len(items) and all(re.fullmatch(allowed_flags,item) for item in items):
            return " ["+",".join(items)+"]"
    return " [UNKNOWN]"
for line in config.splitlines():
    value=line.strip()
    if not value or value.startswith("#"): continue
    parts=value.split()
    name=parts[0].lower()
    if name=="rewritecond":
        pending_conditions=True
        subject=parts[1] if len(parts)>=3 else ""
        condition=parts[2] if len(parts)>=3 else ""
        # A mod_rewrite file/URL test or expanded lookup can perform work
        # before a later condition excludes this URI. Preserve that uncertainty.
        simple_subject=bool(re.fullmatch(r"%\{(?:REQUEST_URI|HTTP_HOST|HTTP:[A-Za-z0-9-]{1,64})\}",subject))
        simple_pattern=bool(re.fullmatch(r"[A-Za-z0-9_./\\^$|()*+!?:<>=\[\]-]{1,256}",condition)
                            and not condition.lstrip("!").startswith("-"))
        if not simple_subject or not simple_pattern:
            lines.append("RewriteCond UNKNOWN UNKNOWN [UNKNOWN]")
            continue
        path=selector(condition) if subject=="%{REQUEST_URI}" else None
        flags=sanitized_flags(parts[3:],r"NC|OR") if len(parts)>=3 else " [UNKNOWN]"
        lines.append("RewriteCond "+("%{REQUEST_URI} "+path if path else "UNKNOWN UNKNOWN")+flags)
        continue
    if pending_conditions and name!="rewriterule":
        lines.append("SLSRewriteBoundary reset")
    pending_conditions=False
    if re.match(r"^</?(?:VirtualHost|Directory|DirectoryMatch|Location|LocationMatch|Files|FilesMatch)\b",value,re.I):
        lines.append(value);continue
    if value.startswith("<"):
        lines.append("</SLSUnknown>" if value.startswith("</") else "<SLSUnknown>")
        continue
    if name not in allowed: continue
    if name=="rewriterule" and re.search(r"[a-z][a-z0-9+.-]*://",value,re.I):
        source=selector(parts[1]) if len(parts)>=3 else None
        flags=sanitized_flags(parts[3:],r"R(?:=30[12378])?|L|END|NE|NC|F|G|P|QSA")
        lines.append("RewriteRule "+(source or "UNKNOWN")+" UNQUALIFIED_REMOTE_HANDLER"+flags)
        continue
    if name=="redirectmatch" and re.search(r"[a-z][a-z0-9+.-]*://",value,re.I):
        statuses={"permanent","temp","seeother","gone","301","302","303","307","308","410"}
        index=2 if len(parts)>1 and parts[1].lower() in statuses else 1
        source=selector(parts[index]) if len(parts)==index+2 else None
        prefix=(parts[1]+" " if index==2 else "")+source+" " if source else ""
        lines.append("RedirectMatch "+prefix+"UNQUALIFIED_REMOTE_HANDLER")
        continue
    if name in {"sethandler","addhandler","proxypass","proxypassmatch","balancermember","rewriterule","redirect","redirectmatch"} and re.search(r"(?:https?|fcgi)://",value,re.I) and not re.search(r"unix:/[^\s|]+\|fcgi://(?:localhost|127\.0\.0\.1|\[::1\])",value,re.I):
        try: parts=shlex.split(value,comments=True)
        except ValueError: parts=[]
        prefix=parts[1] if len(parts)>1 else ""
        if name=="redirect" and prefix in {"permanent","temp","seeother","gone","301","302","303","307","308","410"}:
            prefix=parts[2] if len(parts)>2 else ""
        # A literal local prefix is necessary to keep an unrelated route from
        # imposing its handler on SLL. Destination credentials never cross.
        scoped=name in {"proxypass","redirect"} and re.fullmatch(r"/[A-Za-z0-9_./-]{0,255}",prefix)
        value=name+(" "+prefix if scoped else "")+" UNQUALIFIED_REMOTE_HANDLER"
    lines.append(value)
vhost_lines=[]
for line in before.splitlines():
    if re.match(r"^\s*(?:(?:\*|_default_|[0-9.]+|\[[0-9a-f:]+\]):[0-9]+\s|port\s+[0-9]+\s+namevhost\s|(?:wild\s+)?alias\s)",line,re.I):
        vhost_lines.append(line)
    elif re.match(r"^\s*\S+:\S+\s+",line):
        # Retain incomplete binding authority without passing unparsed text.
        vhost_lines.append("UNCLASSIFIED_VHOST_BINDING")
vhosts="\n".join(vhost_lines)
config="\n".join(lines)
if len(vhosts.encode())>65536 or len(config.encode())>65536: raise SystemExit("Sanitized Apache route authority exceeds its environment bound")
print(json.dumps({"vhosts":vhosts,"config":config},separators=(",",":")))
')" || { log 'The native Apache route authority could not be captured; no authenticated local probe was sent.'; return 1; }
  SLS_LOCAL_WEB_VHOST_DUMP="$(printf '%s' "$authority" | /usr/bin/python3 -I -c 'import json,sys;print(json.load(sys.stdin)["vhosts"])')" || return 1
  SLS_LOCAL_WEB_CONFIG_DUMP="$(printf '%s' "$authority" | /usr/bin/python3 -I -c 'import json,sys;print(json.load(sys.stdin)["config"])')" || return 1
}

authenticated_local_web_probe_program() {
  # The restored module can predate route qualification. Every normal install,
  # rollback and corrected recovery has its own authenticated, private archive.
  local bootstrap="${RECOVERY_PROGRAM_DIR:-$INSTALL_BOOTSTRAP_DIR}"
  [ -n "$bootstrap" ] || return 1
  /usr/bin/timeout --signal=TERM --kill-after=1 8 /usr/bin/python3 -I - "$bootstrap" <<'PYCURRENTPROBE'
import hashlib, os, stat, sys, tarfile
from pathlib import Path

try:
    path = Path(sys.argv[1]).parent / 'package.tgz'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink != 1
                or info.st_mode & 0o077 or not 0 < info.st_size <= 54525952):
            raise ValueError('unprotected package')
        with tarfile.open(fileobj=stream, mode='r|gz') as archive:
            for index, member in enumerate(archive):
                if index >= 10000 or member.offset_data + member.size > 256 * 1024 * 1024:
                    raise ValueError('package inspection bound exceeded')
                if member.name != 'slsmassnotifyserver/LocalWebProbe.php':
                    continue
                if not member.isfile() or not 0 < member.size <= 65536:
                    raise ValueError('unrecognized probe')
                source = archive.extractfile(member).read(65537)
                if (len(source) != member.size or not source.startswith(b'<?php\n')
                        or hashlib.sha256(source).hexdigest() != 'ad9a9f25b9d15ab087ac3074690b556bdba810059b7cb5816e8b533a183977f3'):
                    raise ValueError('unrecognized probe')
                # php -r consumes source without its opening tag. Only the
                # publisher-pinned public helper leaves the private carrier.
                sys.stdout.buffer.write(source[6:])
                break
            else:
                raise ValueError('missing probe')
except (OSError, EOFError, ValueError, tarfile.TarError):
    sys.exit('Current signed local web probe is unavailable in the protected installer package.')
PYCURRENTPROBE
}

local_web_probe() {
  local path="$1" output="$2" expected_pattern="$3" program code
  if ! capture_local_web_probe_authority >&2 || ! program="$(authenticated_local_web_probe_program)"; then
    printf '000\n'; return 1
  fi
  # The account can read its protected settings without opening the carrier
  # or the root-private output. The whole request, including the local socket,
  # uses the same path-specific bounded transport as authenticated UI checks.
  if ! code="$(
    sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 30 /usr/bin/php -r "$program"'
require_once "/usr/local/bin/sls_mass_notify/sls_config_crypto.php";
$settings = SlsConfigCrypto::decode((string)file_get_contents(
    "/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config"
));
$vhosts = getenv("SLS_LOCAL_WEB_VHOST_DUMP");
$config = getenv("SLS_LOCAL_WEB_CONFIG_DUMP");
if (!is_string($vhosts) || !is_string($config) || $config === "") { exit(1); }
$code = 0; $body = "";
foreach (SlsLocalWebProbe::responses($settings["public_pbx_host"] ?? "", $argv[1], [], 10, $vhosts, $config) as $response) {
    $code = $response["status"];
    if ($code && preg_match("~" . $argv[2] . "~D", (string)$code) === 1) {
        $body = $response["body"]; break;
    }
}
printf("%03d\n", $code);
echo $body;
' "$path" "$expected_pattern" 2>/dev/null | /usr/bin/python3 -I -c '
import os, re, stat, sys
frame = sys.stdin.buffer.read(262149)
if (len(frame) > 262148 or not re.fullmatch(rb"(?:000|[1-5][0-9]{2})\n", frame[:4])):
    sys.exit(1)
try:
    fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink != 1 or info.st_mode & 0o077:
            sys.exit(1)
        os.ftruncate(fd, 0)
        stream.write(frame[4:])
except OSError:
    sys.exit(1)
print(frame[:3].decode("ascii"))
' "$output"
  )"; then printf '000\n'; return 1; fi
  printf '%s\n' "$code"
  [[ "$code" =~ $expected_pattern ]]
}

rollback_failure() {
  ROLLBACK_FAILED=1
  log "CRITICAL: rollback could not complete: $1. Recovery files will be preserved."
}

remove_phone_collector_service() {
  local unit="/etc/systemd/system/sls-mass-notify-phone-events.service" active_state
  [ -e "$unit" ] || [ -L "$unit" ] || return 0
  python3 -I - "$unit" <<'PY'
import os
import stat
import sys
path = sys.argv[1]
metadata = os.lstat(path)
if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or metadata.st_uid != 0 or metadata.st_mode & 0o022):
    raise SystemExit("Refusing to remove an unsafe phone collector service file.")
with open(path, encoding="utf-8") as handle:
    if handle.read(128).splitlines()[:2] != ["# Managed by SLS Mass Notify Server", "[Unit]"]:
        raise SystemExit("Refusing to remove an unrelated phone collector service.")
PY
  [ "$?" -eq 0 ] || return 1
  /usr/bin/timeout --kill-after=2 20 systemctl disable --now sls-mass-notify-phone-events.service || return 1
  active_state="$(/usr/bin/timeout --kill-after=2 10 systemctl show --property=ActiveState --value sls-mass-notify-phone-events.service)" || return 1
  case "$active_state" in inactive|failed) ;; *) log "The phone collector has not stopped; its service file was preserved."; return 1 ;; esac
  rm -- "$unit" || return 1
  /usr/bin/timeout --kill-after=2 10 systemctl daemon-reload || return 1
}

repair_restored_api_directory_access() {
  # Legacy installers create root-owned directories under umask027. Repair
  # only the two public API trees after proving they match the restored module.
  python3 -I - "/var/www/html/admin/modules/$MODULE" <<'PY'
import hashlib
import os
import stat
import sys
import time

flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
directories = []
entries = 0
total_bytes = 0
started = time.monotonic()

def open_directory(path):
    current = os.open('/', flags)
    try:
        for component in path.split('/')[1:]:
            if component in {'', '.', '..'}:
                raise RuntimeError('invalid API directory')
            following = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise

def digest(directory, name):
    global total_bytes
    descriptor = os.open(name, file_flags, dir_fd=directory)
    with os.fdopen(descriptor, 'rb') as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError('unsafe API file')
        total_bytes += metadata.st_size
        if total_bytes > 32 * 1024 * 1024:
            raise RuntimeError('API source comparison exceeds its limit')
        result = hashlib.sha256()
        read_bytes = 0
        while True:
            if time.monotonic() - started > 5:
                raise RuntimeError('API source comparison exceeds its limit')
            block = handle.read(65536)
            if not block:
                return result.digest()
            read_bytes += len(block)
            if read_bytes > metadata.st_size:
                raise RuntimeError('API file changed during source comparison')
            result.update(block)

def verify(source, target):
    global entries
    names = sorted(os.listdir(source))
    if names != sorted(os.listdir(target)):
        raise RuntimeError('API inventory differs from the restored source')
    directories.append(os.dup(target))
    for name in names:
        entries += 1
        if entries > 512 or time.monotonic() - started > 5:
            raise RuntimeError('API source comparison exceeds its limit')
        source_meta = os.stat(name, dir_fd=source, follow_symlinks=False)
        target_meta = os.stat(name, dir_fd=target, follow_symlinks=False)
        if stat.S_ISDIR(source_meta.st_mode) and stat.S_ISDIR(target_meta.st_mode):
            child_source = os.open(name, flags, dir_fd=source)
            try:
                child_target = os.open(name, flags, dir_fd=target)
                try:
                    verify(child_source, child_target)
                finally:
                    os.close(child_target)
            finally:
                os.close(child_source)
        elif stat.S_ISREG(source_meta.st_mode) and stat.S_ISREG(target_meta.st_mode):
            if digest(source, name) != digest(target, name):
                raise RuntimeError('API file differs from the restored source')
        else:
            raise RuntimeError('unsafe API entry')

try:
    for name, source_path, target_path in (('sipnotify', '/api/sipnotify', '/var/www/html/api/sipnotify'), ('sls-mass-notify', '/api/sls-mass-notify', '/var/www/html/api/sls-mass-notify'), ('operator-portal', '/portal', '/var/www/html/mass-notify')):
        try:
            source = open_directory(sys.argv[1] + source_path)
        except FileNotFoundError:
            # Signed releases from before the separate operator portal have
            # no portal tree. Their two API trees still require verification.
            if name == 'operator-portal':
                continue
            raise
        try:
            target = open_directory(target_path)
            try:
                if 'index.php' not in os.listdir(source):
                    raise RuntimeError('restored API source is incomplete')
                verify(source, target)
            finally:
                os.close(target)
        finally:
            os.close(source)
    # Every restored inventory must verify before any permission changes. Held directory
    # descriptors prevent symlink traversal if a pathname changes afterward.
    for descriptor in directories:
        os.fchmod(descriptor, 0o755)
        os.fsync(descriptor)
except (OSError, ValueError, RuntimeError):
    raise SystemExit('Unable to verify and restore public API directory access; recovery files were retained.') from None
finally:
    for descriptor in directories:
        os.close(descriptor)
PY
}

prepare_install_recovery() {
  RECOVERY_DIR="$(mktemp -d "${INSTALL_TRANSACTION_DIR:-$INSTALL_TEMP_ROOT}/sls-mass-notify-recovery.XXXXXX")" || return 1
  chmod 0700 "$RECOVERY_DIR" || return 1
  /usr/bin/python3 -I "$RECOVERY_TOOL" --snapshot "$RECOVERY_DIR/static" preflight-services || return 1
  /usr/bin/python3 -I "$IDLE_TOOL" --data "$DATA_DIR" inspect --repair-collector >"$RECOVERY_DIR/idle-before.json" || return 1
  chmod 0600 "$RECOVERY_DIR/idle-before.json" || return 1
  # Complete closed rows remain private evidence only. They can prove a later
  # retention expiry even on an old collector; no recovery operation restores
  # this copy over live admissions, reservations or delivery outcomes.
  /usr/bin/python3 -I "$IDLE_TOOL" --data "$DATA_DIR" snapshot-history-evidence \
    --baseline "$RECOVERY_DIR/idle-before.json" \
    --retained-history-evidence "$RECOVERY_DIR/history-evidence.json" || return 1
  RECOVERY_HISTORY_EVIDENCE="$RECOVERY_DIR/history-evidence.json"
  # Preserve only module-owned registration, the configured/legacy AMI names,
  # eight recording identities and enrollment in existing backup jobs.
  # Operational ledgers remain live and are never part of this restoration.
  local ami_names
  ami_names="$(/usr/bin/python3 -I - "$INSTALL_BOOTSTRAP_DIR/sls_config_crypto.py" "$CONFIG_FILE" <<'PYAMINAMES'
import json, pathlib, re, sys, types
path = pathlib.Path(sys.argv[1]); crypto = types.ModuleType('snapshot_config_crypto'); crypto.__file__ = str(path)
exec(compile(path.read_bytes(), str(path), 'exec'), crypto.__dict__)
config = pathlib.Path(sys.argv[2])
name = crypto.read_config(config).get('ami', {}).get('username') if config.exists() else 'slsmassnotify'
if isinstance(name, str): name = name.strip(" \t\r\n\x00\x0b")
if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9_.-]{1,64}', name):
    raise SystemExit('The configured AMI identity cannot be snapshotted safely')
print(json.dumps(list(dict.fromkeys((name, 'sls_mass_notify')))))
PYAMINAMES
)" || return 1
  SLS_RECOVERY_AMI_NAMES="$ami_names" php -r '
require "/etc/freepbx.conf";
$stmt = \FreePBX::Database()->prepare("SELECT * FROM modules WHERE modulename = ?");
$stmt->execute(["slsmassnotifyserver"]);
$row = $stmt->fetch(\PDO::FETCH_ASSOC);
$amiNames = json_decode((string)getenv("SLS_RECOVERY_AMI_NAMES"), true, 8, JSON_THROW_ON_ERROR);
if (!is_array($amiNames) || !array_is_list($amiNames) || count($amiNames) < 1 || count($amiNames) > 2
    || count(array_unique($amiNames)) !== count($amiNames) || !in_array("sls_mass_notify", $amiNames, true)) {
    throw new \RuntimeException("Invalid scoped AMI snapshot identities");
}
foreach ($amiNames as $name) { if (!is_string($name) || !preg_match("/^[a-z0-9_.-]{1,64}$/D", $name)) { throw new \RuntimeException("Invalid AMI snapshot identity"); } }
$amiTable = \FreePBX::Database()->prepare("SHOW TABLES LIKE ?"); $amiTable->execute(["manager"]);
$amiTablePresent = $amiTable->fetchColumn() !== false;
$amiRows = [];
$amiLookup = $amiTablePresent ? \FreePBX::Database()->prepare("SELECT * FROM manager WHERE name = ?") : null;
$amiColumns = ["manager_id", "name", "secret", "deny", "permit", "read", "write", "writetimeout"];
foreach ($amiNames as $name) {
    $rows = [];
    if ($amiLookup) { $amiLookup->execute([$name]); $rows = $amiLookup->fetchAll(\PDO::FETCH_ASSOC); }
    if (count($rows) > 1) { throw new \RuntimeException("The scoped AMI account is ambiguous"); }
    foreach ($rows as $entry) {
        if (count($entry) !== count($amiColumns) || array_diff(array_keys($entry), $amiColumns)
            || ($entry["name"] ?? null) !== $name) { throw new \RuntimeException("Unsupported native Manager schema; no SLL integration was changed"); }
        foreach ($entry as $value) { if (!(is_string($value) || is_int($value) || $value === null) || is_string($value) && strlen($value) > 4096) { throw new \RuntimeException("Invalid native Manager recovery value"); } }
    }
    $amiRows[$name] = $rows;
}
$filenames = ["custom/SLS_Mass_Notify_Paging_Tone_Opening", "custom/SLS_Mass_Notify_Paging_Tone_Closing", "custom/SLS_Mass_Notify_NWS_Alert", "custom/SLS_Mass_Notify_Lightning_Alert", "custom/Paging_Tone_Opening", "custom/Paging_Tone_Closing", "custom/NWS_alert", "custom/Lightning_alert"];
$recordings = [];
$exists = \FreePBX::Database()->prepare("SHOW TABLES LIKE ?"); $exists->execute(["recordings"]);
$lookup = $exists->fetchColumn() !== false ? \FreePBX::Database()->prepare("SELECT * FROM recordings WHERE filename = ? ORDER BY id") : null;
foreach ($filenames as $filename) { $recordings[$filename] = []; if ($lookup) { $lookup->execute([$filename]); $recordings[$filename] = $lookup->fetchAll(\PDO::FETCH_ASSOC); } if (count($recordings[$filename]) > 100) { throw new \RuntimeException("Too many rows use a reserved SLL recording name"); } }
$backupStatus = \FreePBX::Database()->prepare("SELECT enabled FROM modules WHERE modulename = ?"); $backupStatus->execute(["backup"]);
$backup = $backupStatus->fetchColumn() ? \FreePBX::Create()->Backup : null;
$enrollment = [];
$enabled = static function ($value) { return in_array(strtolower(trim((string)$value)), ["1", "true", "yes", "on"], true); };
foreach (array_keys($backup ? (array)$backup->getAll("backupList") : []) as $job) {
    $job = (string)$job;
    if ($job === "" || strlen($job) > 128 || preg_match("/[\x00-\x1f\x7f]/", $job)) { continue; }
    $selected = (array)$backup->getAll("modules_" . $job);
    if (!array_filter($selected, $enabled) || $enabled($selected["slsmassnotifyserver"] ?? false)) { continue; }
    $enrollment[] = ["job" => $job, "present" => array_key_exists("slsmassnotifyserver", $selected), "value" => $selected["slsmassnotifyserver"] ?? null];
}
$encoded = json_encode(["schema" => 3, "row" => $row ?: null, "recordings" => $recordings, "backup_enrollment" => $enrollment,
    "ami_names" => $amiNames, "ami_rows" => $amiRows, "ami_table_present" => $amiTablePresent], JSON_THROW_ON_ERROR);
if (strlen($encoded) > 1044480) { throw new \RuntimeException("Scoped installation recovery metadata exceeds its bounded private snapshot; no integration was changed"); }
echo $encoded;
exit(0);
' >"$RECOVERY_DIR/module-registration.json" || return 1
  chmod 0600 "$RECOVERY_DIR/module-registration.json" || return 1
  /usr/bin/python3 -I "$RECOVERY_TOOL" --snapshot "$RECOVERY_DIR/static" --approval "$UPGRADE_TRUST_DIR/previous-root-approval.json" snapshot || return 1
  seal_install_recovery_inputs || return 1
}

prepare_module_ami_intent() {
  /usr/bin/python3 -I - "$INSTALL_BOOTSTRAP_DIR/sls_config_crypto.py" "$TRANSACTION_TOOL" "$CONFIG_FILE" "$RECOVERY_DIR" <<'PYAMIINTENT'
import hashlib, pathlib, re, sys, types
def helper(path, name):
    path = pathlib.Path(path); module = types.ModuleType(name); module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module
crypto = helper(sys.argv[1], 'intent_config_crypto')
journal = helper(sys.argv[2], 'intent_transaction')
root = pathlib.Path(sys.argv[4])
saved = journal.decode_json(journal.read(root / 'module-registration.json', 1048576))
settings = crypto.read_config(pathlib.Path(sys.argv[3]))
ami = settings.get('ami', {})
name, secret = ami.get('username'), ami.get('password')
if isinstance(name, str): name = name.strip(" \t\r\n\x00\x0b")
if isinstance(secret, str): secret = secret.strip(" \t\r\n\x00\x0b")
if (saved.get('schema') != 3 or not isinstance(name, str) or not re.fullmatch(r'[a-z0-9_.-]{1,64}', name)
        or name not in saved.get('ami_names', []) or not isinstance(secret, str)
        or not re.fullmatch(r'[\x21-\x7e]{1,128}', secret)):
    raise SystemExit('AMI registration intent does not match the protected snapshot and configuration')
value = {'schema': 1, 'username': name, 'secret_sha256': hashlib.sha256(secret.encode()).hexdigest()}
path = root / 'module-ami-intent.json'
try: previous = journal.decode_json(journal.read(path))
except FileNotFoundError: previous = None
if previous is not None and previous != value:
    raise SystemExit('The protected AMI registration intent already contains different evidence')
if previous is None: journal.atomic(path, value)
print('Protected AMI registration intent retained; no credential was logged.')
PYAMIINTENT
}

registration_recovery_input() {
  /usr/bin/python3 -I - "$TRANSACTION_TOOL" "$RECOVERY_DIR" <<'PYREGISTRATION'
import json, pathlib, sys, types
path = pathlib.Path(sys.argv[1]); journal = types.ModuleType('registration_transaction'); journal.__file__ = str(path)
exec(compile(path.read_bytes(), str(path), 'exec'), journal.__dict__)
root = pathlib.Path(sys.argv[2])
value = journal.decode_json(journal.read(root / 'module-registration.json', 1048576))
if value.get('schema') == 3:
    try: intent = journal.decode_json(journal.read(root / 'module-ami-intent.json'))
    except FileNotFoundError: intent = None
    value['ami_intent'] = intent
body = json.dumps(value, separators=(',', ':'), allow_nan=False)
if len(body.encode()) > 1048576:
    raise SystemExit('Scoped recovery input exceeds its private bound')
print(body)
PYREGISTRATION
}

verify_install_idle_history() {
  assert_worker_coordination || {
    log 'The installer worker guard exited unexpectedly; preserve recovery evidence.'
    return 1
  }
  local attempt maximum=10
  local -a inspection=(--data "$DATA_DIR" inspect --baseline "$RECOVERY_DIR/idle-before.json")
  if [ -n "$RECOVERY_HISTORY_EVIDENCE" ]; then inspection+=(--history-evidence "$RECOVERY_HISTORY_EVIDENCE"); fi
  if [ -n "$RECOVERY_HISTORY_LOSS_APPROVAL" ]; then inspection+=(--history-loss-approval "$RECOVERY_HISTORY_LOSS_APPROVAL"); fi
  # Repair inspection is for the pre-install baseline only. A completed
  # installation or rollback must have its ledger and a fresh collector
  # heartbeat. Cron can briefly launch a worker which exits at the held guard;
  # require the complete strict check after that process has exited as well.
  for ((attempt=1; attempt<=maximum; attempt++)); do
    assert_worker_coordination || return 1
    if /usr/bin/python3 -I "$IDLE_TOOL" "${inspection[@]}" >/dev/null; then
      assert_worker_coordination || return 1
      return 0
    fi
    assert_worker_coordination || return 1
    if [ "$attempt" -lt "$maximum" ]; then sleep 1; fi
  done
  return 1
}

restore_module_registration() {
  [ -n "$RECOVERY_DIR" ] && [ -f "$RECOVERY_DIR/module-registration.json" ] || return 1
  # Root supplies a read-only stdin descriptor; PHP runs as asterisk and never
  # receives access to the private recovery directory or executable snapshots.
  php -r '
require "/etc/freepbx.conf";
$raw = stream_get_contents(STDIN, 1048577);
if (strlen($raw) > 1048576) { throw new \RuntimeException("Oversized registration snapshot"); }
$data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
if (!in_array($data["schema"] ?? null, [2, 3], true) || !array_key_exists("row", $data)) { throw new \RuntimeException("Invalid registration snapshot"); }
$row = $data["row"];
if ($row !== null && (!is_array($row) || ($row["modulename"] ?? "") !== "slsmassnotifyserver")) { throw new \RuntimeException("Invalid module registration identity"); }
foreach (($row ?? []) as $column => $value) {
    if (!preg_match("/^[A-Za-z_][A-Za-z0-9_]*$/D", $column) || !(is_scalar($value) || $value === null)) { throw new \RuntimeException("Invalid registration column"); }
}
$filenames = ["custom/SLS_Mass_Notify_Paging_Tone_Opening", "custom/SLS_Mass_Notify_Paging_Tone_Closing", "custom/SLS_Mass_Notify_NWS_Alert", "custom/SLS_Mass_Notify_Lightning_Alert", "custom/Paging_Tone_Opening", "custom/Paging_Tone_Closing", "custom/NWS_alert", "custom/Lightning_alert"];
if (!is_array($data["recordings"] ?? null) || array_keys($data["recordings"]) !== $filenames || !is_array($data["backup_enrollment"] ?? null)) { throw new \RuntimeException("Invalid scoped integration snapshot"); }
$validateRow = static function ($candidate) {
    if (!is_array($candidate) || !$candidate) { throw new \RuntimeException("Invalid recovery row"); }
    foreach ($candidate as $column => $value) {
        if (!preg_match("/^[A-Za-z_][A-Za-z0-9_]*$/D", $column) || !(is_scalar($value) || $value === null)) { throw new \RuntimeException("Invalid recovery column"); }
    }
};
foreach ($data["recordings"] as $filename => $rows) {
    if (!is_array($rows) || count($rows) > 100) { throw new \RuntimeException("Invalid recording recovery rows"); }
    foreach ($rows as $recording) { $validateRow($recording); if (($recording["filename"] ?? "") !== $filename) { throw new \RuntimeException("Recording recovery identity mismatch"); } }
}
foreach ($data["backup_enrollment"] as $entry) {
    if (!is_array($entry) || !is_string($entry["job"] ?? null) || $entry["job"] === "" || strlen($entry["job"]) > 128 || preg_match("/[\x00-\x1f\x7f]/", $entry["job"]) || !is_bool($entry["present"] ?? null) || !(is_scalar($entry["value"] ?? null) || ($entry["value"] ?? null) === null)) { throw new \RuntimeException("Invalid backup enrollment recovery entry"); }
}
$amiNames = []; $amiRows = []; $amiIntent = null; $amiRender = false;
$amiColumns = ["manager_id", "name", "secret", "deny", "permit", "read", "write", "writetimeout"];
$validateAmiRow = static function ($entry, $name) use ($amiColumns) {
    if (!is_array($entry) || count($entry) !== count($amiColumns) || array_diff(array_keys($entry), $amiColumns)
        || ($entry["name"] ?? null) !== $name || !preg_match("/^[1-9][0-9]{0,19}$/D", (string)($entry["manager_id"] ?? ""))) {
        throw new \RuntimeException("Invalid scoped native AMI recovery row");
    }
    foreach ($entry as $value) {
        if (!(is_string($value) || is_int($value) || $value === null) || is_string($value) && strlen($value) > 4096) {
            throw new \RuntimeException("Invalid native AMI recovery value");
        }
    }
};
$ownedAmiRow = static function ($entry, $name, $secretHash, $canonical) {
    if (($entry["name"] ?? null) !== $name || !is_string($entry["secret"] ?? null) || $entry["secret"] === ""
        || !hash_equals($secretHash, hash("sha256", $entry["secret"]))
        || !in_array($entry["writetimeout"] ?? null, [1000, "1000"], true)
        || !is_string($entry["read"] ?? null) || ($entry["write"] ?? null) !== $entry["read"]
        || !in_array($entry["read"], ["system,call,originate", "system,call,originate,reporting"], true)
        || !is_string($entry["permit"] ?? null) || !is_string($entry["deny"] ?? null)) { return false; }
    if ($canonical) {
        return $entry["read"] === "system,call,originate,reporting"
            && $entry["permit"] === "127.0.0.1/255.255.255.255&::1/128"
            && $entry["deny"] === "0.0.0.0/0.0.0.0&::/0";
    }
    $permit = explode("&", $entry["permit"]); $deny = explode("&", $entry["deny"]);
    return $permit !== [] && !array_diff($permit, ["127.0.0.1/255.255.255.255", "127.0.0.1/32", "::1/128"])
        && (in_array("0.0.0.0/0.0.0.0", $deny, true) || in_array("0.0.0.0/0", $deny, true))
        && (!in_array("::1/128", $permit, true) || in_array("::/0", $deny, true));
};
if ($data["schema"] === 3) {
    $amiNames = $data["ami_names"] ?? null; $amiRows = $data["ami_rows"] ?? null;
    if (!is_array($amiNames) || !array_is_list($amiNames) || count($amiNames) < 1 || count($amiNames) > 2
        || count(array_unique($amiNames)) !== count($amiNames) || !in_array("sls_mass_notify", $amiNames, true)
        || !is_array($amiRows) || count($amiRows) !== count($amiNames) || array_diff(array_keys($amiRows), $amiNames)
        || !is_bool($data["ami_table_present"] ?? null)) { throw new \RuntimeException("Invalid scoped AMI recovery snapshot"); }
    $priorIds = [];
    foreach ($amiNames as $name) {
        if (!is_string($name) || !preg_match("/^[a-z0-9_.-]{1,64}$/D", $name)
            || !is_array($amiRows[$name]) || !array_is_list($amiRows[$name]) || count($amiRows[$name]) > 1
            || !$data["ami_table_present"] && $amiRows[$name]) { throw new \RuntimeException("Invalid scoped AMI recovery identity"); }
        foreach ($amiRows[$name] as $entry) {
            $validateAmiRow($entry, $name);
            $id = (string)$entry["manager_id"];
            if (isset($priorIds[$id])) { throw new \RuntimeException("Ambiguous prior AMI account identifier"); }
            $priorIds[$id] = true;
        }
    }
    $amiIntent = $data["ami_intent"] ?? null;
    if ($amiIntent !== null) {
        if (!is_array($amiIntent) || count($amiIntent) !== 3 || ($amiIntent["schema"] ?? null) !== 1
            || !is_string($amiIntent["username"] ?? null) || !in_array($amiIntent["username"], $amiNames, true)
            || !is_string($amiIntent["secret_sha256"] ?? null) || !preg_match("/^[a-f0-9]{64}$/D", $amiIntent["secret_sha256"])) {
            throw new \RuntimeException("Invalid protected AMI registration intent");
        }
        $expectedNames = array_values(array_unique([$amiIntent["username"], "sls_mass_notify"]));
        if (count($expectedNames) !== count($amiNames) || array_diff($amiNames, $expectedNames)) {
            throw new \RuntimeException("AMI snapshot identities differ from the protected registration intent");
        }
    }
}
$db = \FreePBX::Database();
$db->beginTransaction();
try {
    $amiPlan = [];
    if ($data["schema"] === 3) {
        $table = $db->prepare("SHOW TABLES LIKE ?"); $table->execute(["manager"]);
        $tablePresent = $table->fetchColumn() !== false;
        if (!$tablePresent && $data["ami_table_present"]) { throw new \RuntimeException("The prior native Manager table is missing; preserve recovery evidence"); }
        $lookup = $tablePresent ? $db->prepare("SELECT * FROM manager WHERE name = ? FOR UPDATE") : null;
        foreach ($amiNames as $name) {
            $current = [];
            if ($lookup) { $lookup->execute([$name]); $current = $lookup->fetchAll(\PDO::FETCH_ASSOC); }
            if (count($current) > 1) { throw new \RuntimeException("The current scoped AMI account is ambiguous"); }
            foreach ($current as $entry) { $validateAmiRow($entry, $name); }
            $before = $amiRows[$name];
            if ($current === $before) { continue; }
            if ($amiIntent === null
                || $before && !$ownedAmiRow($before[0], $name, $amiIntent["secret_sha256"], false)
                || $current && !$ownedAmiRow($current[0], $name, $amiIntent["secret_sha256"], true)) {
                throw new \RuntimeException("Native AMI account changed independently; it was not overwritten");
            }
            $amiPlan[$name] = ["before" => $before, "current" => $current];
        }
        $willDelete = [];
        foreach ($amiPlan as $name => $plan) { if ($plan["current"]) { $willDelete[(string)$plan["current"][0]["manager_id"]] = $name; } }
        foreach ($amiPlan as $name => $plan) {
            if (!$plan["before"]) { continue; }
            $id = (string)$plan["before"][0]["manager_id"];
            $collision = $db->prepare("SELECT * FROM manager WHERE manager_id = ? FOR UPDATE"); $collision->execute([$id]);
            foreach ($collision->fetchAll(\PDO::FETCH_ASSOC) as $entry) {
                if (!isset($willDelete[$id]) || ($entry["name"] ?? null) !== $willDelete[$id]) {
                    throw new \RuntimeException("A prior AMI identifier is now owned by another account; it was not overwritten");
                }
            }
        }
        // Delete only the exact candidate-owned row inspected above. This also
        // detects a concurrent native Manager edit before a scoped replacement.
        foreach ($amiPlan as $plan) {
            if (!$plan["current"]) { continue; }
            $entry = $plan["current"][0];
            $delete = $db->prepare("DELETE FROM manager WHERE manager_id = ? AND name = ? AND secret = ? AND deny = ? AND permit = ? AND `read` = ? AND `write` = ? AND writetimeout = ?");
            $delete->execute(array_map(static function ($key) use ($entry) { return $entry[$key]; }, $amiColumns));
            if ($delete->rowCount() !== 1) { throw new \RuntimeException("The scoped AMI account changed during restoration"); }
        }
        foreach ($amiPlan as $plan) {
            foreach ($plan["before"] as $entry) {
                $columns = implode(",", array_map(static function ($value) { return "`" . $value . "`"; }, array_keys($entry)));
                $marks = implode(",", array_fill(0, count($entry), "?"));
                $db->prepare("INSERT INTO manager (" . $columns . ") VALUES (" . $marks . ")")->execute(array_values($entry));
            }
        }
        $amiRender = $tablePresent && $amiIntent !== null;
    }
    $db->prepare("DELETE FROM modules WHERE modulename = ?")->execute(["slsmassnotifyserver"]);
    if ($row !== null) {
        $columns = implode(",", array_map(static function ($value) { return "`" . $value . "`"; }, array_keys($row)));
        $marks = implode(",", array_fill(0, count($row), "?"));
        $db->prepare("INSERT INTO modules (" . $columns . ") VALUES (" . $marks . ")")->execute(array_values($row));
    }
    $exists = $db->prepare("SHOW TABLES LIKE ?"); $exists->execute(["recordings"]);
    $recordingsPresent = (bool)$exists->fetchColumn();
    if (!$recordingsPresent && array_filter($data["recordings"])) { throw new \RuntimeException("Saved System Recordings cannot be restored because their table is unavailable"); }
    $sameRecording = static function ($left, $right) {
        if (count($left) !== count($right) || array_diff_key($left, $right) || array_diff_key($right, $left)) { return false; }
        foreach ($right as $key => $value) {
            if ($key === "id" ? (string)$left[$key] !== (string)$value : $left[$key] !== $value) { return false; }
        }
        return true;
    };
    $recordingPlan = []; $retainedAdditionalRecordings = 0; $requiredRecordingIds = [];
    if ($recordingsPresent) {
        $lookup = $db->prepare("SELECT * FROM recordings WHERE filename = ? ORDER BY id");
        $lookupId = $db->prepare("SELECT * FROM recordings WHERE id = ?");
    }
    foreach ($recordingsPresent ? $data["recordings"] : [] as $filename => $rows) {
        $lookup->execute([$filename]); $current = $lookup->fetchAll(\PDO::FETCH_ASSOC);
        if (count($current) > 100) { throw new \RuntimeException("Current System Recordings exceed the bounded recovery inventory"); }
        $byId = [];
        foreach ($current as $recording) {
            $validateRow($recording);
            $id = (string)($recording["id"] ?? "");
            if (!preg_match("/^[1-9][0-9]{0,19}$/D", $id) || isset($byId[$id])) { throw new \RuntimeException("Ambiguous native System Recording identifier"); }
            $byId[$id] = $recording;
        }
        $originalIds = [];
        foreach ($rows as $before) {
            $id = (string)($before["id"] ?? "");
            if (!preg_match("/^[1-9][0-9]{0,19}$/D", $id) || isset($requiredRecordingIds[$id])) { throw new \RuntimeException("Invalid or duplicate saved System Recording identifier"); }
            $requiredRecordingIds[$id] = true; $originalIds[$id] = true;
            if (!isset($byId[$id])) {
                $lookupId->execute([$id]);
                if ($lookupId->fetchAll(\PDO::FETCH_ASSOC)) { throw new \RuntimeException("A saved System Recording ID is now owned independently; it was not replaced"); }
                $recordingPlan[] = ["before" => $before, "current" => null];
                continue;
            }
            $observed = $byId[$id];
            if ($sameRecording($observed, $before)) { continue; }
            $authored = $before;
            if (strpos($filename, "custom/SLS_Mass_Notify_") !== 0
                || strpos((string)($before["displayname"] ?? ""), "SLS Mass Notify - ") !== 0
                || strpos((string)($before["description"] ?? ""), "Default Southland Servers ") !== 0) {
                throw new \RuntimeException("Required System Recording changed independently; it was preserved");
            }
            $authored["displayname"] = str_replace("SLS Mass Notify - ", "SLL Mass Notify Server - ", $before["displayname"]);
            $authored["description"] = str_replace("Default Southland Servers ", "Default Southland Labs ", $before["description"]);
            if (!$sameRecording($observed, $authored)) { throw new \RuntimeException("Required System Recording changed beyond the authored label transition; it was preserved"); }
            $recordingPlan[] = ["before" => $before, "current" => $observed];
        }
        // A later native IVR, ring group, compound recording or other module
        // may already reference a new ID. Absence from the old snapshot never
        // authorizes deleting additional rows or their shared sound files.
        $retainedAdditionalRecordings += count(array_diff_key($byId, $originalIds));
    }
    foreach ($recordingPlan as $plan) {
        $before = $plan["before"];
        if ($plan["current"] === null) {
            $columns = implode(",", array_map(static function ($value) { return "`" . $value . "`"; }, array_keys($before)));
            $marks = implode(",", array_fill(0, count($before), "?"));
            $db->prepare("INSERT INTO recordings (" . $columns . ") VALUES (" . $marks . ")")->execute(array_values($before));
        } else {
            $where = []; $parameters = [$before["displayname"], $before["description"]];
            foreach ($plan["current"] as $column => $value) {
                $where[] = "(`" . $column . "` = ? OR (`" . $column . "` IS NULL AND ? IS NULL))";
                $parameters[] = $value; $parameters[] = $value;
            }
            $update = $db->prepare("UPDATE recordings SET displayname = ?, description = ? WHERE " . implode(" AND ", $where));
            $update->execute($parameters);
            if ($update->rowCount() !== 1) { throw new \RuntimeException("Required System Recording changed during exact-row restoration"); }
        }
    }
    foreach ($recordingsPresent ? $data["recordings"] : [] as $filename => $rows) {
        $lookup->execute([$filename]); $verified = $lookup->fetchAll(\PDO::FETCH_ASSOC);
        foreach ($rows as $before) {
            $matches = array_values(array_filter($verified, static function ($entry) use ($before) { return (string)($entry["id"] ?? "") === (string)$before["id"]; }));
            if (count($matches) !== 1 || !$sameRecording($matches[0], $before)) { throw new \RuntimeException("A required prior System Recording could not be verified; preserve recovery evidence"); }
        }
    }
    $db->commit();
    if ($retainedAdditionalRecordings > 0) {
        fwrite(STDERR, "Recovery retained " . $retainedAdditionalRecordings . " additional native System Recording row(s) to preserve external references; required prior IDs were verified.\n");
    }
} catch (\Throwable $error) { if ($db->inTransaction()) { $db->rollBack(); } throw $error; }
if ($amiRender) {
    // Render only native Manager configuration from its recovered database.
    // Retry this even when a previous attempt committed rows but file output
    // failed. No SLL install/uninstall or general reload hooks are invoked.
    $manager = \FreePBX::Manager();
    $configuration = $manager->genConfig();
    if (!is_array($configuration) || !is_array($configuration["manager_additional.conf"] ?? null)) {
        throw new \RuntimeException("Native Manager configuration generation failed during recovery");
    }
    $manager->writeConfig(["manager_additional.conf" => $configuration["manager_additional.conf"]]);
}
if ($data["backup_enrollment"]) {
    $class = "\\FreePBX\\modules\\Slsmassnotifyserver";
    if (class_exists($class, false) && method_exists($class, "restoreFreePbxBackupEnrollment")) {
        // An already loaded current class supplies the same checked contract.
        // Do not force-load it: recovery may just have restored an older or
        // disabled public module which predates this method.
        $module = new $class(\FreePBX::Create());
        $module->restoreFreePbxBackupEnrollment($data["backup_enrollment"]);
    } else {
        $backup = \FreePBX::Create()->Backup;
        $jobs = (array)$backup->getAll("backupList");
        $enabled = static function ($value) { return in_array(strtolower(trim((string)$value)), ["1", "true", "yes", "on"], true); };
        foreach ($data["backup_enrollment"] as $entry) {
            if (!array_key_exists("value", $entry) || !$entry["present"] && $entry["value"] !== null) {
                throw new \RuntimeException("Invalid original backup enrollment value");
            }
            $job = $entry["job"];
            if (!array_key_exists($job, $jobs) || $entry["present"] && $enabled($entry["value"])) { continue; }
            $selected = (array)$backup->getAll("modules_" . $job);
            // A native fresh DB_Helper/PDO read returns the authored true as
            // string1; its same-process cache can retain booltrue or integer1.
            // Other spellings remain independently authored selections.
            if (!in_array($selected["slsmassnotifyserver"] ?? null, [true, 1, "1"], true)) { continue; }
            if ($entry["present"]) { $backup->setConfig("slsmassnotifyserver", $entry["value"], "modules_" . $job); }
            else { $backup->delConfig("slsmassnotifyserver", "modules_" . $job); }
        }
    }
}
require_once "/var/www/html/admin/modules/dashboard/classes/DashboardHooks.class.php";
$dashboard = \FreePBX::Dashboard();
$order = $dashboard->getConfig("visualorder");
$dashboard->setConfig("allhooks", \DashboardHooks::genHooks(is_array($order) ? $order : []));
exit(0);
' < <(registration_recovery_input) >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1
}

restore_previous_module_tree() {
  /usr/bin/python3 -I "${RECOVERY_PROGRAM_DIR:-$INSTALL_BOOTSTRAP_DIR}/sls_upgrade_trust.py" \
    --workspace "$UPGRADE_TRUST_DIR" --restore-previous-module \
    --module-backup "$MODULE_BACKUP_DIR" --had-existing-module "$HAD_EXISTING_MODULE"
}

rollback_module_install() {
  ROLLBACK_ATTEMPTED=1
  [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination || {
    rollback_failure 'worker leases were lost before static recovery'; return 1;
  }
  log "Restoring preserved static integration and module registration without running previous install/uninstall hooks."
  if [ -z "$RECOVERY_TOOL" ] || [ -z "$RECOVERY_DIR" ]; then
    rollback_failure "the authenticated recovery helper or snapshot is unavailable"
    return 1
  fi
  # A power loss can occur after the fresh candidate rename but before its
  # completion marker. The staged source is copied and may still be present.
  # Idempotent restoration verifies either the prior tree or prior absence, so
  # every recorded private backup must be inspected, even without that marker.
  if [ "$MODULE_ACTIVATED" -eq 1 ] || [ -n "$MODULE_BACKUP_DIR" ]; then
    restore_previous_module_tree || rollback_failure "the previous module directory could not be restored"
  fi
  [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination || { rollback_failure 'worker leases were lost during module recovery'; return 1; }
  /usr/bin/python3 -I "$RECOVERY_TOOL" --snapshot "$RECOVERY_DIR/static" restore >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 \
    || rollback_failure "the static integration snapshot could not be fully restored"
  [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination || { rollback_failure 'worker leases were lost during static recovery'; return 1; }
  restore_module_registration || rollback_failure "the original module/AMI registration and Dashboard hook index could not be restored"
  [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination || { rollback_failure 'worker leases were lost during native registration recovery'; return 1; }
  asterisk -rx "manager reload" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || rollback_failure "restored Asterisk manager configuration did not reload"
  asterisk -rx "dialplan reload" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || rollback_failure "restored Asterisk dialplan did not reload"
  /usr/bin/python3 -I "$RECOVERY_TOOL" --snapshot "$RECOVERY_DIR/static" restore-services >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 \
    || rollback_failure "the prior collector/Apache process state could not be restored safely"
  refresh_served_php_workers || rollback_failure "the restored PHP-FPM serving processes could not be refreshed safely"
  [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination || { rollback_failure 'worker leases were lost during service recovery'; return 1; }
  /usr/bin/python3 -I "$RECOVERY_TOOL" --snapshot "$RECOVERY_DIR/static" verify >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 \
    || rollback_failure "restored static integration differs from its preserved snapshot"
  if [ "$HAD_EXISTING_MODULE" -eq 1 ] && [ "$ROLLBACK_FAILED" -eq 0 ]; then
    verify_local_api_route /api/sipnotify/desktop '^(401|429)$' '401/429' 'Recovered Desktop API' \
      || rollback_failure "the recovered Desktop API did not pass its read-only route check"
    verify_local_api_route /api/sls-mass-notify/ '^(401|403|405|429)$' '401/403/405/429' 'Recovered Control API' \
      || rollback_failure "the recovered Control API did not pass its read-only route check"
  fi
  verify_install_idle_history || rollback_failure "recovered notification idleness or retained phone history could not be verified"
  if [ "$ROLLBACK_FAILED" -eq 0 ]; then
    [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination || { rollback_failure 'worker leases were lost before maintenance recovery'; return 1; }
    /usr/bin/python3 -I "${RECOVERY_PROGRAM_DIR:-$INSTALL_BOOTSTRAP_DIR}/sls_upgrade_trust.py" --workspace "$UPGRADE_TRUST_DIR" --verify-previous >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 \
      || rollback_failure "the recovered SLS, Dashboard or Framework files differ from their pre-install authenticated approvals"
  fi
  if [ "$ROLLBACK_FAILED" -eq 0 ]; then
    /usr/bin/python3 -I "$RECOVERY_TOOL" --snapshot "$RECOVERY_DIR/static" restore-maintenance >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 \
      || rollback_failure "previous root maintenance could not be restored against its pre-install authenticated approval; root maintenance remains disabled"
  fi
  if [ "$ROLLBACK_FAILED" -eq 0 ]; then
    ROLLBACK_VERIFIED=1
    if [ -n "$RECOVERY_HISTORY_LOSS_APPROVAL" ]; then
      log 'Rollback completed. The authenticated previous runtime and maintenance schedule were restored. Active/pending settings and remaining history were preserved; the administrator-accepted historical loss and original evidence are retained in this transaction.'
    else
      log 'Rollback completed. The authenticated previous runtime and its maintenance schedule were restored; active/pending settings and delivery history were preserved.'
    fi
    return 0
  fi
  return 1
}


verify_recovery_configuration() {
  [ -n "$CONFIG_HASH_BEFORE" ] || [ -n "$PENDING_CONFIG_STATE" ] || return 0
  local targets
  local -a values=()
  targets="$(/usr/bin/python3 -I - "$TRANSACTION_TOOL" "$RECOVERY_DIR" "$CONFIG_HASH_BEFORE" \
      "$CONFIG_SNAPSHOT" "$CONFIG_FILE" "$PENDING_CONFIG_STATE" "$PENDING_CONFIG_HASH" \
      "$PENDING_CONFIG_SNAPSHOT" "$PENDING_CONFIG_PATH" <<'PYCONFIGRECOVERY'
import pathlib, sys, types
helper = pathlib.Path(sys.argv[1])
module = types.ModuleType('sll_configuration_recovery'); module.__file__ = str(helper)
exec(compile(helper.read_bytes(), str(helper), 'exec'), module.__dict__)
targets = module.prepare_configuration_recovery(*sys.argv[2:])
for name in ('active_snapshot', 'active_sha256', 'pending_snapshot', 'pending_sha256'):
    print(targets[name])
PYCONFIGRECOVERY
  )" || return 1
  mapfile -t values <<<"$targets"
  [ "${#values[@]}" -eq 4 ] || return 1
  CONFIG_RECOVERY_SNAPSHOT="${values[0]}"; CONFIG_RECOVERY_HASH="${values[1]}"
  PENDING_RECOVERY_SNAPSHOT="${values[2]}"; PENDING_RECOVERY_HASH="${values[3]}"
}

restore_configuration_under_keeper() {
  [ -n "$CONFIG_HASH_BEFORE" ] || [ -n "$PENDING_CONFIG_STATE" ] || return 0
  local request response targets
  local -a values=()
  # Reacquire after independent keeper loss before interpreting current settings.
  # Only this actual lease owner may derive and publish recovery targets.
  if ! assert_worker_coordination; then
    # Keep the root caller's shared descriptions leased while replacing a
    # dead coordinator. Closing them here would create an exclusion gap.
    stop_worker_guard
    [ -n "$WORKER_GUARD_TOOL" ] || WORKER_GUARD_TOOL="${TRANSACTION_TOOL%/*}/sls_install_guard.py"
    DATA_DIR="${CONFIG_FILE%/*}"
    acquire_worker_coordination || return 1
    acquire_settings_coordination || return 1
  fi
  request="$(/usr/bin/python3 -I - "$RECOVERY_DIR" "$CONFIG_HASH_BEFORE" "$CONFIG_SNAPSHOT" "$CONFIG_FILE" \
      "$PENDING_CONFIG_STATE" "$PENDING_CONFIG_HASH" "$PENDING_CONFIG_SNAPSHOT" \
      "${PENDING_CONFIG_PATH:-${CONFIG_FILE%/*}/mass-notifications.pending.config}" <<'PYRESTOREREQUEST'
import json, sys
print(json.dumps(sys.argv[1:], separators=(',', ':')))
PYRESTOREREQUEST
  )" || return 1
  ( trap '' PIPE; printf 'restore-settings %s\n' "$request" >&"$WORKER_LOCK_KEEPALIVE_FD" ) 2>/dev/null || return 1
  IFS= read -r -t 120 response <&"$WORKER_LOCK_RESPONSE_FD" || return 1
  if [[ "$response" == 'rejected-settings '* ]]; then
    log "Protected configuration recovery refused: ${response#rejected-settings }"
    return 1
  fi
  [[ "$response" == 'restored-settings '* ]] || return 1
  targets="$(/usr/bin/python3 -I - "${response#restored-settings }" <<'PYRESTORERESPONSE'
import json, sys
value=json.loads(sys.argv[1])
names=('active_snapshot','active_sha256','pending_snapshot','pending_sha256')
if type(value) is not dict or set(value)!=set(names) or any(type(value[name]) is not str or '\n' in value[name] for name in names):
    raise SystemExit('Invalid guarded configuration recovery response')
for name in names: print(value[name])
PYRESTORERESPONSE
  )" || return 1
  mapfile -t values <<<"$targets"
  [ "${#values[@]}" -eq 4 ] || return 1
  CONFIG_RECOVERY_SNAPSHOT="${values[0]}"; CONFIG_RECOVERY_HASH="${values[1]}"
  PENDING_RECOVERY_SNAPSHOT="${values[2]}"; PENDING_RECOVERY_HASH="${values[3]}"
  assert_worker_coordination
}

guard_config_on_exit() {
  local status=$? current_hash
  INSTALL_EXIT_CODE="$status"
  trap - EXIT
  # A failed recovery command must not interrupt later config restoration or
  # delete the only recovery copy. Preserve the original install exit status.
  set +e
  if [ "$INSTALL_COMMITTED" -eq 0 ] && ! restore_configuration_under_keeper; then
    log 'CRITICAL: coordinated configuration recovery stopped. Preserve live settings, durable targets and original transaction evidence; no further runtime restoration was started.'
    persist_install_transaction recovery_failed || true
    INSTALL_EXIT_CODE=1
    INSTALL_ERROR_CATEGORY="install_recovery_config_conflict"
    INSTALL_SOLUTION="Preserve the current active/pending settings and original protected snapshots. Review their differences before retrying authenticated recovery; recovery will not overwrite an unrecognized administrator edit."
    record_install_failure
    release_worker_coordination
    exit 1
  fi
  # EXIT status alone is not a commit marker. A premature successful exit or
  # a signal observed after a successful child must still restore changed state.
  if { [ "$STATIC_MUTATION_STARTED" -eq 1 ] || [ -n "$INSTALL_TRANSACTION_DIR" ]; } \
    && [ "$INSTALL_COMMITTED" -eq 0 ] && [ "$status" -eq 0 ]; then status=1; fi

  if [ "$status" -ne 0 ] && [ "$SYSTEM_TIMEZONE_CHANGED" -eq 1 ] && [ -n "$ORIGINAL_SYSTEM_TIMEZONE" ]; then
    if set_system_timezone "$ORIGINAL_SYSTEM_TIMEZONE" \
      && timezone_names_equivalent "$(detect_system_timezone 2>/dev/null || true)" "$ORIGINAL_SYSTEM_TIMEZONE"; then
      log "The installer restored the original system timezone after the failed installation."
      SYSTEM_TIMEZONE_CHANGED=0
    else
      log "CRITICAL: the installer could not restore the original system timezone '$ORIGINAL_SYSTEM_TIMEZONE'."
      log "Run: timedatectl set-timezone $ORIGINAL_SYSTEM_TIMEZONE"
      rollback_failure "the original system timezone could not be restored"
    fi
  fi

  if [ -n "$CONFIG_SNAPSHOT" ] && [ -f "$CONFIG_SNAPSHOT" ]; then
    current_hash="$(safe_config_hash "$CONFIG_FILE" 2>/dev/null || true)"
    if [ "$INSTALL_COMMITTED" -eq 1 ]; then
      if [ "$current_hash" != "${CONFIG_RECOVERY_HASH:-${CONFIG_HASH_EXPECTED:-$CONFIG_HASH_BEFORE}}" ]; then
        log 'CRITICAL: the protected central config changed after post-install verification. Preserve the installer log and configuration backups for review.'
        [ "$status" -ne 0 ] || status=1
      fi
    elif [ "$current_hash" != "${CONFIG_RECOVERY_HASH:-$CONFIG_HASH_BEFORE}" ]; then
      rollback_failure "the guarded central configuration changed after recovery; live settings were preserved"
      [ "$status" -ne 0 ] || status=1
    fi
  fi

  if [ "$PENDING_CONFIG_STATE" = present ] && ! verify_pending_config_unchanged; then
    rollback_failure "pending settings changed after guarded recovery; live pending settings were preserved"
    [ "$status" -ne 0 ] || status=1
  elif [ "$PENDING_CONFIG_STATE" = absent ] && ! verify_pending_config_unchanged; then
    rollback_failure "unexpected pending settings were preserved for administrator review"
    [ "$status" -ne 0 ] || status=1
  fi

  if [ "$status" -ne 0 ] && [ "$STATIC_MUTATION_STARTED" -eq 1 ] && [ "$INSTALL_COMMITTED" -eq 0 ]; then
    persist_install_transaction recovering || rollback_failure 'the persistent recovery journal could not be updated'
    rollback_module_install
  fi

  if [ "$ROLLBACK_ATTEMPTED" -eq 1 ] && [ -n "$CONFIG_HASH_BEFORE" ] && [ "$(safe_config_hash "$CONFIG_FILE" 2>/dev/null)" != "${CONFIG_RECOVERY_HASH:-$CONFIG_HASH_BEFORE}" ]; then
    rollback_failure "restoration changed the protected configuration"
  fi
  if [ "$ROLLBACK_ATTEMPTED" -eq 1 ] && ! verify_pending_config_unchanged; then
    rollback_failure 'restoration changed the protected pending configuration'
  fi

  if [ "$INSTALL_COMMITTED" -eq 0 ] && ! restore_freepbx_chown_permissions; then
    rollback_failure 'the original FreePBX chown configuration could not be restored; preserve the permission snapshot and review administrator changes'
    [ "$status" -ne 0 ] || status=1
  fi
  if [ "$RECOVERY_REQUEST_MODE" -eq 1 ] && [ "$STATIC_MUTATION_STARTED" -eq 0 ] && [ "$ROLLBACK_FAILED" -eq 0 ]; then
    # A crash during approved metadata preparation has no module/runtime
    # snapshot to restore. The bounded native configuration restoration above
    # completes this transaction without inventing absent central settings.
    ROLLBACK_VERIFIED=1
  fi

  # Snapshots are disposable only after an explicit commit, verified rollback,
  # or a transaction which never began changing protected state.
  if [ "$ROLLBACK_FAILED" -eq 0 ] && { [ "$INSTALL_COMMITTED" -eq 1 ] || [ "$ROLLBACK_VERIFIED" -eq 1 ] || [ "$STATIC_MUTATION_STARTED" -eq 0 ]; }; then
    local finish_phase=abandoned
    if [ "$INSTALL_COMMITTED" -eq 1 ]; then finish_phase=committed; elif [ "$ROLLBACK_VERIFIED" -eq 1 ]; then finish_phase=rolled_back; fi
    persist_install_transaction "$finish_phase" || rollback_failure 'verified completion could not be recorded durably; evidence remains protected'
  fi
  local retain_review_evidence=0 evidence_status=3
  if [ "$ROLLBACK_FAILED" -eq 0 ] && [ -n "$INSTALL_TRANSACTION_DIR" ]; then
    /usr/bin/python3 -I "$TRANSACTION_TOOL" --root "$INSTALL_TRANSACTION_ROOT" \
      --transaction "$INSTALL_TRANSACTION_DIR" preserve-evidence >/dev/null
    evidence_status=$?
    case "$evidence_status" in
      0) retain_review_evidence=1 ;;
      3) : ;;
      *) rollback_failure 'recovery evidence could not be authenticated for retention; preserve this entire transaction' ;;
    esac
  fi
  if [ "$ROLLBACK_FAILED" -eq 0 ] && { [ "$INSTALL_COMMITTED" -eq 1 ] || [ "$ROLLBACK_VERIFIED" -eq 1 ] || [ "$STATIC_MUTATION_STARTED" -eq 0 ]; }; then
    if [ "$retain_review_evidence" -eq 1 ]; then
      if [ -n "$RECOVERY_HISTORY_LOSS_APPROVAL" ]; then
        log "Administrator-accepted historical loss: all original recovery evidence and the approval receipt are retained at $INSTALL_TRANSACTION_DIR. Archive privately; they are never restored over live delivery state."
      elif [ -n "$CONFIG_RECOVERY_HASH" ] && [ -f "$RECOVERY_DIR/configuration-mfa-recovery.json" ]; then
        log "Monotonic MFA consumption was preserved. Original configuration snapshots, installer intentions, recovery targets and authenticated carrier evidence are retained at $INSTALL_TRANSACTION_DIR."
      else
        log "Authenticated manual recovery completed. Original configuration snapshots and publisher authentication evidence are retained at $INSTALL_TRANSACTION_DIR."
      fi
    else
    if [ -n "$CONFIG_SNAPSHOT" ] && [ -f "$CONFIG_SNAPSHOT" ]; then
      rm -f "$CONFIG_SNAPSHOT"
      CONFIG_SNAPSHOT=""
    fi
    if [ -n "$CONFIG_EXPECTED_SNAPSHOT" ] && [ -f "$CONFIG_EXPECTED_SNAPSHOT" ]; then
      rm -f "$CONFIG_EXPECTED_SNAPSHOT"
      CONFIG_EXPECTED_SNAPSHOT=""
    fi
    [ -z "$PENDING_CONFIG_SNAPSHOT" ] || rm -f -- "$PENDING_CONFIG_SNAPSHOT"
    [ -z "$STAGING_DIR" ] || rm -rf -- "$STAGING_DIR"
    [ -z "$MODULE_BACKUP_DIR" ] || rm -rf -- "$MODULE_BACKUP_DIR"
    [ -z "$RECOVERY_DIR" ] || rm -rf -- "$RECOVERY_DIR"
    [ -z "$INSTALL_BOOTSTRAP_DIR" ] || rm -rf -- "$INSTALL_BOOTSTRAP_DIR"
    if [ -n "$INSTALL_TRANSACTION_DIR" ]; then
      rm -f -- "$INSTALL_TRANSACTION_DIR/package.tgz" "$INSTALL_TRANSACTION_DIR/installer.sh" "$INSTALL_TRANSACTION_DIR/release-manifest.json" "$INSTALL_TRANSACTION_DIR/release-manifest.sig"
      [ -z "$UPGRADE_TRUST_DIR" ] || rm -rf -- "$UPGRADE_TRUST_DIR"
      # Only a small durable completion marker survives successful finalization.
      # Unfinished transactions retain all authentication and approval evidence.
    fi
    fi
  else
    persist_install_transaction recovery_failed || true
    [ "$status" -ne 0 ] || status=1
    log "Recovery locations: module=${MODULE_BACKUP_DIR:-none}; config=${CONFIG_SNAPSHOT:-none}; pending=${PENDING_CONFIG_SNAPSHOT:-none}; stage=${STAGING_DIR:-none}; static=${RECOVERY_DIR:-none}; helper=${INSTALL_BOOTSTRAP_DIR:-none}; approvals=${UPGRADE_TRUST_DIR:-none}."
    INSTALL_ERROR_CATEGORY="install_rollback_failed"
    if [ "$ROLLBACK_ATTEMPTED" -eq 1 ]; then
      INSTALL_SOLUTION="Recovery requires review: SLL root update/maintenance jobs remain disabled if prior authenticated execution approval or restoration could not be verified. Preserve the module, config, static-state and helper locations in the log; resolve any additional restoration failures before retrying."
    else
      INSTALL_SOLUTION="Protected preflight recovery was incomplete. Preserve the recovery locations printed in the installer log and correct the specified configuration or timezone restoration failure before retrying."
    fi
  fi
  [ -z "$DOWNLOAD_DIR" ] || rm -rf -- "$DOWNLOAD_DIR"

  if [ "$status" -ne 0 ]; then
    if [ "$RECOVERY_REQUEST_MODE" -eq 1 ] && [ "$ROLLBACK_VERIFIED" -eq 1 ] && [ "$ROLLBACK_FAILED" -eq 0 ]; then
      clear_install_failure
      log 'Interrupted installation recovered. Rerun the normal installer to install the candidate.'
      status=0
    fi
  fi
  if [ "$status" -ne 0 ]; then
    INSTALL_EXIT_CODE="$status"
    record_install_failure
  fi

  cleanup_install_temp_root
  release_worker_coordination
  exit "$status"
}

timezone_zoneinfo_path() {
  local timezone_name="$1"

  TIMEZONE_NAME="$timezone_name" /usr/bin/python3 -I - <<'PY'
import os
import pathlib
import re

name = os.environ.get("TIMEZONE_NAME", "")
if not name or len(name) > 128 or "\x00" in name:
    raise SystemExit(1)
if name.startswith("/") or "//" in name or any(part in {"", ".", ".."} for part in name.split("/")):
    raise SystemExit(1)
if not re.fullmatch(r"[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*", name):
    raise SystemExit(1)

base = pathlib.Path("/usr/share/zoneinfo").resolve(strict=True)
candidate = base.joinpath(*name.split("/"))
resolved = candidate.resolve(strict=True)
try:
    resolved.relative_to(base)
except ValueError:
    raise SystemExit(1)
if not resolved.is_file():
    raise SystemExit(1)
print(resolved)
PY
}

validate_system_timezone() {
  local timezone_name="$1"
  local listed_timezones

  timezone_zoneinfo_path "$timezone_name" >/dev/null 2>&1 || return 1
  [ -x /usr/bin/timedatectl ] || return 1
  listed_timezones="$(/usr/bin/timedatectl list-timezones --no-pager 2>/dev/null || true)"
  [ -n "$listed_timezones" ] || return 1
  LC_ALL=C grep -Fxq -- "$timezone_name" <<<"$listed_timezones"
}

detect_system_timezone() {
  local timezone_name=""

  if [ -x /usr/bin/timedatectl ]; then
    timezone_name="$(/usr/bin/timedatectl show --property=Timezone --value 2>/dev/null || true)"
  fi
  if ! timezone_zoneinfo_path "$timezone_name" >/dev/null 2>&1; then
    if [ -r /etc/timezone ] && [ ! -L /etc/timezone ]; then
      timezone_name="$(sed -n '1{s/[[:space:]]*$//;p;q;}' /etc/timezone)"
    fi
  fi
  timezone_zoneinfo_path "$timezone_name" >/dev/null 2>&1 || return 1
  printf '%s\n' "$timezone_name"
}

timezone_names_equivalent() {
  local left="$1"
  local right="$2"
  local left_path right_path

  [ -n "$left" ] && [ -n "$right" ] || return 1
  left_path="$(timezone_zoneinfo_path "$left" 2>/dev/null || true)"
  right_path="$(timezone_zoneinfo_path "$right" 2>/dev/null || true)"
  [ -n "$left_path" ] && [ "$left_path" = "$right_path" ]
}

set_system_timezone() {
  local timezone_name="$1"

  /usr/bin/timedatectl set-timezone "$timezone_name"
}

configure_system_timezone() {
  local detected_timezone requested_timezone confirmed_timezone

  detected_timezone="$(detect_system_timezone 2>/dev/null || true)"
  [ -n "$detected_timezone" ] || {
    log "The installer could not detect a valid IANA system timezone through timedatectl and /usr/share/zoneinfo."
    return 1
  }
  ORIGINAL_SYSTEM_TIMEZONE="$detected_timezone"
  log "Detected system timezone: $detected_timezone"

  requested_timezone="$REQUESTED_SYSTEM_TIMEZONE"

  if [ -z "$requested_timezone" ]; then
    if [ ! -t 0 ] || [ ! -t 1 ]; then
      log "Noninteractive install: keeping $detected_timezone. Set SLS_MASS_NOTIFY_TIMEZONE to a listed IANA timezone to change it explicitly."
    else
      log "System timezone confirmed: $detected_timezone"
    fi
    CONFIRMED_SYSTEM_TIMEZONE="$detected_timezone"
    return 0
  fi

  if ! validate_system_timezone "$requested_timezone"; then
    log "The requested system timezone is not a valid listed IANA timezone."
    log "Choose an exact value from: timedatectl list-timezones"
    return 1
  fi
  if timezone_names_equivalent "$detected_timezone" "$requested_timezone"; then
    log "System timezone confirmed: $detected_timezone"
    CONFIRMED_SYSTEM_TIMEZONE="$detected_timezone"
    return 0
  fi

  log "Changing system timezone from $detected_timezone to $requested_timezone."
  SYSTEM_TIMEZONE_CHANGED=1
  persist_install_transaction mutating || return 1
  set_system_timezone "$requested_timezone" || {
    log "timedatectl could not set the requested system timezone."
    return 1
  }
  confirmed_timezone="$(detect_system_timezone 2>/dev/null || true)"
  if ! timezone_names_equivalent "$confirmed_timezone" "$requested_timezone"; then
    log "System timezone verification failed after timedatectl returned success."
    if set_system_timezone "$detected_timezone" >/dev/null 2>&1 \
      && timezone_names_equivalent "$(detect_system_timezone 2>/dev/null || true)" "$detected_timezone"; then
      SYSTEM_TIMEZONE_CHANGED=0
    fi
    return 1
  fi
  CONFIRMED_SYSTEM_TIMEZONE="$confirmed_timezone"
  log "System timezone is now: $confirmed_timezone"
}

verify_confirmed_system_timezone() {
  local current_timezone

  [ -n "$CONFIRMED_SYSTEM_TIMEZONE" ] || return 1
  current_timezone="$(detect_system_timezone 2>/dev/null || true)"
  if ! timezone_names_equivalent "$current_timezone" "$CONFIRMED_SYSTEM_TIMEZONE"; then
    log "The system timezone changed unexpectedly during installation."
    return 1
  fi
  log "System timezone verified: $current_timezone"
}

require_freepbx() {
  local bootstrap_utility
  [ "${EUID:-$(id -u)}" -eq 0 ] || {
    log "Run the installer as root."
    exit 1
  }
  case "$REPAIR_ASTERISK_PACKAGES" in
    0|1) ;;
    *)
      log "SLS_MASS_NOTIFY_REPAIR_ASTERISK_PACKAGES must be 0 or 1."
      exit 1
      ;;
  esac
  [ -x /usr/sbin/fwconsole ] || {
    log "The required FreePBX CLI is unavailable at /usr/sbin/fwconsole. This runtime cannot activate safely on a nonstandard FreePBX path."
    exit 1
  }
  [ -d /var/www/html/admin/modules ] || {
    log "/var/www/html/admin/modules not found. This does not look like a FreePBX server."
    exit 1
  }
  [ -x /usr/sbin/asterisk ] || {
    log "The required Asterisk CLI is unavailable at /usr/sbin/asterisk. This runtime cannot activate safely on a nonstandard Asterisk path."
    exit 1
  }
  [ -r /etc/freepbx.conf ] || {
    log "/etc/freepbx.conf is missing or unreadable."
    exit 1
  }
  FREEPBX_CONFIRMED=1
  # A minimal FreePBX image may not yet have the locking/process utilities or
  # PHP features needed by the coordination and bootstrap checks below. Repair
  # those only after the target has been identified as a FreePBX host, but
  # before trying to use them.
  install_bootstrap_dependencies
  for bootstrap_utility in /usr/bin/flock /usr/bin/readlink /usr/bin/timeout /usr/sbin/runuser; do
    [ -x "$bootstrap_utility" ] || {
      log "Required installation coordination utility is unavailable: $bootstrap_utility"
      exit 1
    }
  done
  php -r '
$bootstrap_settings = ["freepbx_auth" => false, "skip_astman" => true];
require "/etc/freepbx.conf";
\FreePBX::Database()->query("SELECT 1");
$managerHost = strtolower(trim((string)\FreePBX::Config()->get("ASTMANAGERHOST")));
$managerPort = (int)\FreePBX::Config()->get("ASTMANAGERPORT");
if ($managerHost === "") {
    $managerHost = "localhost";
}
if (!in_array($managerHost, ["localhost", "127.0.0.1", "::1"], true)) {
    fwrite(STDERR, "SLL Mass Notify Server requires FreePBX AMI to use a loopback host; configured ASTMANAGERHOST is unsupported.\n");
    exit(1);
}
if ($managerPort < 1 || $managerPort > 65535) {
    fwrite(STDERR, "FreePBX ASTMANAGERPORT is invalid.\n");
    exit(1);
}
exit(0);
' >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
    log "FreePBX bootstrap or database access failed. See $LOG_FILE."
    exit 1
  }
  local freepbx_version
  freepbx_version="$(fwconsole --version 2>/dev/null)" || {
    log "FreePBX could not report its version. Resolve that CLI failure before installing."
    exit 1
  }
  grep -Eq '(^|[[:space:]])17\.' <<<"$freepbx_version" || {
    log "This release requires FreePBX 17."
    exit 1
  }
  /usr/bin/php -r 'exit(function_exists("openssl_encrypt") && function_exists("openssl_decrypt") ? 0 : 1);' || {
    log "The PHP OpenSSL extension is required for protected desktop credentials."
    exit 1
  }
}

acquire_maintenance_coordination() {
  local lock_file="${SLS_MASS_NOTIFY_MAINTENANCE_LOCK:-/run/lock/sls-mass-notify-maintenance.lock}"
  local descriptor descriptor_path descriptor_target

  [[ "$lock_file" = /* ]] && [ "$lock_file" != "/" ] || {
    log "Unsafe maintenance lock path."
    exit 1
  }
  mkdir -p "$(dirname "$lock_file")"
  [ ! -L "$lock_file" ] || {
    log "Refusing a symbolic-link maintenance lock: $lock_file"
    exit 1
  }

  # A UI-triggered update is launched by the maintenance worker while it holds
  # this lock. Reuse that inherited lock instead of deadlocking the child
  # installer; direct CLI installs acquire their own lock and keep the minute
  # maintenance job out of the module/signing transaction.
  for descriptor_path in "/proc/${BASHPID}/fd/"*; do
    [ -e "$descriptor_path" ] || continue
    descriptor_target="$(readlink -f -- "$descriptor_path" 2>/dev/null || true)"
    [ "$descriptor_target" = "$lock_file" ] || continue
    descriptor="${descriptor_path##*/}"
    if [[ "$descriptor" =~ ^[0-9]+$ ]] && flock -n "$descriptor"; then
      log "Using the maintenance worker's inherited installation lock."
      INSTALL_MAINTENANCE_LOCK_FD="$descriptor"
      return 0
    fi
  done

  open_root_owned_file INSTALL_MAINTENANCE_LOCK_FD "$lock_file" || {
    log "The protected maintenance lock could not be opened safely."
    exit 1
  }
  flock -w 120 "$INSTALL_MAINTENANCE_LOCK_FD" || {
    log "Another Mass Notify maintenance or update operation is still running."
    log "Wait for it to finish, then rerun the installer."
    exit 1
  }
}

acquire_update_coordination() {
  local lock_file=/run/lock/sls-mass-notify-update.lock descriptor target
  for target in "/proc/${BASHPID}/fd/"*; do
    [ "$(readlink -f -- "$target" 2>/dev/null || true)" = "$lock_file" ] || continue
    descriptor="${target##*/}"
    if [[ "$descriptor" =~ ^[0-9]+$ ]] && flock -n "$descriptor"; then return 0; fi
  done
  open_root_owned_file INSTALL_UPDATE_LOCK_FD "$lock_file" || return 1
  flock -w 120 "$INSTALL_UPDATE_LOCK_FD" || { log 'Another SLL update is still running; no release files were changed.'; return 1; }
}

prepare_worker_descriptors() {
  local prepare_pid prepare_input prepare_output response mapping descriptor remote status=0
  local -a remote_fds=()
  coproc SLS_INSTALL_WORKER_PREPARE {
    exec /usr/bin/python3 -I "$WORKER_GUARD_TOOL" --data "$DATA_DIR" --timeout 120 prepare
  }
  prepare_pid="${SLS_INSTALL_WORKER_PREPARE_PID:-}"
  prepare_input="${SLS_INSTALL_WORKER_PREPARE[1]:-}"; prepare_output="${SLS_INSTALL_WORKER_PREPARE[0]:-}"
  if [ -z "$prepare_pid" ] || [ -z "$prepare_input" ] || [ -z "$prepare_output" ] \
    || ! exec {prepare_input}>&"$prepare_input" || ! exec {prepare_output}<&"$prepare_output"; then
    status=1
  elif ! IFS= read -r -t 120 response <&"$prepare_output" || [[ "$response" != 'prepared '* ]]; then
    status=1
  else
    mapping="$(/usr/bin/python3 -I - "$prepare_pid" "${response#prepared }" <<'PYPREPAREDFDS'
import json, sys
if len(sys.argv[2]) > 16384: raise SystemExit('Prepared descriptor response exceeds bound')
value=json.loads(sys.argv[2])
if (type(value) is not dict or set(value)!={'schema','pid','fds'} or type(value['schema']) is not int or value['schema']!=1
        or type(value['pid']) is not int or value['pid']!=int(sys.argv[1]) or type(value['fds']) is not list
        or not 1<=len(value['fds'])<=1100 or any(type(fd) is not int or not 3<=fd<=9999999 for fd in value['fds'])
        or len(set(value['fds']))!=len(value['fds'])):
    raise SystemExit('Invalid prepared worker descriptor inventory')
for fd in value['fds']: print(fd)
PYPREPAREDFDS
    )" || status=1
    if [ "$status" -eq 0 ]; then
      mapfile -t remote_fds <<<"$mapping"
      for remote in "${remote_fds[@]}"; do
        # The helper pins each safe regular anchor. Bash never creates or
        # opens a mutable data pathname, including a substituted FIFO.
        if ! exec {descriptor}<"/proc/$prepare_pid/fd/$remote"; then status=1; break; fi
        WORKER_LEASE_FDS+=("$descriptor")
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
    close_inherited_worker_lock_fds
    log 'The authenticated guard could not prepare retained worker descriptors; an older or unsafe helper is not a fencing fallback.'
    return 1
  fi
}

acquire_worker_coordination() {
  ensure_data_directory || return 1
  # The root caller and keeper share the same open-file descriptions. Keeper
  # death cannot release leases while the caller or a root native waiter lives.
  [ -n "$WORKER_GUARD_TOOL" ] && [ -f "$WORKER_GUARD_TOOL" ] && [ ! -L "$WORKER_GUARD_TOOL" ] || {
    log 'The authenticated worker guard helper has not been staged.'
    return 1
  }
  if [ "${#WORKER_LEASE_FDS[@]}" -eq 0 ]; then prepare_worker_descriptors || return 1; fi
  local inherited
  inherited="$(IFS=,; printf '%s' "${WORKER_LEASE_FDS[*]}")"
  coproc SLS_INSTALL_WORKER_GUARD {
    exec /usr/bin/python3 -I "$WORKER_GUARD_TOOL" --data "$DATA_DIR" --timeout 120 --inherited-fds "$inherited" hold
  }
  WORKER_LOCK_PID="${SLS_INSTALL_WORKER_GUARD_PID:-}"
  local guard_input="${SLS_INSTALL_WORKER_GUARD[1]:-}" guard_output="${SLS_INSTALL_WORKER_GUARD[0]:-}" status
  # Bash removes a coprocess's array/PID when an immediately rejected child
  # exits. Treat that race as the same controlled readiness failure.
  if [ -z "$WORKER_LOCK_PID" ] || [ -z "$guard_input" ] || [ -z "$guard_output" ] \
    || ! exec {WORKER_LOCK_KEEPALIVE_FD}>&"$guard_input" \
    || ! exec {WORKER_LOCK_RESPONSE_FD}<&"$guard_output"; then
    log 'Unable to pause active notification workers safely. No release files were activated.'
    release_worker_coordination
    return 1
  fi
  if ! IFS= read -r status <&"$WORKER_LOCK_RESPONSE_FD" || [ "$status" != ready ]; then
    log 'Unable to pause active notification workers safely. No release files were activated.'
    release_worker_coordination
    return 1
  fi
  WORKER_COORDINATION_REQUIRED=1
}

assert_worker_coordination() {
  local status
  [ -n "${WORKER_LOCK_PID:-}" ] && [ -n "${WORKER_LOCK_KEEPALIVE_FD:-}" ] \
    && [ -n "${WORKER_LOCK_RESPONSE_FD:-}" ] && kill -0 "$WORKER_LOCK_PID" 2>/dev/null \
    && ( trap '' PIPE; printf 'check\n' >&"$WORKER_LOCK_KEEPALIVE_FD" ) 2>/dev/null \
    && IFS= read -r -t 5 status <&"$WORKER_LOCK_RESPONSE_FD" && [ "$status" = checked ] || {
      log 'The installer worker lease could not be confirmed; protected mutation and commit were stopped.'
      return 1
    }
}

stop_worker_guard() {
  if [ -n "${WORKER_LOCK_KEEPALIVE_FD:-}" ]; then
    # A guard rejected before readiness may have already closed its pipe.
    # Isolate SIGPIPE so cleanup cannot kill the installer with exit 141.
    (printf 'release\n' >&"$WORKER_LOCK_KEEPALIVE_FD") 2>/dev/null || true
    exec {WORKER_LOCK_KEEPALIVE_FD}>&-
    WORKER_LOCK_KEEPALIVE_FD=""
  fi
  [ -z "${WORKER_LOCK_PID:-}" ] || wait "$WORKER_LOCK_PID" 2>/dev/null || true
  WORKER_LOCK_PID=""
  if [ -n "${WORKER_LOCK_RESPONSE_FD:-}" ]; then
    exec {WORKER_LOCK_RESPONSE_FD}<&-
    WORKER_LOCK_RESPONSE_FD=""
  fi
}

close_inherited_worker_lock_fds() {
  local descriptor
  for descriptor in "${WORKER_LEASE_FDS[@]}"; do exec {descriptor}>&-; done
  WORKER_LEASE_FDS=()
}

release_worker_coordination() {
  stop_worker_guard
  # No LOCK_UN: closing only this process's shared descriptions leaves any
  # still-running root native waiter fenced until its actual child finishes.
  close_inherited_worker_lock_fds
}

close_inherited_maintenance_lock_fds() {
  local lock_file="${SLS_MASS_NOTIFY_MAINTENANCE_LOCK:-/run/lock/sls-mass-notify-maintenance.lock}"
  local descriptor descriptor_path descriptor_target close_fd

  for descriptor_path in "/proc/${BASHPID}/fd/"*; do
    [ -e "$descriptor_path" ] || continue
    descriptor="${descriptor_path##*/}"
    [[ "$descriptor" =~ ^[0-9]+$ ]] && [ "$descriptor" -gt 2 ] || continue
    descriptor_target="$(readlink -f -- "$descriptor_path" 2>/dev/null || true)"
    [ "$descriptor_target" = "$lock_file" ] || [ "$descriptor_target" = /run/lock/sls-mass-notify-update.lock ] || [ "$descriptor_target" = "$SETTINGS_LOCK" ] || continue
    close_fd="$descriptor"
    exec {close_fd}>&-
  done
}

run_without_install_maintenance_lock() (
  # This root waiter retains the shared worker descriptions until the actual
  # child is reaped. Mutable PHP/native children receive no unlock capability.
  # Explicit stdin redirection preserves heredoc/pipeline input for async jobs.
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
      close_inherited_worker_lock_fds
    fi
    if [ -n "${WORKER_LOCK_KEEPALIVE_FD:-}" ]; then exec {WORKER_LOCK_KEEPALIVE_FD}>&-; fi
    if [ -n "${WORKER_LOCK_RESPONSE_FD:-}" ]; then exec {WORKER_LOCK_RESPONSE_FD}<&-; fi
    "$@"
  ) <&0 &
  child=$!
  status=0
  while true; do
    if wait "$child"; then status=0; break; else status=$?; fi
    # A trapped interruption must not release the fence while the child is
    # still running. An actual child failure is returned after it is reaped.
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

ensure_freepbx_prerequisites() {
  local prerequisite state
  for prerequisite in framework dashboard backup recordings; do
    state="$(module_registry_state "$prerequisite")" || {
      log "The native FreePBX registration could not be read for $prerequisite; no dependency change was authorized."
      return 1
    }
    if [ "$state" = absent ]; then
      log "Installing required FreePBX module: $prerequisite"
      fwconsole ma --no-interaction --ignorecache download "$prerequisite" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 \
        && install_native_module "$prerequisite" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
        log "Required FreePBX module could not be installed: $prerequisite. See $LOG_FILE."
        return 1
      }
    elif [[ "$state" == disabled$'\t'* ]]; then
      log "Enabling required FreePBX module: $prerequisite"
      enable_native_module "$prerequisite" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
        log "Required FreePBX module could not be enabled without an administrator-managed upgrade: $prerequisite. See $LOG_FILE."
        return 1
      }
    elif [[ "$state" != enabled$'\t'* ]]; then
      log "The native FreePBX registration is invalid for $prerequisite; existing modules were preserved."
      return 1
    fi
    if ! module_enabled "$prerequisite"; then
      log "Required FreePBX module has no verified enabled registration: $prerequisite. See $LOG_FILE."
      return 1
    fi
  done
}

strip_asterisk_ansi() {
  # Asterisk can emit terminal color/control sequences even when invoked from
  # a noninteractive installer. Remove CSI sequences before parsing headings.
  LC_ALL=C sed -E $'s/\033\\[[0-?]*[ -\\/]*[@-~]//g'
}

asterisk_cli_output() {
  local command="$1"
  local output

  output="$(asterisk -rx "$command" 2>&1)" || return 1
  strip_asterisk_ansi <<<"$output"
}

asterisk_setting_value() {
  local setting_name="$1"
  local settings

  settings="$(asterisk_cli_output "core show settings")" || return 1
  printf '%s\n' "$settings" | awk -v wanted="$setting_name" '
function trim(value) {
  sub(/^[[:space:]]+/, "", value)
  sub(/[[:space:]]+$/, "", value)
  return value
}
{
  separator = index($0, ":")
  if (separator == 0) {
    next
  }
  key = trim(substr($0, 1, separator - 1))
  if (!found && tolower(key) == tolower(wanted)) {
    print trim(substr($0, separator + 1))
    found = 1
  }
}'
}

asterisk_capability_available() {
  local capability_type="$1"
  local capability_name="$2"
  local capability_info marker

  case "$capability_type" in
    function)
      capability_info="$(asterisk_cli_output "core show function $capability_name")" || return 1
      marker="Info about Function '$capability_name'"
      ;;
    application)
      capability_info="$(asterisk_cli_output "core show application $capability_name")" || return 1
      marker="Info about Application '$capability_name'"
      ;;
    manager)
      if ! capability_info="$(asterisk -rx "manager show command $capability_name" 2>&1)"; then
        return 1
      fi
      capability_info="$(strip_asterisk_ansi <<<"$capability_info")"
      # Manager help has no common presentation heading across Asterisk builds.
      # Its Syntax section identifies the registered action on both 20 and 22.
      LC_ALL=C awk -v wanted="$capability_name" '
function trim(value) {
  sub(/^[[:space:]]+/, "", value)
  sub(/[[:space:]]+$/, "", value)
  return value
}
{
  line = trim($0)
  lower = tolower(line)
  if (lower ~ /^(no such command|unable to connect to remote asterisk|asterisk is not running|usage:)/) invalid = 1
  if (lower == "[syntax]") {
    sections++
    in_syntax = 1
    first = 1
    next
  }
  if (line ~ /^\[[^][]+\]$/) { in_syntax = 0; next }
  if (!in_syntax || line == "") next
  separator = index(line, ":")
  key = separator ? tolower(trim(substr(line, 1, separator - 1))) : ""
  value = separator ? tolower(trim(substr(line, separator + 1))) : ""
  if (first) {
    first = 0
    if (key != "action" || value != tolower(wanted)) invalid = 1
  }
  if (key == "action") {
    actions++
    if (value != tolower(wanted)) invalid = 1
  }
}
END { exit !(sections == 1 && actions == 1 && !invalid) }
' <<<"$capability_info"
      return
      ;;
    *)
      log "Unknown Asterisk capability type: $capability_type"
      return 1
      ;;
  esac

  # Asterisk releases and downstream builds vary the heading capitalization
  # ("Function" versus "function"). Match the complete quoted capability
  # heading case-insensitively so a registered provider never falls through to
  # package repair because of presentation-only CLI differences.
  LC_ALL=C grep -Fqi -- "$marker" <<<"$capability_info"
}

asterisk_module_file() {
  local module_name="$1"
  local module_directory

  module_directory="$(asterisk_setting_value "Module directory")"
  if [ -n "$module_directory" ] && [[ "$module_directory" = /* ]]; then
    printf '%s/%s\n' "${module_directory%/}" "$module_name"
  fi
}

refresh_apt_metadata() {
  if [ "$APT_METADATA_REFRESHED" -eq 1 ]; then
    return 0
  fi
  command -v apt-get >/dev/null 2>&1 || return 1
  log "Refreshing Debian package metadata for dependency verification."
  apt-get update >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || return 1
  APT_METADATA_REFRESHED=1
}

asterisk_provider_package() {
  local provider_file="$1"
  local canonical_provider query record package record_path canonical_record status
  local -a queries

  command -v dpkg-query >/dev/null 2>&1 || return 1
  canonical_provider="$(readlink -m -- "$provider_file" 2>/dev/null || true)"
  [ -n "$canonical_provider" ] || return 1
  queries=("$provider_file")
  if [ "$canonical_provider" != "$provider_file" ]; then
    queries+=("$canonical_provider")
  fi
  queries+=("*/asterisk/modules/$(basename "$provider_file")")

  for query in "${queries[@]}"; do
    while IFS= read -r record; do
      [[ "$record" == *": "* ]] || continue
      package="${record%%: *}"
      record_path="${record#*: }"
      [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*(:[a-z0-9][a-z0-9-]*)?$ ]] || continue
      canonical_record="$(readlink -m -- "$record_path" 2>/dev/null || true)"
      [ "$canonical_record" = "$canonical_provider" ] || continue
      status="$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)"
      [[ "$status" == 'ii ' || "$status" == 'hi ' ]] || continue
      printf '%s\n' "$package"
      return 0
    done < <(dpkg-query -S "$query" 2>/dev/null || true)
  done
  return 1
}

verify_asterisk_packaged_binary() {
  local provider_package="$1" provider_version="$2"
  local binary_package binary_version checksums
  binary_package="$(asterisk_provider_package /usr/sbin/asterisk)" || {
    log 'The active Asterisk binary has no installed package authority; provider-package repair is deferred.'
    return 1
  }
  binary_version="$(dpkg-query -W -f='${Version}' "$binary_package" 2>/dev/null)" || return 1
  [ "$binary_version" = "$provider_version" ] || {
    log "Asterisk binary package $binary_package and provider package $provider_package have different installed versions; repair is deferred."
    return 1
  }
  checksums="$(dpkg-query --control-path "$binary_package" md5sums 2>/dev/null)" || {
    log 'The installed Asterisk binary has no package checksum evidence; provider-package repair is deferred.'
    return 1
  }
  if ! /usr/bin/timeout 15 /usr/bin/python3 -I - /usr/sbin/asterisk "$checksums" /proc <<'PYPACKAGEDASTERISK'
import errno, getopt, hashlib, os, pathlib, re, stat, sys
binary, metadata, processes = map(pathlib.Path, sys.argv[1:])
def cli_client(command):
    argv = command.rstrip(b'\0').split(b'\0')
    if argv and b'rasterisk' in argv[0]: return True
    try:
        options, _ = getopt.gnu_getopt([os.fsdecode(arg) for arg in argv[1:]],
            'BC:cde:FfG:ghIiL:M:mnpqRrs:TtU:VvWXx:', ['version', 'help'])
    except getopt.GetoptError:
        return False  # Unknown arguments must never exempt a possible daemon.
    return any(option in ('-r', '-R', '-x', '-V', '-h', '--version', '--help') for option, _ in options)
def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
def protected_file(path, limit):
    if not path.is_absolute(): raise ValueError('nonabsolute package evidence')
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unprotected package evidence parent')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or before.st_nlink != 1 or not 1 <= before.st_size <= limit):
            raise ValueError('unsafe or oversized package evidence')
        body = stream.read(limit + 1)
        if (len(body) != before.st_size or identity(before) != identity(os.fstat(stream.fileno()))
                or identity(before) != identity(path.lstat())):
            raise ValueError('package evidence changed while reading')
        return body
try:
    contents = protected_file(binary, 67108864)
    sums = protected_file(metadata, 16777216).decode('utf-8')
    expected = []
    for line in sums.splitlines():
        item = re.fullmatch(r'([a-fA-F0-9]{32})[ \t]+(.+)', line)
        if item and item[2] == str(binary).lstrip('/'):
            expected.append(item[1].lower())
    if len(expected) != 1 or hashlib.md5(contents, usedforsecurity=False).hexdigest() != expected[0]:
        raise ValueError('binary differs from its installed package checksum')
    digest = hashlib.sha256(contents).digest()
    candidates = list(processes.iterdir())
    if len(candidates) > 65536: raise ValueError('process evidence exceeds its bound')
    daemons = 0
    for process in candidates:
        if not re.fullmatch(r'[1-9][0-9]{0,9}', process.name): continue
        try:
            image = os.readlink(process / 'exe')
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ESRCH): continue
            raise
        if pathlib.Path(image.removesuffix(' (deleted)')).name != 'asterisk': continue
        try:
            with (process / 'cmdline').open('rb') as stream: command = stream.read(65537)
        except FileNotFoundError: continue
        if len(command) > 65536: raise ValueError('oversized Asterisk process arguments')
        if cli_client(command):
            continue  # Remote CLI clients do not establish daemon provenance.
        if image != str(binary): raise ValueError('running Asterisk uses a different or deleted binary image')
        with (process / 'exe').open('rb') as stream:
            before = os.fstat(stream.fileno())
            running = stream.read(67108865)
            if (not 1 <= len(running) <= 67108864 or identity(before) != identity(os.fstat(stream.fileno()))
                    or hashlib.sha256(running).digest() != digest):
                raise ValueError('running Asterisk differs from its packaged binary')
        daemons += 1
    if daemons != 1: raise ValueError('one matching running Asterisk daemon could not be established')
except (OSError, ValueError, UnicodeError) as error:
    print('Cannot verify the packaged Asterisk binary and running image: ' + str(error)
          + '. Provider-package repair is deferred; no Asterisk packages were changed.', file=sys.stderr)
    raise SystemExit(1)
PYPACKAGEDASTERISK
  then
    return 1
  fi
  verify_asterisk_module_peers "$provider_package" "$provider_version" "${3:-}"
}

verify_asterisk_module_peers() {
  local provider_package="$1" provider_version="$2" provider_module="$3" module_directory
  [[ "$provider_module" =~ ^[a-zA-Z0-9_]+\.so$ ]] || return 1
  module_directory="$(asterisk_setting_value 'Module directory')" || return 1
  [[ "$module_directory" = /* ]] || return 1
  /usr/bin/timeout 15 /usr/bin/python3 -I - "$module_directory" "$provider_package" "$provider_version" "$provider_module" /proc /usr/sbin/asterisk <<'PYASTERISKMODULESET'
import errno, getopt, hashlib, os, pathlib, pwd, re, stat, subprocess, sys
module_path, package, version, targeted, process_path, binary_path = sys.argv[1:]
modules = pathlib.Path(module_path)
processes, binary = pathlib.Path(process_path), pathlib.Path(binary_path)
def cli_client(command):
    argv = command.rstrip(b'\0').split(b'\0')
    if argv and b'rasterisk' in argv[0]: return True
    try:
        options, _ = getopt.gnu_getopt([os.fsdecode(arg) for arg in argv[1:]],
            'BC:cde:FfG:ghIiL:M:mnpqRrs:TtU:VvWXx:', ['version', 'help'])
    except getopt.GetoptError:
        return False
    return any(option in ('-r', '-R', '-x', '-V', '-h', '--version', '--help') for option, _ in options)
def file_identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def native_daemon_binding(process):
    try:
        with (process/'stat').open('r') as stream: raw=stream.read(8193)
        if len(raw)>8192:return None
        fields=raw.rsplit(')',1)[1].split()
        with (process/'status').open('r') as stream: raw=stream.read(65537)
        if len(raw)>65536:return None
        values=dict(row.split(':',1) for row in raw.splitlines() if ':' in row)
        uids=tuple(map(int,values['Uid'].split()));gids=tuple(map(int,values['Gid'].split()))
        if (fields[0] in ('Z','X') or int(fields[19])<=0 or uids!=(runtime.pw_uid,)*4
                or gids!=(runtime.pw_gid,)*4 or os.readlink(process/'exe')!=str(binary)):return None
        return (int(process.name),int(fields[19]),uids,gids)
    except (OSError,ValueError,KeyError,IndexError):return None
def private_authority(path, maximum, native_peer=False):
    for parent in reversed(path.parents):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError('unprotected module/package authority parent')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(descriptor,'rb') as stream:
        before=os.fstat(stream.fileno())
        identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        owner_ok=before.st_uid==0 or (native_peer and before.st_uid==runtime.pw_uid and before.st_gid==runtime.pw_gid)
        if not stat.S_ISREG(before.st_mode) or not owner_ok or before.st_mode&0o022 or before.st_nlink!=1 or not 0<before.st_size<=maximum:
            raise ValueError('unsafe module/package authority: '+repr(str(path)))
        body=stream.read(maximum+1)
        if len(body)!=before.st_size or identity(before)!=identity(os.fstat(stream.fileno())) or identity(before)!=identity(path.lstat()):
            raise ValueError('module/package authority changed during inspection')
        return body,before
def query(*args):
    result=subprocess.run(['/usr/bin/dpkg-query',*args],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=3)
    if len(result.stdout)>4194304: raise ValueError('package query exceeds its output bound')
    return result
def module_name(path):
    return path.parent.resolve(strict=False)/path.name
try:
    try:runtime=pwd.getpwnam('asterisk')
    except KeyError:raise ValueError('canonical Asterisk runtime account is unavailable') from None
    if runtime.pw_uid<=0 or runtime.pw_gid<=0:raise ValueError('canonical Asterisk runtime account must be nonroot')
    modules=modules.resolve(strict=True)
    for parent in (modules,*modules.parents):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError('active module directory is not root-protected')
    owners={}
    for pattern in dict.fromkeys((str(pathlib.Path(module_path)/'*.so'),str(modules/'*.so'),'*/asterisk/modules/*.so')):
        result=query('-S',pattern)
        if result.returncode==1: continue
        if result.returncode!=0: raise ValueError('module package ownership query failed')
        for row in result.stdout.splitlines():
            if ': ' not in row: continue
            owner,filename=row.split(': ',1)
            if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?',owner):
                raise ValueError('ambiguous module package authority')
            path=pathlib.Path(filename)
            if not path.is_absolute() or path.suffix!='.so': continue
            path=module_name(path)
            if path.parent!=modules: continue
            owners.setdefault(path,set()).add(owner)
            if len(owners)>10000: raise ValueError('module inventory exceeds its bound')
    target=modules/targeted
    if target not in owners or len(owners[target])!=1 or next(iter(owners[target])).split(':',1)[0]!=package.split(':',1)[0]:
        raise ValueError('targeted provider lacks exact installed package authority')
    authorities={};verified={};native_verified={}
    def authority(owner):
        if owner in authorities:return authorities[owner]
        if len(authorities)>=128:raise ValueError('package authority count exceeds its bound')
        status=query('-W','-f=${db:Status-Abbrev}\t${Version}',owner)
        installed,separator,actual_version=status.stdout.strip().partition('\t')
        if status.returncode!=0 or installed not in ('ii ', 'hi ') or not separator or not actual_version:
            raise ValueError('module package is not installed with version authority: '+owner)
        # Only the provider being loaded/repaired must share the proven binary
        # release. Already mapped add-ons have independent package versions
        # (for example FreePBX Flite/DPMA); their own package checksums and
        # mapped inode below establish that no existing peer is being changed.
        # Asterisk itself checks module build options, not package releases:
        # asterisk/22.11.0/main/loader.c, inspect_module().
        if owner.split(':',1)[0]==package.split(':',1)[0] and actual_version!=version:
            raise ValueError('module package is not installed at the running build version')
        record=query('--control-path',owner,'md5sums')
        if record.returncode!=0:raise ValueError('module package checksum authority unavailable')
        path=pathlib.Path(record.stdout.strip())
        if not path.is_absolute():raise ValueError('module checksum authority path is invalid')
        raw,_=private_authority(path,16777216);expected={}
        for row in raw.decode('utf-8').splitlines():
            match=re.fullmatch(r'([a-fA-F0-9]{32})[ \t]+(.+)',row)
            if not match:raise ValueError('malformed package checksum authority')
            item=module_name(pathlib.Path('/')/match[2])
            if item.parent!=modules or item.suffix!='.so':continue
            if item in expected:raise ValueError('ambiguous package module checksum')
            expected[item]=match[1].lower()
        authorities[owner]=expected
        return expected
    def verify(path, mapped=False, binding=None):
        if path in verified:
            if path in native_verified:
                info,context=native_verified[path]
                if not mapped or binding!=context or file_identity(path.lstat())!=file_identity(info):
                    raise ValueError('native mapped peer changed: '+repr(str(path)))
            return verified[path]
        owner=owners.get(path,set())
        if len(owner)!=1:raise ValueError('loaded module has no unique installed package authority')
        owner=next(iter(owner))
        expected=authority(owner).get(path)
        if expected is None:raise ValueError('module lacks a package checksum')
        # Existing independently packaged addons run in this native UID domain.
        # This role never admits a new target/core provider or package metadata.
        native_peer=mapped and binding is not None and path!=target and owner.split(':',1)[0]!=package.split(':',1)[0]
        try:body,info=private_authority(path,67108864,native_peer=native_peer)
        except FileNotFoundError:
            if path==target:return None
            raise ValueError('another module in the repair package is missing') from None
        if hashlib.md5(body,usedforsecurity=False).hexdigest()!=expected:
            raise ValueError('custom or changed module peer differs from its installed package')
        verified[path]=info
        if info.st_uid!=0:native_verified[path]=(info,binding)
        return info
    for path,owner in owners.items():
        if any(item.split(':',1)[0]==package.split(':',1)[0] for item in owner):verify(path)
    candidates=list(processes.iterdir())
    if len(candidates)>65536:raise ValueError('process inventory exceeds its bound')
    daemons=0
    for process in candidates:
        if not re.fullmatch(r'[1-9][0-9]{0,9}',process.name):continue
        try:image=os.readlink(process/'exe')
        except OSError as error:
            if error.errno in (errno.ENOENT,errno.ESRCH):continue
            raise
        if image!=str(binary):continue
        with (process/'cmdline').open('rb') as stream:command=stream.read(65537)
        if len(command)>65536:raise ValueError('oversized Asterisk process arguments')
        if cli_client(command):continue
        daemons+=1
        binding=native_daemon_binding(process)
        descriptor=os.open(process/'maps',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(descriptor,'rb') as stream:raw=stream.read(16777217)
        if len(raw)>16777216:raise ValueError('mapped module inventory exceeds its bound')
        for row in raw.decode('utf-8').splitlines():
            fields=row.split(None,5)
            if len(fields)!=6 or not fields[5].startswith('/'):continue
            deleted=fields[5].endswith(' (deleted)')
            path=pathlib.Path(fields[5].removesuffix(' (deleted)'))
            if path.suffix!='.so':continue
            path=module_name(path)
            if path.parent!=modules and not re.match(r'^(?:res|chan|app|func|codec|format|pbx|bridge|cel|cdr)_',path.name):continue
            if deleted or path.parent!=modules:raise ValueError('loaded custom/deleted module has unverified build authority')
            info=verify(path,mapped=True,binding=binding)
            device=fields[3].split(':')
            if info is None or len(device)!=2 or (os.major(info.st_dev),os.minor(info.st_dev),info.st_ino)!=(int(device[0],16),int(device[1],16),int(fields[4])):
                raise ValueError('loaded module image differs from the installed package inode')
        if any(context==binding for _,context in native_verified.values()) and native_daemon_binding(process)!=binding:
            raise ValueError('native mapped peer daemon changed during inspection')
    if daemons!=1:raise ValueError('one matching Asterisk daemon could not establish module authority')
    for path,(info,_) in native_verified.items():
        if file_identity(path.lstat())!=file_identity(info):
            raise ValueError('native mapped peer changed: '+repr(str(path)))
except (OSError,ValueError,UnicodeError,subprocess.SubprocessError) as error:
    print('Cannot qualify the packaged Asterisk module peer set: '+str(error)+'. No provider was loaded or package changed.',file=sys.stderr)
    raise SystemExit(1)
PYASTERISKMODULESET
}

wait_for_asterisk_cli() {
  local attempt=1
  while [ "$attempt" -le 30 ]; do
    if asterisk -rx "core show version" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
      return 0
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  return 1
}

repair_asterisk_provider_package() {
  local provider_module="$1"
  local provider_file package package_version package_spec utility
  local active_channels service_owner=unmanaged

  [ "$REPAIR_ASTERISK_PACKAGES" -eq 1 ] || {
    log "This module installer leaves Asterisk packages unchanged by default. Restore the matching provider with the PBX's normal maintenance procedure."
    log 'An administrator may explicitly request verified packaged-Asterisk repair with SLS_MASS_NOTIFY_REPAIR_ASTERISK_PACKAGES=1; custom builds require their matching build artifacts.'
    return 1
  }
  for utility in apt-get dpkg-query readlink; do
    command -v "$utility" >/dev/null 2>&1 || {
      log "Automatic Asterisk provider-package repair requires $utility, but it is unavailable."
      return 1
    }
  done
  if ! asterisk -rx "core show version" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
    log "Asterisk is not reachable; refusing to start or alter its packages automatically."
    return 1
  fi
  if ! active_channels="$(asterisk -rx "core show channels count" 2>/dev/null \
    | awk '!found && $2 == "active" && $3 == "channels" {print $1; found=1}')" \
    || ! [[ "$active_channels" =~ ^[0-9]+$ ]]; then
    log "Unable to verify that Asterisk has no active channels; automatic package repair was deferred."
    return 1
  fi
  if [ "$active_channels" -gt 0 ]; then
    log "Automatic Asterisk package repair was deferred because $active_channels channel(s) are active."
    log "Rerun the installer after active calls have completed."
    return 1
  fi
  provider_file="$(asterisk_module_file "$provider_module")"
  [ -n "$provider_file" ] || {
    log "Unable to determine the active Asterisk module directory for $provider_module."
    return 1
  }
  package="$(asterisk_provider_package "$provider_file" || true)"
  [ -n "$package" ] || {
    log "No installed Debian package owns $provider_file; this appears to be a custom or incomplete Asterisk build."
    log "The installer will not mix a packaged module into an unowned Asterisk build because that can corrupt the PBX ABI."
    return 1
  }
  package_version="$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)"
  [ -n "$package_version" ] || {
    log "Unable to determine the installed version of the Asterisk provider package $package."
    return 1
  }
  package_spec="${package}=${package_version}"
  verify_asterisk_packaged_binary "$package" "$package_version" "$provider_module" || return 1
  if [[ "$ASTERISK_PACKAGE_REPAIR_ATTEMPTS" == *"|${package_spec}|"* ]]; then
    log "The exact Asterisk package $package_spec was already repaired during this installer run."
    return 1
  fi
  ASTERISK_PACKAGE_REPAIR_ATTEMPTS="${ASTERISK_PACKAGE_REPAIR_ATTEMPTS}|${package_spec}|"

  refresh_apt_metadata || {
    log "Unable to refresh Debian package metadata needed to repair $provider_module. See $LOG_FILE."
    return 1
  }

  # Repository refresh can take time on a deployed PBX. Do not rely on the
  # earlier idle observation when the package operation is about to begin.
  if ! active_channels="$(asterisk -rx "core show channels count" 2>/dev/null \
    | awk '!found && $2 == "active" && $3 == "channels" {print $1; found=1}')" \
    || ! [[ "$active_channels" =~ ^[0-9]+$ ]] || [ "$active_channels" -ne 0 ]; then
    log 'Asterisk is no longer verifiably idle after repository refresh; provider package repair was deferred.'
    return 1
  fi
  if /usr/bin/systemctl is-active --quiet freepbx.service; then
    service_owner=freepbx
  elif /usr/bin/systemctl is-active --quiet asterisk.service; then
    service_owner=asterisk
  fi
  if [ "$service_owner" = unmanaged ]; then
    log 'Asterisk has no recognized active service manager; automatic provider package repair was deferred before changing packages.'
    log "Restore the missing provider from the exact installed package using the normal PBX maintenance procedure, then rerun the installer. Required package: $package_spec."
    return 1
  fi
  # Repository refresh may overlap another administrator's Asterisk update.
  # Recheck the binary image immediately before the opt-in package mutation.
  verify_asterisk_packaged_binary "$package" "$package_version" "$provider_module" || return 1

  log "Repairing $provider_module from the exact installed Asterisk package $package_spec."
  DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall --no-install-recommends --no-remove \
    "$package_spec" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
      log "Exact-version Asterisk package repair failed for $package_spec. See $LOG_FILE."
      log "Restore that exact package version or its matching repository before rerunning the installer."
      return 1
    }
  [ -f "$provider_file" ] || {
    log "Package repair completed, but $provider_file is still missing."
    return 1
  }
  if ! wait_for_asterisk_cli; then
    if [ "$service_owner" != asterisk ] || /usr/bin/systemctl is-active --quiet freepbx.service; then
      log "Asterisk did not recover under its previous $service_owner service manager after package repair."
      log 'Restore Asterisk with the normal PBX service manager, then retry authenticated installer recovery. The installer will not start a different Asterisk service or run FreePBX module hooks as root.'
      return 1
    fi
    log 'Asterisk stopped during package repair; restoring the previously active asterisk.service.'
    /usr/bin/systemctl start asterisk.service >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
      log "FreePBX could not start Asterisk after package repair. See $LOG_FILE."
      return 1
    }
    wait_for_asterisk_cli || {
      log "Asterisk did not return after the exact-version package repair. See $LOG_FILE."
      return 1
    }
  fi
  return 0
}

asterisk_module_loaded() {
  local module_name="$1"
  local module_info line normalized_module_name field_count
  local -a fields
  module_info="$(asterisk_cli_output "module show like $module_name")" || return 1
  normalized_module_name="${module_name,,}"
  while IFS= read -r line; do
    read -r -a fields <<<"$line"
    field_count="${#fields[@]}"
    if [ "$field_count" -ge 3 ] \
      && [ "${fields[0],,}" = "$normalized_module_name" ] \
      && [ "${fields[field_count - 2],,}" = "running" ] \
      && { [ "$field_count" -lt 4 ] || [ "${fields[field_count - 3],,}" != "not" ]; }; then
      return 0
    fi
  done <<<"$module_info"
  return 1
}

require_asterisk_capability() {
  local capability_type="$1"
  local capability_name="$2"

  if asterisk_capability_available "$capability_type" "$capability_name"; then
    return 0
  fi
  log "Required built-in Asterisk $capability_type is unavailable: $capability_name. The installer cannot safely repair a built-in capability."
  return 1
}

verify_asterisk_provider_admission() {
  local module_name="$1" provider_file package package_version
  asterisk_module_starts_persistently "$module_name" || {
    log "The active Asterisk startup configuration does not permit $module_name; no load or package change was attempted."
    return 1
  }
  provider_file="$(asterisk_module_file "$module_name")" || return 1
  [ -n "$provider_file" ] || return 1
  package="$(asterisk_provider_package "$provider_file")" || {
    log "The unavailable provider $module_name has no matching installed package authority. Load or restore it through this PBX's own Asterisk build before retrying; existing custom capabilities are preserved."
    return 1
  }
  package_version="$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null)" || return 1
  verify_asterisk_packaged_binary "$package" "$package_version" "$module_name" || return 1
  if [ ! -f "$provider_file" ]; then
    if [ "${ASTERISK_READ_ONLY_ADMISSION:-0}" -eq 1 ]; then
      if [ "$REPAIR_ASTERISK_PACKAGES" != 1 ]; then
        log "The exact packaged provider $module_name is missing. Restore it using this PBX's maintenance procedure, or explicitly opt in to exact package repair before retrying; no package changes were attempted."
        return 1
      fi
      log "The missing exact packaged provider $module_name requires the separately approved repair phase; repository availability and successful repair remain unverified."
      return 0
    fi
    repair_asterisk_provider_package "$module_name" || return 1
    [ -f "$provider_file" ] || return 1
    verify_asterisk_packaged_binary "$package" "$package_version" "$module_name" || return 1
  fi
}

ensure_asterisk_module_loaded() {
  local module_name="$1"

  if asterisk_module_loaded "$module_name"; then
    return 0
  fi
  verify_asterisk_provider_admission "$module_name" || return 1
  if [ "${ASTERISK_READ_ONLY_ADMISSION:-0}" -eq 1 ]; then
    log "The packaged Asterisk provider $module_name passed read-only admission; loading is deferred until after approval."
    return 0
  fi
  log "Loading required Asterisk module $module_name."
  asterisk -rx "module load $module_name" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || true
  asterisk_module_loaded "$module_name" || {
    log "Required Asterisk module is unavailable after adaptive repair: $module_name. See $LOG_FILE."
    return 1
  }
}

ensure_asterisk_capability() {
  local capability_type="$1"
  local capability_name="$2"
  local provider_module="$3"
  local provider_file

  if asterisk_capability_available "$capability_type" "$capability_name"; then
    return 0
  fi

  verify_asterisk_provider_admission "$provider_module" || return 1
  if [ "${ASTERISK_READ_ONLY_ADMISSION:-0}" -eq 1 ]; then
    log "Asterisk $capability_type $capability_name requires $provider_module; its approved load is deferred until after read-only admission."
    return 0
  fi
  log "Asterisk $capability_type $capability_name is not registered; loading $provider_module."
  asterisk -rx "module load $provider_module" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || true
  if ! asterisk_capability_available "$capability_type" "$capability_name"; then
    provider_file="$(asterisk_module_file "$provider_module")"
    if [ -n "$provider_file" ] && [ ! -f "$provider_file" ]; then
      log "Asterisk $capability_type $capability_name requires $provider_module, but the active Asterisk build does not include $provider_file."
      log "Install the matching Asterisk core/module package for this PBX, then rerun the installer."
    else
      log "Asterisk could not register $capability_type $capability_name from $provider_module. See $LOG_FILE."
    fi
    return 1
  fi

}

ensure_required_asterisk_capabilities() {
  ensure_asterisk_capability function PJSIP_HEADER res_pjsip_header_funcs.so || return 1
  ensure_asterisk_capability function PJSIP_CONTACT func_pjsip_contact.so || return 1
  ensure_asterisk_capability function PJSIP_AOR func_pjsip_aor.so || return 1
  ensure_asterisk_capability function PJSIP_DIAL_CONTACTS chan_pjsip.so || return 1
  ensure_asterisk_capability function TOLOWER func_strings.so || return 1
  ensure_asterisk_capability function CUT func_cut.so || return 1
  ensure_asterisk_capability function FILTER func_strings.so || return 1
  ensure_asterisk_capability function CHANNEL func_channel.so || return 1
  ensure_asterisk_capability function IF func_logic.so || return 1
  ensure_asterisk_capability function DB func_db.so || return 1
  ensure_asterisk_capability function CALLERID func_callerid.so || return 1
  ensure_asterisk_capability function TIMEOUT func_timeout.so || return 1
  ensure_asterisk_capability function MUTEAUDIO res_mutestream.so || return 1
  ensure_asterisk_capability function CONFBRIDGE app_confbridge.so || return 1
  ensure_asterisk_capability manager MuteAudio res_mutestream.so || return 1
  ensure_asterisk_capability manager PlayDTMF app_senddtmf.so || return 1
  require_asterisk_capability manager Setvar || return 1
  require_asterisk_capability manager Getvar || return 1
  ensure_asterisk_capability application ConfBridge app_confbridge.so || return 1
  ensure_asterisk_capability application Page app_page.so || return 1
  ensure_asterisk_capability application AGI res_agi.so || return 1
  ensure_asterisk_capability application Playback app_playback.so || return 1
  ensure_asterisk_capability application PlayTones app_playtones.so || return 1
  ensure_asterisk_capability application StopPlayTones app_playtones.so || return 1
  ensure_asterisk_capability application Read app_read.so || return 1
  ensure_asterisk_capability application ExecIf app_exec.so || return 1
  ensure_asterisk_capability application Gosub app_stack.so || return 1
  ensure_asterisk_capability application Return app_stack.so || return 1
  ensure_asterisk_capability application Log app_verbose.so || return 1
  ensure_asterisk_capability application Verbose app_verbose.so || return 1
  require_asterisk_capability application Wait || return 1
}

asterisk_module_starts_persistently() {
  local module_name="$1"
  local modules_config="${2:-}" configuration_directory
  local -a interpreter=(/usr/bin/python3 -I)
  if [ -z "$modules_config" ]; then
    configuration_directory="$(asterisk_setting_value 'Configuration directory')" || return 1
    [[ "$configuration_directory" = /* ]] || {
      log 'The active Asterisk configuration directory is unavailable; no module loading was attempted.'
      return 1
    }
    modules_config="${configuration_directory%/}/modules.conf"
  fi
  [ -r "$modules_config" ] || return 1
  # Qualify exactly the access the supported daemon account will have after
  # restart. Root readability cannot establish daemon configuration access.
  if [ "$EUID" -eq 0 ]; then interpreter=(sls_as_asterisk /usr/bin/python3 -I); fi
  "${interpreter[@]}" - "$module_name" "$modules_config" <<'PYASTERISKSTART'
import glob
import os
from pathlib import Path
import re
import stat
import sys

wanted = sys.argv[1].lower().removesuffix('.so')
base = Path(sys.argv[2]).absolute().parent
categories = []
current = None
opened_files = 0
read_bytes = 0
row_count = 0
expanded_rows = 0
stack = []
inspected = {}

def file_identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def read_file(path):
    global current, opened_files, read_bytes, row_count, expanded_rows
    if len(stack) >= 10 or path in stack:
        raise ValueError('include cycle or depth limit')
    opened_files += 1
    if opened_files > 128:
        raise ValueError('include file limit')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1048576:
            raise ValueError('nonregular or oversized configuration')
        with os.fdopen(fd, 'rb') as stream:
            fd = -1
            raw = stream.read(1048577)
            after = os.fstat(stream.fileno())
        named = path.lstat()
        if (len(raw) != info.st_size or file_identity(info) != file_identity(after)
                or file_identity(after) != file_identity(named)
                or path in inspected and inspected[path] != file_identity(named)):
            raise ValueError('configuration changed during inspection')
        inspected[path] = file_identity(named)
    finally:
        if fd >= 0:
            os.close(fd)
    read_bytes += len(raw)
    if read_bytes > 2097152:
        raise ValueError('aggregate configuration limit')
    text = raw.decode('utf-8')
    stack.append(path)
    comment_depth = 0
    try:
        for source in text.splitlines():
            if len(source) > 4096:
                raise ValueError('configuration line limit')
            line = ''
            index = 0
            while index < len(source):
                if source.startswith(';--', index):
                    comment_depth += 1
                    if comment_depth > 128:
                        raise ValueError('nested comment limit')
                    index += 3
                elif comment_depth and source.startswith('--;', index):
                    comment_depth -= 1
                    index += 3
                elif comment_depth:
                    index += 1
                elif source[index] == ';' and (index == 0 or source[index-1] != '\\'):
                    break
                else:
                    line += source[index]
                    index += 1
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                directive = re.fullmatch(r'#(include|tryinclude)\s+(.+)', line, re.I)
                if not directive:
                    raise ValueError('unsupported directive; #exec is never executed by this check')
                name = directive[2].strip()
                if name[0] in ('"', '<'):
                    end = '"' if name[0] == '"' else '>'
                    if not name.endswith(end):
                        raise ValueError('malformed include')
                    name = name[1:-1]
                target = Path(name)
                if not target.is_absolute():
                    target = base / target
                matches = []
                for match in glob.iglob(str(target)):
                    matches.append(match)
                    if len(matches) > 128:
                        raise ValueError('include match limit')
                matches.sort()
                if not matches and directive[1].lower() == 'include':
                    raise ValueError('required include is missing')
                for match in matches:
                    read_file(Path(match).absolute())
                continue
            if line.startswith('['):
                section = re.fullmatch(r'\[([^]\x00-\x1f]{1,79})\]\s*(?:\(([^()]*)\))?', line)
                if not section:
                    raise ValueError('unsupported category syntax')
                name = section[1].lower()
                modifiers = [part.strip().lower() for part in (section[2] or '').split(',') if part.strip()]
                if '+' in modifiers:
                    if modifiers != ['+']:
                        raise ValueError('unsupported category append')
                    current = next((cat for cat in categories if cat['name'] == name and not cat['ignored']), None)
                    if current is None:
                        raise ValueError('appended category is missing')
                else:
                    current = {'name': name, 'ignored': '!' in modifiers, 'rows': []}
                    for template in modifiers:
                        if template == '!':
                            continue
                        inherited = next((cat for cat in categories if cat['name'] == template), None)
                        if inherited is None:
                            raise ValueError('inherited category is missing')
                        expanded_rows += len(inherited['rows'])
                        if expanded_rows > 100000:
                            raise ValueError('inherited setting limit')
                        current['rows'].extend(inherited['rows'])
                    categories.append(current)
                    if len(categories) > 4096:
                        raise ValueError('category limit')
                continue
            entry = re.fullmatch(r'([^=+]+?)\s*=>(.*)|([^=+]+?)\s*=(.*)', line)
            if entry is None or current is None:
                raise ValueError('unsupported setting or missing category')
            key, value = (entry[1], entry[2]) if entry[1] else (entry[3], entry[4])
            current['rows'].append((key.strip().lower(), value.strip().lower()))
            row_count += 1
            if row_count > 100000:
                raise ValueError('setting limit')
        if comment_depth:
            raise ValueError('unterminated block comment')
    finally:
        stack.pop()

try:
    read_file(Path(sys.argv[2]).absolute())
    if any(file_identity(path.lstat()) != expected for path,expected in inspected.items()):
        raise ValueError('configuration changed during inspection')
    # ast_variable_browse resolves the first non-template category and
    # ast_variable_retrieve resolves its first matching variable. Independent
    # duplicate categories and later autoload values do not override them.
    category = next((cat for cat in categories if cat['name'] == 'modules' and not cat['ignored']), None)
    modules = category['rows'] if category is not None else []
    allowed = {'autoload','load','require','preload','preload-require','noload'}
    if any(key not in allowed for key,value in modules):
        raise ValueError('unknown effective module loader option')
    required = {value.removesuffix('.so') for key,value in modules if key in ('require','preload-require')}
    denied = {value.removesuffix('.so') for key,value in modules if key == 'noload'}
    if required & denied:
        raise ValueError('a required module is also explicitly noloaded')
    autoload = next((value for key, value in modules if key == 'autoload'), 'no') in ('yes', 'true', 'y', 't', '1', 'on')
    blocked = any(key == 'noload' and value.removesuffix('.so') == wanted for key, value in modules)
    explicit = any(key in ('load', 'preload', 'require', 'preload-require') and value.removesuffix('.so') == wanted for key, value in modules)
    sys.exit(1 if blocked or not (autoload or explicit) else 0)
except (OSError, ValueError, UnicodeError) as error:
    print('Asterisk startup configuration could not be qualified: ' + str(error)[:200] + '. Review modules.conf and its includes; no configuration was changed.', file=sys.stderr)
    sys.exit(2)
PYASTERISKSTART
}

verify_asterisk_module_startup_persistence() {
  local module_name configuration_directory modules_config
  configuration_directory="$(asterisk_setting_value 'Configuration directory')" || return 1
  [[ "$configuration_directory" = /* ]] || {
    log 'The active Asterisk configuration directory is unavailable; startup persistence cannot be established.'
    return 1
  }
  modules_config="${configuration_directory%/}/modules.conf"
  for module_name in \
    res_pjsip.so res_pjsip_session.so chan_pjsip.so res_pjsip_notify.so \
    pbx_spool.so format_wav.so res_pjsip_header_funcs.so \
    func_pjsip_contact.so func_pjsip_aor.so func_strings.so func_cut.so func_channel.so \
    func_logic.so func_db.so func_callerid.so app_exec.so \
    app_page.so app_confbridge.so app_stack.so app_verbose.so \
    res_agi.so app_read.so app_playback.so func_timeout.so \
    res_mutestream.so app_senddtmf.so app_playtones.so; do
    asterisk_module_starts_persistently "$module_name" "$modules_config" || {
      log "Required Asterisk module is available now but is blocked after restart by $modules_config: $module_name"
      log "Enable Asterisk module autoloading or explicitly load that module through the PBX-managed module configuration, then rerun the installer."
      return 1
    }
  done
}

verify_asterisk_notify_readiness() {
  local attempt
  asterisk_module_starts_persistently res_pjsip_notify.so || {
    log 'Asterisk startup policy does not permit the required SIP NOTIFY provider. Final verification made no provider changes.'
    return 1
  }
  for ((attempt=1; attempt<=20; attempt++)); do
    if asterisk_module_loaded res_pjsip_notify.so \
      && asterisk_capability_available manager PJSIPNotify; then
      return 0
    fi
    [ "$attempt" -eq 20 ] || sleep 1
  done
  log 'The required SIP NOTIFY provider did not become ready after FreePBX reload. No provider was loaded or repaired during final verification; review Asterisk health and retry the authenticated installer.'
  return 1
}

asterisk_channel_type_available() {
  local channel_type="$1"
  local channel_info

  channel_info="$(asterisk_cli_output "core show channeltype $channel_type")" || return 1
  LC_ALL=C grep -Fqi -- "Info about channel driver: $channel_type" <<<"$channel_info"
}

verify_asterisk_runtime_identity() {
  /usr/bin/timeout 10 /usr/bin/python3 -I - "$1" /etc/asterisk /proc /usr/sbin/asterisk <<'PYASTERISKRUNTIME'
import errno, getopt, os, pathlib, pwd, re, sys
configuration, expected, processes, binary = map(pathlib.Path, sys.argv[1:])
def cli_client(command):
    # Asterisk 20/22 getopt options: parse clusters without treating letters in
    # attached option values (-Uasterisk, -C/path) as remote-console switches.
    argv = command.rstrip(b'\0').split(b'\0')
    if argv and b'rasterisk' in argv[0]: return True
    try:
        options, _ = getopt.gnu_getopt([os.fsdecode(arg) for arg in argv[1:]],
            'BC:cde:FfG:ghIiL:M:mnpqRrs:TtU:VvWXx:', ['version', 'help'])
    except getopt.GetoptError:
        return False
    return any(option in ('-r', '-R', '-x', '-V', '-h', '--version', '--help') for option, _ in options)
try:
    account = pwd.getpwnam('asterisk')
    if account.pw_uid <= 0 or account.pw_gid <= 0:
        raise ValueError('the asterisk runtime account/group must be non-root')
    if not configuration.is_absolute() or not configuration.is_dir() or not os.path.samefile(configuration, expected):
        raise ValueError('the active Configuration directory differs from /etc/asterisk; this runtime cannot write a separate daemon configuration tree')
    image = binary.stat()
    candidates = list(processes.iterdir())
    if len(candidates) > 65536:
        raise ValueError('the Asterisk process inventory exceeds its bound')
    found = 0
    for process in candidates:
        if not re.fullmatch(r'[1-9][0-9]{0,9}', process.name): continue
        try:
            running = (process / 'exe').stat()
            if (running.st_dev, running.st_ino) != (image.st_dev, image.st_ino): continue
            with (process / 'cmdline').open('rb') as source: command = source.read(65537)
            if len(command) > 65536: raise ValueError('the Asterisk arguments exceed their inspection bound')
            if cli_client(command): continue
            with (process / 'status').open('r', encoding='ascii') as source: status = source.read(65537)
            if len(status) > 65536: raise ValueError('the Asterisk identity exceeds its inspection bound')
            for label, identifier in (('Uid', account.pw_uid), ('Gid', account.pw_gid)):
                match = re.search(r'^' + label + r':\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*$', status, re.M)
                if not match or any(int(value) != identifier for value in match.groups()):
                    raise ValueError('the active daemon ' + label + ' at PID ' + process.name + ' does not match the supported asterisk runtime account')
            confirmed = (process / 'exe').stat()
            if (confirmed.st_dev, confirmed.st_ino) != (running.st_dev, running.st_ino):
                raise ValueError('the Asterisk process image changed during admission')
            found += 1
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.ESRCH): raise
    if found != 1:
        raise ValueError('one active Asterisk daemon matching the installed CLI image could not be verified; resolve a stopped, replaced or duplicate daemon through normal PBX maintenance')
except (OSError, ValueError, KeyError, UnicodeError) as error:
    print('Asterisk runtime admission failed: ' + str(error) + '. No provider was loaded and no alternate runtime tree was created.', file=sys.stderr)
    raise SystemExit(1)
PYASTERISKRUNTIME
}

verify_supported_asterisk_directories() {
  local spool_directory varlib_directory data_directory configuration_directory
  local canonical_spool canonical_varlib canonical_data

  spool_directory="$(asterisk_setting_value "Spool directory")"
  varlib_directory="$(asterisk_setting_value "VarLib directory")"
  data_directory="$(asterisk_setting_value "Data directory")"
  configuration_directory="$(asterisk_setting_value 'Configuration directory')" || return 1
  verify_asterisk_runtime_identity "$configuration_directory" || return 1

  if [[ "$spool_directory" != /* ]]; then
    log "Unable to determine Asterisk's active Spool directory from 'core show settings'."
    return 1
  fi
  if [[ "$varlib_directory" != /* ]]; then
    log "Unable to determine Asterisk's active VarLib directory from 'core show settings'."
    return 1
  fi

  canonical_spool="$(readlink -m -- "$spool_directory" 2>/dev/null || true)"
  canonical_varlib="$(readlink -m -- "$varlib_directory" 2>/dev/null || true)"
  if [ "$canonical_spool" != "/var/spool/asterisk" ]; then
    log "Unsupported Asterisk Spool directory: $spool_directory. This release writes call files only to /var/spool/asterisk and will not activate against a different live spool path."
    return 1
  fi
  if [ "$canonical_varlib" != "/var/lib/asterisk" ]; then
    log "Unsupported Asterisk VarLib directory: $varlib_directory. This release stores sounds and state only under /var/lib/asterisk and will not activate against a different live data path."
    return 1
  fi

  # Some builds omit Data directory from the CLI. When it is reported, ensure
  # that the module's fixed sound path points at the active Asterisk data root.
  if [ -n "$data_directory" ]; then
    if [[ "$data_directory" != /* ]]; then
      log "Asterisk reported a non-absolute Data directory: $data_directory."
      return 1
    fi
    canonical_data="$(readlink -m -- "$data_directory" 2>/dev/null || true)"
    if [ "$canonical_data" != "/var/lib/asterisk" ]; then
      log "Unsupported Asterisk Data directory: $data_directory. This release expects /var/lib/asterisk for sounds."
      return 1
    fi
  fi

  return 0
}

asterisk_labeled_value() {
  local command="$1"
  local label="$2"
  local output

  output="$(asterisk_cli_output "$command")" || return 1
  printf '%s\n' "$output" | awk -v wanted="$label" '
function trim(value) {
  sub(/^[[:space:]]+/, "", value)
  sub(/[[:space:]]+$/, "", value)
  return value
}
{
  separator = index($0, ":")
  if (separator == 0) {
    next
  }
  key = trim(substr($0, 1, separator - 1))
  if (!found && tolower(key) == tolower(wanted)) {
    print trim(substr($0, separator + 1))
    found = 1
  }
}'
}

pjsip_dial_string_supported() {
  local dial_string="$1"
  local channel
  local -a channels

  [ -n "$dial_string" ] || return 1
  IFS='&' read -r -a channels <<<"$dial_string"
  [ "${#channels[@]}" -gt 0 ] || return 1
  for channel in "${channels[@]}"; do
    channel="$(printf '%s' "$channel" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    [ -n "$channel" ] || return 1
    [[ "${channel,,}" == pjsip/* ]] || return 1
  done
}

pjsip_endpoint_available() {
  local endpoint="$1"
  local endpoint_info

  [[ "$endpoint" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
  endpoint_info="$(asterisk_cli_output "pjsip show endpoint $endpoint")" || return 1
  printf '%s\n' "$endpoint_info" | awk -v wanted="$endpoint" '
function trim(value) {
  sub(/^[[:space:]]+/, "", value)
  sub(/[[:space:]]+$/, "", value)
  return value
}
{
  separator = index($0, ":")
  if (separator == 0 || tolower(trim(substr($0, 1, separator - 1))) != "endpoint") {
    next
  }
  value = trim(substr($0, separator + 1))
  split(value, columns, /[[:space:]]+/)
  split(columns[1], endpoint_parts, "/")
  if (endpoint_parts[1] == wanted) {
    found = 1
  }
}
END {
  exit(found ? 0 : 1)
}'
}

pjsip_dial_string_endpoints_available() {
  local dial_string="$1"
  local channel endpoint
  local -a channels

  pjsip_dial_string_supported "$dial_string" || return 1
  IFS='&' read -r -a channels <<<"$dial_string"
  for channel in "${channels[@]}"; do
    channel="$(printf '%s' "$channel" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    endpoint="${channel#*/}"
    endpoint="${endpoint%%/*}"
    if ! pjsip_endpoint_available "$endpoint"; then
      log "PJSIP paging route component does not resolve to an active endpoint object: $channel"
      return 1
    fi
  done
}

verify_registered_endpoint_route() {
  local extension="$1"
  local device_route device_aor dial_string route_source

  [[ "$extension" =~ ^[0-9]+$ ]] || {
    log "Refusing to validate a nonnumeric paging extension: $extension"
    return 1
  }

  # Match the managed dialplan: explicit registered contacts are preferred so
  # Page creates one conference participant per contact instead of allowing a
  # single endpoint Dial operation to cancel sibling registrations.
  dial_string="$(asterisk_labeled_value "dialplan eval function PJSIP_DIAL_CONTACTS(${extension})" "Result")"
  route_source="PJSIP_DIAL_CONTACTS(${extension})"
  device_route=""
  device_aor=""
  if [ -z "$dial_string" ]; then
    device_route="$(asterisk_labeled_value "database get DEVICE ${extension}/dial" "Value")"
    if [[ "$device_route" =~ ^PJSIP/([A-Za-z0-9_.-]+)(/.*)?$ ]]; then
      device_aor="${BASH_REMATCH[1]}"
    fi
    if [ -n "$device_aor" ] && [ "$device_aor" != "$extension" ]; then
      dial_string="$(asterisk_labeled_value "dialplan eval function PJSIP_DIAL_CONTACTS(${device_aor})" "Result")"
      route_source="PJSIP_DIAL_CONTACTS(${device_aor}) from AstDB DEVICE/${extension}/dial"
    fi
  fi
  if [ -z "$dial_string" ]; then
    dial_string="$device_route"
    route_source="AstDB DEVICE/${extension}/dial fallback"
  fi
  if [ -z "$dial_string" ]; then
    dial_string="PJSIP/${extension}"
    route_source="PJSIP endpoint fallback"
  fi

  if ! pjsip_dial_string_supported "$dial_string"; then
    log "Registered endpoint $extension resolves through $route_source to a non-PJSIP paging route: $dial_string"
    log "The module will not rewrite DEVICE routes or SIP peers. Configure extension $extension as a PJSIP endpoint before installing."
    return 1
  fi
  if ! pjsip_dial_string_endpoints_available "$dial_string"; then
    log "Registered endpoint $extension resolves through $route_source, but one or more referenced PJSIP endpoint objects are unavailable."
    log "The module will not rewrite DEVICE routes or SIP peers. Repair the FreePBX endpoint route, then rerun the installer."
    return 1
  fi
  log "Registered endpoint $extension has a PJSIP-capable paging route with verified endpoint objects via $route_source."
}

endpoint_inventory_records() {
  local inventory_file="$1"
  python3 -I - "$inventory_file" <<'PY'
import json
import sys

supported_formats = {
    "yealink", "yealink_text", "yealink_image", "cisco", "poly", "grandstream",
    "fanvil", "snom", "aastra", "sangoma", "avaya", "vtech",
    "ale", "panasonic", "generic", "unknown",
}

with open(sys.argv[1], encoding="utf-8") as handle:
    inventory = json.load(handle)
if not isinstance(inventory, dict):
    raise SystemExit("endpoint inventory is not a JSON object")

for extension, details in sorted(inventory.items()):
    if not isinstance(extension, str) or not isinstance(details, dict):
        raise SystemExit("endpoint inventory contains an invalid entry")
    if not extension.isdigit():
        # The notification module intentionally targets numeric FreePBX
        # extensions, not trunks or arbitrary alphanumeric PJSIP objects.
        continue
    try:
        contacts = int(details.get("contacts") or 0)
    except (TypeError, ValueError):
        raise SystemExit(f"endpoint {extension} has an invalid contact count")
    phone_format = str(details.get("format") or "").strip().lower()
    formats = details.get("formats") or [phone_format]
    if not isinstance(formats, list):
        raise SystemExit(f"endpoint {extension} has an invalid format list")
    normalized_formats = [str(value or "").strip().lower() for value in formats]
    if contacts < 1:
        raise SystemExit(f"endpoint {extension} has no registered contacts")
    if phone_format not in supported_formats or any(value not in supported_formats for value in normalized_formats):
        raise SystemExit(f"endpoint {extension} has an unsupported phone format")
    raw_user_agent = str(details.get("user_agent") or "")
    # AMI values originate at handsets. Keep terminal controls, bidi marks,
    # and other non-ASCII bytes out of root's console and installer log.
    user_agent = " ".join("".join(
        character if 0x20 <= ord(character) <= 0x7e else "?"
        for character in raw_user_agent
    ).split())[:300]
    unique_formats = sorted(set(normalized_formats))
    unknown = "1" if phone_format == "unknown" or "unknown" in unique_formats else "0"
    mixed = "1" if len(unique_formats) > 1 else "0"
    print("\t".join((
        extension,
        phone_format,
        str(contacts),
        unknown,
        mixed,
        ",".join(unique_formats),
        user_agent,
    )))
PY
}

mixed_endpoint_visual_route_supported() {
  # Contact-specific delivery is preferred, but portable endpoint fan-out with
  # generic XML is a safe runtime fallback and must not abort installation.
  return 0
}

bootstrap_cached_config_crypto_directory() {
  /usr/bin/python3 -I - "$CONFIG_CRYPTO_BOOTSTRAP_SHA256" <<'SLS_CACHED_CRYPTO_PY'
from pathlib import Path
import hashlib,itertools,os,re,stat,sys

root=Path("/var/lib/sls-mass-notify-trust")
def directory(path):
    for part in (path,*path.parents):
        info=part.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0
                or info.st_mode&0o022 and not info.st_mode&stat.S_ISVTX):
            raise ValueError('unprotected cached helper path')
def pinned(path):
    directory(path.parent)
    descriptor=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022
                or before.st_nlink!=1 or not 0<before.st_size<=262144):
            raise ValueError('unprotected cached helper')
        body=bytearray()
        while len(body)<=262144:
            block=os.read(descriptor,min(65536,262145-len(body)))
            if not block:break
            body.extend(block)
        identity=lambda value:(value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
        if len(body)!=before.st_size or identity(before)!=identity(os.fstat(descriptor)) or identity(before)!=identity(path.lstat()):
            raise ValueError('cached helper changed during inspection')
        return hashlib.sha256(body).hexdigest()==sys.argv[1]
    finally:os.close(descriptor)
try:
    directory(root)
    if root.stat().st_mode&0o077:raise ValueError('cache is not root-private')
    generations=list(itertools.islice(root.iterdir(),513))
    if len(generations)>512:raise ValueError('cached generation inventory exceeds its bound')
    for generation in sorted(generations):
        if not re.fullmatch(r'slsmassnotifyserver-[a-f0-9]{64}',generation.name):continue
        helper=generation/'module/bin/sls_mass_notify/sls_config_crypto.py'
        if not helper.exists() and not helper.is_symlink():continue
        if pinned(helper):print(helper.parent);break
    else:raise ValueError('no exact pinned helper is cached')
except (OSError,ValueError):
    sys.exit('The retained encrypted configuration needs its protected crypto helper. No exact, safe signed-cache copy was available; preserve the configuration and encryption keys and restore the authenticated runtime before retrying.')
SLS_CACHED_CRYPTO_PY
}

bootstrap_resource_capacity() {
  # Standalone installers need this before a release archive is available.
  # Keep this copy identical to the packaged helper; a regression checks parity.
  local cached_crypto_directory=""
  if [ "${1:-}" != --cpu-isa-only ] \
    && { [ -e "$CONFIG_FILE" ] || [ -L "$CONFIG_FILE" ]; } \
    && [ ! -e /usr/local/bin/sls_mass_notify/sls_config_crypto.py ] \
    && [ ! -L /usr/local/bin/sls_mass_notify/sls_config_crypto.py ]; then
    cached_crypto_directory="$(bootstrap_cached_config_crypto_directory)" || return 3
  fi
  (
  # The embedded reader uses its protected adjacent helper. A failed first
  # installation can retain settings after runtime rollback; enter only the
  # independently hash-pinned cached helper directory, without copying files.
  [ -z "$cached_crypto_directory" ] || cd "$cached_crypto_directory" || exit 3
  /usr/bin/python3 -I - "$@" <<'SLS_RESOURCE_CAPACITY_PY'
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
SLS_RESOURCE_CAPACITY_PY
  )
}

installer_profile_memory_state() {
  /usr/bin/python3 -I -c '
import json, sys
try:
    value = json.loads(sys.argv[1]); selection = value["profile_selection"]
    profile = value["deployment_profile"]
    assert profile in ("standard", "lite")
    assert type(selection["standard_memory_eligible"]) is bool
    assert type(selection["lite_memory_eligible"]) is bool
    print(profile + ":" + str(int(selection["standard_memory_eligible"])) + ":" + str(int(selection["lite_memory_eligible"])))
except (ValueError, KeyError, TypeError, AssertionError):
    raise SystemExit(1)
' "$1"
}

show_lite_install_limits() {
  log 'Lite mode limitations: at most 25 desktops and 25 phone contacts; one speech renderer and at most two waiting speech jobs.'
  log 'Lite allows four desktop SSE streams (one per username), with authenticated polling available; one Weather/Lightning delivery worker and two Weather.gov fetch workers.'
  log 'Enterprise Labs and enterprise SSO are unavailable in Lite. Saved configuration is retained; core notifications, authentication, encryption and rollback checks remain enabled.'
  log 'Lite requires two effective CPU cores, nominal 2 GiB RAM and the full storage checks. This is a low-volume beta profile, not load certification.'
}

validate_installer_memory_profile() {
  local state
  state="$(installer_profile_memory_state "$1")" || {
    log 'The installer could not verify deployment-profile RAM eligibility. No profile was guessed.'
    return 2
  }
  case "$state" in
    lite:1:*)
      log 'This PBX meets the Standard RAM baseline. Lite is only offered below that baseline; use the verified installer with --standard to convert an existing Lite installation, or remove --lite for a fresh Standard installation.'
      return 2 ;;
    lite:0:0)
      log 'This PBX does not meet the Lite RAM baseline. Add RAM before installation.'
      return 2 ;;
  esac
}

preflight_hardware_requirements() {
  local report status state lite_report answer
  # Select the final installation workspace before retaining any preparation
  # paths. Inspection has its separate, lighter source-only admission.
  local -a arguments=(--check --mode prepare --reserve-install-workspace --desktop-limit 25 --auto-phone-limit)
  if [ -e "$CONFIG_FILE" ] || [ -L "$CONFIG_FILE" ]; then
    arguments=(--check --mode prepare --reserve-install-workspace --config "$CONFIG_FILE")
  fi
  [ -z "$REQUESTED_DEPLOYMENT_PROFILE" ] || arguments+=(--profile "$REQUESTED_DEPLOYMENT_PROFILE")
  if report="$(bootstrap_resource_capacity "${arguments[@]}")"; then status=0; else status=$?; fi
  state="$(installer_profile_memory_state "$report" || true)"
  if [ "$status" -ne 0 ] && [ "$state" = standard:0:1 ] && [ "$REQUESTED_DEPLOYMENT_PROFILE" != standard ]; then
    log 'This PBX does not meet the 4 GiB Standard RAM baseline. Checking whether the bounded Lite profile can be offered.'
    if lite_report="$(bootstrap_resource_capacity "${arguments[@]}" --profile lite)"; then
      validate_installer_memory_profile "$lite_report" || return $?
      show_lite_install_limits
      if [ ! -t 0 ] || { [ ! -t 1 ] && [ ! -t 2 ]; }; then
        log 'Lite was not selected. Run from an interactive terminal to choose it, or explicitly pass --lite to accept these limitations for an unattended installation.'
        return 2
      fi
      answer=""
      if ! read -r -t 120 -p 'Would you like to install Lite with these limitations? [y/N] ' answer; then answer=""; fi
      case "$answer" in
        y|Y|yes|YES|Yes)
          REQUESTED_DEPLOYMENT_PROFILE=lite
          FRESH_DEPLOYMENT_PROFILE=lite
          report="$lite_report"
          status=0
          log 'Lite selected after explicit confirmation.' ;;
        *) log 'Installation cancelled; Lite was not selected.'; return 2 ;;
      esac
    else
      status=$?
      report="$lite_report"
      log 'Lite cannot be offered because its CPU, RAM, phone-capacity or storage requirements are not met.'
    fi
  fi
  if [ "$status" -eq 0 ]; then
    validate_installer_memory_profile "$report" || return $?
    if [ "$state" = lite:0:1 ]; then show_lite_install_limits; fi
    select_install_temp_root "$report" || return 1
    if [ ! -e "$CONFIG_FILE" ]; then
      remember_fresh_phone_capacity "$report" || return 1
    fi
    log "Combined PBX/SLL CPU/RAM and dedicated SLL free-space headroom verified (provisional allocation; not a load certification)."
    printf '%s\n' "$report" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}"
    return 0
  fi
  log "Resource admission failed before optional dependency or module changes."
  printf '%s\n' "$report" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}"
  /usr/bin/python3 -I -c '
import json, sys
try:
    result = json.loads(sys.argv[1])
    for item in result.get("errors", [])[:20]:
        print("[" + str(item.get("code", "resource_error"))[:80] + "] " + str(item.get("message", "Review the installer log."))[:1000])
except (ValueError, TypeError, AttributeError):
    print("The resource probe did not return valid diagnostics. Review the installer log before retrying.")
' "$report"
  return "$status"
}

install_temporary_root_action() {
  /usr/bin/python3 -I - "$@" <<'PYSLSINSTALLTEMP'
from pathlib import Path
import errno, json, os, pwd, stat, sys
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

def select_private_install_temporary(report, root=Path('/')):
    storage = report['requirements']['storage']
    admitted = storage['temporary_directory_state']
    current = private_install_temporary_state(root, allow_missing=True)
    if (storage.get('temporary_directory') != PRIVATE_INSTALL_TEMP
            or storage.get('mode') not in ('prepare', 'install')
            or type(admitted.get('exists')) is not bool
            or type(admitted.get('uid')) is not int
            or admitted.get('uid') != current['uid']
            or type(admitted.get('gid')) is not int
            or admitted.get('gid') != current['gid']
            or admitted.get('parent_identity') != current['parent_identity']
            or any(type(v) is not int for v in admitted.get('parent_identity', {}).values())
            or (admitted['exists'] and admitted.get('identity') != current['identity'])
            or (not current['exists'] and storage.get('mode') == 'prepare'
                and storage.get('install_workspace_reserved') is not True)):
        raise ValueError('private installer workspace admission changed')
    rows = [row for row in report['hardware']['filesystems'] if PRIVATE_INSTALL_TEMP in row.get('paths', [])]
    if len(rows) != 1 or rows[0].get('filesystem_type') in ('tmpfs', 'ramfs', 'devtmpfs') or rows[0].get('read_only') or rows[0].get('volatile_targets'):
        raise ValueError('private installer workspace must be a writable persistent filesystem')
    row = rows[0]
    required = row['required_free_bytes']
    inodes = row.get('required_inodes', 0)
    if type(required) is not int or required < 0 or type(inodes) is not int or inodes < 0:
        raise ValueError('invalid aggregate private workspace reservation')
    parent = _private_spool_parent(root)
    name = Path(PRIVATE_INSTALL_TEMP).name
    created = False
    selected = None
    try:
        stamp = lambda info: {key: getattr(info, 'st_' + key) for key in ('dev', 'ino', 'uid', 'gid', 'mode')}
        if stamp(os.fstat(parent)) != admitted['parent_identity']:
            raise ValueError('private installer workspace parent changed before creation')
        if not current['exists']:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
                created = True
            except FileExistsError:
                pass
            if created:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    selected = stamp(os.fstat(child))
                    os.fchown(child, 0, current['gid'])
                    os.fchmod(child, 0o710)
                    selected = stamp(os.fstat(child))
                    os.fsync(child)
                finally:
                    os.close(child)
                os.fsync(parent)
        final = private_install_temporary_state(root)
        if final['parent_identity'] != admitted['parent_identity'] or final['uid'] != current['uid'] or final['gid'] != current['gid'] or (selected is not None and final['identity'] != selected):
            raise ValueError('private installer workspace identity changed after creation')
        if final['read_only'] or final['available_bytes'] < required or (final['available_inodes'] is not None and final['available_inodes'] < inodes):
            raise ValueError('private installer workspace lost admitted aggregate capacity')
        return {'path': PRIVATE_INSTALL_TEMP, 'identity': final['identity'], 'created': created}
    except BaseException:
        if created and selected is not None:
            try:
                if stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == selected:
                    os.rmdir(name, dir_fd=parent)
                    os.fsync(parent)
            except OSError:
                pass
        raise
    finally:
        os.close(parent)


def cleanup_private_install_temporary(identity, root=Path('/')):
    if not isinstance(identity, dict) or set(identity) != {'dev', 'ino', 'uid', 'gid', 'mode'} or any(type(v) is not int for v in identity.values()):
        raise ValueError('typed selected private workspace identity required')
    current = private_install_temporary_state(root, allow_missing=True)
    if not current['exists']:
        return True
    if current['identity'] != identity:
        raise ValueError('selected private workspace changed; preserve it')
    parent = _private_spool_parent(root)
    name = Path(PRIVATE_INSTALL_TEMP).name
    try:
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            if os.listdir(child):
                return False
            stamp = lambda info: {key: getattr(info, 'st_' + key) for key in ('dev', 'ino', 'uid', 'gid', 'mode')}
            if stamp(os.fstat(child)) != identity or stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity:
                raise ValueError('private workspace changed before empty cleanup')
        finally:
            os.close(child)
        try:
            os.rmdir(name, dir_fd=parent)
        except OSError as error:
            if error.errno in (errno.ENOTEMPTY, errno.EEXIST):
                return False
            raise
        os.fsync(parent)
        return True
    finally:
        os.close(parent)

if sys.argv[1] == 'cleanup':
    print(json.dumps({'removed_if_empty': cleanup_private_install_temporary(json.loads(sys.argv[2]))}))
else:
    report = json.loads(sys.argv[2])
    path = report.get('requirements', {}).get('storage', {}).get('temporary_directory', '/tmp')
    if path == PRIVATE_INSTALL_TEMP:
        print(json.dumps(select_private_install_temporary(report), sort_keys=True))
    else:
        if path not in ('/tmp', '/var/tmp'):
            raise ValueError('Unsupported installation workspace')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in path.split('/')[1:]:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
                info = os.fstat(fd)
                if info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                    raise ValueError('Unsafe standard installation workspace')
        finally:
            os.close(fd)
        print(json.dumps({'path': path, 'identity': None, 'created': False}))
PYSLSINSTALLTEMP
}

select_install_temp_root() {
  local selection directory
  selection="$(install_temporary_root_action select "$1")" || { log 'The selected temporary directory is unsafe or lost capacity; no module or dependency changes were started.'; return 1; }
  directory="$(/usr/bin/python3 -I -c 'import json,sys;print(json.loads(sys.argv[1])["path"])' "$selection")" || return 1
  INSTALL_PRIVATE_WORKSPACE_IDENTITY="$(/usr/bin/python3 -I -c 'import json,sys;print(json.dumps(json.loads(sys.argv[1])["identity"]))' "$selection")" || return 1
  INSTALL_TEMP_ROOT="$directory"
  export TMPDIR="$directory"
  log "Installer workspaces: $INSTALL_TEMP_ROOT (free space verified on its actual filesystem)."
}

cleanup_install_temp_root() {
  [ -n "${INSTALL_PRIVATE_WORKSPACE_IDENTITY:-}" ] && [ "$INSTALL_PRIVATE_WORKSPACE_IDENTITY" != null ] || return 0
  install_temporary_root_action cleanup "$INSTALL_PRIVATE_WORKSPACE_IDENTITY" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 \
    || log 'Private installer scratch was retained for review; no unknown entries were removed.'
}

remember_fresh_phone_capacity() {
  local capacity profile
  profile="$FRESH_DEPLOYMENT_PROFILE"
  capacity="$(/usr/bin/python3 -I -c '
import json, sys
report = json.loads(sys.argv[1]); profile = sys.argv[2]
selection = report["auto_phone_selection"]
count, limit = selection["detected_phone_contacts"], report["requested_phone_limit"]
assert type(count) is int and 0 <= count <= 1000
assert profile in ("standard", "lite") and report["deployment_profile"] == profile
expected = 25 if profile == "lite" or count <= 25 else (count + 49) // 50 * 50
assert type(limit) is int and limit == expected
assert selection["rounded_phone_capacity"] == limit and not report["errors"]
print(limit)
' "$1" "$profile")" || { log 'The detected phone capacity could not be verified; no default was guessed.'; return 1; }
  FRESH_PHONE_CAPACITY="$capacity"
  if [ "$profile" = lite ]; then
    log "Fresh-install profile: Lite; capacity is limited to 25 desktops and 25 phone contacts (resources verified)."
  else
    log "Fresh-install profile: Standard; phone capacity is $FRESH_PHONE_CAPACITY contacts (25 minimum, rounded up in blocks of 50; resources verified)."
  fi
}

verify_staged_hardware_requirements() {
  local helper="$STAGING_DIR/$MODULE/bin/sls_mass_notify/sls_resource_capacity.py"
  local report
  local -a arguments=(--check --desktop-limit 25 --auto-phone-limit)
  if [ -e "$CONFIG_FILE" ]; then
    arguments=(--check --config "$CONFIG_FILE")
  fi
  [ -z "$REQUESTED_DEPLOYMENT_PROFILE" ] || arguments+=(--profile "$REQUESTED_DEPLOYMENT_PROFILE")
  report="$(/usr/bin/python3 -I "$helper" "${arguments[@]}" --mode install --candidate-source "$STAGING_DIR/$MODULE" --temporary-directory "$INSTALL_TEMP_ROOT" --prepared-release-review "$UPGRADE_TRUST_DIR" 2>>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}")" || {
    log "$report"
    log "This PBX does not meet the configured desktop/phone capacities or SLL free-space requirements. See $LOG_FILE."
    return 1
  }
  validate_installer_memory_profile "$report" || return $?
  CAPACITY_STOCK_CACHE_PROOF_SHA256="$(/usr/bin/python3 -I -c '
import json,re,sys
value=json.loads(sys.argv[1]);storage=value.get("requirements",{}).get("storage",{})
if (storage.get("release_storage_proof_kind")=="sll-prepared-upgrade-storage-proof-v3"
        and isinstance(storage.get("stock_cache_publication_sizes"),list)):
    digest=storage.get("release_storage_proof_canonical_sha256")
    if not isinstance(digest,str)or re.fullmatch("[a-f0-9]{64}",digest)is None:raise SystemExit(1)
    print(digest)
' "$report")" || return 1
  printf '%s\n' "$report" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}"
  if [ ! -e "$CONFIG_FILE" ]; then
    remember_fresh_phone_capacity "$report"
  fi
}

preflight_platform() {
  local apache_module apache_modules utility
  # Runtime and dialplan paths are conventional FreePBX paths. Detect a
  # relocated installation explicitly instead of creating a second, unused tree.
  sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 20 /usr/bin/php <<'PHP' || {
<?php
require '/etc/freepbx.conf';
$expected = ['AMPWEBROOT'=>'/var/www/html', 'ASTETCDIR'=>'/etc/asterisk',
    'ASTSPOOLDIR'=>'/var/spool/asterisk', 'ASTVARLIBDIR'=>'/var/lib/asterisk',
    'AMPASTERISKUSER'=>'asterisk', 'AMPASTERISKGROUP'=>'asterisk'];
foreach ($expected as $key => $path) {
    $actual = rtrim((string)($amp_conf[$key] ?? ''), '/');
    if ($actual !== $path) {
        fwrite(STDERR, 'Unsupported FreePBX layout: ' . $key . ' must be ' . $path . '. No alternate runtime tree will be created.' . PHP_EOL);
        exit(1);
    }
}
exit(0);
PHP
    log "This FreePBX layout requires an explicitly supported path adapter; installation stopped before activation."
    exit 1
  }
  for utility in timeout runuser flock readlink; do
    command -v "$utility" >/dev/null || {
      log "Required system utility is unavailable: $utility"
      exit 1
    }
  done
  /usr/sbin/apache2ctl configtest >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
    log "Apache configuration validation failed before installation. See $LOG_FILE."
    exit 1
  }
  log 'Apache configuration accepted. DocumentRoot warnings from other virtual hosts do not fail this check; the PBX and SLL routes are verified separately.'
  systemctl is-active --quiet apache2 || {
    log "Apache is not active."
    exit 1
  }
  systemctl is-active --quiet cron || {
    if [ "${1:-}" = check ]; then
      log 'The cron scheduler is inactive; the approved dependency phase will repair/start it before activation.'
    else
      log 'The cron scheduler is still inactive after dependency repair. Start cron and retry.'
      exit 1
    fi
  }
  apache_modules="$(/usr/sbin/apache2ctl -M 2>/dev/null)"
  for apache_module in rewrite_module setenvif_module; do
    grep -Fq "$apache_module" <<<"$apache_modules" || {
      log "Required Apache module is not loaded: $apache_module"
      exit 1
    }
  done
  asterisk -rx "core show version" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
    log "The Asterisk control socket is unavailable. Start Asterisk before installing."
    exit 1
  }
  verify_supported_asterisk_directories || {
    log "Asterisk uses paths this release does not support; no module files were activated."
    exit 1
  }
  validate_piper_wrapper_ownership /usr/local/bin/piper || exit 1
  preflight_piper_platform || exit 1
  local ASTERISK_READ_ONLY_ADMISSION=0
  if [ "${1:-}" = check ]; then ASTERISK_READ_ONLY_ADMISSION=1; fi
  verify_asterisk_module_startup_persistence || exit 1
  local module_name
  for module_name in \
    res_pjsip.so res_pjsip_session.so chan_pjsip.so res_pjsip_notify.so \
    pbx_spool.so format_wav.so; do
    ensure_asterisk_module_loaded "$module_name" || exit 1
  done
  asterisk_channel_type_available Local || {
    log "Required Asterisk Local channel driver is unavailable."
    exit 1
  }
  ensure_required_asterisk_capabilities || {
    log "Required Asterisk paging capabilities are unavailable before module activation."
    exit 1
  }
  if [ "$ASTERISK_READ_ONLY_ADMISSION" -eq 1 ]; then return 0; fi
  secure_asterisk_spool || exit 1
}

preflight_piper_platform() {
  [ -x /usr/bin/unshare ] && [ -x /usr/bin/mount ] || {
    log 'Piper environment repair requires util-linux unshare and mount. Install that prerequisite before retrying; no SLL runtime was changed.'
    return 1
  }
  /usr/bin/timeout 5 /usr/bin/unshare --mount --propagation private /usr/bin/mount --bind / / >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
    log 'This host does not permit the private mount namespace required for safe Piper environment replacement. Grant this capability to the test/container host or use a supported FreePBX VM; existing runtime and services were preserved.'
    return 1
  }
  /usr/bin/python3 -I -c 'import ctypes; assert hasattr(ctypes.CDLL(None), "renameat2")' || {
    log 'Atomic Piper replacement requires renameat2 support in the system libc. Existing runtime and services were preserved.'
    return 1
  }
}

secure_asterisk_spool() {
  /usr/bin/python3 -I - <<'PYSPOOL'
import os, pwd, stat
account = pwd.getpwnam('asterisk')
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
parent = os.open('/', flags)
handles = []
def safe(info, owners, groups, writable_mask):
    return (stat.S_ISDIR(info.st_mode) and info.st_uid in owners and
            info.st_gid in groups and not info.st_mode & (0o7000 | writable_mask))
try:
    for part in ('var', 'spool', 'asterisk'):
        child = os.open(part, flags, dir_fd=parent)
        os.close(parent); parent = child
        info = os.fstat(parent)
        allowed = (0, account.pw_uid) if part == 'asterisk' else (0,)
        groups = (0, account.pw_gid) if part == 'asterisk' else (0,)
        if not safe(info, allowed, groups, 0o002 if part == 'asterisk' else 0o022):
            raise RuntimeError('Unsafe Asterisk spool parent; no spool permissions were changed')
    for name, mode in (('tmp', 0o775), ('outgoing', 0o775), ('outgoing_done', 0o750)):
        try: child = os.open(name, flags, dir_fd=parent)
        except FileNotFoundError:
            handles.append((name, None, mode))
            continue
        handles.append((name, child, mode))
        info = os.fstat(child)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not safe(info, (0, account.pw_uid), (0, account.pw_gid), 0o002) or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError('Unsafe Asterisk spool directory ownership or permissions; review the directory before retrying. No spool permissions were changed')
    # Validate all existing destinations before applying any permission repair.
    for index, (name, child, mode) in enumerate(handles):
        if child is None:
            os.mkdir(name, 0o750, dir_fd=parent)
            child = os.open(name, flags, dir_fd=parent)
            handles[index] = (name, child, mode)
    for name, child, mode in handles:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        info = os.fstat(child)
        if not safe(info, (0, account.pw_uid), (0, account.pw_gid), 0o002) or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError('Asterisk spool directory changed during preparation')
    for name, child, mode in handles:
        os.fchown(child, account.pw_uid, account.pw_gid)
        os.fchmod(child, mode)
finally:
    for _, child, _ in handles:
        if child is not None: os.close(child)
    os.close(parent)
PYSPOOL
}

validate_piper_wrapper_ownership() {
  local wrapper="${1:-/usr/local/bin/piper}"
  local target wrapper_uid wrapper_gid wrapper_links wrapper_size wrapper_mode wrapper_permissions wrapper_hash
  if [ ! -e "$wrapper" ] && [ ! -L "$wrapper" ]; then
    return 0
  fi
  if [ -L "$wrapper" ]; then
    target="$(readlink "$wrapper" 2>/dev/null || true)"
    case "$target" in
      /usr/local/bin/sls_mass_notify/piper/venv/bin/piper|/var/lib/asterisk/SLS_Mass_Notifications_Plugin/piper/venv/bin/piper)
        if [ "$wrapper" = /usr/local/bin/piper ] \
          && [ "$(stat -c '%u:%g:%h' -- "$wrapper" 2>/dev/null || true)" != "0:0:1" ]; then
          log "$wrapper has unsafe ownership or link metadata. SLL Mass Notify Server did not replace it."
          return 1
        fi
        return 0
        ;;
    esac
  elif [ -f "$wrapper" ]; then
    IFS=: read -r wrapper_uid wrapper_gid wrapper_links wrapper_size wrapper_mode \
      <<<"$(stat -c '%u:%g:%h:%s:%a' -- "$wrapper" 2>/dev/null || true)"
    [[ "$wrapper_uid" =~ ^[0-9]+$ && "$wrapper_gid" =~ ^[0-9]+$ \
      && "$wrapper_links" = 1 && "$wrapper_size" =~ ^[0-9]+$ \
      && "$wrapper_size" -le 16384 && "$wrapper_mode" =~ ^[0-7]{3,4}$ ]] || {
      log "$wrapper has unsafe ownership, link count, size, or permissions. SLL Mass Notify Server did not replace it."
      return 1
    }
    wrapper_permissions=$((8#$wrapper_mode))
    if (( (wrapper_permissions & 07022) != 0 )); then
      log "$wrapper has unsafe permissions. SLL Mass Notify Server did not replace it."
      return 1
    fi
    if [ "$wrapper" = /usr/local/bin/piper ] && { [ "$wrapper_uid" -ne 0 ] || [ "$wrapper_gid" -ne 0 ]; }; then
      log "$wrapper is not owned by root:root. SLL Mass Notify Server did not replace it."
      return 1
    fi
    wrapper_hash="$(/usr/bin/sha256sum -- "$wrapper" 2>/dev/null || true)"
    wrapper_hash="${wrapper_hash%% *}"
    case "$wrapper_hash" in
      dc52fdc05dc72b9d8637cdc89b6e7bbb59e5ebe542652d6551615643f80688f5|a2f9671cb1f69acc055a88f58b9fb610578f5efea43a047938b16ed8634f4d56|97792a8e4ca9f3f48be0be0c24202921008807da030ac85438b58034f21130e4|4c6c0dfe69c1b59b8650c0c5a9d38adf5a9c6cbe311c283a929a7fc5580015c0)
        return 0
        ;;
    esac
  fi
  log "$wrapper already belongs to another application. SLL Mass Notify Server did not overwrite it."
  log "Move or rename that wrapper explicitly, then rerun the installer if SLL should own the compatibility path."
  return 1
}

install_bootstrap_dependencies() {
  local -a missing_packages=()

  [ -x /usr/bin/php ] || missing_packages+=(php-cli)
  if [ -x /usr/bin/php ]; then
    /usr/bin/php -r 'exit(function_exists("openssl_encrypt") && function_exists("openssl_decrypt") ? 0 : 1);' >/dev/null 2>&1 \
      || missing_packages+=(php-common)
  else
    missing_packages+=(php-common)
  fi
  { [ -x /usr/bin/flock ] && [ -x /usr/sbin/runuser ] && [ -x /usr/bin/prlimit ]; } || missing_packages+=(util-linux)
  { [ -x /usr/bin/timeout ] && [ -x /usr/bin/readlink ]; } || missing_packages+=(coreutils)
  [ -x /usr/bin/timedatectl ] || missing_packages+=(systemd)
  [ -r /usr/share/zoneinfo/UTC ] || missing_packages+=(tzdata)
  [ -x /usr/bin/openssl ] || missing_packages+=(openssl)
  [ -x /usr/bin/gpg ] || missing_packages+=(gnupg)
  { [ -x /usr/bin/curl ] || [ -x /usr/bin/wget ]; } || missing_packages+=(curl)

  if [ "${#missing_packages[@]}" -gt 0 ]; then
    command -v apt-get >/dev/null 2>&1 || {
      log "Missing installation bootstrap prerequisites and no supported Debian package manager is available: ${missing_packages[*]}"
      exit 1
    }
    log "Installing missing installation bootstrap prerequisites: ${missing_packages[*]}"
    refresh_apt_metadata || {
      log "Unable to refresh Debian package metadata for bootstrap prerequisites. See $LOG_FILE."
      exit 1
    }
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-remove "${missing_packages[@]}"
  fi

  for bootstrap_utility in /usr/bin/php /usr/bin/flock /usr/bin/readlink /usr/bin/timeout /usr/bin/timedatectl /usr/sbin/runuser; do
    [ -x "$bootstrap_utility" ] || {
      log "A required installation bootstrap prerequisite is unavailable after dependency installation: $bootstrap_utility"
      exit 1
    }
  done
  /usr/bin/php -r 'exit(function_exists("openssl_encrypt") && function_exists("openssl_decrypt") ? 0 : 1);' || {
    log "The PHP OpenSSL extension is required for protected desktop credentials. Install php-common, then rerun the installer."
    exit 1
  }
  [ -r /usr/share/zoneinfo/UTC ] || {
    log "The IANA timezone database is required. Install tzdata, then rerun the installer."
    exit 1
  }
}

install_dependencies() {
  local package
  local -a missing_packages=()
  add_missing_package() {
    local candidate="$1"
    local existing
    for existing in "${missing_packages[@]:-}"; do
      [ "$existing" = "$candidate" ] && return 0
    done
    missing_packages+=("$candidate")
  }

  if command -v apt-get >/dev/null; then
    [ -x /usr/bin/curl ] || add_missing_package curl
    [ -x /usr/bin/wget ] || add_missing_package wget
    [ -r /etc/ssl/certs/ca-certificates.crt ] || add_missing_package ca-certificates
    [ -x /usr/bin/gpg ] || add_missing_package gnupg
    [ -x /usr/bin/openssl ] || add_missing_package openssl
    [ -x /usr/sbin/logrotate ] || add_missing_package logrotate
    [ -x /usr/bin/python3 ] || add_missing_package python3
    if [ -x /usr/bin/python3 ]; then
      /usr/bin/python3 -I -c 'import ensurepip, venv; ensurepip.version()' >/dev/null 2>&1 || add_missing_package python3-venv
      /usr/bin/python3 -I -m pip --version >/dev/null 2>&1 || add_missing_package python3-pip
    else
      add_missing_package python3-venv
      add_missing_package python3-pip
    fi
    { [ -x /usr/bin/sox ] && [ -x /usr/bin/soxi ]; } || add_missing_package sox
    { [ -x /usr/bin/convert ] && [ -x /usr/bin/identify ]; } || add_missing_package imagemagick
    [ -r /usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf ] || add_missing_package fonts-dejavu-core
    [ -x /usr/bin/tar ] || add_missing_package tar
    [ -x /usr/bin/php ] || add_missing_package php-cli
    if [ -x /usr/bin/php ]; then
      local sls_php_runtime_version
      sls_php_runtime_version="$(/usr/bin/php -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;')"
      [[ "$sls_php_runtime_version" =~ ^[0-9]+\.[0-9]+$ ]] || { log "Cannot identify the active PHP runtime for extension installation."; exit 1; }
      /usr/bin/php -r 'exit(extension_loaded("pdo_sqlite") ? 0 : 1);' >/dev/null 2>&1 || add_missing_package "php${sls_php_runtime_version}-sqlite3"
      /usr/bin/php -r 'exit(function_exists("curl_init") ? 0 : 1);' >/dev/null 2>&1 || add_missing_package "php${sls_php_runtime_version}-curl"
      /usr/bin/php -r 'exit(class_exists("DOMDocument") ? 0 : 1);' >/dev/null 2>&1 || add_missing_package "php${sls_php_runtime_version}-xml"
      /usr/bin/php -r 'exit(extension_loaded("mbstring") && function_exists("mb_strlen") && function_exists("mb_substr") ? 0 : 1);' >/dev/null 2>&1 || add_missing_package "php${sls_php_runtime_version}-mbstring"
      /usr/bin/php -r 'exit(function_exists("posix_getpwnam") && function_exists("openssl_encrypt") && function_exists("openssl_decrypt") && function_exists("sodium_crypto_pwhash") && function_exists("sodium_crypto_aead_xchacha20poly1305_ietf_encrypt") ? 0 : 1);' >/dev/null 2>&1 || add_missing_package "php${sls_php_runtime_version}-common"
    else
      add_missing_package php-mbstring
      add_missing_package php-sqlite3
      add_missing_package php-curl
      add_missing_package php-xml
    fi
    local served_profile served_version served_package
    while IFS= read -r served_profile; do
      [ -n "$served_profile" ] || continue
      served_version="${served_profile%:*}"
      for served_package in cli common sqlite3 curl xml mbstring; do
        dpkg-query -W -f='${Status}' "php${served_version}-${served_package}" 2>/dev/null | grep -Exq '(install|hold) ok installed' \
          || add_missing_package "php${served_version}-${served_package}"
      done
    done <<<"$SERVED_PHP_PROFILES"
    /usr/bin/python3 -I -c 'from cryptography.hazmat.primitives.ciphers.aead import AESGCM' >/dev/null 2>&1 || add_missing_package python3-cryptography
    [ -x /usr/bin/node ] || add_missing_package nodejs
    { [ -x /usr/bin/crontab ] && [ -x /usr/sbin/cron ]; } || add_missing_package cron
    { [ -x /usr/bin/flock ] && [ -x /usr/sbin/runuser ] && [ -x /usr/bin/prlimit ]; } || add_missing_package util-linux
    { [ -x /usr/bin/timeout ] && [ -x /usr/bin/readlink ]; } || add_missing_package coreutils

    if [ "${#missing_packages[@]}" -gt 0 ]; then
      log "Installing missing runtime prerequisites: ${missing_packages[*]}"
      refresh_apt_metadata || {
        log "Unable to refresh Debian package metadata for missing prerequisites. See $LOG_FILE."
        exit 1
      }
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-remove "${missing_packages[@]}"
    else
      log "Runtime package prerequisites are already available; skipping apt metadata refresh."
    fi
  else
    command -v curl >/dev/null || command -v wget >/dev/null || {
      log "curl or wget is required to download the module."
      exit 1
    }
    command -v python3 >/dev/null || {
      log "python3 is required."
      exit 1
    }
    command -v sox >/dev/null || {
      log "sox is required."
      exit 1
    }
    { command -v convert >/dev/null && command -v identify >/dev/null; } || {
      log "ImageMagick is required for phone alert images."
      exit 1
    }
  fi
  /usr/bin/python3 -I -c 'import ensurepip, venv; ensurepip.version()' >/dev/null 2>&1 || {
    log "Python virtual-environment bootstrap support is unavailable after dependency installation. Install the matching python3-venv package, then rerun the installer; no Piper environment was replaced."
    exit 1
  }
  [ -x /usr/bin/php ] || {
    log "The scheduling worker requires the canonical /usr/bin/php CLI executable. Install php-cli, then rerun the installer."
    exit 1
  }
  /usr/bin/php -r 'exit(extension_loaded("pdo_sqlite") && function_exists("curl_init") && class_exists("DOMDocument") ? 0 : 1);' || {
    log "The active PHP CLI still lacks SQLite, cURL or XML after dependency installation. Enable the matching PHP-version extensions and verify the PBX web PHP runtime uses them too. No module activation was attempted."
    exit 1
  }
  /usr/bin/php -r 'exit(extension_loaded("mbstring") && function_exists("mb_strlen") && function_exists("mb_substr") ? 0 : 1);' || {
    log "The PHP mbstring extension is required for safe alert text validation. Install php-mbstring, then rerun the installer."
    exit 1
  }
  /usr/bin/php -r 'exit(function_exists("posix_getpwnam") ? 0 : 1);' || {
    log "PHP POSIX support is required to resolve the configured FreePBX service account safely. Install php-common, then rerun the installer."
    exit 1
  }
  /usr/bin/php -r 'exit(function_exists("sem_get") && function_exists("sem_acquire") && function_exists("sem_remove") ? 0 : 1);' || {
    log "Native FreePBX cron coordination requires PHP sysvsem with sem_get, sem_acquire and sem_remove enabled. Restore these in the active CLI and Apache/FPM configuration before retrying; no module activation was attempted."
    exit 1
  }
  /usr/bin/php -r 'exit(function_exists("sodium_crypto_pwhash") && function_exists("sodium_crypto_aead_xchacha20poly1305_ietf_encrypt") ? 0 : 1);' || {
    log "PHP Sodium is unavailable for authenticated encrypted configuration backups. Enable sodium for the installed PHP CLI and PBX web PHP versions, then rerun the installer. The protected configuration was not rewritten."
    exit 1
  }
  /usr/bin/php -r 'exit(function_exists("openssl_encrypt") && function_exists("openssl_decrypt") ? 0 : 1);' || {
    log "The PHP OpenSSL extension is required for protected desktop credentials. Install php-common, then rerun the installer."
    exit 1
  }
  [ -r /usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf ] || {
    log "The DejaVu Sans Bold font required for phone alert images is unavailable after dependency installation."
    exit 1
  }
  for package in /usr/bin/curl /usr/bin/wget /usr/bin/gpg /usr/bin/python3 /usr/bin/sox /usr/bin/soxi /usr/bin/convert /usr/bin/identify /usr/bin/tar /usr/bin/crontab /usr/bin/flock /usr/bin/readlink /usr/bin/timeout /usr/sbin/runuser; do
    [ -x "$package" ] || {
      log "A required runtime prerequisite is still unavailable after dependency installation: $package"
      exit 1
    }
  done
  if [ "$STATIC_MUTATION_STARTED" -eq 1 ] && [ "$FREEPBX_CONFIRMED" -eq 1 ]; then
    systemctl is-active --quiet cron || {
      log 'Starting the stock cron scheduler after authenticated upgrade approval.'
      systemctl start cron || { log 'The stock cron scheduler could not start; no module activation was attempted.'; return 1; }
    }
  fi
}

preflight_python() {
  command -v python3 >/dev/null || {
    log "python3 is required."
    exit 1
  }
  python3 --version >/dev/null 2>&1 || {
    log "python3 is installed but not executable or broken."
    exit 1
  }
  python_path="$(command -v python3)"
  [ -x "$python_path" ] || {
    log "$python_path exists but is not executable."
    exit 1
  }
  /usr/bin/python3 -I - <<'PYABI' || return 1
import platform, sys
if sys.implementation.name != 'cpython' or sys.version_info[:2] != (3, 11) or platform.machine() not in ('x86_64', 'amd64'):
    raise SystemExit('This release qualifies Debian 12 / CPython 3.11 / amd64 binary dependencies. This interpreter or architecture needs a separately tested, hash-locked wheel profile; no protected runtime was changed.')
if platform.libc_ver()[0] != 'glibc':
    raise SystemExit('The qualified Piper wheel profile requires glibc; this libc needs a separately tested profile.')
print('Qualified Python ABI and architecture verified before protected runtime preparation.')
PYABI
  local cpu_isa_report cpu_isa_status
  if cpu_isa_report="$(bootstrap_resource_capacity --cpu-isa-only)"; then cpu_isa_status=0; else cpu_isa_status=$?; fi
  if [ "$cpu_isa_status" -ne 0 ]; then
    printf '%s\n' "$cpu_isa_report" | /usr/bin/python3 -I -c 'import json,sys; report=json.load(sys.stdin); [print("["+row["code"]+"] "+row["message"], file=sys.stderr) for row in report.get("errors", [])]'
    log 'Pinned speech runtime CPU admission failed before protected runtime preparation.'
    return "$cpu_isa_status"
  fi
  log 'Pinned speech runtime x86-64-v2 CPU baseline verified; AVX is not required by this baseline check.'
}

bootstrap_missing_dashboard() {
  [ ! -e /var/www/html/admin/modules/dashboard ] && [ ! -L /var/www/html/admin/modules/dashboard ] || return 0
  local version="${SLS_MASS_NOTIFY_BOOTSTRAP_DASHBOARD_VERSION:-}" evidence
  if [ -z "$version" ]; then
    version="$(php -r '$bootstrap_settings=["freepbx_auth"=>false,"skip_astman"=>true]; require "/etc/freepbx.conf"; $modules=\module_functions::create()->getonlinexml("dashboard"); echo (string)($modules["dashboard"]["version"] ?? ""); exit(0);')" || return 1
  fi
  [[ "$version" =~ ^17\.[0-9]+(\.[0-9]+){1,3}$ ]] || {
    log 'Dashboard is absent and its stock version could not be discovered. Supply SLS_MASS_NOTIFY_BOOTSTRAP_DASHBOARD_VERSION=17.x.x and its independently signed upstream package; no SLL maintenance was changed.'
    return 1
  }
  /usr/bin/dpkg --compare-versions "$version" ge 17.0.5 || {
    log 'The absent Dashboard stock package is below the reviewed vendor floor 17.0.5. Select a current independently signed 17.x stock package; no Dashboard files or native hooks were changed.'
    return 1
  }
  evidence="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-stock-bootstrap.XXXXXX")" || return 1
  chmod 0700 "$evidence" || return 1
  run_logged /usr/bin/python3 -I "$INSTALL_BOOTSTRAP_DIR/sls_upgrade_trust.py" --workspace "$evidence" --bootstrap-dashboard-version "$version" || return 1
  log "Installing independently authenticated stock Dashboard $version. Stock dependency evidence: $evidence"
  install_native_module dashboard || {
    log 'The authenticated stock Dashboard was staged, but FreePBX could not register it. Preserve the stock bootstrap evidence; repair Dashboard through Module Admin before retrying. Existing SLL runtime and maintenance remain unchanged.'
    return 1
  }
  module_enabled dashboard || {
    log 'The authenticated Dashboard install returned without enabled native registration. Preserve the stock bootstrap evidence and review Module Admin before retrying.'
    return 1
  }
}

detect_served_php_profiles() {
  SERVED_PHP_PROFILES="$(/usr/bin/python3 -I - <<'PYPHPHANDLER'
from pathlib import Path
import configparser, grp, os, pwd, re, stat, subprocess

def protected_config(path, freepbx_managed=False):
    # Validate enabled links and their resolved sources. Only FreePBX-managed
    # Apache evidence admits asterisk ownership; FPM pool evidence stays root-owned.
    path=Path(path);owners={0}
    if freepbx_managed:
        try: owners.add(pwd.getpwnam('asterisk').pw_uid)
        except KeyError: raise SystemExit('The asterisk account is required to inspect FreePBX-managed Apache configuration.')
    for item in (path,*path.parents):
        info=item.lstat()
        if info.st_uid not in owners: raise SystemExit('PHP handler evidence has an unexpected owner: '+str(path))
        if stat.S_ISLNK(info.st_mode): continue
        if info.st_mode&0o022 and not (item==Path('/tmp') and info.st_mode&stat.S_ISVTX):
            raise SystemExit('PHP handler evidence has a writable parent or source: '+str(path))
    resolved=path.resolve(strict=True)
    for item in (resolved,*resolved.parents):
        info=item.lstat()
        if info.st_uid not in owners or info.st_mode&0o022 and not (item==Path('/tmp') and info.st_mode&stat.S_ISVTX):
            raise SystemExit('PHP handler evidence is not protected: '+str(path))
    info=resolved.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>1048576:
        raise SystemExit('PHP handler evidence must be a bounded regular file: '+str(path))
    fd=os.open(resolved,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as handle:
        before=os.fstat(handle.fileno());body=handle.read(1048577);after=os.fstat(handle.fileno())
    identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid not in owners or before.st_mode&0o022 or len(body)>1048576 or len(body)!=before.st_size or identity(before)!=identity(after):
        raise SystemExit('PHP handler evidence changed or exceeded its inspection bound: '+str(path))
    return body.decode('utf-8','replace')

def local_socket(path):
    return '/run/php/'+path[len('/var/run/php/'):] if path.startswith('/var/run/php/') else path

result = subprocess.run(['/usr/sbin/apache2ctl','-t','-D','DUMP_INCLUDES','-D','DUMP_CONFIG','-D','DUMP_MODULES','-C','LoadModule info_module /usr/lib/apache2/modules/mod_info.so'], capture_output=True, text=True, timeout=20)
if result.returncode: raise SystemExit('Apache includes cannot be inspected before dependency repair.')
dump = result.stdout + '\n' + result.stderr
if len(dump)>4194304 or '# In file:' not in dump:
    raise SystemExit('Apache effective configuration is unavailable; the native mod_info DUMP_CONFIG adapter is required before PHP qualification.')
files = list(dict.fromkeys(re.findall(r'^\s*\((?:\*|[0-9]+)\)\s+(/[^\n]+)',dump,re.M)))
files.extend(str(path) for path in Path('/etc/apache2/mods-enabled').glob('php*.load') if str(path) not in files)
if len(files)>512: raise SystemExit('Apache include inspection exceeded 512 files.')
profiles=set(); unknown=[]; apache_users=[]; apache_groups=[]; served_sockets=set(); php_versions=set()
for name in files:
    path=Path(name)
    if not path.is_file(): raise SystemExit('Apache include evidence disappeared during PHP qualification.')
    text=protected_config(path,freepbx_managed=True)
    for version in re.findall(r'^\s*LoadModule\s+php\w*_module\s+[^\n#]*libphp(\d+\.\d+)\.so',text,re.M): php_versions.add(version)
# DUMP_CONFIG is the native parser's active directive tree. Raw include files
# contain inactive IfDefine/IfModule bodies and must not establish handlers.
global_lines=[]; virtual_hosts=[]; current=None; dumping=False
for line in dump.splitlines():
    if line.startswith('# In file:'): dumping=True
    if not dumping or not line.strip() or line.lstrip().startswith('#'): continue
    if re.match(r'^\s*<VirtualHost\b',line,re.I):
        if current is not None: raise SystemExit('Nested Apache virtual hosts cannot be qualified.')
        current=[]
    elif re.match(r'^\s*</VirtualHost\s*>',line,re.I):
        if current is None: raise SystemExit('Apache virtual-host evidence is inconsistent.')
        virtual_hosts.append(current);current=None
    elif current is not None: current.append(line)
    else: global_lines.append(line)
if current is not None: raise SystemExit('Apache virtual-host evidence is incomplete.')
global_text='\n'.join(global_lines)
apache_users=re.findall(r'^\s*User\s+([^\s#]+)',global_text,re.M)
apache_groups=re.findall(r'^\s*Group\s+([^\s#]+)',global_text,re.M)
routes=[]
for lines in virtual_hosts:
    text='\n'.join(lines)
    roots=re.findall(r'^\s*DocumentRoot\s+[\"\']?([^\"\'\n]+?)[\"\']?\s*$',text,re.M)
    if not roots: roots=re.findall(r'^\s*DocumentRoot\s+[\"\']?([^\"\'\n]+?)[\"\']?\s*$',global_text,re.M)
    alias=bool(re.search(r'^\s*Alias\s+[\"\']?/admin/?[\"\']?\s+[\"\']?/var/www/html/admin/?[\"\']?\s*$',text,re.M))
    if any(str(Path(root.strip()).resolve(strict=False))=='/var/www/html' for root in roots) or alias:
        routes.append(global_lines+lines)
if not virtual_hosts: routes=[global_lines]
if not routes: raise SystemExit('No effective Apache virtual host serves the supported FreePBX web root.')
php_loaded=bool(re.search(r'^\s*php\w*_module\s+\(shared\)',dump,re.M))
pbx_urls=('/admin','/api/sipnotify','/api/sls-mass-notify','/sls_mass_notify','/index.php')
pbx_files=tuple('/var/www/html'+path for path in pbx_urls)
static_suffixes={'css','js','png','jpg','jpeg','gif','svg','ico','woff','woff2','ttf','eot','map'}
def static_files_only(value):
    # Prove only this small static-selector grammar disjoint from PBX PHP.
    # Unknown PCRE remains in scope; do not simulate Apache with Python regex.
    value=value.lower()
    if value.startswith('(?i)'): value=value[4:]
    if value.startswith('^'): value=value[1:]
    if value.startswith(('.*','.+')): value=value[2:]
    if not value.startswith('\\.') or not value.endswith('$'): return False
    suffix=value[2:-1]
    if suffix.startswith('(?:') and suffix.endswith(')'): suffix=suffix[3:-1]
    elif suffix.startswith('(') and suffix.endswith(')'): suffix=suffix[1:-1]
    return bool(re.fullmatch(r'[a-z0-9]+(?:\|[a-z0-9]+)*',suffix)) and set(suffix.split('|'))<=static_suffixes
def literal_scope(value,roots):
    # Wildcards, expressions and regex sections need an explicit adapter rather
    # than being mistaken for unrelated literal paths.
    if not value.startswith('/') or any(token in value for token in ('*','?','[','${','%{')): return True
    value=os.path.normpath(value)
    return any(value=='/' or root==value or root.startswith(value+'/') or value.startswith(root+'/') for root in roots)
def section_relevant(sections):
    for name,value in sections:
        if name=='directory' and not literal_scope(value,pbx_files): return False
        if name=='location' and not literal_scope(value,pbx_urls): return False
        if name=='filesmatch' and static_files_only(value): return False
    return True
def proxy_relevant(line):
    match=re.match(r'^\s*ProxyPass\s+(?:"([^"]+)"|\x27([^\x27]+)\x27|(\S+))',line,re.I)
    if not match: return True
    prefix=next(value for value in match.groups() if value is not None)
    if not prefix.startswith('/') or any(token in prefix for token in ('*','?','[','${','%{')): return True
    return any(root.startswith(prefix) or prefix==root or prefix.startswith(root+'/') for root in pbx_urls)
def blanket_php_fpm(line,sections):
    if not re.match(r'^\s*SetHandler\s+',line,re.I): return False
    selectors={r'\.php$',r'.+\.php$',r'^.+\.php$',r'\.ph(?:ar|p|tml)$',r'.+\.ph(?:ar|p|tml)$'}
    for name,value in sections:
        if name in {'ifmodule','ifdefine','ifversion','ifdirective','iffile','ifsection'}: continue
        if name=='directory' and value.startswith('/') and os.path.normpath(value) in {'/','/var','/var/www','/var/www/html'}: continue
        if name=='location' and value=='/': continue
        if name=='filesmatch' and value in selectors: continue
        if name=='files' and value=='*.php': continue
        return False
    return True
for lines in routes:
    blanket_fpm=False;explicit_modphp=False;sections=[]
    for line in lines:
        close=re.match(r'^\s*</([A-Za-z]+)\s*>\s*$',line)
        if close:
            if not sections or sections[-1][0]!=close[1].lower(): raise SystemExit('Apache handler scope evidence is inconsistent.')
            sections.pop();continue
        opening=re.match(r'^\s*<([A-Za-z]+)(?:\s+(.+))?>\s*$',line)
        if opening:
            sections.append((opening[1].lower(),(opening[2] or '').strip().strip('\"\x27')));continue
        if not section_relevant(sections): continue
        if re.search(r'^\s*(?:SetHandler|AddHandler|AddType)\b.*application/x-httpd-php(?=[\"\x27\s]|$)',line,re.I): explicit_modphp=True
        if not re.search(r'^\s*(?:SetHandler|ProxyPass(?:Match)?|BalancerMember)\b.*(?:fcgi|proxy:balancer)',line,re.I): continue
        if not proxy_relevant(line): continue
        local=re.findall(r'(?:proxy:)?unix:(/[^\s|"\']+)\|fcgi://(?:localhost|127\.0\.0\.1|\[::1\])(?=[/\s"\']|$)',line,re.I)
        if len(local)!=1 or len(re.findall(r'fcgi://',line,re.I))!=1 or not re.fullmatch(r'/(?:run|var/run)/php/[A-Za-z0-9_.-]{1,128}\.sock',local[0]):
            unknown.append('FreePBX route');continue
        served_sockets.add(local_socket(local[0]))
        blanket_fpm=blanket_fpm or blanket_php_fpm(line,sections)
    # An explicit mod_php handler can overlap a blanket FPM rule. Qualify
    # both possible runtimes instead of assuming which handler Apache selects.
    if php_loaded and (explicit_modphp or not blanket_fpm):
        if len(php_versions)!=1: raise SystemExit('The active Apache PHP module ABI is ambiguous; qualify its protected module source.')
        profiles.add((next(iter(php_versions)),'apache2'))
if unknown: raise SystemExit('Apache has an unidentified or remote FastCGI handler in '+', '.join(sorted(set(unknown)))+'. Use a protected local PHP-FPM pool/socket or qualify an explicit handler adapter; CLI PHP cannot establish its served runtime.')
if len(served_sockets)>32: raise SystemExit('More than 32 served PHP-FPM sockets require explicit administrator review.')
try:
    account=pwd.getpwnam('asterisk');expected_uid=account.pw_uid;expected_gid=account.pw_gid
except KeyError: raise SystemExit('The nonroot asterisk account is required before PHP-handler qualification.')
if expected_uid<=0 or expected_gid<=0: raise SystemExit('The asterisk account and primary group must not be root.')
def uid(name):
    try: return int(name) if name.isdecimal() else pwd.getpwnam(name).pw_uid
    except (KeyError,ValueError): return -1
def gid(name):
    try: return int(name) if name.isdecimal() else grp.getgrnam(name).gr_gid
    except (KeyError,ValueError): return -1
if any(sapi=='apache2' for unused,sapi in profiles):
    if not apache_users or not apache_groups: raise SystemExit('Apache mod_php has no inspectable User/Group directive. Qualify its runtime identity before installation.')
    envvars=Path('/etc/apache2/envvars')
    environment=protected_config(envvars,freepbx_managed=True) if envvars.is_file() else ''
    match=re.search(r'^\s*(?:export\s+)?APACHE_RUN_USER\s*=\s*([A-Za-z0-9_\-]+|\'[A-Za-z0-9_\-]+\'|"[A-Za-z0-9_\-]+")\s*(?:#.*)?$',environment,re.M)
    for name in apache_users:
        if name=='${APACHE_RUN_USER}': name=match.group(1).strip('\'"') if match else ''
        if uid(name)!=expected_uid: raise SystemExit('Apache mod_php must run as the asterisk service account. Review the Apache User directive/envvars; SLL will not change the global web-server user.')
    group_match=re.search(r'^\s*(?:export\s+)?APACHE_RUN_GROUP\s*=\s*([A-Za-z0-9_\-]+|\'[A-Za-z0-9_\-]+\'|"[A-Za-z0-9_\-]+")\s*(?:#.*)?$',environment,re.M)
    for name in apache_groups:
        if name=='${APACHE_RUN_GROUP}': name=group_match.group(1).strip('\'"') if group_match else ''
        if gid(name)!=expected_gid: raise SystemExit('Apache mod_php must use the asterisk primary group. Review the Apache Group directive/envvars before activation.')
required_functions={'exec','proc_open','posix_geteuid','posix_getpwnam','openssl_encrypt','openssl_decrypt','sodium_crypto_pwhash','sodium_crypto_pwhash_str','sodium_crypto_aead_xchacha20poly1305_ietf_encrypt','sem_get','sem_acquire','sem_remove'}
matched={socket:[] for socket in served_sockets}
if served_sockets:
    directories=sorted(Path('/etc/php').glob('*/fpm'))
    if len(directories)>20: raise SystemExit('PHP-FPM version inspection exceeded 20 configurations.')
    for directory in directories:
        version=directory.parent.name
        if not re.fullmatch(r'\d+\.\d+',version): continue
        global_config=directory/'php-fpm.conf'
        if not global_config.is_file(): continue
        includes=re.findall(r'^\s*include\s*=\s*([^;\n]+)',protected_config(global_config),re.M)
        expected_include=str(directory/'pool.d/*.conf')
        standard_include=bool(includes) and all(value.strip()==expected_include for value in includes)
        pools=list((directory/'pool.d').glob('*.conf'))
        if len(pools)>100: raise SystemExit('PHP-FPM pool inspection exceeded 100 configuration files.')
        for path in pools:
            parser=configparser.ConfigParser(interpolation=None,strict=True,inline_comment_prefixes=(';',),delimiters=('=',))
            try: parser.read_string(protected_config(path))
            except configparser.Error: raise SystemExit('PHP-FPM pool configuration could not be parsed safely: '+str(path))
            for section in parser.sections():
                pool=parser[section];listen=local_socket(pool.get('listen','').strip())
                if listen not in matched: continue
                if not standard_include: raise SystemExit('PHP-FPM '+version+' uses a custom pool include layout; qualify its active pool and user before installation.')
                matched[listen].append((version,section,dict(pool)))
    for listen,rows in matched.items():
        if len(rows)!=1: raise SystemExit('Each served PHP-FPM socket must match exactly one configured local pool; qualify this layout before activation.')
        version,section,pool=rows[0]
        # A version-looking socket name is only a hint. Its configured pool and
        # fixed, root-protected FPM binary must independently establish the ABI.
        hint=re.search(r'/php(\d+\.\d+)-fpm(?:-[A-Za-z0-9_.-]+)?\.sock$',listen)
        if hint and hint[1]!=version: raise SystemExit('The served PHP-FPM socket name and configured pool ABI disagree: '+listen)
        binary=Path('/usr/sbin')/('php-fpm'+version)
        for item in (binary,*binary.parents):
            info=item.lstat()
            expected=stat.S_ISREG if item==binary else stat.S_ISDIR
            if not expected(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022: raise SystemExit('The versioned PHP-FPM binary is not root-protected: '+str(binary))
        result=subprocess.run([str(binary),'-n','-v'],capture_output=True,text=True,timeout=5)
        abi=re.match(r'^PHP (\d+\.\d+)\.\d+[^\n]*\(fpm-fcgi\)',result.stdout)
        if result.returncode or not abi or abi[1]!=version: raise SystemExit('The configured PHP-FPM pool and installed binary ABI disagree: '+listen)
        if uid(pool.get('user','').strip())!=expected_uid: raise SystemExit('The PHP-FPM pool serving '+listen+' must run as asterisk. Configure this pool explicitly; SLL will not grant other web users access to PBX secrets.')
        if pool.get('group','').strip() and gid(pool['group'].strip())!=expected_gid:
            raise SystemExit('The PHP-FPM pool serving '+listen+' must use the asterisk primary group before activation.')
        disabled=set(re.split(r'[,\s]+',pool.get('php_admin_value[disable_functions]','')+','+pool.get('php_value[disable_functions]','')))
        blocked=sorted(disabled & required_functions)
        if blocked: raise SystemExit('The PHP-FPM pool serving '+listen+' disables required functions: '+', '.join(blocked)+'. Review this pool before activation.')
        profiles.add((version,'fpm'))
if not profiles: raise SystemExit('No qualified Apache PHP module or local PHP-FPM pool was detected. Qualify this handler before installation.')
if len(profiles)>4: raise SystemExit('More than four active PHP handler profiles require explicit administrator review.')
for version,sapi in sorted(profiles):
    if tuple(map(int,version.split('.')))<(8,2): raise SystemExit('Apache PHP '+version+' is unsupported; use a qualified PHP 8.2 or newer handler before installation.')
    print(version+':'+sapi)
PYPHPHANDLER
)" || return 1
  log "Detected served PHP profiles: ${SERVED_PHP_PROFILES//$'\n'/, }"
}

verify_php_security_versions_before_mutation() {
  /usr/bin/php -r '
$missing=[]; foreach (["sem_get","sem_acquire","sem_remove"] as $function) { if (!function_exists($function)) $missing[]=$function; }
if ($missing) { fwrite(STDERR,"Native FreePBX cron coordination requires enabled PHP functions: ".implode(", ",$missing).". Restore sysvsem in the active CLI PHP configuration before retrying; no SLL transaction or native hook was started.".PHP_EOL);exit(1); }
' || return 1
  local profile version policy fpm_banner
  policy="$(cat "$STAGING_DIR/$MODULE/bin/sls_mass_notify/php-security-policy.json")" || return 1
  while IFS= read -r profile; do
    [ -n "$profile" ] || continue
    version="${profile%:*}"
    [ -x "/usr/bin/php$version" ] || { log "PHP $version CLI is missing for the served handler. Install the matching trusted vendor package before retrying. No SLL workers were paused."; return 1; }
    sls_as_asterisk "/usr/bin/php$version" -n -r '
$policy=json_decode($argv[1],true,16,JSON_THROW_ON_ERROR);$branch=PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;$floor=$policy["branches"][$branch]??null;
if (($policy["schema"]??null)!==1 || !is_string($floor) || !preg_match("/^[0-9]+\\.[0-9]+\\.[0-9]+$/D",$floor) || version_compare(PHP_VERSION,$floor,"<") || preg_match("/(?:dev|alpha|beta|rc)/i",PHP_VERSION)) {
 fwrite(STDERR,"PHP ".PHP_VERSION." does not meet the reviewed PHP security floor ".($floor??"(unqualified branch)").". Update the matching CLI and Apache/FPM packages through the trusted operating-system repository, then retry. No SLL workers were paused.".PHP_EOL);exit(1);
}
' "$policy" || return 1
    if [ "${profile#*:}" = fpm ]; then
      # Discovery proves the pool ABI and protected binary identity. Check the
      # actual served SAPI's full version too: a newer CLI package does not
      # establish that its separately packaged FPM binary meets this policy.
      fpm_banner="$(sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=1 5 "/usr/sbin/php-fpm$version" -n -v)" || {
        log "PHP $version FPM could not report its version before mutation. Repair the matching trusted vendor package; no SLL workers were paused."
        return 1
      }
      [ "${#fpm_banner}" -le 8192 ] || { log 'PHP-FPM returned an unqualified version response; no SLL workers were paused.'; return 1; }
      /usr/bin/python3 -I - "$policy" "$version" "$fpm_banner" <<'PYFPMSECURITY' || return 1
import json, re, sys
policy, branch, banner = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
floor = policy.get('branches', {}).get(branch)
match = re.match(r'^PHP ([0-9]+\.[0-9]+\.[0-9]+)([^\r\n ]*) \(fpm-fcgi\)(?:[ \r\n]|$)', banner)
valid = (policy.get('schema') == 1 and isinstance(floor, str)
         and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', floor) and match
         and '.'.join(match[1].split('.')[:2]) == branch
         and not re.search(r'dev|alpha|beta|rc', match[2], re.I)
         and tuple(map(int, match[1].split('.'))) >= tuple(map(int, floor.split('.'))))
if not valid:
    raise SystemExit('The served PHP-FPM binary does not meet its reviewed ABI and stable security floor. '
                     'Update the matching FPM package through the trusted operating-system repository, then retry. '
                     'No SLL workers were paused.')
PYFPMSECURITY
    fi
  done <<<"$SERVED_PHP_PROFILES"
}

verify_freepbx_web_response() {
  local checker="$STAGING_DIR/$MODULE/bin/sls_mass_notify/sls_web_readiness.py"
  [ -f "$checker" ] && [ ! -L "$checker" ] || {
    log 'The authenticated FreePBX web-response checker is missing from the staged package.'
    return 1
  }
  if ! /usr/bin/timeout --signal=TERM --kill-after=1 5 /usr/sbin/apache2ctl -t -D DUMP_VHOSTS 2>>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" \
    | /usr/bin/python3 -I "$checker" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
    log 'The local FreePBX web response could not be verified. Check the served PHP/FPM handler and native vendor ionCube loader; an HTTP 200 error page does not establish readiness. No web credentials or response body were logged.'
    return 1
  fi
}

verify_served_php_configuration() {
  local profile version sapi
  while IFS= read -r profile; do
    [ -n "$profile" ] || continue
    version="${profile%:*}"; sapi="${profile#*:}"
    [ -x "/usr/bin/php$version" ] && [ -r "/etc/php/$version/$sapi/php.ini" ] || { log "The served PHP $version/$sapi configuration is unavailable; repair that handler before activation."; return 1; }
    sls_as_asterisk /usr/bin/env "PHP_INI_SCAN_DIR=/etc/php/$version/$sapi/conf.d" "/usr/bin/php$version" -c "/etc/php/$version/$sapi/php.ini" -r '
$missing=[]; foreach (["pdo_sqlite","curl","dom","mbstring","posix","openssl","sodium"] as $extension) { if (!extension_loaded($extension)) $missing[]=$extension; }
if (PHP_VERSION_ID < 80200) $missing[]="php_8_2_or_newer";
$securityFloors=["8.2"=>"8.2.35","8.3"=>"8.3.36","8.4"=>"8.4.27","8.5"=>"8.5.12"];
$branch=PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;
if (!isset($securityFloors[$branch]) || version_compare(PHP_VERSION,$securityFloors[$branch],"<")) { fwrite(STDERR,"PHP ".PHP_VERSION." does not meet the reviewed security policy. Update this PHP branch using its trusted vendor packages, then retry. Unknown backports need independent vendor review; SLL does not change the PHP branch.".PHP_EOL); exit(1); }
foreach (["exec","proc_open","posix_geteuid","posix_getpwnam","openssl_encrypt","openssl_decrypt","sodium_crypto_pwhash","sodium_crypto_aead_xchacha20poly1305_ietf_encrypt","sem_get","sem_acquire","sem_remove"] as $function) { if (!function_exists($function)) $missing[]=$function."_enabled"; }
if ($missing) { fwrite(STDERR,"Served PHP configuration missing: ".implode(", ",$missing).PHP_EOL); exit(1); }
' || { log "Review the named PHP $version/$sapi security or extension prerequisite; update this handler through trusted vendor packages. No module activation has started."; return 1; }
  done <<<"$SERVED_PHP_PROFILES"
}

refresh_served_php_workers() {
  local profile version sapi unit
  local -A units=()
  [ -n "$SERVED_PHP_PROFILES" ] || detect_served_php_profiles || return 1
  # Validate the complete set before any service action. Apache is refreshed by
  # protected activation/recovery; a separate FPM master has its own opcode cache.
  while IFS= read -r profile; do
    [[ "$profile" =~ ^[0-9]{1,2}\.[0-9]{1,2}:(apache2|fpm)$ ]] || {
      log 'The served PHP profile is invalid; no PHP-FPM service was reloaded.'
      return 1
    }
    version="${profile%:*}"; sapi="${profile#*:}"
    [ "$sapi" != fpm ] || units["php${version}-fpm"]=1
  done <<<"$SERVED_PHP_PROFILES"
  for unit in "${!units[@]}"; do
    /usr/bin/timeout --signal=TERM --kill-after=5 25 /usr/bin/systemctl reload "$unit" || {
      log "The qualified PHP-FPM service $unit could not reload. Review its service journal; old cached PHP may still be served. SLL will not restart Asterisk or change PHP settings."
      return 1
    }
  done
}

fetch_release_asset() {
  SLS_ASSET_URL="$1" SLS_ASSET_OUTPUT="$2" SLS_ASSET_LIMIT="$3" SLS_ASSET_TOKEN="$TOKEN" /usr/bin/timeout --signal=TERM --kill-after=5 905 /usr/bin/python3 -I - <<'PY'
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

url = os.environ['SLS_ASSET_URL']
pattern = (r'https://github\.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/'
           r'(?:(?:slsmassnotifyserver-|v)([0-9]+\.[0-9]+\.[0-9]+(?:-beta)?)/'
           r'(?:slsmassnotifyserver-\1\.tgz|release-manifest\.json|release-manifest\.sig)'
           r'|V0\.1\.9-beta/(?:slsmassnotifyserver-0\.1\.9-beta\.tgz|release-manifest\.(?:json|sig))'
           r'|release-0\.1\.9-beta/(?:slsmassnotifyserver-0\.1\.9-beta\.tgz|release-manifest\.(?:json|sig)))')
if not re.fullmatch(pattern, url):
    raise SystemExit('Use a signed HTTPS GitHub release URL, or an offline TGZ with an explicitly trusted SHA-256.')
limit = int(os.environ['SLS_ASSET_LIMIT'])
if not 1 <= limit <= 52 * 1024 * 1024:
    raise SystemExit('Invalid release download limit.')
token = os.environ.get('SLS_ASSET_TOKEN', '')
if any(ord(character) < 32 or ord(character) == 127 for character in token):
    raise SystemExit('Invalid GitHub token format.')

class ReleaseRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    def redirect_request(self, request, response, code, message, headers, new_url):
        target = urllib.parse.urlsplit(new_url)
        if (target.scheme != 'https' or target.username or target.password
                or target.port not in (None, 443) or target.fragment
                or target.hostname not in {'github.com', 'objects.githubusercontent.com',
                                           'release-assets.githubusercontent.com'}):
            raise ValueError('Release download redirected outside approved HTTPS asset hosts.')
        redirected = super().redirect_request(request, response, code, message, headers, new_url)
        # Authentication applies only to the original GitHub request. Signed
        # asset redirects do not need it, including a later redirect back.
        if redirected is not None:
            redirected.remove_header('Authorization')
        return redirected

request = urllib.request.Request(url, headers={
    'User-Agent': 'SLL-Mass-Notify-Installer', 'Accept': 'application/octet-stream',
    'Accept-Encoding': 'identity',
})
if token:
    request.add_unredirected_header('Authorization', 'Bearer ' + token)
opener = urllib.request.build_opener(ReleaseRedirects())
path = os.environ['SLS_ASSET_OUTPUT']
deadline = time.monotonic() + 900
try:
    # The caller owns the private parent directory; never truncate or follow
    # a pre-existing pathname, even inside that directory.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        for attempt in range(5):
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Release download deadline exceeded.')
                with opener.open(request, timeout=min(20, remaining)) as response:
                    length = response.headers.get('Content-Length')
                    if length is not None and (not length.isdigit() or int(length) > limit):
                        raise ValueError('Release asset exceeds its download limit.')
                    total = 0
                    while True:
                        if time.monotonic() >= deadline:
                            raise TimeoutError('Release download deadline exceeded.')
                        chunk = response.read(min(65536, limit - total + 1))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > limit:
                            raise ValueError('Release asset exceeds its download limit.')
                        output.write(chunk)
                    if total == 0 or (length is not None and total != int(length)):
                        raise ValueError('Release asset was empty or incomplete.')
                output.flush()
                os.fsync(output.fileno())
                break
            except (urllib.error.URLError, socket.timeout, TimeoutError):
                if attempt == 4 or time.monotonic() >= deadline:
                    raise
                output.seek(0)
                output.truncate()
                time.sleep(min(2 ** attempt, max(0, deadline - time.monotonic())))
except Exception:
    # Do not include redirected URLs, signed query parameters, or headers in
    # diagnostics. The caller removes the private directory on failure.
    raise SystemExit('Release download failed validation, exceeded its size/time limit, or could not be completed.')
PY
}

copy_private_release_asset() {
  /usr/bin/python3 -I - "$1" "$2" "$3" <<'PYASSET'
import os, stat, sys
source, target, bound = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    raise SystemExit(
        'Local release asset is missing: ' + source + '. '
        'Supply SLS_MASS_NOTIFY_TGZ_URL for a signed release download, or keep '
        'the matching TGZ, release-manifest.json and release-manifest.sig together. '
        'Local archives also require SLS_MASS_NOTIFY_SHA256.'
    ) from None
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= bound:
        raise RuntimeError('release asset must be a bounded, single-link regular file')
    out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(out, 'wb') as handle:
        total = 0
        while True:
            block = os.read(fd, 65536)
            if not block: break
            total += len(block)
            if total > bound: raise RuntimeError('release asset exceeds size limit')
            handle.write(block)
        handle.flush()
        os.fsync(handle.fileno())
    after = os.fstat(fd)
    if total != info.st_size or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise RuntimeError('release asset changed during private copy')
finally:
    os.close(fd)
PYASSET
}

download_tgz() {
  local original_tgz="$TGZ"
  if [ -n "$URL" ]; then
    TGZ_REQUEST_BASENAME="${URL##*/}"
  else
    TGZ_REQUEST_BASENAME="$(basename -- "$original_tgz")"
  fi
  DOWNLOAD_DIR="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-mass-notify-download.XXXXXX")" || return 1
  if [ -n "$URL" ]; then
    TGZ="$DOWNLOAD_DIR/package.tgz"
    fetch_release_asset "$URL" "$TGZ" 54525952 || return 1
  else
    TGZ="$DOWNLOAD_DIR/package.tgz"
    copy_private_release_asset "$original_tgz" "$TGZ" 54525952 || return 1
  fi

  [ -f "$TGZ" ] && [ ! -L "$TGZ" ] && [ -s "$TGZ" ] || {
    log "$TGZ is missing. Set SLS_MASS_NOTIFY_TGZ_URL or upload the TGZ to this path first."
    return 1
  }
  chmod 0600 "$TGZ"
}

verify_tgz() {
  local requested_basename="${TGZ_REQUEST_BASENAME:-$(basename -- "$TGZ")}"
  actual_sha="$(sha256sum -- "$TGZ" | awk '{print $1}')"
  if [ -n "$SHA256" ]; then
    if [[ ! "$SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
      log 'SLS_MASS_NOTIFY_SHA256 must contain exactly 64 hexadecimal characters.'
      return 1
    fi
    if [ "${SHA256,,}" != "$actual_sha" ]; then
      log 'The release archive does not match the explicitly trusted SLS_MASS_NOTIFY_SHA256.'
      return 1
    fi
  elif [ "$requested_basename" = "slsmassnotifyserver-0.2.0-beta.tgz" ] && [ "$actual_sha" != "$EXPECTED_TGZ_SHA256" ]; then
    log "$TGZ does not match the current slsmassnotifyserver-0.2.0-beta package."
    log "Expected SHA256: $EXPECTED_TGZ_SHA256"
    log "Actual SHA256:   $actual_sha"
    log "Remove the stale local TGZ or install with SLS_MASS_NOTIFY_TGZ_URL so the current release is downloaded."
    return 1
  else
    printf '%s  %s\n' "$actual_sha" "$TGZ"
  fi
  if [ -n "$URL" ]; then
    verify_publisher_release || return 1
  else
    [ -n "$SHA256" ] || { log 'A local/offline TGZ requires an explicit trusted SLS_MASS_NOTIFY_SHA256.'; return 1; }
    verify_publisher_release || return 1
  fi
  TGZ_PATH="$TGZ" MODULE_NAME="$MODULE" python3 -I - <<'PY'
import os
import pathlib
import tarfile
import xml.etree.ElementTree as ET

archive = os.environ["TGZ_PATH"]
module = os.environ["MODULE_NAME"]
total = 0
seen_module_xml = False
with tarfile.open(archive, "r:gz") as handle:
    members = handle.getmembers()
    if not members or len(members) > 5000:
        raise SystemExit("TGZ has an invalid file count")
    seen = set()
    for member in members:
        raw_name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
        raw_parts = raw_name.split('/')
        path = pathlib.PurePosixPath(raw_name)
        if (path.is_absolute() or not raw_parts or any(part in ('', '.', '..') for part in raw_parts)
                or not path.parts or path.parts[0] != module):
            raise SystemExit(f"Unsafe or unexpected TGZ path: {member.name}")
        identity = path.as_posix()
        if (identity in seen or len(member.name) > 240
                or any(not part or any(ord(character) < 32 or ord(character) == 127
                                      for character in part) for part in path.parts)):
            raise SystemExit(f"Duplicate or malformed TGZ path: {member.name}")
        seen.add(identity)
        if member.mode & 0o7022:
            raise SystemExit(f"Unsafe TGZ metadata: {member.name}")
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"Unsupported TGZ member type: {member.name}")
        if member.isfile():
            if member.size < 0 or member.size > 50 * 1024 * 1024:
                raise SystemExit(f"Unsafe TGZ member size: {member.name}")
            total += member.size
            if member.name == f"{module}/module.xml":
                if member.size > 1024 * 1024:
                    raise SystemExit("module.xml exceeds its 1 MiB limit")
                seen_module_xml = True
    if total > 50 * 1024 * 1024:
        raise SystemExit("TGZ expands beyond the 50 MB module limit")
    if not seen_module_xml:
        raise SystemExit("TGZ does not contain the required module.xml")
    module_xml = handle.extractfile(f"{module}/module.xml")
    if module_xml is None:
        raise SystemExit("Unable to read module.xml")
    module_xml_body = module_xml.read(1024 * 1024 + 1)
    if len(module_xml_body) > 1024 * 1024 or b'<!DOCTYPE' in module_xml_body.upper() or b'<!ENTITY' in module_xml_body.upper():
        raise SystemExit("module.xml contains an unsupported declaration or exceeds its limit")
    root = ET.fromstring(module_xml_body)
    rawname = root.findall("rawname")
    version = root.findall("version")
    if len(rawname) != 1 or (rawname[0].text or "").strip() != module:
        raise SystemExit("module.xml rawname does not match the requested module")
    if len(version) != 1 or (version[0].text or "").strip() != "0.2.0-beta":
        raise SystemExit("module.xml does not contain the expected 0.2.0-beta version")
PY
}

verify_publisher_release() {
  [ -n "$DOWNLOAD_DIR" ] && [ -d "$DOWNLOAD_DIR" ] || return 1
  if [ -n "$URL" ]; then
    fetch_release_asset "${URL%/*}/release-manifest.json" "$DOWNLOAD_DIR/release-manifest.json" 16384 || return 1
    fetch_release_asset "${URL%/*}/release-manifest.sig" "$DOWNLOAD_DIR/release-manifest.sig" 64 || return 1
  else
    copy_private_release_asset "${SLS_MASS_NOTIFY_MANIFEST:-${OFFLINE_ASSET_DIR}/release-manifest.json}" "$DOWNLOAD_DIR/release-manifest.json" 16384 || return 1
    copy_private_release_asset "${SLS_MASS_NOTIFY_MANIFEST_SIGNATURE:-${OFFLINE_ASSET_DIR}/release-manifest.sig}" "$DOWNLOAD_DIR/release-manifest.sig" 64 || return 1
  fi
  SLS_RELEASE_DIRECTORY="$DOWNLOAD_DIR" SLS_RELEASE_URL="$URL" SLS_RELEASE_TGZ="$TGZ" SLS_RELEASE_INSTALLER="$INSTALLER_SOURCE_PATH" /usr/bin/python3 -I - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import types

url = os.environ['SLS_RELEASE_URL']
match = re.fullmatch(r'https://github\.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/((?:slsmassnotifyserver-|v|V)([0-9]+\.[0-9]+\.[0-9]+(?:-beta)?))/(slsmassnotifyserver-\2\.tgz)', url)
if match and match.group(1).startswith('V') and match.group(1) != 'V0.1.9-beta':
    match = None
reserved_alias = url == 'https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/release-0.1.9-beta/slsmassnotifyserver-0.1.9-beta.tgz'
if url and not (match or reserved_alias):
    raise SystemExit('Use a signed GitHub release URL or a signed offline package.')
release_tag, version, package = match.groups() if match else (('release-0.1.9-beta', '0.1.9-beta', 'slsmassnotifyserver-0.1.9-beta.tgz') if reserved_alias else ('v0.2.0-beta', '0.2.0-beta', 'slsmassnotifyserver-0.2.0-beta.tgz'))
public_key = b'-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=\n-----END PUBLIC KEY-----\n'

def unique(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError('Duplicate retained publisher field')
        value[name] = item
    return value

def retained_helper_source(directory):
    # Uninstall removes the runtime but preserves independently approved source.
    # Authenticate the same protected reference/inventory/hash boundary used by
    # the bootstrap; downloaded candidate code cannot authorize its own package.
    def protected_read(path, maximum):
        for item in (path, *path.parents):
            metadata = item.lstat()
            expected = stat.S_ISREG if item == path else stat.S_ISDIR
            if (not expected(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022 and not (item != path and metadata.st_mode & stat.S_ISVTX)):
                raise ValueError('Retained publisher verifier is not root-protected')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
                raise ValueError('Retained publisher verifier evidence is not bounded regular source')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                source = stream.read(maximum + 1)
            after = os.fstat(fd)
            current = path.lstat()
            identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
                                      value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)
            if len(source) != before.st_size or identity(before) != identity(after) or identity(after) != identity(current):
                raise ValueError('Retained publisher verifier changed during authentication')
            return source
        finally:
            os.close(fd)
    if directory.lstat().st_mode & 0o077:
        raise ValueError('Retained publisher directory must remain root-private')
    reference = json.loads(protected_read(directory / 'slsmassnotifyserver.active.json', 1024), object_pairs_hook=unique)
    if (not isinstance(reference, dict) or set(reference) != {'generation', 'sha256'}
            or not isinstance(reference['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', reference['sha256'])
            or reference['generation'] != 'slsmassnotifyserver-' + reference['sha256']):
        raise ValueError('Retained publisher reference is invalid')
    generation = directory / reference['generation']
    if generation.lstat().st_mode & 0o077:
        raise ValueError('Retained publisher generation must remain root-private')
    raw = protected_read(generation / 'inventory.json', 8388608)
    if hashlib.sha256(raw).hexdigest() != reference['sha256']:
        raise ValueError('Retained publisher inventory differs from its protected reference')
    inventory = json.loads(raw, object_pairs_hook=unique)
    if (not isinstance(inventory, dict) or type(inventory.get('schema')) is not int or inventory['schema'] != 1
            or inventory.get('module') != 'slsmassnotifyserver'
            or not isinstance(inventory.get('source'), dict)
            or inventory['source'].get('kind') != 'publisher-ed25519'
            or not re.fullmatch(r'[a-f0-9]{64}', str(inventory['source'].get('archive_sha256', '')))
            or not isinstance(inventory.get('files'), dict)):
        raise ValueError('Retained publisher inventory has no independent SLL authority')
    relative = 'bin/sls_mass_notify/sls_release_trust.py'
    entry = inventory['files'].get(relative)
    if (not isinstance(entry, dict) or set(entry) != {'sha256', 'target'}
            or entry['target'] != 'admin/modules/slsmassnotifyserver/' + relative
            or not isinstance(entry['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', entry['sha256'])):
        raise ValueError('Retained publisher verifier is absent from the protected inventory')
    helper = generation / 'module' / relative
    source = protected_read(helper, 262144)
    if hashlib.sha256(source).hexdigest() != entry['sha256']:
        raise ValueError('Retained publisher verifier differs from its approved source')
    return helper, source

try:
    with tempfile.TemporaryDirectory(prefix='sls-release-verification-') as directory:
        root = Path(directory)
        for name, limit in [('release-manifest.json', 16384), ('release-manifest.sig', 64)]:
            body = (Path(os.environ['SLS_RELEASE_DIRECTORY']) / name).read_bytes()
            if len(body) > limit or (name.endswith('.sig') and len(body) != 64):
                raise ValueError('Invalid manifest/signature size')
            (root / name).write_bytes(body)
        trusted_helper = Path('/usr/local/bin/sls_mass_notify/sls_release_trust.py')
        trust_state = Path('/var/lib/sls-mass-notify-trust')
        if trusted_helper.exists() or trusted_helper.is_symlink():
            for path in (trusted_helper, *trusted_helper.parents):
                metadata = path.lstat()
                expected = stat.S_ISREG if path == trusted_helper else stat.S_ISDIR
                if not expected(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise ValueError('Installed publisher verifier is not protected by root')
            sys.dont_write_bytecode = True
            fd = os.open(trusted_helper, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or before.st_nlink != 1 or before.st_size > 256 * 1024:
                    raise ValueError('Installed publisher verifier is not a bounded protected source')
                source = bytearray()
                while len(source) <= 256 * 1024:
                    block = os.read(fd, 65536)
                    if not block: break
                    source.extend(block)
                after = os.fstat(fd)
                if len(source) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError('Installed publisher verifier changed during inspection')
            finally: os.close(fd)
            trust = types.ModuleType('installed_publisher_trust'); trust.__file__ = str(trusted_helper)
            exec(compile(source, str(trusted_helper), 'exec'), trust.__dict__)
            manifest = trust.authenticate_manifest((root / 'release-manifest.json').read_bytes(),
                (root / 'release-manifest.sig').read_bytes(), anchor=public_key)
        elif (trust_state / 'slsmassnotifyserver.active.json').exists() or (trust_state / 'slsmassnotifyserver.active.json').is_symlink():
            trusted_helper, source = retained_helper_source(trust_state)
            sys.dont_write_bytecode = True
            trust = types.ModuleType('retained_publisher_trust'); trust.__file__ = str(trusted_helper)
            exec(compile(source, str(trusted_helper), 'exec'), trust.__dict__)
            manifest = trust.authenticate_manifest((root / 'release-manifest.json').read_bytes(),
                (root / 'release-manifest.sig').read_bytes(), anchor=public_key, directory=trust_state)
        else:
            if any((trust_state / name).exists() or (trust_state / name).is_symlink()
                   for name in ('publisher-trust.json', 'release-trust.initialized')):
                raise ValueError('Established publisher trust requires its protected verifier; restore it before updating')
            (root / 'publisher.pub').write_bytes(public_key)
            subprocess.run(['/usr/bin/openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(root / 'publisher.pub'),
                            '-in', str(root / 'release-manifest.json'), '-sigfile', str(root / 'release-manifest.sig')],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            manifest = json.loads((root / 'release-manifest.json').read_bytes())
            signing = manifest.get('signing') if isinstance(manifest, dict) else None
            if signing is not None:
                # The bootstrap accepts only the pinned key, including for the
                # new metadata format. A downloaded policy cannot add authority.
                anchor_der = subprocess.run(['/usr/bin/openssl','pkey','-pubin','-outform','DER'],
                    input=public_key, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10).stdout
                now = int(time.time())
                if not isinstance(signing, dict) or set(signing) != {'key_id','issued_at','expires_at'} \
                        or signing['key_id'] != hashlib.sha256(anchor_der).hexdigest() \
                        or type(signing['issued_at']) is not int or type(signing['expires_at']) is not int \
                        or signing['issued_at'] < 0 or signing['issued_at'] > now + 300 \
                        or not signing['issued_at'] < signing['expires_at'] <= signing['issued_at'] + 2 * 366 * 86400 \
                        or now >= signing['expires_at']:
                    raise ValueError('Signed release metadata is expired or invalid')
        if not isinstance(manifest, dict) or manifest.get('schema') != 1 or manifest.get('version') != version \
                or manifest.get('tag') not in ((release_tag,) if url else (('v' + version, 'slsmassnotifyserver-' + version) + (('V0.1.9-beta','release-0.1.9-beta') if version == '0.1.9-beta' else ()))) or manifest.get('package') != package:
            raise ValueError('Signed release identity mismatch')
        for field, path in [('package_sha256', os.environ['SLS_RELEASE_TGZ']), ('installer_sha256', os.environ['SLS_RELEASE_INSTALLER'])]:
            with open(path, 'rb') as handle:
                actual = hashlib.file_digest(handle, 'sha256').hexdigest()
            if manifest.get(field) != actual:
                raise ValueError('Signed release artifact mismatch: ' + field)
except Exception as error:
    raise SystemExit('Publisher verification failed before activation: ' + str(error))
print('Publisher signature and installer/package hashes verified.')
PY
}

prepare_settings_lock() {
  [ ! -L "$CONFIG_FILE" ] || {
    log "Refusing to install while the protected central configuration is a symbolic link."
    exit 1
  }
  [ -e "$CONFIG_FILE" ] || return 0
  SETTINGS_LOCK_PATH="$SETTINGS_LOCK" /usr/bin/python3 -I - <<'PY'
import os
import pwd
import stat

path = os.environ["SETTINGS_LOCK_PATH"]
parts = [part for part in path.split("/") if part]
if not path.startswith("/") or not parts or "\x00" in path or any(part in (".", "..") for part in parts):
    raise SystemExit("invalid settings-lock path")
if os.geteuid() != 0:
    raise SystemExit("settings-lock preparation requires root")
account = pwd.getpwnam("asterisk")
if account.pw_uid == 0:
    raise SystemExit("Asterisk UID must be nonzero")
directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
file_flags = os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
parent_fd = os.open("/", directory_flags)
try:
    for index, component in enumerate(parts[:-1]):
        next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = next_fd
        info = os.fstat(parent_fd)
        sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX and index < len(parts) - 2
        if (info.st_uid not in (0, account.pw_uid) or info.st_mode & 0o002 and not sticky
                or info.st_mode & 0o020 and not sticky and info.st_gid not in (0, account.pw_gid)):
            raise SystemExit("settings-lock parent ownership or permissions are unsafe")
    try:
        file_fd = os.open(parts[-1], file_flags | os.O_CREAT | os.O_EXCL, 0o640, dir_fd=parent_fd)
    except FileExistsError:
        file_fd = os.open(parts[-1], file_flags, dir_fd=parent_fd)
    try:
        metadata = os.fstat(file_fd)
        named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size != 0
                or metadata.st_uid not in (0, account.pw_uid) or metadata.st_gid not in (0, account.pw_gid)
                or stat.S_IMODE(metadata.st_mode) not in (0o600, 0o640, 0o644)
                or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)):
            raise SystemExit("settings lock is not an empty, single-link regular file with recognized private ownership and mode")
        os.fchown(file_fd, account.pw_uid, account.pw_gid)
        os.fchmod(file_fd, 0o640)
        os.fsync(file_fd)
        verified = os.fstat(file_fd)
        named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (verified.st_uid != account.pw_uid or verified.st_gid != account.pw_gid
                or stat.S_IMODE(verified.st_mode) != 0o640 or verified.st_nlink != 1 or verified.st_size != 0
                or (verified.st_dev, verified.st_ino) != (named.st_dev, named.st_ino)):
            raise SystemExit("settings lock changed during preparation; preserve it for review")
        os.fsync(parent_fd)
    finally:
        os.close(file_fd)
finally:
    os.close(parent_fd)
PY
}

acquire_settings_coordination() {
  [ ! -L "$CONFIG_FILE" ] || {
    log "Refusing to install while the protected central configuration is a symbolic link."
    exit 1
  }
  [ -e "$CONFIG_FILE" ] || return 0
  prepare_settings_lock || return 1
  [ ! -L "$SETTINGS_LOCK" ] && [ -f "$SETTINGS_LOCK" ] || {
    log "Refusing to use an unsafe central-configuration lock file."
    exit 1
  }
  # The authenticated keeper opens with no-follow/nonblocking semantics and
  # retains this mutex beside the worker leases. No shell pathname reopen or
  # lock descriptor reaches an unprivileged FreePBX subprocess.
  local status
  if [ -z "${WORKER_LOCK_KEEPALIVE_FD:-}" ] || [ -z "${WORKER_LOCK_RESPONSE_FD:-}" ] \
    || [ -z "${WORKER_LOCK_PID:-}" ] || ! kill -0 "$WORKER_LOCK_PID" 2>/dev/null; then
    log 'The authenticated worker keeper is unavailable; no configuration was replaced.'
    return 1
  fi
  if ! (printf 'settings\n' >&"$WORKER_LOCK_KEEPALIVE_FD") 2>/dev/null \
    || ! IFS= read -r status <&"$WORKER_LOCK_RESPONSE_FD" || [ "$status" != settings-ready ]; then
    log 'The configuration mutex could not be acquired safely. Review its ownership, mode, identity or active editor in the log; no settings were replaced.'
    return 1
  fi
}

safe_config_snapshot() {
  source_path="$1"
  snapshot_path="$2"
  CONFIG_SOURCE_PATH="$source_path" CONFIG_SNAPSHOT_PATH="$snapshot_path" /usr/bin/python3 -I - <<'PY'
import hashlib
import os
import stat

source_path = os.environ["CONFIG_SOURCE_PATH"]
snapshot_path = os.environ["CONFIG_SNAPSHOT_PATH"]
limit = 16 * 1024 * 1024

def open_regular(path, flags):
    parts = [part for part in path.split("/") if part]
    if not path.startswith("/") or not parts or "\x00" in path:
        raise RuntimeError("invalid path")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open("/", directory_flags)
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        file_fd = os.open(parts[-1], flags | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    if not stat.S_ISREG(os.fstat(file_fd).st_mode):
        os.close(file_fd)
        raise RuntimeError("protected config is not a regular file")
    return file_fd

source_fd = open_regular(source_path, os.O_RDONLY)
source_before = os.fstat(source_fd)
if source_before.st_nlink != 1 or source_before.st_size > limit:
    os.close(source_fd)
    raise RuntimeError("protected config is linked or exceeds the size limit")
snapshot_fd = open_regular(snapshot_path, os.O_WRONLY)
snapshot_before = os.fstat(snapshot_fd)
if snapshot_before.st_uid != 0 or snapshot_before.st_nlink != 1 or snapshot_before.st_mode & 0o077:
    os.close(snapshot_fd)
    os.close(source_fd)
    raise RuntimeError("config snapshot is not a private root-owned file")
os.ftruncate(snapshot_fd, 0)
digest = hashlib.sha256()
total = 0
try:
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise RuntimeError("protected config exceeds the size limit")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(snapshot_fd, view)
            if written <= 0:
                raise RuntimeError("config snapshot write made no progress")
            view = view[written:]
    source_after = os.fstat(source_fd)
    stable = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
    if total != source_before.st_size or stable(source_before) != stable(source_after):
        raise RuntimeError("protected config changed during snapshot")
    os.fsync(snapshot_fd)
finally:
    os.close(snapshot_fd)
    os.close(source_fd)
print(digest.hexdigest())
PY
}

safe_config_hash() {
  CONFIG_SOURCE_PATH="$1" /usr/bin/python3 -I - <<'PY'
import hashlib
import os
import stat

path = os.environ["CONFIG_SOURCE_PATH"]
parts = [part for part in path.split("/") if part]
if not path.startswith("/") or not parts or "\x00" in path:
    raise SystemExit(2)
directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
parent_fd = os.open("/", directory_flags)
try:
    for component in parts[:-1]:
        next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = next_fd
    file_fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
finally:
    os.close(parent_fd)
try:
    metadata = os.fstat(file_fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 16 * 1024 * 1024:
        raise SystemExit(3)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(file_fd, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > 16 * 1024 * 1024:
            raise SystemExit(3)
        digest.update(chunk)
    after = os.fstat(file_fd)
    stable = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
    if total != metadata.st_size or stable(metadata) != stable(after):
        raise SystemExit(4)
finally:
    os.close(file_fd)
print(digest.hexdigest())
PY
}

safe_config_restore() {
  snapshot_path="$1"
  destination_path="$2"
  CONFIG_SNAPSHOT_PATH="$snapshot_path" CONFIG_DESTINATION_PATH="$destination_path" /usr/bin/python3 -I - <<'PY'
import hashlib
import os
import pwd
import secrets
import stat

source_path = os.environ["CONFIG_SNAPSHOT_PATH"]
destination_path = os.environ["CONFIG_DESTINATION_PATH"]
limit = 16 * 1024 * 1024
directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
file_nofollow = os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)

def open_parent(path):
    parts = [part for part in path.split("/") if part]
    if not path.startswith("/") or not parts or "\x00" in path:
        raise RuntimeError("invalid path")
    parent_fd = os.open("/", directory_flags)
    for component in parts[:-1]:
        next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = next_fd
    return parent_fd, parts[-1]

source_parent_fd, source_name = open_parent(source_path)
try:
    source_fd = os.open(source_name, os.O_RDONLY | os.O_NONBLOCK | file_nofollow, dir_fd=source_parent_fd)
finally:
    os.close(source_parent_fd)
source_before = os.fstat(source_fd)
if (not stat.S_ISREG(source_before.st_mode) or source_before.st_nlink != 1
        or source_before.st_uid != 0 or source_before.st_mode & 0o077 or source_before.st_size > limit):
    os.close(source_fd)
    raise SystemExit("config snapshot is not a bounded, private root-owned regular file")

destination_parent_fd, destination_name = open_parent(destination_path)
temporary_name = ".mass-notifications.config.restore." + secrets.token_hex(8)
temporary_fd = -1
try:
    temporary_fd = os.open(
        temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | file_nofollow,
        0o600,
        dir_fd=destination_parent_fd,
    )
    total = 0
    digest = hashlib.sha256()
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise RuntimeError("config snapshot exceeds the size limit")
        digest.update(chunk)
        view = memoryview(chunk)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                raise RuntimeError("config restore write made no progress")
            view = view[written:]
    source_after = os.fstat(source_fd)
    stable = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
    if total != source_before.st_size or stable(source_before) != stable(source_after):
        raise RuntimeError("config snapshot changed during restoration")
    account = pwd.getpwnam("asterisk")
    os.fchmod(temporary_fd, 0o640)
    os.fchown(temporary_fd, account.pw_uid, account.pw_gid)
    os.fsync(temporary_fd)
    os.close(temporary_fd)
    temporary_fd = -1
    os.replace(temporary_name, destination_name, src_dir_fd=destination_parent_fd, dst_dir_fd=destination_parent_fd)
    os.fsync(destination_parent_fd)
    restored_fd = os.open(destination_name, os.O_RDONLY | os.O_NONBLOCK | file_nofollow, dir_fd=destination_parent_fd)
    try:
        metadata = os.fstat(restored_fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o640
            or metadata.st_uid != account.pw_uid
            or metadata.st_gid != account.pw_gid
        ):
            raise RuntimeError("restored config metadata is invalid")
        restored = hashlib.sha256()
        restored_total = 0
        while True:
            chunk = os.read(restored_fd, 1024 * 1024)
            if not chunk:
                break
            restored_total += len(chunk)
            if restored_total > limit:
                raise RuntimeError("restored config exceeds the size limit")
            restored.update(chunk)
        if restored_total != total or stable(metadata) != stable(os.fstat(restored_fd)):
            raise RuntimeError("restored config changed during verification")
        if restored.digest() != digest.digest():
            raise RuntimeError("restored config digest mismatch")
    finally:
        os.close(restored_fd)
finally:
    if temporary_fd >= 0:
        os.close(temporary_fd)
    try:
        os.unlink(temporary_name, dir_fd=destination_parent_fd)
    except FileNotFoundError:
        pass
    os.close(destination_parent_fd)
    os.close(source_fd)
PY
}

snapshot_pending_config() {
  PENDING_CONFIG_PATH="$DATA_DIR/mass-notifications.pending.config"
  PENDING_CONFIG_STATE=absent
  if [ -e "$PENDING_CONFIG_PATH" ] || [ -L "$PENDING_CONFIG_PATH" ]; then
    PENDING_CONFIG_SNAPSHOT="$(mktemp "$INSTALL_TEMP_ROOT/slsmassnotifyserver-pending.XXXXXX")" || return 1
    PENDING_CONFIG_HASH="$(safe_config_snapshot "$PENDING_CONFIG_PATH" "$PENDING_CONFIG_SNAPSHOT")" || {
      log 'Pending configuration is unsafe or unreadable. It was not applied or replaced.'
      return 1
    }
    PENDING_CONFIG_STATE=present
  fi
}

verify_pending_config_unchanged() {
  if [ "$PENDING_CONFIG_STATE" = present ]; then
    [ "$(safe_config_hash "$PENDING_CONFIG_PATH" 2>/dev/null || true)" = "${PENDING_RECOVERY_HASH:-$PENDING_CONFIG_HASH}" ] || {
      log 'Pending settings changed during installation; the installer will not apply them.'
      return 1
    }
  elif [ "$PENDING_CONFIG_STATE" = absent ]; then
    [ ! -e "$PENDING_CONFIG_PATH" ] && [ ! -L "$PENDING_CONFIG_PATH" ] || {
      log 'A pending configuration appeared during installation; preserve it for administrator review.'
      return 1
    }
  fi
}

initialize_fresh_install_config() {
  [ ! -e "$CONFIG_FILE" ] && [ ! -L "$CONFIG_FILE" ] || return 0
  [ "$HAD_EXISTING_MODULE" -eq 0 ] && [ ! -d "$MODULE_BACKUP_DIR/$MODULE" ] || {
    log 'An existing module has no active configuration. Restore its protected configuration backup before upgrading; existing credentials will not be silently regenerated.'
    return 1
  }
  local initialization_result
  initialization_result="$(SLS_INIT_PHONE_CAPACITY="$FRESH_PHONE_CAPACITY" SLS_INIT_DEPLOYMENT_PROFILE="$FRESH_DEPLOYMENT_PROFILE" php -r '
require "/etc/freepbx.conf";
require_once "/var/www/html/admin/modules/slsmassnotifyserver/Slsmassnotifyserver.class.php";
$class = "\\FreePBX\\modules\\Slsmassnotifyserver";
$obj = new $class(\FreePBX::Create());
$capacity = getenv("SLS_INIT_PHONE_CAPACITY");
$profile = getenv("SLS_INIT_DEPLOYMENT_PROFILE");
if (!preg_match("/^[0-9]{1,4}$/D", (string)$capacity) || (int)$capacity < 25 || (int)$capacity > 1000) { exit(1); }
if (!in_array($profile, ["standard", "lite"], true)) { exit(1); }
echo $obj->initializeFreshInstallerConfiguration((int)$capacity, $profile) ? "created" : "existing";
exit(0);
')" || return 1
  case "$initialization_result" in
    created) FRESH_CONFIG_INITIALIZED=1 ;;
    existing) FRESH_CONFIG_INITIALIZED=0 ;;
    *) log "Fresh configuration initialization did not return a verified result."; return 1 ;;
  esac
  # No config lock was held while the file was absent. Freeze the completed
  # initial file before module installation/reload can observe it.
  acquire_settings_coordination
  snapshot_config
  verify_fresh_install_defaults
}

snapshot_config() {
  if [ -L "$CONFIG_FILE" ]; then
    log "Refusing to install while the protected central configuration is a symbolic link."
    exit 1
  fi
  [ -r "$CONFIG_FILE" ] || return 0
  CONFIG_SNAPSHOT="$(mktemp "$INSTALL_TEMP_ROOT/slsmassnotifyserver-config.XXXXXX")"
  if ! CONFIG_HASH_BEFORE="$(safe_config_snapshot "$CONFIG_FILE" "$CONFIG_SNAPSHOT")"; then
    rm -f "$CONFIG_SNAPSHOT"
    CONFIG_SNAPSHOT=""
    log "Refusing to install because the protected central configuration could not be opened safely without following symbolic links."
    exit 1
  fi
  CONFIG_HASH_EXPECTED="$CONFIG_HASH_BEFORE"
}

run_installer_settings_transform() {
  local action="$1" requested="$2" request response
  assert_worker_coordination || return 1
  request="$(/usr/bin/python3 -I - "$action" "$CONFIG_FILE" "$requested" "$PENDING_CONFIG_STATE" "$RECOVERY_DIR" "$CONFIG_HASH_BEFORE" <<'PYTRANSFORMREQUEST'
import json, sys
print(json.dumps(sys.argv[1:], separators=(',', ':')))
PYTRANSFORMREQUEST
  )" || return 1
  ( trap '' PIPE; printf 'transform-settings %s\n' "$request" >&"$WORKER_LOCK_KEEPALIVE_FD" ) 2>/dev/null || return 1
  IFS= read -r -t 120 response <&"$WORKER_LOCK_RESPONSE_FD" || return 1
  if [[ "$response" == 'rejected-settings '* ]]; then
    # The successful result is captured by the caller. A policy refusal is
    # actionable diagnostic output, so keep it outside that result channel.
    log "Protected installer settings transformation refused: ${response#rejected-settings }" >&2
    return 1
  fi
  [[ "$response" == 'transformed-settings '* ]] || return 1
  assert_worker_coordination || return 1
  /usr/bin/python3 -I - "$action" "${response#transformed-settings }" <<'PYTRANSFORMRESPONSE'
import json, re, sys
value=json.loads(sys.argv[2])
if (type(value) is not dict or set(value)!={'changed','profile','sha256'} or type(value['changed']) is not bool
        or value['profile'] not in ('standard','lite') or type(value['sha256']) is not str
        or not re.fullmatch('[a-f0-9]{64}', value['sha256'])):
    raise SystemExit('Invalid guarded installer settings response')
print(('changed' if value['changed'] else 'unchanged') + (':' + value['profile'] if sys.argv[1]=='profile' else ''))
PYTRANSFORMRESPONSE
}

apply_requested_deployment_profile() {
  [ -n "$REQUESTED_DEPLOYMENT_PROFILE" ] || return 0
  [ -n "$CONFIG_HASH_BEFORE" ] || return 0
  local result
  if ! result="$(run_installer_settings_transform profile "$REQUESTED_DEPLOYMENT_PROFILE")"; then
    log 'The requested deployment profile could not be applied safely; settings and protected recovery evidence were preserved.'
    return 1
  fi
  case "$result" in
    "unchanged:$REQUESTED_DEPLOYMENT_PROFILE")
      CONFIG_HASH_EXPECTED="$CONFIG_HASH_BEFORE"
      log "Deployment profile already uses ${REQUESTED_DEPLOYMENT_PROFILE^} mode."
      ;;
    "changed:$REQUESTED_DEPLOYMENT_PROFILE")
      CONFIG_EXPECTED_SNAPSHOT="$(mktemp "$INSTALL_TEMP_ROOT/slsmassnotifyserver-config-expected.XXXXXX")" || return 1
      CONFIG_HASH_EXPECTED="$(safe_config_snapshot "$CONFIG_FILE" "$CONFIG_EXPECTED_SNAPSHOT")" || {
        log 'The changed deployment profile could not be snapshotted safely; the original configuration will be restored.'
        return 1
      }
      log "Deployment profile changed transactionally to ${REQUESTED_DEPLOYMENT_PROFILE^} mode; a failed installation will restore the original settings."
      ;;
    *)
      log 'The deployment profile helper returned an invalid result; the original configuration will be restored.'
      return 1
      ;;
  esac
}


apply_factory_branding_defaults() {
  [ -n "$CONFIG_HASH_BEFORE" ] || return 0
  if [ "$PENDING_CONFIG_STATE" = present ]; then
    log 'Saved factory branding was preserved because staged settings exist. Review those settings before applying them.'
    return 0
  fi
  local result
  result="$(run_installer_settings_transform branding '')" || return 1
  case "$result" in
    unchanged) return 0 ;;
    changed)
      if [ -z "$CONFIG_EXPECTED_SNAPSHOT" ]; then
        CONFIG_EXPECTED_SNAPSHOT="$(mktemp "$INSTALL_TEMP_ROOT/slsmassnotifyserver-config-expected.XXXXXX")" || return 1
      fi
      CONFIG_HASH_EXPECTED="$(safe_config_snapshot "$CONFIG_FILE" "$CONFIG_EXPECTED_SNAPSHOT")" || return 1
      log 'Factory sender and subject labels migrated to Southland Labs transactionally; custom settings were preserved.'
      ;;
    *) log 'Factory branding migration returned an invalid result.'; return 1 ;;
  esac
}

validate_preserved_config_prerequisites() {
  [ -n "$CONFIG_HASH_BEFORE" ] || return 0
  if ! CONFIG_PATH="$CONFIG_SNAPSHOT" /usr/bin/php -r '
$path = getenv("CONFIG_PATH");
require_once (getenv("SLS_CONFIG_CRYPTO_PHP") ?: "/usr/local/bin/sls_mass_notify/sls_config_crypto.php");
$settings = \FreePBX\modules\SlsConfigCrypto::decode((string)file_get_contents($path));
if (!is_array($settings)) {
    exit(1);
}

$ami = $settings["ami"] ?? null;
if (!is_array($ami)) {
    exit(2);
}
$username = trim((string)($ami["username"] ?? ""));
$password = trim((string)($ami["password"] ?? ""));
if (!preg_match("/^[a-z0-9_.-]{1,64}$/", $username)) {
    exit(3);
}
if (!preg_match("/^[\\x21-\\x7e]{1,128}$/", $password)) {
    exit(4);
}
exit(0);
'; then
    log "The preserved central config has invalid JSON or AMI credentials. Restore a valid mass-notifications.config before upgrading; the installer did not alter it."
    exit 1
  fi
}

validate_staged_central_config() {
  [ -n "$CONFIG_HASH_BEFORE" ] || return 0
  if /usr/bin/python3 -I "$STAGING_DIR/$MODULE/bin/sls_mass_notify/sls_config.py" "$CONFIG_FILE" >/dev/null 2>>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}"; then
    return 0
  else
    local config_status=$?
    INSTALL_ERROR_CATEGORY="protected_config_validation_failed"
    log "The protected central configuration failed validation against the staged runtime. Module activation was not started."
    return "$config_status"
  fi
}

describe_config_drift() {
  before_path="$1"
  after_path="$2"
  CONFIG_BEFORE="$before_path" CONFIG_AFTER="$after_path" python3 -I - "$INSTALL_BOOTSTRAP_DIR/sls_config_crypto.py" <<'PY' 2>/dev/null || true
import json
import os

from pathlib import Path
import sys
import types
sys.dont_write_bytecode = True
path = Path(sys.argv[1])
module = types.ModuleType('sls_config_crypto'); module.__file__ = str(path)
exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
before = module.read_config(os.environ["CONFIG_BEFORE"])
after = module.read_config(os.environ["CONFIG_AFTER"])

changes = []
def compare(left, right, path="settings"):
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            child = f"{path}.{key}"
            if key not in left:
                changes.append(f"added {child}")
            elif key not in right:
                changes.append(f"removed {child}")
            else:
                compare(left[key], right[key], child)
        return
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            changes.append(f"changed {path} length")
            return
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            compare(left_item, right_item, f"{path}[{index}]")
        return
    if left != right:
        changes.append(f"changed {path}")

compare(before, after)
for item in changes[:25]:
    print(f"Config drift: {item}")
if len(changes) > 25:
    print(f"Config drift: {len(changes) - 25} additional path(s)")
if not changes:
    print("Config drift: JSON values are equivalent; formatting or key order changed")
PY
}

verify_config_unchanged() {
  [ -n "$CONFIG_HASH_BEFORE" ] || return 0
  [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination || return 1
  local expected_hash expected_snapshot
  expected_hash="${CONFIG_HASH_EXPECTED:-$CONFIG_HASH_BEFORE}"
  expected_snapshot="${CONFIG_EXPECTED_SNAPSHOT:-$CONFIG_SNAPSHOT}"
  if [ -n "$CONFIG_RECOVERY_HASH" ]; then
    expected_hash="$CONFIG_RECOVERY_HASH"; expected_snapshot="$CONFIG_RECOVERY_SNAPSHOT"
  fi
  current_hash="$(safe_config_hash "$CONFIG_FILE" 2>/dev/null || true)"
  if [ "$current_hash" = "$expected_hash" ]; then
    # Later postconditions can still fail. Retire this snapshot only after the
    # transaction's commit or verified rollback has been recorded durably.
    [ "$WORKER_COORDINATION_REQUIRED" != 1 ] || assert_worker_coordination || return 1
    return 0
  fi
  current_snapshot="$(mktemp "$INSTALL_TEMP_ROOT/slsmassnotifyserver-config-current.XXXXXX")"
  if safe_config_snapshot "$CONFIG_FILE" "$current_snapshot" >/dev/null 2>&1; then
    describe_config_drift "$expected_snapshot" "$current_snapshot"
  else
    log "Config drift: the live protected path became missing, non-regular, or unsafe."
  fi
  rm -f "$current_snapshot"
  # The final verifier has no authority to rewind a live MFA cursor. EXIT may
  # recover only inside a live lease owner using strict durable targets.
  log "The installer detected an unexpected central config change and stopped; live settings and the original snapshot were preserved."
  exit 1
}

module_registry_state() {
  SLS_NATIVE_REGISTRY_MODULE="$1" php -r '
$bootstrap_settings = ["freepbx_auth" => false, "skip_astman" => true];
require "/etc/freepbx.conf";
$module = getenv("SLS_NATIVE_REGISTRY_MODULE");
if (!in_array($module, ["slsmassnotifyserver", "framework", "dashboard", "backup", "recordings"], true)) { exit(2); }
$statement = \FreePBX::Database()->prepare("SELECT version, enabled FROM modules WHERE modulename = ?");
$statement->execute([$module]); $rows = $statement->fetchAll(\PDO::FETCH_ASSOC);
if (count($rows) === 0) { echo "absent\n"; exit(0); }
if (count($rows) !== 1 || !is_string($rows[0]["version"] ?? null)
    || !preg_match("/^[A-Za-z0-9_.+-]{1,64}$/D", $rows[0]["version"])
    || !in_array($rows[0]["enabled"] ?? null, [0, 1, "0", "1"], true)) { exit(3); }
echo (in_array($rows[0]["enabled"], [1, "1"], true) ? "enabled" : "disabled") . "\t" . $rows[0]["version"] . "\n";
// A native bootstrap can leave a nonzero ambient CLI status. Return success
// explicitly, only after the registry shape and values above were verified.
exit(0);
'
}

preflight_native_dependency_versions() {
  local module floor state version
  for module in framework dashboard backup recordings; do
    case "$module" in
      framework) floor=17.0.33 ;;
      dashboard) floor=17.0.5 ;;
      backup) floor=17.0.13 ;;
      recordings) floor=17.0.6 ;;
    esac
    state="$(module_registry_state "$module")" || {
      log "The native $module registration could not be verified; no SLL transaction was started."
      return 1
    }
    # Missing optional prerequisites follow the authenticated installation path;
    # Framework must already exist to establish a functioning FreePBX host.
    if [ "$state" = absent ] && [ "$module" != framework ]; then continue; fi
    if [[ "$state" != enabled$'\t'* && "$state" != disabled$'\t'* ]]; then
      log "The native $module registration is missing or invalid; no SLL transaction was started."
      return 1
    fi
    version="${state#*$'\t'}"
    if [[ ! "$version" =~ ^17\.[0-9]+(\.[0-9]+){1,3}$ ]] \
      || ! /usr/bin/dpkg --compare-versions "$version" ge "$floor"; then
      log "FreePBX $module $version is below the reviewed vendor floor $floor or is an unqualified version. Update this module through native FreePBX Module Admin, then retry; no SLL transaction was started."
      return 1
    fi
  done
}

module_known() {
  local state
  state="$(module_registry_state "$1")" || return $?
  [[ "$state" == enabled$'\t'* || "$state" == disabled$'\t'* ]]
}

module_enabled() {
  local state
  state="$(module_registry_state "$1")" || return $?
  [[ "$state" == enabled$'\t'* ]]
}

lint_staged_module_php() {
  local source_root="$1" script php_version_id
  php_version_id="$(/usr/bin/php -n -r 'echo PHP_VERSION_ID;')" || return 1
  if [ "$php_version_id" -lt 80500 ] && [ -e "$source_root/passkey-libs/vendor/symfony/polyfill-uuid/bootstrap85.php" ]; then
    # The authenticated archive contains one upstream branch gated to PHP 8.5.
    # Match both its exact bytes and its exact version-gated loader before any
    # parser exception; unrelated PHP files always receive normal syntax checks.
    /usr/bin/python3 -I - "$source_root" <<'PYPHP_COMPATIBILITY' || return 1
from pathlib import Path
import hashlib, os, stat, sys
root = Path(sys.argv[1])
expected = {
    'bootstrap80.php': 'f5fb564b3680b4c79c14697e2e92053b620b90207fe30684ce4b809bd309f07e',
    'bootstrap85.php': 'ac3e2f020892721841f0083ef34c6794992e6db06b6379969a245f51066e5a85',
}
identity = lambda m: (m.st_dev, m.st_ino, m.st_uid, m.st_mode, m.st_nlink,
    m.st_size, m.st_mtime_ns, m.st_ctime_ns)
for name, digest in expected.items():
    path = root / 'passkey-libs/vendor/symfony/polyfill-uuid' / name
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, 'rb') as source:
            before = os.fstat(source.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != 0 or before.st_mode & 0o022 or before.st_size > 65536):
                raise ValueError('unsafe file metadata')
            body = source.read(65537)
            after = os.fstat(source.fileno())
        if (len(body) != before.st_size or identity(before) != identity(after)
                or identity(after) != identity(path.lstat())
                or hashlib.sha256(body).hexdigest() != digest):
            raise ValueError('unexpected file contents')
    except (OSError, ValueError):
        raise SystemExit('The reviewed PHP 8.5 compatibility profile differs at ' + name
            + '. Preserve the package and use its matching verified installer; no PHP checks were bypassed.') from None
PYPHP_COMPATIBILITY
  fi
  while IFS= read -r -d '' script; do
    if [ "$php_version_id" -lt 80500 ] && [ "$script" = "$source_root/passkey-libs/vendor/symfony/polyfill-uuid/bootstrap85.php" ]; then continue; fi
    /usr/bin/php -n -l "$script" >/dev/null || {
      log "The staged module contains an invalid PHP file: $script"
      return 1
    }
  done < <(find "$source_root" -type f -name '*.php' -print0)
}

stage_module_directory() {
  local state inventory_status
  INITIAL_NATIVE_MODULE_REGISTRY_STATE=unknown
  case "${1:-}" in
    ''|--source-only) ;;
    *) log 'Unknown module staging mode; no source was extracted.'; return 2 ;;
  esac
  # Inspection and retained-source review need only the already authenticated
  # payload. They must not bootstrap mutable FreePBX PHP to query its registry.
  if [ "${1:-}" != --source-only ]; then
    state="$(module_registry_state "$MODULE")" || {
      inventory_status=$?
      log 'FreePBX could not return its native module registration. Installation stopped before staging; no existing module was classified as absent.'
      return "$inventory_status"
    }
    case "$state" in
      enabled$'\t'*) HAD_EXISTING_MODULE=1; MODULE_WAS_ENABLED=1; INITIAL_NATIVE_MODULE_REGISTRY_STATE=established ;;
      disabled$'\t'*) HAD_EXISTING_MODULE=1; MODULE_WAS_ENABLED=0; INITIAL_NATIVE_MODULE_REGISTRY_STATE=established ;;
      absent) HAD_EXISTING_MODULE=0; MODULE_WAS_ENABLED=0; INITIAL_NATIVE_MODULE_REGISTRY_STATE=known_absent ;;
      *) log 'FreePBX returned an invalid native module registration; no module was staged.'; return 1 ;;
    esac
    if [ "$HAD_EXISTING_MODULE" -eq 1 ]; then
      [ -e "$CONFIG_FILE" ] || { log "An existing SLL module is missing its protected configuration. Restore a configuration backup before upgrading."; return 1; }
      log "Existing SLL Mass Notify Server module detected; preserving config and preparing a recoverable upgrade."
    fi
  fi
  STAGING_DIR="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-mass-notify-stage.XXXXXX")" || return 1
  tar -xzf "$TGZ" -C "$STAGING_DIR" || return 1
  if [ ! -d "$STAGING_DIR/$MODULE" ] || [ ! -r "$STAGING_DIR/$MODULE/module.xml" ]; then
    log "The staged module tree is incomplete."
    return 1
  fi
  lint_staged_module_php "$STAGING_DIR/$MODULE" || return 1
  while IFS= read -r script; do
    bash -n "$script" || {
      log "The staged module contains an invalid shell script: $script"
      return 1
    }
  done < <(find "$STAGING_DIR/$MODULE" -type f -name '*.sh' -print)
  while IFS= read -r script; do
    python3 -I -c 'import pathlib,sys; compile(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[1], "exec")' "$script" || {
      log "The staged module contains an invalid Python script: $script"
      return 1
    }
  done < <(find "$STAGING_DIR/$MODULE" -type f -name '*.py' -print)
}

create_module_recovery_directory() {
  /usr/bin/python3 -I - <<'PYMODULEBACKUP'
import os, pwd, stat
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
account = pwd.getpwnam('asterisk')
if account.pw_uid == 0: raise RuntimeError('Asterisk UID must be nonzero')
public = '/var/www/html/admin/modules'
parent = os.open('/', flags)
anchor = -1
try:
    for part in public.split('/')[1:]:
        child = os.open(part, flags, dir_fd=parent)
        os.close(parent); parent = child
    info = os.fstat(parent)
    if (info.st_uid not in (0, account.pw_uid) or info.st_gid not in (0, account.pw_gid)
            or info.st_mode & 0o4002):
        raise RuntimeError('Unsafe public module directory')
    name = '.sls-mass-notify-recovery'
    try: os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError: pass
    anchor = os.open(name, flags, dir_fd=parent)
    opened = os.fstat(anchor)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    def mount_id(fd):
        with open('/proc/self/fdinfo/' + str(fd), encoding='ascii') as source:
            for line in source:
                if line.startswith('mnt_id:'): return int(line.split(':', 1)[1])
        raise RuntimeError('Module backup mount identity is unavailable')
    if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or opened.st_dev != info.st_dev or mount_id(anchor) != mount_id(parent)):
        raise RuntimeError('Unsafe module recovery anchor; preserve it for review')
    if (opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode)) != (0, 0, 0o700):
        # mkdir inherits a setgid parent. Only an empty, root-created private
        # inode can finish that interrupted initialization; existing contents
        # or service ownership never become trusted through normalization.
        if (opened.st_uid != 0 or opened.st_gid not in (0, account.pw_gid)
                or stat.S_IMODE(opened.st_mode) not in (0o700, 0o2700) or os.listdir(anchor)):
            raise RuntimeError('Unsafe module recovery anchor; preserve it for review')
        os.fchown(anchor, 0, 0); os.fchmod(anchor, 0o700)
        os.fsync(anchor)
    child_name = 'transaction.' + os.urandom(12).hex()
    os.mkdir(child_name, 0o700, dir_fd=anchor)
    child = os.open(child_name, flags, dir_fd=anchor)
    try:
        current = os.fstat(child)
        if current.st_uid != 0 or current.st_gid != 0 or stat.S_IMODE(current.st_mode) != 0o700:
            raise RuntimeError('New module recovery directory changed during creation')
        os.fsync(child)
    finally: os.close(child)
    os.fsync(anchor); os.fsync(parent)
    if (os.stat(name, dir_fd=parent, follow_symlinks=False).st_dev,
            os.stat(name, dir_fd=parent, follow_symlinks=False).st_ino) != (opened.st_dev, opened.st_ino):
        raise RuntimeError('Module recovery anchor changed during creation')
    print(public + '/.sls-mass-notify-recovery/' + child_name)
finally:
    if anchor >= 0: os.close(anchor)
    os.close(parent)
PYMODULEBACKUP
}

activate_staged_module() {
  MODULE_BACKUP_DIR="$(create_module_recovery_directory)" || return 1
  persist_install_transaction mutating || return 1
  # Activate by descriptor-relative renames: a replaced public pathname must
  # never redirect privileged copying or ownership changes to another tree.
  /usr/bin/python3 -I - "$STAGING_DIR" "$MODULE_BACKUP_DIR" <<'PYACTIVATE' || return 1
import os, pwd, stat, sys
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
account = pwd.getpwnam('asterisk')
if account.pw_uid == 0: raise RuntimeError('Asterisk UID must be nonzero')
def directory(path):
    fd = os.open('/', flags)
    try:
        for part in path.split('/'):
            if not part: continue
            if part in ('.', '..'): raise RuntimeError('unsafe module directory')
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd); raise
stage, backup, web = (directory(path) for path in (*sys.argv[1:], '/var/www/html/admin/modules'))
try:
    for fd in (stage, backup):
        info = os.fstat(fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700: raise RuntimeError('unsafe private module directory')
    if os.fstat(backup).st_dev != os.fstat(web).st_dev:
        raise RuntimeError('module recovery must share the installed module filesystem')
    os.mkdir('candidate', 0o700, dir_fd=backup)
    tree = os.open('candidate', flags, dir_fd=backup)
    source = os.open('slsmassnotifyserver', flags, dir_fd=stage)
    def copy_tree(src, dst):
        for name in os.listdir(src):
            before = os.stat(name, dir_fd=src, follow_symlinks=False)
            if before.st_uid != 0 or before.st_mode & 0o022:
                raise RuntimeError('unprotected staged module source')
            if stat.S_ISDIR(before.st_mode):
                os.mkdir(name, 0o700, dir_fd=dst)
                child = os.open(name, flags, dir_fd=src)
                target = os.open(name, flags, dir_fd=dst)
                try: copy_tree(child, target)
                finally: os.close(child); os.close(target)
            elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=src)
                target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dst)
                try:
                    opened = os.fstat(child)
                    if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                        raise RuntimeError('staged module changed before copy')
                    while True:
                        block = os.read(child, 65536)
                        if not block: break
                        view = memoryview(block)
                        while view:
                            count = os.write(target, view)
                            if count <= 0: raise RuntimeError('short module activation copy')
                            view = view[count:]
                    after = os.fstat(child)
                    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise RuntimeError('staged module changed during copy')
                    os.fchmod(target, 0o755 if before.st_mode & 0o111 else 0o644)
                    os.fsync(target)
                finally: os.close(child); os.close(target)
            else: raise RuntimeError('unsafe staged module entry')
        os.fsync(dst)
    try: copy_tree(source, tree)
    except BaseException: os.close(tree); raise
    finally: os.close(source)
    def prepare(fd):
        for name in os.listdir(fd):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, flags, dir_fd=fd)
                try: prepare(child)
                finally: os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    if (info.st_dev,info.st_ino)!=(opened.st_dev,opened.st_ino): raise RuntimeError('staged source changed')
                    os.fchown(child,account.pw_uid,account.pw_gid)
                    os.fchmod(child,0o755 if info.st_mode & 0o111 else 0o644)
                    os.fsync(child)
                finally: os.close(child)
            else: raise RuntimeError('unsafe staged module entry')
        os.fchown(fd,account.pw_uid,account.pw_gid); os.fchmod(fd,0o755)
        os.fsync(fd)
    try: prepare(tree)
    finally: os.close(tree)
    os.fsync(backup)
    prior=False
    try: info=os.stat('slsmassnotifyserver',dir_fd=web,follow_symlinks=False)
    except FileNotFoundError: pass
    else:
        if not stat.S_ISDIR(info.st_mode): raise RuntimeError('installed module directory is unsafe')
        os.rename('slsmassnotifyserver','slsmassnotifyserver',src_dir_fd=web,dst_dir_fd=backup)
        prior=True
        os.fsync(backup); os.fsync(web)
    try: os.rename('candidate','slsmassnotifyserver',src_dir_fd=backup,dst_dir_fd=web)
    except BaseException:
        if prior:
            os.rename('slsmassnotifyserver','slsmassnotifyserver',src_dir_fd=backup,dst_dir_fd=web)
            os.fsync(web); os.fsync(backup)
        raise
    os.fsync(web); os.fsync(backup)
    marker = os.open('module-swap-complete', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=backup)
    os.fsync(marker); os.close(marker)
    os.fsync(web); os.fsync(backup)
finally:
    for fd in (stage,backup,web): os.close(fd)
PYACTIVATE
  MODULE_ACTIVATED=1
}

sync_module_version() {
  # Retain the old internal entrypoint for transaction compatibility. Native
  # installation owns registration; writing a version here could disguise a
  # refused hook, especially when repairing the same already-installed version.
  module_registered_at_expected_version
}

module_registered_at_expected_version() {
  SLS_MASS_NOTIFY_MODULE="$MODULE" php -r '
require "/etc/freepbx.conf";
$module = getenv("SLS_MASS_NOTIFY_MODULE") ?: "slsmassnotifyserver";
$stmt = \FreePBX::Database()->prepare("SELECT version, enabled FROM modules WHERE modulename = ?");
$stmt->execute([$module]);
$rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);
exit(count($rows) === 1 && ($rows[0]["version"] ?? null) === "0.2.0-beta"
    && in_array($rows[0]["enabled"] ?? null, [1, "1"], true) ? 0 : 1);
' >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1
}

install_native_module() {
  SLS_NATIVE_INSTALL_MODULE="$1" SLS_NATIVE_INSTALL_ACTION="${2:-install}" php -r '
require "/etc/freepbx.conf";
$module = getenv("SLS_NATIVE_INSTALL_MODULE");
if (!in_array($module, ["slsmassnotifyserver", "framework", "dashboard", "backup", "recordings"], true)) { exit(2); }
$action = getenv("SLS_NATIVE_INSTALL_ACTION");
if (!in_array($action, ["install", "enable"], true)) { exit(2); }
$report = static function ($result) {
    if (!is_array($result)) { return; }
    foreach (array_slice($result, 0, 10) as $message) {
        if (!is_string($message)) { continue; }
        $message = preg_replace("/[\x00-\x1f\x7f]/", " ", substr($message, 0, 2048));
        fwrite(STDERR, "  " . $message . "\n");
    }
};
// Moduleadmin CLI can exit zero after doInstall returns false. Consume the
// native result directly so errors cannot be hidden by console exit semantics.
$freepbx = \FreePBX::Create();
$freepbx->Modules->loadAllFunctionsInc();
$modules = \module_functions::create();
$info = $modules->getinfo($module);
$record = $info[$module] ?? null;
if (!is_array($record) || !is_string($record["version"] ?? null) || $record["version"] === "") { exit(3); }
$expected = $record["version"];
if (($record["status"] ?? null) === MODULE_STATUS_DISABLED) {
    $result = $modules->enable($module, false, false);
    if ($result !== true) {
        fwrite(STDERR, "Native FreePBX module enable was refused.\n"); $report($result); exit(4);
    }
    $info = $modules->getinfo($module); $record = $info[$module] ?? null;
}
if (!is_array($record) || !in_array($record["status"] ?? null,
    [MODULE_STATUS_ENABLED, MODULE_STATUS_NOTINSTALLED, MODULE_STATUS_NEEDUPGRADE], true)) {
    fwrite(STDERR, "Native FreePBX module status cannot enter installation.\n"); exit(5);
}
if ($action === "enable" && ($record["status"] ?? null) !== MODULE_STATUS_ENABLED) {
    fwrite(STDERR, "The existing module needs administrator-managed installation before it can be enabled.\n"); exit(5);
}
if ($action === "install") {
    $result = $modules->install($module, false, false);
    if ($result !== true) {
        fwrite(STDERR, "Native FreePBX module installation was refused. Preserve the installer log and recovery evidence.\n");
        $report($result); exit(6);
    }
}
$statement = \FreePBX::Database()->prepare("SELECT version, enabled FROM modules WHERE modulename = ?");
$statement->execute([$module]); $rows = $statement->fetchAll(\PDO::FETCH_ASSOC);
if (count($rows) !== 1 || ($rows[0]["version"] ?? null) !== $expected
    || !in_array($rows[0]["enabled"] ?? null, [1, "1"], true)) {
    fwrite(STDERR, "Native FreePBX module registration did not match the completed installation.\n"); exit(7);
}
echo "Native FreePBX module installation and registration verified.\n";
exit(0);
'
}

enable_native_module() {
  install_native_module "$1" enable
}

refresh_module_install() {
  log "Refreshing SLL Mass Notify Server runtime integration through native Module Admin."
  SLS_MASS_NOTIFY_DEFER_SIGNING=1 install_native_module "$MODULE" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
    log "Native runtime refresh failed. See $LOG_FILE."
    return 1
  }
}

runtime_install_postconditions_available() {
  local executable
  for executable in \
    /usr/local/bin/slsconsole \
    /usr/local/bin/sls_mass_notify/sls_mass_notify_install_piper_voices.sh \
    /usr/local/bin/sls_mass_notify/sls_notify.py \
    /usr/local/bin/sls_mass_notify/sls_config.py \
    /usr/local/bin/sls_mass_notify/piper/venv/bin/piper \
    /usr/local/bin/piper \
    "$DATA_DIR/piper/venv/bin/piper"; do
    if [ ! -x "$executable" ]; then
      log "Runtime prerequisite is missing or not executable: $executable"
      return 1
    fi
  done
  MODULE_ROOT="/var/www/html/admin/modules/$MODULE" python3 -I - <<'PY'
import filecmp
import os
import pathlib

module = pathlib.Path(os.environ["MODULE_ROOT"])
runtime = pathlib.Path("/usr/local/bin/sls_mass_notify")
expected = {}
for name in (
    "sls_mass_notify_nws_poll.sh",
    "sls_mass_notify_weather_poll.sh",
    "sls_mass_notify_schedule_worker.php",
    "sls_mass_notify_announcement_worker.php",
    "sls_mass_notify_automation_worker.php",
    "sls_mass_notify_cluster_worker.php",
    "sls_mass_notify_cluster_effect.php",
    "sls_mass_notify_delivery_authorization.php",
    "sls_mass_notify_panic.php",
    "sls_mass_notify_live_paging.php",
    "sls_mass_notify_weather_channels.php",
    "sls_mass_notify_phone_agi.py",
    "sls_mass_notify_test.sh",
    "sls_mass_notify_update.sh",
    "sls_mass_notify_maintenance.sh",
    "sls_mass_notify_uninstall.sh",
    "sls_mass_notify_install_piper_voices.sh",
):
    expected[pathlib.PurePosixPath(name)] = module / "bin" / name
source_root = module / "bin" / "sls_mass_notify"
if not source_root.is_dir():
    print("Runtime source directory is missing: bin/sls_mass_notify")
    raise SystemExit(1)
for source in source_root.rglob("*"):
    if source.is_file() and "__pycache__" not in source.parts and source.suffix != ".pyc":
        expected[pathlib.PurePosixPath(source.relative_to(source_root).as_posix())] = source
actual = {
    pathlib.PurePosixPath(path.relative_to(runtime).as_posix())
    for path in runtime.rglob("*")
    if path.is_file()
    and path.relative_to(runtime).parts[:1] != ("piper",)
    and "__pycache__" not in path.parts
    and path.suffix != ".pyc"
}
if actual != set(expected):
    for label, paths in (("missing", set(expected) - actual), ("unexpected", actual - set(expected))):
        for path in sorted(paths)[:12]:
            print(f"Runtime inventory {label}: {str(path)!r}")
    raise SystemExit(1)
for relative, source in expected.items():
    target = runtime / pathlib.Path(str(relative))
    if not target.is_file() or not filecmp.cmp(source, target, shallow=False):
        print(f"Runtime file does not match the installed package: {str(relative)!r}")
        raise SystemExit(1)
PY
}

ensure_runtime_installed() {
  protected_install_phase admit || return 1
  runtime_install_postconditions_available || {
    log "Authenticated runtime postconditions are incomplete. Preserve recovery files; the installer will not execute an older module hook to repair privileged files."
    return 1
  }
}

install_module_with_autoenable() {
  local install_output install_status

  if install_output="$(install_native_module "$MODULE" 2>&1 | /usr/bin/tail -c 131072)"; then
    printf '%s\n' "$install_output" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}"
    return 0
  else
    install_status=$?
  fi
  printf '%s\n' "$install_output" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}"

  return "$install_status"
}

verify_runtime_shell_syntax() {
  local runtime_dir="${1:-/usr/local/bin/sls_mass_notify}"
  local script
  for script in sls_mass_notify_nws_poll.sh sls_mass_notify_weather_poll.sh \
    sls_mass_notify_test.sh sls_mass_notify_update.sh sls_mass_notify_maintenance.sh \
    sls_mass_notify_uninstall.sh sls_mass_notify_install_piper_voices.sh; do
    if [ ! -x "$runtime_dir/$script" ] || ! /bin/bash -n "$runtime_dir/$script" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
      INSTALL_ERROR_CATEGORY="update_script_syntax_error"
      log "Required runtime shell script is missing, not executable, or invalid: $script"
      return 2
    fi
  done
}

verify_announcement_worker_health() {
  local runtime_dir="${1:-/usr/local/bin/sls_mass_notify}"
  /usr/bin/php -l "$runtime_dir/sls_announcement_jobs.php" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || return $?
  /usr/bin/php -l "$runtime_dir/sls_mass_notify_announcement_worker.php" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || return $?
  sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 45 \
    /usr/bin/php "$runtime_dir/sls_mass_notify_announcement_worker.php" --health-check --record-health >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1
}

ensure_piper_runtime() {
  protected_install_phase dependencies --apply
}

verify_piper_voices() {
  local voice_dir="$DATA_DIR/piper/voices"
  local synthesis_file model
  while read -r expected filename; do
    printf '%s  %s\n' "$expected" "$voice_dir/$filename" | sha256sum -c - >/dev/null || {
      log "Required Piper voice failed checksum validation: $filename"
      exit 1
    }
  done <<'EOF'
f7d01dde371555732c4c314111ac79672b1a5ce2fc19266ab42178fd8df7f375 en_US-lessac-low.onnx
45754dfdebb3b8661c3fc564713772deec6e064feeb5b4e9594857dc7305193a en_US-lessac-low.onnx.json
a5a91abb7de0f104358a25aded480ddacf1ff0762886325886ec406a2e86aab3 en_US-amy-low.onnx
2250a9a605b8dc35a116717fadc5056695dd809e34a15d02f72a0f52d53d3ebb en_US-amy-low.onnx.json
8d21a085cc4c0010f1f3e91d5008c8691277ccfa744eb0d747becd33a3444baf en_US-ryan-low.onnx
b27147e56b0525962609f82f58171f4618cbf17c6fb043d7d724ff28cc4aed60 en_US-ryan-low.onnx.json
EOF
  for model in en_US-lessac-low.onnx en_US-amy-low.onnx en_US-ryan-low.onnx; do
    synthesis_file="$DATA_DIR/sounds/tts/installer-voice-check-${model%.onnx}-$$.wav"
    rm -f "$synthesis_file"
    if ! printf '%s\n' 'SLL voice check.' | sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 90 /usr/bin/env ORT_DISABLE_TELEMETRY=1 /usr/local/bin/piper \
      --model "$voice_dir/$model" --output-file "$synthesis_file" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
      rm -f "$synthesis_file"
      log "Piper could not synthesize audio with $model. See $LOG_FILE."
      exit 1
    fi
    soxi "$synthesis_file" >/dev/null 2>&1 || {
      rm -f "$synthesis_file"
      log "Piper produced an invalid WAV with $model."
      exit 1
    }
    rm -f "$synthesis_file"
  done
}

repair_runtime_permissions() {
  # Permission repair and promotion are one authenticated, bounded operation.
  # This replaces recursive ownership repair of arbitrary web-owned files.
  protected_install_phase prepare --apply
}

secure_central_config() {
  if ! CONFIG_PATH="$CONFIG_FILE" /usr/bin/python3 -I - <<'PY'
import os
import pwd
import stat

path = os.environ["CONFIG_PATH"]
parts = [part for part in path.split("/") if part]
if not path.startswith("/") or not parts or "\x00" in path:
    raise SystemExit(2)
directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
parent_fd = os.open("/", directory_flags)
try:
    for component in parts[:-1]:
        next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = next_fd
    file_fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
finally:
    os.close(parent_fd)
try:
    metadata = os.fstat(file_fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SystemExit(3)
    account = pwd.getpwnam("asterisk")
    os.fchmod(file_fd, 0o640)
    os.fchown(file_fd, account.pw_uid, account.pw_gid)
    verified = os.fstat(file_fd)
    if stat.S_IMODE(verified.st_mode) != 0o640 or verified.st_uid != account.pw_uid or verified.st_gid != account.pw_gid:
        raise SystemExit(4)
finally:
    os.close(file_fd)
PY
  then
    log "Protected central configuration permissions or ownership could not be secured."
    exit 1
  fi
}

validate_ami_health_file() {
  python3 -I - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    health = json.load(handle)
if health.get("status") != "ok" or health.get("ami") != "authenticated" or health.get("ping") != "pong":
    raise SystemExit("AMI health result is incomplete")
if health.get("pjsip_show_contacts") not in {"authorized", "authorized_empty"}:
    raise SystemExit("AMI PJSIPShowContacts authorization was not confirmed")
if health.get("pjsip_notify") != "authorized":
    raise SystemExit("AMI PJSIPNotify authorization was not confirmed")
if health.get("live_paging_actions") != {
        name: "authorized" for name in ("MuteAudio", "PlayDTMF", "Setvar", "Getvar")}:
    raise SystemExit("AMI live-paging authorization was not confirmed for MuteAudio, PlayDTMF, Setvar and Getvar")
PY
}

verify_ami_with_repair() (
  local attempt probe_dir
  probe_dir="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-mass-notify-ami-check.XXXXXX")" || {
    log "Unable to create private AMI verification storage. Check free space and /tmp permissions."
    return 1
  }
  trap 'rm -f -- "$probe_dir/health.json" "$probe_dir/health.err"; rmdir -- "$probe_dir" 2>/dev/null || true' EXIT
  for attempt in 1 2 3; do
    if sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 15 /usr/bin/python3 /usr/local/bin/sls_mass_notify/sls_notify.py --ami-health-json \
      >"$probe_dir/health.json" 2>"$probe_dir/health.err"; then
      if validate_ami_health_file "$probe_dir/health.json" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1
      then
        return 0
      fi
    fi
    cat "$probe_dir/health.err" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>/dev/null || true
    log "SLL AMI health check attempt $attempt failed; rebuilding the loopback manager integration."
    refresh_module_install >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || true
    asterisk -rx "manager reload" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || true
    sleep 2
  done
  log "SLL AMI authentication, contact/NOTIFY discovery, or caller-ready paging authorization failed after automatic repair. See $LOG_FILE."
  return 1
)

validate_phone_collector_probe_file() {
  python3 -I - "$1" "$2" <<'PY'
import json
import math
import sys

kind, path = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    result = json.load(handle)
if not isinstance(result, dict) or result.get("ok") is not True:
    raise SystemExit("Phone runtime probe failed; review the collector service and local AMI permissions.")
if kind == "ami":
    if result.get("ping") is not True or result.get("show_dialplan") is not True:
        raise SystemExit("AMI Ping/ShowDialPlan authorization was not confirmed; the SLL account requires reporting permission.")
elif kind == "health":
    age = result.get("heartbeat_age_seconds")
    if (result.get("connected") is not True or type(age) not in (int, float)
            or not math.isfinite(age) or not 0 <= age <= 15
            or any(type(result.get(key)) is not int or result[key] < 0 for key in ("active_batches", "reserved_contacts"))):
        raise SystemExit("The phone collector has no valid current heartbeat; new phone audio admission remains blocked.")
else:
    raise SystemExit("Unknown phone runtime probe.")
PY
}

verify_phone_collector() (
  local probe_dir attempt service_ready=0
  systemctl is-enabled --quiet sls-mass-notify-phone-events.service || {
      log "The phone outcome collector must be enabled and active. Review systemctl status sls-mass-notify-phone-events.service, then run Repair Installation."
      return 1
    }
  # A fresh Manager::add_manager account becomes usable only after FreePBX
  # generates manager_additional.conf. Allow the existing systemd restart
  # delay to finish; never start a disabled unit or accept status alone.
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if systemctl is-active --quiet sls-mass-notify-phone-events.service; then service_ready=1; break; fi
    [ "$attempt" -eq 10 ] || sleep 2
  done
  [ "$service_ready" -eq 1 ] || {
    log "The phone outcome collector did not become active within its bounded startup wait. Review its service journal, then run Repair Installation."
    return 1
  }
  probe_dir="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-phone-collector-check.XXXXXX")" || return 1
  trap 'rm -f -- "$probe_dir/ami.json" "$probe_dir/health.json"; rmdir -- "$probe_dir" 2>/dev/null || true' EXIT
  if ! sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=1 15 /usr/bin/python3 -I \
      /usr/local/bin/sls_mass_notify/sls_phone_admission.py --probe-ami >"$probe_dir/ami.json" 2>>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" \
    || ! validate_phone_collector_probe_file ami "$probe_dir/ami.json" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
    log "The SLL phone runtime could not confirm AMI Ping and ShowDialPlan reporting authorization. Review the local AMI connection and run Repair Installation."
    return 1
  fi
  for attempt in 1 2 3; do
    if sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=1 5 /usr/bin/python3 -I \
        /usr/local/bin/sls_mass_notify/sls_phone_events.py --health >"$probe_dir/health.json" 2>>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" \
      && validate_phone_collector_probe_file health "$probe_dir/health.json" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
      return 0
    fi
    sleep 2
  done
  log "The phone outcome collector has no fresh authenticated heartbeat. New phone audio admission remains blocked; inspect its service journal and private data permissions."
  return 1
)

verify_pjsip_contact_inventory() (
  local probe_dir
  probe_dir="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-mass-notify-contact-check.XXXXXX")" || {
    log "Unable to create private PJSIP verification storage. Check free space and /tmp permissions."
    return 1
  }
  trap 'rm -f -- "$probe_dir/contacts.out"; rmdir -- "$probe_dir" 2>/dev/null || true' EXIT
  if ! asterisk -rx "pjsip show contacts" >"$probe_dir/contacts.out" 2>&1; then
    cat "$probe_dir/contacts.out" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>/dev/null || true
    log "Asterisk could not return the PJSIP contact inventory. See $LOG_FILE."
    return 1
  fi
)

verify_local_api_route() (
  local path="$1" expected_pattern="$2" expected_codes="$3" label="$4"
  local probe_dir code
  probe_dir="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-mass-notify-api-check.XXXXXX")" || {
    log "Unable to create private API verification storage. Check free space and /tmp permissions."
    return 1
  }
  trap 'rm -f -- "$probe_dir/response.out"; rmdir -- "$probe_dir" 2>/dev/null || true' EXIT
  code="$(local_web_probe "$path" "$probe_dir/response.out" "$expected_pattern" || true)"
  if [[ ! "$code" =~ $expected_pattern ]]; then
    # A failed route may return a login page or PHP exception. Do not retain
    # that potentially sensitive response body in a shared temporary file.
    log "$label expected HTTP $expected_codes for $path, got $code. Check routing on the detected local Apache listener ports and the application error log."
    return 1
  fi
)

verify_served_php_runtime() (
  local directory code
  directory="$(mktemp -d "$INSTALL_TEMP_ROOT/sls-served-php.XXXXXX")" || return 1
  trap 'rm -f -- "$directory/response.json"; rmdir -- "$directory" 2>/dev/null || true' EXIT
  code="$(local_web_probe '/api/sls-mass-notify/?sls_installer_runtime=1' "$directory/response.json" '^(200|503)$' || true)"
  /usr/bin/python3 -I - "$directory/response.json" "$code" <<'PY'
import json, sys
from pathlib import Path
try:
    result = json.loads(Path(sys.argv[1]).read_bytes())
    assert result.get('probe') == 'sls_served_php_v1'
    assert isinstance(result.get('missing'), list)
except (OSError, ValueError, AssertionError):
    raise SystemExit('The served PHP runtime probe did not reach SLL. Check the local virtual host, API route and PHP handler; CLI PHP alone is insufficient.')
if result.get('ok') is not True or sys.argv[2] != '200':
    missing = [name for name in result['missing'] if name in ('pdo_sqlite','curl','dom','mbstring','posix','openssl','sodium','php_8_2_or_newer','php_security_floor','exec_enabled','proc_open_enabled','posix_geteuid_enabled','posix_getpwnam_enabled','openssl_encrypt_enabled','openssl_decrypt_enabled','sodium_crypto_aead_xchacha20poly1305_ietf_encrypt_enabled','sodium_crypto_pwhash_str_enabled','sem_get_enabled','sem_acquire_enabled','sem_remove_enabled','web_runtime_must_run_as_asterisk')]
    raise SystemExit('The PHP runtime serving Apache is missing: ' + ', '.join(missing) + '. Enable these for the active Apache/FPM PHP version and retry; installing CLI extensions alone does not repair another PHP handler.')
if result.get('module_version') != '0.2.0-beta':
    raise SystemExit('The web PHP handler is still serving another SLL release. Review Apache/PHP-FPM reload errors and draining requests, then retry; a CLI file check cannot verify cached web code.')
print('Served PHP prerequisites verified through the local API route.')
PY
)

verify_dashboard_integration() {
  local source_section="/var/www/html/admin/modules/$MODULE/dashboard/sections/SlsMassNotifyAnnouncement.class.php"
  local source_view="/var/www/html/admin/modules/$MODULE/dashboard/views/sections/sls-mass-notify-announcement.php"
  local dashboard_section="/var/www/html/admin/modules/dashboard/sections/SlsMassNotifyAnnouncement.class.php"
  local dashboard_view="/var/www/html/admin/modules/dashboard/views/sections/sls-mass-notify-announcement.php"

  cmp -s "$source_section" "$dashboard_section" || {
    log "Dashboard announcement section is missing or does not match the installed module."
    exit 1
  }
  cmp -s "$source_view" "$dashboard_view" || {
    log "Dashboard announcement view is missing or does not match the installed module."
    exit 1
  }

  php -r '
require "/etc/freepbx.conf";
$dashboard = \FreePBX::Dashboard();
$hooks = $dashboard->getConfig("allhooks");
$found = false;
foreach ((array)$hooks as $page) {
    foreach ((array)($page["entries"] ?? []) as $entry) {
        if (($entry["rawname"] ?? "") === "SlsMassNotifyAnnouncement"
            && ($entry["section"] ?? "") === "sls_mass_notify_announcement") {
            $found = true;
            break 2;
        }
    }
}
if (!$found) {
    fwrite(STDERR, "Mass Notify announcement hook is absent from the persisted Dashboard index.\n");
    exit(1);
}
require_once "/var/www/html/admin/modules/dashboard/sections/SlsMassNotifyAnnouncement.class.php";
$section = new \FreePBX\modules\Dashboard\Sections\SlsMassNotifyAnnouncement();
$html = $section->getContent("sls_mass_notify_announcement");
if (strpos($html, "dashboard-sls-mass-notify-announcement") === false
    || strpos($html, "Unable to load Mass Notify") !== false) {
    fwrite(STDERR, "Mass Notify announcement panel did not render successfully.\n");
    exit(1);
}
echo "Mass Notify Dashboard announcement panel verified (" . strlen($html) . " bytes).\n";
exit(0);
' >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
    log "Dashboard announcement hook or panel rendering verification failed. See $LOG_FILE."
    exit 1
  }
}

verify_installed_payload_parity() {
  MODULE_ROOT="/var/www/html/admin/modules/$MODULE" python3 -I - <<'PY'
import filecmp
import os
import pathlib
import stat

module = pathlib.Path(os.environ["MODULE_ROOT"])
runtime = pathlib.Path("/usr/local/bin/sls_mass_notify")
expected_runtime = {}
for name in (
    "sls_mass_notify_nws_poll.sh",
    "sls_mass_notify_weather_poll.sh",
    "sls_mass_notify_schedule_worker.php",
    "sls_mass_notify_announcement_worker.php",
    "sls_mass_notify_automation_worker.php",
    "sls_mass_notify_cluster_worker.php",
    "sls_mass_notify_cluster_effect.php",
    "sls_mass_notify_delivery_authorization.php",
    "sls_mass_notify_panic.php",
    "sls_mass_notify_live_paging.php",
    "sls_mass_notify_weather_channels.php",
    "sls_mass_notify_phone_agi.py",
    "sls_mass_notify_test.sh",
    "sls_mass_notify_update.sh",
    "sls_mass_notify_maintenance.sh",
    "sls_mass_notify_uninstall.sh",
    "sls_mass_notify_install_piper_voices.sh",
):
    expected_runtime[pathlib.PurePosixPath(name)] = module / "bin" / name
for source in (module / "bin" / "sls_mass_notify").rglob("*"):
    if not source.is_file() or "__pycache__" in source.parts or source.suffix == ".pyc":
        continue
    relative = pathlib.PurePosixPath(source.relative_to(module / "bin" / "sls_mass_notify").as_posix())
    expected_runtime[relative] = source

actual_runtime = {
    pathlib.PurePosixPath(path.relative_to(runtime).as_posix())
    for path in runtime.rglob("*")
    if path.is_file()
    and path.relative_to(runtime).parts[:1] != ("piper",)
    and "__pycache__" not in path.parts
    and path.suffix != ".pyc"
}
if actual_runtime != set(expected_runtime):
    missing = sorted(str(path) for path in set(expected_runtime) - actual_runtime)
    extra = sorted(str(path) for path in actual_runtime - set(expected_runtime))
    raise SystemExit(f"runtime manifest mismatch; missing={missing} extra={extra}")
for relative, source in expected_runtime.items():
    target = runtime / pathlib.Path(str(relative))
    if not target.is_file() or not filecmp.cmp(source, target, shallow=False):
        raise SystemExit(f"runtime file differs from packaged source: {relative}")

for source_root, target_root, label in (
    (module / "api" / "sipnotify", pathlib.Path("/var/www/html/api/sipnotify"), "desktop API"),
    (module / "api" / "sls-mass-notify", pathlib.Path("/var/www/html/api/sls-mass-notify"), "control API"),
    (module / "portal", pathlib.Path("/var/www/html/mass-notify"), "operator portal"),
    (module / "assets", pathlib.Path("/var/www/html/sls_mass_notify/assets"), "public assets"),
):
    expected = {
        pathlib.PurePosixPath(path.relative_to(source_root).as_posix()): path
        for path in source_root.rglob("*")
        if path.is_file()
    }
    actual = {
        pathlib.PurePosixPath(path.relative_to(target_root).as_posix())
        for path in target_root.rglob("*")
        if path.is_file()
    }
    if actual != set(expected):
        raise SystemExit(f"{label} manifest differs from packaged source")
    for relative, source in expected.items():
        target = target_root / pathlib.Path(str(relative))
        if not target.is_file() or not filecmp.cmp(source, target, shallow=False):
            raise SystemExit(f"{label} file differs from packaged source: {relative}")

signer_source = module / "bin" / "sign_sls_mass_notify_local_sig.sh"
signer_target = pathlib.Path("/usr/local/sbin/sign_sls_mass_notify_local_sig.sh")
if not signer_target.is_file() or not filecmp.cmp(signer_source, signer_target, shallow=False):
    raise SystemExit("local signer differs from packaged source")
console_source = module / "bin" / "slsconsole"
console_target = pathlib.Path("/usr/local/bin/slsconsole")
console_info = console_target.lstat()
if not stat.S_ISREG(console_info.st_mode) or console_info.st_uid != 0 or console_info.st_nlink != 1 or stat.S_IMODE(console_info.st_mode) != 0o755 or not filecmp.cmp(console_source, console_target, shallow=False):
    raise SystemExit("SLL console differs from its protected packaged source")
PY
}

verify_desktop_transport() {
  capture_local_web_probe_authority || return 1
  local desktop_status=0
  sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 60 /usr/bin/php -r '
$path = "/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config";
require_once "/usr/local/bin/sls_mass_notify/sls_config_crypto.php";
$settings = \FreePBX\modules\SlsConfigCrypto::decode((string)file_get_contents($path));
if (!is_array($settings) || !function_exists("openssl_decrypt")) {
    exit(1);
}
$selected = null;
foreach ((array)($settings["desktop_clients"] ?? []) as $client) {
    if (is_array($client) && !empty($client["enabled"])) {
        $selected = $client;
        break;
    }
}
if (!is_array($selected)) {
    exit(3);
}
$key = base64_decode((string)($settings["desktop_auth_key"] ?? ""), true);
if (!is_string($key) || strlen($key) !== 32) {
    exit(1);
}
$encoded = (string)($selected["password_enc"] ?? "");
$raw = strpos($encoded, "v1:") === 0 ? base64_decode(substr($encoded, 3), true) : false;
if (!is_string($raw) || strlen($raw) < 29) {
    exit(1);
}
$password = openssl_decrypt(
    substr($raw, 28),
    "aes-256-gcm",
    $key,
    OPENSSL_RAW_DATA,
    substr($raw, 0, 12),
    substr($raw, 12, 16)
);
$username = (string)($selected["username"] ?? "");
if (!is_string($password) || $password === "" || $username === "") {
    exit(1);
}
require_once "/var/www/html/admin/modules/slsmassnotifyserver/LocalWebProbe.php";
require_once "/var/www/html/admin/modules/slsmassnotifyserver/api/sls-mass-notify/security.php";
$authorization = "Authorization: Basic " . base64_encode($username . ":" . $password);
$pollingAdvertised = false;
foreach (\FreePBX\modules\SlsLocalWebProbe::responses(
    (string)($settings["public_pbx_host"] ?? ""),
    "/api/sipnotify/desktop/stream?stream_seconds=1",
    [$authorization, "Accept: text/event-stream"],
    8
) as $response) {
    $headers = implode("\n", (array)$response["headers"]);
    $body = (string)$response["body"];
    if ((int)$response["status"] === 200
        && stripos($headers, "Content-Type: text/event-stream") !== false
        && strpos($body, "event: authenticated") !== false
        && strpos($body, "\"transport\":\"live_sse\"") !== false) {
        exit(0);
    }
    if ((int)$response["status"] !== 429 || stripos($headers, "Content-Type: application/json") === false) {
        continue;
    }
    try { $reply = \SLS\MassNotify\ApiSecurity::jsonObject($body, false, 16); }
    catch (\Throwable $error) { continue; }
    $fallback = $reply["fallback"] ?? null;
    if (($reply["ok"] ?? null) === false && ($reply["error"] ?? null) === "stream_capacity_reached"
        && is_array($fallback) && ($fallback["transport"] ?? null) === "json_poll"
        && ($fallback["path"] ?? null) === "/api/sipnotify/desktop"
        && ($fallback["cursor_parameter"] ?? null) === "last_event_id"
        && ($fallback["poll_interval_seconds"] ?? null) === 5) {
        $pollingAdvertised = true;
        break;
    }
}
if (!$pollingAdvertised) { exit(1); }
// The empty cursor establishes a live baseline without fetching old alerts.
// Never send credentials to a response-supplied URL.
foreach (\FreePBX\modules\SlsLocalWebProbe::responses(
    (string)($settings["public_pbx_host"] ?? ""),
    "/api/sipnotify/desktop?last_event_id=&limit=1",
    [$authorization, "Accept: application/json"],
    8
) as $response) {
    $headers = implode("\n", (array)$response["headers"]);
    if ((int)$response["status"] !== 200 || stripos($headers, "Content-Type: application/json") === false
        || !preg_match("/^Cache-Control:[^\\r\\n]*\\bno-store\\b/im", $headers)) { continue; }
    try { $reply = \SLS\MassNotify\ApiSecurity::jsonObject((string)$response["body"], false, 16); }
    catch (\Throwable $error) { continue; }
    $identity = is_array($reply["client"] ?? null) ? ($reply["client"]["client_id"] ?? null) : null;
    $cursor = $reply["last_event_id"] ?? null;
    if (($reply["ok"] ?? null) === true && ($reply["transport"] ?? null) === "json_poll"
        && ($reply["cursor_parameter"] ?? null) === "last_event_id"
        && ($reply["poll_interval_seconds"] ?? null) === 5
        && is_string($identity) && $identity !== "" && $identity === ($selected["client_id"] ?? null)
        && ($reply["events"] ?? null) === [] && ($reply["count"] ?? null) === 0
        && ($reply["has_more"] ?? null) === false && ($reply["limit"] ?? null) === 1
        && is_string($cursor) && strlen($cursor) <= 2048 && preg_match("/^[^\\x00-\\x20\\x7f]+$/D", $cursor)) {
        exit(4);
    }
}
exit(1);
' >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || desktop_status=$?
  if [ "$desktop_status" -eq 0 ]; then
    log "Desktop live SSE authentication handshake verified."
    return 0
  fi
  if [ "$desktop_status" -eq 3 ]; then
    log "Desktop transport handshake skipped because all desktop clients are disabled."
    return 0
  fi
  if [ "$desktop_status" -eq 4 ]; then
    log "Desktop JSON polling authentication and live cursor baseline verified (stream capacity policy)."
    return 0
  fi
  log "Desktop authenticated transport verification failed on the detected local Apache ports. On a custom port, the configured public PBX hostname must match that virtual host's ServerName or ServerAlias. Check that binding, Authorization-header forwarding, stream/polling policy, and $LOG_FILE."
  return 1
}

verify_media_access() {
  capture_local_web_probe_authority || return 1
  if ! sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 60 /usr/bin/php -r '
require_once "/var/www/html/admin/modules/slsmassnotifyserver/LocalWebProbe.php";
require_once "/var/www/html/api/sls-mass-notify/media-policy.php";
require_once "/usr/local/bin/sls_mass_notify/sls_config_crypto.php";
$settings = \FreePBX\modules\SlsConfigCrypto::decode((string)file_get_contents("/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config", false, null, 0, 3145729));
if (!is_array($settings)) { fwrite(STDERR, "Media policy cannot read the protected configuration.\n"); exit(1); }
$result = \FreePBX\modules\SlsLocalWebProbe::mediaAccess($settings);
if (!$result["ok"]) { fwrite(STDERR, $result["message"] . "\n"); exit(1); }
' >> "${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
    log "Generated-media access enforcement could not be verified. Review the protected policy/Apache routing error in $LOG_FILE before retrying installation."
    return 1
  fi
}

verify_control_api_authentication() {
  capture_local_web_probe_authority || return 1
  local control_status=0
  sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 60 /usr/bin/php -r '
$path = "/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config";
require_once "/usr/local/bin/sls_mass_notify/sls_config_crypto.php";
$settings = \FreePBX\modules\SlsConfigCrypto::decode((string)file_get_contents($path));
$control = is_array($settings["control_api"] ?? null) ? $settings["control_api"] : [];
if (empty($control["enabled"])) {
    exit(3);
}
$key = trim((string)($control["api_key"] ?? ""));
if ($key === "") {
    exit(1);
}
require_once "/var/www/html/admin/modules/slsmassnotifyserver/LocalWebProbe.php";
$lastError = "";
foreach (\FreePBX\modules\SlsLocalWebProbe::responses(
    (string)($settings["public_pbx_host"] ?? ""),
    "/api/sls-mass-notify/?resource=status",
    ["Authorization: Bearer " . $key, "Accept: application/json"],
    8
) as $response) {
    $decoded = json_decode((string)$response["body"], true);
    if ((int)$response["status"] === 200 && is_array($decoded)
        && !empty($decoded["ok"]) && ($decoded["resource"] ?? "") === "status") {
        exit(0);
    }
    if (is_array($decoded) && ($decoded["error"] ?? "") === "ip_not_allowed") {
        exit(4);
    }
    if (is_array($decoded) && ($decoded["error"] ?? "") === "rate_limited") {
        exit(5);
    }
    if (is_array($decoded)) {
        $lastError = (string)($decoded["error"] ?? "");
    }
}
exit($lastError === "unauthorized" ? 2 : 1);
' >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || control_status=$?
  case "$control_status" in
    0)
      log "Control API authenticated status request verified."
      ;;
    3)
      log "Control API authenticated request skipped because the API is disabled."
      ;;
    4)
      log "Control API authenticated request skipped because the configured allowlist excludes loopback."
      ;;
    5)
      log "Control API authenticated request skipped because the configured rate limit is already exhausted."
      ;;
    *)
      log "Control API authentication or Authorization-header forwarding failed. See $LOG_FILE."
      return 1
      ;;
  esac
}

verify_fresh_install_defaults() {
  [ -z "$CONFIG_HASH_BEFORE" ] || [ "$FRESH_CONFIG_INITIALIZED" -eq 1 ] || return 0
  CONFIG_PATH="$CONFIG_FILE" SLS_INIT_PHONE_CAPACITY="$FRESH_PHONE_CAPACITY" SLS_INIT_DEPLOYMENT_PROFILE="$FRESH_DEPLOYMENT_PROFILE" php -r '
require_once "/usr/local/bin/sls_mass_notify/sls_config_crypto.php";
$settings = \FreePBX\modules\SlsConfigCrypto::decode((string)file_get_contents(getenv("CONFIG_PATH")));
if (!is_array($settings)) {
    exit(1);
}
$setup = is_array($settings["setup"] ?? null) ? $settings["setup"] : [];
$lightning = is_array($settings["xweather"] ?? null) ? $settings["xweather"] : [];
$control = is_array($settings["control_api"] ?? null) ? $settings["control_api"] : [];
$ami = is_array($settings["ami"] ?? null) ? $settings["ami"] : [];
$checks = [
    (int)($settings["phone_device_limit"] ?? 0) === (int)getenv("SLS_INIT_PHONE_CAPACITY"),
    (int)($settings["desktop_client_limit"] ?? 0) === 25,
    (string)($settings["deployment_profile"] ?? "") === (string)getenv("SLS_INIT_DEPLOYMENT_PROFILE"),
    (int)($settings["speech_synthesis_limit"] ?? 0) === 1,
    (string)getenv("SLS_INIT_DEPLOYMENT_PROFILE") !== "lite" || (int)($settings["speech_queue_limit"] ?? 0) <= 2,
    (string)($settings["enabled"] ?? "") === "0",
    (string)($setup["completed"] ?? "") === "0",
    (string)($setup["beta_accepted"] ?? "") === "0",
    (string)($lightning["enabled"] ?? "") === "0",
    (int)($lightning["query_interval_minutes"] ?? 0) === 4,
    (string)($lightning["adaptive_free_tier"] ?? "") === "1",
    (int)($lightning["adaptive_grace_minutes"] ?? 0) === 60,
    (string)($lightning["quiet_hours_enabled"] ?? "") === "0",
    (int)($lightning["tts_volume"] ?? 0) === 25,
    (int)($settings["nws_tts_volume"] ?? 0) === 25,
    (int)($settings["announcement_tts_volume"] ?? 0) === 25,
    (string)($settings["announcement_timeout_mode"] ?? "") === "none",
    (int)($settings["announcement_timeout_seconds"] ?? 0) === 300,
    is_array($settings["scheduled_announcements"] ?? null) && count($settings["scheduled_announcements"]) === 0,
    basename((string)($settings["nws_piper_voice"] ?? "")) === "en_US-amy-low.onnx",
    basename((string)($settings["announcement_piper_voice"] ?? "")) === "en_US-lessac-low.onnx",
    (string)($settings["opening_tone"] ?? "") === "opening_Paging_Tone_Opening",
    (string)($settings["closing_tone"] ?? "") === "closing_Paging_Tone_Closing",
    (string)($settings["nws_opening_tone"] ?? "") === "opening_NWS_alert",
    (string)($settings["nws_closing_tone"] ?? "invalid") === "",
    (string)($lightning["opening_tone"] ?? "") === "opening_Lightning_alert",
    (string)($lightning["closing_tone"] ?? "invalid") === "",
    (string)($control["enabled"] ?? "") === "0",
    preg_match("/^[A-Za-z0-9_-]{24,128}$/", (string)($control["api_key"] ?? "")) === 1,
    preg_match("/^[A-Za-z0-9_-]{24,128}$/", (string)($ami["password"] ?? "")) === 1,
];
exit(!in_array(false, $checks, true) ? 0 : 1);
' || {
    log "Fresh central configuration does not contain the required safe defaults."
    exit 1
  }
}

ensure_local_signer() {
  # The root signer is promoted only from the authenticated immutable generation.
  # Never copy executable bytes out of the web-writable installed module tree.
  protected_install_phase admit
}

sign_and_verify_touched_modules() {
  local signer="/usr/local/sbin/sign_sls_mass_notify_local_sig.sh"
  local module_name attempt signed
  local -a modules_to_sign

  ensure_local_signer || exit 1

  modules_to_sign=("$MODULE")
  [ -d /var/www/html/admin/modules/dashboard ] && modules_to_sign+=("dashboard")
  [ -d /var/www/html/admin/modules/framework ] && modules_to_sign+=("framework")

  for module_name in "${modules_to_sign[@]}"; do
    signed=0
    for attempt in 1 2; do
      if run_without_install_maintenance_lock sls_bounded_native_command 360 5 /usr/bin/timeout --signal=TERM --kill-after=5 360 "$signer" "$module_name" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
        signed=1
        break
      fi
      log "Local signing attempt $attempt of 2 failed for $module_name."
      [ "$attempt" -eq 2 ] || sleep 2
    done
    [ "$signed" -eq 1 ] || {
      log "Unable to locally sign $module_name. See $LOG_FILE."
      tail -100 "$LOG_FILE" 2>/dev/null || true
      exit 1
    }

    SLS_MASS_NOTIFY_MODULE="$module_name" php -r '
require "/etc/freepbx.conf";
$module = getenv("SLS_MASS_NOTIFY_MODULE");
$gpg = \FreePBX::GPG();
$gpg->timeout = 30;
$result = $gpg->verifyModule($module);
echo json_encode($result, JSON_PRETTY_PRINT), "\n";
$valid = is_array($result)
    && array_key_exists("status", $result)
    && is_int($result["status"])
    && $result["status"] === 129
    && array_key_exists("details", $result)
    && is_array($result["details"])
    && count($result["details"]) === 0;
if (!$valid) {
    exit(1);
}
exit(0);
' >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
      log "FreePBX signature verification did not return trusted/good for $module_name. See $LOG_FILE."
      tail -60 "$LOG_FILE" 2>/dev/null || true
      exit 1
    }
  done
}

retire_legacy_framework_menu() {
  local hashes before after
  hashes="$(/usr/bin/python3 -I - "$UPGRADE_TRUST_DIR" <<'PYMENU'
from pathlib import Path
import json, re, sys
review = Path(sys.argv[1])
name = 'amp_conf/htdocs/admin/views/menu_items.php'
previous = json.loads((review / 'previous-web-approval.json').read_bytes())['framework']
candidate = json.loads((review / 'framework.json').read_bytes())
values = []
for manifest in (previous, candidate):
    if manifest['module'] != 'framework':
        raise SystemExit('Framework menu migration needs the protected Framework approvals.')
    entry = manifest['files'].get(name)
    if entry is None:
        values.append('absent')
    elif entry['target'] == 'admin/views/menu_items.php' and re.fullmatch('[a-f0-9]{64}', entry['sha256']):
        values.append(entry['sha256'])
    else:
        raise SystemExit('The approved Framework menu identity is invalid.')
if 'absent' in values and values[0] != values[1]:
    raise SystemExit('The Framework menu was added or removed during the installation review.')
print(*values)
PYMENU
)" || return 1
  read -r before after <<< "$hashes" || return 1
  [ "$before" != "$after" ] || return 0
  php -r 'require "/etc/freepbx.conf"; \FreePBX::Create()->Slsmassnotifyserver->retireLegacyFrameworkMenu($argv[1], $argv[2]);' "$before" "$after"
}

verify_install_cron() {
  [ -n "$RECOVERY_TOOL" ] && [ -f "$RECOVERY_TOOL" ] && [ ! -L "$RECOVERY_TOOL" ] || {
    log "The authenticated cron inspection helper is unavailable."
    return 1
  }
  # Both fixed account tables are read strictly under native FreePBX cron
  # coordination. The helper never prints administrator cron contents.
  /usr/bin/python3 -I "$RECOVERY_TOOL" --cron-action verify-installed >/dev/null
}

verify_install() {
  protected_install_phase verify
  secure_central_config
  verify_installed_payload_parity
  verify_fresh_install_defaults
  sign_and_verify_touched_modules
  verify_dashboard_integration
  php -r 'require "/etc/freepbx.conf"; \FreePBX::Create()->Slsmassnotifyserver->verifyFrameworkMenuRegistration();' || {
    log "FreePBX could not verify the native Mass Notify menu registration."
    exit 1
  }
  module_list="$(fwconsole ma list)"
  printf '%s\n' "$module_list" | grep -Ei 'slsmassnotifyserver|dashboard|framework|Module'
  module_enabled "$MODULE" || {
    log "The SLL Mass Notify Server module is not enabled after installation."
    exit 1
  }
  for required_module in framework dashboard backup recordings; do
    module_enabled "$required_module" || {
        log "Required FreePBX module is not enabled after installation: $required_module"
        exit 1
      }
  done
  if ! php -r '
require "/etc/freepbx.conf";
$freepbx = \FreePBX::Create();
if (!$freepbx->Modules->checkStatus("backup")) {
    fwrite(STDERR, "FreePBX Backup is not enabled.\n");
    exit(1);
}
$available = $freepbx->Backup->getModules();
if (!is_array($available) || !isset($available["slsmassnotifyserver"])) {
    fwrite(STDERR, "FreePBX did not discover the Mass Notify native backup adapter.\n");
    exit(2);
}
$enrollment = $freepbx->Slsmassnotifyserver->ensureFreePbxBackupEnrollment();
$health = $freepbx->Slsmassnotifyserver->getFreePbxBackupHealth();
$jobs = (int)($enrollment["jobs"] ?? 0);
$enrolled = (int)($enrollment["enrolled"] ?? 0);
if (empty($enrollment["success"]) || $jobs !== $enrolled || ($health["state"] ?? "") !== "ok") {
    fwrite(STDERR, "Mass Notify backup enrollment verification failed.\n");
    exit(3);
}
if ($jobs === 0) {
    echo "Native FreePBX backup adapter verified; this PBX has no administrator-defined module backup jobs yet.\n";
} else {
    echo "Native FreePBX backup adapter verified and enrolled in {$enrolled} module backup job(s).\n";
}
exit(0);
' >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
    log "Native FreePBX backup integration verification failed. See $LOG_FILE."
    exit 1
  fi
  ensure_required_asterisk_capabilities || {
    log "Required Asterisk paging capabilities disappeared after FreePBX reload."
    exit 1
  }
  verify_asterisk_module_startup_persistence || {
    log "Required Asterisk modules are not configured to survive an Asterisk restart."
    exit 1
  }
  audio_dialplan="$(asterisk -rx "dialplan show 1000@sls-alert-audio" 2>&1)"
  printf '%s\n' "$audio_dialplan"
  if ! printf '%s\n' "$audio_dialplan" | /usr/bin/python3 -I -c 'import sys; text=sys.stdin.read(); prefix="Page(${SLS_DIAL},b(sls-alert-autoanswer^s^1(${EXTEN}))A(${SLS_SAFE_SOUND})inq,"; sys.exit(0 if any(prefix+str(seconds)+")" in text for seconds in range(1,6)) else 1)'; then
    log "The SLL audio paging context is missing its multi-contact Page/ConfBridge auto-answer and audio handler."
    exit 1
  fi
  if grep -Fq 'Dial(${SLS_DIAL}' <<<"$audio_dialplan"; then
    log "The SLL audio paging context still uses first-answer Dial semantics instead of multi-contact Page semantics."
    exit 1
  fi
  if ! grep -Fq 'AGI(/usr/local/bin/sls_mass_notify/sls_mass_notify_phone_agi.py,origin)' <<<"$audio_dialplan" \
    || grep -Fq 'Set(SLS_DIAL=${PJSIP_DIAL_CONTACTS' <<<"$audio_dialplan"; then
    log "The SLL audio context lacks frozen-contact admission or still resolves new contacts after admission."
    exit 1
  fi
  if grep -Eq 'macro-autoanswer|b\(autoanswer\^' <<<"$audio_dialplan"; then
    log "The SLL audio paging context still depends on a FreePBX internal auto-answer context."
    exit 1
  fi
  autoanswer_dialplan="$(asterisk -rx "dialplan show s@sls-alert-autoanswer" 2>&1)"
  outbound_playback_dialplan="$(asterisk -rx "dialplan show s@sls-outbound-playback" 2>&1)"
  if ! grep -Fq 'AGI(/usr/local/bin/sls_mass_notify/sls_mass_notify_phone_agi.py,playback)' <<<"$outbound_playback_dialplan" \
    || ! grep -Fq 'GotoIf($["${SLS_PHONE_ALLOW}"!="1"]?done)' <<<"$outbound_playback_dialplan" \
    || ! grep -Fq 'Playback(${SLS_SAFE_SOUND})' <<<"$outbound_playback_dialplan" \
    || ! grep -Fq 'Read(SLS_ACK,${SLS_ACK_PROMPT},1,,1,${SLS_ACK_TIMEOUT})' <<<"$outbound_playback_dialplan" \
    || ! grep -Fq 'AGI(/usr/local/bin/sls_mass_notify/sls_mass_notify_phone_agi.py,ack)' <<<"$outbound_playback_dialplan"; then
    log "External voice playback lacks its per-recipient answer or keypad-result handling. No external test call was made."
    exit 1
  fi
  grep -Fq 'AGI(/usr/local/bin/sls_mass_notify/sls_mass_notify_phone_agi.py,contact)' <<<"$autoanswer_dialplan" || {
    log "The SLL auto-answer context lacks its exact-contact admission guard."
    exit 1
  }
  grep -Fq 'PJSIP_HEADER(add,Alert-Info)' <<<"$autoanswer_dialplan" || {
    log "The SLL PJSIP auto-answer header context is missing."
    exit 1
  }
  grep -Fq 'PJSIP_HEADER(add,Call-Info)' <<<"$autoanswer_dialplan" || {
    log "The SLL PJSIP Call-Info auto-answer header is missing."
    exit 1
  }
  grep -Fq 'Set(SLS_AUTOANSWER_CONTACT=${CHANNEL(contact)})' <<<"$autoanswer_dialplan" || {
    log "The SLL PJSIP auto-answer context is missing per-contact user-agent discovery."
    exit 1
  }
  grep -Fq 'PJSIP_AOR(${SLS_AUTOANSWER_AOR},contact)' <<<"$autoanswer_dialplan" || {
    log "The SLL PJSIP auto-answer context is missing its extension/AOR contact fallback."
    exit 1
  }
  grep -Fq '${SLS_AUTOANSWER_UA:0:7}"="yealink"]?Set(SLS_ALERT_INFO=Intercom)' <<<"$autoanswer_dialplan" || {
    log "The SLL PJSIP auto-answer context is missing the Yealink Intercom Alert-Info policy."
    exit 1
  }
  command -v runuser >/dev/null 2>&1 || {
    log "runuser is required to verify Asterisk call-file spool access."
    exit 1
  }
  for spool_dir in /var/spool/asterisk/tmp /var/spool/asterisk/outgoing /var/spool/asterisk/outgoing_done; do
    [ -d "$spool_dir" ] || {
      log "Required Asterisk call-file spool directory is missing: $spool_dir"
      exit 1
    }
    if ! sls_as_asterisk test -w "$spool_dir" \
      || ! sls_as_asterisk test -x "$spool_dir"; then
      log "The asterisk service account cannot search and write to $spool_dir."
      exit 1
    fi
  done
  if [ "$(stat -c '%d' /var/spool/asterisk/tmp)" != "$(stat -c '%d' /var/spool/asterisk/outgoing)" ] \
    || [ "$(stat -c '%d' /var/spool/asterisk/outgoing)" != "$(stat -c '%d' /var/spool/asterisk/outgoing_done)" ]; then
    log "Asterisk's temporary, outgoing, and test-result call-file directories are on different filesystems."
    exit 1
  fi
  expected_sound_target="$DATA_DIR/sounds"
  for sound_link in \
    /var/lib/asterisk/sounds/SLS_Mass_Notifications_Plugin \
    /var/lib/asterisk/sounds/en/SLS_Mass_Notifications_Plugin; do
    if [ ! -L "$sound_link" ] || [ "$(readlink -f "$sound_link" 2>/dev/null || true)" != "$expected_sound_target" ]; then
      log "$sound_link does not resolve to the protected SLL sound directory."
      exit 1
    fi
  done
  for sound_file in \
    "$DATA_DIR/sounds/tones/opening_Paging_Tone_Opening.wav" \
    "$DATA_DIR/sounds/tones/closing_Paging_Tone_Closing.wav" \
    "$DATA_DIR/sounds/tones/opening_NWS_alert.wav" \
    "$DATA_DIR/sounds/tones/opening_Lightning_alert.wav"; do
    [ -r "$sound_file" ] || {
      log "Required paging sound is missing or unreadable: $sound_file"
      exit 1
    }
    sound_rate="$(soxi -r "$sound_file" 2>/dev/null || true)"
    sound_channels="$(soxi -c "$sound_file" 2>/dev/null || true)"
    sound_bits="$(soxi -b "$sound_file" 2>/dev/null || true)"
    if [ "$sound_rate" != "8000" ] || [ "$sound_channels" != "1" ] || [ "$sound_bits" != "16" ]; then
      log "Paging sound must be 8 kHz, mono, 16-bit PCM: $sound_file"
      exit 1
    fi
  done
  for writable_dir in "$DATA_DIR/sounds/tts" "$DATA_DIR/sounds/tones" /var/www/html/sls_mass_notify; do
    if ! sls_as_asterisk test -w "$writable_dir" \
      || ! sls_as_asterisk test -x "$writable_dir"; then
      log "The asterisk service account cannot search and write to $writable_dir."
      exit 1
    fi
  done
  for recording_file in \
    /var/lib/asterisk/sounds/en/custom/SLS_Mass_Notify_Paging_Tone_Opening.wav \
    /var/lib/asterisk/sounds/en/custom/SLS_Mass_Notify_Paging_Tone_Closing.wav \
    /var/lib/asterisk/sounds/en/custom/SLS_Mass_Notify_NWS_Alert.wav \
    /var/lib/asterisk/sounds/en/custom/SLS_Mass_Notify_Lightning_Alert.wav; do
    [ -r "$recording_file" ] || {
      log "Bundled System Recording is missing: $recording_file"
      exit 1
    }
    [ "$(soxi -r "$recording_file" 2>/dev/null || true)" = "8000" ] \
      && [ "$(soxi -c "$recording_file" 2>/dev/null || true)" = "1" ] \
      && [ "$(soxi -b "$recording_file" 2>/dev/null || true)" = "16" ] || {
        log "Bundled System Recording has an invalid Asterisk WAV format: $recording_file"
        exit 1
      }
  done
  php -r '
require "/etc/freepbx.conf";
$required = [
    "custom/SLS_Mass_Notify_Paging_Tone_Opening",
    "custom/SLS_Mass_Notify_Paging_Tone_Closing",
    "custom/SLS_Mass_Notify_NWS_Alert",
    "custom/SLS_Mass_Notify_Lightning_Alert",
];
$stmt = \FreePBX::Database()->prepare("SELECT COUNT(*) FROM recordings WHERE filename = ?");
foreach ($required as $filename) {
    $stmt->execute([$filename]);
    if ((int)$stmt->fetchColumn() < 1) {
        fwrite(STDERR, "Missing System Recordings entry: " . $filename . "\n");
        exit(1);
    }
}
exit(0);
' >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
    log "Bundled sounds were not registered with FreePBX System Recordings. See $LOG_FILE."
    exit 1
  }
  asterisk_file_formats="$(asterisk -rx "core show file formats" 2>&1)"
  grep -Eq '(^|[[:space:]])wav([[:space:]]|$)' <<<"$asterisk_file_formats" || {
    log "Asterisk WAV file-format support is unavailable."
    exit 1
  }
  [ -f /etc/apache2/conf-available/sls-mass-notify.conf ] \
    && [ -e /etc/apache2/conf-enabled/sls-mass-notify.conf ] \
    && grep -Fq '<Directory /var/www/html/api/sipnotify>' /etc/apache2/conf-available/sls-mass-notify.conf \
    && grep -Fq '<Directory /var/www/html/api/sls-mass-notify>' /etc/apache2/conf-available/sls-mass-notify.conf \
    && grep -Fq '<Directory /var/www/html/sls_mass_notify>' /etc/apache2/conf-available/sls-mass-notify.conf || {
      log "The SLL Apache integration is missing or is not enabled."
      exit 1
    }
  verify_asterisk_notify_readiness || exit 1
  grep -q "SLS Mass Notifications SIP NOTIFY Templates" /etc/asterisk/sip_notify_custom.conf || {
    log "Managed SIP NOTIFY templates were not installed in /etc/asterisk/sip_notify_custom.conf."
    exit 1
  }
  if [ ! -x /usr/local/bin/piper ]; then
    log "Piper wrapper was not created at /usr/local/bin/piper."
    exit 1
  fi
  sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 20 /usr/bin/env ORT_DISABLE_TELEMETRY=1 /usr/local/bin/piper -h >/dev/null
  if [ -x /usr/local/bin/sls_mass_notify/piper/venv/bin/piper ]; then
    sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 20 /usr/bin/env ORT_DISABLE_TELEMETRY=1 /usr/local/bin/sls_mass_notify/piper/venv/bin/piper -h >/dev/null
  elif [ -x /usr/local/bin/sls_mass_notify/piper/venv/bin/python ]; then
    sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 20 /usr/bin/env ORT_DISABLE_TELEMETRY=1 /usr/local/bin/sls_mass_notify/piper/venv/bin/python -I -m piper -h >/dev/null
  else
    log "Piper venv runtime is missing or not executable."
    exit 1
  fi
  [ -x "$DATA_DIR/piper/venv/bin/piper" ] || {
    log "Piper compatibility executable is missing at $DATA_DIR/piper/venv/bin/piper."
    exit 1
  }
  runtime_python_files=(
    /usr/local/bin/sls_mass_notify/sls_notify.py
    /usr/local/bin/sls_mass_notify/sls_live_paging_visual.py
    /usr/local/bin/sls_mass_notify/sls_config.py
    /usr/local/bin/sls_mass_notify/sls_config_crypto.py
    /usr/local/bin/sls_mass_notify/sls_console.py
    /usr/local/bin/sls_mass_notify/sls_cluster_guard.py
    /usr/local/bin/sls_mass_notify/sls_branded_email.py
    /usr/local/bin/sls_mass_notify/sls_announcement_email.py
    /usr/local/bin/sls_mass_notify/sls_branded_discord.py
    /usr/local/bin/sls_mass_notify/sls_notification_destinations.py
    /usr/local/bin/sls_mass_notify/sls_system_notifications.py
    /usr/local/bin/sls_mass_notify/sls_nws_status.py
    /usr/local/bin/sls_mass_notify/sls_nws_delivery_claims.py
    /usr/local/bin/sls_mass_notify/sls_mass_notify_xweather_poll.py
    /usr/local/bin/sls_mass_notify/sls_weather_queue.py
    /usr/local/bin/sls_mass_notify/sls_audio_queue.py
    /usr/local/bin/sls_mass_notify/sls_audio_state.py
    /usr/local/bin/sls_mass_notify/sls_storage_maintenance.py
    /usr/local/bin/sls_mass_notify/sls_audit_separation.py
    /usr/local/bin/sls_mass_notify/sls_operational_backup.py
    /usr/local/bin/sls_mass_notify/sls_external_monitor.py
    /usr/local/bin/sls_mass_notify/sls_piper_dependencies.py
    /usr/local/bin/sls_mass_notify/sls_piper_environment.py
    /usr/local/bin/sls_mass_notify/sls_update_policy.py
    /usr/local/bin/sls_mass_notify/sls_module_trust.py
    /usr/local/bin/sls_mass_notify/sls_privileged_install.py
    /usr/local/bin/sls_mass_notify/sls_installer_recovery.py
    /usr/local/bin/sls_mass_notify/sls_upgrade_trust.py
    /usr/local/bin/sls_mass_notify/sls_install_idle.py
    /usr/local/bin/sls_mass_notify/sls_install_guard.py
    /usr/local/bin/sls_mass_notify/sls_legacy_permissions.py
    /usr/local/bin/sls_mass_notify/sls_mail_admission.py
    /usr/local/bin/sls_mass_notify/sls_cron_runner.py
    /usr/local/bin/sls_mass_notify/sls_resource_capacity.py
    /usr/local/bin/sls_mass_notify/sls_bounded_stream.py
    /usr/local/bin/sls_mass_notify/sls_phone_admission.py
    /usr/local/bin/sls_mass_notify/sls_voicemail.py
    /usr/local/bin/sls_mass_notify/sls_phone_events.py
    /usr/local/bin/sls_mass_notify/sls_emergency_observer.py
    /usr/local/bin/sls_mass_notify/sls_trigger_actions.py
    /usr/local/bin/sls_mass_notify/sls_weather_channels.py
    /usr/local/bin/sls_mass_notify/sls_lightning_providers.py
    /usr/local/bin/sls_mass_notify/sls_phone_outcomes.py
    /usr/local/bin/sls_mass_notify/sls_outbound_routes.py
    /usr/local/bin/sls_mass_notify/sls_mass_notify_phone_agi.py
    /usr/local/bin/sls_mass_notify/sls_release_verify.py
    /usr/local/bin/sls_mass_notify/sls_release_trust.py
    /usr/local/bin/sls_mass_notify/sls_install_doctor.py
    /usr/local/bin/sls_mass_notify/sls_web_readiness.py
    /usr/local/bin/sls_mass_notify/sls_update_status.py
    /usr/local/bin/sls_mass_notify/sls_atomic_json.py
    /usr/local/bin/sls_mass_notify/sls_install_transaction.py
    /usr/local/bin/sls_mass_notify/sls_phone_inventory.py
    /usr/local/bin/sls_mass_notify/sls_speech_admission.py
    /usr/local/bin/sls_mass_notify/sls_render_paging_prompt.py
    /usr/local/bin/sls_mass_notify/sls_desktop_history.py
    /usr/local/bin/sls_mass_notify/sls_desktop_feed_cache.py
    /usr/local/bin/sls_mass_notify/sls_mail_evidence.py
    /usr/local/bin/sls_mass_notify/sls_nws_http.py
    /usr/local/bin/sls_mass_notify/sls_php_security.py
    /usr/local/bin/sls_mass_notify/sls_piper_worker.py
    /usr/local/bin/sls_mass_notify/sls_support_snapshot.py
    /usr/local/bin/sls_mass_notify/sls_weather_payload.py
  )
  for runtime_python in "${runtime_python_files[@]}"; do
    [ -x "$runtime_python" ] || {
      log "Required Python runtime is missing or not executable: $runtime_python"
      exit 1
    }
  done
  python3 -I - "${runtime_python_files[@]}" <<'PY'
import pathlib
import sys

for value in sys.argv[1:]:
    path = pathlib.Path(value)
    compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY
  if /usr/local/bin/sls_mass_notify/sls_config.py "$CONFIG_FILE" >/dev/null; then
    :
  else
    config_status=$?
    INSTALL_ERROR_CATEGORY="protected_config_validation_failed"
    log "The protected central configuration failed validation after runtime integration."
    exit "$config_status"
  fi
  [ ! -e "$DATA_DIR/mass-notifications.conf" ] || {
    log "Obsolete executable shell configuration still exists at $DATA_DIR/mass-notifications.conf."
    exit 1
  }
  [ ! -e /usr/local/bin/sls_mass_notify/config.ini ] || {
    log "Obsolete duplicate Python configuration still exists."
    exit 1
  }
  media_probe="/var/www/html/sls_mass_notify/installer-render-check-$$.png"
  media_fetch="$(mktemp "$INSTALL_TEMP_ROOT/sls-mass-notify-render-fetch.XXXXXX")"
  rm -f "$media_probe"
  if ! sls_as_asterisk convert -size 480x272 xc:'#991b1b' -font DejaVu-Sans-Bold \
    -fill white -gravity center -pointsize 24 -annotate +0+0 'SLL render test' \
    -colorspace sRGB -depth 8 -interlace none -strip "PNG24:$media_probe"; then
    rm -f "$media_probe" "$media_fetch"
    log "The asterisk service account could not render an alert image in the public media directory."
    exit 1
  fi
  /usr/sbin/apache2ctl configtest >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || {
    rm -f "$media_probe" "$media_fetch"
    log "Apache configuration validation failed after integration was installed. See $LOG_FILE."
    exit 1
  }
  verify_media_access || { rm -f "$media_probe" "$media_fetch"; exit 1; }
  media_code="$(local_web_probe "/sls_mass_notify/$(basename "$media_probe")" "$media_fetch" '^(200|403)$' || true)"
  if [ "$media_code" = "200" ] && cmp -s "$media_probe" "$media_fetch"; then
    :
  elif [ "$media_code" = "403" ] && /usr/bin/python3 -I - "$media_fetch" /usr/local/bin/sls_mass_notify/sls_config_crypto.py <<'PY'
import json
from pathlib import Path
import sys
body = Path(sys.argv[1]).read_bytes()
if len(body) > 1024:
    raise SystemExit(1)
import types
sys.dont_write_bytecode = True
path = Path(sys.argv[2])
module = types.ModuleType('sls_config_crypto'); module.__file__ = str(path)
exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
config = module.read_config('/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config')
raise SystemExit(0 if config.get('media_access', {}).get('network_restricted') is True
                 and json.loads(body).get('error') == 'media_network_denied' else 1)
PY
  then
    log 'Generated-media policy correctly blocks this local probe. Image bytes are validated locally; test image retrieval from an allowed device network.'
  else
    rm -f "$media_probe" "$media_fetch"
    log "Public phone-image delivery check failed with HTTP $media_code."
    exit 1
  fi
  media_identity="$(identify -format '%w %h %[bit-depth] %[colorspace] %[interlace]' "$media_probe" 2>/dev/null || true)"
  rm -f "$media_probe" "$media_fetch"
  case "$media_identity" in
    "480 272 8 sRGB None"|"480 272 8 RGB None") ;;
    *)
      log "Rendered phone image does not meet the 480x272, 8-bit, non-interlaced requirement: $media_identity"
      exit 1
      ;;
  esac
  log "Verifying Asterisk PJSIP contact inventory and SLL AMI authentication."
  verify_pjsip_contact_inventory || exit 1
  if ! verify_ami_with_repair; then
    exit 1
  fi
  verify_phone_collector || exit 1
  notify_capabilities="$(mktemp "$INSTALL_TEMP_ROOT/sls-mass-notify-notify-capabilities.XXXXXX")"
  if ! sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 15 /usr/bin/python3 /usr/local/bin/sls_mass_notify/sls_notify.py --notify-capabilities-json >"$notify_capabilities"; then
    rm -f "$notify_capabilities"
    log "SLL could not inspect Asterisk SIP NOTIFY routing capabilities."
    exit 1
  fi
  notify_routing_mode="$(python3 -I - "$notify_capabilities" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    capabilities = json.load(handle)
if not isinstance(capabilities, dict) or capabilities.get("endpoint_target") is not True:
    raise SystemExit("Asterisk does not expose portable endpoint-targeted PJSIPNotify")
mode = capabilities.get("routing_mode")
if mode not in {"endpoint_fanout", "contact_uri"}:
    raise SystemExit("Asterisk returned an invalid SIP NOTIFY routing mode")
print(mode)
PY
)" || {
    cat "$notify_capabilities" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>/dev/null || true
    rm -f "$notify_capabilities"
    log "Asterisk does not expose the required endpoint-targeted PJSIPNotify capability."
    exit 1
  }
  if [ "$notify_routing_mode" = "contact_uri" ]; then
    log "SIP NOTIFY routing verified: endpoint fan-out is primary; contact URI routing is available for mixed-format registrations."
  else
    log "SIP NOTIFY routing verified: portable endpoint fan-out will be used because no usable default outbound endpoint is configured."
  fi
  rm -f "$notify_capabilities"
  # Always exercise the same AMI discovery path used by the Dashboard. Do not
  # infer whether it should run from the presentation-dependent summary line of
  # `pjsip show contacts`; community Asterisk builds format that output
  # differently, and an empty PBX is a valid installation state.
  endpoint_inventory="$(mktemp "$INSTALL_TEMP_ROOT/sls-mass-notify-endpoints.XXXXXX")"
  endpoint_inventory_err="$(mktemp "$INSTALL_TEMP_ROOT/sls-mass-notify-endpoints-error.XXXXXX")"
  if ! sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 15 /usr/bin/python3 /usr/local/bin/sls_mass_notify/sls_notify.py --list-endpoints-json \
    >"$endpoint_inventory" 2>"$endpoint_inventory_err"; then
    cat "$endpoint_inventory_err" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>/dev/null || true
    rm -f "$endpoint_inventory" "$endpoint_inventory_err"
    log "SLL AMI PJSIP contact discovery failed. Confirm the loopback manager user has system-event read permission; see $LOG_FILE."
    exit 1
  fi
  endpoint_records=""
  if ! endpoint_records="$(endpoint_inventory_records "$endpoint_inventory" 2>>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}")"; then
    cat "$endpoint_inventory" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>/dev/null || true
    rm -f "$endpoint_inventory" "$endpoint_inventory_err"
    log "SLL AMI PJSIP contact discovery returned invalid data; see $LOG_FILE."
    exit 1
  fi

  registered_endpoint_count=0
  yealink_endpoint_list=""
  while IFS=$'\t' read -r extension phone_format contact_count unknown_format mixed_format formats_csv user_agent; do
    [ -n "$extension" ] || continue
    registered_endpoint_count=$((registered_endpoint_count + 1))
    if [ "$unknown_format" = "1" ]; then
      log "Warning: registered endpoint $extension has an unknown phone format (user agent: ${user_agent:-not reported})."
      log "A safe generic SIP NOTIFY fallback will be used; add a Phone Format Override after confirming the device family."
    fi
    case ",${formats_csv}," in
      *,yealink,*|*,yealink_text,*|*,yealink_image,*)
        yealink_endpoint_list="${yealink_endpoint_list}${yealink_endpoint_list:+,}${extension}"
        ;;
    esac
    if [ "$mixed_format" = "1" ]; then
      if [ "$notify_routing_mode" = "contact_uri" ]; then
        log "Warning: extension $extension has mixed registered phone formats ($formats_csv). Each resolved contact URI will receive its matching vendor payload."
      else
        log "Warning: extension $extension has mixed registered phone formats ($formats_csv), but contact-URI routing is unavailable. Runtime delivery will use one safe generic XML payload through portable endpoint fan-out."
      fi
    fi
    if ! verify_registered_endpoint_route "$extension"; then
      rm -f "$endpoint_inventory" "$endpoint_inventory_err"
      log "Registered endpoint route validation failed before the installation was committed."
      exit 1
    fi
    log "Registered endpoint $extension discovery verified through AMI: format=$phone_format contacts=$contact_count."
  done <<<"$endpoint_records"

  if [ -n "$yealink_endpoint_list" ]; then
    log "Warning: Yealink registration(s) detected on extension(s) $yealink_endpoint_list. Auto-answer requires the phone's Intercom Allow policy; XML SIP NOTIFY display requires push_xml.sip_notify = 1 (Features > Remote Control > SIP Notify)."
    log "The installer does not modify handset provisioning, firmware, or SIP peers. Confirm these settings on each Yealink phone or in its authorized provisioning template."
  fi

  if [ "$registered_endpoint_count" -eq 0 ]; then
    log "No registered numeric PJSIP contacts are present; AMI discovery and empty-PBX handling were verified."
  else
    log "AMI discovery and PJSIP paging routes verified for $registered_endpoint_count registered endpoint(s)."
  fi
  rm -f "$endpoint_inventory" "$endpoint_inventory_err"
  php -l /var/www/html/admin/modules/slsmassnotifyserver/Slsmassnotifyserver.class.php >/dev/null
  verify_local_api_route /api/sipnotify/desktop '^(401|429)$' '401/429' 'Desktop notification API smoke test' || exit 1
  verify_local_api_route /api/sipnotify/desktop/stream '^(401|429)$' '401/429' 'Desktop live-stream API without credentials' || exit 1
  verify_control_api_authentication || exit 1
  # Use the canonical directory URL. Apache otherwise returns its expected
  # DirectorySlash 301 before the protected API front controller runs.
  verify_local_api_route /api/sls-mass-notify/ '^(401|403|405|429)$' '401/403/405/429' 'Control API route smoke test' || exit 1
  verify_local_api_route /api/sls-mass-notify/sms-callback.php '^405$' '405' 'SMS callback route without a provider submission' || exit 1
  verify_desktop_transport || exit 1
  [ "$(stat -c '%U:%G' /usr/local/bin/sls_mass_notify)" = "root:root" ] || {
    log "Executable runtime is not owned by root:root."
    exit 1
  }
  [ "$(stat -c '%U:%G' /usr/local/bin/sls_mass_notify/piper/venv/bin/piper)" = "root:root" ] || {
    log "Piper executable is not owned by root:root."
    exit 1
  }
  systemctl is-active --quiet cron || {
    log "The cron scheduler stopped during installation."
    exit 1
  }
  verify_install_cron || exit 1
  if ! sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 20 /usr/local/bin/sls_mass_notify/sls_mass_notify_schedule_worker.php --self-test >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1; then
    log "Scheduled-announcement worker failed its Asterisk-account self-test."
    exit 1
  fi
  # This tiny native-runtime fixture must be readable through its parents.
  # Protected installer scratch intentionally grants the PBX group search only;
  # the configuration reader requires directory-read permission as well as search.
  scheduler_probe="$(/usr/bin/python3 -I - <<'PYSLSWEATHERPROBE'
import os
from pathlib import Path
import pwd
import stat
import tempfile

parent_path = Path('/tmp')
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
parent = os.open(parent_path, flags)
created = None
child = None
try:
    before = os.fstat(parent)
    identity = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
    if before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o1777:
        raise ValueError('Native scheduler probe requires the root-owned sticky runtime temporary directory')
    account = pwd.getpwnam('asterisk')
    if account.pw_uid <= 0 or account.pw_gid <= 0:
        raise ValueError('Native scheduler probe requires a nonroot PBX account')
    created = Path(tempfile.mkdtemp(prefix='sls-mass-notify-scheduler-check.', dir=parent_path))
    child = os.open(created.name, flags, dir_fd=parent)
    file = os.open('disabled.config', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=child)
    try:
        with os.fdopen(os.dup(file), 'wb') as output:
            output.write(b'{"enabled":"0","xweather":{"enabled":"0"}}\n')
        os.fchown(file, account.pw_uid, account.pw_gid)
        os.fchmod(file, 0o640)
    finally:
        os.close(file)
    if identity(before) != identity(os.stat(parent_path, follow_symlinks=False)):
        raise ValueError('Native scheduler probe parent changed during creation')
    # Publish ownership only after all root writes to this private fixture end.
    os.fchown(child, account.pw_uid, account.pw_gid)
    os.fchmod(child, 0o750)
    print(created)
except BaseException:
    if child is not None:
        try:
            os.unlink('disabled.config', dir_fd=child)
        except FileNotFoundError:
            pass
    if created is not None:
        os.rmdir(created.name, dir_fd=parent)
    raise
finally:
    if child is not None:
        os.close(child)
    os.close(parent)
PYSLSWEATHERPROBE
)" || {
    log "Unable to create the private native scheduler check in the guarded runtime temporary directory."
    exit 1
  }
  if ! sls_supervised_as_asterisk /usr/bin/timeout --signal=TERM --kill-after=2 15 /usr/bin/env \
    CONFIG_FILE="$scheduler_probe/disabled.config" \
    DATA_DIR="$scheduler_probe" \
    LOG="$scheduler_probe/weather.log" \
    RUNTIME_DIR="/usr/local/bin/sls_mass_notify" \
    /usr/local/bin/sls_mass_notify/sls_mass_notify_weather_poll.sh; then
    rm -rf "$scheduler_probe"
    log "Weather scheduler wrapper failed its disabled-config execution check."
    exit 1
  fi
  rm -rf "$scheduler_probe"
  if [ ! -x /usr/sbin/sendmail ]; then
    log "Warning: /usr/sbin/sendmail is unavailable; email delivery will remain disabled until a local MTA is installed."
  elif [ ! -x /usr/sbin/postqueue ]; then
    log "Warning: SLL email requires the local Postfix postqueue command to check backlog before submission. No mail transport was changed; configure Postfix before using SLL email."
  fi
  ls -lh /var/lib/asterisk/SLS_Mass_Notifications_Plugin/piper/voices
}

run_retained_release_review() {
  local -a arguments=(--workspace "$INSTALL_BOOTSTRAP_DIR" --trust-root "$TRUST_ROOT")
  case "$REQUESTED_RETAINED_MODE" in
    review) arguments+=(--review-retained) ;;
    approve) arguments+=(--approve-retained "$REQUESTED_RETAINED_APPROVAL" \
      --operator "$REQUESTED_RETAINED_OPERATOR" --reason "$REQUESTED_RETAINED_REASON") ;;
    *) return 2 ;;
  esac
  # These exact helpers were copied from the publisher-authenticated package.
  # Review is read-only; only separate explicit approval can create its bounded
  # receipt under existing live trust. Neither action prepares an installation.
  run_logged /usr/bin/python3 -I "$INSTALL_BOOTSTRAP_DIR/sls_upgrade_trust.py" "${arguments[@]}"
}

retained_review_scratch_report() {
  # Reviewing retained publisher evidence does not deploy a runtime or convert
  # its profile. Qualify only the bounded authenticated-source scratch space;
  # installation and ordinary inspection keep their full resource admission.
  /usr/bin/python3 -I - <<'PYRETAINEDSCRATCH'
import json
import os
import stat
import sys

MIB = 1024 * 1024
REQUIRED_INODES = 5000 + 12 + 16
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
for path in ('/tmp', '/var/tmp'):
    fd = None
    try:
        fd = os.open('/', flags)
        for name in path.split('/')[1:]:
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            metadata = os.fstat(fd)
            if metadata.st_uid != 0 or (metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX):
                raise ValueError('unsafe scratch parent')
        capacity = os.fstatvfs(fd)
        allocation_unit = max(4096, capacity.f_frsize)
        # Accepted archives are at most52MiB compressed/50MiB expanded and
        # 5,000 entries. The copied helper subset is at most another50MiB.
        # Reserve8MiB for bounded metadata/logs, plus allocation rounding for
        # every archive/helper/metadata entry on this actual filesystem.
        required_bytes = (52 + 50 + 50 + 8) * MIB + REQUIRED_INODES * allocation_unit
        if (capacity.f_flag & os.ST_RDONLY or capacity.f_bavail * capacity.f_frsize < required_bytes
                or capacity.f_favail < REQUIRED_INODES):
            continue
        print(json.dumps({'purpose': 'retained_source_review', 'requirements': {'storage': {
            'temporary_directory': path, 'required_bytes': required_bytes,
            'required_inodes': REQUIRED_INODES}}}, sort_keys=True))
        break
    except (OSError, ValueError):
        continue
    finally:
        if fd is not None:
            os.close(fd)
else:
    print('Retained release review needs a safe writable /tmp or /var/tmp with bounded source scratch space '
          '(160 MiB plus filesystem allocation overhead and 5,028 available inodes). '
          'No installation was started.', file=sys.stderr)
    raise SystemExit(1)
PYRETAINEDSCRATCH
}

inspect_installation() {
  # Inspection uses only existing utilities and private evidence. It does not
  # bootstrap PHP/FreePBX, repair packages, acquire/create worker locks or enroll
  # trust pointers. All active and pending settings remain untouched.
  # Separate explicit retained approval uses the same authenticated scratch path
  # and may write only its bounded root receipt through helper coordination.
  local utility report inspection_status
  for utility in /usr/bin/python3 /usr/bin/openssl /usr/bin/tar /usr/bin/php /usr/bin/sha256sum; do
    [ -x "$utility" ] || { printf 'Inspection needs the existing utility %s; it will not install packages.\n' "$utility" >&2; return 1; }
  done
  [ -x /usr/bin/curl ] || [ -x /usr/bin/wget ] || { printf 'Inspection needs curl or wget for signed release evidence.\n' >&2; return 1; }
  [ -f /etc/freepbx.conf ] && [ -f /var/www/html/admin/modules/framework/module.xml ] || { printf 'FreePBX is not present at the supported paths.\n' >&2; return 1; }
  if [ -n "$REQUESTED_RETAINED_MODE" ]; then
    report="$(retained_review_scratch_report)" || return 1
  else
    if [ -e "$CONFIG_FILE" ] || [ -L "$CONFIG_FILE" ]; then
      local -a capacity_arguments=(--check --mode prepare --config "$CONFIG_FILE")
    else
      local -a capacity_arguments=(--check --mode prepare --desktop-limit 25 --auto-phone-limit)
    fi
    [ -z "$REQUESTED_DEPLOYMENT_PROFILE" ] || capacity_arguments+=(--profile "$REQUESTED_DEPLOYMENT_PROFILE")
    report="$(bootstrap_resource_capacity "${capacity_arguments[@]}")" || { printf '%s\n' "$report"; return 1; }
  fi
  select_install_temp_root "$report" || return 1
  LOG_FILE="$(mktemp "$INSTALL_TEMP_ROOT/sls-mass-notify-inspection.XXXXXXXX.log")" || return 1
  chmod 0600 "$LOG_FILE" || return 1
  INSTALL_LOG_FD=""
  open_root_owned_file INSTALL_LOG_FD "$LOG_FILE" log || return 1
  INSTALL_LOG_OUTPUT="/proc/${BASHPID}/fd/$INSTALL_LOG_FD"
  printf '%s\n' "$report" >>"$INSTALL_LOG_OUTPUT"
  if [ -z "$REQUESTED_RETAINED_MODE" ]; then
    validate_installer_memory_profile "$report" || return $?
  fi
  if download_tgz && verify_tgz && stage_module_directory --source-only && prepare_installer_bootstrap; then
    if [ -n "$REQUESTED_RETAINED_MODE" ]; then
      if run_retained_release_review; then inspection_status=0; else inspection_status=$?; fi
    elif prepare_authenticated_installer; then
      inspection_status=0
    else
      inspection_status=$?
    fi
  else
    inspection_status=$?
  fi
  # The reviewed approval directory is the inspection result. Candidate
  # downloads, extracted payloads, and executable bootstrap copies are scratch
  # data; retaining them after each inspection can consume hundreds of MiB.
  [ -z "$DOWNLOAD_DIR" ] || rm -rf -- "$DOWNLOAD_DIR"
  [ -z "$STAGING_DIR" ] || rm -rf -- "$STAGING_DIR"
  [ -z "$INSTALL_BOOTSTRAP_DIR" ] || rm -rf -- "$INSTALL_BOOTSTRAP_DIR"
  cleanup_install_temp_root
  DOWNLOAD_DIR=""
  STAGING_DIR=""
  INSTALL_BOOTSTRAP_DIR=""
  if [ "$inspection_status" -ne 0 ]; then
    if [ -n "$REQUESTED_RETAINED_MODE" ]; then
      printf 'Retained release %s failed; no installation was started. Diagnostics: %s\n' "$REQUESTED_RETAINED_MODE" "$LOG_FILE" >&2
    else
      printf 'Inspection failed. Evidence and diagnostics: %s\n' "$LOG_FILE" >&2
    fi
    return "$inspection_status"
  fi
  if [ -n "$REQUESTED_RETAINED_MODE" ]; then
    printf 'Retained release %s completed. Diagnostics: %s\n' "$REQUESTED_RETAINED_MODE" "$LOG_FILE"
  else
    printf 'Inspection passed. Evidence: %s; log: %s\n' "$UPGRADE_TRUST_DIR" "$LOG_FILE"
  fi
}

main() {
  cd /tmp
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    printf 'Run this installer as root.\n' >&2
    exit 1
  fi
  if [ "${SLS_MASS_NOTIFY_INVENTORY_ONLY:-0}" = 1 ] || [ -n "$REQUESTED_RETAINED_MODE" ]; then
    inspect_installation
    return $?
  fi
  ensure_installer_log_prerequisites || exit 1
  if [ -n "$REQUESTED_RECOVERY" ]; then
    recover_interrupted_installation "$REQUESTED_RECOVERY"
    return $?
  fi
  preflight_profile_identity || exit $?
  for coordination_utility in flock timeout runuser; do
    command -v "$coordination_utility" >/dev/null || { printf 'Installation coordination requires %s before bootstrap. Install coreutils/util-linux and retry; no PBX state was changed.\n' "$coordination_utility" >&2; exit 2; }
  done
  # Coordinate before appending the shared transaction log or starting repairs.
  acquire_update_coordination || exit 1
  acquire_maintenance_coordination || exit 1
  check_interrupted_installation || exit $?
  INSTALL_LOG_FD=""
  open_root_owned_file INSTALL_LOG_FD "$LOG_FILE" log || {
    printf 'The installer log could not be opened safely: %s. Check for a symlink, hardlink, special file, or unexpected owner. No module files were changed.\n' "$LOG_FILE" >&2
    exit 1
  }
  # Use the held descriptor for every write, including after fwconsole chown.
  # LOG_FILE remains the human-readable path for diagnostics and support.
  INSTALL_LOG_OUTPUT="/proc/${BASHPID}/fd/$INSTALL_LOG_FD"
  printf '\nSLL Mass Notify Server installation started: %s\n' "$(date --iso-8601=seconds)" >>"$INSTALL_LOG_OUTPUT"
  trap guard_config_on_exit EXIT
  trap 'handle_install_signal TERM 143' TERM
  trap 'handle_install_signal INT 130' INT
  trap 'handle_install_signal HUP 129' HUP
  set_install_stage "hardware admission" "Provide the combined PBX/SLL CPU, RAM, persistent storage, and free-space requirements documented in README before retrying installation."
  preflight_hardware_requirements || exit $?
  set_install_stage "platform validation" "Confirm this is a healthy FreePBX 17 host with working database, Asterisk, fwconsole, package repositories, and local AMI access, then rerun the installer."
  require_freepbx
  preflight_native_dependency_versions || exit $?
  preflight_platform check
  preflight_python
  detect_served_php_profiles
  set_install_stage "release download and validation" "Confirm the release URL and checksum, restore GitHub or network access if needed, and rerun the installer."
  download_tgz
  verify_tgz
  stage_module_directory
  prepare_installer_bootstrap
  INSTALL_ERROR_CATEGORY="php_security_preflight_failed"
  verify_php_security_versions_before_mutation
  INSTALL_ERROR_CATEGORY="freepbx_web_preflight_failed"
  verify_freepbx_web_response
  INSTALL_ERROR_CATEGORY="install_command_failed"
  bootstrap_missing_dashboard
  set_install_stage "publisher and stock approval" "Review the upgrade evidence directory printed in the log. Standard stock modules bootstrap from signed upstream packages; local differences require independently reviewed inventories. No maintenance changes occur before approval."
  prepare_authenticated_installer
  capture_install_resource_proof
  # Persist authenticated recovery evidence before even the bounded native
  # chown exclusion or legacy metadata repair can change protected state.
  begin_install_transaction
  set_install_stage "FreePBX ownership protection" "Review the FreePBX chown configuration conflict named in the log. Existing unrelated ownership rules are preserved."
  protect_freepbx_chown_permissions
  INSTALL_ERROR_CATEGORY="legacy_permission_recovery_failed"
  set_install_stage "legacy configuration and runtime permissions" "Review the exact filename, ownership, mode or validation error in the log. Valid central configuration and a missing settings mutex are recovered without replacing settings or existing lock inodes. Unknown owners, links and damaged data require review."
  repair_authenticated_legacy_permissions
  INSTALL_ERROR_CATEGORY="install_command_failed"
  set_install_stage "authenticated prerequisite validation" "Review the specific prerequisite in the log. Previous executable files and approved PBX integration must still match their authenticated inventories."
  preflight_authenticated_prerequisites
  INSTALL_ERROR_CATEGORY="previous_collector_recovery_failed"
  set_install_stage "previous phone collector recovery" "Review the collector journal and approved service state. The installer verifies a fresh authenticated heartbeat before pausing notification workers; it does not reset phone history."
  restore_previous_phone_collector
  INSTALL_ERROR_CATEGORY="worker_coordination_failed"
  set_install_stage "notification worker coordination" "Let active SLL work finish, then retry. Review the named worker mutex if ownership, mode, contents or identity were rejected."
  acquire_worker_coordination
  INSTALL_ERROR_CATEGORY="protected_config_validation_failed"
  set_install_stage "configuration coordination" "Close active configuration editors and retry. The settings mutex must remain an empty, private regular file with a stable inode; review the specific failure in the log."
  acquire_settings_coordination
  snapshot_config
  snapshot_pending_config
  validate_preserved_config_prerequisites
  INSTALL_ERROR_CATEGORY="install_command_failed"
  verify_staged_hardware_requirements
  retain_configuration_snapshots
  persist_install_transaction prepared
  commit_authenticated_installer
  set_install_stage "dependency installation" "Restore Debian package repository access and install the prerequisite named in the installer log, then rerun the installer. Approved system packages are retained after a module rollback."
  install_dependencies
  verify_served_php_configuration
  preflight_python
  initialize_configuration_keyring
  apply_requested_deployment_profile
  apply_factory_branding_defaults
  validate_staged_central_config
  ensure_freepbx_prerequisites
  preflight_platform
  set_install_stage "timezone validation" "Choose a valid IANA timezone listed by timedatectl or repair the host timezone configuration."
  configure_system_timezone
  persist_install_transaction mutating
  set_install_stage "protected runtime preparation" "Correct the specific protected-path or dependency error in the installer log; do not run FreePBX module hooks as root."
  STATIC_MUTATION_STARTED=1
  protected_install_phase prepare --apply
  protected_install_phase dependencies --apply
  set_install_stage "module activation" "Review the rejected unprivileged FreePBX integration step in the installer log, then correct that prerequisite before retrying."
  activate_staged_module
  persist_install_transaction mutating
  initialize_fresh_install_config
  retain_configuration_snapshots
  persist_install_transaction mutating
  prepare_module_ami_intent
  ensure_local_signer
  if SLS_MASS_NOTIFY_DEFER_SIGNING=1 install_module_with_autoenable; then
    :
  else
    install_status=$?
    log "FreePBX module installation failed (exit $install_status). See $LOG_FILE."
    exit "$install_status"
  fi
  retire_legacy_framework_menu
  SLS_MASS_NOTIFY_MODULE="$MODULE" sync_module_version
  set_install_stage "runtime integration" "Correct the named integration prerequisite in the installer log; protected operations require the authenticated release and approved stock inventories."
  ensure_runtime_installed
  secure_central_config
  # Fresh installs need the collector running before FreePBX postReload
  # performs readiness checks. Install already wrote the loopback AMI user.
  asterisk -rx "manager reload" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || true
  protected_install_phase activate --apply
  refresh_served_php_workers
  SLS_MASS_NOTIFY_PRESERVE_PENDING=1 fwconsole reload
  verify_phone_collector
  protected_install_phase verify
  asterisk -rx "module reload res_pjsip_notify.so" >>"${INSTALL_LOG_OUTPUT:-$LOG_FILE}" 2>&1 || true
  asterisk -rx "dialplan reload" || true
  set_install_stage "post-install verification" "Review the failed verification in /tmp/slsmassnotifyserver-install.log, correct that PBX-specific prerequisite, and rerun the installer or Repair Installation."
  verify_runtime_shell_syntax
  verify_announcement_worker_health
  verify_piper_voices
  verify_served_php_runtime
  verify_freepbx_web_response
  verify_install
  verify_confirmed_system_timezone
  verify_config_unchanged
  verify_pending_config_unchanged
  verify_install_idle_history
  INSTALL_COMMITTED=1
  persist_install_transaction committed || { INSTALL_COMMITTED=0; exit 1; }
  clear_install_failure
  log "SLL Mass Notify Server install finished."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
