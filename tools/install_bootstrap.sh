#!/usr/bin/env bash
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

bootstrap_download() {
  /usr/bin/timeout --signal=TERM --kill-after=3 75 /usr/bin/python3 -I - "$1" "$2" <<'PY'
import os,re,sys,urllib.request,urllib.parse
from pathlib import Path
root=Path(sys.argv[1]);version=sys.argv[2];tag='release-0.1.9-beta' if version=='0.1.9-beta' else ('slsmassnotifyserver-' if tuple(map(int,version.removesuffix('-beta').split('.')))<(0,1,9) else 'v')+version
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,url):
        target=urllib.parse.urlsplit(url)
        if target.scheme!='https' or target.hostname not in ('github.com','raw.githubusercontent.com','objects.githubusercontent.com','release-assets.githubusercontent.com') or target.username or target.password or target.port not in (None,443):raise ValueError('Unapproved release redirect')
        return super().redirect_request(request,fp,code,message,headers,url)
client=urllib.request.build_opener(Redirect())
assets=[('release-manifest.json',16384,'https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/'+tag+'/release-manifest.json'),
        ('release-manifest.sig',64,'https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/'+tag+'/release-manifest.sig'),
        ('install_release.sh',1048576,'https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/'+tag+'/tools/install_release.sh')]
try:
    for name,maximum,url in assets:
        with client.open(urllib.request.Request(url,headers={'User-Agent':'SLS-Verified-Bootstrap/1'}),timeout=20) as response:
            if response.status!=200:raise ValueError('Release asset is unavailable')
            body=response.read(maximum+1)
        if not 0<len(body)<=maximum:raise ValueError('Release asset exceeded its size bound')
        with (root/name).open('xb') as output:output.write(body);output.flush();os.fsync(output.fileno())
except Exception:
    raise SystemExit('The signed release could not be downloaded within its bounds. Confirm the release exists and HTTPS access to GitHub works; no installer was executed.') from None
PY
}

bootstrap_verify() {
  local directory="$1" version="$2" expected_tag="${3:-}" existing_mode="${4:-0}"
  /usr/bin/openssl pkey -pubin -in "$directory/publisher.pem" -outform DER -out "$directory/publisher.der"
  /usr/bin/openssl pkeyutl -verify -pubin -inkey "$directory/publisher.pem" -rawin \
    -in "$directory/release-manifest.json" -sigfile "$directory/release-manifest.sig" >/dev/null || {
      printf 'Publisher signature verification failed. No installer was executed.\n' >&2; return 1;
    }
  /usr/bin/python3 -I - "$directory" "$version" "$expected_tag" "$existing_mode" <<'PY'
import hashlib,json,os,re,stat,sys,time,types
from pathlib import Path
root=Path(sys.argv[1]);version=sys.argv[2];expected_tag=sys.argv[3];existing_mode=sys.argv[4]
def unique(pairs):
    value={}
    for name,item in pairs:
        if name in value:raise ValueError('Duplicate manifest field')
        value[name]=item
    return value
def installed_helper(name):
    helper=Path('/usr/local/bin/sls_mass_notify')/(name+'.py')
    for path in (helper,*helper.parents):
        info=path.lstat()
        expected=stat.S_ISREG if path==helper else stat.S_ISDIR
        if not expected(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError('Installed publisher verifier is not root-protected')
    fd=os.open(helper,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>262144:
            raise ValueError('Installed publisher verifier is not bounded regular source')
        with os.fdopen(os.dup(fd),'rb') as stream:source=stream.read(262145)
        after=os.fstat(fd);named=helper.lstat()
        identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_nlink)
        if len(source)!=before.st_size or identity(before)!=identity(after) or identity(after)!=identity(named):
            raise ValueError('Installed publisher verifier changed')
    finally:os.close(fd)
    sys.dont_write_bytecode=True
    trusted=types.ModuleType('sls_bootstrap_existing_authority');trusted.__file__=str(helper)
    exec(compile(source,str(helper),'exec'),trusted.__dict__)
    return trusted

try:
    raw=(root/'release-manifest.json').read_bytes()
    if len(raw)>16384 or (root/'release-manifest.sig').stat().st_size!=64:raise ValueError('Manifest bounds')
    manifest=json.loads(raw,object_pairs_hook=unique)
    if set(manifest)!={'schema','version','tag','package','package_sha256','installer_sha256','signing'} or type(manifest['schema']) is not int or manifest['schema']!=1 or manifest['version']!=version or manifest['tag'] not in (('v'+version,'slsmassnotifyserver-'+version)+(('V0.1.9-beta','release-0.1.9-beta') if version=='0.1.9-beta' else ())) or (expected_tag and manifest['tag']!=expected_tag) or manifest['package']!='slsmassnotifyserver-'+version+'.tgz':raise ValueError('Release identity')
    signing=manifest['signing'];now=int(time.time())
    if not isinstance(signing,dict) or set(signing)!={'key_id','issued_at','expires_at'} or signing['key_id']!=hashlib.sha256((root/'publisher.der').read_bytes()).hexdigest() or type(signing['issued_at']) is not int or type(signing['expires_at']) is not int or not 0<signing['issued_at']<=now+60 or not signing['issued_at']<signing['expires_at']<=signing['issued_at']+366*86400 or signing['expires_at']<=now:raise ValueError('Signing validity')
    for field in ('installer_sha256','package_sha256'):
        if not isinstance(manifest[field],str) or not re.fullmatch(r'[a-f0-9]{64}',manifest[field]):raise ValueError('Artifact hash')
    if existing_mode not in ('0','1'):
        raise ValueError('Invalid existing-installation mode')
    if existing_mode == '1':
        directory=Path('/var/lib/sls-mass-notify-trust')
        trusted=installed_helper('sls_release_trust')
        anchor=(root/'publisher.pem').read_bytes()
        state,initialized=trusted.TrustStore(directory,anchor).load()
        if not initialized:
            legacy=installed_helper('sls_module_trust')
            inventory,generation=legacy.load(directory,'slsmassnotifyserver')
            legacy_version=inventory.get('version','')
            match=re.fullmatch(r'([0-9]+)\.([0-9]+)\.([0-9]+)(?:-beta)?',legacy_version)
            if not match or inventory.get('source',{}).get('kind')!='publisher-ed25519':
                raise ValueError('Existing publisher approval is invalid; restore its protected records')
            anchor=legacy.PUBLIC_KEY
        authorized=trusted.authenticate_manifest(raw,(root/'release-manifest.sig').read_bytes(),anchor=anchor,directory=directory)
        if authorized!=manifest:
            raise ValueError('Existing publisher policy did not authorize this manifest')
    installer=(root/'install_release.sh').read_bytes()
    if not 0<len(installer)<=1048576 or hashlib.sha256(installer).hexdigest()!=manifest['installer_sha256']:raise ValueError('Installer hash')
except (OSError,ValueError,TypeError,KeyError,RuntimeError):
    raise SystemExit('Signed release identity, validity or installer hash did not match. No installer was executed.') from None
PY
}

bootstrap_main() (
  [ "$EUID" -eq 0 ] || { printf 'Run the verified bootstrap as root on the PBX.\n' >&2; exit 2; }
  [ "$#" -ge 1 ] && [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-beta)?$ ]] || { printf 'Usage: bash install_bootstrap.sh VERSION [--upgrade] [--lite|--standard] [--inspect | --recover TRANSACTION [--history-evidence FILE] [--review-history | --approve-history-loss SHA256 --history-loss-operator NAME --history-loss-reason TEXT]]\n' >&2; exit 2; }
  local version="$1" directory release_tag existing_mode=0; shift
  if [ "${1:-}" = --upgrade ]; then existing_mode=1; shift; fi
  local -a installer_arguments=()
  if [ "${1:-}" = --lite ] || [ "${1:-}" = --standard ]; then installer_arguments+=("$1"); shift; fi
  if [ "$#" -eq 1 ] && [ "$1" = --inspect ]; then installer_arguments+=(--inspect)
  elif [ "$#" -ge 2 ] && [ "$1" = --recover ] && [ "${#installer_arguments[@]}" -eq 0 ] && [[ "$2" =~ ^/var/lib/sls-mass-notify-installer/transaction-[a-f0-9]{24}$ ]]; then
    installer_arguments=(--recover "$2")
    shift 2
    local history_review=0 history_approval=0 history_evidence=0 history_operator=0 history_reason=0
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --review-history)
          [ "$history_review" -eq 0 ] || { printf 'Duplicate history review option. No installer was executed.\n' >&2; exit 2; }
          history_review=1; installer_arguments+=("$1"); shift ;;
        --history-evidence)
          [ "$history_evidence" -eq 0 ] && [[ "${2:-}" = /* ]] && [ "$2" != / ] || {
            printf 'Recovery evidence requires one absolute root-private ledger path. No installer was executed.\n' >&2; exit 2;
          }
          history_evidence=1; installer_arguments+=("$1" "$2"); shift 2 ;;
        --approve-history-loss)
          [ "$history_approval" -eq 0 ] && [[ "${2:-}" =~ ^[a-f0-9]{64}$ ]] || {
            printf 'History-loss approval requires one exact SHA256 review challenge. No installer was executed.\n' >&2; exit 2;
          }
          history_approval=1; installer_arguments+=("$1" "$2"); shift 2 ;;
        --history-loss-operator|--history-loss-reason)
          [ -n "${2:-}" ] && [[ "$2" != *[$'\001'-$'\037'$'\177']* ]] && [ "${#2}" -le 2048 ] || {
            printf 'History-loss operator and reason require bounded nonempty text. No installer was executed.\n' >&2; exit 2;
          }
          if [ "$1" = --history-loss-operator ]; then
            [ "$history_operator" -eq 0 ] || { printf 'Duplicate history-loss operator. No installer was executed.\n' >&2; exit 2; }; history_operator=1
          else
            [ "$history_reason" -eq 0 ] || { printf 'Duplicate history-loss reason. No installer was executed.\n' >&2; exit 2; }; history_reason=1
          fi
          installer_arguments+=("$1" "$2"); shift 2 ;;
        *) printf 'Unknown recovery option. No installer was executed.\n' >&2; exit 2 ;;
      esac
    done
    [ "$history_review" -eq 0 ] || [ "$history_approval" -eq 0 ] || { printf 'History review and approval require separate commands. No installer was executed.\n' >&2; exit 2; }
    if [ "$history_approval" -eq 1 ]; then
      [ "$history_operator" -eq 1 ] && [ "$history_reason" -eq 1 ] || { printf 'History-loss approval requires an operator and reason. No installer was executed.\n' >&2; exit 2; }
    else
      [ "$history_operator" -eq 0 ] && [ "$history_reason" -eq 0 ] || { printf 'History-loss metadata requires an explicit approval challenge. No installer was executed.\n' >&2; exit 2; }
    fi
  elif [ "$#" -ne 0 ]; then printf 'Use an optional --lite or --standard profile, --inspect, or the exact --recover transaction path printed by the installer. No installer was executed.\n' >&2; exit 2; fi
  for command in /usr/bin/python3 /usr/bin/openssl /usr/bin/mktemp /usr/bin/timeout /bin/bash; do [ -x "$command" ] || { printf 'Missing bootstrap prerequisite: %s\n' "$command" >&2; exit 2; }; done
  if [ -e /var/lib/sls-mass-notify-trust/publisher-trust.json ] || [ -L /var/lib/sls-mass-notify-trust/publisher-trust.json ] || [ -e /var/lib/sls-mass-notify-trust/release-trust.initialized ] || [ -L /var/lib/sls-mass-notify-trust/release-trust.initialized ] || [ -e /var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json ] || [ -L /var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json ]; then
    if [ "$existing_mode" != 1 ]; then
      printf 'This PBX has an explicit publisher trust policy or an approved existing installation. Use --upgrade to verify against that policy; the fresh bootstrap will not bypass it.\n' >&2; exit 2
    fi
  fi
  if [ "$existing_mode" = 1 ] && [ ! -e /var/lib/sls-mass-notify-trust/publisher-trust.json ] && [ ! -L /var/lib/sls-mass-notify-trust/publisher-trust.json ] && [ ! -e /var/lib/sls-mass-notify-trust/release-trust.initialized ] && [ ! -L /var/lib/sls-mass-notify-trust/release-trust.initialized ] && [ ! -e /var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json ] && [ ! -L /var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json ]; then
    printf 'An upgrade requires protected existing installation records. Preserve trust data; use the fresh command only on a host without an established installation.\n' >&2; exit 2
  fi
  /usr/bin/python3 -I - <<'PY'
import os,stat
from pathlib import Path
trust=Path('/var/lib/sls-mass-notify-trust')
if trust.exists() or trust.is_symlink():
    if trust.resolve()!=trust:raise SystemExit('The publisher trust directory is not canonical; preserve it for administrator review.')
    for path in (trust,*trust.parents):
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or (info.st_mode&0o022 and (path==trust or not info.st_mode&stat.S_ISVTX)):raise SystemExit('The publisher trust directory is unsafe; no installer was executed.')
    if trust.stat().st_mode&0o077:raise SystemExit('The publisher trust directory must remain root-private.')
value=os.lstat('/tmp')
if not stat.S_ISDIR(value.st_mode) or value.st_uid!=0 or not value.st_mode&stat.S_ISVTX or os.path.realpath('/tmp')!='/tmp':raise SystemExit('The bootstrap requires the canonical root-owned sticky /tmp directory.')
PY
  directory="$(/usr/bin/mktemp -d /tmp/sls-verified-bootstrap.XXXXXXXX)"
  trap 'rm -rf -- "$directory"' EXIT
  cat >"$directory/publisher.pem" <<'KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=
-----END PUBLIC KEY-----
KEY
  if [[ "$version" == 0.1.9-beta ]]; then release_tag=release-0.1.9-beta
  elif /usr/bin/python3 -I -c 'import sys; raise SystemExit(0 if tuple(map(int,sys.argv[1].removesuffix("-beta").split("."))) < (0,1,9) else 1)' "$version"; then release_tag="slsmassnotifyserver-$version"
  else release_tag="v$version"; fi
  bootstrap_download "$directory" "$version"
  bootstrap_verify "$directory" "$version" "$release_tag" "$existing_mode"
  printf 'Publisher signature and installer hash verified for %s.\n' "$version"
  SLS_MASS_NOTIFY_TGZ_URL="https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/download/$release_tag/slsmassnotifyserver-$version.tgz" \
    /bin/bash "$directory/install_release.sh" "${installer_arguments[@]}"
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then bootstrap_main "$@"; fi
