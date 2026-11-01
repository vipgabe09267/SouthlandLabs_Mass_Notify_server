#!/bin/bash
set -euo pipefail
[[ "${SLS_TEST_NAMESPACE:-}" == entered ]] || { printf 'Use the verified private test wrapper.\n' >&2; exit 2; }
for kind in MOUNT NET PID; do
  variable="SLS_TEST_PARENT_${kind}_NS"
  case "$kind" in MOUNT) namespace=mnt ;; NET) namespace=net ;; PID) namespace=pid ;; esac
  [[ -n "${!variable:-}" && "$(readlink "/proc/self/ns/$namespace")" != "${!variable}" ]] || {
    printf 'Dependency fixture isolation verification failed; no mounts were made.\n' >&2
    exit 2
  }
done
task_dir="$(mktemp -d /tmp/sls-dependency-fixture.XXXXXX)"
php_target="$(readlink -f /usr/bin/php)"
python_target="$(readlink -f /usr/bin/python3)"
trap 'umount "$python_target"; umount "$php_target"; rm -rf "$task_dir"' EXIT
cat > "$task_dir/php" <<'PHP'
#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$SLS_DEPENDENCY_TRACE"
if [[ "$*" == *PHP_MAJOR_VERSION* ]]; then printf '8.2'; exit 0; fi
if [[ "$*" == *pdo_sqlite* || "$*" == *curl_init* || "$*" == *DOMDocument* || "$*" == *mbstring* || "$*" == *openssl_encrypt* ]]; then
  [[ -f "$SLS_DEPENDENCY_INSTALLED" ]] || exit 1
fi
exit 0
PHP
cat > "$task_dir/python" <<'PYTHON'
#!/bin/bash
set -eu
# Debian's standard library can provide venv while its separate ensurepip
# package is absent. Importing venv alone must not qualify this installation.
if [[ "$*" == *ensurepip* && "$SLS_DEPENDENCY_SCENARIO" == venv_bootstrap_* ]]; then
  [[ -f "$SLS_DEPENDENCY_VENV_INSTALLED" ]]
  exit $?
fi
exit 0
PYTHON
cat > "$task_dir/apt-get" <<'APT'
#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$SLS_DEPENDENCY_APT_TRACE"
[[ "$*" == install\ * ]] || exit 8
[[ "$SLS_DEPENDENCY_SCENARIO" != package_failure ]] || exit 9
if [[ "$SLS_DEPENDENCY_SCENARIO" != verification_failure ]]; then touch "$SLS_DEPENDENCY_INSTALLED"; fi
if [[ "$SLS_DEPENDENCY_SCENARIO" != venv_bootstrap_verification_failure ]]; then touch "$SLS_DEPENDENCY_VENV_INSTALLED"; fi
APT
chmod 0755 "$task_dir/php" "$task_dir/python" "$task_dir/apt-get"
mount --bind "$task_dir/php" "$php_target"
mount --bind "$task_dir/python" "$python_target"
export PATH="$task_dir:$PATH"
export SLS_DEPENDENCY_TRACE="$task_dir/php-trace" SLS_DEPENDENCY_INSTALLED="$task_dir/installed" SLS_DEPENDENCY_APT_TRACE="$task_dir/apt-trace"
export SLS_DEPENDENCY_MOCK_PATH="$task_dir"
export SLS_DEPENDENCY_VENV_INSTALLED="$task_dir/venv-installed"
installer="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install_release.sh"
for scenario in success present verification_failure package_failure metadata_failure venv_bootstrap_missing venv_bootstrap_verification_failure; do
  rm -f "$SLS_DEPENDENCY_TRACE" "$SLS_DEPENDENCY_INSTALLED" "$SLS_DEPENDENCY_APT_TRACE" "$SLS_DEPENDENCY_VENV_INSTALLED"
  case "$scenario" in present|venv_bootstrap_*) touch "$SLS_DEPENDENCY_INSTALLED" ;; esac
  export SLS_DEPENDENCY_SCENARIO="$scenario"
  set +e
  bash -c 'source "$1"; PATH="$SLS_DEPENDENCY_MOCK_PATH:/usr/sbin:/usr/bin:/sbin:/bin"; export PATH; log(){ printf "%s\n" "$*"; }; refresh_apt_metadata(){ [[ "$SLS_DEPENDENCY_SCENARIO" != metadata_failure ]]; }; install_dependencies' fixture "$installer" > "$task_dir/result" 2>&1
  status=$?
  set -e
  case "$scenario" in
    success)
      [[ "$status" == 0 && -f "$SLS_DEPENDENCY_INSTALLED" ]]
      for package in php8.2-sqlite3 php8.2-curl php8.2-xml php8.2-mbstring php8.2-common; do grep -Fq "$package" "$SLS_DEPENDENCY_APT_TRACE"; done
      ;;
    present) [[ "$status" == 0 && ! -f "$SLS_DEPENDENCY_APT_TRACE" ]] ;;
    verification_failure) [[ "$status" != 0 ]]; grep -Fq 'still lacks SQLite, cURL or XML after dependency installation' "$task_dir/result" ;;
    package_failure) [[ "$status" != 0 && ! -f "$SLS_DEPENDENCY_INSTALLED" ]] ;;
    metadata_failure) [[ "$status" != 0 && ! -f "$SLS_DEPENDENCY_APT_TRACE" ]]; grep -Fq 'Unable to refresh Debian package metadata' "$task_dir/result" ;;
    venv_bootstrap_missing)
      [[ "$status" == 0 && -f "$SLS_DEPENDENCY_VENV_INSTALLED" ]] || {
        cat "$task_dir/result" >&2
        printf 'Installer did not repair missing ensurepip when venv was importable.\n' >&2
        exit 1
      }
      grep -Fq 'python3-venv' "$SLS_DEPENDENCY_APT_TRACE"
      ;;
    venv_bootstrap_verification_failure)
      [[ "$status" != 0 && -f "$SLS_DEPENDENCY_APT_TRACE" ]]
      grep -Fq 'Python virtual-environment bootstrap support is unavailable after dependency installation' "$task_dir/result"
      ;;
  esac
done
printf 'Installer dependency recovery: version-matched PHP, missing Debian ensurepip with venv present, existing packages and actionable package/metadata/runtime failures passed.\n'
