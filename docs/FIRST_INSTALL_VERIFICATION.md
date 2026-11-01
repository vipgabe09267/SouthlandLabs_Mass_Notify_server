# Verify an installation or upgrade

The software version is **0.1.9-beta** and the GitHub tag is **v0.1.9-beta**. GitHub permanently retired the withdrawn release's original tag. Existing 0.1.8-beta and withdrawn 0.1.9-beta installations need the one-time `--upgrade` command in [README](../README.md); their old updaters cannot recognize the new tag format.

## Publisher identity

Compare this public key with your independently retained SLL publisher record. A key downloaded alongside an installer cannot establish its own authority.

```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=
-----END PUBLIC KEY-----
```

DER SHA-256 fingerprint: `f2101cc51ecd5fdda7104d7e63ec166928c8985a0b3870f866849f5df6819bbd`.

## Online installation

Use the complete checksum-pinned command in [README](../README.md#install-or-update). The bootstrap's SHA-256 is `05fac61c24f70ad59a75418450e83d0c769254d4237fa096f47765e560284900`.

For a fresh host, omit `--upgrade`. If publisher trust is already initialized, the default command refuses to proceed. For an existing installation, append `--upgrade` after the version. That mode requires protected existing installation records. It enforces an initialized publisher policy, including active keys, expiry, revocations and sequence. For signed 0.1.8-and-earlier approvals that predate this policy, it uses the existing protected publisher authority; the authenticated installer establishes the first policy. A newer installation missing its policy is refused. Existing keys and revocations are never reset.

Both paths verify the signed release identity, validity and exact installer hash. The authenticated installer then verifies the package and applies the normal admission, recovery and preservation checks. Lite still requires consent on eligible hardware; unattended users explicitly append `--lite` after `--upgrade` when upgrading.

## Offline bundle

Obtain the corrected release bundle and its checksum through a trusted channel. Extract it as root into a new root-owned directory with mode 0700. Preserve all files together. Independently compare the bootstrap digest above and the publisher fingerprint, then verify:

```bash
(
set -euo pipefail
sha256sum --check SHA256SUMS
printf '%s\n' '05fac61c24f70ad59a75418450e83d0c769254d4237fa096f47765e560284900  install_bootstrap.sh' | sha256sum --check
cp release-signing.pub publisher.pem
source ./install_bootstrap.sh
existing_policy=0
if [ -e /var/lib/sls-mass-notify-trust/publisher-trust.json ] ||
   [ -L /var/lib/sls-mass-notify-trust/publisher-trust.json ] ||
   [ -e /var/lib/sls-mass-notify-trust/release-trust.initialized ] ||
   [ -L /var/lib/sls-mass-notify-trust/release-trust.initialized ] ||
   [ -e /var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json ] ||
   [ -L /var/lib/sls-mass-notify-trust/slsmassnotifyserver.active.json ]; then
  existing_policy=1
fi
bootstrap_verify "$PWD" 0.1.9-beta v0.1.9-beta "$existing_policy" &&
SLS_MASS_NOTIFY_TGZ="$PWD/slsmassnotifyserver-0.1.9-beta.tgz" \
SLS_MASS_NOTIFY_MANIFEST="$PWD/release-manifest.json" \
SLS_MASS_NOTIFY_MANIFEST_SIGNATURE="$PWD/release-manifest.sig" \
bash ./install_release.sh
)
```

The package filename remains `slsmassnotifyserver-0.1.9-beta.tgz` for compatibility. Missing, unsafe, expired or revoked authority stops verification before installer execution. Keep the failure evidence; never delete trust files, replace the live operational ledger or manually enable maintenance jobs to bypass a refusal.

## Interrupted installation

Complete the exact printed `--recover` transaction before starting another upgrade. Use the independently verified corrected installer and retained signed assets. A legacy hash-only baseline may need matching protected pre-upgrade history supplied with `--history-evidence`; that history is evidence, never a replacement for the live ledger. A `transaction-sequence` counter is not a recovery directory. See [installer recovery](INSTALLER_OPERATIONS.md#interrupted-installations).
