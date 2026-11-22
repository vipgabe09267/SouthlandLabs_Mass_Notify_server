# Verify 0.2.0-beta before installation

Use tag `v0.2.0-beta`. The signed release includes the versioned module archive, installer, manifest and signature. [GitHub release](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/tag/v0.2.0-beta).

## Publisher identity and retained evidence

Compare retained signed evidence with your independently retained SLL publisher record. A key downloaded alongside an installer cannot establish its own authority.

```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=
-----END PUBLIC KEY-----
```

DER SHA-256 fingerprint: `f2101cc51ecd5fdda7104d7e63ec166928c8985a0b3870f866849f5df6819bbd`.

The bootstrap SHA-256 is `4cb772cb82f3c2c7ce7754efcc25d3cf265ce50b388b3f00b5dd042a05b20aa1`. Verify it before running the appropriate command for a fresh installation or upgrade. [Installation commands](../README.md#install-or-update).

```bash
# Verify the tagged bootstrap.
curl --fail --location --proto '=https' --tlsv1.2 -o sls-bootstrap.sh \
  https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/v0.2.0-beta/tools/install_bootstrap.sh &&
printf '%s\n' '4cb772cb82f3c2c7ce7754efcc25d3cf265ce50b388b3f00b5dd042a05b20aa1  sls-bootstrap.sh' | sha256sum --check
```

The bootstrap verifies the signed manifest and installer. The installer verifies `slsmassnotifyserver-0.2.0-beta.tgz` against that manifest. Existing installations use `--upgrade` to verify against their protected publisher policy. The exact release hashes are recorded in the [qualification matrix](QUALIFICATION_MATRIX.md).

## Interrupted installation

Preserve the exact failed transaction directory, logs, signed assets, protected snapshots, live settings, keyring and publisher trust. A `transaction-sequence` counter is not a recovery directory. Do not delete evidence, rewrite a baseline or replace the operational ledger to make recovery pass.

The recovery installer preserves increasing MFA replay counters and checks all other settings and retained phone history. If it requests backup evidence or an administrator decision, preserve the original transaction and follow the [recovery procedure](INSTALLER_OPERATIONS.md#interrupted-installations).
