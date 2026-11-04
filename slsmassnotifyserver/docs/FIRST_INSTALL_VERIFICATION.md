# Verify the unpublished reserved-tag 0.1.9-beta correction

The corrected software remains **0.1.9-beta**, candidate L, with planned reserved tag `release-0.1.9-beta`. It is **unpublished**; its command examples remain unavailable until qualification and publication. The available published prerelease is **0.1.8-beta**. The retired uppercase `V0.1.9-beta` release and the withdrawn `v0.1.10-beta` release must not be reused. Do not execute retained installers or bundles from the withdrawn tags.

## Publisher identity and retained evidence

Compare retained signed evidence with your independently retained SLL publisher record. A key downloaded alongside an installer cannot establish its own authority.

```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=
-----END PUBLIC KEY-----
```

DER SHA-256 fingerprint: `f2101cc51ecd5fdda7104d7e63ec166928c8985a0b3870f866849f5df6819bbd`.

The corrected bootstrap SHA-256 is `0ef425a966647e8db8ebbd9c6a3bc0ae4586c96db8fd0ce50f3089b42217edb6`. Once the new candidate is qualified and published, verify its exact reserved-tag file before considering the separate [installation or upgrade command](../README.md#install-or-update):

```bash
# Unavailable until lowercase release-0.1.9-beta is qualified and published.
curl --fail --location --proto '=https' --tlsv1.2 -o sls-bootstrap.sh \
  https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/release-0.1.9-beta/tools/install_bootstrap.sh &&
printf '%s\n' '0ef425a966647e8db8ebbd9c6a3bc0ae4586c96db8fd0ce50f3089b42217edb6  sls-bootstrap.sh' | sha256sum --check
```

A matching bootstrap checksum does not establish release availability or package qualification. The new installer, `slsmassnotifyserver-0.1.9-beta.tgz`, manifest and signature must bind lowercase `release-0.1.9-beta` and the new exact hashes; historical uppercase packages share the filename but have different signed bytes. Existing installations use `--upgrade` to preserve publisher policy, keys and revocations.

Current L qualification and publication remain pending. The withdrawn J build passed 424 isolated suites and nine bounded native scenarios as 0.1.10-beta; those exact source/artifact results remain historical evidence and do not qualify these rebuilt 0.1.9-beta assets. See [qualification boundaries](QUALIFICATION_MATRIX.md).

## Interrupted installation

Preserve the exact failed transaction directory, logs, signed assets, protected snapshots, live settings, keyring and publisher trust. A `transaction-sequence` counter is not a recovery directory. Do not delete evidence, rewrite a baseline or replace the operational ledger to make recovery pass.

The user reports that 0.1.10-beta installed successfully, passed 16 doctor checks and preserved MFA/settings/keys after the administrator explicitly accepted 21 missing history records. This is user-reported, not independent target qualification of the new 0.1.9-beta artifacts.

The replacement implements narrow preservation of increasing TOTP counters and their associated operator-access revision through separate durable recovery targets. Every other setting remains exact, original snapshots and intentions stay unchanged, and unproved changes remain conflicts. Crash retries and later valid MFA advancement preserve the highest validated counters; never reset them or remove an unfinished settings journal to force recovery.

The [installer recovery protocol](INSTALLER_OPERATIONS.md#interrupted-installations) explains evidence and review. The planned reserved-tag installer can provide its own authenticated carrier only after qualification/publication. J native recovery used that fixture's full matching backup. The separate user-reported target success and administrator acceptance above do not qualify the new naming correction on that target.