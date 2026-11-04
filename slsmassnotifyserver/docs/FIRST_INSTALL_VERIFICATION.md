# Verify the published 0.1.10-beta release

**0.1.10-beta is the available published prerelease**, immutable tag `v0.1.10-beta`, with signed assets and verified public readback/provenance. V0.1.9-beta remains withdrawn, its downloads removed and its immutable tag retired. Do not execute copied V0.1.9-beta installers or offline bundles.

## Publisher identity and retained evidence

Compare retained signed evidence with your independently retained SLL publisher record. A key downloaded alongside an installer cannot establish its own authority.

```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=
-----END PUBLIC KEY-----
```

DER SHA-256 fingerprint: `f2101cc51ecd5fdda7104d7e63ec166928c8985a0b3870f866849f5df6819bbd`.

The unchanged bootstrap SHA-256 is `bdf8e32e22a0baeed9a5764f0ade1f6a110fbde686cb8ea5f4f06a026ea1da75`. It supports the published release's generic `v` tag. Verify that exact tagged file before considering the separate [installation or upgrade command](../README.md#install-or-update):

```bash
# Verify the published immutable tag before executing its bootstrap.
curl --fail --location --proto '=https' --tlsv1.2 -o sls-bootstrap.sh \
  https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/v0.1.10-beta/tools/install_bootstrap.sh &&
printf '%s\n' 'bdf8e32e22a0baeed9a5764f0ade1f6a110fbde686cb8ea5f4f06a026ea1da75  sls-bootstrap.sh' | sha256sum --check
```

A matching bootstrap checksum does not establish release availability or package qualification. The new installer, `slsmassnotifyserver-0.1.10-beta.tgz`, manifest and signature must match their own published identities and tag; do not substitute H/G hashes or withdrawn assets. Existing installations use `--upgrade` to retain enrolled publisher policy, keys and revocations.

**424/424 independent isolated suites passed**, including required browser/UI and schema checks; **9 native scenarios passed** in marked disposable QEMU branches. Signed public assets and exact-tag provenance were verified. The earlier 207 focused cases across seven isolated suites also passed. The [qualification boundaries](QUALIFICATION_MATRIX.md) distinguish these results from historical H/G findings, universal compatibility and the still-unrecovered actual LiteNet target. The immutable tag and signed package retain their original prepublication documentation snapshot. This published-status update belongs to a separate documentation commit on main; it does not change release bytes or move the tag.

## Interrupted installation

Preserve the exact failed transaction directory, logs, signed assets, protected snapshots, live settings, keyring and publisher trust. A `transaction-sequence` counter is not a recovery directory. Do not delete evidence, rewrite a baseline or replace the operational ledger to make recovery pass.

The reported LiteNet baseline contains 22 records: 1 unchanged, 21 missing and 0 with proven expiry. Ordinary history refusal remains exit 4 without matching evidence or a valid explicit decision; no administrator has accepted that reported loss. MFA preservation does not bypass history admission.

The replacement implements narrow preservation of increasing TOTP counters and their associated operator-access revision through separate durable recovery targets. Every other setting remains exact, original snapshots and intentions stay unchanged, and unproved changes remain conflicts. Crash retries and later valid MFA advancement preserve the highest validated counters; never reset them or remove an unfinished settings journal to force recovery.

The [installer recovery protocol](INSTALLER_OPERATIONS.md#interrupted-installations) explains evidence and review. The published installer can provide its own authenticated carrier while preserving original evidence. Disposable native recovery passed only with that fixture's full matching backup; the reported actual LiteNet target has not been recovered.