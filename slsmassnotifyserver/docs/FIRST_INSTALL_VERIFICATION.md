# Verify installation evidence during withdrawal

**V0.1.9-beta is withdrawn.** The source candidate is unpublished and its GitHub release/downloads have been removed. The available published prerelease is **0.1.8-beta**. Fresh installation, repair and upgrade commands are suspended pending a corrected signed release and newly selected release identity. Do not execute copied V0.1.9-beta installers or offline bundles.

## Publisher identity and retained evidence

Compare retained signed evidence with your independently retained SLL publisher record. A key downloaded alongside an installer cannot establish its own authority.

```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFMDOgOaBGcaI8d+v0w/NX4RbwGlBsoktNc2V2F8UkUQ=
-----END PUBLIC KEY-----
```

DER SHA-256 fingerprint: `f2101cc51ecd5fdda7104d7e63ec166928c8985a0b3870f866849f5df6819bbd`.

The historical bootstrap SHA-256 is `bdf8e32e22a0baeed9a5764f0ade1f6a110fbde686cb8ea5f4f06a026ea1da75`. This identifies old bytes; it does not authorize running them. The [qualification boundaries](QUALIFICATION_MATRIX.md) retain H's artifact hashes, 423 isolated suites, four native lifecycle cases and three journal profiles as historical evidence. Those tests did not establish recovery of the reported actual target state.

## Interrupted installation

Preserve the exact failed transaction directory, logs, signed assets, protected snapshots, live settings, keyring and publisher trust. A `transaction-sequence` counter is not a recovery directory. Do not delete evidence, rewrite a baseline or replace the operational ledger to make recovery pass.

The reported LiteNet baseline contains 22 records: 1 unchanged, 21 missing and 0 with proven expiry. Ordinary history refusal must remain exit 4 without matching evidence; no administrator has accepted that loss. Independently, `totp_last_counter` and the `operator_access` revision changed and the configuration hash guard blocks recovery. Their handling remains unresolved; do not replace current settings with the snapshot.

The generic [installer recovery protocol](INSTALLER_OPERATIONS.md#interrupted-installations) explains retained evidence and review. A new carrier, exact version/tag and checksum-pinned installation/recovery commands will be documented only after a corrected signed release is qualified. No successful actual LiteNet recovery or replacement publication is claimed.
