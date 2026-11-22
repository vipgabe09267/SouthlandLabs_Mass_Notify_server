# Publisher rotation, expiry and recovery

The current Ed25519 self-signing key remains the bootstrap authority. Normal
installation does not rotate keys, initialize a stricter policy, or trust a
downloaded public key. Module signatures and publisher verification are separate:
this procedure changes publisher authority, not the existing local module signer.

Verify a first installer before execution using [trusted host tools](FIRST_INSTALL_VERIFICATION.md).
The release policy for new versions is immutable publication: use a newer version for corrections. Earlier beta assets, including 0.1.7, were mutable. Enable GitHub release immutability before publishing the next release; the provenance workflow refuses a mutable release.
Installed identity includes its authenticated inventory digest. The protected
updater does not replace equal versions.

Root can inspect retained generation storage without modifying it:

```bash
python3 -I /usr/local/bin/sls_mass_notify/sls_module_trust.py storage
```

The report marks active generations and retains every other generation for
recovery review. It does not authorize deletion: installer transactions and
previous-release approval may still reference those files. Preserve active,
pending and recoverable references before separately reviewed storage cleanup.

New release manifests carry signed `key_id`, `issued_at` and `expires_at`
metadata. The release signer sets a one-year validity. Verification rejects
future/expired metadata and signatures outside a key's active window, before
using artifact hashes or executing the installer. Existing published manifests
without metadata remain compatible until a PBX explicitly initializes the
reviewed policy. Keep the clock synchronized.

## Initialize and review

As root, inspect the installed authority:

```bash
python3 -I /usr/local/bin/sls_mass_notify/sls_release_trust.py status
```

After confirming the bootstrap fingerprint and that the intended release uses
the new metadata, run the same command with `initialize`. This preserves the
current key and creates a root-private ledger plus a permanent initialized
marker under `/var/lib/sls-mass-notify-trust`. Once initialized, old manifests
without signed expiry metadata are rejected. Missing/corrupt established state
fails closed; an update cannot silently revert to bootstrap trust.

This ledger is security authority and revocation history, not PBX settings. It is
deliberately outside web-writable `.config`, is not exposed by an API, and is not
rewound by ordinary configuration or native PBX restoration. Include the entire
root trust directory in independently protected disaster recovery material.

## Normal rotation

Prepare a reviewed policy with exactly `schema: 1`, the current `sequence + 1`,
and one to four keys. Each key has:

| Field | Meaning |
|---|---|
| `id` | SHA-256 of its 44-byte Ed25519 DER SubjectPublicKeyInfo. |
| `public_key` | Base64 of those DER bytes; no URL or file path. |
| `not_before` | UTC Unix timestamp; zero permits immediate use. |
| `expires_at` | Exclusive UTC timestamp; zero has no key-level expiry. |
| `revoked_at` | Revocation timestamp; zero is not revoked. |

The helper's `key_entry(public_PEM_bytes)` returns this structure. First retain
the existing key and add the new key for an overlap period. Generate and store
the new private key independently of the repository. On the publisher's protected
build machine, sign the reviewed policy using both private keys:

```bash
python3 tools/sign_trust_policy.py --policy reviewed-policy.json \
  --key /secure/existing-ed25519.key --key /secure/new-ed25519.key \
  --output signed-transition.json
```

The output is a signed envelope, not executable code. Independently review its
fingerprints, sequence, validity dates and intended deployments. On each PBX,
import the reviewed local file as root:

```bash
python3 -I /usr/local/bin/sls_mass_notify/sls_release_trust.py import-transition \
  --transition /secure/signed-transition.json
```

Import requires a currently trusted active issuer signature and possession
proof for every new key. It rejects skipped/replayed sequences and cannot revive
a retired key or delay an existing revocation. After qualifying the overlap,
import the next signed policy to revoke/remove the old key. Keep at least one
currently active authority. Removed keys are permanently retired locally.

Installed updates and tagged/offline installers use the same protected verifier
when available. Fresh installations bootstrap using the pinned current key;
deploy the reviewed overlap policy before distributing releases signed only by a
replacement key. Downloaded code cannot establish authority for its own signature.

The `0.2.0-beta` bootstrap's existing-installation mode and temporary candidate
registries consult that same current root-approved policy. They do not reset to
the original key or accept policy supplied inside a downloaded candidate.

## Expired retained release metadata

In `0.2.0-beta`, an expired manifest for the exact protected active generation
has an explicit root-review path. Normal downloaded candidates still require
unexpired metadata. An expired or revoked signing key remains a refusal.

Using the installed `0.2.0-beta` protected helper, inspect the evidence first:

```bash
sudo /usr/bin/python3 -I /usr/local/bin/sls_mass_notify/sls_upgrade_trust.py \
  --workspace /root/sls-retained-review --review-retained
```

If the installed release predates this review feature, use a separately
publisher-authenticated `0.2.0-beta` installer as the launch boundary:

```bash
sudo /bin/bash ./install_release.sh --review-retained
sudo /bin/bash ./install_release.sh --approve-retained EXACT_SHA256_CHALLENGE \
  --operator 'Administrator name' \
  --reason 'Independently reviewed this exact retained release for upgrade continuity.'
```

These modes verify the current candidate before loading its new root-protected
helper, then inspect or explicitly approve the existing live trust root. They do
not start a transaction, bootstrap native FreePBX PHP, pause workers, activate a
module or install software. The bootstrap forwards these modes only with
`--upgrade`. Candidate-provided trust policy is never existing authority. Ordinary
`--inspect` uses the same source-only staging boundary and creates no approval.

After independently reviewing its exact generation and evidence hashes, use the
displayed challenge with the administrator's identity and review reason:

```bash
sudo /usr/bin/python3 -I /usr/local/bin/sls_mass_notify/sls_upgrade_trust.py \
  --workspace /root/sls-retained-review --approve-retained EXACT_SHA256_CHALLENGE \
  --operator 'Administrator name' \
  --reason 'Independently reviewed this exact retained release for upgrade continuity.'
```

These actions do not write to the required workspace argument. Approval joins
the installation/maintenance and publisher locks and writes a root-private
`retained-release-approval.json` in the protected trust directory. It expires
after seven days and does not renew automatically. Every use rechecks the exact
active reference, inventory, manifest, signature, source bytes and current trust
policy. Changed evidence or policy invalidates the approval. The exception covers
only this retained manifest's expiration; it cannot authorize a fresh candidate,
revoked/expired key, altered module or restoration of an old operational ledger.

## Emergency recovery

Stop automatic release installation at the operating-system level and investigate
the affected signing/build infrastructure. Independently obtain and verify a new
public key fingerprint through an owner-controlled channel. Do not accept a
replacement fingerprint merely because the compromised publisher supplied it.

With trusted installed recovery code and a readable current ledger, root can use
`recover-offline --public-key /secure/replacement.pub --fingerprint <exact SHA-256>
--current-sequence <reviewed sequence> --reason "<reviewed recovery reason>"`.
This deliberately bypasses a compromised/lost issuer after explicit root review,
retires every prior authority, increments the sequence and records the recovery
in the durable ledger. It is never invoked by the updater, web UI, or `.config`.

If the ledger or installed helper itself is untrusted/unreadable, recover them
from independently verified offline evidence before using this procedure. Do not
delete the initialized marker or roll back revocations to make an update pass.
Actual disaster recovery on a separate PBX remains an acceptance requirement.

Real disposable-key fixtures test overlap, possession proofs, revocation,
sequence replay, unsafe/missing storage, expiry, offline replacement and the
installer's use of the same authority. No production key is rotated by tests.
