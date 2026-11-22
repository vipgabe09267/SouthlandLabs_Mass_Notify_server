# Installer diagnostics, recovery and qualification

The published release is **0.2.0-beta**. Use the signed installer for tag `v0.2.0-beta`. For recovery, retain the failed transaction and the original authenticated assets. [Release downloads](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/tag/v0.2.0-beta).

The user reports that 0.1.10-beta installed successfully, passed 16 doctor checks and preserved MFA/settings/keys after the administrator explicitly accepted 21 missing history records. This is user-reported, not independent target qualification of the new 0.1.9-beta artifacts. The naming correction retains existing MFA/history behavior. Do not overwrite settings, reset MFA or replace the ledger; preserve the recorded administrator decision with the transaction evidence. L passed 424/424 independent isolated suites with required browser/schema checks and both bounded native cases: fresh 0.1.9 installation and explicit authenticated 0.1.10-to-0.1.9 PHP-FPM/HTTPS correction. Public assets and exact-tag provenance were verified. See [qualification boundaries](QUALIFICATION_MATRIX.md).

Activation reloads Apache and each independently qualified PHP-FPM version. This
refreshes their separate opcode caches without changing PHP settings or restarting
Asterisk. Rollback refreshes FPM after restoring the approved files. The local,
read-only API probe reports its compiled SLL version; installation fails clearly
if the serving handler still runs a previous release or its reload fails.

FreePBX Apply Config may need to generate SLL audio after paging or panic
settings change. The renderer runs as `asterisk` for both web and root CLI
reloads. It checks storage on the actual paging destination and speech
workspace. If speech is busy or storage is exhausted, the pending settings
stay staged and FreePBX can apply unrelated extension changes. Check the
FreePBX reload output and PHP error log for the SLL warning, correct the
reported condition and retry Apply Config. A shortcut whose required audio
is unavailable stays out of the dialplan until its prompts are ready.

The supported profile is FreePBX 17 on Debian 12, amd64, CPython 3.11 and
Apache, using the standard FreePBX paths and the `asterisk` service account.
Versioned local PHP-FPM sockets are inspected separately from CLI PHP. The
served Apache or FPM process must run as `asterisk`; required process and
cryptographic functions must be enabled in both the served PHP configuration
and its FPM pool overrides. SLL does not change the global web-server user or
grant another web account access to PBX secrets. Other
architectures, relocated layouts and restricted containers require explicit
adapters and qualification; the installer does not guess replacement paths or
disable its trust checks to accommodate them.

Installer and uninstaller native-account commands, including Module Admin and
FreePBX PHP bootstrap/hooks, have a fixed 20-minute budget followed by a
five-second TERM-to-KILL grace. Existing shorter probe budgets and their kill
graces remain separate. The execution clock includes the account transition;
blocked command output cannot disable it. An independent root waiter and
supervisor retain worker and maintenance leases while mutable native children
receive none. Their own child inventories and admission handshake contain loss
of either root stage or the outer caller's process group. Failed or cancelled
commands retire only their owned descendants, including detached hooks, before
semantic completion permits recovery or release of the root worker leases.
Successful native hooks may start intentional services; those services are not
explicitly killed by successful command cleanup.

If semantic completion cannot be verified, a CRITICAL message identifies the
root waiter PID and private `/run/sls-native-command-*` evidence. The surviving
root holder keeps coordination fenced and does not begin rollback or re-enable
jobs while owned work remains unverified. Administrator review is required
before terminating that holder and resuming authenticated recovery; deleting
lock files or manufacturing a completion record does not prove retirement.
The `/run` evidence is volatile and should be preserved before reboot. The
protected installation/removal transaction and logs remain the durable recovery
evidence. This contains the tested loss of a stage while another trusted holder
survives; destruction of every root holder is outside that contract.

Preserve the printed transaction and logs after a timeout; use the authenticated
recovery or removal retry described below. Identity/NSS
lookups and operating-system storage I/O are outside this command deadline.
Manual Weather pickup also caps each native CLI request to the remaining pickup
budget, with a fixed two-second termination grace, before reporting an unaccepted
job and removing only that test's queued call file.

Required native module floors are Framework `17.0.33`, Dashboard `17.0.5`, Backup `17.0.13` and Recordings `17.0.6`. Existing older or unqualified registrations stop before an SLL transaction starts; update them through native Module Admin and retry. SLL does not run an automatic `upgradeall`. These reviewed floors cover the vendor advisories cited below and do not certify the entire host as vulnerability-free:

- [Framework reviewed security fixes](https://github.com/FreePBX/framework/blob/release/17.0/module.xml)
- [Dashboard fixed version](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-hw7v-v2jp-wc4v)
- [Backup fixed version](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-5457-hm39-pcfc)
- [Recordings fixed version](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-9cjf-xw9x-55hh)

The exact locked NumPy wheel requires x86-64-v2; AVX is optional. CPU count and RAM alone do not establish this capability. Admission checks every CPU allowed by process affinity and accounts for cgroup limits using the actual mount root and membership path. An unresolvable hierarchy stops admission instead of assuming host resources are available.

The disabled Weather scheduler verification uses a small private data fixture in
the root-owned sticky `/tmp` runtime workspace. The installer validates that
parent, finishes the fixture configuration before handing ownership to the PBX
account, and removes it after the bounded check. Protected installer scratch
keeps its search-only PBX group permission; configuration reader checks and
storage reservations are unchanged.

Storage admission normally reserves previous-release source and download space.
The signed installer can prove that these copies are absent through a successful
native registration read, candidate-bound previous-source approvals and protected
absence of the active module, runtime and SLL source pointer. A missing module
directory alone does not qualify. Retained configuration, keys, history and inactive
authenticated generations after a completed fresh-install rollback are preserved;
they do not themselves authorize a previous source release or a configuration restore.
The existing strict fresh-install proof remains supported.

The final check runs after the current transaction's inputs have been retained.
A separate capacity-only proof verifies the exact private prepared journal,
candidate archive, installer, signed-manifest bytes, twelve bootstrap files and
complete approval source against the authenticated candidate. Only those completed
current allocations have no further creation cost. An early capsule alone cannot
remove these reservations. Unknown, changing or partial evidence keeps the
conservative budget, and no resource proof grants execution, rollback or
configuration-restoration authority.

Established upgrades use a separate prepared-transaction proof. The exact current
archive, bootstrap and candidate approval source must already be complete. The
previous protected active generation must contain its approved full source and
signed release inputs, with no previous-package acquisition fallback. These facts
remove future creation costs for resident copies; they do not describe a fresh
installation or authorize an operational restore.

The installer checks the exact Dashboard and Framework versions and the signed
archive digest in each approved inventory. A matching protected package already
in the cache requires no further publication space. When FreePBX updates either
module, the installer reserves the measured new signed package and directory
growth on the cache filesystem. Unknown cache contents retain the full cache
budget. The prior and candidate source copies have independent evidence.
The writer verifies the signatures and checks the bound hashes and native
versions again before publication. It checks free bytes and inodes for any
interrupted recovery copies on the trust filesystem before removing an old file.
GPG keeps its verification space on the selected installer filesystem.

Local signing checks the filesystem that holds the signing lock, temporary
files, each keyring and the module signature. The signer queries FreePBX for the
keyring location and verifies its metadata during an ownership repair.

Operational state headroom, configuration and prior-static snapshots, journal
metadata, voice replacement space, new live trust-generation and manifest
allowances remain reserved. Inode admission includes the full environment
directory/alias count and temporary construction trees. Initial preparation keeps its existing reservations, and the
late check still measures available space on each actual target filesystem.

An authenticated upgrade can reuse the unchanged pinned Piper environment only
after exact prior/candidate data contracts, protected structure, ABI and bounded
native-user health checks pass. The dependency phase uses the same validator.
Validation runs with a clean environment and stays out of periodic Doctor checks.
A failed later check re-admits full replacement bytes and inodes before creating
a stage or building packages. Remaining operational and recovery-metadata floors
stay reserved, including the separate runtime audio filesystem. File, directory
and standard-alias nodes are counted; snapshots use the recovery filesystem's
allocation units. Missing voices keep their growth space plus a separate atomic
repair peak, including optional packs, up to the complete size of the selected
catalog. Sparse or multiply linked models retain a full replacement allowance.
A fresh Lite installation carries its selected profile into dependency preparation
before the module creates its first configuration file.

Online speech dependency downloads accept the root operator’s HTTP(S) proxy and
bypass settings and protected absolute CA bundle paths. Pip uses the first
configured value in the following order, `PIP_CERT`, `REQUESTS_CA_BUNDLE`,
`SSL_CERT_FILE`, `CURL_CA_BUNDLE`. Set these in the root environment that
starts the installer. Offline package preparation, permission repair and runtime
health checks use the clean environment.

Automatic scratch selection skips volatile `/tmp` and `/var/tmp` installation
workspaces before trying qualified persistent spool storage. Explicitly selected
late paths remain bound and cannot silently move to a different filesystem.

The phone collector continues to update its ledger and heartbeat while install
workers are guarded. Permission repair takes each file's permanent writer mutex
and leaves already-correct metadata alone. Only exact collector temporary names
may disappear during this walk; missing canonical files, lost mutexes, unsafe
links and mount changes remain errors. Recognized legacy heartbeat/display
caches are validated under their original mutexes before their modes are repaired.

The signed voicemail helper is installed and checked with the other protected
phone runtimes. Voicemail itself remains optional: SLL does not require an enabled
mailbox to install, create mailboxes, modify FreePBX voicemail policies or open a
new service. Weather/Lightning and live paging default to voicemail fallback only
for eligible internal mailboxes. Review the independent controls and the existing
mailbox length/capacity policy during acceptance. Installer and manual alert probes
do not leave voicemail.

Native legacy cron cleanup requires a complete successful read. A timeout,
permission error or partial read leaves existing entries untouched and stops
installation with a specific message. Only the exact current-user “no crontab”
result is treated as an empty initial configuration.

## FreePBX Framework updates

Before approving a Framework change in **Admin → Module Admin**, compare the proposed version with the SLL advisory on the confirmation page. The v0.2.0-beta installer supports FreePBX 17 with Framework 17.0.33 or later. Stock package checks cover 17.0.33, 17.0.33.1 through 17.0.33.5, and 17.0.34. A new package or a customized installation can need independent review. Keep a verified backup of site branding and other Framework changes.

For a scheduled update or `fwconsole ma` upgrade, check the target version and backup first. These paths run without the Module Admin confirmation page. After updating, SLL maintenance checks the installed files against authenticated packages and the site’s approved changes before refreshing local signatures. If a previously approved custom file disappears or changes, examine the affected paths and restore the approved bytes from backup or review the new site inventory. An administrator can retry signed-package reconciliation with `sudo slsconsole reconcile-stock --online`, or provide independently signed offline packages with `--upstream-packages DIRECTORY`. A successful explicit review schedules signature verification for the next maintenance run, including after restoring approved files on the same Framework version.

## Read-only diagnostics

After installation, run:

```bash
sudo slsconsole doctor
sudo slsconsole doctor --json
```

The doctor reports the detected Asterisk version and the PHP version, handler,
required extensions/functions and service-account check observed through the
local API route. An active collector service is checked separately from its
current authenticated AMI heartbeat. Root inspection verifies the saved release
signature, installed SLL inventory and reviewed Framework/Dashboard inventories;
it reports the release version and artifact/inventory hashes.

The installer also checks the local FreePBX web response before mutation and
after activation. A vendor ionCube loader error returned with HTTP 200 fails
readiness. When changing a PBX to FPM, configure its native vendor loaders for
that SAPI as well as CLI PHP; SLL does not change those global PHP settings.
Redirects and access-controlled routes are reported as limited observations,
without following redirects or supplying web credentials. They still require
an administrator's authenticated browser check. Response bodies are bounded
and excluded from diagnostics and installer logs.

The report also includes prerequisites, Apache configuration, requested resource
allocation and the latest recorded installer phase and stage. Its default probe
uses the deployment profile in the protected central configuration, so a Lite
installation is not evaluated against Standard RAM. Pass `--profile standard`
or `--profile lite` only to inspect a hypothetical profile explicitly. A saved failure
marker is explicitly historical; a later commit marks it superseded, and current
readiness comes from the live checks. JSON output excludes configuration contents,
credentials, PINs, provider tokens and recovery snapshot contents. The Help page
uses the saved phone/desktop capacities. `slsconsole doctor` checks 25 desktops
and 25 phone contacts. To inspect another allocation, pass explicit limits to
the protected doctor helper:

```bash
sudo /usr/bin/python3 -I \
  /usr/local/bin/sls_mass_notify/sls_install_doctor.py \
  --json --desktop-limit 50 --phone-limit 100
```

Doctor checks the operating headroom for the selected workload, including CPU,
RAM, ongoing state and log writes, configuration backups and runtime audio
space. The authenticated installer separately checks its full download,
replacement and recovery workspace before mutation.

Probes have fixed arguments, output limits and deadlines and run concurrently.
Root CLI diagnosis allows up to 15 seconds for signed inventory verification
and the collector probe, and 18 seconds for the resource helper, including its
bounded runtime storage scan. Web and unprivileged reports retain five-second
helper limits and a two-second collector probe within the web caller's existing
ten-second deadline. Collector freshness charges the complete probe time and
any wait for other probes or report assembly before publication. If an initially
healthy sample expires during that work, one final bounded collector observation
uses the same two-second quick or 15-second root CLI limit. Initial failures are
not retried, and a failed or stale refresh cannot reuse the earlier PASS. A
delayed response or parallel check cannot make an old heartbeat appear current.
A timeout remains an incomplete, failing
observation; it does not approve files or declare the PBX healthy.
HTTP probes connect only to loopback, use the local virtual-host name and never
follow redirects or resolve a public address. The local HTTPS prerequisite probe
does not validate the public certificate chain; it only identifies the served
PHP runtime. The doctor does not install packages, change configuration, start
services, run FreePBX hooks, open a new AMI session or contact notification
providers. A web-process diagnostic cannot inspect root-only trust or recovery
snapshots; those checks explicitly direct the administrator to the CLI.

Candidate authenticated local probes require the configured public PBX hostname
to match the effective native `ServerName` or `ServerAlias`. Literal and wildcard
aliases are supported. A sole unnamed virtual host can also qualify when native
Apache and effective configuration independently identify the same unique
route, with no explicit local or inherited server name. This supports manual
installations where Apache infers a different name from the machine hostname.
Competing or unclassified bindings still prevent this exception. Named virtual
hosts retain strict hostname matching. Discovery uses Apache's parsed vhost and effective
configuration dumps, accounting for address specificity, first matching names,
the canonical PBX document root and relevant handler scopes before sending
credentials to loopback. The root installer passes only bounded, sanitized route
authority to the runtime account when included configuration is root-private;
remote destinations and credentials are excluded. Unavailable or ambiguous
authority stops the probe. The installer checks the actual desktop, control API,
served PHP or generated-media path. It uses the same PHP transport as the
module, under the Asterisk service account, and pins the socket to the
selected IPv4 or IPv6 loopback address and port. During rollback the signed
installer supplies this transport from its protected transaction package or
corrected recovery carrier, including when the restored module has an older
helper. A missing or damaged carrier or an unqualified route yields HTTP 000
in the installer verification log. Review that transaction and the native
Apache route for the reported path before retrying.

On a fresh host, use the publisher-authenticated installer's `--inspect` mode
for signed package and stock inventory checks. Inspection may download evidence
into private temporary storage; it does not enroll live trust or activate code.

## Interrupted installations

Protected recovery evidence is stored under
`/var/lib/sls-mass-notify-installer/transaction-<id>`, with root-only directories
and files. The journal is synchronized before protected mutation and at each
recorded stage transition. It retains
the signed candidate, the signed installer, verified bootstrap helpers,
independent stock/previous-release approvals and recovery snapshots across a
reboot. Public module recovery remains on the module filesystem for atomic
renames; the journal records that location.

New module backups use root-private transaction directories below
`/var/www/html/admin/modules/.sls-mass-notify-recovery` on the module filesystem.
A separate native FreePBX ownership exclusion keeps that directory private
when FreePBX starts or normalizes permissions. This installer infrastructure
and its exclusion remain with recovery records after rollback or uninstall;
the ordinary SLL data exclusion is restored or removed separately. Apache also
denies web access to these backups and the older sibling-directory layout.

Recovery of an older backup can recognize native FreePBX ownership and mode
normalization only after checking its original module against the protected
pre-install inventory. It seals the directory and checks the approved bytes
again before restoration. Unknown entries, links, independent code changes and
unsupported ownership remain failures; observed hashes never become approval.

Retained configuration copies and the phone-history/native-registration
baselines are flushed with their containing directories before the journal
authorizes mutation. A failed storage flush stops installation. Original
configuration snapshot temporaries remain until durable retention completes.

Discovery and recovery acquire the existing installation locks before examining
unfinished work. A named, empty, root-owned mode 0700 transaction directory left
before its first journal write is safely recorded as abandoned on the next run.
Unknown contents, unsafe ownership/modes and existing incomplete signed evidence
remain preserved for review. Completed transactions cannot start recovery again,
even when their saved installer is from an older release.

TERM, INT and HUP cause an explicit abort. The installer terminates its own
child work while keeping the worker guard until restoration finishes. Recovery
copies are removed only after a recorded commit, verified rollback or a
transaction that did not begin protected mutation. Incomplete recovery retains
its evidence and blocks the next installation.

If the installer reports an interrupted transaction, preserve its directory
and use the exact location printed in its log:

```bash
bash /path/to/publisher-authenticated/install_release.sh --recover \
  '/var/lib/sls-mass-notify-installer/transaction-<id>'
```

Recovery authenticates the saved installer, package and executable helpers
against publisher evidence. The withdrawn H `0.1.9-beta` installer historically supplied recovery
helpers for earlier unfinished transactions, including an earlier withdrawn package
with the same version. That history does not authorize its use for the currently
blocked target. The published `0.2.0-beta` installer retains corrected recovery logic
and can provide its own independently authenticated carrier. Carrier installer and package are authenticated separately and
retained in a private `recovery-carrier.*` directory. The original signed
artifacts, approvals and operational baseline remain the restoration authority.
Before creating a corrected carrier in the original transaction, the installer
checks the actual authenticated archive, installer, manifest/signature and exact
bootstrap files against available bytes and inodes on that filesystem. A private
snapshot binds the running installer to its signed manifest. Unsafe or changing
inputs, read-only targets and insufficient capacity stop before creating a carrier;
the original transaction is preserved. The prepared-install allocation proof does
not claim to reserve space for an arbitrary future corrected release.
The journal does not approve live file hashes. It does not restore operational
delivery history over newer records. Failed restoration or newer activity that
prevents safe verification requires administrator review.

A valid root-owned legacy `transaction-sequence` file is a counter, not an
unfinished installation. Use only a real `transaction-<id>` directory with
authenticated unfinished evidence. Malformed counters, links and unexpected
permissions still stop admission with a specific diagnostic.

Recovery checks active and pending settings before restoring anything. It
accepts the original configuration or a change whose exact encoded hash was
recorded durably before an installer profile/branding write. The replacement
also proves the limited MFA delta below. Unrelated administrator edits remain
preserved conflicts; retain live settings and original snapshots together.

### MFA consumption during recovery

History admission runs first. Unexplained missing phone rows still return exit 4
before MFA-target preparation or configuration/runtime restoration. This source
correction does not supply missing evidence or record administrator acceptance.

While holding the existing central settings mutex, the installer authenticates
and decodes the protected inputs and permits only increasing integer TOTP
counters for otherwise unchanged enabled, enrolled portal accounts, together
with their associated operator-access revision. Comparison remains type-exact
for every other setting: account IDs/order, permissions, passwords, auth versions,
secrets, recovery codes/state, passkeys and other revision sections. A revision
change alone is not an exception. Existing pending settings can mirror that MFA
progress while retaining unrelated staged values; divergent staged operator
policy remains a conflict. An MFA merge does not invent pending files. Ordinary
exactly approved missing-file restoration retains its existing recovery path.

The original `config.snapshot`, pending snapshot, hashes and
`configuration-intents.json` chain remain unchanged. Future installer writes
first retain their exact ciphertext in protected
`configuration-intent-<sha256>.snapshot` evidence, fsync it, then publish the hash
intention before replacing live settings. This proves an approved intermediate
configuration plus later MFA progress. A legacy hash-only transaction can still
prove a pure MFA delta against its original snapshot; an intermediate without
its corresponding bytes is refused rather than reconstructed by guessing an
encryption nonce or ignoring changed settings.

The derived targets are separate root-private
`configuration-mfa-<sha256>.snapshot` files and a transaction-bound
`configuration-mfa-recovery.json`. Bytes are staged privately, fsynced and
published atomically without replacing a contradictory existing image. Strict
ownership, modes, link counts, no-follow reads, bounds and stable identity checks
remain mandatory. Every restore and final configuration check uses the validated
target. A crash can resume before or between restores, and another valid MFA
login after a failed attempt advances the retained cursor monotonically.

An existing `.sls-immediate-settings-transaction.json` blocks this merge before
configuration mutation. Preserve that journal and both settings files for
coordinated recovery; never delete it or reset a counter to bypass refusal.

Verified rollback records a distinct `mfa_recovery` receipt and retains original
settings, intention ciphertexts, derived targets, publisher artifacts and carrier
authentication evidence. Later transaction creation/pruning must preserve those
bytes and refuse tampering. This archive is not an administrator-accepted
history-loss receipt and grants no permission to restore delivery history or
approve unrelated configuration changes. These behaviors have focused fixture
coverage and signed native crash/retry coverage using a complete matching backup.
The user later reported successful 0.1.10 installation and explicit acceptance of
the actual target's missing history. That is separate from this matching-backup
fixture and does not prove expiry or qualify new 0.1.9 artifacts.

### Phone history during installation

The installer holds an exclusive retention lease while notification workers
are paused. The collector can update its heartbeat and ledger while pruning is
deferred. New transactions retain protected closure times and a complete,
root-private copy of their baseline's closed records in `history-evidence.json`.
The copy is taken under the collector's permanent mutex, matched against every
original baseline hash, and synced before mutation. It is evidence for history
verification, never an operational restore source. Modified closed
records, missing nonexpired records and active voicemail dependencies still
prevent completion. Final checks require an existing ledger and a fresh
collector heartbeat, with a bounded wait for startup or a guarded cron worker
to exit.

An early withdrawn `0.1.9-beta` installer could let retention prune closed
records after taking its baseline, then fail both installation and rollback.
That explains a possible failure mechanism, not the cause of any individual
missing record. Its hash-only baseline cannot establish when a missing record
closed or why it disappeared. First seek a genuine pre-upgrade ledger copy in
site snapshots, private installation evidence or offsite backups. A FreePBX
configuration backup does not necessarily contain the phone ledger. For a
matching copy, use:

```bash
bash /path/to/publisher-authenticated/install_release.sh --recover \
  '/var/lib/sls-mass-notify-installer/transaction-<id>' \
  --history-evidence '/root/pre-upgrade-phone-admission.json'
```

The copy must be a private root-owned regular file under protected directories.
Only complete closed records matching the original baseline hash can prove
retirement after the seven-day limit. Matching facts from separate backups can
accumulate across recovery attempts; unmatched backup records grant no approval.
The verifier does not copy this evidence over the live ledger. Without enough
matching evidence, recovery preserves the transaction and leaves root SLL jobs
disabled. Preserve backups and the failed installer log; do not reset history or
delete the transaction to bypass the check.

Recovery also retains complete current closed records which still match the
original hashes. These facts protect the surviving history if an older
collector expires it during recovery. They do not explain any record already
missing. The original baseline and live ledger remain unchanged.

### Review when legacy history cannot be proven

Ordinary recovery now checks history before repeating static restoration. An
unexplained missing record leaves the transaction unfinished, returns exit 4,
and prints the location of a protected review. It does not create a new
baseline or enable root maintenance jobs. Collector health may be deferred
during this preflight; final recovery still requires a fresh healthy collector.

Generate a report without restoring files or changing maintenance schedules:

```bash
bash /path/to/publisher-authenticated/install_release.sh --recover \
  '/var/lib/sls-mass-notify-installer/transaction-<id>' --review-history
```

Add `--history-evidence '/root/pre-upgrade-phone-admission.json'` to check a real
backup. Matching evidence may accumulate across attempts. The report separates
unchanged records, proven expired records, unexplained loss and blocking changes.
The protected `history-loss-review.json` binds the original signed artifacts,
exact transaction directory, original baseline bytes and missing record hashes.
Review its counts and `review_sha256` before deciding what to do.

The administrator subsequently accepted missing history for the reported LiteNet case, according to the user's successful-installation report. Preserve that decision and its transaction binding; do not apply it to another transaction.
The following documents the separate explicit loss-decision mechanism; it is
not an instruction or approval to use it for that target. If no matching
evidence can be found, an administrator can separately accept
the **unverified historical loss**. This is a recorded loss decision; it does
not reconstruct missing history or prove retention expiry. Replace the three
placeholders below with the exact reviewed SHA256, administrator identity and
reason:

```bash
bash /path/to/publisher-authenticated/install_release.sh --recover \
  '/var/lib/sls-mass-notify-installer/transaction-<id>' \
  --approve-history-loss 'REVIEW_SHA256' \
  --history-loss-operator 'ADMINISTRATOR_NAME' \
  --history-loss-reason 'REASON_AFTER_REVIEWING_AVAILABLE_BACKUPS'
```

The installer authenticates the original evidence again and requires the
review to match the current missing set. It cannot accept modified records,
known nonexpired loss, a missing live ledger, pending reconciliation or active
voicemail dependencies. A receipt for another transaction or baseline fails.
Final verification counts accepted missing records separately from proven
expired records. Later matching evidence may narrow the unverified portion;
it cannot extend the approval to a newly missing record.

After all restoration and health checks pass, recovery durably records
`rolled_back`. Manually recovered transactions retain their original baseline,
signed artifacts and recovery evidence, including evidence-only recovery with
no accepted loss. A separate loss receipt is retained when applicable. These
private archives are excluded from automatic installer cleanup.
Retain a private archive. A later publisher-key expiry or revocation does not
delete this passive archive or turn it into execution authority. Active recovery
still enforces the current publisher policy. Start a fresh upgrade only after
verified recovery has completed; recovery itself never starts another upgrade.

### Custom Asterisk builds

This module installer does not reinstall Asterisk packages by default. Already
available capabilities work with supported source-built Asterisk installations.
If a required provider is missing, repair it through that PBX's normal Asterisk
maintenance process. Keep its build options, module ABI and service management
consistent; do not mix distribution modules into a custom build.

For a distribution-managed PBX only, the separate explicit environment option
`SLS_MASS_NOTIFY_REPAIR_ASTERISK_PACKAGES=1` permits the existing exact-version
provider repair. It additionally requires matching installed binary/provider
package versions, protected package checksums and matching installed and running
Asterisk bytes. Package ownership alone is insufficient. The check repeats
after repository refresh before any repair. Unverifiable or custom binaries
are refused; the default is `0`.

New installation snapshots also preserve the scoped native Manager database
rows. Rollback restores their original identities and regenerates native
Manager configuration before restarting the collector. Unrelated accounts and
independent edits are preserved; older snapshots cannot supply database state
they did not record. Module-tree restoration is idempotent across either rename
and verifies the old tree before re-enabling its root maintenance schedule.

An earlier `0.1.6-beta` installer omitted ownership, permission, collector and
coordination stage names from its transaction allowlist. Those copies can exit with code 2 while their
journal remains in `prepared` phase. Recover that retained transaction with
the command above, then rerun the normal corrected installer. A prepared
transaction is not disposable: its signed evidence and any native-permission
snapshot are checked before completion. The supported recovery stage is also
recognized by the earlier helper. Do not edit its allowlist, replace its saved
installer or delete the transaction directory to bypass recovery.

New stage transitions are recorded before replacing the last successful stage.
If recording fails, restoration can still record completion against that
previous stage. Active and pending settings snapshots remain available through
all postconditions and are removed only after durable completion.

An interruption before complete signed evidence was saved, an expired/revoked
release, lost recovery media or unknown modifications can require manual
review. Keep the installer log and snapshots; do not remove the transaction
directory merely to bypass the retry guard. Successfully completed generations
retain small audit markers; older completed markers are bounded separately
from unfinished recovery evidence. If interruption occurs after durable commit
but before cleanup, the next admitted transaction removes only known completed
evidence inside that generation. Unknown files require review; unfinished
recovery sources are never pruned.

## Missing stock Dashboard

An absent Dashboard can be staged from an independently verified official
GPG package before SLL maintenance changes. Its installation hooks run as
`asterisk`. Existing Dashboard files are never replaced by this bootstrap.
Unknown local differences still require reviewed inventories.

The installer discovers the available Dashboard version through FreePBX's
module metadata without invoking `ma listonline`, which can trigger unrelated
automatic updates. For offline installation, select the exact supplied version:

```bash
export SLS_MASS_NOTIFY_BOOTSTRAP_DASHBOARD_VERSION=17.x.x
```

Supply the corresponding official `dashboard-17.x.x.tgz.gpg`. An invalid,
expired or unapproved upstream signature is rejected before staging it.

## Offline support bundles

Prepare this directory on a trusted machine:

```text
bundle/
  install_release.sh
  slsmassnotifyserver-<version>.tgz
  release-manifest.json
  release-manifest.sig
  upstream/
    dashboard-<exact-version>.tgz.gpg
    framework-<exact-version>.tgz.gpg
  assets/
    wheels/    # complete CPython 3.11 / amd64 hash-locked wheelhouse
    voices/    # every pinned voice and voice JSON from the candidate catalogue
  previous/    # required if prior publisher evidence is not already enrolled
    install_release.sh
    slsmassnotifyserver-<previous-version>.tgz
    release-manifest.json
    release-manifest.sig
```

Keep the directory root-owned and protected from other users' writes.
`tools/prepare_offline_install.py /path/to/bundle` verifies release signatures,
artifact hashes, pinned voices, complete compatible wheel resolution and official
stock package signatures. `--print-environment` prints shell-quoted installer
paths for the reviewed bundle. The installer repeats its own verification.

The 0.2.0-beta preparation tool requires both Framework and Dashboard
stock packages. Pass `--framework-version VERSION --dashboard-version VERSION`
to check the bundle against the exact versions needed by a target PBX. Without
both requirements, successful verification describes the supplied packages; it
does not establish completeness for an unspecified installation. For each
selected optional voice, pass `--optional-voice-pack PACK_ID` (at most two).
Both the model and its configuration must match the authenticated catalogue.
These options do not read or change a target PBX's configuration, and the
installer still enforces its own protected publisher policy.

The Piper dependency phase uses `--no-index` with the supplied wheelhouse and
copies voices only after the existing size and SHA-256 checks. It does not fall
back to internet downloads when an explicitly selected offline asset is absent.

The bundle does not replace Debian's package trust. Required Debian packages
must already be installed or available through a separately authenticated APT
mirror. Include the exact installed stock versions rather than the newest
available versions. A bundle index alone is never installation authority.

## Complete FreePBX VM qualification

`tools/qualify_installer_vm.py` and the manually dispatched
`installer-vm-qualification.yml` workflow exercise real FreePBX installations
outside the production PBX. They require an independently reviewed standalone
qcow2 image, a signed offline bundle and explicit disposable-VM opt-in.

The image must contain only a sanitized test PBX, its prerequisites and this
marker:

```text
/etc/sls-qualification-vm:
SLS_DISPOSABLE_QUALIFICATION_ONLY
```

Each scenario uses a new overlay. Guest outbound networking is disabled; SSH
is forwarded only to the controller's loopback interface. The harness checks
the declared fresh or 0.1.4-beta through 0.1.8-beta baseline, protected settings, installer
completion, reload and doctor results. Scenarios cover installation, inactive
cron, absent Dashboard, TERM/INT/HUP and an abrupt VM power interruption followed
by authenticated recovery and retry. Power interruption tests require a VM;
they are not simulated by editing an EXIT status.

The ordinary isolated fixtures remain valuable for malformed packages,
permission boundaries, split mounts, low space, PHP configuration, idleness,
rollback and retained history. They do not establish full-PBX VM compatibility,
provider delivery, physical endpoint behavior or load certification. Record
actual qualification results before expanding the supported deployment matrix.

## Recognized legacy permission recovery

Desktop-journal lock ownership and recognized legacy permissions are normalized while holding the permanent exclusive lock. The H correction rechecks the named inode and file safety after acquiring that lock, so a cooperating migration cannot cause simultaneous writers to fail their metadata comparison. Unknown replacements and unsafe paths remain rejected; preserve the journal and permanent lock when reviewing a failure.

An older FreePBX chown/startup run can leave `enterprise-worker.lock`, `phone-admission.lock` or `phone-admission.json` publicly readable at mode `0644`. The installer authenticates the previous release before recovering recognized files to `0640`. The same bounded pass checks the active/pending central configuration and its permanent locks when native chown changed their modes. Configuration is decoded with the authenticated crypto helper before any permission changes; ciphertext, keys and saved settings are not rewritten. It validates the directory and open file descriptors, rejects symbolic/hard links, unexpected ownership, oversized or malformed state, and preserves journal bytes and lock inodes. It does not erase admission history or delete locks.

Copied or restored central settings may be owned by root rather than Asterisk, or may lack `mass-notifications.config.lock`. The installer accepts only known root/Asterisk UID and GID combinations at modes `0600`, `0640` or `0644` for the active/pending settings and empty mutex. It authenticates and decodes every present settings file before creating an absent mutex, then normalizes recognized ownership in place. This also permits a signed fresh-install retry containing valid settings. Other runtime files retain their stricter ownership and previous-release approval checks. A new empty private mutex is retained if a later prerequisite fails, so retry uses the same inode. Existing mutexes, configuration bytes and encryption keys are never replaced by this repair.

The authenticated worker keeper holds the configuration mutex until completion or recovery; it validates the current directory and mutex before and after acquisition. Unsafe files are rejected without blocking on FIFOs or adopting hard links. Active editors have a bounded wait. Failure markers identify publisher approval, legacy permission recovery, previous collector recovery or worker/configuration coordination separately. Review the first specific error in the protected installer log. Successful final verification clears the installation marker; manual permission changes alone do not establish a successful installation.

A managed entry in `/etc/asterisk/freepbx_chown.conf` excludes only `/var/lib/asterisk/SLS_Mass_Notifications_Plugin` from recursive permission normalization. Existing unrelated settings remain intact. Conflicting custom SLL permission directives require administrator review. Managed changes have private recovery evidence; concurrent administrator edits are not silently overwritten.

After recovery, the installer verifies the approved collector service and a fresh authenticated heartbeat before acquiring notification-worker guards. It can start an approved, enabled inactive collector; disabled, masked or custom service states require review. Do not delete a ledger, loosen runtime checks or repeatedly restart FreePBX to bypass a failed readiness check. Preserve the specific diagnostic and installer recovery locations instead.

On a normal service stop, the phone collector clears its live heartbeat, records a disconnected dashboard status and preserves closed batches. New phone audio admissions require a fresh authenticated heartbeat after restart. If the process is killed before it can record a stop, its last heartbeat expires after 15 seconds.

An older collector may have a voicemail fallback pending in a closed phone batch. Upgrade preflight refuses that still-eligible, unexpired fallback before activation; let it finish or expire, then retry. It does not claim or erase the fallback. Current collectors coordinate voicemail submission and recording cleanup with the same worker guards.

## Legacy Python-cache quarantine

Earlier installers can stop with `Previous runtime changed after preflight; no additional files were approved` immediately after reporting `quarantined_caches: 1` or more. They remove recognized legacy Python caches during permission preparation, then incorrectly require those same caches during the next runtime verification.

Current installers recognize completed or partially completed quarantine only when the protected `runtime-cache-recovery/inventory.json` matches the original approval and the saved cache bytes match their recorded hashes. Each check still verifies authenticated source files and rejects unknown runtime files, unsafe recovery entries and changed caches. Quarantined bytecode never receives execution or rollback approval. Completed quarantine evidence is left intact.

Keep the publisher-authenticated installer and package recorded in the retained transaction. The `0.2.0-beta` repair installer can supply its own authenticated recovery carrier as described in [Interrupted installations](#interrupted-installations); it does not replace older signed evidence or approve arbitrary live files. Do not substitute retired uppercase V0.1.9-beta or withdrawn v0.1.10-beta downloads. After recovery, run the intended target release as a new installation. Missing or changed quarantine evidence requires review rather than manual cache deletion or new live-file approvals.

## Included offline removal

Removal records its preparation, teardown and verification stages in a private
transaction under `/var/lib/sls-mass-notify-uninstaller`. Failed attempts retain
authenticated local retry helpers and configuration recovery locations. Completion
is recorded after teardown postconditions, not merely after deleting the runtime.
Only recorded workspaces are cleaned; unrelated `/tmp` files remain untouched.

Run `sudo slsconsole uninstall` or the included `/usr/local/bin/sls_mass_notify/sls_mass_notify_uninstall.sh`. Removal does not download packages or require the installed `sls_privileged_install.py`, speech engine or collector to be healthy. It authenticates fixed teardown helpers against the retained publisher generation and checks independently approved Framework/Dashboard inventories. It drains notification workers under private leases before changing services or removing files, and refuses active phone delivery. It preserves configuration, media, history, logs and recovery keys by default. Purging data is a separate destructive option.

Both crontabs are read and checked before SLL entries are removed. Unexpected read/write failures retain private originals and require review; unrelated jobs are preserved. Retry accepts only exact approved installed or uninstall stock variants. An absent SLL directory must also have an independently checked absent module registry entry. Unknown partial file changes remain a review boundary.

If a late failure removed the command itself, the signed uninstaller remains under the active retained generation, at `/var/lib/sls-mass-notify-trust/<generation>/module/bin/sls_mass_notify_uninstall.sh`. Run that retained script with Bash after reviewing the reported recovery location. Do not substitute an arbitrary live inventory. A stopped PBX is not started. Software removal and a failed final PBX reload are reported separately.

Before deleting Manager records, removal saves a root-private immutable plan of only accounts whose secret hash, loopback ACL and permissions prove SLL ownership. Native read-only account-absence checks then report `verified_absent`, `daemon_absent` or `pending_unverified`. These inspect configured Manager users only. [Asterisk preserves previously authenticated sessions across reloads](https://github.com/asterisk/asterisk/blob/22.11.0/main/manager.c#L2186); account absence does not prove those sessions ended, and this read-only check does not inspect or disconnect them. A failed or unknown CLI response never proves absence. Software removal may still finish after a reload warning, but its output and retained `ami-revocation.json` explicitly state that a loaded SLL Manager account may remain. `daemon_absent` describes the current stopped state; it does not certify a later startup. No unrelated Manager account is removed or disconnected by these checks.

Pending plans survive retries and purge. An empty plan from a later attempt cannot erase an earlier unresolved account. After the desired native `fwconsole reload`, run the exact retained command printed in the log with `--verify-runtime` and its protected uninstall transaction path. This follow-up reads retained ownership evidence and the native CLI only: it does not bootstrap FreePBX, reload services, infer ownership from live names, alter settings or replace the original removal evidence. Its JSON reports the current observation. Keep the original transaction privately even after a successful follow-up.

## Mail and cron safeguards

SLL requires executable local Postfix `sendmail` and `postqueue` supporting `-j` for email. Missing queue evidence disables SLL email with an explicit reason; the installer does not replace an existing MTA. The queue probe stops at 200 records and has a one-second deadline. A private reservation journal limits all SLL submissions before transport, with stricter system-fault and recovery quotas. Accepted or ambiguous mail is not automatically replayed.

All five SLL cron entries use the fixed `sls_cron_runner.py` job names and end in `>/dev/null 2>&1`. Child output is captured in private `cron-diagnostics/<job>.jsonl` files, bounded to 1 MiB each with a 64 KiB output tail. Excessive output and fixed job timeouts terminate the child group. Interpreter/logging failures cannot become cron email. Existing unrelated cron and Postfix settings are not changed.

## Beta acknowledgment

The warning appears on each FreePBX administrator's first authenticated page visit after the mandatory wizard or upgrade. Each account must agree separately; later logins do not repeat it while that account's receipt matches the current warning revision. Existing single receipts apply only to their recorded administrator. It cannot be dismissed with a close button, Escape or backdrop click. Its confirmation requires five visible seconds and a server-side five-second session challenge. The receipt is saved in encrypted active/pending configuration without enabling any feature. The Enterprise Labs warning waits until beta acceptance has been saved. This warning does not prevent command-line removal.

### Root-generated voice-selection cache

The optional voice-selection reader now suppresses Python bytecode generation.
Older installers could leave `/usr/local/bin/sls_mass_notify/__pycache__` owned
by root with no PBX traversal permission, making the General Settings resource
check report unreadable storage after installation. Authenticated repair uses
its existing protected cache quarantine and keeps the original bytes as review
evidence. Do not widen permissions or execute quarantined bytecode. Verify the
resource result in General Settings as well as `slsconsole doctor` after repair. The doctor also runs its resource helper as the PBX account when started by root; its broader installer inventory checks retain their root-only authority.
