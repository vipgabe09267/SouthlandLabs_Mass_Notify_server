# Installer diagnostics, recovery and qualification

The V0.1.9-beta release is withdrawn and its downloads have been removed. The source candidate is unpublished; 0.1.8-beta remains the available published prerelease. Installation, repair and upgrade commands await a corrected signed release. Preserve any existing failed transaction; the generic recovery examples below document the protocol and do not authorize executing withdrawn assets.

The reported actual LiteNet recovery has 22 baseline records, 1 unchanged, 21 missing and 0 with proven expiry. Ordinary history recovery must continue to refuse with exit 4; no loss acceptance exists. Separately, changes limited to `totp_last_counter` and the `operator_access` revision trigger the configuration hash guard. Do not overwrite live settings, mask those changes, replace history or manually approve loss to force completion. No successful target recovery or replacement fix is established. See [qualification boundaries](QUALIFICATION_MATRIX.md).

Activation reloads Apache and each independently qualified PHP-FPM version. This
refreshes their separate opcode caches without changing PHP settings or restarting
Asterisk. Rollback refreshes FPM after restoring the approved files. The local,
read-only API probe reports its compiled SLL version; installation fails clearly
if the serving handler still runs a previous release or its reload fails.

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

Required native module floors are Framework `17.0.33`, Dashboard `17.0.5`, Backup `17.0.13` and Recordings `17.0.6`. Existing older or unqualified registrations stop before an SLL transaction starts; update them through native Module Admin and retry. SLL does not run an automatic `upgradeall`. These reviewed floors cover the vendor advisories cited below and do not certify the entire host as vulnerability-free:

- [Framework reviewed security fixes](https://github.com/FreePBX/framework/blob/release/17.0/module.xml)
- [Dashboard fixed version](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-hw7v-v2jp-wc4v)
- [Backup fixed version](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-5457-hm39-pcfc)
- [Recordings fixed version](https://github.com/FreePBX/security-reporting/security/advisories/GHSA-9cjf-xw9x-55hh)

The exact locked NumPy wheel requires x86-64-v2; AVX is optional. CPU count and RAM alone do not establish this capability. Admission checks every CPU allowed by process affinity and accounts for cgroup limits using the actual mount root and membership path. An unresolvable hierarchy stops admission instead of assuming host resources are available.

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

Probes have fixed arguments, output limits and deadlines and run concurrently.
HTTP probes connect only to loopback, use the local virtual-host name and never
follow redirects or resolve a public address. The local HTTPS prerequisite probe
does not validate the public certificate chain; it only identifies the served
PHP runtime. The doctor does not install packages, change configuration, start
services, run FreePBX hooks, open a new AMI session or contact notification
providers. A web-process diagnostic cannot inspect root-only trust or recovery
snapshots; those checks explicitly direct the administrator to the CLI.

Authenticated local probes on custom ports require the configured public PBX
hostname to match the site's native `ServerName` or `ServerAlias`. Literal and
wildcard aliases are supported. Apache omits aliases from its compact single-site
inventory, so SLL may perform a second bounded configuration-test command with a
temporary command-line virtual host to obtain Apache's expanded alias inventory.
This changes no files, listeners or running services. The synthetic site grants
no credential authority; failed discovery never sends credentials to an unrelated
custom-port site.

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
blocked target; a corrected carrier remains pending. Carrier installer and package are authenticated separately and
retained in a private `recovery-carrier.*` directory. The original signed
artifacts, approvals and operational baseline remain the restoration authority.
The journal does not approve live file hashes. It does not restore operational
delivery history over newer records. Failed restoration or newer activity that
prevents safe verification requires administrator review.

A valid root-owned legacy `transaction-sequence` file is a counter, not an
unfinished installation. Use only a real `transaction-<id>` directory with
authenticated unfinished evidence. Malformed counters, links and unexpected
permissions still stop admission with a specific diagnostic.

Recovery checks active and pending settings before restoring anything. It
accepts the original configuration or a change whose exact encoded hash was
recorded durably before an installer profile/branding write. Later administrator
edits are preserved and reported for review. The reported target shows that
normal MFA replay-counter and operator-access revision changes can also reach
this guard; distinguishing those semantics safely remains unresolved. Do not
replace the live settings merely to get past this check; retain both the live
file and original snapshot.

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

No administrator has accepted missing history for the reported LiteNet case.
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

An older collector may have a voicemail fallback pending in a closed phone batch. Upgrade preflight refuses that still-eligible, unexpired fallback before activation; let it finish or expire, then retry. It does not claim or erase the fallback. Current collectors coordinate voicemail submission and recording cleanup with the same worker guards.

## Legacy Python-cache quarantine

Earlier installers can stop with `Previous runtime changed after preflight; no additional files were approved` immediately after reporting `quarantined_caches: 1` or more. They remove recognized legacy Python caches during permission preparation, then incorrectly require those same caches during the next runtime verification.

Current installers recognize completed or partially completed quarantine only when the protected `runtime-cache-recovery/inventory.json` matches the original approval and the saved cache bytes match their recorded hashes. Each check still verifies authenticated source files and rejects unknown runtime files, unsafe recovery entries and changed caches. Quarantined bytecode never receives execution or rollback approval. Completed quarantine evidence is left intact.

Keep the publisher-authenticated installer and package recorded in the retained transaction. The corrected `0.1.9-beta` authenticated repair installer can supply its own separately verified recovery carrier as described in [Interrupted installations](#interrupted-installations); it does not replace the older signed evidence or approve current live files. After recovery, run the intended target release as a new installation. Missing or changed quarantine evidence requires review rather than manual cache deletion or new live-file approvals.

## Included offline removal

Removal records its preparation, teardown and verification stages in a private
transaction under `/var/lib/sls-mass-notify-uninstaller`. Failed attempts retain
authenticated local retry helpers and configuration recovery locations. Completion
is recorded after teardown postconditions, not merely after deleting the runtime.
Only recorded workspaces are cleaned; unrelated `/tmp` files remain untouched.

Run `sudo slsconsole uninstall` or the included `/usr/local/bin/sls_mass_notify/sls_mass_notify_uninstall.sh`. Removal does not download packages or require the installed `sls_privileged_install.py`, speech engine or collector to be healthy. It authenticates fixed teardown helpers against the retained publisher generation and checks independently approved Framework/Dashboard inventories. It drains notification workers under private leases before changing services or removing files, and refuses active phone delivery. It preserves configuration, media, history, logs and recovery keys by default. Purging data is a separate destructive option.

Both crontabs are read and checked before SLL entries are removed. Unexpected read/write failures retain private originals and require review; unrelated jobs are preserved. Retry accepts only exact approved installed or uninstall stock variants. An absent SLL directory must also have an independently checked absent module registry entry. Unknown partial file changes remain a review boundary.

If a late failure removed the command itself, the signed uninstaller remains under the active retained generation, at `/var/lib/sls-mass-notify-trust/<generation>/module/bin/sls_mass_notify_uninstall.sh`. Run that retained script with Bash after reviewing the reported recovery location. Do not substitute an arbitrary live inventory. A stopped PBX is not started. Software removal and a failed final PBX reload are reported separately.

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
