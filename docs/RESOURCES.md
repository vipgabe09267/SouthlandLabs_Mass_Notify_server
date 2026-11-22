# Capacity, storage and retention

The installer and General Settings use the same combined PBX/SLL resource policy.
These are engineering admission budgets, not load certification. Existing calls,
codecs, transcoding, conferencing, recording and backups need their own margin.

## CPU and memory

Standard mode is the default. Its initial **25 desktops and 25 phone contacts**
require **2 effective CPU cores and 4 GiB RAM**; the baseline includes up to 50
desktops and 100 contacts. For ordinary PBX traffic or call recording, allow at
least 4 cores and 8 GiB.

Standard remains the default. Below its 4 GiB RAM baseline (with bounded kernel reservations), the interactive installer offers Lite only after checking all Lite prerequisites. The displayed limits require explicit acceptance; No, EOF or a 120-second timeout cancels. Unattended callers must pass `--lite` explicitly. A Standard-capable host cannot select Lite.

The signed installer's `--lite` profile admits a nominal 2 GiB host only
at 1–25 desktops and 1–25 phone contacts with two effective CPU cores. It fixes
speech at one renderer and at most two waiting jobs, permits four simultaneous
SSE streams, uses one Weather/Lightning delivery worker and two Weather.gov fetch
workers. Enterprise Labs and enterprise SSO are unavailable in Lite. Their saved configuration and credentials are retained, but activation, administrator actions and PHP/Python runtime entry points are blocked. Returning to Standard does not automatically reactivate these features.

Lite mode keeps the same local authentication, encryption, journaling, storage,
signature and rollback checks. It never truncates detected contacts or recipients.
It is an engineering admission profile for low-volume beta testing, not measured
throughput certification. Switch profiles only through the verified installer;
configuration import and restore cannot bypass resource admission.

| Desktop limit | Required cores / vCPUs | Required RAM | Recommended cores / RAM |
| --- | --- | --- | --- |
| 1–50 | 2 | 4 GiB | 4 / 8 GiB |
| 51–100 | 3 | 5 GiB | 4 / 8 GiB |
| 101–250 | 4 | 6 GiB | 6 / 10 GiB |
| 251–500 | 6 | 8 GiB | 8 / 12 GiB |
| 501–1,000 | 8 | 12 GiB | 12 / 16 GiB |

For phone capacity `P`, let `extra = max(P - 100, 0)`. Add
`ceil(extra / 200)` cores and `extra × 2 MiB` RAM, rounded up to a
256 MiB block, to the desktop row.

| Phone contacts | Additional cores | Additional RAM | Combined minimum with 50 desktops |
| --- | --- | --- | --- |
| 1–100 | 0 | 0 | 2 cores / 4 GiB |
| 150 | 1 | 0.25 GiB | 3 cores / 4.25 GiB |
| 250 | 1 | 0.50 GiB | 3 cores / 4.50 GiB |
| 500 | 2 | 1 GiB | 4 cores / 5 GiB |
| 1,000 | 5 | 2 GiB | 7 cores / 6 GiB |

For 1,000 desktops and 1,000 contacts, the combined minimum is 13 cores and 14 GiB.
Each registered contact counts separately. A fresh installation counts configured
internal PJSIP devices, including offline devices and additional registrations,
and excludes trunks. Above 25, initial phone capacity rounds up to the next 50:
79 or 89 selects 100; 125 selects 150. Upgrades preserve saved limits.

Checks honor CPU affinity and container quotas. Kernel reservations may reduce
reported RAM by at most 256 MiB, and never more than one sixteenth of the tier.
A cgroup quota below the nominal tier receives no allowance. Scratch on tmpfs
also consumes the RAM budget. CPU and free-space checks have no allowance.
Oversubscribed vCPUs can delay calls and synthesis even when the count passes.

Capacity increases are rejected when resources are insufficient. New desktop
enrollment stops at the saved limit. An audio audience above the contact limit
is rejected; an eligible audience can wait briefly for occupied shared capacity.
Timeouts report failure without submitting that audio. Limits never silently
truncate recipients or delete existing clients.

**General Settings > Phones and address** previews requirements with green checks
and red X indicators. Previewing does not save settings.

## Desktop transport

Under Apache module PHP, Standard mode allows 32 simultaneous SSE connections,
with two per desktop username. Lite mode allows four, with one per username.
PHP-FPM does not hold streaming workers: it returns
`stream_capacity_reached` with `reason: php_fpm_worker_pool` and a 300-second
`Retry-After`, and clients use authenticated cursor-aware JSON polling.
The reviewed app falls back to authenticated five-second JSON polling after a
stalled or throttled stream. Normal polling, acknowledgments and stream requests
share a 120-request-per-minute budget per username. Failed-login protection is
separate, so desktops sharing one public IP do not share normal traffic limits.
Throttled responses include `Retry-After`.

The identity and limiter stores support up to 1,000 clients. Test fleet size,
burst rate and PBX call load together; this is not a 1,000-device certification.

## Runtime audio temporary space

Audio generation still uses `/tmp`, including Weather/test speech files and
composition. Installer scratch can fall back to `/var/tmp`; that does not move
these runtime files. The installer, General Settings and doctor now check both
locations separately before reporting resource readiness.

The runtime check preserves the configured `generated_media_min_free_mib`
floor and reserves the supported 600-second render bound for each configured
renderer. With the default 128 MiB floor this requires about 221 MiB free in
`/tmp` for one renderer, or 499 MiB for four. Lite uses one renderer. A custom
free-space floor increases this requirement. `/tmp` must be writable and
traversable by the PBX account, with safe ownership and permissions, free inodes
and a writable mount. An undersized mount is rejected before installation
changes anything; increase it or free space and retry. Active rendering and
other PBX workloads can still consume space after a successful preflight.

## Additional free workspace

SLL checks **additional free headroom**, not total disk size or a fixed partition
minimum. Existing managed trees are measured again on each check. The installer
distinguishes runtime, preparation and installation budgets and reports every
component, path, required byte count and inode requirement.

| Component | Reserved workspace |
| --- | --- |
| Runtime replacement | Complete measured/reference environment files, directories and standard aliases plus signed helper payload; qualified unchanged-environment reuse keeps helper promotion space. |
| Voices | A qualified install hashes the selected models and metadata against the signed catalog. Only pending files require target space and download scratch. Without verified content, admission keeps the catalog growth and atomic replacement allowance. |
| State and configuration | Phone/Weather journal replacements; actual schedule journal or its 10 MiB backup limit; a 3 MiB encrypted write; up to 25 concurrent 2 MiB job writes; remaining space for 20 retained 3 MiB config backups. |
| Module, assets, APIs and portal | Measured authenticated destination payloads and per-entry allocation overhead; bounded catalog before verification. |
| Event-log compaction | Two 64 MiB copies; logs are compacted sequentially. |
| Trust generation | Bounded authenticated payload and stock/release manifests on the trust filesystem. |
| Persistent recovery | Private transaction metadata, authenticated sources, protected settings and runtime/API/recording snapshots retained until recovery is verified. |
| Temporary installation | Bounded 52 MiB release download and metadata, extraction, failed-release recovery, wheel downloads, unpacking, old packages and one largest voice download. |
| Package review | Previous/candidate sources, previous-release download, two signed upstream packages, GPG workspace, missing helper repairs and bounded cache quarantine. |

The final upgrade check verifies the protected candidate and previous source
copies. Stock cache checks have their own evidence. A newly approved Dashboard
or Framework release uses its measured signed package size and directory growth
on the cache filesystem. Packages already present need no second copy. Unknown
cache contents retain the full publication budget. Re-verifying upstream
signatures uses the installer temporary filesystem. The writer checks any
interrupted evidence copies on the trust filesystem before retiring a package.
See [installer operations](INSTALLER_OPERATIONS.md).

At final admission, the installer reads each selected core or optional voice
through a bounded descriptor and checks the expected size, SHA-256, ownership,
permissions and file identity. Matching files need no promotion or download.
Changed files still need space for an atomic replacement on the voice volume
and a download on the selected temporary filesystem. These costs add when
both paths share a device. An ordinary readiness check uses the conservative
estimate and does not rehash the voice catalog.

State writes, bounded backup growth and log compaction account for approximately
283 MiB. These are workspaces, not installed size or disk quotas. Sparse/compressed
recovery copies retain the larger source allocation or logical bytes plus
per-entry/directory allocation on the recovery destination; the existing metadata
floor remains reserved. Budgets add only when paths share a filesystem; separate or bind-mounted destinations are
checked by device identity. Persistent SLL paths cannot use tmpfs.

Scratch uses `/tmp`, or `/var/tmp` when the first is too small and the complete
recalculated check passes. Dedicated mounts are checked directly; an unused parent
volume has no separate minimum. Genuine destination or scratch shortages still
block installation before dependency or module changes.

The current voice catalog contains eight models and eight metadata files,
approximately 482 MiB total. The complete pinned Python 3.11 reference includes 4,383 regular files,
538 directories and four standard aliases. Its conservative 4 KiB allocation
projection is 220,450,816 bytes; its ten compatible wheels total 77,861,012 bytes.
Filesystem fragments and measured retained trees can increase requirements.
Pip uses compatible binary wheels without a persistent download cache.
At the final authenticated upgrade check, only matching prior/candidate pins,
protected runtime structure, the qualified ABI and clean native-user health
checks can remove an unchanged environment's rebuild and wheel workspaces.
Periodic Doctor/runtime checks do not start these probes. A later failed check
requires full replacement admission before any stage or build write; it keeps
operational, voice, backup, log, remaining module and recovery-metadata floors
on their actual filesystems. Existing source, trust and snapshot copies remain
occupied rather than being charged as new copies again. Directory/alias inode
counts and larger-fragment growth apply to early and replacement admission.
Unsupported wheel availability produces an actionable error.
See [dependency inventory](DEPENDENCIES.md).

## Generated media and history

The combined unused-media cache target defaults to **512 MiB** and accepts
64–4096 MiB, stored as `generated_media_cache_mib` in the central configuration.
Maintenance removes age-expired files first, then oldest unused speech, images
and phone XML above the target. It preserves active/configured/desktop references,
custom recordings and each file's first 15 minutes. Protected usage above target
raises a current warning, cleared by a later healthy measurement. Incomplete
inventories preserve files rather than risk deleting active media.

Speech generation uses a shared bounded queue: Standard defaults to one active
job and eight waiting jobs; Lite fixes one active job and at most two waiting
jobs. Both default to a 15-second wait. Media admission reserves workspace and
leaves at least 128 MiB free. Neither a cache target nor successful admission
guarantees arbitrary workload capacity.

Raw mono 16-bit PCM needs `seconds × voice sample rate × 2` bytes plus a WAV
header; telephone audio needs `seconds × 8,000 × 2`. Ten minutes uses 18.3 MiB
at 16 kHz or 50.5 MiB at 44.1 kHz before conversion and sequence copies.
Allow raw audio, converted speech, final sequence and temporary replacement for
every simultaneous render. Opening and closing tones count toward duration.

Terminal jobs are eligible for cleanup after 30 days, generated images after
3 days and unreferenced generated audio after 15 minutes. Active work, pending
delivery and desktop history can retain media longer. Event logs follow the
configured days; unsafe or oversized records can defer cleanup. Interrupted
compaction retains private recovery evidence and blocks another cleanup until
reviewed. Do not delete this evidence to force cleanup.

Measure retained-byte growth over representative busy days and peak generation
between successful cleanup runs. Add that growth over the chosen retention
window to the measured footprint and workspace. Monitor free space and deferred
cleanup; retention ages are not storage quotas. PBX recordings, voicemail, backups
and operating-system package work need separate provisioning.


### Installation scratch on partitioned hosts

The 0.2.0-beta installer chooses scratch using the full future installation byte and inode budget before it prepares files. It tries qualified `/tmp`, `/var/tmp`, then the fixed protected `/var/spool/sls-mass-notify-installer-tmp`. The third location must use persistent writable storage; its bytes and inodes are combined with other SLL requirements on the same filesystem. Root creates an absent directory only after admission, with mode `0710` and the canonical native primary group. Existing unsafe metadata is preserved and refused. Capacity lost before the final measured check remains a refusal. Lighter inspection does not create this private root, and changing installer scratch never moves or waives runtime audio `/tmp` requirements.
