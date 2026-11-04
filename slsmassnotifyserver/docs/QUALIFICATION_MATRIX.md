# Qualification boundaries

`0.1.9-beta` is the unpublished corrected candidate K, planned lowercase tag `v0.1.9-beta`. Available published prerelease: `0.1.8-beta`. Commands and new signed assets remain unavailable pending qualification/publication. Retired uppercase V0.1.9-beta and withdrawn v0.1.10-beta evidence below do not qualify the rebuilt candidate or establish recovery of the reported actual target.

## Current lowercase-tag 0.1.9-beta correction — 2026-11-04

The user required the software to remain 0.1.9-beta. The correction retains the strict MFA/history recovery changes; no replay counter, credential, key or operational history is reset. New artifacts must bind the lowercase tag and exact package/installer hashes because historical uppercase assets have the same module version/package filename. This pass changes naming/package/signature metadata only. Its full isolated build and planned fresh 0.1.9 plus explicit manual 0.1.10-to-0.1.9 PHP-FPM/HTTPS test require their own completed evidence; no automatic updater downgrade is enabled.

The bootstrap now selects lowercase v0.1.9-beta for new downloads. Its current SHA-256 is `89fb64997bf84ddb427b133effbaf960dd10b847791c4360e9c6749452949c54`. Existing-version equality/downgrade protections remain; the manual authenticated installer provides repair while preserving enrolled publisher policy. Exact generated metadata is rebuilt from module.xml and truthful release status.

| Current K gate | Status |
| --- | --- |
| Recovery fixes retained; version/default/document metadata reviewed | Source preparation in progress. |
| Full isolated build/browser/schema gate | Pending for K. |
| Fresh 0.1.9 and explicit manual 0.1.10-to-0.1.9 PHP-FPM/HTTPS tests | Pending. |
| Signed assets, public readback/provenance and publication | Pending; commands unavailable. |

## Withdrawals and reported actual target

The uppercase V0.1.9-beta release/downloads were withdrawn on 2026-11-03. The v0.1.10-beta release/downloads were withdrawn on 2026-11-04 because that version was outside the user's required version. Their immutable tags/source remain historical evidence and must not be reused or moved.

The user subsequently reported that 0.1.10-beta installed successfully: committed exit 0, 16 doctor checks passed, MFA/settings/keys preserved, signatures valid, five managed cron jobs, 92 endpoints and healthy SSE. The administrator explicitly accepted the 21 missing history records. This is a user-reported target result, not an independently repeated target qualification or proof of expiry. The new 0.1.9-beta naming correction has not yet been tested on that target. Ordinary unknown loss on another transaction still refuses until its own matching evidence or valid explicit decision exists. An accepted loss is not a reconstructed ledger or proof of expiry.

## Historical withdrawn J — 0.1.10-beta, 2026-11-04

J was published with immutable tag v0.1.10-beta and verified public downloads/provenance before withdrawal for the version correction. The exact source/commit, hashes and bounded observed results below remain historical evidence only. They are not qualification of candidate K or permission to use withdrawn downloads.

The earlier **207 focused cases across seven isolated suites passed** through the official namespace wrapper. The subsequent exact-release gate passed **424/424 independent isolated suites**, including required browser/UI and schema validation. The official archive reproduced the signed J package. Source freeze `fb3da7bd27f90e3a88db3b17cc65af4bf9bfb92ba28014c0a8e0a119abc39d8e` contains 3123 files; release commit `b3fbafc2d9304732f45643d5892b7cebdc83931e`, immutable tag `v0.1.10-beta`.

Future installer writes retain exact ciphertext before publishing a hash intention. Durable separate root-private targets and transaction-bound MFA receipts preserve only proved monotonic TOTP counters and associated revisions, together with original configuration/intention/carrier evidence. Unresolved immediate-settings transactions, divergent staged operator policy, credential/recovery-code/passkey changes, malformed counters, unrelated revision changes and unproved legacy intermediate ciphertext remain conflicts.

| Exact-release native scenario | Observed result |
| --- | --- |
| `mfa-history-unapproved-refusal` | Passed. Unknown 21-row history loss: ordinary exit 4, review without acceptance, no MFA target or restoration. |
| `mfa-targets-power-loss` | Passed. Actual QEMU power loss after durable MFA targets, before active/pending restoration. |
| `mfa-recovery-after-new-login` | Passed. New PHP TOTP consumption after reboot; signed old-transaction rollback, latest MFA/pending/key preservation, old doctor 15/15 and replay rejection. |
| `mfa-upgrade-0110` | Passed. 0.1.8 to 0.1.10 upgrade over recovered MFA/pending/key/surviving-history state; actual new-generation authentication. |
| `mfa-unrelated-settings-refusal` | Passed. Unrelated configuration changes remain conflicts; no broad operator-section waiver. |
| `fresh-install-0110` | Passed. Fresh installation from the preserved truly absent-config/module/zero-ledger branch. |
| `lite-2gb-0110` | Passed. Actual 2 GiB Lite profile upgrade, with preserved configuration, pending state, keys and history. |
| `fpm-https8443-0110` | Passed. Native PHP-FPM over HTTPS 8443 with timestamp validation disabled; warmed old handler replaced and served new version verified. |
| `post-activation-rollback-0110` | Passed. Controlled post-activation exit 97, verified rollback and preserved MFA/pending/key/native state. |

The recovery fixture reproduced the old signed transaction with 22 baseline rows, 1 unchanged survivor and 21 unknown missing rows. Ordinary recovery first returned exit 4 before MFA-target preparation or configuration/runtime restoration. Supplying the fixture's **full matching 22-row backup** then established **21 expired** rows and zero unknown loss. An actual QEMU power loss occurred after durable target publication; after reboot and another real PHP TOTP login, ordinary signed recovery returned 0 and `rolled_back`. Latest active/pending MFA counters and revisions, every other setting, key bytes/metadata, the surviving closed row, original evidence and authenticated native state were preserved. Both consumed codes were rejected within their original valid windows, and the next actual code succeeded. The old generation passed 15/15 doctor checks; new-generation install/rollback cases require 16/16. No operational ledger replacement, key reset or history-loss approval was used.

Native Framework may regenerate only the two recognized native cron jobs' allowed schedules/positions; unrelated jobs and bytes/order remain protected. Root SLL maintenance/update jobs are restored only after verified rollback and must match their authenticated original approval. No notifications were sent and no production PBX was installed or repaired. The disposable VM was cleanly stopped after the complete matrix. Fresh, Lite and PHP-FPM/HTTPS tests are bounded native profiles, not a universal topology or every-crash-window guarantee.

| Published artifact | SHA-256 |
| --- | --- |
| Package | `ed167717198282349f89569f39bd7e6b08e3550e9ce8085072caee13d1858d6b` |
| Installer | `27a8a5eec07f5c8e21f8ceba8c1ab12edd39e07388bcc58d9ecf16fe6646a7e0` |
| Manifest | `b83fb63347d68a4226821def91032093abf94bdaf80568c7a771dfb0c412a177` |
| Manifest signature | `4161a68cf8897acf76abb4eebd90aad142d0fb53e7d155e92afbd46549ea9a9a` |

Public readback verified all 9 release assets without GitHub download authentication, matched tagged bootstrap/installer bytes and exercised the real bootstrap downloader/signature verifier without installation. All 4 package/installer/manifest/signature provenance policies matched this repository, tag, source/signer commit and GitHub-hosted runner; the exact release provenance workflow succeeded. Required exact main/tag validation and tag sensor compilation also passed. [Published release](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/tag/v0.1.10-beta).

The immutable tag and signed package retain their original prepublication documentation snapshot. This published-status update belongs to a separate documentation commit on main; it does not change release bytes or move the tag.

At J qualification time, before the later user report, the actual target remained a separate unresolved history gate. The user-reported successful installation and explicit administrator acceptance are recorded above. The disposable matching-backup fixture did not authorize that acceptance or supply the actual target's missing records.

## Historical withdrawn H — 2026-11-03

H was published and its public downloads/provenance were verified before the release was withdrawn. The artifact identities and observed results remain below for evidence review; they do not authorize installation.

Candidate H corrects a real desktop-journal race exposed by G's second tag CI run. Lock ownership and recognized legacy permissions are normalized under the permanent exclusive lock, and the named inode and file safety are rechecked after acquisition. H includes new runtime bytes, installer/package pins, signed metadata and regression coverage; the earlier G release draft was not published.

H source freeze SHA-256: `245943efa556e8e073ef1ce3c6d9927e6726be72110a0ef7caa767b75030f97d`. The freeze contains 3,122 source files. H release commit: `babdb5230e2acdd2e4712063ad19ca77863c1885`; tag: `V0.1.9-beta`. All 3,122 committed and worktree source hashes matched this freeze, all six frozen/nine release asset hashes matched, the publisher signature verified and the deterministic package reproduced exactly. The earlier G commits are separate historical identities. The retained source tag and package are historical snapshots. Their signed bytes and prior public readback do not establish that recovery is suitable for the reported target; the release is now withdrawn.

| H artifact | SHA-256 |
| --- | --- |
| `slsmassnotifyserver-0.1.9-beta.tgz` | `c3086abf251ae5c400ee83b52dac42552a16c7ed8ac6df590a623962c0505dbb` |
| `install_release.sh` | `f367db706fea8c7ecc2983106a39192b07ef4713fd36885576e2b52ba18808ca` |
| `release-manifest.json` | `3118b362db7235abb30949d9c5a5829a1e543b892a73d26227db487796a5abe6` |
| `release-manifest.sig` | `4dc85eb1ecc8f283c96dc87b860e37226486c9bfe8d7d3f30dd85a8e47f86a4c` |
| `install_bootstrap.sh` | `bdf8e32e22a0baeed9a5764f0ade1f6a110fbde686cb8ea5f4f06a026ea1da75` |
| Offline release bundle | `fd46fbac1bff1448b5d808815c6f3f5ec73f37cb5dcdc47fb4b7267f4faa15be` |

These hashes identify H artifacts bound to the completed source, full-suite, native-delta and public-release checks. Publisher signature and established trust checks remain required on each target PBX. The bootstrap remains byte-identical to G.

| Historical H verification gate | Evidence before withdrawal |
| --- | --- |
| Full isolated suite, required browser/UI and schema checks | **Passed: 423/423 independent suites**, including required browser/UI and JSON-schema validation. The official archive matches signed package `c3086abf251ae5c400ee83b52dac42552a16c7ed8ac6df590a623962c0505dbb`. |
| Native install and rollback delta | **Passed: four cases**, covering post-activation rollback, ordinary Standard installation with pending settings, PHP-FPM/HTTPS 8443 and Lite over preserved settings. All four passed 16/16 doctor checks. |
| Installed desktop-journal stress | **Passed: three service-account profiles** — Standard, PHP-FPM/HTTPS 8443 and nominal 2 GiB Lite. These are bounded journal-concurrency checks, not sustained delivery or PBX-load certification. |
| H committed source and artifacts | **Verified.** Exact commit `babdb5230e2acdd2e4712063ad19ca77863c1885`, 3,122 source hashes, six frozen/nine release assets, publisher signature and deterministic package reproduction. |
| GitHub CI | **Passed.** Exact H commit passed [main validation](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/actions/runs/41612842592), [tag validation](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/actions/runs/41612842602) and [sensor compilation](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/actions/runs/41612842525). |
| Public release and bootstrap | **Historically verified, now withdrawn.** Before removal, all nine assets downloaded without GitHub authentication and matched H hashes. The bootstrap authenticated its manifest/installer without executing an installation. |
| Artifact provenance | **Verified.** All four package/manifest/signature/installer policies bound the exact H tag, source and signer commits to the [GitHub-hosted release workflow](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/actions/runs/41615979149). |

The H rollback case deliberately exited 97 after activation and returned `rolled_back`; the other three installations exited 0 and committed. All four preserved active configuration bytes, present pending configuration bytes/captured metadata, keys and retained closed phone-history rows, with unchanged boot and Asterisk process identity. Native Framework regenerated only the two recognized cron jobs' valid schedules/positions; unrelated bytes and their relative order stayed exact. No production notifications were sent, and the disposable VM was cleanly stopped afterward.

On each installed journal profile, eight `asterisk` writers performed four appends each: 32 exact events in a fresh journal and 32 with a legacy `0644` lock. A separate controlled stale-snapshot interleaving with a real locked peer produced one exact event. Final journal/lock modes were `0640`, and existing lock inodes were preserved. Native legacy fixtures were owned by `asterisk`; these cases do not establish native root-owned-lock migration coverage. The installed H runtime ran in private workspaces with read-only operational data, isolated loopback networking and forbidden socket/subprocess transports; no delivery entry points were called.

These H results are a bounded delta following the journal correction. They do not repeat G's entire 18-record native matrix or its 360 focused follow-up tests; fresh crash recovery, source Asterisk and unsupported-CPU cases below remain historical G evidence.

H full-suite skips remain declared: the host timezone catalogue was unavailable; mocked timezone validation and rollback ran, and fixture-specific unittest skips remain in the complete log. This is not a zero-skips claim. Full-gate log SHA-256: `2f212afb0b2f6f21377f715a0ab7769f2472163cf4331f532ad3bbd407e5fdc5`.

The supported adapter is Debian 12 / FreePBX 17 / amd64 / CPython 3.11, standard FreePBX paths and the `asterisk` service account. Reviewed native prerequisite floors are Framework 17.0.33, Dashboard 17.0.5, Backup 17.0.13 and Recordings 17.0.6. Standard requires two effective cores and nominal 4 GiB RAM. Explicit Lite requires two cores and nominal 2 GiB, caps desktops and phone contacts at 25 each, and excludes Enterprise Labs/SSO. Every available CPU must expose x86-64-v2; AVX is optional.

## Historical candidate G — 2026-11-02

The following local results apply to G package `63def4495d03d0e8dc41bafd4ca04e9a4d954c3e60f6582d2d86c8d8a7cb28f0`. A subsequent tag CI run exposed the real desktop-journal race, so G was not published. These historical results are not a complete H native rerun or an H qualification claim.

- **423/423 independent isolated suites passed**, including required browser/UI and JSON-schema validation. The full log retains namespace timezone-catalogue and fixture-specific skips; this is not a zero-skips claim.
- **18 recorded native scenarios passed** in disposable FreePBX VMs. These include expected refusals and related scenario observations; they are not 18 independent complete installations.
- **360 targeted follow-up tests passed**, including the exact 22-to-19 closed-batch expiry regression and a protected counter beside a real failed transaction. All 3,122 frozen source hashes remained unchanged; the deterministic G package, publisher signature and offline bundle matched.

| Historical G native scenario group | Observed result and boundary |
| --- | --- |
| Fresh install and retained-config reinstall | Ordinary signed installation completed with 16/16 doctor checks. Fresh setup created its four required factory recording rows; retained encrypted configuration survived the reinstall after the historical F rollback. |
| 0.1.8 upgrade and controlled rollback | Upgrade completed with 16/16 checks and the exact factory-branding migration. Injected post-activation exit 97 restored active/pending settings, keys, closed history and native state. |
| Fresh interrupted before ledger creation | Installer process-group SIGKILL after durable activation; ordinary recovery returned `rolled_back`, preserving prior configuration/ledger absence and the existing keyring alongside native state and signed originals. |
| Abrupt QEMU stop and reboot | QEMU SIGKILL 0.554 seconds after the armed report; ordinary recovery on the same disk after a different boot returned `rolled_back`. One selected virtual-machine boundary was tested, not physical-host power loss or every crash window. |
| Legacy hash-only history | Six negative/review attempts preserved unknown loss. Partial matching proof still blocked; complete protected evidence verified 16 expired records and restored the old release with 15/15 doctor checks. A separate synthetic administrator decision accepted 16 unverified losses; it did not classify them as verified expiry. |
| Actual Lite resource admission | At nominal 2 GiB, two CPUs and no swap, unattended default, explicit Standard and interactive No all refused before protected mutation. Guest cron was briefly quiescent for exact metadata comparison, then restored before ordinary Lite installation, which passed 16/16 checks. |
| Preserved Lite uninstall/reinstall | Signed removal and reinstall preserved active settings, an actual pending file, key bytes and captured metadata, plus six closed history rows. Pending contained the same valid encrypted values as active, not divergent staged values. Whole-ledger bytes changed with collector bookkeeping. |
| PHP-FPM and HTTPS 8443 | Native PHP-FPM 8.2.35 with ionCube and timestamp checks disabled; ports 80/443 closed. Actual cached content A with disk content B became B after ordinary repair without manual flushing. Existing canonical site, hostname binding, configuration, keys, boot and Asterisk PID were preserved; 16/16 doctor checks passed. FPM reload can close active requests. |
| Source Asterisk 20.7 without AVX | Actual Nehalem CPU met v2 without AVX. Repair passed 16/16 checks and preserved all 302 coherent loaded-build files, binary/module inventory and package database. Native packaged Asterisk 22 was also exercised by the matrix. |
| Unsupported CPU | Actual kvm64 missing required v2 features refused with exit 3 before downstream mutation or NumPy/ONNX/Piper import. The guest scheduler was quiescent only for exact metadata comparison. |

Native Framework reload intentionally regenerates schedules and entry positions for exactly one each of `/usr/sbin/fwconsole util cleanplaybackcache -q` and `[ -e /usr/sbin/fwconsole ] && /usr/sbin/fwconsole ma listonline --sendemail -q > /dev/null 2>&1`. Under the unchanged, read-only-captured default policy, cleanup allows hour 0–5 with its other four fields `*`; the updater allows minute 0–59, hour 8–11, day/month `*` and Saturday. Qualification retained raw crons and explicitly recorded only those valid schedule/position changes; all unknown/admin bytes and their relative order remained strict. Complete crontabs are not claimed byte-identical across reload. FreePBX Module Admin disable is not a verified notification pause control: use `sudo slsconsole stop` and verify admission state before maintenance. The native cron semaphore coordinates participating writers; crontab has no atomic compare-and-swap against direct administrator writes.

Actual kernel cgroup calculations covered ordinary v2, remounted namespace and bind-root topologies in earlier candidate C. The complete resource helper is byte-identical in G. This is bounded component evidence, not a complete G installation under each constrained resource topology.

The protected `transaction-sequence` file is a counter, never a recovery directory. A real failed transaction beside it still requires recovery. Hash-only history cannot prove why records are missing: matching protected evidence or a separate explicit transaction/artifact-bound administrator decision is required. These historical G tests did not recover the actual LiteNet transaction. At the time of those historical G tests the reported target remained blocked. Later user-reported success and administrator acceptance are recorded above; the historical test results are not relabeled.

No production installation or real notifications occurred during qualification. There is no universal-layout, other-OS/architecture, sustained PBX/fleet load, physical handset/provider delivery or every-crash-window claim. Each target PBX still needs read-only inspection, `slsconsole doctor --json` and its own endpoint/provider acceptance.

## Historical qualification records

The following dated records describe earlier candidates and fixtures. Their successes do not replace the exact-release matrix above.

## Native installer incident qualification — 2026-11-01

The incident review used disposable Debian 12 / FreePBX 17 VMs with native
Manager/Core/Dashboard modules, MariaDB, Apache, Asterisk and the SLL collector.
No production configuration was copied into them. All phone endpoints and calls
were synthetic; no physical phones or external notification providers were used.

| Scenario | Observed result |
| --- | --- |
| Withdrawn installer, populated history, 0.1.8 upgrade | Reproduced the exact failure: 22 closed batches became 19; three disappeared and none of the retained records changed. Activation and endpoint/SSE checks passed before history verification and rollback failed. |
| Recovery of that existing failed transaction | New authenticated carrier recovered the same transaction with matching protected pre-upgrade retention proof. Old module, settings, keyring and native registrations were restored; the 19 retained records were unchanged and the two root jobs returned. No ledger rewind or reset. Missing proof refused safely and kept jobs disabled. |
| Upgrade across real retention expiry | A live collector write completed during the install lease while pruning was deferred. The exact retained rows passed final comparison; ordinary pruning resumed after lease release. |
| Failure after activation across real expiry | Controlled exit 97 rolled back successfully, with original settings/keyring/native rows and nonexpired history preserved. |
| Actual abrupt VM power loss after activation | New module-filesystem recovery anchor stayed root-private across native FreePBX startup. Authenticated recovery completed from the existing transaction after reboot. |
| Legacy public-sibling backup after native startup ownership changes | Original protected module approval was checked before resealing the recognized legacy backup; the same failed transaction recovered. Changed or unknown backup contents remain rejected. |
| Repeated same-version repair | Three consecutive complete Apache repairs passed, preserving settings, keyring, closed history and Asterisk PID. |
| PHP-FPM 8.2 with opcode timestamp checks disabled | Upgrade, repair and existing-transaction recovery passed after correcting the disposable FPM fixture's missing native ionCube configuration. Earlier API/history results did not establish GUI health for that incomplete fixture. |
| FreePBX HTTP 200 loader failure | Exact signed installer refused the native ionCube error before creating a transaction or changing code, settings, keyring, history or root jobs. Corrected FPM passed the added GUI health check. |
| HTTPS 8443 only, literal and wildcard ServerAlias | Signed repair and desktop authentication/SSE checks passed with ports 80/443 closed. Credential probes remained bound to the native local virtual host. |
| Boot-mounted 64 MiB noexec/nosuid/nodev /tmp | An earlier candidate completed installation through /var/tmp, but the combined smoke test exposed an insufficient runtime speech reserve. The patched signed installer now refuses this mount before mutation with a specific runtime-audio diagnostic. A separate incorrectly mounted PrivateTmp fixture was recovered after correcting the VM boot mount. |
| Native Asterisk 20.21 and 22.11 | Native installation checks passed on both. Asterisk 20 repair preserved an unrelated private Local call. Missing res_pjsip_notify was restored from the exact installed-version provider package without starting the inactive independent Asterisk service or changing the running daemon PID. |
| Lite upgrade at nominal 2 GiB, no swap | Native upgrade passed. Unattended default, explicit Standard and interactive No all refused without changing settings, keys, module, transaction inventory or root jobs. |
| Native Lite browser | Setup, capacity warning and Enterprise Labs denial checked through actual FreePBX login. UI showed the 25/25 hard limits and unavailable Labs/SSO, with no console errors or horizontal overflow at the tested desktop size. |
| Lite uninstall and preserved-data reinstall | Uninstall preserved encrypted settings, keyring and phone history and left FreePBX/Asterisk running; reinstall preserved the settings bytes and restored two root jobs. |
| Explicit purge followed by cold fresh Lite install | After the 64 MiB admission refusal, a fresh signed install on a 256 MiB noexec /tmp mount rebuilt pinned speech dependencies/voices and passed all 16 checks as the PBX identity. The VM retained two CPUs, nominal 2 GiB RAM and no swap. |
| Bounded combined Lite workload | 25 unique authenticated idle-poll clients, six five-second waves (150 polls), CPU speech to a private WAV and one private Local-only Asterisk call. Poll p95 42.1 ms/max 59.4 ms; available RAM stayed above 910.9 MiB, no kernel OOM events, valid 31.89-second WAV, call preserved then removed. Settings were restored byte-for-byte; no physical/provider notifications. This 25-second smoke is not sustained load certification. |

An early Lite browser pass exposed a root-only generated Python cache that broke
the PBX account's resource check. A regression reproduced it; optional voice
selection now suppresses bytecode generation. Authenticated repair quarantines
the old cache with its review evidence instead of widening its permissions. The native repair passed the actual PBX-account resource check afterward. Root-run doctor now also measures resources as the PBX account, so root traversal authority cannot hide a runtime permission problem.

Historical scenario evidence is retained separately from the public source tree.
Qualification of earlier candidates is recorded by scenario; it does not imply
every discarded candidate passed the complete gate. The subsequently published
H correction is now withdrawn; its earlier local and public checks do not
qualify a replacement release or the reported actual LiteNet recovery.

## Local browser qualification — 2026-10-17

All six browser suites ran with the pinned Playwright/Chromium runtime in private
mount, network and PID namespaces. They covered subscriber-worker CSP, separate
IdP navigation, operator and Labs screens, calendars and recordings, per-admin
beta warnings, 1,000 scheduled browser recipients and voicemail controls.
Desktop and mobile layout assertions passed. The tests used synthetic settings
and inert transports; they did not change the PBX or contact real providers.

The first run exposed two fixture setup errors: an advertised SSO callback that
did not match the private HTTPS origin, and a calendar-name test whose parent
editor was closed. Both fixtures were corrected and passed. Production origin
checks and text escaping were retained.

The SSO fixture also releases its private mounts before later suites. The
35-case legacy-permission suite, including native FreePBX permission handling,
then passed without skips. Missing browser dependencies fail all required
browser gates, including voicemail controls.

## Installer profiles

| Condition | Admission and evidence |
| --- | --- |
| Debian 12 / FreePBX 17 / amd64 / CPython 3.11 | Supported adapter, standard paths and `asterisk` runtime identity. |
| Apache PHP / PHP-FPM | Served extensions and routes inspected. Native FPM VM upgrades/repairs/recovery and actual browser login were exercised with timestamp checks disabled, along with isolated active-request checks. FPM can close active web connections during reload; uninterrupted requests are not guaranteed. |
| Forwarded HTTPS ports / proxies / IPv6 | Explicit advertised ports retained; trusted-proxy policy and TLS authority checks enforced. |
| Split filesystems / tmpfs | Free space and inodes checked on actual destination filesystems; unsuitable persistent storage rejected. |
| Containers / cgroups | Effective resource limits measured; namespaces and atomic replacement capabilities required. |
| Standard / Lite resources | Standard keeps the 4 GiB baseline. Lite is offered with explicit consent only below the Standard RAM baseline; it requires two effective cores and nominal 2 GiB, caps capacity at 25 desktops/25 phone contacts, binds runtime concurrency and disables Enterprise Labs/SSO. Neither profile is load certification; full target-PBX acceptance remains required. |
| Asterisk includes / explicit loading | Includes and templates parsed without executing `#exec`; unavailable or excluded providers rejected. |
| Recognized legacy permissions | Exact known ownership, type, links, size and modes checked before recovery; unknown changes require review. |
| Standard FreePBX web modes | Root/Asterisk-owned integration files with the Asterisk group retain `0775/0664` modes in static snapshots and rollback. Root runtime stays private; foreign groups and world writes are rejected. Read-only inspection covers the complete static inventory. |
| Fresh / 0.1.4 / 0.1.5 / 0.1.6 / 0.1.7 / 0.1.8 / 0.1.9 baselines | Native incident VMs covered 0.1.8 upgrades, failed 0.1.9 transaction recovery and corrected-candidate repairs. Older inputs have fixture/controller support only; a complete historical-version VM matrix has not run. |
| Other OS, architecture, paths or identity | Unqualified. Unknown executable layouts are not automatically adopted. |

Use `sudo slsconsole doctor --json` for read-only prerequisites, release identity
and recovery locations. Use authenticated installer `--inspect` for upgrade
inventories. Repair is a separate explicit action.

## Delivery and integrations

| Integration | Local checks | External acceptance still required |
| --- | --- | --- |
| Desktop polling / SSE | Private Apache HTTPS, enrollment authorization, receipts, bursts, revocation, heartbeat and disconnect cleanup. | Public-edge routing, current app and sustained full deployment capacity. |
| Phones / voicemail | Private Asterisk, AMI admission/outcomes, vendor payloads and dialplan fixtures. | Each handset/firmware, full playback, auto-answer and mailbox delivery. |
| External calls | Routing, answer-gated playback, admission and receipt fixtures. | Carrier, selected trunk/DID, audio quality and keypad behavior. |
| Postfix email | Bounded admission, initialization recovery and failure fixtures. | Relay configuration and actual inbox receipt. |
| Twilio / Telnyx SMS/MMS | Request/response, signed callbacks, STOP, consent and spending fixtures. | Provisioning, approved sender and live handset/opt-out round trip. |
| BulkVS SMS/MMS | Outbound requests, diagnostics and API acceptance fixtures. | Live routing and provider-managed opt-outs. Authenticated inbound callbacks remain unsupported; unsigned callbacks are rejected. |
| OIDC / SAML — Labs | Assertions, state/replay, revocation, browser redirect and local TOTP flow. | Configured IdP, tenant policy and recovery process. |
| Browser subscribers — Labs | Proof, audience authorization, push deduplication and actual worker registration under CSP. | Push service, permissions, expiry and device display. |
| Speakers / access control — Labs | Bounded adapters, capabilities, claims, failures and uncertain outcomes. | Exact API/firmware and physical effects. HTTP acceptance does not prove playback or door state. |
| Zoom / Google Meet / Webex — Labs | OAuth, refresh, idempotency and callbacks. | Credentials, tenant permissions and actual meeting lifecycle. |
| Failover / remote sites — Labs | Lease, witness, replay, mirror and local delivery fixtures. | Separate PBXs, partitions, power loss, fencing and recovery. Experimental failover must not be used on production servers. |
| Sensors — Labs | Signed source admission, pending/expiry handling and local SDK compilation for ESP32, MKR WiFi 1010 and Nano 33 IoT. | Flash/power-loss, clock/TLS and isolated-contact hardware trials. |
| CAP / IPAWS — Labs | XML bounds, selected-language context, identity, expiry and cancellation. | Reviewed feeds, authorization and actual public-warning bridge. |

Restricted operators and named API senders may target only their explicitly
permitted browser subscribers and connectors. Saved audiences retain enrollment
and configuration bindings; queued jobs recheck current permission and identity.
Existing operator accounts receive no implicit grants. Incident language cohorts
and scheduled delivery preserve these recipients. Existing announcement and
desktop schemas remain compatible.

Native FreePBX archives contain recovery keys: protect the complete archive with
FreePBX encryption and restricted storage. Operational snapshots preflight size
and stream within fixed bounds. Oversized or unfinished journals fail clearly
without omitting evidence.

## 0.1.8 qualification boundary

The October 23 private Chromium checks also exercised the actual browser-display
PHP page and CSP, authenticated and legacy image downloads, absolute expiry,
calendar month/week/list edits, save-state cancellation, 320-pixel layouts and
200/400-percent CSS zoom. These checks do not replace an assistive-technology or
physical-device acceptance review.

| Area | Source/private-fixture evidence | Acceptance still required |
| --- | --- | --- |
| Desktop polling | Two-worker private FPM, 25/100/250/500/1,000 unique five-second clients, same public IP; cursor bursts, current authority and control-probe latency | Sustained actual FreePBX dashboard, calls and storage workload on each supported host |
| Passkeys | Real library signatures, origin/RP/UV/challenge/revocation and private HTTP login cases | Physical authenticators and chosen browser/platform |
| Optional regional voices | Pinned native CPU synthesis to private audio files; duration and nonzero sample checks | Local pronunciation and handset/gateway playback quality |
| Radio | Profile authorization, immutable bindings, complete-audio rejection, existing phone admission | Real SIP gateway/PTT/RF/channel release and legal authorization |
| Cloud directories/collaboration | Bounded payload, TLS, paging and reviewed-import fixtures | Credentialed tenant/provider behavior, quotas and key rollover |
| Restricted scripts | No-fallback admission, command/mount/resource validation | This host denies unprivileged user namespaces; positive execution remains unqualified. Requires target-host kernel/bubblewrap acceptance; not arbitrary-code certification |
| Browser | Event-bound proofs, live-only display, revocation and private JavaScript/HTTP tests | Actual browser push-service delivery and visual accessibility with assistive technology |
| Full installer lifecycle | Independent failure, trust, rollback, legacy-mode and filesystem fixtures; disposable VM workflow included | Every historical upgrade baseline and target-host acceptance beyond the native incident cases above |
| Paired-host failover, door control, public origination | Existing disabled Labs contracts and danger acknowledgments | Hardware/provider credentials, partitions, fencing and local recovery; do not use in production |

The repeated fleet fixture used six five-second polling waves per tier. Its
1,000-client sample measured about 399 ms poll p95 and 380 ms concurrent
control-probe p95. Summed worker RSS was about 101 MiB and CPU approached two
cores. State used private tmpfs and FastCGI sockets, without the production TLS
route or a real PBX workload; shared pages can be counted twice in summed RSS.
These short measurements establish neither physical-storage throughput nor a
complete PBX resource recommendation. All external acceptance rows remain open.

Manual review claims can be checked with
`python3 tools/check_audit_ledger.py /path/to/review-ledger.json --root /path/to/source`.
It rejects pending passes and changed source hashes; it never marks a review
complete. A passing ledger covers only its declared inventory, not an unlisted
file or every possible defect. Retain inherited open reviews separately.
