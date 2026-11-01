# Qualification boundaries

`0.1.9-beta` is the corrected unpublished candidate. The original withdrawn installer must not be reused. These entries distinguish native disposable-PBX qualification from isolated fixtures and external acceptance. They do not certify every deployment or delivery provider.

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

Release artifacts are rebuilt and signed after the final source checks. Native
scenario evidence is retained separately from the public source tree. Qualification
of earlier candidates is recorded by scenario; it does not imply every discarded
candidate passed the complete gate.

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
