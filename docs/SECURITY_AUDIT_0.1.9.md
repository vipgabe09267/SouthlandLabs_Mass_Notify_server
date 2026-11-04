# 0.1.9-beta security and reliability audit

Historical status at review: unpublished prerelease candidate, 2026-10-27. Later uppercase V0.1.9-beta and v0.1.10-beta releases were withdrawn; their tags remain historical evidence. This dated review retains its original findings and limits. See [qualification boundaries](QUALIFICATION_MATRIX.md) for the new unpublished reserved-tag 0.1.9-beta correction, the separate user-reported successful target installation and separate historical H/G/J qualification.

**2026-11-04 version correction addendum:** The unpublished 0.1.9-beta candidate L, planned reserved tag `release-0.1.9-beta`, retains the strict monotonic TOTP-counter/revision preservation, durable ciphertext/target publication, crash retries and original evidence retention implemented in J. Other credential/settings edits and unresolved immediate-settings journals remain conflicts. This is not history-loss acceptance.

Withdrawn J passed 424 isolated suites and nine native scenarios as 0.1.10-beta, following 207 focused recovery cases. That exact evidence remains historical; new L qualification/publication is pending and published availability remains 0.1.8-beta. The user reports that 0.1.10-beta installed successfully, passed 16 doctor checks and preserved MFA/settings/keys after the administrator explicitly accepted 21 missing history records. This is user-reported, not independent target qualification of the new 0.1.9-beta artifacts. The dated findings below do not authorize withdrawn downloads or certify the new artifacts.

This record covers the repository candidate, not an installed PBX. The review
inventoried every tracked file, parsed or linted applicable PHP, Python,
JavaScript, shell, JSON and XML, scanned packaged dependencies and dangerous
operations, and manually traced the security-sensitive first-party paths. Those
paths included authentication, authorization, CSRF, API input limits, delivery
journals, filesystem operations, external requests, secrets, restore, installer,
updater and uninstaller behavior. Vendored source was checked against its locked
inventory and exercised by focused compatibility and boundary fixtures; it was
not represented as a new independent audit of each upstream project.

The objective is a defensible semi-stable beta candidate. This is not a
production, life-safety, compliance or penetration-test certification.

## Confirmed findings corrected in this candidate

| Area | Finding | Correction and evidence |
| --- | --- | --- |
| Weather and Lightning delivery | Provider and PBX I/O could keep the durable queue lock occupied, blocking unrelated work. A crash around an external handoff also needed an explicit uncertainty state. | Workers now claim one bounded lease, commit intent before I/O and finish under a short second transaction. Interrupted or unconfirmed effects become terminal uncertainty and are not replayed automatically. Concurrency and journal fixtures cover competing workers, stale leases and transport failures. |
| Weather queue parsing | Legacy jobs and metrics were accepted with incomplete structural, numeric, depth and Unicode validation. Malformed state could fail late or enter permission migration. | One bounded schema validates jobs, snapshots and metrics before runtime or migration. Duplicate members, nonfinite values, invalid UTF-8, excessive depth/size and unknown structures fail closed without rewriting evidence. |
| Lightning media | Path-based synthesis and conversion left opportunities for source replacement and partial output visibility. | Inputs are opened without following links, metadata and identity are rechecked, output is bounded, and complete WAV data is committed by atomic replacement. Link, ownership, mutation, oversize and failed-conversion fixtures preserve the prior file. |
| XML declarations | Byte-only declaration guards missed UTF-16 document types in Lightning responses and installed-module identity parsing, allowing internal entity expansion despite the intended prohibition. | Parser callbacks reject decoded document types before content is accepted. Provider, doctor and upgrade fixtures reject UTF-8/UTF-16 declarations and retain valid UTF-8/UTF-16 metadata and namespaced strike responses. The change uses the documented [ElementTree target callback](https://docs.python.org/3.11/library/xml.etree.elementtree.html#xml.etree.ElementTree.TreeBuilder.doctype). |
| Voicemail fallback | A missing or delayed AMI response could be treated like a definite originate rejection, allowing the reservation to close despite an uncertain carrier/PBX effect. | Only an explicit negative Asterisk response closes the reservation as rejected. Timeout, disconnect and ambiguous replies remain unconfirmed and are never redialed automatically. |
| Dial-in paging | A shared menu could disclose groups a caller was not authorized to select. Older saved scripts could also retain an unbounded execution mode. | Menus are generated per admitted caller and contain only authorized groups. Legacy scripts migrate to restricted execution; deadlines, output, descriptors and CPU remain bounded. |
| Browser credential handling | Saved desktop ciphertext and Lightning credential values could be returned to administrative form data. | Browser responses no longer contain saved secrets. Blank fields preserve an existing credential, clearing is explicit, and new desktop records require a new password. Regression fixtures verify both preservation and redaction. |
| Restore authority | Configuration import/restore could retain Control API authority alongside restored provider state. | Restore disables the Control API, rotates its legacy key, revokes named credentials and disables schedules, automation, external channels and Labs features pending review. Deployment profile changes are rejected outside the authenticated installer. |
| Operator SSO | Expired SAML certificates could prevent administrators from retaining a disabled provider for repair; broad errors could reveal provider response details. | Disabled providers remain repairable, while enablement and runtime use still reject invalid certificates. Browser errors use bounded categories; private audit evidence keeps the diagnostic class. |
| Federated session completion | The portal called a private settings method after local MFA, causing valid federated logins to return an unavailable response. The test facade incorrectly made that method public. | A public session-boundary operation checks federation against fresh settings. The HTTP fixture now preserves the real method visibility; valid login and grants revoked before or during completion are covered. |
| Operator pre-authentication | A request could target a known username before password authentication and consume shared account-oriented work, creating a focused denial-of-service primitive. | Unauthenticated work is constrained without trusting the submitted account name. Durable address/password limits and post-authentication account controls remain authoritative. |
| Administrative removal | A web request could queue privileged complete removal, unnecessarily expanding the root-operation surface. | Complete purge is local-only through the authenticated bundled `sudo slsconsole uninstall --purge` path. The dashboard no longer creates a purge request. |
| Health reporting | Old dependency and delivery faults could remain current after a later healthy check, producing repeated false warnings and mail. | A successful authoritative check clears only its current fault dependency; retained history stays separate. Desktop journal data is validated once and reused for the request. |
| Phone delivery outcome | The generic `child_finished` result could label several materially different SIP NOTIFY outcomes the same way. | Results now distinguish accepted, timed out and nonzero sender exits. Once the sender starts, missing evidence remains uncertainty rather than success. |
| OIDC token exchange | `client_secret_basic` used RFC 3986 component encoding instead of OAuth form encoding and also repeated `client_id` in the body. Strict identity providers could reject a valid login. | Client IDs and secrets are encoded with application/x-www-form-urlencoded rules before Basic authentication. Basic, POST and public clients now send exactly their registered authentication form. Fixtures include spaces and reserved characters for all three modes. |
| Installer profile admission | A low-memory mode needed bounded runtime behavior without becoming a resource or trust bypass. | `--lite` requires two effective cores and nominal 2 GiB, caps desktops and phone contacts at 25, and constrains speech, stream and Weather concurrency. Profile conversion is encrypted, transactional and restored on failure; pending settings and over-capacity conversion are refused. |
| Upgrade permissions and state | Runtime and migration policy differed for private Weather state, and malformed legacy state needed to be rejected before a permission change. | Active and migration policy now agree on private `0640` files. Known regular, single-link, expected-owner files are changed through validated descriptors; bytes and inodes are preserved. Unknown ownership, links, size, mode or content stop the upgrade. |
| Release correction path | The historical same-version correction bootstrap complicated provenance and repeat-install behavior. | The candidate returns to an ordinary immutable versioned release. Fresh bootstrap refuses established publisher policy; upgrades, repair and recovery use the enrolled authenticated path. |
| Desktop qualification | The cross-repository adapter selected removed test modules and forced the PBX interpreter on a client requiring a newer Python. | Current consolidated and legacy suites are selected explicitly; incomplete trees fail before execution. An optional reviewed client interpreter is supported. Adapter regressions and 105 current-client contract tests passed in isolation. |
| VM qualification input | The controller and dispatch workflow omitted the current `0.1.8-beta` upgrade baseline. | Both accept that baseline. Regression coverage verifies the explicit disposable-VM opt-in still blocks image access. A controller test is not a completed VM upgrade. |

## Installer and removal review

The installer was treated as a release-blocking component. Review covered:

- signed manifest, installer and archive identity; exact version and immutable
  package naming; archive traversal, duplicate path, link, device, mode, count
  and expanded-byte rejection;
- independently verified Framework/Dashboard sources, prior SLL overlays and
  refusal to approve arbitrary live hashes;
- root/Asterisk privilege separation, no-follow opens, bounded logs and locks,
  private recovery evidence and same-filesystem activation;
- missing legacy inventories, recognized permission migrations, Piper
  compatibility layout, served PHP/FPM validation and Asterisk capability
  output variants;
- encrypted active/pending configuration snapshots, stage allowlist parity,
  signal interruption, rollback, retained failed recovery and explicit retry;
- cgroup CPU/RAM, destination filesystem identity, free bytes, inodes, tmpfs,
  persistence, Standard/Lite profiles and auto-detected phone capacity;
- offline local uninstall, active-work refusal, default data preservation and
  separately explicit purge.

The focused isolated gate passed 33 of 33 installer, uninstaller, bootstrap,
resource and release suites. It includes failures before mutation, failures at
each recorded stage, prepared/mutating recovery, rollback recording, repeated
installation, links/hard links/special files, unknown owners, oversized state,
legacy modes, missing helpers, package repair refusal and local uninstall. The
host timezone catalogue is unavailable in the private fixture namespace; mocked
timezone validation and rollback passed.

## Additional evidence

- Syntax/parse checks cover project PHP, Python, JavaScript, shell, JSON and XML.
- The release source scanner rejects private keys, generated state, caches,
  unsafe archive entries and unexpected executable material.
- The dependency/SBOM check queried OSV during the review and returned no
  matching advisory for its current 62-component inventory. This point-in-time
  result does not cover the host OS or other FreePBX modules.
- Semgrep Community Edition 1.182.1 ran the approved security, secrets,
  OWASP, language and five third-party rule collections with metrics disabled.
  The initial repository scan produced usable results for 13 of 14 selected
  scans; `p/yaml` was unavailable from the registry. A separate GitHub Actions
  scan covered the hidden workflow directory. Repeating the packaged-source
  scan with a longer timeout reduced timeout gaps to three rules on the main
  facade. Some upstream rules were invalid and some shell constructs were
  only partially parsed. Shell syntax and ShellCheck were checked separately.
  Community Edition does not provide cross-file taint analysis. These limits
  remain part of the evidence; raw scanner flags are not confirmed defects.
- Authentication fixtures cover password/TOTP/passkey recovery, OIDC, signed
  SAML, assertion replay, XML wrapping, JWT algorithm/key confusion, CSRF,
  account expiry, recipient authorization and rate limits.
- Delivery fixtures cover duplicate submissions, uncertain external effects,
  queue corruption, recipient isolation, desktop cursor/expiry behavior,
  voicemail admission, phone results and concurrent workers.

## Required deployment qualification

Before any public prerelease is relied on, run a clean supported FreePBX 17 VM
installation and upgrades from every supported prior version, followed by
rollback/retry and local uninstall. Qualify Apache or PHP-FPM, the public HTTPS
route, Postfix, every carrier/provider, each handset/firmware, voicemail,
desktop fleets, physical devices, paired-host Labs features and sustained load
in the target environment. No live provider, phone or notification test was
performed during this audit. Destructive lifecycle checks belong on disposable
systems. Independent external review
remains valuable and is not replaced by project-owned fixtures.

Release remains blocked by any failed isolated suite, mismatched package hash,
unsigned manifest, incomplete rollback, unreviewed target-PBX difference or
failed administrator acceptance test.

## Extended review, 2026-10-28

This section supplements the earlier findings above. The additional sustained
review examined auth/API/portal/recovery, delivery and state transitions,
privileged lifecycle operations and the actual browser flows. It used independent
review, concrete data-flow tracing, private red/green reproductions and exact
source digests. The [threat model](THREAT_MODEL_0.1.9.md) records the confirmed
deployment assumptions and distinguishes threat scenarios from demonstrated bugs.

The following statuses describe **candidate source**, not an installed PBX.
Earlier private proposals were integrated only after review and per-file input
and output hash checks. Parent UI edits and inherited source changes were
preserved. The updated email source-expiry correction supersedes the older frozen
email proposal; the final STOP/deadline bundle supersedes its first private
candidate. Duplicate Weather/Lightning/webhook leaf patches were not applied twice.

| Severity | Confirmed finding | Source correction / remaining qualification |
| --- | --- | --- |
| Medium, reliability | IdP/directory HTTP selected one vetted DNS address; a failed first address stranded a healthy alternate. CAP fetching had the equivalent IPv4 limitation. | libcurl receives the immutable fully vetted address set and performs connection fallback. Unsafe members reject the whole set; exact private pins, TLS hostname/certificate checks, primary-IP membership, forbidden redirects/proxies and no manual POST retry remain. Native HTTPS failure/alternate/uncertain-POST controls passed. |
| Medium | Weather retry could submit later email/webhook/channel work after source cancellation, expiry, quiet hours or configuration withdrawal; cancellation projection could overwrite evidence. | Current authority is checked per remaining handoff; original record lifetime, accepted/uncertain effects and consumed claims remain authoritative. Concurrent process/crash/lease fixtures verify unrelated work progresses and uncertain effects never replay. No arbitrary recipient or beyond-frozen-audience effect was demonstrated. |
| Medium | NWS/Lightning preparation and per-call placement could outlast source validity or recipient removal. Child rendering/contact lookup could outlast the parent check. | Parent and child source contexts ship together; fresh current/frozen route and enrollment checks guard later callfile, AMI and journal handoffs. Known pre-submit refusal keeps consumed claims and prior partial results with uncertainty=false; actual started transport errors remain uncertain. |
| Medium | Native voicemail could proceed after source/configuration withdrawal during mailbox lookup. | The final native handoff rechecks current source and configuration after preparation. Consumed parent/child admissions remain intact and are not reopened. |
| Medium | MMS admission/publication could consume the original provider start window. | Monotonic elapsed time is included before the provider request; expired messages retain the original conservative reservation without a provider call or automatic retry. |
| Medium | SMS could use stale sender authority after durable progress/admission or ignore a signed STOP committed during MMS preparation. Full permanent opt-out replay history refused a new STOP while new sends remained possible. | Final sender/source checks and current local consent/capacity checks are applied. Production authorization carries immutable absolute and monotonic bounds across later database reads, including the earlier Weather source expiry. Full 100,000-entry replay history pauses new sends until reviewed maintenance; no history eviction or budget refund. Existing accepted outcomes remain readable. Provider-side STOP remains independently required; handset delivery or a carrier opt-out bypass was not demonstrated. |
| Medium | Email could use stale principal/recipient/sender/source authorization after progress, admission or cluster coordination. Source expiry could pass while the final PHP policy helper completed. | Same validated effective target is bound to bounded relevant configuration projections; current policy is checked at the child handoff. The final proof caps original email/schedule/principal/automation/Weather source deadlines and is checked after helper completion. Known refusal retains the consumed claim and bounded no-submit receipt. Mutable authorization metadata is excluded from immutable cluster intent. |
| Medium | Webhook cluster coordination and a final policy read could outlast authorization or the original request budget. | Guard and original remaining budget are checked after the consumed cluster claim, socket timeout is refreshed beside POST, and proven no-submit is recorded without refund/replay. Started uncertainty and late known HTTP acceptance are retained. |
| Medium | PBX identity lookup could outlast local operator expiry in API and normal PBX-session principal resolution; approver lookups could outlast approval expiry or cross clock rollback. | Final current-account/review-clock predicates run after the relevant lookups. Trusted PBX administrator recovery and unlimited-account behavior remain; no caller-settings snapshot refresh or broader account bypass is claimed. |
| Medium | A trigger HMAC accepted before PBX bootstrap could authorize admission under a newly rotated enrollment key. | Original signed bytes/headers are carried separately from caller JSON and rechecked against the same current rule/settings snapshot used for activation, panic challenge or heartbeat admission. Same current key may legitimately admit changed administrator policy. Newly signed duplicates preserve the original completed effect. |
| Medium | A Control API announcement could be accepted without an idempotency key, and delayed phone or Weather work could outlive credential rotation, revocation or audience withdrawal. | `send_announcement` requires a bounded `Idempotency-Key`. Queued authorization binds a non-secret authority revision and rechecks the current credential, scopes and audience before later handoffs. Legacy-key rotation/disablement and named-credential revocation fixtures stop delayed effects without reopening consumed claims. |
| Medium, local hardening | The direct root installer entered through an environment-selected shell and resolved `readlink` before replacing a caller-controlled `PATH`. | The entrypoint uses `/bin/bash`, installs and exports its fixed system `PATH` before utility resolution, and retains absolute-path bootstrap checks. A poison-shell/poison-`readlink` fixture proves neither caller-controlled executable runs. |
| Low, confidentiality | Authenticated desktop event projections retained PBX-only vendor XML and phone-routing fields that desktop clients did not need. | The desktop projection removes vendor XML, phone recipients/formats and phone image routing while retaining authorized desktop presentation fields. Port rewriting and retained-event compatibility fixtures verify the allowlist. |
| Low, reliability | A browser notification could be displayed before its deduplication claim was durable, while receipt failures could retry without a bounded attempt count. | The worker claims the event before display, preserves conservative uncertainty on storage failure, permits retry only after explicit display rejection, and bounds receipt attempts across worker restarts. Cache eviction, worker/browser lifecycle and human display remain outside an exactly-once guarantee. |
| Low, UI safety | Destructive removals, disabled-schedule activation, door actions and update installation did not consistently preserve drafts or present contextual confirmation. | Scoped save-state boundaries now cover structural editors; removals, schedule activation, door actuation and installation use contextual confirmations. Real Chromium verifies cancellation leaves controls usable, retains unsaved General Settings and sends no update POST. |
| Low | Restricted read+monitor scope union exposed full readiness details; a full login-source registry could produce a misleading recovery success notice. | Detailed readiness requires unrestricted read. Recovery accurately distinguishes password change from inability to clear the address limit. No secret/device-acceptance leak or login-limit bypass was demonstrated. |
| Low, accessibility | Cluster help text became part of field accessible names. | Exact field names and separately associated descriptions are preserved; actual Chromium checks cover naming, help and focus. |
| Low, reliability | Removing a coordination row did not mark the editor dirty, risking loss of unsaved changes on navigation. | Removal sets editor save state; the browser regression verifies navigation protection and that removal was not persisted without Save. |
| Medium | PHP/Python configuration-key maintenance could coordinate on incompatible ownership/group/content/inode assumptions. | Permanent shared mutex coordination is aligned and tested in both acquisition orders, including replacement/refusal cases. Configuration encryption still does not isolate a compromised Asterisk UID that legitimately reads the runtime keyring. |
| Medium | GPG could expand unsigned compressed plaintext before signature rejection, beyond the caller's intended plaintext cap. | The decrypt/verify subprocess is given an explicit output bound. A 2,082-byte unsigned fixture previously produced 2 MiB despite a 64 KiB fixture cap; bounded rejection and valid inputs are covered. |
| Medium, reliability | A valid large encrypted configuration backup could exceed the older 2 MiB envelope limit. | Backup handling uses the actual authenticated configuration-envelope maximum, preserving supported large configurations and existing recovery behavior. |
| Low, reliability | Stock uninstall workspace prefixes did not match their admission validator. | Both mirrored uninstallers accept only their actual protected workspace shape; unknown paths remain refused. |
| Medium, restore availability | A 4 KiB SQLite database in an administrator-supplied backup could use a view to synthesize a 32 MiB replay-identity row before rejection, exceeding the 16 MiB source-file bound. | Restore requires a real stored reports table with a plain text identity column and bounds the identity projection before materialization. Invalid identities cause refusal rather than being silently omitted. Native archived reports with large encoded bodies remain supported. This is resource exhaustion during administrator-initiated restore, not code execution; final qualification is recorded externally. |
| High | A compromised Asterisk process could replace a writable web ancestor after preflight, redirecting root recursive uninstall deletion into a protected recovery-key directory. | Descriptor-relative containment is applied to source; nine focused canonical suites passed, including 18 adversarial containment cases. Final build/install verification remains a release gate. The reproduced impact was protected synthetic deletion, not root code execution. Final application/build/install status is tracked in the external verification record; earlier lifecycle-suite passes alone do not qualify this containment correction. |

The first private STOP correction introduced a **private-candidate regression**:
a real 180 ms SQLite writer wait after a boolean authorizer crossed an actual UTC
credential expiry. Independent review caught it before canonical integration.
The replacement immutable deadline proof was tested with an oracle that proves
the authorizer was current before the wait and cannot swallow a setup failure.
This was not a newly deployed canonical regression.

### Stable qualification evidence and limits

- The frozen extended composition passed **410/410 runtime/compatibility suites**
  in 865.823 seconds; all **3,101 source hashes remained unchanged**. This is the
  recorded prior generation: the later email helper/source bound and parent
  coordination-removal browser regression require their own final-generation
  checks. It is not the final package/install verdict.
- A later final-generation pre-pin run executed all **414** registered isolated
  suites with Chromium, JSON Schema, the reviewed desktop-client checkout and
  pinned voice/runtime fixtures required. **413 passed**; the sole failure was
  the deliberately stale unsigned-package digest after candidate changes. That
  historical run is evidence for source behavior, not the final package/sign/install
  verdict, which remains in the external owner verification record.
- Six optional browser suites ran with explicit existing Chromium, Playwright,
  library and public jQuery inputs: 39 browser methods plus the 1,000-recipient
  envelope script passed. Initial missing-library and missing-jQuery setup
  failures were retained and corrected, not counted as successful checks. The
  later parent coordination-removal case is recorded separately.
- The two-hour frozen desktop soak completed 7,203.01 seconds and 1,188,925 polls
  for 1,000 clients with the same two long-lived workers. Worst window poll/control
  p95 was 319.23/304.62 ms and RSS stayed about 99.76–101.76 MiB. Actual throughput
  was **165.06 polls/s, below the 200 polls/s target**; this is not a successful
  1,000-clients-per-five-seconds throughput qualification.
- The auth/API subreview ledger records 89 paths: 78 complete semantic reviews,
  seven explicitly partial reviews and four dependency inventories. Other
  component ledgers retain their own scopes. Exact inventory/advisory comparison
  is not exhaustive semantic review of every vendor line.
- A second Semgrep Community 1.182.1 source pass again produced usable results
  for 13 of 14 groups and no secret findings; the upstream `p/yaml` registry
  configuration again failed. The PHP command-execution count increased because
  the first pass had timed out that rule on the main facade; the second completed
  it. New echo-taint deltas were traced through bounded input and output escaping.
  Community Edition, parser, rule and cross-file limits remain; a scanner result
  is not proof that a project is vulnerability-free.
- The earlier renewed broad run lacked a reviewed desktop application checkout.
  The later pre-pin run required the preserved reviewed checkout and its 105
  current-client contract tests passed. Current device/provider/OS/client
  acceptance and production TLS/PBX recovery remain deployment-specific. All new
  sends, provider callbacks and Asterisk effects in these fixtures were synthetic
  and isolated; **no real notification, page, SMS, email or provider action was
  sent by this extended review**.

### Retained policy and operational observations

Expired-account credential repair does not reactivate the account. The bounded
512-source failed-login inventory and 200 awaiting-approval allocation deliberately
fail closed and require their documented expiry/reviewer/maintenance paths; no
silent eviction or authorization bypass was introduced. Active SMS recipient and
provider changes serialize with the worker's activity lease; synthetic mutation
alone was not claimed as a demonstrated concurrent production race. Network API
credential revocation uses a separate settings mutex and was traced independently.

Native DNS resolution occurs before the IdP cURL timer. An isolated real resolver
and HTTPS fixture took 22.038 seconds with five 4.4-second DNS replies despite the
12-second cURL transfer limit. Unsafe answers still caused zero HTTP requests.
This measured availability limit remains; an unreviewed resolver redesign was not
bundled with connection fallback. Read-only host inspection also found Apache
processes mapping deleted crypto-library inodes after package updates. Final
service-cycle verification must confirm the active generation, rather than infer
it only from package versions on disk.

### Final package and PBX verification

A separately retained owner verification record is outside the package. It is
the place for the final frozen catalog/source
checks, authenticated build/signature/package hashes, installation/rollback and
post-install service/readiness results. Updating that evidence after source
freeze must not silently change the already qualified package. Until that record
confirms a step, this report does not claim it succeeded. It does not promise
zero remaining defects, life-safety suitability, human receipt or every external
provider/device deployment.
