# Southland Labs branding and compatibility

The product is **SLL Mass Notify Server**, published by **Southland Labs**.
The public server repository is
[SouthlandLabs_Mass_Notify_server](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server).

## Public URLs

Current company links use the same HTTPS origin and preserve their purpose:

| Purpose | Current URL |
| --- | --- |
| Company website | `https://southlandlabs.dev` |
| Projects | `https://southlandlabs.dev/projects` |
| Server project | `https://southlandlabs.dev/projects/mass-notify/server` |
| Community/support | `https://southlandlabs.dev/discord` |
| Notification schema identifier | `https://southlandlabs.dev/schemas/sls/notification-1.json` |

GitHub source, issues, vulnerability reporting, release downloads, the updater,
raw installer/bootstrap links and README image links all use the renamed server
repository. Existing version tags and release asset names retain their identity.
The separate desktop application's repository is an external compatibility link;
this server rebrand does not rename that separate project.

An older installed updater pins the previous repository name when validating
release asset URLs. GitHub redirects the old repository URL, but its API returns
asset URLs under the new name; that older updater can correctly refuse the
different metadata. For the first upgrade from an old-repository build, use the
independently verified standalone installer and signed assets from the renamed
repository. The updated installer and updater use the new repository. Existing
release assets and their signatures must not be rewritten to work around this
check.

These are company/project links. Each PBX's saved advertised host, public port,
mail domain, provider callbacks, SSO origins and passkey relying-party origin
remain deployment configuration. Changing company branding does not create DNS
records, provision TLS certificates or migrate enrolled clients. Review those
endpoints using General Settings when the replacement deployment origin is ready.

## Existing installations

The public name changes without renaming the installed FreePBX module or its
stored state. Keep `slsmassnotifyserver`, `slsconsole`, `sls-mass-notify` runtime
paths, `SLS_Mass_Notifications_Plugin`, environment/settings keys, API paths,
`X-SLS-*` headers, dependency package names, existing worker-attribution identities,
namespace/schema values and managed-file markers. In particular,
`com.southlandservers.massnotify.event.v1` remains the existing webhook wire
identifier; it is not a website request. Renaming these values would break
upgrades, restore, existing clients or authenticated state.

The signed installer recognizes old and new exact managed web/collector
configurations. Bundled recording labels migrate to the current publisher while
retaining recording IDs, filenames, sound bytes and existing references. Cleanup
and rollback recognize both exact label pairs and preserve administrator edits.

Only exact factory sender-name and email-subject defaults migrate automatically.
Custom sender names, subjects and templates remain intact. The migration runs
under the installer's settings/worker coordination and original snapshot; a failed
installation restores the original protected configuration. If staged settings
exist, automatic factory-label migration is deferred to preserve that editor state.
New SMS reply prompts use `SLL`; already-issued `SLS` reply tokens retain their
existing provider, person, consent, expiry and idempotency checks.

The bundled server logo comes from the owner-provided Southland Labs asset:
https://southlandlabs.dev/images/mass-notify-server.png?v=20261029

The original is retained as `assets/mass-notify-server.png`. Smaller copies serve
the existing UI, email and webhook paths; email artwork stays within its existing
size limit. Legacy filenames remain compatible. Alerts use bundled artwork and
do not fetch images from the Southland Labs website during delivery.
