# Generated media access

General Settings → **Generated image and phone XML access** controls downloads from `/sls_mass_notify/`. These settings are saved only in `mass-notifications.config` and use the normal Save / Apply Config workflow. Anonymous compatibility access remains the default: existing installations start with unrestricted networks, no download expiry, no authenticated desktop media endpoint, and no short-lived phone capability requirement. The installer preserves existing settings and does not add a port or firewall rule.

Administrators can instead require the authenticated desktop media endpoint for generated announcement images. The event then identifies `image_authentication` as `desktop_basic`, and the desktop must send its current enrollment's Basic credentials only to the exact advertised HTTPS origin and `/api/sipnotify/desktop/media?event_id=...` route. Current enrollment, original routing, event expiry and the ten-minute desktop lifetime are rechecked. This option requires a coordinated compatible desktop release; credentials must never follow a cross-origin redirect or be attached to an ordinary generated-media URL.

Administrators can additionally require a short-lived signed capability for phone image and XML URLs. Each capability is bound to one exact filename, the current revocation generation and an expiry no more than ten minutes in the future. This mode requires HTTPS and authenticated desktop media. **Revoke existing phone links** rotates the generation when settings are applied. Network and absolute file-age restrictions continue to apply after either authentication method succeeds.

Generated images and phone XML use random URL identifiers. The desktop app currently downloads an image without Basic authentication or browser cookies; this behavior remains compatible. A URL is not proof of recipient identity. An authorized viewer can share or retain downloaded content. These controls restrict future downloads, not already downloaded copies or screenshots.

## Network restriction

Enable **Allow generated media only from listed networks** and specify up to 32 IPv4/IPv6 addresses or CIDRs. An enabled empty list and a `/0` network are rejected. Include the phone subnets and the public NAT addresses of remote desktops, as seen by the PBX. API authentication allowlists and these media download rules are independent.

SLL normally uses the direct request address. Only proxies explicitly configured under **Trusted reverse proxies** may supply forwarded client addresses; SLL walks their chain from the trusted end and rejects malformed proxy metadata. A client cannot bypass the rule merely by sending `X-Forwarded-For`. A network-denied download returns HTTP 403. The PBX itself has no blanket loopback exemption.

## Expiry

Set **Download expiry after file creation** to `0` to disable it, or choose 10–1440 minutes. Expiry is absolute relative to the generated file's modification time, which rendering sets when creating the file. Reading, polling, applying settings, or fetching the same URL does not refresh that time. At the limit, new requests receive HTTP 410. A backward clock beyond the allowed one-minute skew returns HTTP 503 instead of extending access.

This includes images belonging to a weather alert that remains active longer than the chosen media lifetime. Choose a lifetime that fits the phone display workflow. A phone may need to download its XML and then its image; both downloads must satisfy the policy. Desktop Details retains plain message text when an image cannot be loaded. Some phone formats cannot display anything if media access is denied. File cleanup and announcement expiry are separate: download expiry does not erase delivery records or incident history.

## Routing, limits, and repair

The installer enables Apache's required rewrite/setenvif modules and installs a fixed media route. Requests keep their existing public URL, hostname and port. Normal requests and older API prefix aliases both reach the same policy handler. Direct requests to `/api/sls-mass-notify/media.php` enforce the same policy. The authenticated desktop route resolves only an event authorized for that enrollment and then invokes the same media policy. Directory overrides cannot bypass these routes. Packaged branding under `assets/` remains public and separate from generated alerts.

Downloads accept GET and HEAD, return `Cache-Control: no-store, private`, and validate a bounded, single-link regular file before returning content. Unsafe paths, links, special files, writable-by-group/other files, invalid PNG signatures, images above 5 MiB and XML above 256 KiB are rejected. A missing, malformed, or unreadable protected configuration returns HTTP 503 rather than falling back to unrestricted access. The response does not expose configuration contents or filesystem paths.

Deployment readiness checks the actual local Apache route with a nonexistent random filename, without creating a file or sending an alert. Installation additionally renders and validates a test image. If configured restrictions intentionally deny local retrieval, installation validates the bytes locally and reports that an allowed device network needs acceptance testing. It does not remove the restriction. **Repair Installation** reinstalls the managed route and correct file permissions; review conflicting custom aliases or virtual-host rules if the route still fails. No PBX or firewall restart is needed for changing these media policy settings.

Behavioral tests use a private Apache/mod_php instance with dummy configuration, normal and legacy routing, allowed/denied requests, proxy forgery, expiry, HEAD/GET, exact returned bytes, and config failures. Filesystem and import/backup fixtures exercise type bounds, links, locks, malformed policy and retained settings. A browser fixture checks actual form fields and both desktop/narrow layouts. Hardware display acceptance still requires the actual device and its network path.
