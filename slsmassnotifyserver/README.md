<p align="center">
  <a href="https://southlandlabs.dev/projects/mass-notify/server"><img src="https://southlandlabs.dev/images/mass-notify-server.png?v=20261029" width="128" alt="SLL Mass Notify Server"></a>
</p>

# SLL Mass Notify Server

Send phone pages, desktop alerts, email, SMS and webhooks from FreePBX. Schedule announcements, publish weather alerts, and see results for each destination.

Built by [Southland Labs](https://southlandlabs.dev) for **FreePBX 17 on Debian 12 (amd64)**. **0.1.9-beta is withdrawn.** Its GitHub release and downloads have been removed. The available published prerelease is **0.1.8-beta**; the 0.1.9-beta source candidate is unpublished while recovery corrections are investigated.

> Beta software. Do not rely on it for critical or urgent notifications. Test your phones, network and delivery providers before use.

[Installation](#install-or-update) · [Requirements](#requirements) · [Features](#features) · [Documentation](#documentation) · [Report an issue](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/issues)

## Install or update

**Installation and upgrade commands for 0.1.9-beta are suspended pending a corrected signed release.** Do not install, repair or upgrade from the retired `V0.1.9-beta` assets or copied offline bundles. The source tag remains historical recovery evidence; it does not advertise an available installer. A replacement version and tag have not been selected.

The latest remaining published prerelease is `0.1.8-beta` (tag `slsmassnotifyserver-0.1.8-beta`). This is release availability information, not an instruction to downgrade an existing PBX or use it as a recovery carrier. Preserve existing settings, publisher trust and every failed transaction directory.

The reported LiteNet recovery has 22 baseline history records: 1 unchanged, 21 missing and 0 with proven expiry. Ordinary history recovery must continue to return exit 4 without matching evidence; no administrator has accepted the missing history. Independently, configuration differences limited to `totp_last_counter` and the `operator_access` revision currently trigger the configuration hash guard. Neither blocker has been resolved by this withdrawal. See [recovery operations](docs/INSTALLER_OPERATIONS.md) and the [qualification boundaries](docs/QUALIFICATION_MATRIX.md).

Historical bootstrap identity is retained for evidence checks only:

```text
bdf8e32e22a0baeed9a5764f0ade1f6a110fbde686cb8ea5f4f06a026ea1da75  sls-bootstrap.sh
```

The former invocation `sls-bootstrap.sh 0.1.9-beta` is withdrawn; do not run it. A checksum or publisher signature authenticates old bytes and does not make the withdrawn installer suitable for use. Updated installation commands will accompany a newly qualified signed release.

Candidate H previously passed 423 isolated suites, four native install/rollback cases and three installed journal profiles. Those bounded historical results did not cover the reported target recovery blockers and do not qualify a replacement release. Earlier G 423/18/360 results remain historical as well.

## Requirements

| Profile | Minimum resources | Limits |
| --- | --- | --- |
| Standard | 2 effective CPU cores, nominal 4 GiB RAM | Starts at 25 desktops and 25 phone contacts; higher capacity needs more resources. |
| Lite | 2 effective CPU cores, nominal 2 GiB RAM | 25 desktops, 25 phone contacts; Enterprise Labs and enterprise SSO unavailable. |

The locked speech runtime requires an x86-64-v2 CPU on every CPU available to the process. AVX is not required. Virtual machines must expose those features; the installer reports missing features before preparing SLL state.

**Standard is the default.** If usable RAM falls below its baseline, the installer checks whether Lite can run, explains its limits and asks before installing it. Ordinary kernel reservations on a nominal 4 GiB system are allowed. Declining the Lite prompt cancels installation.

For a future corrected release, unattended Lite installation will require explicit selection. The withdrawn bootstrap command is suspended along with the Standard installation commands above.

Lite allows one speech renderer, two waiting speech jobs, four simultaneous desktop streams, one Weather/Lightning delivery worker and two Weather.gov fetch workers. It retains core notifications, scheduling and local operator authentication. Saved Enterprise configuration is retained but disabled. Hosts that meet Standard requirements cannot select Lite.

Both profiles need free space for the application, speech models, logs and installer recovery. PBX recordings and backups need additional space. See [resource requirements](docs/RESOURCES.md) for capacity and storage details. A 2 GiB installation is intended for light use; plan more RAM for ordinary PBX traffic or frequent speech generation.

## Features

| Feature | Details |
| --- | --- |
| Announcements | Phone audio and displays, desktop messages, email, SMS and webhooks with per-destination results. |
| Scheduling | One-time and repeating announcements, calendars, holidays and reviewed imports. |
| Weather and lightning | Weather.gov alerts and configured lightning providers, with separate audiences and delivery settings. |
| Paging | Dial-in groups, caller restrictions, live audio and optional voicemail delivery. |
| Operators and incidents | Scoped accounts, passkeys or TOTP, incident templates, drills, responses and reports. |
| Enterprise Labs | Optional SSO, remote-site coordination, device integrations and automation. Disabled by default; unavailable in Lite. |

Optional channels require their own setup. Email uses local Postfix; SMS and cloud services need provider accounts. The [desktop app](https://github.com/vipgabe09267/SouthlandServers_Mass_Notify_app) is a separate project.

Delivery reports distinguish submission from confirmed receipt. A mail server accepting a message does not prove inbox delivery, and a phone answering does not prove someone heard the whole announcement. Uncertain submissions are not automatically replayed. See [delivery behavior](docs/DELIVERY.md).

## Service commands

| Command | Action |
| --- | --- |
| `sudo slsconsole status` | Show notification and collector status. |
| `sudo slsconsole doctor` | Check installation health without sending notifications. |
| `sudo slsconsole stop` | Pause new SLL notifications. |
| `sudo slsconsole start` | Resume SLL notifications. |
| `sudo slsconsole reboot` | Restart the SLL collector. |
| `slsconsole help` | List available commands. |

These commands manage SLL; they do not reboot the PBX or restart Asterisk. Add `--json` to status and doctor for scripts.

## Repair and recovery

Installer-driven repair and upgrade remain suspended pending a corrected signed release. Follow the evidence-preservation guidance in the [installer recovery guide](docs/INSTALLER_OPERATIONS.md). Keep the recovery path printed by a failed installer; do not delete it, replace live settings or alter history to bypass a check.

Export configuration under **General Settings > Config Backup**. Keep the export passphrase separately. Native FreePBX backups also include module recovery data; protect the whole backup archive. See [backup and restore](docs/RECOVERY.md).

## Uninstall

The included uninstaller works offline:

```bash
sudo slsconsole uninstall
# Equivalent local script:
sudo /usr/local/bin/sls_mass_notify/sls_mass_notify_uninstall.sh
```

Normal removal preserves configuration, backups, recordings and history. Use `sudo slsconsole uninstall --purge` only when you intend to delete retained SLL data. See [removal and purge](INSTALL.md#uninstall).

## Documentation

- [Installation](INSTALL.md), [resource requirements](docs/RESOURCES.md), and [troubleshooting](docs/INSTALLER_OPERATIONS.md)
- [Paging](docs/PAGING.md), [scheduling](docs/SCHEDULING.md), and [locations](docs/LOCATIONS.md)
- [Operators](docs/OPERATORS.md), [incidents](docs/INCIDENT_API.md), and [triggers](docs/TRIGGERS.md)
- [Control API](docs/CONTROL_API.md), [OpenAPI](docs/openapi.json), and [desktop compatibility](docs/DESKTOP_READINESS.md)
- [Enterprise setup](docs/ENTERPRISE_INTEGRATIONS.md), [identity](docs/ENTERPRISE_IDENTITY.md), and [remote sites](docs/ENTERPRISE_CLUSTER.md)
- [Changelog](CHANGELOG.md), [security policy](SECURITY.md), and [qualification results](docs/QUALIFICATION_MATRIX.md)

For development and release checks, see [VALIDATION.md](docs/VALIDATION.md). On a PBX, run source tests through `sudo bash tools/run_isolated_tests.sh --build` so fixtures cannot use live PBX state.

Licensed under [AGPL-3.0-or-later](LICENSE).

[Project page](https://southlandlabs.dev/projects/mass-notify/server) · [Southland Labs](https://southlandlabs.dev) · [Discord](https://southlandlabs.dev/discord) · [GitHub issues](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/issues)
