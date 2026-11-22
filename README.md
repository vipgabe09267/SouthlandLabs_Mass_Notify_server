<p align="center">
  <a href="https://southlandlabs.dev/projects/mass-notify/server"><img src="https://southlandlabs.dev/images/mass-notify-server.png?v=20261029" width="128" alt="SLL Mass Notify Server"></a>
</p>

# SLL Mass Notify Server

Send phone pages, desktop alerts, email, SMS and webhooks from FreePBX. Schedule announcements, publish weather alerts, and see results for each destination.

Built by [Southland Labs](https://southlandlabs.dev) for **FreePBX 17 on Debian 12 (amd64)**. The current beta release is **0.2.0-beta**. [Release notes and signed downloads](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/releases/tag/v0.2.0-beta).

> Beta software. Do not rely on it for critical or urgent notifications. Test your phones, network and delivery providers before use.

[Installation](#install-or-update) · [Requirements](#requirements) · [Features](#features) · [Documentation](#documentation) · [Report an issue](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/issues)

## Install or update

Use the checksum-pinned bootstrap below. For an existing installation, use `--upgrade` so the bootstrap verifies the release against your installed publisher policy. Preserve any failed transaction directory for recovery.

**Fresh installation**

```bash
curl --fail --location --proto '=https' --tlsv1.2 -o sls-bootstrap.sh \
  https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/v0.2.0-beta/tools/install_bootstrap.sh &&
printf '%s\n' '4cb772cb82f3c2c7ce7754efcc25d3cf265ce50b388b3f00b5dd042a05b20aa1  sls-bootstrap.sh' | sha256sum --check &&
sudo bash ./sls-bootstrap.sh 0.2.0-beta
```

**Upgrade an existing installation**

```bash
curl --fail --location --proto '=https' --tlsv1.2 -o sls-bootstrap.sh \
  https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/v0.2.0-beta/tools/install_bootstrap.sh &&
printf '%s\n' '4cb772cb82f3c2c7ce7754efcc25d3cf265ce50b388b3f00b5dd042a05b20aa1  sls-bootstrap.sh' | sha256sum --check &&
sudo bash ./sls-bootstrap.sh 0.2.0-beta --upgrade
```

For eligible unattended Lite installations, explicitly add `--lite` after the version and any `--upgrade` option. For interrupted installations, preserve the transaction path printed by the installer and follow the [recovery guide](docs/INSTALLER_OPERATIONS.md#interrupted-installations).

## Requirements

| Profile | Minimum resources | Limits |
| --- | --- | --- |
| Standard | 2 effective CPU cores, nominal 4 GiB RAM | Starts at 25 desktops and 25 phone contacts; higher capacity needs more resources. |
| Lite | 2 effective CPU cores, nominal 2 GiB RAM | 25 desktops, 25 phone contacts; Enterprise Labs and enterprise SSO unavailable. |

The locked speech runtime requires an x86-64-v2 CPU on every CPU available to the process. AVX is not required. Virtual machines must expose those features; the installer reports missing features before preparing SLL state.

**Standard is the default.** If usable RAM falls below its baseline, the installer checks whether Lite can run, explains its limits and asks before installing it. Ordinary kernel reservations on a nominal 4 GiB system are allowed. Declining the Lite prompt cancels installation.

Unattended Lite installation requires explicit `--lite` selection after `--upgrade` when applicable. Eligible interactive users receive the Lite offer only after its resource checks pass.

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

For authenticated repair, keep the signed assets, publisher policy and failed transaction directory. The installer checks configuration changes and retained history before restoring service. [Recovery procedure](docs/INSTALLER_OPERATIONS.md#interrupted-installations).

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
