<p align="center">
  <a href="https://southlandlabs.dev/projects/mass-notify/server"><img src="https://southlandlabs.dev/images/mass-notify-server.png?v=20261029" width="128" alt="SLL Mass Notify Server"></a>
</p>

# SLL Mass Notify Server

Send phone pages, desktop alerts, email, SMS and webhooks from FreePBX. Schedule announcements, publish weather alerts, and see results for each destination.

Built by [Southland Labs](https://southlandlabs.dev) for **FreePBX 17 on Debian 12 (amd64)**. **0.1.10-beta is the available published prerelease**, tag `v0.1.10-beta`. **0.1.9-beta is withdrawn**; its release and downloads were removed, and the retired `V0.1.9-beta` tag must not be reused.

> Beta software. Do not rely on it for critical or urgent notifications. Test your phones, network and delivery providers before use.

[Installation](#install-or-update) · [Requirements](#requirements) · [Features](#features) · [Documentation](#documentation) · [Report an issue](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/issues)

## Install or update

**0.1.10-beta is published with signed assets and verified public downloads/provenance.** The checksum-pinned commands below use its new immutable tag. Never substitute retired `V0.1.9-beta` downloads or an old offline bundle.

Use `--upgrade` for an existing installation so its publisher policy, keys and revocations remain authoritative. Preserve existing settings, publisher trust and every failed transaction directory. The immutable tag and signed package retain their original prepublication documentation snapshot. This published-status update belongs to a separate documentation commit on main; it does not change release bytes or move the tag.

Fresh installation:

```bash
curl --fail --location --proto '=https' --tlsv1.2 -o sls-bootstrap.sh \
  https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/v0.1.10-beta/tools/install_bootstrap.sh &&
printf '%s\n' 'bdf8e32e22a0baeed9a5764f0ade1f6a110fbde686cb8ea5f4f06a026ea1da75  sls-bootstrap.sh' | sha256sum --check &&
sudo bash ./sls-bootstrap.sh 0.1.10-beta
```

Existing-installation upgrade or repair:

```bash
curl --fail --location --proto '=https' --tlsv1.2 -o sls-bootstrap.sh \
  https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/v0.1.10-beta/tools/install_bootstrap.sh &&
printf '%s\n' 'bdf8e32e22a0baeed9a5764f0ade1f6a110fbde686cb8ea5f4f06a026ea1da75  sls-bootstrap.sh' | sha256sum --check &&
sudo bash ./sls-bootstrap.sh 0.1.10-beta --upgrade
```

The unchanged bootstrap supports the new version's generic `v` tag. `--upgrade` authenticates against existing publisher policy and preserves keys and revocations; fresh bootstrap refuses established installations. An eligible unattended Lite installation needs explicit `--lite` (after `--upgrade` when upgrading). Review the limits below before selecting it.

The release preserves consumed MFA counters and the associated operator-access revision during recovery. Separate durable targets preserve that progress without replacing original evidence or accepting unrelated settings edits. **424/424 independent isolated suites passed**, including required browser/UI and schema checks; **9 native scenarios passed** in marked disposable QEMU branches. Signed public assets and exact-tag provenance were verified. See the [qualification boundaries](docs/QUALIFICATION_MATRIX.md) for the nine scenarios and their limits.

The reported LiteNet history still has 22 baseline records: 1 unchanged, 21 missing and 0 with proven expiry. Ordinary recovery must return exit 4 without matching evidence; no administrator has accepted the missing history. MFA handling does not waive this gate. See [recovery operations](docs/INSTALLER_OPERATIONS.md) and the [qualification boundaries](docs/QUALIFICATION_MATRIX.md).

Historical H passed 423 isolated suites, four native install/rollback cases and three installed journal profiles before withdrawal. Those results and earlier G 423/18/360 evidence do not qualify 0.1.10-beta or establish recovery of the reported target.

## Requirements

| Profile | Minimum resources | Limits |
| --- | --- | --- |
| Standard | 2 effective CPU cores, nominal 4 GiB RAM | Starts at 25 desktops and 25 phone contacts; higher capacity needs more resources. |
| Lite | 2 effective CPU cores, nominal 2 GiB RAM | 25 desktops, 25 phone contacts; Enterprise Labs and enterprise SSO unavailable. |

The locked speech runtime requires an x86-64-v2 CPU on every CPU available to the process. AVX is not required. Virtual machines must expose those features; the installer reports missing features before preparing SLL state.

**Standard is the default.** If usable RAM falls below its baseline, the installer checks whether Lite can run, explains its limits and asks before installing it. Ordinary kernel reservations on a nominal 4 GiB system are allowed. Declining the Lite prompt cancels installation.

Unattended Lite installation requires explicit `--lite` selection. The published commands above otherwise select Standard by default; eligible interactive users receive the Lite offer only after its resource checks pass.

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

Installer-driven repair and upgrade await a qualified, published 0.1.10-beta release. Follow the evidence-preservation guidance in the [installer recovery guide](docs/INSTALLER_OPERATIONS.md). Keep the exact recovery path printed by a failed installer; do not delete it, reset MFA state or alter history to bypass a check.

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
