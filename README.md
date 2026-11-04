<p align="center">
  <a href="https://southlandlabs.dev/projects/mass-notify/server"><img src="https://southlandlabs.dev/images/mass-notify-server.png?v=20261029" width="128" alt="SLL Mass Notify Server"></a>
</p>

# SLL Mass Notify Server

Send phone pages, desktop alerts, email, SMS and webhooks from FreePBX. Schedule announcements, publish weather alerts, and see results for each destination.

Built by [Southland Labs](https://southlandlabs.dev) for **FreePBX 17 on Debian 12 (amd64)**. The corrected software remains **0.1.9-beta**, candidate L, with planned reserved tag `release-0.1.9-beta`. It is **unpublished**; its command examples remain unavailable until qualification and publication. The available published prerelease is **0.1.8-beta**. The retired uppercase `V0.1.9-beta` release and the withdrawn `v0.1.10-beta` release must not be reused.

> Beta software. Do not rely on it for critical or urgent notifications. Test your phones, network and delivery providers before use.

[Installation](#install-or-update) · [Requirements](#requirements) · [Features](#features) · [Documentation](#documentation) · [Report an issue](https://github.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/issues)

## Install or update

**The following 0.1.9-beta command examples are unavailable pending qualification and publication. Do not run them yet.** They target only the reserved `release-0.1.9-beta` correction. Never substitute retired uppercase `V0.1.9-beta` downloads, withdrawn `v0.1.10-beta` downloads or an old offline bundle.

After publication, use `--upgrade` for an existing installation so its publisher policy, keys and revocations remain authoritative. Preserve settings and every failed transaction directory. The software version remains 0.1.9-beta; the updater does not automatically replace an equal version. The new reserved tag and signed artifact hashes distinguish this correction from the retired uppercase release.

Planned fresh installation, after qualification and publication:

```bash
curl --fail --location --proto '=https' --tlsv1.2 -o sls-bootstrap.sh \
  https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/release-0.1.9-beta/tools/install_bootstrap.sh &&
printf '%s\n' '0ef425a966647e8db8ebbd9c6a3bc0ae4586c96db8fd0ce50f3089b42217edb6  sls-bootstrap.sh' | sha256sum --check &&
sudo bash ./sls-bootstrap.sh 0.1.9-beta
```

Planned existing-installation upgrade or repair, also unavailable until publication:

```bash
curl --fail --location --proto '=https' --tlsv1.2 -o sls-bootstrap.sh \
  https://raw.githubusercontent.com/vipgabe09267/SouthlandLabs_Mass_Notify_server/release-0.1.9-beta/tools/install_bootstrap.sh &&
printf '%s\n' '0ef425a966647e8db8ebbd9c6a3bc0ae4586c96db8fd0ce50f3089b42217edb6  sls-bootstrap.sh' | sha256sum --check &&
sudo bash ./sls-bootstrap.sh 0.1.9-beta --upgrade
```

The corrected bootstrap selects only the reserved `release-0.1.9-beta` alias for this version by default while retained historical evidence remains verifiable. `--upgrade` authenticates existing publisher policy and preserves keys and revocations; fresh bootstrap refuses established installations. Eligible unattended Lite installation requires explicit `--lite` after `--upgrade` when upgrading.

The MFA/history recovery fixes are retained. Only proved monotonic TOTP-counter and associated operator-access revision progress can enter separate durable targets; every other setting remains exact. Original snapshots, write intentions, ciphertext evidence and authenticated carrier records remain protected. Unknown missing history still requires matching evidence or a valid explicit administrator decision. Current L qualification and publication remain pending. The withdrawn J build passed 424 isolated suites and nine bounded native scenarios as 0.1.10-beta; those exact source/artifact results remain historical evidence and do not qualify these rebuilt 0.1.9-beta assets. See the [qualification boundaries](docs/QUALIFICATION_MATRIX.md).

The user reports that 0.1.10-beta installed successfully, passed 16 doctor checks and preserved MFA/settings/keys after the administrator explicitly accepted 21 missing history records. This is user-reported, not independent target qualification of the new 0.1.9-beta artifacts. See [qualification boundaries](docs/QUALIFICATION_MATRIX.md).

Historical H passed 423 isolated suites, four native install/rollback cases and three installed journal profiles before withdrawal. Earlier G 423/18/360 and withdrawn J 424/nine-native results remain separate historical evidence; they do not qualify the new reserved-tag 0.1.9-beta correction or establish recovery of the reported target.

## Requirements

| Profile | Minimum resources | Limits |
| --- | --- | --- |
| Standard | 2 effective CPU cores, nominal 4 GiB RAM | Starts at 25 desktops and 25 phone contacts; higher capacity needs more resources. |
| Lite | 2 effective CPU cores, nominal 2 GiB RAM | 25 desktops, 25 phone contacts; Enterprise Labs and enterprise SSO unavailable. |

The locked speech runtime requires an x86-64-v2 CPU on every CPU available to the process. AVX is not required. Virtual machines must expose those features; the installer reports missing features before preparing SLL state.

**Standard is the default.** If usable RAM falls below its baseline, the installer checks whether Lite can run, explains its limits and asks before installing it. Ordinary kernel reservations on a nominal 4 GiB system are allowed. Declining the Lite prompt cancels installation.

Unattended Lite installation requires explicit `--lite` selection. The candidate commands above remain unavailable until qualification and publication; eligible interactive users receive the Lite offer only after its resource checks pass.

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

Installer-driven repair and upgrade await qualified, published reserved-tag `release-0.1.9-beta` assets. Follow the [installer recovery guide](docs/INSTALLER_OPERATIONS.md). Keep the exact failed transaction directory; do not reset MFA, delete evidence or alter history to bypass a check.

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
