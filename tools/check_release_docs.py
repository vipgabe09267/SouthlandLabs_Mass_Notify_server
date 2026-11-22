#!/usr/bin/python3
"""Check candidate/published documentation state without consulting live PBX state."""
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def release_state(record, version):
    if (
        not isinstance(record, dict)
        or set(record)
        != {
            "schema",
            "published_version",
            "candidate_version",
            "candidate_status",
            "purpose",
        }
        or type(record["schema"]) is not int
        or record["schema"] != 1
        or not isinstance(record["purpose"], str)
        or not record["purpose"].strip()
    ):
        raise ValueError("Release documentation record has an invalid schema.")
    if record["candidate_version"] != version:
        raise ValueError("Candidate documentation state differs from module.xml.")
    for value in [version, record["published_version"]]:
        if not isinstance(value, str) or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+-beta", value
        ):
            raise ValueError("Release documentation version is invalid.")
    current = tuple(map(int, version[:-5].split(".")))
    published = tuple(map(int, record["published_version"][:-5].split(".")))
    status = record["candidate_status"]
    if status == "published" and version == record["published_version"]:
        return status
    if status == "unpublished" and current > published:
        return status
    raise ValueError("Published documentation must match the release; unpublished candidates must follow it.")


def check_mirrors(root, names):
    """A published source tree keeps the packaged manuals from its signed install."""
    different = []
    for name in names:
        source = (root / name).read_bytes()
        packaged = (root / "slsmassnotifyserver" / name).read_bytes()
        if source != packaged:
            different.append((name, hashlib.sha256(packaged).hexdigest()))
    if not different:
        return

    version = ET.parse(root / "slsmassnotifyserver/module.xml").findtext("version")
    state = json.loads((root / "docs/release-status.json").read_bytes())
    if release_state(state, version) == "published":
        # This receipt records manual hashes read from the authenticated release
        # archive. Bind it to the installer, which pins that exact archive.
        receipt = root / "tools/published-doc-snapshots" / (version + ".json")
        if receipt.is_file():
            pins = json.loads(receipt.read_bytes())
            installer = hashlib.sha256((root / "tools/install_release.sh").read_bytes()).hexdigest()
            if installer == pins["installer_sha256"]:
                different = [(name, digest) for name, digest in different
                             if pins["files"].get(name) != digest]
    if different:
        raise ValueError("Packaged documentation differs: " + different[0][0])


def check(root=ROOT):
    record = json.loads((root / "docs/release-status.json").read_text())
    version = ET.parse(root / "slsmassnotifyserver/module.xml").findtext("version")
    status = release_state(record, version)
    for name in ["CONTROL_API.md", "QUALIFICATION_MATRIX.md"]:
        intro = (root / "docs" / name).read_text()[:500]
        if (version not in intro or re.search(r"\b" + status + r"\b", intro) is None
                or (status == "published" and re.search(r"\bunpublished\b", intro))):
            raise ValueError("Current release state is missing from " + name)
    check_mirrors(root, [
        "docs/release-status.json", "docs/QUALIFICATION_MATRIX.md",
        "docs/openapi.json", "docs/schemas/notification.schema.json",
    ])
    readme = (root / "README.md").read_text()
    digest = hashlib.sha256(
        (root / "tools/install_bootstrap.sh").read_bytes()
    ).hexdigest()
    candidate_command = "sls-bootstrap.sh " + version in readme
    published = record["published_version"]
    published_tag = ("release-0.1.9-beta" if published == "0.1.9-beta" else
                     ("slsmassnotifyserver-" if tuple(map(int, published[:-5].split('.'))) < (0,1,9) else "v") + published)
    retained_published_commands = (status == "unpublished" and not candidate_command
        and "sls-bootstrap.sh " + published in readme and published_tag in readme
        and version in readme and "unpublished" in readme
        and re.search(r"\b[0-9a-f]{64}  sls-bootstrap\.sh\b", readme) is not None)
    if not retained_published_commands and (
        digest + "  sls-bootstrap.sh" not in readme or not candidate_command
    ):
        raise ValueError("The README bootstrap checksum/version is stale.")
    security = (root / "SECURITY.md").read_text()
    if "currently `" + record["published_version"] + "`" not in security:
        raise ValueError("The security policy published version is stale.")
    print(
        "Module version, release state, bootstrap checksum and packaged descriptions agree."
    )


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--top-level-mirrors"]:
            check_mirrors(ROOT, ["README.md", "INSTALL.md", "CHANGELOG.md", "SECURITY.md",
                                 "PHONE_FORMATS.md", "LICENSE"])
        elif len(sys.argv) == 1:
            check()
        else:
            raise ValueError("Usage: check_release_docs.py [--top-level-mirrors]")
    except (OSError, ValueError, ET.ParseError) as error:
        raise SystemExit(str(error))
