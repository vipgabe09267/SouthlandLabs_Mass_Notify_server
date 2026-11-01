#!/usr/bin/python3
"""Optional cross-repository compatibility checks in the private test namespace."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

def qualification_suites(root):
    common = [
        "test_sls_live_polling", "test_sls_delivery_store",
        "test_sls_backend_contract", "test_sls_transport_deadlines",
    ]
    # Current clients consolidate cursor, negotiation and authenticated-media
    # checks in this suite. Earlier reviewed clients kept separate modules.
    if (root / "tests/test_sls_desktop_compatibility.py").is_file():
        names = common + ["test_sls_desktop_compatibility"]
    else:
        names = common + ["test_sls_live_poll_cursor", "test_sls_panic", "test_sls_media_auth"]
    required = [root / "src/sls_mass_notify.py", root / "tests/__init__.py"]
    required += [root / "tests" / (name + ".py") for name in names]
    missing = [str(path.relative_to(root)) for path in required if not path.is_file() or path.is_symlink()]
    if missing:
        raise SystemExit("The desktop qualification source tree is incomplete: " + ", ".join(missing))
    return ["tests." + name for name in names]


def main():
    source = os.environ.get("SLS_DESKTOP_APP_SOURCE", "")
    if not source:
        if os.environ.get("SLS_DESKTOP_APP_REQUIRED") == "1":
            raise SystemExit("Set SLS_DESKTOP_APP_SOURCE to the reviewed desktop checkout.")
        print("Desktop cross-repository qualification not run: no reviewed app checkout was supplied.")
        return 0
    if os.environ.get("SLS_TEST_NAMESPACE") != "entered":
        raise SystemExit("Use tools/run_isolated_tests.sh for desktop compatibility checks.")
    root = Path(source).resolve(strict=True)
    suites = qualification_suites(root)
    # The Windows client can require a newer CPython than the supported PBX.
    # Use only an explicit reviewed executable; never install one in a fixture.
    python = os.environ.get("SLS_DESKTOP_PYTHON") or sys.executable
    if not Path(python).is_absolute() or not Path(python).is_file() or not os.access(python, os.X_OK):
        raise SystemExit("SLS_DESKTOP_PYTHON must name an available absolute Python executable.")
    print("Desktop contract suites: " + ", ".join(suites), flush=True)
    with tempfile.TemporaryDirectory(prefix="sls-desktop-app-qualification-") as temporary:
        paths = [str(root / "src")] + [
            value for value in os.environ.get("SLS_DESKTOP_PYTHON_PATH", "").split(os.pathsep) if value
        ]
        environment = dict(
            os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=os.pathsep.join(paths),
            APPDATA=temporary, LOCALAPPDATA=temporary,
        )
        result = subprocess.run(
            [python, "-m", "unittest", *suites], cwd=root, env=environment,
            check=False, timeout=210,
        )
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
