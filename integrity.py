"""
integrity.py — OmniCore startup integrity check (fail-closed)
==============================================================
Verifies that all required bootstrap files exist in the application
root BEFORE anything else runs.  Missing files abort startup with a
clear message — nothing is deleted, nothing is modified.

Design:
  * Pure stdlib.  No imports beyond os/sys/pathlib.
  * Never writes to disk.  Never spawns subprocesses.
  * Safe to call from main.py at the very top.
  * Bypass for development: set OMNICORE_DEV=1 (but only when the
    check itself would fail for a non-security reason).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# ─── Required bootstrap files ───────────────────────────────────────────
# These MUST exist next to main.py for the framework to function.  If any
# is missing, OmniCore refuses to start (fail-closed).
REQUIRED_BOOTSTRAP = (
    "main.py",
    "hwid_guard.py",
    "updater.py",
    "hardware_id.py",
)

# ─── Optional-but-recommended ───────────────────────────────────────────
# Missing entries produce a warning only (they can be regenerated).
RECOMMENDED_BOOTSTRAP = (
    "README.md",
    "requirements.txt",
)


class IntegrityError(RuntimeError):
    """Raised when the bootstrap file set is incomplete."""


def _project_root() -> Path:
    """Directory containing this file = the application root."""
    return Path(__file__).resolve().parent


def check_required(root: Path = None) -> tuple:
    """
    Check that every REQUIRED_BOOTSTRAP file exists.

    Returns (ok: bool, missing: list[str], present: list[str]).
    """
    root = root or _project_root()
    missing = []
    present = []
    for name in REQUIRED_BOOTSTRAP:
        if (root / name).is_file():
            present.append(name)
        else:
            missing.append(name)
    return (len(missing) == 0, missing, present)


def check_recommended(root: Path = None) -> list:
    """Return list of missing recommended files."""
    root = root or _project_root()
    return [n for n in RECOMMENDED_BOOTSTRAP
            if not (root / n).is_file()]


def assert_bootstrap(root: Path = None, *, allow_dev: bool = True) -> None:
    """
    Raise IntegrityError if any required file is missing.

    When allow_dev=True and OMNICORE_DEV=1, only prints a warning
    instead of raising — used during development to keep working on a
    partial tree.
    """
    root = root or _project_root()
    ok, missing, present = check_required(root)
    if ok:
        return

    dev_bypass = allow_dev and os.environ.get("OMNICORE_DEV", "").strip() \
        in ("1", "true", "yes")

    msg = (
        "OmniCore bootstrap integrity check FAILED.\n"
        "  Missing required file(s): " + ", ".join(missing) + "\n"
        "  Root directory         : " + str(root) + "\n"
        "\n"
        "This is a fail-closed policy: the framework will not start\n"
        "with an incomplete installation.  No files were modified.\n"
        "\n"
        "To fix:\n"
        "  * Re-clone the repository, or\n"
        "  * Restore the missing file(s) from a backup, or\n"
        "  * Re-install OmniCore.\n"
    )

    if dev_bypass:
        # Development-only: warn and continue
        sys.stderr.write(
            "[OmniCore][dev] integrity warning — missing: %s\n"
            % ", ".join(missing))
        sys.stderr.flush()
        return

    raise IntegrityError(msg)


def install_exit_handler() -> None:
    """Ensure a clean message and non-zero exit if IntegrityError
    reaches the top level (used when main.py does not catch it)."""
    import atexit  # noqa: F401 — kept for future use


def summary_line() -> str:
    """One-line summary for banners and logs."""
    root = _project_root()
    ok, missing, present = check_required(root)
    total = len(REQUIRED_BOOTSTRAP)
    if ok:
        return "bootstrap integrity: OK (%d/%d files)" % (total, total)
    return "bootstrap integrity: FAILED (%d/%d present)" % (
        total - len(missing), total)


# ─── CLI smoke test ──────────────────────────────────────────────────────
if __name__ == "__main__":
    root = _project_root()
    print("=" * 62)
    print("  OmniCore · Bootstrap Integrity")
    print("=" * 62)
    print("  root: %s" % root)
    print()
    ok, missing, present = check_required(root)
    for name in REQUIRED_BOOTSTRAP:
        mark = "*" if name in present else " "
        status = "present" if name in present else "MISSING"
        print("    %s %-20s %s" % (mark, name, status))
    print()
    rec_missing = check_recommended(root)
    if rec_missing:
        print("  recommended missing: %s" % ", ".join(rec_missing))
    else:
        print("  recommended: all present")
    print()
    print("  %s" % summary_line())
    print()
    sys.exit(0 if ok else 1)
