#!/usr/bin/env python3
"""OmniCore — entry point, license gate and dynamic module runtime.

Strict four-phase startup pipeline for the OmniCore Linux framework:

    Phase 1  HWID & license enforcement via the sibling ``hwid_guard``
            module (``authorize_application(interactive=True)``).
    Phase 2  Atomic, hash-verified auto-update pipeline via the sibling
            ``updater`` module (Supabase REST + XDG module store).
    Phase 3  ``$XDG_DATA_HOME/OmniCore/modules`` is prepended to
            ``sys.path`` and the configured core modules are dynamically
            imported; the primary module's entry hook is invoked.
    Phase 4  Graceful shutdown with structured exit codes.

Module contract (Phase 3)
-------------------------
Core modules are selected via ``$OMNICORE_CORE_MODULES`` (comma-separated,
default ``core_engine``).  The first successfully loaded module is the
*primary* module; if it exposes ``omnicore_entry(ctx)``, ``omnicore_main``,
``main`` or ``run``, it is invoked — with the :class:`RuntimeContext` when
the hook accepts a positional argument, without one otherwise.  An integer
return value becomes the process exit code.

Environment
-----------
    SUPABASE_URL             Supabase project URL (license + updates)
    SUPABASE_ANON_KEY        Supabase anon key
    OMNICORE_CORE_MODULES    ordered core-module names
    XDG_DATA_HOME / XDG_CACHE_HOME / XDG_STATE_HOME / XDG_RUNTIME_DIR
    NO_COLOR / FORCE_COLOR   ANSI palette overrides

Exit codes
----------
    0    success
    11   access denied (LicenseEnforcementError)
    12   license server unreachable (SupabaseConnectionError)
    13   core module failure
    14   fatal / unexpected error
    130  interrupted by user (SIGINT)
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import logging
import os
import platform
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:  # pragma: no cover - typing only
    from updater import SyncReport

# Ensure sibling modules (updater.py, hwid_guard.py) are importable no
# matter which directory the process was launched from.
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ─── Fail-closed bootstrap integrity check ──────────────────────────────
# Runs before anything else.  If a required bootstrap file is missing,
# OmniCore refuses to start — no files are ever modified or deleted.
try:
    from integrity import assert_bootstrap as _assert_bootstrap
    _assert_bootstrap(allow_dev=True)   # dev bypass honoured if OMNICORE_DEV=1
except ImportError:
    # The integrity module itself is missing — refuse to start.
    sys.stderr.write(
        "[x] Fatal: 'integrity.py' is missing from the install root.\n"
        "[x] Re-clone the repository or restore integrity.py.\n")
    sys.exit(1)
except Exception as _ie:
    # IntegrityError carries a detailed message; print it and exit.
    sys.stderr.write("\n" + str(_ie) + "\n")
    sys.exit(1)


# ─── Embedded credentials (PUBLIC — protected by Row-Level Security) ───
# The anon key is DESIGNED to be public: it grants only the "anon" role,
# and RLS policies on the database decide what that role may do. Shipping
# it inside main.py is safe and matches Supabase's official guidance.
#
# A local config.py — if present — may OVERRIDE these values, so operators
# can point the same binary at a different project without editing main.py.
SUPABASE_URL = "https://dolgcaxknbfufxyqrkmd.supabase.co"
SUPABASE_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRvbGdjYXhrbmJmdWZ4eXFya21kIiwicm9s"
    "ZSI6ImFub24iLCJpYXQiOjE3OTA2ODg2NzQsImV4cCI6MjEwNjI2NDY3NH0."
    "hTX7afaCD2FyFtQfm7x2QYiiDZzvC7Jzwpo5vbrjC3Y"
)

try:
    import config as _cfg  # type: ignore
    if getattr(_cfg, "SUPABASE_URL", None):
        SUPABASE_URL = _cfg.SUPABASE_URL
    if getattr(_cfg, "SUPABASE_ANON_KEY", None):
        SUPABASE_ANON_KEY = _cfg.SUPABASE_ANON_KEY
except ImportError:
    pass
except Exception:
    pass

# Export to the process environment — hwid_guard.py and updater.py read
# from here, so no code change is needed in either of them.
os.environ.setdefault("SUPABASE_URL", SUPABASE_URL)
os.environ.setdefault("SUPABASE_ANON_KEY", SUPABASE_ANON_KEY)

APP_NAME = "OmniCore"
APP_VERSION = "1.0.0"
TAGLINE = "unified linux framework · secure module runtime"

EXIT_OK = 0
EXIT_LICENSE_DENIED = 11
EXIT_SERVER_UNREACHABLE = 12
EXIT_MODULE_FAILURE = 13
EXIT_FATAL = 14
EXIT_INTERRUPTED = 130

_PANEL_WIDTH = 70
_DEFAULT_CORE_MODULES = ("core_engine",)
_CORE_MODULES_ENV = "OMNICORE_CORE_MODULES"
_ENTRY_HOOK_NAMES = ("omnicore_entry", "omnicore_main", "main", "run")
_HWID_PROVIDER_NAMES = (
    "get_system_hwid",      # ← الاسم الفعلي في hwid_guard.py
    "generate_hwid",
    "compute_hwid",
    "get_hwid",
    "hwid",
    "get_machine_id",
)

_BANNER_LINES: tuple[str, ...] = (
    " ██████╗ ███╗   ███╗███╗   ██╗██╗ ██████╗ ██████╗ ██████╗ ███████╗",
    "██╔═══██╗████╗ ████║████╗  ██║██║██╔════╝██╔═══██╗██╔══██╗██╔════╝",
    "██║   ██║██╔████╔██║██╔██╗ ██║██║██║     ██║   ██║██████╔╝█████╗  ",
    "██║   ██║██║╚██╔╝██║██║╚████╗║██║██║     ██║   ██║██╔══██╗██╔══╝  ",
    "██║   ██║██║ ╚═╝ ██║██║ ╚███║║██║██║     ██║   ██║██║  ██║███████╗",
    "╚██████╔╝╚═╝     ╚═╝╚═╝  ╚══╝╝╚═╝╚██████╗╚██████╔╝██║  ██║╚══════╝",
)
_BANNER_GRADIENT: tuple[str, ...] = (
    "38;5;51", "38;5;50", "38;5;49", "38;5;48", "38;5;47", "38;5;46",
)


# ----------------------------------------------------------------------
# Console aesthetics
# ----------------------------------------------------------------------
class ConsolePalette:
    """ANSI escape palette honouring TTY detection, NO_COLOR, FORCE_COLOR."""

    __slots__ = ("enabled",)

    def __init__(self, enabled: bool | None = None) -> None:
        """Create a palette; ``None`` auto-detects colour support."""
        self.enabled = self._detect() if enabled is None else bool(enabled)

    @staticmethod
    def _detect() -> bool:
        """Return True when stdout can safely render ANSI escapes."""
        if os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        if os.environ.get("TERM", "dumb").strip().lower() == "dumb":
            return False
        return sys.stdout.isatty()

    def wrap(self, text: str, code: str) -> str:
        """Wrap *text* in the given SGR *code* (no-op when disabled)."""
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def cyan(self, text: str) -> str:
        """Neon cyan (primary brand colour)."""
        return self.wrap(text, "38;5;51")

    def green(self, text: str) -> str:
        """Neon green (success states)."""
        return self.wrap(text, "38;5;46")

    def yellow(self, text: str) -> str:
        """Amber (warnings)."""
        return self.wrap(text, "38;5;226")

    def red(self, text: str) -> str:
        """Neon red (errors / denials)."""
        return self.wrap(text, "38;5;196")

    def dim(self, text: str) -> str:
        """Dimmed metadata."""
        return self.wrap(text, "2")


def _truncate(text: str, limit: int) -> str:
    """Clip *text* to *limit* visible characters using an ellipsis."""
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    return text[: max(limit - 1, 0)] + "…"


def _os_release_field(field: str) -> str:
    """Read a single field from /etc/os-release (or its lib fallback)."""
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = Path(candidate).read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, _, raw = line.partition("=")
            if key.strip() == field:
                return raw.strip().strip('"').strip("'")
    return ""


def _os_description() -> str:
    """Return a human-readable OS/kernel/machine description."""
    pretty = _os_release_field("PRETTY_NAME")
    kernel = platform.release() or "unknown"
    machine = platform.machine() or "?"
    base = pretty or f"{platform.system()} {kernel}"
    return f"{base} (kernel {kernel}, {machine})"


def _session_environment() -> str:
    """Classify the desktop / graphics / remote environment."""
    if os.environ.get("SSH_TTY") or os.environ.get("SSH_CONNECTION"):
        return "remote (SSH)"
    parts: list[str] = []
    session_type = os.environ.get("XDG_SESSION_TYPE", "").lower()
    if session_type:
        parts.append(session_type)
    if os.environ.get("WAYLAND_DISPLAY") and "wayland" not in parts:
        parts.append("wayland")
    elif os.environ.get("DISPLAY") and "x11" not in parts:
        parts.append("x11")
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").strip()
    if desktop:
        parts.append(desktop)
    if not parts:
        return "headless / TTY"
    return " · ".join(parts)


def _probe_hwid_summary() -> str:
    """Best-effort HWID summary for the banner (never fatal)."""
    try:
        import hwid_guard  # deferred: sibling module shipped with the app
    except ImportError:
        return "deferred (resolved during license check)"
    for name in _HWID_PROVIDER_NAMES:
        provider = getattr(hwid_guard, name, None)
        if not callable(provider):
            continue
        try:
            value = provider()
        except Exception:  # noqa: BLE001 - banner probe must never break boot
            continue
        if isinstance(value, str) and value.strip():
            digest = value.strip().lower()
            return f"{digest[:12]}… ({len(digest)}-char fingerprint)"
    return "unavailable"


def print_banner(palette: ConsolePalette) -> None:
    """Render the OmniCore ASCII banner (cyan-to-green gradient)."""
    width = max(len(line) for line in _BANNER_LINES)
    rule = palette.dim("─" * (width + 4))
    print()
    print(f"  {rule}")
    for line, code in zip(_BANNER_LINES, _BANNER_GRADIENT):
        print(f"  {palette.wrap(line, code)}")
    print(f"  {palette.cyan(f'OMNICORE v{APP_VERSION} · {TAGLINE}')}")
    print(f"  {rule}")
    print()


def print_status_panel(
    palette: ConsolePalette,
    *,
    hwid_summary: str,
    license_state: str,
) -> None:
    """Render the boxed system status panel (pre-flight snapshot)."""
    rows: list[tuple[str, str]] = [
        ("Python", f"{platform.python_version()} "
                   f"({platform.python_implementation()})"),
        ("OS", _os_description()),
        ("Environment", _session_environment()),
        ("HWID", hwid_summary),
        ("Session", license_state),
    ]
    label_width = max(len(label) for label, _ in rows)
    value_width = _PANEL_WIDTH - label_width - 7
    header = "┌─[ SYSTEM STATUS ]"
    top = header + "─" * (_PANEL_WIDTH - len(header) - 1) + "┐"
    bottom = "└" + "─" * (_PANEL_WIDTH - 2) + "┘"
    print(palette.dim(top))
    for label, value in rows:
        cell = _truncate(value, value_width).ljust(value_width)
        if label == "Session" and "PENDING" in value:
            cell = palette.yellow(cell)
        elif label == "Session":
            cell = palette.green(cell)
        elif label == "HWID":
            cell = palette.cyan(cell)
        label_cell = palette.dim(label.ljust(label_width))
        print(f"│ {label_cell} : {cell} │")
    print(palette.dim(bottom))
    print()


def _phase_header(palette: ConsolePalette, title: str) -> None:
    """Print a cyan phase separator."""
    filler = "─" * max(2, _PANEL_WIDTH - len(title) - 5)
    print(palette.cyan(f"── {title} {filler}"))


def _colorize_summary(palette: ConsolePalette, line: str) -> str:
    """Apply a semantic colour to a summary line based on its status token."""
    match line[:3]:
        case "[+]":
            return palette.green(line)
        case "[=]":
            return palette.cyan(line)
        case "[i]":
            return palette.dim(line)
        case "[!]" | "[~]" | "[-]":
            return palette.yellow(line)
        case "[x]":
            return palette.red(line)
        case _:
            return line


# ----------------------------------------------------------------------
# Pipeline control flow
# ----------------------------------------------------------------------
class PipelineAbort(Exception):
    """Internal signal: abort the pipeline with a specific exit code."""

    def __init__(self, exit_code: int, message: str) -> None:
        """Store the mandated exit code and a human-readable reason."""
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


@dataclass(slots=True)
class RuntimeContext:
    """Execution context handed to dynamically loaded core modules."""

    app_name: str
    app_version: str
    data_dir: Path
    modules_dir: Path
    hwid: str
    sync_report: SyncReport | None
    logger: logging.Logger
    argv: list[str]


def _parse_args(argv: Sequence[str]) -> tuple[argparse.Namespace, list[str]]:
    """Parse known flags; unknown arguments flow through to core modules."""
    parser = argparse.ArgumentParser(
        prog="omnicore",
        description="OmniCore — secure, hash-verified Linux module runtime.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="verbose (DEBUG) logging"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="disable ANSI colours"
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="skip the ASCII banner and status panel",
    )
    parser.add_argument(
        "--version", action="version", version=f"OmniCore {APP_VERSION}"
    )
    known, extra = parser.parse_known_args(list(argv))
    return known, extra


def _session_summary(session: object, fallback: str = "unknown") -> str:
    """Summarise whatever ``authorize_application`` returned."""
    if isinstance(session, str) and session.strip():
        digest = session.strip().lower()
        return f"{digest[:12]}… ({len(digest)}-char fingerprint)"
    if session is None:
        return fallback
    return "granted"


def _phase1_license(palette: ConsolePalette, hwid_probe: str) -> str:
    """Phase 1 — HWID & license enforcement.

    Returns:
        The verified HWID summary string.

    Raises:
        PipelineAbort: with the mandated exit code on any licensing failure.
    """
    _phase_header(palette, "PHASE 1 :: HWID & LICENSE ENFORCEMENT")
    try:
        import hwid_guard  # deferred: sibling module shipped with the app
    except ImportError as exc:
        raise PipelineAbort(
            EXIT_FATAL,
            f"required component 'hwid_guard' unavailable: {exc}",
        ) from exc
    authorizer = getattr(hwid_guard, "authorize_application", None)
    if not callable(authorizer):
        raise PipelineAbort(
            EXIT_FATAL, "'hwid_guard.authorize_application' is missing"
        )
    # Defensive lookups: () never matches, so a missing exception class
    # degrades into the generic handler instead of an AttributeError.
    enforcement_error = getattr(hwid_guard, "LicenseEnforcementError", ())
    connection_error = getattr(hwid_guard, "SupabaseConnectionError", ())
    try:
        session = authorizer(interactive=True)
    except enforcement_error as exc:
        raise PipelineAbort(
            EXIT_LICENSE_DENIED, f"access denied — {exc}"
        ) from exc
    except connection_error as exc:
        raise PipelineAbort(
            EXIT_SERVER_UNREACHABLE, f"license server unreachable — {exc}"
        ) from exc
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        raise PipelineAbort(
            EXIT_FATAL, f"unexpected licensing subsystem error: {exc}"
        ) from exc
    # Prefer the real fingerprint over the abstract session summary.
    try:
        real_hwid = hwid_guard.get_system_hwid()
    except Exception:
        real_hwid = ""
    if isinstance(real_hwid, str) and real_hwid.strip():
        fp = real_hwid.strip().lower()
        summary = f"{fp[:12]}... ({len(fp)}-char fingerprint)"
    else:
        summary = _session_summary(session, hwid_probe)
    print(palette.green(
        f"[+] License verified :: HWID {summary} :: session ACTIVE"
    ))
    print()
    return summary


def _phase2_sync_modules(
    palette: ConsolePalette, *, verbose: bool
) -> SyncReport:
    """Phase 2 — run the auto-update pipeline and print a clean summary.

    Returns:
        The :class:`~updater.SyncReport`; a degraded (offline) report is
        returned instead of raising so execution continues from cache.
    """
    from updater import AutoUpdater, SyncReport, UpdaterError  # deferred

    _phase_header(palette, "PHASE 2 :: AUTO-UPDATE PIPELINE")
    print(palette.dim("[i] Checking remote manifest…"))
    try:
        updater = AutoUpdater(
            supabase_url=os.environ.get("SUPABASE_URL"),
            supabase_key=(
                os.environ.get("SUPABASE_ANON_KEY")
                or os.environ.get("SUPABASE_KEY")
            ),
        )
        report = updater.sync_all()
    except UpdaterError as exc:
        degraded = SyncReport(
            offline=True,
            notes=[
                f"[!] Offline — update pipeline degraded: {exc}",
                "[i] Continuing with cached local modules.",
            ],
        )
        print(palette.yellow(degraded.notes[0]))
        print(palette.dim(degraded.notes[1]))
        print()
        return degraded
    if verbose:
        for line in report.detail_lines():
            print(palette.dim(line))
    for line in report.summary_lines():
        print(_colorize_summary(palette, line))
    print()
    return report


def _core_module_names() -> list[str]:
    """Resolve the ordered core-module list (env override included)."""
    raw = os.environ.get(_CORE_MODULES_ENV, "")
    names = [token.strip() for token in raw.split(",") if token.strip()]
    return names or list(_DEFAULT_CORE_MODULES)


def _discover_modules(root: Path) -> list[str]:
    """List importable top-level modules/packages inside *root*."""
    discovered: list[str] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return discovered
    for entry in entries:
        if entry.name.startswith(".") or entry.name == "__init__.py":
            continue
        if entry.is_file() and entry.suffix == ".py":
            discovered.append(entry.stem)
        elif entry.is_dir() and (entry / "__init__.py").is_file():
            discovered.append(entry.name)
    return discovered


def _phase3_load_modules(
    context: RuntimeContext, palette: ConsolePalette
) -> dict[str, ModuleType]:
    """Phase 3 — prepend the module store to ``sys.path`` and import cores.

    Returns:
        Mapping of module name to imported module (insertion-ordered).

    Raises:
        PipelineAbort: a downloaded module exists but fails to import.
    """
    _phase_header(palette, "PHASE 3 :: DYNAMIC MODULE INJECTION")
    modules_dir = context.modules_dir
    logger = context.logger
    if not modules_dir.is_dir():
        message = f"module store missing: {modules_dir}"
        logger.warning("%s", message)
        print(palette.yellow(f"[!] {message}"))
        return {}
    modules_path = str(modules_dir)
    if modules_path not in sys.path:
        sys.path.insert(0, modules_path)
        logger.debug("prepended %s to sys.path", modules_path)
    importlib.invalidate_caches()
    loaded: dict[str, ModuleType] = {}
    missing: list[str] = []
    broken: list[tuple[str, Exception]] = []
    for name in _core_module_names():
        try:
            loaded[name] = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name == name:
                missing.append(name)
            else:
                broken.append((name, exc))
        except ImportError as exc:
            broken.append((name, exc))
        except Exception as exc:  # module-level code failed — strict abort
            broken.append((name, exc))
        else:
            origin = getattr(loaded[name], "__file__", "<builtin>")
            logger.info("loaded module '%s' from %s", name, origin)
            print(palette.green(f"[+] Loaded module '{name}' ({origin})"))
    if missing:
        available = _discover_modules(modules_dir)
        listing = ", ".join(available) if available else "none"
        print(palette.yellow(f"[!] Not downloaded yet: {', '.join(missing)}"))
        print(palette.dim(f"[i] Module store contents: {listing}"))
        logger.warning(
            "core module(s) missing from store: %s", ", ".join(missing)
        )
    if broken:
        for name, exc in broken:
            logger.error("module '%s' failed to import: %s", name, exc)
        raise PipelineAbort(
            EXIT_MODULE_FAILURE,
            "core module import failure: " + ", ".join(n for n, _ in broken),
        )
    return loaded


def _invoke_entry_hook(
    module: ModuleType, context: RuntimeContext
) -> int | None:
    """Invoke the entry hook of the primary core module, if defined.

    Returns:
        The hook's integer return value (an exit code), or None.
    """
    logger = context.logger
    for name in _ENTRY_HOOK_NAMES:
        hook = getattr(module, name, None)
        if not callable(hook):
            continue
        logger.info("invoking entry hook %s.%s()", module.__name__, name)
        try:
            signature = inspect.signature(hook)
        except (TypeError, ValueError):
            signature = None
        accepts_context = False
        if signature is not None:
            accepts_context = any(
                parameter.kind in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
                for parameter in signature.parameters.values()
            )
        try:
            outcome = hook(context) if accepts_context else hook()
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            raise PipelineAbort(
                EXIT_MODULE_FAILURE,
                f"entry hook {module.__name__}.{name}() failed: {exc}",
            ) from exc
        if isinstance(outcome, int) and not isinstance(outcome, bool):
            return outcome
        logger.info("entry hook %s.%s() completed", module.__name__, name)
        return None
    logger.info(
        "module '%s' exposes no entry hook; nothing to execute",
        module.__name__,
    )
    return None


def _print_shutdown(
    palette: ConsolePalette, started: float, exit_code: int
) -> None:
    """Phase 4 — graceful shutdown footer."""
    elapsed = time.monotonic() - started
    print()
    print(palette.dim("─" * (_PANEL_WIDTH - 2)))
    print(palette.cyan(
        f"[i] OmniCore session terminated :: {elapsed:.2f}s :: exit {exit_code}"
    ))


def run(argv: Sequence[str]) -> int:
    """Execute the four-phase OmniCore startup pipeline.

    Args:
        argv: command line arguments (without the program name).

    Returns:
        Process exit code (see the module docstring for the code table).
    """
    from updater import OmniPaths, setup_logging  # deferred import

    started = time.monotonic()
    args, passthrough = _parse_args(argv)
    palette = ConsolePalette(enabled=False if args.no_color else None)
    logger = setup_logging(verbose=args.verbose)
    logger.info(
        "%s v%s starting (pid=%d, python=%s)",
        APP_NAME, APP_VERSION, os.getpid(), platform.python_version(),
    )
    hwid_probe = _probe_hwid_summary()
    if args.no_banner:
        print(palette.dim(f"OMNICORE v{APP_VERSION} :: banner suppressed"))
    else:
        print_banner(palette)
        print_status_panel(
            palette,
            hwid_summary=hwid_probe,
            license_state="PENDING VERIFICATION",
        )
    try:
        hwid_summary = _phase1_license(palette, hwid_probe)

        # ── Phase 2: sync modules from Supabase ─────────────────
        sync_report = _phase2_sync_modules(palette, verbose=args.verbose)

        # ── Start launch session AFTER modules are on disk ──────
        # session_guard.py lives in modules_dir, so we must add
        # that directory to sys.path BEFORE importing it.
        try:
            import hwid_guard as _hg
            _raw_hwid = _hg.get_system_hwid()
        except Exception:
            _raw_hwid = "unknown"

        _mods = Path.home() / ".local" / "share" / "OmniCore" / "modules"
        if _mods.is_dir() and str(_mods) not in sys.path:
            sys.path.insert(0, str(_mods))
            logger.debug("prepended %s to sys.path", _mods)

        try:
            from session_guard import start_session
            start_session(_raw_hwid)
            logger.debug("launch session established")
        except Exception as _se:
            logger.warning("session guard unavailable: %s", _se)

        modules_dir = OmniPaths.modules_dir()
        context = RuntimeContext(
            app_name=APP_NAME,
            app_version=APP_VERSION,
            data_dir=modules_dir.parent,
            modules_dir=modules_dir,
            hwid=hwid_summary,
            sync_report=sync_report,
            logger=logger,
            argv=list(passthrough),
        )
        modules = _phase3_load_modules(context, palette)
        exit_code = EXIT_OK
        primary = next(iter(modules.values())) if modules else None
        if primary is not None:
            hook_code = _invoke_entry_hook(primary, context)
            if hook_code is not None:
                exit_code = hook_code
        else:
            print(palette.dim("[i] No core module loaded — runtime idle."))
        _print_shutdown(palette, started, exit_code)
        return exit_code
    except PipelineAbort as abort:
        logger.error(
            "pipeline aborted (exit=%d): %s", abort.exit_code, abort.message
        )
        print(palette.red(f"[x] {abort.message}"))
        print(palette.red(f"[x] OmniCore exiting :: code {abort.exit_code}"))
        return abort.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point with hard fault containment (Phase 4)."""
    tokens = sys.argv[1:] if argv is None else list(argv)
    try:
        return run(tokens)
    except KeyboardInterrupt:
        print(
            "\n[!] Interrupted by user (Ctrl+C) — shutting down cleanly.",
            file=sys.stderr,
        )
        return EXIT_INTERRUPTED
    except Exception as exc:  # last-resort guard; never leak tracebacks
        logging.getLogger("omnicore").exception("unrecoverable error")
        print(f"[x] Fatal error: {exc}", file=sys.stderr)
        print(
            "[x] Traceback recorded in the OmniCore XDG state logs.",
            file=sys.stderr,
        )
        return EXIT_FATAL


if __name__ == "__main__":
    sys.exit(main())
