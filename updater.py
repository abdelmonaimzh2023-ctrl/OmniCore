#!/usr/bin/env python3
"""OmniCore Auto-Updater.

Atomic, SHA-256-verified synchronisation of OmniCore scripts and modules
between a Supabase REST backend and the local XDG data directory.  The
module deliberately uses only the standard library (urllib + hashlib) so it
can bootstrap itself before any package manager is available.

Data layout (XDG Base Directory Specification)
----------------------------------------------
    $XDG_DATA_HOME/OmniCore/modules/      downloaded scripts & modules
                                            (default ~/.local/share/...)
    $XDG_CACHE_HOME/OmniCore/             last-known manifest cache
    $XDG_STATE_HOME/OmniCore/logs/        rotating updater logs
    $XDG_RUNTIME_DIR/OmniCore/            inter-process sync lock
                                            (fallback: XDG_STATE_HOME)

Remote contract
---------------
    GET {SUPABASE_URL}/rest/v1/app_files
        ?select=file_path,file_hash,content,is_critical,version
    Headers: apikey / Authorization: Bearer <SUPABASE_ANON_KEY>

Security model
--------------
    * every payload digest is verified against the manifest SHA-256 before
      anything is written, and re-verified after installation;
    * manifest paths are traversal-safe, extension-allow-listed and must
      resolve inside the modules directory;
    * writes go through tempfile.mkstemp() in the target directory, are
      flushed, fsynced, chmod-ed (0o755 / 0o644) and installed with a single
      atomic os.replace(), followed by a directory fsync;
    * failed installs roll back to the previous version and never leave
      temp artifacts behind;
    * network or configuration failures degrade gracefully to an offline
      audit of the cached local store instead of raising.

Standalone usage
----------------
    python updater.py [--dry-run] [--verify] [-v] [--no-logfile]

Exit codes: 0 = success (offline degradation included),
            1 = file failures / verification drift,
            2 = missing configuration.
"""

from __future__ import annotations

import argparse
import enum
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import base64
import binascii
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

try:  # POSIX only — the lock silently degrades on exotic platforms.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

__version__ = "1.0.0"
APP_NAME = "OmniCore"

_READ_CHUNK_BYTES = 1024 * 1024
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_SELECT_FIELDS = "file_path,file_hash,content,content_encoding,is_critical,version"
_ENDPOINT_PATH = "/rest/v1/app_files"
_DEFAULT_ALLOWED_SUFFIXES = frozenset({".py", ".sh", ".json"})
_TEMP_SUFFIX = ".part"
_BACKUP_SUFFIX = ".bak"
_STALE_ARTIFACT_MAX_AGE_SECONDS = 900.0
_LOG_MAX_BYTES = 1_048_576
_LOG_BACKUP_COUNT = 5

__all__ = [
    "APP_NAME",
    "AppFileManifest",
    "AutoUpdater",
    "ConfigurationError",
    "IntegrityError",
    "ManifestFetchError",
    "OmniPaths",
    "SyncReport",
    "SyncResult",
    "SyncStatus",
    "UnsafePathError",
    "UpdaterError",
    "setup_logging",
]


# ----------------------------------------------------------------------
# XDG path resolution
# ----------------------------------------------------------------------
def _xdg_path(variable: str, default: str) -> Path:
    """Resolve an XDG base directory, falling back per the specification.

    Relative or empty values are ignored (as required by the XDG spec).
    """
    value = os.environ.get(variable, "").strip()
    if value and Path(value).is_absolute():
        return Path(value)
    return Path(default).expanduser()


class OmniPaths:
    """Immutable namespace resolving every XDG path used by OmniCore."""

    app_name = APP_NAME

    @classmethod
    def data_home(cls) -> Path:
        """Return the OmniCore data root ($XDG_DATA_HOME/OmniCore)."""
        return _xdg_path("XDG_DATA_HOME", "~/.local/share") / cls.app_name

    @classmethod
    def modules_dir(cls) -> Path:
        """Return the downloaded module store."""
        return cls.data_home() / "modules"

    @classmethod
    def cache_home(cls) -> Path:
        """Return the OmniCore cache root ($XDG_CACHE_HOME/OmniCore)."""
        return _xdg_path("XDG_CACHE_HOME", "~/.cache") / cls.app_name

    @classmethod
    def manifest_cache_path(cls) -> Path:
        """Return the last-known manifest cache file."""
        return cls.cache_home() / "manifest_cache.json"

    @classmethod
    def state_home(cls) -> Path:
        """Return the OmniCore state root ($XDG_STATE_HOME/OmniCore)."""
        return _xdg_path("XDG_STATE_HOME", "~/.local/state") / cls.app_name

    @classmethod
    def log_dir(cls) -> Path:
        """Return the rotating-log directory."""
        return cls.state_home() / "logs"

    @classmethod
    def log_file(cls) -> Path:
        """Return the primary OmniCore log file."""
        return cls.log_dir() / "omnicore.log"

    @classmethod
    def runtime_dir(cls) -> Path | None:
        """Return $XDG_RUNTIME_DIR/OmniCore when available, else None."""
        value = os.environ.get("XDG_RUNTIME_DIR", "").strip()
        if value and Path(value).is_absolute():
            return Path(value) / cls.app_name
        return None

    @classmethod
    def lock_path(cls) -> Path:
        """Return the updater lock-file location."""
        runtime = cls.runtime_dir()
        base = runtime if runtime is not None else cls.state_home()
        return base / "updater.lock"


# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------
class UpdaterError(Exception):
    """Base class for every failure raised by this module."""


class ConfigurationError(UpdaterError):
    """Credentials or endpoints are missing or malformed."""


class UnsafePathError(UpdaterError):
    """A manifest path violated the path-safety policy."""


class IntegrityError(UpdaterError):
    """Content failed SHA-256 verification."""


class ManifestFetchError(UpdaterError):
    """The Supabase manifest could not be retrieved or parsed."""


# ----------------------------------------------------------------------
# Manifest / result models
# ----------------------------------------------------------------------
@dataclass(slots=True)
class AppFileManifest:
    """One validated row of the remote ``app_files`` manifest."""

    file_path: str
    file_hash: str
    content: str
    content_encoding: str = "base64"    # "base64" | "utf-8" | "" (heuristic)
    is_critical: bool = False
    version: str = "?"

    @classmethod
    def from_row(
        cls,
        row: Mapping[str, Any],
        *,
        require_content: bool = True,
    ) -> AppFileManifest:
        """Build an entry from a raw Supabase row.

        Args:
            row: raw JSON object from the REST response (or the cache).
            require_content: online rows must carry the file body; cached
                rows are allowed to omit it.

        Returns:
            A fully validated manifest entry.

        Raises:
            ValueError: the row is malformed and must be skipped.
        """
        if not isinstance(row, Mapping):
            raise ValueError("row is not a JSON object")
        file_path = str(row.get("file_path") or "").strip()
        file_hash = str(row.get("file_hash") or "").strip().lower()
        if not file_path:
            raise ValueError("missing 'file_path'")
        if not _SHA256_HEX_RE.fullmatch(file_hash):
            raise ValueError(f"malformed sha-256 digest for {file_path!r}")
        content = row.get("content")
        if require_content and not isinstance(content, str):
            raise ValueError(f"missing 'content' for {file_path!r}")
        version = row.get("version")
        version = str(version).strip() if version is not None else ""
        enc_raw = row.get("content_encoding")
        enc = str(enc_raw).strip().lower() if enc_raw is not None else ""
        return cls(
            file_path=file_path,
            file_hash=file_hash,
            content=content if isinstance(content, str) else "",
            content_encoding=enc or "base64",   # legacy rows default to base64
            is_critical=bool(row.get("is_critical", False)),
            version=version or "?",
        )


class SyncStatus(str, enum.Enum):
    """Terminal state of a single file synchronisation."""

    UPDATED = "updated"
    UP_TO_DATE = "up-to-date"
    STALE = "stale"
    FAILED = "failed"
    RESTORED = "restored"


_STATUS_PREFIXES = {
    SyncStatus.UPDATED: "[+]",
    SyncStatus.UP_TO_DATE: "[=]",
    SyncStatus.STALE: "[-]",
    SyncStatus.FAILED: "[x]",
    SyncStatus.RESTORED: "[~]",
}


@dataclass(slots=True)
class SyncResult:
    """Outcome of synchronising a single manifest entry."""

    file_path: str
    status: SyncStatus
    version: str = "?"
    detail: str = ""
    is_critical: bool = False


def _plural(count: int, noun: str) -> str:
    """Return *noun* singularised or pluralised for *count*."""
    return noun if count == 1 else f"{noun}s"


@dataclass(slots=True)
class SyncReport:
    """Aggregated outcome of one ``sync_all`` / ``check_local`` run."""

    results: list[SyncResult] = field(default_factory=list)
    offline: bool = False
    dry_run: bool = False
    duration_s: float = 0.0
    notes: list[str] = field(default_factory=list)

    # -- counters --------------------------------------------------------
    @property
    def total(self) -> int:
        """Number of manifest entries considered."""
        return len(self.results)

    @property
    def updated_count(self) -> int:
        """Entries freshly written to disk."""
        return self._count(SyncStatus.UPDATED)

    @property
    def current_count(self) -> int:
        """Entries whose local hash already matched."""
        return self._count(SyncStatus.UP_TO_DATE)

    @property
    def stale_count(self) -> int:
        """Entries detected as outdated but not (yet) written."""
        return self._count(SyncStatus.STALE)

    @property
    def failed_count(self) -> int:
        """Entries that could not be installed."""
        return self._count(SyncStatus.FAILED)

    @property
    def restored_count(self) -> int:
        """Entries rolled back after a failed verification."""
        return self._count(SyncStatus.RESTORED)

    @property
    def critical_failures(self) -> int:
        """Failed entries flagged ``is_critical`` by the manifest."""
        return sum(
            1
            for result in self.results
            if result.is_critical and result.status is SyncStatus.FAILED
        )

    def _count(self, status: SyncStatus) -> int:
        """Count results carrying the given status."""
        return sum(1 for result in self.results if result.status is status)

    # -- presentation ----------------------------------------------------
    def detail_lines(self) -> list[str]:
        """One status line per synchronised file (verbose / CLI output)."""
        lines: list[str] = []
        for result in self.results:
            prefix = _STATUS_PREFIXES.get(result.status, "[?]")
            line = f"{prefix} {result.file_path} (v{result.version})"
            if result.detail:
                line += f" — {result.detail}"
            if result.is_critical:
                line += " [critical]"
            lines.append(line)
        return lines

    def summary_lines(self) -> list[str]:
        """Human-readable summary, e.g. ``[+] 2 modules updated``."""
        lines = list(self.notes)
        if self.dry_run:
            lines.append("[i] Dry-run mode — no files were modified.")
        if self.offline and not any(
            line.startswith("[!] Offline") for line in lines
        ):
            lines.append(
                "[!] Offline — Supabase unreachable; serving cached modules."
            )
        if self.updated_count:
            lines.append(
                f"[+] {self.updated_count} "
                f"{_plural(self.updated_count, 'module')} updated"
            )
        if self.restored_count:
            lines.append(
                f"[~] {self.restored_count} "
                f"{_plural(self.restored_count, 'file')} rolled back"
            )
        if self.failed_count:
            critical = self.critical_failures
            suffix = f" ({critical} critical)" if critical else ""
            lines.append(
                f"[x] {self.failed_count} "
                f"{_plural(self.failed_count, 'file')} failed{suffix}"
            )
        if self.stale_count:
            if self.dry_run:
                lines.append(
                    f"[-] {self.stale_count} "
                    f"{_plural(self.stale_count, 'file')} would be updated"
                )
            else:
                lines.append(
                    f"[~] {self.stale_count} "
                    f"{_plural(self.stale_count, 'file')} differ from "
                    "the last-known manifest"
                )
        if self.total and not any(
            line.startswith(("[+]", "[x]", "[~]", "[-]")) for line in lines
        ):
            lines.append("[=] All scripts up to date")
        if not self.total and not lines:
            lines.append("[i] Manifest contained no files.")
        lines.append(f"[i] Sync finished in {self.duration_s:.2f}s")
        return lines


# ----------------------------------------------------------------------
# Inter-process lock
# ----------------------------------------------------------------------
class SyncLock:
    """Best-effort advisory inter-process lock around manifest syncs.

    Uses ``fcntl.flock`` on a lock file inside ``$XDG_RUNTIME_DIR`` (or the
    XDG state directory).  Failure to lock never aborts a sync: per-file
    writes are atomic by construction, so concurrent runs can only race
    harmlessly.
    """

    __slots__ = ("path", "timeout", "poll", "acquired", "_fd", "_logger")

    def __init__(
        self,
        path: Path,
        *,
        timeout: float = 5.0,
        poll: float = 0.25,
        logger: logging.Logger | None = None,
    ) -> None:
        """Create a lock handle for *path*."""
        self.path = path
        self.timeout = float(timeout)
        self.poll = float(poll)
        self.acquired = False
        self._fd: int | None = None
        self._logger = logger or logging.getLogger("omnicore.updater.lock")

    def acquire(self) -> bool:
        """Try to take the lock, polling for up to ``timeout`` seconds.

        Returns:
            True when exclusive ownership is held (or safely assumed).
        """
        if fcntl is None:  # pragma: no cover - non-POSIX fallback
            self._logger.debug("fcntl unavailable; running without a lock")
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            self._logger.warning("lock file unusable (%s); continuing", exc)
            self._fd = None
            return True
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.acquired = True
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    self._logger.warning(
                        "lock %s stays busy; proceeding unlocked", self.path
                    )
                    os.close(self._fd)
                    self._fd = None
                    return False
                time.sleep(self.poll)

    def release(self) -> None:
        """Release the lock (safe to call multiple times)."""
        if self._fd is None:
            return
        try:
            if self.acquired and fcntl is not None:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError as exc:  # pragma: no cover - defensive
            self._logger.debug("unlock failed: %s", exc)
        finally:
            os.close(self._fd)
            self._fd = None
            self.acquired = False

    def __enter__(self) -> SyncLock:
        """Context-manager entry: acquire the lock."""
        self.acquire()
        return self

    def __exit__(self, *_exc_info: object) -> None:
        """Context-manager exit: always release the lock."""
        self.release()


# ----------------------------------------------------------------------
# The updater itself
# ----------------------------------------------------------------------
class AutoUpdater:
    """Atomic, hash-verified synchroniser for OmniCore scripts & modules.

    The updater talks to ``{SUPABASE_URL}/rest/v1/app_files`` using the anon
    key, verifies every payload against its manifest SHA-256 digest, and
    installs files atomically inside ``$XDG_DATA_HOME/OmniCore/modules``.

    Example:
        >>> updater = AutoUpdater()          # reads $SUPABASE_* variables
        >>> report = updater.sync_all()
        >>> print(report.summary_lines()[0])
    """

    def __init__(
        self,
        supabase_url: str | None = None,
        supabase_key: str | None = None,
        *,
        modules_dir: Path | None = None,
        manifest_cache_path: Path | None = None,
        lock_path: Path | None = None,
        timeout: float = 15.0,
        lock_timeout: float = 5.0,
        allowed_suffixes: Iterable[str] = _DEFAULT_ALLOWED_SUFFIXES,
        logger: logging.Logger | None = None,
    ) -> None:
        """Initialise the updater.

        Args:
            supabase_url: project URL; falls back to ``$SUPABASE_URL``.
            supabase_key: anon key; falls back to ``$SUPABASE_ANON_KEY``.
            modules_dir: module store override (XDG default otherwise).
            manifest_cache_path: manifest cache override.
            lock_path: sync lock override.
            timeout: per-request network timeout in seconds.
            lock_timeout: how long to wait for the sync lock.
            allowed_suffixes: file extensions accepted from the manifest.
            logger: custom logger; defaults to ``omnicore.updater``.

        Raises:
            ConfigurationError: an explicitly supplied URL is malformed.
        """
        raw_url = (supabase_url or os.environ.get("SUPABASE_URL") or "").strip()
        raw_key = (
            supabase_key
            or os.environ.get("SUPABASE_ANON_KEY")
            or os.environ.get("SUPABASE_KEY")           # fallback
            or ""
        ).strip()
        self._url = raw_url or None
        self._key = raw_key or None
        if self._url is not None:
            parsed = urllib.parse.urlsplit(self._url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ConfigurationError(
                    f"malformed Supabase URL: {self._url!r}"
                )
        self.modules_dir = (
            Path(modules_dir) if modules_dir else OmniPaths.modules_dir()
        )
        self._manifest_cache = (
            Path(manifest_cache_path)
            if manifest_cache_path
            else OmniPaths.manifest_cache_path()
        )
        self._lock_path = (
            Path(lock_path) if lock_path else OmniPaths.lock_path()
        )
        self._timeout = float(timeout)
        self._lock_timeout = float(lock_timeout)
        self._allowed_suffixes = frozenset(
            suffix.lower() if suffix.startswith(".") else f".{suffix.lower()}"
            for suffix in allowed_suffixes
        )
        self._logger = logger or logging.getLogger("omnicore.updater")

    # -- public API ------------------------------------------------------
    def compute_hash(self, path: Path) -> str | None:
        """Compute the SHA-256 hex digest of a local file.

        Args:
            path: file to hash.

        Returns:
            Lowercase hex digest, or None when the file is missing or
            unreadable.
        """
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(_READ_CHUNK_BYTES):
                    digest.update(chunk)
        except FileNotFoundError:
            return None
        except OSError as exc:
            self._logger.warning("cannot read %s: %s", path, exc)
            return None
        return digest.hexdigest()

    def fetch_manifest(self) -> list[AppFileManifest]:
        """Fetch and validate the remote file manifest from Supabase.

        Returns:
            Every usable manifest entry (malformed rows are skipped with a
            warning).

        Raises:
            ConfigurationError: credentials are missing.
            ManifestFetchError: network, HTTP or payload failure.
        """
        if not self._url or not self._key:
            raise ConfigurationError(
                "SUPABASE_URL and SUPABASE_ANON_KEY must be supplied "
                "(constructor or environment)"
            )
        base = self._url.rstrip("/")
        query = urllib.parse.urlencode({"select": _SELECT_FIELDS})
        url = f"{base}{_ENDPOINT_PATH}?{query}"
        headers = {
            "apikey": self._key,
            "Authorization": f"Bearer {self._key}",
            "Accept": "application/json",
            "User-Agent": f"{APP_NAME}-Updater/{__version__}",
        }
        payload = self._http_get_json(url, headers)
        if isinstance(payload, dict):
            detail = (
                payload.get("message")
                or payload.get("error")
                or payload.get("hint")
                or "unrecognised error payload"
            )
            raise ManifestFetchError(f"Supabase rejected the request: {detail}")
        if not isinstance(payload, list):
            raise ManifestFetchError(
                f"unexpected manifest payload type: {type(payload).__name__}"
            )
        manifest: list[AppFileManifest] = []
        for index, row in enumerate(payload):
            try:
                manifest.append(AppFileManifest.from_row(row))
            except ValueError as exc:
                self._logger.warning(
                    "skipping manifest row #%d: %s", index, exc
                )
        self._logger.info(
            "manifest validated: %d/%d usable entries",
            len(manifest),
            len(payload),
        )
        return manifest

    def sync_file(self, entry: AppFileManifest, *, dry_run: bool = False) -> SyncResult:
        """Bring the local copy of *entry* in sync with the manifest.

        The local file is hashed first and skipped when identical.  New
        content is verified against the manifest digest, written to a temp
        file in the target directory, fsynced, chmod-ed and installed with
        a single atomic ``os.replace``.  A failed post-write verification
        rolls the previous version back.

        Args:
            entry: the manifest row to install.
            dry_run: report ``STALE`` without writing.

        Returns:
            The per-file :class:`SyncResult`.

        Raises:
            IntegrityError: the payload digest does not match the manifest
                digest, so the write is refused outright.
        """
        try:
            target = self._safe_target(entry.file_path)
        except UnsafePathError as exc:
            self._logger.error("rejecting %r: %s", entry.file_path, exc)
            return SyncResult(
                entry.file_path, SyncStatus.FAILED, entry.version,
                f"unsafe path: {exc}", entry.is_critical,
            )
        local_hash = self.compute_hash(target)
        if local_hash == entry.file_hash:
            self._logger.debug(
                "%s already current (v%s)", entry.file_path, entry.version
            )
            return SyncResult(
                entry.file_path, SyncStatus.UP_TO_DATE, entry.version,
                "hash match", entry.is_critical,
            )
        if dry_run:
            return SyncResult(
                entry.file_path, SyncStatus.STALE, entry.version,
                "would update (dry-run)", entry.is_critical,
            )
        # Content is stored base64-encoded by admin_dashboard.py.
        # Fall back to raw UTF-8 only for legacy plaintext rows.
        # Decide how to interpret entry.content based on the manifest's
        # declared content_encoding. Falls back to a heuristic when the
        # column is empty (legacy rows).
        enc = (entry.content_encoding or "").lower()
        if enc in ("utf-8", "utf8", "text", "plain"):
            payload: bytes = entry.content.encode("utf-8")
        elif enc == "base64":
            try:
                payload = base64.b64decode(
                    entry.content.strip(), validate=True)
            except (binascii.Error, ValueError) as exc:
                raise IntegrityError(
                    f"declared base64 payload for {entry.file_path!r} "
                    f"failed to decode: {exc}"
                ) from exc
        else:
            # Unknown/empty encoding — heuristic (backward compatibility).
            _stripped = entry.content.strip()
            _is_b64 = (
                len(_stripped) >= 16
                and len(_stripped) % 4 == 0
                and all(c.isalnum() or c in "+/=" for c in _stripped)
            )
            if _is_b64:
                try:
                    payload = base64.b64decode(_stripped, validate=True)
                except (binascii.Error, ValueError):
                    payload = entry.content.encode("utf-8")
            else:
                payload = entry.content.encode("utf-8")

        payload_hash = hashlib.sha256(payload).hexdigest()
        if payload_hash != entry.file_hash:
            raise IntegrityError(
                f"payload digest {payload_hash[:12]}... does not match the "
                f"manifest digest for {entry.file_path!r}"
            )
        mode = self._mode_for(target, payload)
        backup = self._backup_existing(target)
        try:
            self._atomic_write_bytes(target, payload, mode)
        except OSError as exc:
            if backup is not None:
                backup.unlink(missing_ok=True)
            self._logger.error(
                "write failed for %s: %s", entry.file_path, exc
            )
            return SyncResult(
                entry.file_path, SyncStatus.FAILED, entry.version,
                f"write failed: {exc}", entry.is_critical,
            )
        if self.compute_hash(target) != entry.file_hash:
            detail = self._rollback(target, backup)
            status = (
                SyncStatus.RESTORED if backup is not None else SyncStatus.FAILED
            )
            self._logger.error(
                "post-write verification failed for %s: %s",
                entry.file_path, detail,
            )
            return SyncResult(
                entry.file_path, status, entry.version,
                f"rolled back: {detail}", entry.is_critical,
            )
        if backup is not None:
            backup.unlink(missing_ok=True)
        self._logger.info(
            "installed %s -> v%s (mode %o, %d bytes)",
            entry.file_path, entry.version, mode, len(payload),
        )
        return SyncResult(
            entry.file_path, SyncStatus.UPDATED, entry.version,
            "atomic install verified", entry.is_critical,
        )

    def sync_all(self, *, dry_run: bool = False) -> SyncReport:
        """Synchronise every manifest entry into the local module store.

        Resilient by design: network or configuration failure downgrades the
        run to an offline audit against the cached manifest instead of
        raising, so callers can keep serving cached modules.

        Args:
            dry_run: report drift without touching the file system.

        Returns:
            A :class:`SyncReport` describing every file outcome.
        """
        started = time.monotonic()
        notes: list[str] = []
        results: list[SyncResult] = []
        offline = False
        try:
            self.modules_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            note = f"[!] Offline — modules directory unavailable: {exc}"
            notes.append(note)
            self._logger.error("%s", note.removeprefix("[!] Offline — "))
            return SyncReport(
                results=[], offline=True, notes=notes,
                duration_s=time.monotonic() - started,
            )
        self._cleanup_stale_artifacts()
        with SyncLock(
            self._lock_path, timeout=self._lock_timeout, logger=self._logger
        ) as lock:
            if not lock.acquired:
                self._logger.warning(
                    "concurrent sync detected; per-file writes stay atomic"
                )
            manifest: list[AppFileManifest] = []
            try:
                manifest = self.fetch_manifest()
                self._persist_manifest_cache(manifest)
                self._logger.info(
                    "manifest fetched: %d file(s) from Supabase", len(manifest)
                )
            except ConfigurationError as exc:
                offline = True
                notes.append(f"[!] Offline — credentials unavailable: {exc}")
            except ManifestFetchError as exc:
                offline = True
                notes.append(f"[!] Offline — Supabase unreachable: {exc}")
            if offline:
                self._logger.warning("falling back to cached modules")
                manifest = self._load_cached_manifest()
            for entry in manifest:
                if offline:
                    results.append(self._offline_check(entry))
                    continue
                try:
                    results.append(self.sync_file(entry, dry_run=dry_run))
                except IntegrityError as exc:
                    results.append(SyncResult(
                        entry.file_path, SyncStatus.FAILED, entry.version,
                        f"integrity refusal: {exc}", entry.is_critical,
                    ))
        report = SyncReport(
            results=results, offline=offline, dry_run=dry_run,
            duration_s=time.monotonic() - started, notes=notes,
        )
        self._log_report(report)
        return report

    def check_local(self) -> SyncReport:
        """Audit the module store against the cached manifest (no network).

        Returns:
            A :class:`SyncReport` whose ``STALE`` entries mark local drift.
        """
        started = time.monotonic()
        manifest = self._load_cached_manifest()
        notes = ["[i] Offline audit against the cached manifest."]
        if not manifest:
            notes.append("[!] No cached manifest yet — run an online sync first.")
        results = [self._offline_check(entry) for entry in manifest]
        return SyncReport(
            results=results, notes=notes,
            duration_s=time.monotonic() - started,
        )

    # -- internals ---------------------------------------------------------
    def _http_get_json(self, url: str, headers: dict[str, str]) -> Any:
        """Perform a GET request and parse the JSON response.

        Raises:
            ManifestFetchError: on any transport, HTTP or parsing failure.
        """
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout
            ) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(512).decode("utf-8", "replace").strip()
            except OSError:
                body = ""
            detail = f"HTTP {exc.code} {exc.reason}"
            if body:
                detail += f": {body}"
            raise ManifestFetchError(detail) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ManifestFetchError(f"network error: {reason}") from exc
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestFetchError(f"invalid JSON payload: {exc}") from exc

    def _safe_target(self, file_path: str) -> Path:
        """Resolve a manifest-relative path to an absolute target.

        The policy rejects absolute paths, backslashes, parent traversal,
        non-allow-listed extensions and any resolved location outside the
        modules directory (which also defeats symlink escapes).

        Raises:
            UnsafePathError: the path violates the safety policy.
        """
        candidate = file_path.strip()
        if not candidate or "\\" in candidate or "\x00" in candidate:
            raise UnsafePathError("empty or forbidden characters in path")
        pure = PurePosixPath(candidate)
        if pure.is_absolute() or ".." in pure.parts or pure.root or pure.drive:
            raise UnsafePathError(
                "absolute paths and parent traversal are forbidden"
            )
        if pure.suffix.lower() not in self._allowed_suffixes:
            raise UnsafePathError(
                f"extension {pure.suffix!r} is not in the allow-list"
            )
        base = self.modules_dir.resolve()
        target = (self.modules_dir / pure).resolve()
        if target != base and not target.is_relative_to(base):
            raise UnsafePathError("resolved target escapes the modules directory")
        return target

    def _mode_for(self, target: Path, payload: bytes) -> int:
        """Pick the POSIX mode: executables get 0o755, data gets 0o644."""
        if target.suffix.lower() == ".sh" or payload.startswith(b"#!"):
            return 0o755
        return 0o644

    def _atomic_write_bytes(self, target: Path, payload: bytes, mode: int) -> None:
        """Atomically write *payload* to *target*.

        Uses ``tempfile.mkstemp`` in the target directory (same filesystem,
        guaranteeing rename atomicity), flushes, fsyncs, applies *mode*, and
        installs the file with a single ``os.replace`` followed by a
        directory fsync.  Temp files are always removed on failure.
        """
        target.parent.mkdir(parents=True, exist_ok=True)
        handle_fd: int | None = None
        temp_path: Path | None = None
        try:
            handle_fd, temp_name = tempfile.mkstemp(
                dir=str(target.parent),
                prefix=".omnicore_",
                suffix=_TEMP_SUFFIX,
            )
            temp_path = Path(temp_name)
            stream = os.fdopen(handle_fd, "wb")
            handle_fd = None  # fdopen now owns the descriptor
            with stream:
                stream.write(payload)
                stream.flush()
                os.fchmod(stream.fileno(), mode)
                os.fsync(stream.fileno())
            os.replace(temp_path, target)
            temp_path = None
            self._fsync_directory(target.parent)
        finally:
            if handle_fd is not None:
                os.close(handle_fd)
            if temp_path is not None:
                try:
                    temp_path.unlink()
                except OSError:
                    self._logger.debug(
                        "temp cleanup skipped for %s", temp_path
                    )

    def _fsync_directory(self, directory: Path) -> None:
        """Best-effort fsync of a directory so renames survive a crash."""
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            descriptor = os.open(str(directory), flags)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def _backup_existing(self, target: Path) -> Path | None:
        """Copy the current file to ``<name>.bak`` for rollback purposes."""
        if not target.exists():
            return None
        backup = target.with_name(target.name + _BACKUP_SUFFIX)
        try:
            shutil.copy2(target, backup)
        except OSError as exc:
            self._logger.warning(
                "could not back up %s (%s); proceeding without rollback "
                "safety", target, exc,
            )
            return None
        return backup

    def _rollback(self, target: Path, backup: Path | None) -> str:
        """Undo a failed install and describe what happened.

        Returns:
            A human-readable description of the rollback outcome.
        """
        if backup is not None and backup.is_file():
            try:
                os.replace(backup, target)
            except OSError as exc:
                return f"restore failed ({exc})"
            return "previous version restored atomically"
        try:
            target.unlink(missing_ok=True)
        except OSError as exc:
            return f"corrupt copy removal failed ({exc})"
        return "corrupt copy removed (no prior version existed)"

    def _offline_check(self, entry: AppFileManifest) -> SyncResult:
        """Classify one cached entry against the local store (no network)."""
        target = self.modules_dir / PurePosixPath(entry.file_path)
        if self.compute_hash(target) == entry.file_hash:
            return SyncResult(
                entry.file_path, SyncStatus.UP_TO_DATE, entry.version,
                "matches last-known manifest (offline)", entry.is_critical,
            )
        return SyncResult(
            entry.file_path, SyncStatus.STALE, entry.version,
            "differs from last-known manifest (offline)", entry.is_critical,
        )

    def _cleanup_stale_artifacts(self) -> None:
        """Sweep orphaned temp/backup files older than the staleness window."""
        if not self.modules_dir.is_dir():
            return
        cutoff = time.time() - _STALE_ARTIFACT_MAX_AGE_SECONDS
        for pattern in (f"*{_TEMP_SUFFIX}", f"*{_BACKUP_SUFFIX}"):
            for candidate in self.modules_dir.rglob(pattern):
                try:
                    if candidate.is_file() and candidate.stat().st_mtime < cutoff:
                        candidate.unlink()
                        self._logger.debug(
                            "swept stale artifact %s", candidate
                        )
                except OSError as exc:
                    self._logger.debug(
                        "cannot sweep %s: %s", candidate, exc
                    )

    def _persist_manifest_cache(self, manifest: list[AppFileManifest]) -> None:
        """Atomically store a slim copy of the manifest for offline audits."""
        payload = [
            {
                "file_path": entry.file_path,
                "file_hash": entry.file_hash,
                "version": entry.version,
                "is_critical": entry.is_critical,
            }
            for entry in manifest
        ]
        blob = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        try:
            self._manifest_cache.parent.mkdir(parents=True, exist_ok=True)
            self._atomic_write_bytes(self._manifest_cache, blob, 0o644)
            self._logger.debug(
                "manifest cache refreshed: %d entries", len(payload)
            )
        except OSError as exc:
            self._logger.warning("manifest cache write failed: %s", exc)

    def _load_cached_manifest(self) -> list[AppFileManifest]:
        """Load the slim cached manifest written by the last online sync."""
        try:
            raw = self._manifest_cache.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except OSError as exc:
            self._logger.warning("manifest cache unreadable: %s", exc)
            return []
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._logger.warning("manifest cache corrupt: %s", exc)
            return []
        if not isinstance(rows, list):
            self._logger.warning("manifest cache has unexpected shape")
            return []
        entries: list[AppFileManifest] = []
        for row in rows:
            try:
                entries.append(
                    AppFileManifest.from_row(row, require_content=False)
                )
            except ValueError as exc:
                self._logger.debug("skipping cached row: %s", exc)
        return entries

    def _log_report(self, report: SyncReport) -> None:
        """Emit a finished report through the structured logger."""
        self._logger.debug(
            "per-file outcomes: %s",
            " | ".join(
                f"{result.file_path}={result.status.value}"
                for result in report.results
            ),
        )
        for line in report.summary_lines():
            self._logger.info("%s", line)


# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------
def setup_logging(
    *,
    verbose: bool = False,
    console: bool = True,
    logfile: bool = True,
    logger_name: str = "omnicore",
) -> logging.Logger:
    """Configure structured logging for the whole OmniCore framework.

    Console output goes to stderr (stdout stays reserved for banners and
    summaries); the rotating file lands in ``$XDG_STATE_HOME/OmniCore/logs``.

    Args:
        verbose: emit DEBUG records as well.
        console: attach a stderr handler.
        logfile: attach a rotating file handler.
        logger_name: root logger of the OmniCore hierarchy.

    Returns:
        The configured :class:`logging.Logger`.
    """
    root = logging.getLogger(logger_name)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.propagate = False
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d | %(levelname)-8s | %(name)s | "
            "%(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    if console:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(formatter)
        root.addHandler(stream)
    if logfile:
        log_path = OmniPaths.log_file()
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=_LOG_MAX_BYTES,
                backupCount=_LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
            root.debug("file logging enabled: %s", log_path)
        except OSError as exc:
            root.warning("file logging unavailable (%s)", exc)
    if not root.handlers:
        root.addHandler(logging.NullHandler())
    return root


# ----------------------------------------------------------------------
# Standalone harness
# ----------------------------------------------------------------------
def _print_report_to_stdout(report: SyncReport) -> None:
    """Render per-file details followed by the summary block."""
    details = report.detail_lines()
    for line in details:
        print(line)
    if details:
        print()
    for line in report.summary_lines():
        print(line)


def _cli(argv: Sequence[str] | None = None) -> int:
    """Standalone test harness (see the module docstring for semantics)."""
    parser = argparse.ArgumentParser(
        prog="updater.py",
        description="OmniCore atomic auto-updater (standalone harness).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="compare hashes and report drift without writing",
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="offline audit of local files against the cached manifest",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable DEBUG logging"
    )
    parser.add_argument(
        "--no-logfile", action="store_true",
        help="disable the XDG_STATE_HOME log file",
    )
    tokens = sys.argv[1:] if argv is None else list(argv)
    args = parser.parse_args(tokens)
    setup_logging(verbose=args.verbose, logfile=not args.no_logfile)
    logger = logging.getLogger("omnicore.updater")
    try:
        updater = AutoUpdater()
    except ConfigurationError as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 2
    if args.verify:
        report = updater.check_local()
        _print_report_to_stdout(report)
        drift = report.stale_count + report.failed_count + report.restored_count
        return 0 if drift == 0 else 1
    if not (
        os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_ANON_KEY")
    ):
        logger.error("SUPABASE_URL and SUPABASE_ANON_KEY are required")
        print("[x] SUPABASE_URL and SUPABASE_ANON_KEY are required",
              file=sys.stderr)
        return 2
    report = updater.sync_all(dry_run=args.dry_run)
    _print_report_to_stdout(report)
    return 1 if report.failed_count else 0


if __name__ == "__main__":
    sys.exit(_cli())