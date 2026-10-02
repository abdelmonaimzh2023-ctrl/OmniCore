"""
hwid_guard.py
=============

Hardware fingerprinting and license / ban enforcement for Linux applications
using Supabase (PostgREST RPC) as their licensing back end.

Design principles
-----------------
* Deterministic HWID : stable machine-local identifiers, SHA-256 -> 64 hex chars.
* Clean storage      : plain JSON under the XDG config dir
                       (~/.config/<app>/session.json). No padding, no
                       obfuscated filenames, no anti-analysis tricks.
* Fail-closed        : network failures, malformed payloads and unknown
                       statuses never authorize the device.
* Server is authority: the client is untrusted. Validity, device binding and
                       bans are decided exclusively inside the Postgres RPC.

Requires: Python 3.8+, requests  (pip install requests)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─── Robust multi-source fingerprint (see hardware_id.py) ───────────────
try:
    from hardware_id import (
        get_system_hwid as _robust_hwid,
        get_full_fingerprint as _robust_full_fp,
    )
    _HAS_ROBUST_HWID = True
except Exception:
    _HAS_ROBUST_HWID = False

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

APP_NAME = "OmniCore"

MACHINE_ID_CANDIDATES = (
    Path("/etc/machine-id"),
    Path("/var/lib/dbus/machine-id"),
)
DMI_PRODUCT_UUID_PATH = Path("/sys/class/dmi/id/product_uuid")
PROC_CPUINFO_PATH = Path("/proc/cpuinfo")
SYSFS_NET_DIR = Path("/sys/class/net")

HWID_PLACEHOLDER = "unavailable"   # stable contribution for missing sources
HWID_SCHEMA_VERSION = 1            # bump if the derivation ever changes

# --- Supabase configuration (environment variable NAMES only) --------------
# SECURITY: these constants hold the *names* of environment variables.
# Secret values (project URL / API keys) must come from the environment and
# are never hard-coded in this file nor printed to logs.

SUPABASE_URL_ENV = "SUPABASE_URL"

# API key candidates, in priority order: the first variable set to a
# non-empty value wins.
SUPABASE_KEY_ENV = "SUPABASE_KEY"
SUPABASE_ANON_KEY_ENV = "SUPABASE_ANON_KEY"
SUPABASE_SERVICE_KEY_ENV = "SUPABASE_SERVICE_KEY"

SUPABASE_KEY_ENV_CANDIDATES = (
    SUPABASE_KEY_ENV,
    SUPABASE_ANON_KEY_ENV,
    SUPABASE_SERVICE_KEY_ENV,
)

LICENSE_KEY_ENV = "APP_LICENSE_KEY"

# ─── Embedded public credentials (override via env or config.py) ────────
# The anon key is PUBLIC by design — it only grants the "anon" role, and
# RLS policies decide what that role may do. Safe to ship in source.
_EMBEDDED_URL = "https://dolgcaxknbfufxyqrkmd.supabase.co"
_EMBEDDED_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRvbGdjYXhrbmJmdWZ4eXFya21kIiwicm9s"
    "ZSI6ImFub24iLCJpYXQiOjE3OTA2ODg2NzQsImV4cCI6MjEwNjI2NDY3NH0."
    "hTX7afaCD2FyFtQfm7x2QYiiDZzvC7Jzwpo5vbrjC3Y"
)

# Optional local config.py override
try:
    import config as _cfg  # type: ignore
    if getattr(_cfg, "SUPABASE_URL", None):
        _EMBEDDED_URL = _cfg.SUPABASE_URL
    if getattr(_cfg, "SUPABASE_ANON_KEY", None):
        _EMBEDDED_ANON_KEY = _cfg.SUPABASE_ANON_KEY
except ImportError:
    pass
except Exception:
    pass

os.environ.setdefault(SUPABASE_URL_ENV, _EMBEDDED_URL)
os.environ.setdefault(SUPABASE_KEY_ENV, _EMBEDDED_ANON_KEY)


# Process exit codes (documented contract for wrappers/systemd units)
EXIT_CODE_OK = 0
EXIT_CODE_BANNED = 10
EXIT_CODE_INVALID = 11
EXIT_CODE_SERVER_UNAVAILABLE = 12

log = logging.getLogger("hwid_guard")

# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class LicenseEnforcementError(RuntimeError):
    """Base class for all license-enforcement failures."""


class SupabaseConnectionError(LicenseEnforcementError):
    """Network / timeout / server-unavailable failure (transient)."""


class SupabaseProtocolError(LicenseEnforcementError):
    """Supabase answered, but the response could not be trusted or parsed."""


class LicenseInvalidError(LicenseEnforcementError):
    """Key invalid, expired, or bound to a different device."""


class DeviceBannedError(LicenseEnforcementError):
    """Hardware fingerprint is blacklisted server-side."""


# --------------------------------------------------------------------------
# Part 1 — HWID generation
# --------------------------------------------------------------------------


def _read_text(path: Path) -> Optional[str]:
    """Read a small UTF-8 text file; return None on ANY failure (never raise)."""
    try:
        content = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as exc:  # covers missing/perm/IO errors
        log.debug("Could not read %s: %s", path, exc)
        return None
    return content or None


def _get_machine_id() -> Optional[str]:
    """systemd machine-id (primary stable anchor on modern Linux)."""
    for path in MACHINE_ID_CANDIDATES:
        value = _read_text(path)
        if value:
            return value.lower()
    log.warning("No machine-id found in %s (non-systemd or container host?).",
                ", ".join(str(p) for p in MACHINE_ID_CANDIDATES))
    return None


def _get_product_uuid() -> Optional[str]:
    """
    DMI product UUID. Typically root-only (mode 0400) on Linux.

    NOTE: this value is usually readable only as root. Running the same app
    as root vs. as a regular user will therefore yield different HWIDs.
    Pick one privilege mode for your deployment (or remove this source).
    """
    value = _read_text(DMI_PRODUCT_UUID_PATH)
    return value.lower() if value else None


def _mac_from_sysfs() -> Optional[str]:
    """First stable hardware MAC from /sys/class/net (deterministic order)."""
    try:
        entries = sorted(SYSFS_NET_DIR.iterdir())
    except OSError:
        return None
    for entry in entries:
        if entry.name == "lo":
            continue
        addr = _read_text(entry / "address")
        if addr and addr != "00:00:00:00:00:00":
            return addr.replace(":", "").lower()
    return None


def _get_mac_address() -> Optional[str]:
    """
    Stable MAC as 12 lowercase hex digits.

    uuid.getnode() fabricates a RANDOM multicast address when no hardware
    address exists (some containers/VMs). Detect the multicast bit and fall
    back to sysfs rather than injecting non-deterministic entropy.
    """
    node = uuid.getnode()
    if ((node >> 40) & 0x01) == 0:
        return f"{node:012x}"
    log.debug("uuid.getnode() returned a random fallback; consulting sysfs")
    return _mac_from_sysfs()


def _read_cpuinfo_field(name: str) -> Optional[str]:
    try:
        lines = PROC_CPUINFO_PATH.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    for line in lines:
        if ":" in line:
            key, _, value = line.partition(":")
            if key.strip().lower() == name:
                return " ".join(value.split()).lower()  # collapse whitespace
    return None


def _get_platform_signature() -> str:
    """Kernel / architecture / CPU model strings (x86: 'model name')."""
    cpu_model = (
        _read_cpuinfo_field("model name")
        or platform.processor().strip().lower()
        or HWID_PLACEHOLDER
    )
    return "|".join((
        platform.system().strip().lower(),   # "linux"
        platform.machine().strip().lower(),  # "x86_64", "aarch64", ...
        cpu_model,
    ))


def get_system_hwid() -> str:
    """Return the 64-hex strict hardware fingerprint.

    Uses hardware_id.get_full_fingerprint() when available (multi-source
    robust fingerprint).  Falls back to the legacy single-source
    derivation otherwise.
    """
    if _HAS_ROBUST_HWID:
        try:
            fp = _robust_full_fp()
            log.debug("robust HWID components: %s", fp["components"])
            log.info("Derived hardware fingerprint (strict): %s",
                     fp["strict"][:16] + "...")
            return fp["strict"]
        except Exception as exc:
            log.warning("hardware_id failed, using legacy: %s", exc)
    # Legacy fallback (identical to previous v1 behaviour)
    components = (
        _get_machine_id() or HWID_PLACEHOLDER,
        _get_product_uuid() or HWID_PLACEHOLDER,
        _get_mac_address() or HWID_PLACEHOLDER,
        _get_platform_signature(),
    )
    preimage = f"hwid-v{HWID_SCHEMA_VERSION}|" + "|".join(components)
    log.debug("HWID preimage: %s", preimage)
    hwid = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
    log.info("Derived hardware fingerprint (legacy): %s", hwid)
    return hwid


def get_full_hwid_payload() -> dict:
    """Return the complete fingerprint payload for the server."""
    if _HAS_ROBUST_HWID:
        try:
            fp = _robust_full_fp()
            return {
                "hwid": fp["strict"],
                "hwid_soft": fp["soft"],
                "hwid_components": fp["components"],
            }
        except Exception:
            pass
    h = get_system_hwid()
    return {"hwid": h, "hwid_soft": h, "hwid_components": {}}


# --------------------------------------------------------------------------
# Part 2 — Supabase verification
# --------------------------------------------------------------------------


class DeviceStatus(str, Enum):
    SUCCESS = "SUCCESS"
    BANNED = "BANNED"
    INVALID = "INVALID"


@dataclass(frozen=True)
class DeviceCheckResult:
    status: DeviceStatus
    message: str = ""
    session_key: Optional[str] = None
    expires_at: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def authorized(self) -> bool:
        return self.status is DeviceStatus.SUCCESS


class SupabaseLicenseClient:
    """Hardened wrapper around the PostgREST RPC `validate_license`."""

    RPC_NAME = "validate_license"
    PARAM_HWID = "p_hwid"   # must match the SQL function signature
    PARAM_KEY = "p_key"

    def __init__(
        self,
        supabase_url: str,
        supabase_key: str,
        *,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        max_retries: int = 3,
    ) -> None:
        self._url = supabase_url.rstrip("/")
        self._timeout = (connect_timeout, read_timeout)

        self._session = requests.Session()
        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            # Safe to retry POST: validate_license is an idempotent check.
            allowed_methods=frozenset({"POST"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
        self._session.headers.update({
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "SupabaseLicenseClient":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # -- public API ---------------------------------------------------------

    def check_device_status(
        self, hwid: str, key_code: Optional[str] = None
    ) -> DeviceCheckResult:
        """
        Ask the server whether this HWID (+ optional key) is authorized.

        Returns a DeviceCheckResult. Raises:
          SupabaseConnectionError  - network / 5xx (transient, fail-closed)
          SupabaseProtocolError    - bad key, missing RPC, malformed payload
        """
        if not hwid or len(hwid) != 64 or any(c not in "0123456789abcdef" for c in hwid):
            raise ValueError("hwid must be a 64-character lowercase SHA-256 hex string")

        key = (key_code or "").strip()
        if len(key) > 256:
            raise ValueError("key_code exceeds maximum length of 256 characters")

        endpoint = f"{self._url}/rest/v1/rpc/{self.RPC_NAME}"
        payload = {self.PARAM_HWID: hwid, self.PARAM_KEY: key}
        # Attach the multi-tier fingerprint so the server can perform
        # fuzzy matching on partial component drift.
        try:
            _full = get_full_hwid_payload()
            payload["p_hwid_soft"] = _full.get("hwid_soft", hwid)
            payload["p_components"] = _full.get("hwid_components", {})
        except Exception:
            payload["p_hwid_soft"] = hwid
            payload["p_components"] = {}

        try:
            response = self._session.post(endpoint, json=payload, timeout=self._timeout)
        except requests.exceptions.RequestException as exc:
            # NOTE: the API key travels in headers and is never rendered in
            # exception text, so no credential can leak through this path.
            raise SupabaseConnectionError(f"Could not reach Supabase: {exc}") from exc

        return self._interpret(response)

    # -- internals ----------------------------------------------------------

    def _interpret(self, response: requests.Response) -> DeviceCheckResult:
        code = response.status_code

        if code in (401, 403):
            # SECURITY: environment variable NAMES only — never their values.
            raise SupabaseProtocolError(
                f"Supabase rejected the API key (HTTP {code}). Check "
                f"{SUPABASE_URL_ENV} and one of "
                f"{', '.join(SUPABASE_KEY_ENV_CANDIDATES)} "
                "as well as the RPC EXECUTE grant."
            )
        if code == 404:
            raise SupabaseProtocolError(
                f"RPC '{self.RPC_NAME}' not found (HTTP 404). Is the function deployed?"
            )
        if 500 <= code < 600:
            # Retries exhausted / server unhealthy -> transient, fail-closed.
            raise SupabaseConnectionError(
                f"License server error (HTTP {code}): {response.text[:300]}"
            )
        if code >= 400:
            raise SupabaseProtocolError(
                f"RPC rejected the request (HTTP {code}): {response.text[:300]} "
                "Do the RPC parameters match PARAM_HWID/PARAM_KEY?"
            )

        try:
            body = response.json()
        except ValueError as exc:
            raise SupabaseProtocolError(f"Malformed JSON from RPC: {exc}") from exc

        # PostgREST returns a bare JSON string when the SQL function returns
        # `text`, and an object when it returns `jsonb`. Support both.
        if isinstance(body, str):
            status_raw, fields = body.strip(), {}
        elif isinstance(body, dict):
            status_raw, fields = str(body.get("status", "")).strip(), body
        else:
            raise SupabaseProtocolError(
                f"Unexpected RPC payload type: {type(body).__name__}"
            )

        try:
            status = DeviceStatus(status_raw.upper())
        except ValueError:
            # Fail closed on anything the contract does not define.
            raise SupabaseProtocolError(f"Unknown status from server: {status_raw!r}")

        return DeviceCheckResult(
            status=status,
            message=str(fields.get("message", "")),
            session_key=fields.get("session_key") or None,
            expires_at=fields.get("expires_at") or None,
            raw=fields,
        )


def build_client_from_env() -> SupabaseLicenseClient:
    """
    Build a SupabaseLicenseClient from the process environment.

      * URL  : read from SUPABASE_URL.
      * Key  : first non-empty value among SUPABASE_KEY, SUPABASE_ANON_KEY,
               SUPABASE_SERVICE_KEY (priority order).

    Raises:
      ValueError: naming ONLY the missing environment variables
        (e.g. "Missing required environment variables: SUPABASE_KEY").
        Values are never included, so credentials cannot leak into logs,
        tracebacks, or crash reports.
    """
    url = os.environ.get(SUPABASE_URL_ENV, "").strip()

    # Flexible key resolution: first non-empty candidate wins
    # (SUPABASE_KEY -> SUPABASE_ANON_KEY -> SUPABASE_SERVICE_KEY).
    key = ""
    key_var: Optional[str] = None
    for env_name in SUPABASE_KEY_ENV_CANDIDATES:
        candidate = os.environ.get(env_name, "").strip()
        if candidate:
            key = candidate
            key_var = env_name
            break

    missing = []
    if not url:
        missing.append(SUPABASE_URL_ENV)
    if not key:
        # Primary key variable name (alternatives documented above).
        missing.append(SUPABASE_KEY_ENV)

    if missing:
        # SECURITY: include variable NAMES only — never their values.
        raise ValueError(
            "Missing required environment variables: " + ", ".join(missing)
        )

    # Log the *names* of the variables that supplied the credentials.
    log.debug("Supabase credentials resolved from env vars: %s, %s",
              SUPABASE_URL_ENV, key_var)
    return SupabaseLicenseClient(url, key)


# --------------------------------------------------------------------------
# Part 3 — Clean session storage (XDG-compliant, plain JSON, atomic writes)
# --------------------------------------------------------------------------


class SessionStore:
    """Plain-JSON session storage: ~/.config/<app>/session.json (or $XDG_CONFIG_HOME)."""

    def __init__(self, app_name: str = APP_NAME) -> None:
        config_root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        self._dir = config_root / app_name
        self._path = self._dir / "session.json"

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> Dict[str, Any]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Ignoring unreadable session file %s: %s", self._path, exc)
            return {}
        if not isinstance(data, dict):
            log.warning("Session file %s is not a JSON object; ignoring.", self._path)
            return {}
        return data

    def save(self, data: Dict[str, Any]) -> None:
        """Atomic write (temp file + rename) with 0600 permissions."""
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeError(f"Cannot create config directory {self._dir}: {exc}") from exc

        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(prefix=".session-", dir=self._dir)  # 0600 by design
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_name, 0o600)  # explicit for clarity
            os.replace(tmp_name, self._path)
        except OSError as exc:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise RuntimeError(f"Failed to persist session file: {exc}") from exc

    def update(self, **fields: Any) -> None:
        data = self.load()
        data.update(fields)
        self.save(data)

    def clear(self) -> None:
        try:
            self._path.unlink(missing_ok=True)
        except OSError as exc:
            log.warning("Could not remove session file %s: %s", self._path, exc)


# --------------------------------------------------------------------------
# Enforcement policy + orchestration
# --------------------------------------------------------------------------


def enforce_device_authorization(
    result: DeviceCheckResult,
    *,
    store: Optional[SessionStore] = None,
    hwid: str = "",
    key_code: str = "",
) -> DeviceCheckResult:
    """
    Apply the server's decision:
      SUCCESS -> persist the session and return the result.
      INVALID -> raise LicenseInvalidError (caller owns the UX).
      BANNED  -> raise DeviceBannedError.
    """
    if result.status is DeviceStatus.SUCCESS:
        if store is not None:
            store.update(
                hwid=hwid,
                key_code=key_code,
                session_key=result.session_key or "",
                expires_at=result.expires_at or "",
                last_validated=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
        return result

    if result.status is DeviceStatus.BANNED:
        raise DeviceBannedError(result.message or "This device has been banned.")

    raise LicenseInvalidError(result.message or "Invalid license key or device mismatch.")


def authorize_application(
    *, interactive: bool = True, client: Optional[SupabaseLicenseClient] = None
) -> DeviceCheckResult:
    """
    End-to-end startup gate: fingerprint -> server check -> enforce.

    Returns DeviceCheckResult on SUCCESS.
    Raises LicenseInvalidError / Supabase*Error on other failures.
    TERMINATES THE PROCESS (exit code 10) on BANNED, per policy.
    """
    hwid = get_system_hwid()
    store = SessionStore()
    own_client = client is None
    client = client or build_client_from_env()

    stored = store.load()
    key_code = (
        os.environ.get(LICENSE_KEY_ENV, "").strip()
        or str(stored.get("key_code", "") or "").strip()
    )
    if not key_code and interactive:
        try:
            key_code = input("License key: ").strip()
        except EOFError:
            key_code = ""

    try:
        result = client.check_device_status(hwid, key_code)
        return enforce_device_authorization(
            result, store=store, hwid=hwid, key_code=key_code
        )
    except DeviceBannedError as exc:
        log.critical("Device banned by license server: %s", exc)
        print(f"\n[!] Access denied: {exc}\n", file=sys.stderr)
        sys.exit(EXIT_CODE_BANNED)  # hard termination — the only intentional exit
    finally:
        if own_client:
            client.close()


# --------------------------------------------------------------------------
# CLI demo / smoke test
# --------------------------------------------------------------------------


def _demo() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    try:
        result = authorize_application()
    except LicenseInvalidError as exc:
        log.error("License invalid: %s", exc)
        return EXIT_CODE_INVALID
    except SupabaseConnectionError as exc:
        log.error("License server unreachable (fail-closed): %s", exc)
        return EXIT_CODE_SERVER_UNAVAILABLE
    except (SupabaseProtocolError, RuntimeError, ValueError) as exc:
        log.error("Enforcement error: %s", exc)
        return EXIT_CODE_SERVER_UNAVAILABLE
    log.info("Authorized. Session expires at: %s", result.expires_at or "n/a")
    return EXIT_CODE_OK


if __name__ == "__main__":
    raise SystemExit(_demo())