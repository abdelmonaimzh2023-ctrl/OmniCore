"""
hardware_id.py — OmniCore Robust Hardware Fingerprint
======================================================
Collects MULTIPLE independent hardware identifiers and produces a
three-tier fingerprint that survives OS reinstall, MAC randomization,
root/non-root context differences, and containerization.

Sources (in stability order):
  1. Motherboard serial   /sys/class/dmi/id/board_serial        (very stable)
  2. Product UUID         /sys/class/dmi/id/product_uuid        (very stable)
  3. Chassis serial       /sys/class/dmi/id/chassis_serial      (very stable)
  4. Primary disk serial  /sys/block/*/device/serial            (very stable)
  5. CPU signature        model + count                         (stable)
  6. Machine-id           /etc/machine-id                       (per-OS, weak)
  7. Physical MAC         1st physical iface                    (spoofable)

Three outputs:
  * strict_hash    — SHA-256 over the 4 most stable sources only
  * soft_hash      — SHA-256 over all 7 sources
  * components     — dict {source_name: SHA-256(value)[:16]}

The strict hash is what a fresh install SHOULD preserve.  The soft
hash + components allow the server to perform fuzzy matching when a
single source drifts (e.g. NIC replaced, MAC spoofed).
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

__all__ = [
    "collect_components",
    "strict_hash",
    "soft_hash",
    "get_system_hwid",
    "get_full_fingerprint",
]

# Serial keys — the "gold standard".  Require root.
_SERIAL_KEYS = ("board_serial", "product_uuid",
                "chassis_serial", "disk_serial")

# Model keys — world-readable, stable across reinstall.
_MODEL_KEYS = ("sys_vendor", "product_name", "product_version",
               "board_name", "board_version",
               "bios_vendor", "bios_version", "bios_date")

# Always-available keys.
_ALWAYS_KEYS = ("cpu_sig", "machine_id", "mac_physical")

STRICT_KEYS = _SERIAL_KEYS + _MODEL_KEYS + ("cpu_sig",)   # adaptive
SOFT_KEYS = STRICT_KEYS + _ALWAYS_KEYS

# Legacy alias kept for compatibility
_LEGACY_STRICT_KEYS = _SERIAL_KEYS


# ─── Low-level readers ───────────────────────────────────────────────────
def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _read_disk_serial() -> str:
    """First physical disk serial from /sys/block/*/device/serial."""
    base = Path("/sys/block")
    if not base.is_dir():
        return ""
    candidates = []
    for entry in sorted(base.iterdir()):
        name = entry.name
        # Skip loop / ram / dm-* / sr* (optical) / zram
        if name.startswith(("loop", "ram", "dm-", "sr", "zram", "md")):
            continue
        # Skip removable media (SD cards, USB sticks) — they move
        removable = entry / "removable"
        if removable.is_file():
            try:
                if removable.read_text().strip() == "1":
                    continue
            except OSError:
                pass
        serial = _read(str(entry / "device" / "serial"))
        if serial:
            candidates.append((name, serial))
    if not candidates:
        return ""
    # Deterministic: alphabetical by device name
    candidates.sort(key=lambda x: x[0])
    return candidates[0][1]


def _cpu_signature() -> str:
    """Stable CPU descriptor: model name + logical count + vendor."""
    model = ""
    vendor = ""
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8",
                                               errors="replace")
        for line in text.splitlines():
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            k = k.strip().lower()
            v = v.strip()
            if k == "model name" and not model:
                model = v
            elif k == "vendor_id" and not vendor:
                vendor = v
    except OSError:
        pass
    try:
        count = os.cpu_count() or 0
    except Exception:
        count = 0
    parts = [p for p in (vendor, model, str(count)) if p]
    return " / ".join(parts) if parts else ""


def _physical_mac() -> str:
    """First non-loopback, non-virtual interface's MAC (12 hex chars)."""
    base = Path("/sys/class/net")
    if not base.is_dir():
        return ""
    # Virtual prefixes to exclude
    VIRTUAL = ("lo", "docker", "veth", "br-", "virbr", "tap", "tun",
               "wg", "vmnet", "vboxnet", "dummy")
    entries = []
    try:
        entries = sorted(base.iterdir(), key=lambda p: p.name)
    except OSError:
        return ""
    for entry in entries:
        name = entry.name
        if any(name.startswith(p) for p in VIRTUAL):
            continue
        addr = _read(str(entry / "address"))
        if not addr or addr == "00:00:00:00:00:00":
            continue
        # Reject multicast / locally-administered
        try:
            first = int(addr.split(":")[0], 16)
            if first & 0x01:                # multicast
                continue
            if first & 0x02:                # locally-administered
                continue
        except (ValueError, IndexError):
            continue
        return addr.replace(":", "").lower()
    return ""


def _hash(value: str) -> str:
    """Short stable hash; empty values → literal marker."""
    if not value:
        return "unavailable"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


# ─── Public API ──────────────────────────────────────────────────────────
def collect_components() -> dict:
    """Return {source_name: sha256_prefix(value)} for every source.

    DMI serial fields require root (mode 0400).  When the tool runs
    without root they come back "unavailable" — we therefore also
    collect the DMI *model* fields (board_name, product_name, sys_vendor,
    bios_version) which are world-readable and remain stable across
    OS reinstall (they come from the firmware).
    """
    return {
        # ── Serial-based (root required, best uniqueness) ────────────
        "board_serial":   _hash(_read("/sys/class/dmi/id/board_serial")),
        "product_uuid":   _hash(_read("/sys/class/dmi/id/product_uuid")),
        "chassis_serial": _hash(_read("/sys/class/dmi/id/chassis_serial")),
        "disk_serial":    _hash(_read_disk_serial()),

        # ── Model-based (world-readable, survive reinstall) ──────────
        "sys_vendor":     _hash(_read("/sys/class/dmi/id/sys_vendor")),
        "product_name":   _hash(_read("/sys/class/dmi/id/product_name")),
        "product_version":_hash(_read("/sys/class/dmi/id/product_version")),
        "board_name":     _hash(_read("/sys/class/dmi/id/board_name")),
        "board_version":  _hash(_read("/sys/class/dmi/id/board_version")),
        "bios_vendor":    _hash(_read("/sys/class/dmi/id/bios_vendor")),
        "bios_version":   _hash(_read("/sys/class/dmi/id/bios_version")),
        "bios_date":      _hash(_read("/sys/class/dmi/id/bios_date")),

        # ── Always available ─────────────────────────────────────────
        "cpu_sig":        _hash(_cpu_signature()),
        "machine_id":     _hash(_read("/etc/machine-id") or
                                _read("/var/lib/dbus/machine-id")),
        "mac_physical":   _hash(_physical_mac()),
    }


def strict_hash(components: dict = None) -> str:
    """Adaptive strict hash.

    Three levels:
      FULL     — >=3 of 4 serial sources readable (running as root)
                 preimage = "hwid-full-v1|<serial1>|<serial2>|..."
      PARTIAL  — 1-2 serials readable
                 preimage = "hwid-partial-v1|<serials>|<models>|<cpu>"
      DEGRADED — no serials readable (non-root)
                 preimage = "hwid-degraded-v1|<models>|<cpu>|<machine_id>"
    Each level uses a distinct version tag so hashes from different
    levels can never collide.
    """
    components = components or collect_components()

    serials = [components.get(k, "unavailable") for k in _SERIAL_KEYS]
    serials_present = sum(1 for s in serials if s != "unavailable")

    models = [components.get(k, "unavailable") for k in _MODEL_KEYS]
    models_present = sum(1 for m in models if m != "unavailable")

    if serials_present >= 3:
        tag = "hwid-full-v1"
        parts = serials + [components.get("cpu_sig", "unavailable")]
    elif serials_present >= 1:
        tag = "hwid-partial-v1"
        parts = serials + models + [components.get("cpu_sig", "unavailable")]
    else:
        # Degraded — no serials.  Use model + cpu + machine_id.
        # machine_id changes on OS reinstall, but combined with model
        # fields + cpu it is still unique enough for identification.
        tag = "hwid-degraded-v1"
        parts = models + [
            components.get("cpu_sig", "unavailable"),
            components.get("machine_id", "unavailable"),
        ]

    preimage = tag + "|" + "|".join(p if p else "unavailable"
                                    for p in parts)
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def strict_level(components: dict = None) -> str:
    """Return "full" | "partial" | "degraded"."""
    components = components or collect_components()
    serials_present = sum(
        1 for k in _SERIAL_KEYS
        if components.get(k, "unavailable") != "unavailable"
    )
    if serials_present >= 3:
        return "full"
    if serials_present >= 1:
        return "partial"
    return "degraded"


def soft_hash(components: dict = None) -> str:
    """SHA-256 over all 7 sources."""
    components = components or collect_components()
    preimage = "hwid-soft-v2|" + "|".join(
        components.get(k, "unavailable") for k in SOFT_KEYS
    )
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def get_system_hwid() -> str:
    """Backward-compatible single-hash API (returns the strict hash)."""
    return strict_hash()


def _cache_dir() -> Path:
    """Resolve the cache directory, honouring SUDO_USER when running
    under sudo so the cache lands in the *user's* home, not /root.

    Falls back to /var/cache/omnicore/hwid (root-only) when neither
    works — a shared location that all processes can read.
    """
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    if sudo_user and sudo_user != "root":
        try:
            import pwd
            home = pwd.getpwnam(sudo_user).pw_dir
            return Path(home) / ".config" / "OmniCore"
        except (KeyError, ImportError):
            pass
    # Regular user
    home = Path.home()
    # Do not use /root even when root — that would hide the cache
    if str(home) == "/root":
        return Path("/var/cache/omnicore")
    return home / ".config" / "OmniCore"


def _cache_file() -> Path:
    return _cache_dir() / "hwid_cache.json"


def _fix_cache_ownership(path: Path) -> None:
    """If running as root for a non-root SUDO_USER, chown the file so
    the user can later read it."""
    if os.geteuid() != 0:
        return
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    if not sudo_user or sudo_user == "root":
        return
    try:
        import pwd
        info = pwd.getpwnam(sudo_user)
        os.chown(str(path), info.pw_uid, info.pw_gid)
        os.chmod(str(path), 0o600)
    except Exception:
        pass


def _cache_read() -> dict:
    try:
        import json
        p = _cache_file()
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _cache_write(data: dict) -> None:
    try:
        import json
        d = _cache_dir()
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / (".hwid_cache-%d.tmp" % os.getpid())
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, d / "hwid_cache.json")
        _fix_cache_ownership(d / "hwid_cache.json")
        # Also chown the parent directory so the user can write too
        if os.geteuid() == 0:
            sudo_user = os.environ.get("SUDO_USER", "").strip()
            if sudo_user and sudo_user != "root":
                try:
                    import pwd
                    info = pwd.getpwnam(sudo_user)
                    os.chown(str(d), info.pw_uid, info.pw_gid)
                except Exception:
                    pass
    except Exception:
        pass


def get_full_fingerprint() -> dict:
    """Return the complete fingerprint, using a cache when privileged
    serial values have been read before."""
    comps = collect_components()
    level = strict_level(comps)
    current_strict = strict_hash(comps)
    current_soft = soft_hash(comps)

    # If we just read a FULL strict hash (running as root), cache it.
    if level == "full":
        _cache_write({
            "strict": current_strict,
            "soft": current_soft,
            "level": level,
            "components": comps,
            "cached_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc).isoformat(),
        })
        return {
            "strict": current_strict,
            "soft": current_soft,
            "components": comps,
            "strict_level": level,
            "from_cache": False,
        }

    # Otherwise, if we have a FULL cached value, prefer it (it comes
    # from a root run and reflects the true hardware).
    cache = _cache_read()
    if cache.get("level") == "full" and cache.get("strict"):
        # Sanity: if any readable component CHANGED vs the cache,
        # treat that as a hardware change — do not use stale cache.
        changed = False
        for k, v in (cache.get("components") or {}).items():
            if v == "unavailable":
                continue
            now = comps.get(k, "unavailable")
            if now != "unavailable" and now != v:
                changed = True
                break
        if not changed:
            return {
                "strict": cache["strict"],
                "soft": cache["soft"],
                "components": {**cache.get("components", {}), **comps},
                "strict_level": "full",
                "from_cache": True,
            }

    return {
        "strict": current_strict,
        "soft": current_soft,
        "components": comps,
        "strict_level": level,
        "from_cache": False,
    }


if __name__ == "__main__":
    fp = get_full_fingerprint()
    print("=" * 62)
    print("  OmniCore · Hardware Fingerprint")
    print("=" * 62)
    print("  strict_hash  : %s" % fp["strict"])
    print("  soft_hash    : %s" % fp["soft"])
    print("  strict_level : %s%s" % (
        fp.get("strict_level", "unknown"),
        "  (from cache — run with sudo once)" if fp.get("from_cache") else ""))
    if fp.get("strict_level") == "degraded":
        print()
        print("  ⚠  Running as a regular user — DMI serials are unreadable.")
        print("     The current hash uses MODEL fields + CPU + machine-id.")
        print("     Run once with:  sudo python3 hardware_id.py")
        print("     to cache the FULL fingerprint (root-only serials).")
    print()
    print("  components:")
    for k, v in fp["components"].items():
        marker = "*" if v != "unavailable" else " "
        print("    %s %-16s %s" % (marker, k, v))
    print()
    present = sum(1 for v in fp["components"].values()
                  if v != "unavailable")
    print("  sources present: %d / %d" % (present, len(fp["components"])))
