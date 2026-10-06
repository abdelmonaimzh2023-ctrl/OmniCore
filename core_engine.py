#!/usr/bin/env python3
"""
════════════════════════════════════════════════════════════════════════
  OmniCore — Authorized Penetration Testing Framework
  core_engine.py — Main TUI Module
════════════════════════════════════════════════════════════════════════
  This module provides the main terminal user interface for OmniCore.
  It is designed for AUTHORIZED security testing only, wrapping tools
  shipped with Kali Linux against targets the operator owns or has
  explicit written permission to test.

  Loaded dynamically by main.py after license verification.
════════════════════════════════════════════════════════════════════════
"""

import os
import sys
import json
import time
import shutil
import string
import secrets
import textwrap
import tempfile
import webbrowser
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable

# ─── Auto-install rich if missing (helps every user) ────────────────────
def _ensure_rich() -> bool:
    """Ensure 'rich' is importable. Auto-installs if missing."""
    try:
        import rich  # noqa: F401
        return True
    except ImportError:
        pass

    import subprocess as _sp
    import sys as _sys

    candidates = [
        [_sys.executable, "-m", "pip", "install", "--user", "rich"],
        [_sys.executable, "-m", "pip", "install",
         "--user", "--break-system-packages", "rich"],
        [_sys.executable, "-m", "pip", "install", "rich"],
    ]

    print("[i] 'rich' library not found. Attempting automatic installation...")
    for cmd in candidates:
        try:
            r = _sp.run(cmd, capture_output=True, text=True, timeout=180)
        except (FileNotFoundError, _sp.TimeoutExpired, OSError) as e:
            print(f"[!] {cmd[0]} attempt failed: {e}")
            continue
        if r.returncode == 0:
            import importlib
            importlib.invalidate_caches()
            try:
                import rich  # noqa: F401
                print("[+] 'rich' installed successfully.")
                return True
            except ImportError:
                continue
    return False


if not _ensure_rich():
    print()
    print("[FATAL] Could not install 'rich' automatically.")
    print("Install it manually with one of:")
    print("  sudo apt install python3-rich        # Debian / Kali / Ubuntu")
    print("  sudo dnf install python3-rich        # Fedora")
    print("  sudo pacman -S python-rich           # Arch")
    print("  pip install --user rich              # any (fallback)")
    print()
    import sys
    sys.exit(1)


# ─── Rich imports (safe now) ────────────────────────────────────────────
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TaskProgressColumn, TimeRemainingColumn, TextColumn
)
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.align import Align
from rich import box
from rich.table import Table
from rich.markdown import Markdown

# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

APP_NAME = "OmniCore"
CONSENT_DIR = Path(
    os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
) / "OmniCore"
CONSENT_FILE = CONSENT_DIR / "consent.json"
SETTINGS_FILE = CONSENT_DIR / "settings.json"

# Color palette (256-color ANSI escape codes)
CLR_CYAN  = "color(51)"
CLR_GREEN = "color(46)"
CLR_AMBER = "color(226)"
CLR_RED   = "color(196)"
CLR_DIM   = "color(240)"

# Rich style equivalents
STYLE_CYAN = "color(51)"
STYLE_GREEN = "color(46)"
STYLE_AMBER = "color(226)"
STYLE_RED = "color(196)"
STYLE_DIM = "color(240)"
STYLE_BANNER = "bold color(51)"

# Banner timing
BANNER_CHAR_DELAY = 0.012  # seconds per character
BANNER_PAUSE = 0.250       # pause after full reveal

# Subprocess timeout (seconds)
SUBPROCESS_TIMEOUT = 300

# Telegram support handle
SUPPORT_TELEGRAM = "@monaimFp"
SUPPORT_TELEGRAM_URL = "https://t.me/monaimFp"

# ═══════════════════════════════════════════════════════════════════════
# INTERNATIONALIZATION DICTIONARIES
# ═══════════════════════════════════════════════════════════════════════

EN_DICT: Dict[str, str] = {
    # ── Menu keys ──
    "menu.title": "OMNICORE — MAIN MENU",
    "menu.install": "Install / Update Pentest Toolkit",
    "menu.health": "System Health Scan",
    "menu.health.sub": "defensive",
    "menu.recon": "Reconnaissance",
    "menu.recon.sub": "nmap / whois / dns",
    "menu.web": "Web Assessment",
    "menu.web.sub": "nikto / gobuster / sqlmap",
    "menu.tools": "Tools",
    "menu.tools.sub": "coming soon",
    "menu.report": "Report Generator",
    "menu.report.sub": "export PDF/MD",
    "menu.support": "Support",
    "menu.settings": "Settings",
    "menu.exit": "Exit",
    "menu.prompt": "Select an option [0-8]: ",
    "menu.invalid": "Invalid option. Please enter a number between 0 and 8.",

    # ── Status keys ──
    "status.hwid": "HWID",
    "status.session": "Session",
    "status.version": "Version",
    "status.modules": "Modules",
    "status.language": "Language",
    "status.active": "ACTIVE",

    # ── Authorization gate keys ──
    "gate.title": "AUTHORIZATION GATE — READ CAREFULLY",
    "gate.intro": (
        "OmniCore is a professional pentest framework. "
        "Before using it, you must confirm ALL of the following:"
    ),
    "gate.c1": "I will only test systems I own or have WRITTEN",
    "gate.c1b": "authorization to test.",
    "gate.c2": "I understand unauthorized access is a criminal offense",
    "gate.c2b": "in my jurisdiction.",
    "gate.c3": "I will keep all findings confidential and use them only",
    "gate.c3b": "to improve the security of the authorized target.",
    "gate.c4": "I accept full legal responsibility for my actions.",
    "gate.prompt": 'Type "I AGREE" to continue, or press Ctrl+C to exit.',
    "gate.refused": (
        "You did not accept the authorization terms. "
        "OmniCore will not proceed without explicit consent."
    ),
    "gate.agreed": "Authorization accepted. Welcome to OmniCore.",
    "gate.stored": "Previous authorization found (HWID match).",

    # ── Warning keys ──
    "warn.module_missing": (
        "Module '{name}' is not installed. Run option [1] first."
    ),
    "warn.invalid_input": "Invalid input. Please try again.",
    "warn.file_error": "File system error: {error}",

    # ── Footer keys ──
    "footer.text": (
        "[i] AUTHORIZED USE ONLY. You must have written permission "
        "from the target system's owner. Unauthorized use is illegal "
        "in most jurisdictions and violates this tool's license. "
        "The author assumes no responsibility for misuse."
    ),

    # ── Support keys ──
    "support.title": "SUPPORT",
    "support.telegram": "Telegram",
    "support.opening": "Opening support channel...",
    "support.opened": (
        "If your browser or Telegram client did not open, "
        "manually visit: {url}"
    ),
    "support.press_enter": "Press Enter to return to menu...",

    # ── Settings keys ──
    "settings.title": "SETTINGS",
    "settings.language": "Language",
    "settings.theme": "Theme (dark/light)",
    "settings.reset_consent": "Reset local consent",
    "settings.reset_warning": (
        "This will delete your stored authorization consent. "
        "The tool will exit and require re-acceptance on next run."
    ),
    "settings.confirm_reset": "Type 'RESET' to confirm, or press Enter to cancel: ",
    "settings.reset_done": "Consent has been reset. Exiting...",
    "settings.cancelled": "Action cancelled.",
    "settings.current": "Current",
    "settings.new_value": "New value set to: {value}",
    "settings.available": "Available: {values}",
    "settings.theme.dark": "dark",
    "settings.theme.light": "light",

    # ── Exit keys ──
    "exit.message": "Goodbye. Stay within your authorization scope.",
    "exit.interrupted": "\nInterrupted by user. Exiting safely.",

    # ── Banner ──
    "banner.tagline": "Authorized Penetration Testing Framework",
}

RU_DICT: Dict[str, str] = {
    # ── Ключи меню ──
    "menu.title": "OMNICORE — ГЛАВНОЕ МЕНЮ",
    "menu.install": "Установка / Обновление инструментов",
    "menu.health": "Проверка состояния системы",
    "menu.health.sub": "защитное сканирование",
    "menu.recon": "Разведка",
    "menu.recon.sub": "nmap / whois / dns",
    "menu.web": "Веб-аудит",
    "menu.web.sub": "nikto / gobuster / sqlmap",
    "menu.tools": "Инструменты",
    "menu.tools.sub": "скоро",
    "menu.report": "Генератор отчётов",
    "menu.report.sub": "экспорт PDF/MD",
    "menu.support": "Поддержка",
    "menu.settings": "Настройки",
    "menu.exit": "Выход",
    "menu.prompt": "Выберите опцию [0-8]: ",
    "menu.invalid": "Неверная опция. Введите число от 0 до 8.",

    # ── Статус ──
    "status.hwid": "HWID",
    "status.session": "Сессия",
    "status.version": "Версия",
    "status.modules": "Модули",
    "status.language": "Язык",
    "status.active": "АКТИВНА",

    # ── Экран авторизации ──
    "gate.title": "ЭКРАН АВТОРИЗАЦИИ — ЧИТАЙТЕ ВНИМАТЕЛЬНО",
    "gate.intro": (
        "OmniCore — профессиональный пентест-фреймворк. "
        "Перед использованием вы должны подтвердить ВСЁ следующее:"
    ),
    "gate.c1": "Я буду тестировать только системы, которыми владею",
    "gate.c1b": "или на которые есть ПИСЬМЕННОЕ разрешение.",
    "gate.c2": "Я понимаю, что несанкционированный доступ —",
    "gate.c2b": "уголовное преступление в моей юрисдикции.",
    "gate.c3": "Я буду сохранять конфиденциальность результатов и",
    "gate.c3b": "использовать их только для улучшения безопасности.",
    "gate.c4": "Я принимаю полную юридическую ответственность.",
    "gate.prompt": 'Введите "I AGREE" для продолжения или Ctrl+C для выхода.',
    "gate.refused": (
        "Вы не приняли условия авторизации. "
        "OmniCore не будет работать без явного согласия."
    ),
    "gate.agreed": "Авторизация принята. Добро пожаловать в OmniCore.",
    "gate.stored": "Найдена предыдущая авторизация (HWID совпадает).",

    # ── Предупреждения ──
    "warn.module_missing": (
        "Модуль '{name}' не установлен. Сначала запустите опцию [1]."
    ),
    "warn.invalid_input": "Неверный ввод. Попробуйте снова.",
    "warn.file_error": "Ошибка файловой системы: {error}",

    # ── Подвал ──
    "footer.text": (
        "[i] ТОЛЬКО АВТОРИЗОВАННОЕ ИСПОЛЬЗОВАНИЕ. У вас должно быть "
        "письменное разрешение от владельца целевой системы. "
        "Несанкционированное использование незаконно в большинстве "
        "юрисдикций и нарушает лицензию этого инструмента."
    ),

    # ── Поддержка ──
    "support.title": "ПОДДЕРЖКА",
    "support.telegram": "Telegram",
    "support.opening": "Открытие канала поддержки...",
    "support.opened": (
        "Если браузер или Telegram не открылся, "
        "перейдите вручную: {url}"
    ),
    "support.press_enter": "Нажмите Enter для возврата в меню...",

    # ── Настройки ──
    "settings.title": "НАСТРОЙКИ",
    "settings.language": "Язык",
    "settings.theme": "Тема (тёмная/светлая)",
    "settings.reset_consent": "Сброс локального согласия",
    "settings.reset_warning": (
        "Это удалит сохранённое согласие на авторизацию. "
        "Инструмент завершит работу и потребует повторного принятия."
    ),
    "settings.confirm_reset": "Введите 'RESET' для подтверждения или Enter для отмены: ",
    "settings.reset_done": "Согласие сброшено. Выход...",
    "settings.cancelled": "Действие отменено.",
    "settings.current": "Текущее",
    "settings.new_value": "Новое значение: {value}",
    "settings.available": "Доступно: {values}",
    "settings.theme.dark": "тёмная",
    "settings.theme.light": "светлая",

    # ── Выход ──
    "exit.message": "До свидания. Оставайтесь в рамках ваших полномочий.",
    "exit.interrupted": "\nПрервано пользователем. Безопасный выход.",

    # ── Баннер ──
    "banner.tagline": "Фреймворк авторизованного пентеста",
}

# ═══════════════════════════════════════════════════════════════════════
# i18n HANDLER (with graceful fallback)
# ═══════════════════════════════════════════════════════════════════════

_i18n_module = None
_current_language = "en"


def _try_import_i18n() -> Optional[Any]:
    """Attempt to import the i18n sibling module. Returns None on failure."""
    global _i18n_module
    if _i18n_module is not None:
        return _i18n_module
    try:
        import i18n as _mod
        _i18n_module = _mod
        return _mod
    except ImportError:
        return None


def _setup_i18n() -> None:
    """Register our dictionaries with the i18n module if available."""
    global _current_language
    mod = _try_import_i18n()
    if mod is not None:
        try:
            if hasattr(mod, "set_strings"):
                mod.set_strings("en", EN_DICT)
                mod.set_strings("ru", RU_DICT)
            if hasattr(mod, "available_languages"):
                _langs = mod.available_languages()
                if _langs:
                    _current_language = _langs[0] if isinstance(_langs[0], str) else "en"
        except Exception:
            pass


def t(key: str, **kwargs) -> str:
    """
    Translate a key. Uses i18n module if available, otherwise falls
    back to EN_DICT directly. Supports {placeholder} formatting.
    """
    global _current_language
    mod = _try_import_i18n()

    result: Optional[str] = None
    if mod is not None and hasattr(mod, "t"):
        try:
            result = mod.t(key)
        except Exception:
            result = None

    if result is None:
        if _current_language == "ru" and key in RU_DICT:
            result = RU_DICT[key]
        else:
            result = EN_DICT.get(key, key)

    if kwargs:
        try:
            result = result.format(**kwargs)
        except (KeyError, IndexError):
            pass

    return result


def set_language(code: str) -> None:
    """Set the current language code."""
    global _current_language
    _current_language = code
    mod = _try_import_i18n()
    if mod is not None and hasattr(mod, "set_language"):
        try:
            mod.set_language(code)
        except Exception:
            pass


def get_current_language() -> str:
    """Return the current language code."""
    return _current_language


# ═══════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

def _ensure_config_dir() -> bool:
    """Ensure the OmniCore config directory exists with proper permissions."""
    try:
        CONSENT_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(str(CONSENT_DIR), 0o700)
        return True
    except (OSError, PermissionError):
        return False


def atomic_write_json(path: Path, data: Dict[str, Any], console: Console) -> bool:
    """
    Write JSON data to a file atomically with 0600 permissions.
    Uses a temporary file in the same directory, then renames.
    """
    try:
        _ensure_config_dir()
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent), prefix=".tmp_", suffix=".json"
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(path))
        return True
    except (OSError, PermissionError, ValueError) as e:
        console.print(
            f"[{CLR_RED}]x[/] {t('warn.file_error', error=str(e))}"
        )
        # Clean up temp file if it exists
        try:
            os.unlink(tmp_path)
        except (OSError, UnboundLocalError):
            pass
        return False


def load_json_file(path: Path) -> Optional[Dict[str, Any]]:
    """Safely load a JSON file. Returns None if missing or corrupt."""
    try:
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


def get_consent_data() -> Optional[Dict[str, Any]]:
    """Load the stored consent data, or None if not present."""
    return load_json_file(CONSENT_FILE)


def consent_is_valid(context: Any) -> bool:
    """
    Check if stored consent exists and matches the current HWID
    and app version (MAJOR.MINOR comparison).
    """
    data = get_consent_data()
    if data is None:
        return False

    stored_hwid = data.get("hwid", "")
    stored_version = data.get("app_version", "")

    if stored_hwid != context.hwid:
        return False

    # Compare MAJOR.MINOR only
    current_mm = _major_minor(context.app_version)
    stored_mm = _major_minor(stored_version)

    return current_mm == stored_mm


def _major_minor(version: str) -> str:
    """Extract MAJOR.MINOR from a version string."""
    parts = str(version).split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return str(version)


def count_modules(modules_dir: str) -> int:
    """Count .py files in the modules directory."""
    try:
        p = Path(modules_dir)
        if p.is_dir():
            return len(list(p.glob("*.py")))
        return 0
    except (OSError, ValueError):
        return 0


def _short_hwid(hwid: str) -> str:
    """Return first 12 chars of HWID with ellipsis."""
    if len(hwid) > 12:
        return hwid[:12] + "..."
    return hwid


# ═══════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════

BANNER_LINES = (
    " ██████╗ ███╗   ███╗███╗   ██╗██╗ ██████╗ ██████╗ ██████╗ ███████╗",
    "██╔═══██╗████╗ ████║████╗  ██║██║██╔════╝██╔═══██╗██╔══██╗██╔════╝",
    "██║   ██║██╔████╔██║██╔██╗ ██║██║██║     ██║   ██║██████╔╝█████╗  ",
    "██║   ██║██║╚██╔╝██║██║╚████╗║██║██║     ██║   ██║██╔══██╗██╔══╝  ",
    "██║   ██║██║ ╚═╝ ██║██║ ╚███║║██║██║     ██║   ██║██║  ██║███████╗",
    "╚██████╔╝╚═╝     ╚═╝╚═╝  ╚══╝╝╚═╝╚██████╗╚██████╔╝██║  ██║╚══════╝",
)


# Fire-red palette: bright at top → dark ember at bottom
_BANNER_PALETTE = ("196", "203", "196", "160", "124", "88")


def _banner_char_color(line_idx: int, total_lines: int, char_idx: int,
                       total_chars: int) -> str:
    """
    Return a 256-color code for a character. Vertical red gradient
    with a subtle horizontal shimmer.
    """
    if total_lines <= 0:
        return "196"
    # clamp and index into palette
    idx = min(line_idx, len(_BANNER_PALETTE) - 1)
    return _BANNER_PALETTE[idx]


def render_banner(console: Console) -> None:
    """
    Display the animated OmniCore banner, revealing character by character.
    """
    console.print()  # spacing

    total_lines = len(BANNER_LINES)
    current_lines: List[Text] = [Text("") for _ in range(total_lines)]

    with Live(console=console, refresh_per_second=30) as live:
        for li, line in enumerate(BANNER_LINES):
            current = Text("")
            for ci, ch in enumerate(line):
                color = _banner_char_color(li, total_lines, ci, len(line))
                current.append(ch, style=f"color({color})")
                current_lines[li] = current
                # Build display text
                display = Text()
                for idx in range(total_lines):
                    if idx == li:
                        display.append(current_lines[idx].plain)
                        display.stylize(
                            f"color({_banner_char_color(li, total_lines, ci, len(line))})",
                            0, len(current_lines[idx].plain)
                        )
                    else:
                        display.append(current_lines[idx].plain)
                    display.append("\n")

                live.update(Align.center(display))
                time.sleep(BANNER_CHAR_DELAY)

        # Final frame with full gradient
        final = Text()
        for li, line in enumerate(BANNER_LINES):
            for ci, ch in enumerate(line):
                color = _banner_char_color(li, total_lines, ci, len(line))
                final.append(ch, style=f"color({color})")
            final.append("\n")

        # Add tagline
        final.append("\n")
        tagline = f"  {t('banner.tagline')}  "
        final.append(tagline, style=f"dim {STYLE_AMBER}")
        final.append("\n")

        live.update(Align.center(final))
        time.sleep(BANNER_PAUSE)

    console.print()


# ═══════════════════════════════════════════════════════════════════════
# STATUS PANEL
# ═══════════════════════════════════════════════════════════════════════

def build_status_panel(context: Any) -> Panel:
    """Build the status panel showing session information."""
    module_count = count_modules(context.modules_dir)
    lang = get_current_language().upper()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style=STYLE_DIM, justify="right", width=10)
    table.add_column(style=STYLE_GREEN, justify="left")

    table.add_row(f"{t('status.hwid')} :", _short_hwid(context.hwid))
    table.add_row(f"{t('status.session')} :", f"[{CLR_GREEN}]* {t('status.active')}[/]")
    table.add_row(f"{t('status.version')} :", context.app_version)
    table.add_row(f"{t('status.modules')} :", str(module_count))
    table.add_row(f"{t('status.language')} :", lang)

    return Panel(
        Align.center(table),
        box=box.ROUNDED,
        border_style=STYLE_CYAN,
        padding=(0, 4),
        title=f"[{CLR_CYAN}]── STATUS ──[/]",
        title_align="left",
    )


# ═══════════════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════════════

# ─── Import name → PyPI name map (common mismatches) ────────────────
_IMPORT_TO_PYPI = {
    "yaml":       "PyYAML",
    "PIL":        "Pillow",
    "cv2":        "opencv-python",
    "sklearn":    "scikit-learn",
    "bs4":        "beautifulsoup4",
    "dotenv":     "python-dotenv",
    "serial":     "pyserial",
    "Crypto":     "pycryptodome",
    "OpenSSL":    "pyOpenSSL",
    "dateutil":   "python-dateutil",
    "magic":      "python-magic",
    "requests":   "requests",
    "flask":      "flask",
    "rich":       "rich",
    "docx":       "python-docx",
    "pptx":       "python-pptx",
    "fitz":       "PyMuPDF",
    "lxml":       "lxml",
    "tqdm":       "tqdm",
    "numpy":      "numpy",
    "pandas":     "pandas",
    "matplotlib": "matplotlib",
    "scapy":      "scapy",
    "paramiko":   "paramiko",
    "pyfiglet":   "pyfiglet",
    "tabulate":   "tabulate",
    "colorama":   "colorama",
    "termcolor":  "termcolor",
    "psutil":     "psutil",
    "httpx":      "httpx",
    "aiohttp":    "aiohttp",
    "jinja2":     "Jinja2",
}

_REQUIREMENTS_FILENAMES = (
    "requirements.txt", "requirements.in",
    "deps.txt", "dependencies.txt",
)


def _parse_requirements_file(path):
    """Read a requirements.txt and return clean package names."""
    names = []
    try:
        for raw in path.read_text(encoding="utf-8",
                                   errors="replace").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            # strip version specifiers and extras
            for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "[", ";"):
                if sep in line:
                    line = line.split(sep, 1)[0]
            name = line.strip()
            if name:
                names.append(name)
    except OSError:
        pass
    return names


def _scan_plugin_imports(plugin_dir):
    """
    AST-scan every .py in plugin_dir and return top-level imports
    that are NOT stdlib and NOT local files.
    """
    import ast
    try:
        stdlib = set(sys.stdlib_module_names)  # py3.10+
    except AttributeError:
        stdlib = set()

    local = set()
    try:
        for entry in plugin_dir.iterdir():
            if entry.is_file() and entry.suffix == ".py":
                local.add(entry.stem)
            elif entry.is_dir() and (entry / "__init__.py").is_file():
                local.add(entry.name)
    except OSError:
        pass

    needed = set()
    for py in plugin_dir.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8",
                                           errors="replace"))
        except (SyntaxError, OSError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    top = n.name.split(".", 1)[0]
                    if top and top not in stdlib and top not in local:
                        needed.add(top)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    top = node.module.split(".", 1)[0]
                    if top and top not in stdlib and top not in local:
                        needed.add(top)
    return needed


def _pip_install_packages(pypi_names, console=None):
    """
    Install a list of PyPI packages for the current user.
    Tries --user --break-system-packages first (PEP 668 environments),
    then plain --user, then pipx for CLI tools.
    Returns (ok, log_lines).
    """
    if not pypi_names:
        return True, []
    import subprocess as _sp

    env = dict(os.environ)
    env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    env.setdefault("PIP_NO_CACHE_DIR", "0")

    base = [sys.executable, "-m", "pip", "install",
            "--upgrade", "--no-input"]
    attempts = [
        base + ["--user", "--break-system-packages"] + list(pypi_names),
        base + ["--user"] + list(pypi_names),
        base + list(pypi_names),
    ]
    log = []
    for cmd in attempts:
        try:
            r = _sp.run(cmd, capture_output=True, text=True,
                        timeout=900, env=env)
            tail = (r.stdout or "").strip().splitlines()[-3:]
            log.append(f"  $ {' '.join(cmd[2:5])}... -> rc={r.returncode}")
            if r.returncode == 0:
                return True, log
            if r.stderr:
                log.append("    " + r.stderr.strip().splitlines()[-1][:120])
        except (_sp.TimeoutExpired, OSError) as e:
            log.append(f"  ! {e}")
    return False, log


def _ensure_plugin_deps(plugin_dir, meta=None, console=None):
    """
    Ensure a plugin's Python dependencies are available.
    1. If MENU_META declares "requires": use that list.
    2. Else if a requirements file exists: parse it.
    3. Else scan the plugin's code via AST.
    Then install only what is missing.
    """
    import importlib.util as _ilu

    # 1) Explicit list from MENU_META
    wanted = []
    if meta and isinstance(meta.get("requires"), (list, tuple)):
        wanted = [str(x) for x in meta["requires"]]

    # 2) requirements file
    if not wanted:
        for fname in _REQUIREMENTS_FILENAMES:
            rf = plugin_dir / fname
            if rf.is_file():
                wanted = _parse_requirements_file(rf)
                break

    # 3) AST scan
    if not wanted:
        wanted = sorted(_scan_plugin_imports(plugin_dir))

    if not wanted:
        return True, []

    # Filter: keep only modules that are NOT importable
    missing_pypi = []
    for mod in wanted:
        top = mod.split("[", 1)[0].split("=", 1)[0].strip()
        try:
            if _ilu.find_spec(top) is None:
                missing_pypi.append(_IMPORT_TO_PYPI.get(top, top))
        except (ImportError, ValueError):
            missing_pypi.append(_IMPORT_TO_PYPI.get(top, top))

    # Drop duplicates while preserving order
    seen = set()
    missing_pypi = [x for x in missing_pypi
                    if not (x.lower() in seen or seen.add(x.lower()))]

    if not missing_pypi:
        return True, []

    if console:
        console.print(
            f"  [{CLR_CYAN}]i[/] Plugin needs: "
            f"[{CLR_GREEN}]{', '.join(missing_pypi)}[/]")
        console.print(
            f"  [{CLR_DIM}]  installing for user "
            f"(this may take a moment)...[/]")

    ok, log = _pip_install_packages(missing_pypi, console)

    if console:
        if ok:
            console.print(
                f"  [{CLR_GREEN}]+[/] Dependencies installed.")
        else:
            console.print(
                f"  [{CLR_AMBER}]![/] Auto-install failed — "
                f"plugin may crash.")
            for line in log[-3:]:
                console.print(f"  [{CLR_DIM}]{line}[/]")

    # Invalidate import caches so the freshly-installed modules
    # become importable within this same process.
    import importlib
    importlib.invalidate_caches()

    return ok, log




def discover_plugins(modules_dir, console=None):
    """
    Scan for plugins in modules_dir/plugins/ and ./plugins/ (dev).
    Supports BOTH single files (plugin.py) and packages (plugin/__init__.py).
    Packages get their own directory prepended to sys.path so sibling
    imports inside them work. Also auto-installs missing dependencies
    via _ensure_plugin_deps().
    """
    import importlib.util as _ilu
    import importlib as _il

    candidates = [
        Path(modules_dir) / "plugins",
        Path(__file__).resolve().parent / "plugins",
    ]
    search_dirs = [d for d in candidates if d.is_dir()]
    if not search_dirs:
        return []

    # Collect entry-point files: *.py files and dir/__init__.py
    entries = []
    for d in search_dirs:
        try:
            for item in sorted(d.iterdir()):
                if item.is_file() and item.suffix == ".py" \
                        and not item.name.startswith("_"):
                    entries.append(item)
                elif item.is_dir() and (item / "__init__.py").is_file():
                    entries.append(item / "__init__.py")
        except OSError:
            continue

    found = []
    seen_files = set()          # dedupe by plugin NAME, not full path
    seen_names = set()

    for entry_file in entries:
        # Same plugin name in dev/ and modules/ ?  Keep the first only.
        _name = (entry_file.parent.name
                 if entry_file.name == "__init__.py"
                 else entry_file.stem)
        if _name in seen_names:
            continue
        seen_names.add(_name)

        plugin_root = entry_file.parent
        if entry_file.name == "__init__.py":
            display_name = entry_file.parent.name
        else:
            display_name = entry_file.stem

        try:
            # Make the plugin's own directory importable for siblings.
            root_str = str(plugin_root)
            if root_str not in sys.path:
                sys.path.insert(0, root_str)

            spec = _ilu.spec_from_file_location(
                f"omnicore_plugin_{display_name}", entry_file)
            if spec is None or spec.loader is None:
                continue
            mod = _ilu.module_from_spec(spec)
            spec.loader.exec_module(mod)

            meta = getattr(mod, "MENU_META", None)
            if not isinstance(meta, dict):
                continue

            # Ensure dependencies BEFORE registering the plugin.
            try:
                _ensure_plugin_deps(plugin_root, meta, console)
            except Exception as _de:
                if console:
                    console.print(
                        f"  [{CLR_AMBER}]![/] dep-check failed for "
                        f"{display_name}: {_de}")

            # Reload the module so freshly-installed deps are visible.
            try:
                _il.invalidate_caches()
                spec = _ilu.spec_from_file_location(
                    f"omnicore_plugin_{display_name}", entry_file)
                mod = _ilu.module_from_spec(spec)
                spec.loader.exec_module(mod)
            except Exception:
                pass  # keep the first load as fallback

            entry_name = meta.get("entry", "run")
            entry = getattr(mod, entry_name, None)
            if not callable(entry):
                if console:
                    console.print(
                        f"  [{CLR_AMBER}]![/] plugin '{display_name}': "
                        f"entry '{entry_name}' missing or not callable")
                continue

            found.append({
                "key":   str(meta.get("key", "?")),
                "label": str(meta.get("label", display_name)),
                "sub":   str(meta.get("sub", "")),
                "entry": entry,
                "file":  entry_file,
            })
        except Exception as _pe:
            if console:
                console.print(
                    f"  [{CLR_AMBER}]![/] plugin '{display_name}' skipped: "
                    f"{_pe}")
            continue

    # Sort by numeric key ("9" < "10" < "11"), then alphabetically.
    def _key_num(pl):
        try:
            return (0, int(pl["key"]))
        except (ValueError, TypeError):
            return (1, str(pl["key"]))

    found.sort(key=_key_num)
    return found


def build_main_menu(plugins=None) -> Panel:
    """Build the main menu panel."""
    menu_items = [
        ("1", t("menu.install"), ""),
        ("2", t("menu.health"), t("menu.health.sub")),
        ("3", t("menu.recon"), t("menu.recon.sub")),
        ("4", t("menu.web"), t("menu.web.sub")),
        ("5", t("menu.tools"), t("menu.tools.sub")),
        ("6", t("menu.report"), t("menu.report.sub")),
        ("7", t("menu.support"), ""),
        ("8", t("menu.settings"), ""),
    ]

    # ── injected plugin entries ──
    for _p in (plugins or []):
        menu_items.append((_p["key"], _p["label"], _p["sub"]))

    # ── Exit is always last ──
    menu_items.append(("0", t("menu.exit"), ""))

    lines = Text()
    for key, label, sub in menu_items:
        lines.append(f"  [{key}] ", style=STYLE_CYAN)
        lines.append(label, style=STYLE_GREEN)
        if sub:
            lines.append(f"  - {sub}", style=STYLE_DIM)
        lines.append("\n")

    return Panel(
        lines,
        box=box.ROUNDED,
        border_style=STYLE_GREEN,
        padding=(1, 2),
        title=f"[{CLR_GREEN}]{t('menu.title')}[/]",
        title_align="center",
    )


def build_footer() -> Panel:
    """Build the always-visible authorization footer."""
    footer_text = t("footer.text")
    wrapped = textwrap.fill(footer_text, width=72)
    return Panel(
        Text(wrapped, style="dim"),
        box=box.SIMPLE,
        border_style=STYLE_DIM,
        padding=(0, 2),
    )


# ═══════════════════════════════════════════════════════════════════════
# AUTHORIZATION GATE
# ═══════════════════════════════════════════════════════════════════════

def show_authorization_gate(console: Console, context: Any) -> bool:
    """
    Display the authorization gate. Returns True if the user agrees,
    False otherwise. Writes consent.json on acceptance.
    """
    console.clear()

    gate_content = Text()
    gate_content.append(f"  {t('gate.intro')}\n\n", style=STYLE_AMBER)

    checkboxes = [
        (t("gate.c1"), t("gate.c1b")),
        (t("gate.c2"), t("gate.c2b")),
        (t("gate.c3"), t("gate.c3b")),
        (t("gate.c4"), ""),
    ]

    for i, (line1, line2) in enumerate(checkboxes, 1):
        gate_content.append(f"    [ ] {line1}\n", style=STYLE_CYAN)
        if line2:
            gate_content.append(f"        {line2}\n", style=STYLE_CYAN)

    gate_content.append(f"\n  {t('gate.prompt')}\n", style=STYLE_GREEN)

    gate_panel = Panel(
        gate_content,
        box=box.ROUNDED,
        border_style=STYLE_AMBER,
        padding=(1, 2),
        title=f"[{CLR_RED}]{t('gate.title')}[/]",
        title_align="center",
        width=68,
    )

    console.print(Align.center(gate_panel))
    console.print()

    try:
        answer = console.input("  [bold]  > [/]").strip()
    except EOFError:
        console.print(f"\n  [{CLR_RED}]{t('gate.refused')}[/]\n")
        return False

    if answer.upper() != "I AGREE":
        console.print(f"\n  [{CLR_RED}]{t('gate.refused')}[/]\n")
        return False

    # Write consent file
    consent_data = {
        "hwid": context.hwid,
        "agreed_at": datetime.now(timezone.utc).isoformat(),
        "app_version": context.app_version,
    }

    if atomic_write_json(CONSENT_FILE, consent_data, console):
        console.print(f"\n  [{CLR_GREEN}]+ {t('gate.agreed')}[/]\n")
        return True
    else:
        # If write fails, still allow the session but warn
        console.print(
            f"\n  [{CLR_AMBER}]! Could not persist consent file.[/]\n"
        )
        return True


# ═══════════════════════════════════════════════════════════════════════
# SUPPORT SUB-MENU
# ═══════════════════════════════════════════════════════════════════════

def show_support(console: Console) -> None:
    """Display the support panel and open the Telegram channel."""
    console.clear()
    support_content = Text()
    support_content.append(f"  {t('support.telegram')}: ", style=STYLE_CYAN)
    support_content.append(f"{SUPPORT_TELEGRAM}\n\n", style=STYLE_GREEN)
    support_content.append(f"  {t('support.opening')}\n", style=STYLE_DIM)

    panel = Panel(
        support_content,
        box=box.ROUNDED,
        border_style=STYLE_CYAN,
        padding=(1, 2),
        title=f"[{CLR_CYAN}]{t('support.title')}[/]",
        width=50,
    )
    console.print(Align.center(panel))

    # Try opening Telegram via multiple methods
    _open_telegram(console)

    console.print(
        f"  [{CLR_DIM}]{t('support.opened', url=SUPPORT_TELEGRAM_URL)}[/]\n"
    )
    try:
        console.input(f"  [{CLR_DIM}]{t('support.press_enter')}[/]")
    except EOFError:
        pass
    console.print()


def _open_telegram(console: Console) -> None:
    """Attempt to open Telegram support link via multiple methods."""
    # Method 1: telegram-desktop (if installed)
    if shutil.which("telegram-desktop"):
        try:
            subprocess.run(
                ["telegram-desktop", f"--url={SUPPORT_TELEGRAM_URL}"],
                timeout=10,
                capture_output=True,
                start_new_session=True,
            )
            return
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    # Method 2: xdg-open
    if shutil.which("xdg-open"):
        try:
            subprocess.run(
                ["xdg-open", SUPPORT_TELEGRAM_URL],
                timeout=10,
                capture_output=True,
                start_new_session=True,
            )
            return
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    # Method 3: Python webbrowser
    try:
        webbrowser.open(SUPPORT_TELEGRAM_URL)
    except Exception:
        pass  # Non-fatal, URL is displayed for manual access


# ═══════════════════════════════════════════════════════════════════════
# SETTINGS SUB-MENU
# ═══════════════════════════════════════════════════════════════════════

def load_settings() -> Dict[str, Any]:
    """Load settings.json, returning defaults if not present."""
    defaults = {"language": "en", "theme": "dark"}
    stored = load_json_file(SETTINGS_FILE)
    if stored and isinstance(stored, dict):
        defaults.update({k: v for k, v in stored.items() if k in defaults})
    return defaults


def save_settings(settings: Dict[str, Any], console: Console) -> bool:
    """Persist settings atomically."""
    return atomic_write_json(SETTINGS_FILE, settings, console)


def show_settings(console: Console, context: Any) -> Optional[str]:
    """
    Display the settings sub-menu.
    Returns a signal string:
      - "exit" if consent was reset (tool should exit)
      - None otherwise
    """
    settings = load_settings()

    while True:
        console.clear()
        settings_content = Text()
        settings_content.append("  [1] ", style=STYLE_CYAN)
        settings_content.append(t("settings.language"), style="")
        settings_content.append(f"  ( {settings['language'].upper()} )", style=STYLE_GREEN)
        settings_content.append("\n")
        settings_content.append("  [2] ", style=STYLE_CYAN)
        settings_content.append(t("settings.theme"), style="")
        settings_content.append(f"  ( {settings['theme']} )", style=STYLE_GREEN)
        settings_content.append("\n")
        settings_content.append("  [3] ", style=STYLE_CYAN)
        settings_content.append(t("settings.reset_consent"), style="")
        settings_content.append("\n")
        settings_content.append("  [0] ", style=STYLE_CYAN)
        settings_content.append(t("menu.exit"), style="")
        settings_content.append("\n")

        panel = Panel(
            settings_content,
            box=box.ROUNDED,
            border_style=STYLE_GREEN,
            padding=(1, 2),
            title=f"[{CLR_GREEN}]{t('settings.title')}[/]",
            width=56,
        )
        console.print(Align.center(panel))

        try:
            choice = console.input(
                f"  [{CLR_CYAN}]> [/]"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        if choice == "0":
            return None

        elif choice == "1":
            # Language selection
            _handle_language_selection(console, settings)

        elif choice == "2":
            # Theme toggle
            new_theme = "light" if settings["theme"] == "dark" else "dark"
            settings["theme"] = new_theme
            save_settings(settings, console)
            console.print(
                f"  [{CLR_GREEN}]+ {t('settings.new_value', value=new_theme)}[/]\n"
            )

        elif choice == "3":
            # Reset consent
            result = _handle_reset_consent(console, context)
            if result == "exit":
                return "exit"

        else:
            console.print(
                f"  [{CLR_AMBER}]! {t('menu.invalid')}[/]\n"
            )


def _handle_language_selection(console: Console, settings: Dict) -> None:
    """Handle the language selection submenu."""
    i18n_mod = _try_import_i18n()
    available: List[str] = ["en", "ru"]
    if i18n_mod and hasattr(i18n_mod, "available_languages"):
        try:
            langs = i18n_mod.available_languages()
            if langs and isinstance(langs, list):
                available = [str(l) for l in langs if isinstance(l, str)]
        except Exception:
            pass

    console.print(
        f"  [{CLR_DIM}]{t('settings.available', values=', '.join(available))}[/]"
    )
    try:
        choice = console.input("  [bold]  > [/]").strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print()
        return

    if choice in available:
        settings["language"] = choice
        set_language(choice)
        save_settings(settings, console)
        console.print(
            f"  [{CLR_GREEN}]+ {t('settings.new_value', value=choice.upper())}[/]\n"
        )
    else:
        console.print(
            f"  [{CLR_AMBER}]! {t('warn.invalid_input')}[/]\n"
        )


def _handle_reset_consent(console: Console, context: Any) -> Optional[str]:
    """Handle consent reset. Returns 'exit' if confirmed, None otherwise."""
    console.print(
        f"\n  [{CLR_AMBER}]! {t('settings.reset_warning')}[/]\n"
    )
    try:
        confirm = console.input(
            f"  [{CLR_RED}]{t('settings.confirm_reset')}[/]"
        ).strip()
    except (EOFError, KeyboardInterrupt):
        console.print(f"\n  [{CLR_GREEN}]{t('settings.cancelled')}[/]\n")
        return None

    if confirm == "RESET":
        try:
            if CONSENT_FILE.exists():
                CONSENT_FILE.unlink()
            console.print(
                f"\n  [{CLR_GREEN}]+ {t('settings.reset_done')}[/]\n"
            )
            time.sleep(1.5)
            return "exit"
        except OSError as e:
            console.print(
                f"  [{CLR_RED}]{t('warn.file_error', error=str(e))}[/]\n"
            )
            return None
    else:
        console.print(f"\n  [{CLR_GREEN}]{t('settings.cancelled')}[/]\n")
        return None


# ═══════════════════════════════════════════════════════════════════════
# MODULE LAUNCHER (lazy import + graceful failure)
# ═══════════════════════════════════════════════════════════════════════

def launch_module(console: Console, module_name: str,
                  entry_func: str, context: Any) -> bool:
    """
    Lazily import a sibling module and call its entry function.
    Returns True on success, False if the module is missing or errors.
    """
    try:
        import importlib
        import inspect as _inspect
        mod = importlib.import_module(module_name)
        func = getattr(mod, entry_func, None)
        if func is None or not callable(func):
            raise AttributeError(
                f"'{module_name}' has no callable '{entry_func}'"
            )
        # Pass context when the entry function accepts a second positional arg.
        try:
            sig = _inspect.signature(func)
            n_pos = sum(
                1 for prm in sig.parameters.values()
                if prm.kind in (prm.POSITIONAL_ONLY,
                                prm.POSITIONAL_OR_KEYWORD)
                and prm.default is prm.empty
            )
            has_ctx_kw = "context" in sig.parameters
        except (TypeError, ValueError):
            n_pos, has_ctx_kw = 1, False

        if has_ctx_kw:
            result = func(console, context=context)
        elif n_pos >= 2:
            result = func(console, context)
        else:
            result = func(console)
        # Module ran successfully
        if context.logger:
            context.logger.info(
                "Module %s completed with code %s", module_name, result
            )
        return True
    except ImportError:
        console.print()
        console.print(
            f"  [{CLR_AMBER}]! {t('warn.module_missing', name=module_name)}[/]\n"
        )
        if context.logger:
            context.logger.warning("Module '%s' not found", module_name)
        time.sleep(1.5)
        return False
    except KeyboardInterrupt:
        raise  # Let the caller handle Ctrl+C
    except Exception as e:
        console.print()
        console.print(
            f"  [{CLR_RED}]x Module '{module_name}' error: {e}[/]\n"
        )
        if context.logger:
            context.logger.error(
                "Module '%s' failed: %s", module_name, e, exc_info=True
            )
        time.sleep(1.5)
        return False


# ═══════════════════════════════════════════════════════════════════════
# MAIN MENU LOOP
# ═══════════════════════════════════════════════════════════════════════

def main_menu_loop(console: Console, context: Any) -> int:
    """
    Main menu loop. Returns exit code (0 or 130).
    """
    plugins = discover_plugins(context.modules_dir, console=console)
    plugin_map = {p["key"]: p["entry"] for p in plugins}
    if plugins and context.logger:
        context.logger.info("loaded %d plugin(s): %s",
                            len(plugins),
                            ", ".join(p["label"] for p in plugins))
    while True:
        console.clear()

        # Build and display all panels
        console.print(build_status_panel(context))
        console.print()
        console.print(build_main_menu(plugins))
        console.print()
        console.print(build_footer())
        console.print()

        # Get user input
        try:
            choice = console.input(
                f"  [{CLR_CYAN}]{t('menu.prompt')}[/]"
            ).strip()
        except KeyboardInterrupt:
            console.print(
                f"\n  [{CLR_DIM}]{t('exit.interrupted')}[/]\n"
            )
            return 130
        except EOFError:
            console.print(
                f"\n  [{CLR_DIM}]{t('exit.interrupted')}[/]\n"
            )
            return 0

        # Process choice
        if choice == "0":
            console.print(
                f"\n  [{CLR_GREEN}]{t('exit.message')}[/]\n"
            )
            if context.logger:
                context.logger.info("User requested exit from main menu")
            return 0

        elif choice in plugin_map:
            try:
                plugin_map[choice](context, console)
            except KeyboardInterrupt:
                raise
            except Exception as _e:
                console.print(
                    f"\n  [{CLR_RED}]x Plugin error: {_e}[/]\n")
                if context.logger:
                    context.logger.error(
                        "plugin %s failed: %s", choice, _e,
                        exc_info=True)
                time.sleep(2.0)

        elif choice == "1":
            # Install / Update toolkit — dedicated terminal window
            rc = _spawn_installer_terminal()
            if rc == 127:
                console.print()
                console.print(
                    f"  [{CLR_AMBER}]! {t('warn.module_missing', name='installer')}[/]\n"
                )
                time.sleep(2.0)
            elif rc != 0:
                console.print()
                console.print(
                    f"  [{CLR_RED}]x Could not open installer terminal (rc={rc}).[/]\n"
                )
                time.sleep(2.0)

        elif choice == "2":
            # System Health Scan
            launch_module(console, "health_scan", "run_health_scan", context)

        elif choice == "3":
            # Reconnaissance
            launch_module(console, "recon", "run_recon", context)

        elif choice == "4":
            # Web Assessment
            launch_module(console, "web_scan", "run_web_scan", context)

        elif choice == "5":
            # Tools module (placeholder — will be replaced)
            launch_module(console, "tools", "run_tools", context)

        elif choice == "6":
            # Report Generator
            launch_module(console, "report", "run_report", context)

        elif choice == "7":
            # Support
            show_support(console)

        elif choice == "8":
            # Settings
            result = show_settings(console, context)
            if result == "exit":
                console.print(
                    f"\n  [{CLR_GREEN}]{t('exit.message')}[/]\n"
                )
                return 0

        else:
            console.print(
                f"\n  [{CLR_AMBER}]! {t('menu.invalid')}[/]\n"
            )
            time.sleep(1.0)


# ═══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

# ─── Locked terminal width (computed once per process) ───
_CONSOLE_WIDTH: int | None = None


def _locked_width() -> int:
    """Return a stable terminal width, computed once per process."""
    global _CONSOLE_WIDTH
    if _CONSOLE_WIDTH is None:
        try:
            cols = shutil.get_terminal_size(fallback=(100, 24)).columns
            _CONSOLE_WIDTH = max(80, min(int(cols), 120))
        except Exception:
            _CONSOLE_WIDTH = 100
    return _CONSOLE_WIDTH


# ─── Alternate screen buffer (vim / htop style) ──────────────────────────
_alt_screen_active = False


def _enter_alt_screen() -> None:
    """Enter the alternate screen buffer — a pristine, scrollback-free view."""
    global _alt_screen_active
    if _alt_screen_active:
        return
    try:
        sys.stdout.write("\033[?1049h\033[H\033[2J")
        sys.stdout.flush()
        _alt_screen_active = True
    except Exception:
        pass


def _exit_alt_screen() -> None:
    """Exit the alternate screen buffer — restore the user's original view."""
    global _alt_screen_active
    if not _alt_screen_active:
        return
    try:
        sys.stdout.write("\033[?1049l")
        sys.stdout.flush()
    except Exception:
        pass
    _alt_screen_active = False


import atexit as _atexit
_atexit.register(_exit_alt_screen)


# ─── Spawn installer.py in a dedicated terminal window ──────────────────
def _spawn_installer_terminal() -> int:
    """
    Launch installer.py in a new terminal window (detached from this one).
    Returns 0 on success, non-zero on failure.
    """
    import importlib.util as _ilu
    spec = _ilu.find_spec("installer")
    if spec is None or spec.origin is None:
        return 127  # not installed yet
    installer_path = spec.origin

    # Terminal candidates: (binary, [args-template])
    candidates = [
        ("gnome-terminal", ["--", "{py}", "{script}", "--standalone"]),
        ("kitty",          ["{py}", "{script}", "--standalone"]),
        ("alacritty",      ["-e", "{py}", "{script}", "--standalone"]),
        ("konsole",        ["-e", "{py}", "{script}", "--standalone"]),
        ("xfce4-terminal", ["-e", "{py} {script} --standalone"]),
        ("mate-terminal",  ["-e", "{py} {script} --standalone"]),
        ("lxterminal",     ["-e", "{py} {script} --standalone"]),
        ("xterm",          ["-e", "{py}", "{script}", "--standalone"]),
    ]

    py = sys.executable
    for binary, tmpl in candidates:
        if not shutil.which(binary):
            continue
        args = [
            a.format(py=py, script=installer_path) for a in tmpl
        ]
        # xfce4/lxterminal need single-string -e
        if binary in ("xfce4-terminal", "lxterminal", "mate-terminal"):
            args = ["-e", f"{py} {installer_path} --standalone"]
        try:
            subprocess.Popen(
                [binary] + args,
                start_new_session=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return 0
        except (FileNotFoundError, OSError):
            continue

    # Fallback: run in the same terminal (not detached)
    try:
        r = subprocess.run(
            [py, installer_path, "--standalone"],
            timeout=None,
        )
        return r.returncode
    except (OSError, subprocess.SubprocessError):
        return 1



def omnicore_entry(context: Any) -> int:
    """
    Main entry point called by main.py.

    Args:
        context: RuntimeContext dataclass with fields:
            - app_name, app_version, data_dir, modules_dir,
              hwid, sync_report, logger, argv

    Returns:
        Exit code: 0 on clean exit, 130 on Ctrl+C.
    """
    # Create console with specified settings
    console = Console(
        highlight=False,
        soft_wrap=False,
        color_system="truecolor",
        legacy_windows=False,    # Unicode box drawing (terminal is UTF-8)
        width=_locked_width(),   # lock width: no drift across re-renders
    )

    # Initialize i18n
    _setup_i18n()

    # Enter the pristine alternate screen (vim/htop style)
    _enter_alt_screen()

    # Load persisted language setting
    try:
        settings = load_settings()
        if "language" in settings:
            set_language(settings["language"])
    except Exception:
        pass

    # Log entry
    if context.logger:
        context.logger.info(
            "OmniCore core_engine starting (v%s, hwid=%s...)",
            context.app_version,
            str(context.hwid)[:8],
        )

    try:
        # ── Authorization Gate ──
        if not consent_is_valid(context):
            if not show_authorization_gate(console, context):
                if context.logger:
                    context.logger.info("User refused authorization gate")
                return 0
        else:
            if context.logger:
                context.logger.info("Existing consent validated")

        # ── Animated Banner ──
        render_banner(console)

        # ── Main Menu Loop ──
        exit_code = main_menu_loop(console, context)

        if context.logger:
            context.logger.info("OmniCore exiting with code %d", exit_code)

        return exit_code

    except KeyboardInterrupt:
        console.print(
            f"\n  [{CLR_DIM}]{t('exit.interrupted')}[/]\n"
        )
        if context.logger:
            context.logger.info("Interrupted (Ctrl+C), returning 130")
        return 130

    except Exception as e:
        console.print(f"\n  [{CLR_RED}]FATAL ERROR: {e}[/]\n")
        if context.logger:
            context.logger.critical(
                "Unhandled exception in core_engine: %s", e, exc_info=True
            )
        return 1


# ═══════════════════════════════════════════════════════════════════════
# DEMO / STANDALONE RUN
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class DummyContext:
    """Dummy RuntimeContext for standalone demo execution."""
    app_name: str = "OmniCore"
    app_version: str = "1.0.0"
    data_dir: str = "/tmp/omnicore_data"
    modules_dir: str = "/tmp/omnicore_modules"
    hwid: str = "DEMOHWID123456789ABCDEF"
    sync_report: Any = None
    logger: Any = None
    argv: List[str] = None

    def __post_init__(self):
        if self.argv is None:
            self.argv = []


if __name__ == "__main__":
    # Create a minimal logger for the demo
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(name)s: %(message)s"
    )
    demo_logger = logging.getLogger("OmniCore.demo")

    # Create dummy context
    dummy = DummyContext(logger=demo_logger)

    # Ensure directories exist for the demo
    Path(dummy.modules_dir).mkdir(parents=True, exist_ok=True)

    # Run the engine
    _exit = omnicore_entry(dummy)
    sys.exit(_exit)