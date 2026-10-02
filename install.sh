cat > ~/OmniCore/install.sh << 'INSTALLEOF'
#!/usr/bin/env bash
# ============================================================================
#  OmniCore — Quick installer
#  Supports: Debian/Ubuntu/Kali/Mint · Fedora/RHEL · Arch/Manjaro ·
#            openSUSE · antiX/Devuan · Alpine · Void
# ============================================================================
set -e

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}   OmniCore — Authorized Pentest Framework · Installer    ${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}!${NC}  $*"; }
fail() { echo -e "  ${RED}✗${NC}  $*"; }
info() { echo -e "  ${CYAN}i${NC}  $*"; }

# ── Detect project root (script location) ───────────────────────────────────
PROJECT_ROOT="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$PROJECT_ROOT"

banner

# ── 1 · Verify bootstrap files ──────────────────────────────────────────────
echo -e "${BOLD}[1/5] Verifying installation files${NC}"
REQUIRED=(
    "main.py"
    "hwid_guard.py"
    "updater.py"
    "hardware_id.py"
    "integrity.py"
)
MISSING=()
for f in "${REQUIRED[@]}"; do
    if [[ -f "$PROJECT_ROOT/$f" ]]; then
        ok "$f"
    else
        fail "$f  MISSING"
        MISSING+=("$f")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo ""
    fail "Installation incomplete — aborting."
    info "Please re-clone the repository:"
    echo -e "      ${DIM}git clone https://github.com/MONAIM-FP/OmniCore.git${NC}"
    exit 1
fi

# ── 2 · Detect distro ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[2/5] Detecting distribution${NC}"

DISTRO_ID="unknown"
DISTRO_FAMILY="unknown"
if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_PRETTY="${PRETTY_NAME:-$ID}"
    for like in ${ID_LIKE:-}; do
        case "$like" in
            debian) DISTRO_FAMILY="debian"; break ;;
            fedora|rhel) DISTRO_FAMILY="fedora"; break ;;
            arch) DISTRO_FAMILY="arch"; break ;;
            suse|opensuse) DISTRO_FAMILY="suse"; break ;;
        esac
    done
    # Direct ID map (when ID_LIKE is empty)
    if [[ "$DISTRO_FAMILY" == "unknown" ]]; then
        case "$DISTRO_ID" in
            debian|ubuntu|kali|parrot|mint|linuxmint|pop|elementary|antix|mx|devuan|raspbian) DISTRO_FAMILY="debian" ;;
            fedora|rhel|centos|rocky|almalinux|ol)                                    DISTRO_FAMILY="fedora" ;;
            arch|manjaro|blackarch|endeavouros|garuda|artix|cachyos)                  DISTRO_FAMILY="arch"   ;;
            opensuse*|suse|sles)                                                       DISTRO_FAMILY="suse"   ;;
            alpine)                                                                    DISTRO_FAMILY="alpine" ;;
            void)                                                                      DISTRO_FAMILY="void"   ;;
        esac
    fi
fi

ok "Distro : ${DISTRO_PRETTY:-unknown}"
ok "Family : $DISTRO_FAMILY"

# ── 3 · Check Python ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[3/5] Verifying Python 3.10+${NC}"

if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 not found — install it first"
    exit 1
fi

PYVER=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
PYMAJ=$(python3 -c 'import sys; print(sys.version_info[0])')
PYMIN=$(python3 -c 'import sys; print(sys.version_info[1])')

if [[ "$PYMAJ" -lt 3 ]] || { [[ "$PYMAJ" -eq 3 ]] && [[ "$PYMIN" -lt 10 ]]; }; then
    fail "Python $PYVER found — 3.10 or newer is required"
    exit 1
fi
ok "Python $PYVER"

# ── 4 · Install Python dependencies ─────────────────────────────────────────
echo ""
echo -e "${BOLD}[4/5] Installing Python dependencies${NC}"

# Try progressively permissive strategies
pip_install() {
    local pkg="$1"

    # Fast path: already present
    if python3 -c "import $pkg" 2>/dev/null; then
        ok "$pkg already installed"
        return 0
    fi

    info "Installing $pkg…"

    # Strategy 1: apt/dnf/pacman/zypper system package
    case "$DISTRO_FAMILY" in
        debian)
            if command -v apt >/dev/null 2>&1; then
                if sudo apt install -y "python3-$pkg" >/dev/null 2>&1; then
                    ok "$pkg installed via apt"; return 0
                fi
            fi ;;
        fedora)
            if command -v dnf >/dev/null 2>&1; then
                if sudo dnf install -y "python3-$pkg" >/dev/null 2>&1; then
                    ok "$pkg installed via dnf"; return 0
                fi
            fi ;;
        arch)
            if command -v pacman >/dev/null 2>&1; then
                if sudo pacman -S --noconfirm "python-$pkg" >/dev/null 2>&1; then
                    ok "$pkg installed via pacman"; return 0
                fi
            fi ;;
        suse)
            if command -v zypper >/dev/null 2>&1; then
                if sudo zypper install -y "python3-$pkg" >/dev/null 2>&1; then
                    ok "$pkg installed via zypper"; return 0
                fi
            fi ;;
        alpine)
            if command -v apk >/dev/null 2>&1; then
                if sudo apk add --no-cache "py3-$pkg" >/dev/null 2>&1; then
                    ok "$pkg installed via apk"; return 0
                fi
            fi ;;
    esac

    # Strategy 2: pip --user
    if python3 -m pip install --user "$pkg" >/dev/null 2>&1; then
        ok "$pkg installed via pip --user"; return 0
    fi

    # Strategy 3: pip --user --break-system-packages (PEP 668)
    if python3 -m pip install --user --break-system-packages "$pkg" >/dev/null 2>&1; then
        ok "$pkg installed via pip --user --break-system-packages"; return 0
    fi

    # Strategy 4: pipx
    if command -v pipx >/dev/null 2>&1; then
        if pipx install "$pkg" >/dev/null 2>&1; then
            ok "$pkg installed via pipx"; return 0
        fi
    fi

    fail "$pkg could not be installed automatically"
    info "Install it manually:  pip install --user $pkg"
    return 1
}

DEP_FAIL=0
pip_install requests || DEP_FAIL=1
pip_install rich     || DEP_FAIL=1

if [[ "$DEP_FAIL" -ne 0 ]]; then
    echo ""
    warn "One or more dependencies are missing."
    info "OmniCore can still start — the missing packages will be"
    info "installed automatically on first run via tools_bootstrap."
fi

# ── 5 · Set permissions + smoke test ────────────────────────────────────────
echo ""
echo -e "${BOLD}[5/5] Finalizing${NC}"

chmod +x "$PROJECT_ROOT/main.py" \
         "$PROJECT_ROOT/hwid_guard.py" \
         "$PROJECT_ROOT/updater.py" \
         "$PROJECT_ROOT/hardware_id.py" \
         "$PROJECT_ROOT/integrity.py" \
         "$PROJECT_ROOT/install.sh" 2>/dev/null || true
ok "Executables marked"

# Verify integrity module loads
if python3 -c "import sys; sys.path.insert(0, '$PROJECT_ROOT'); import integrity" 2>/dev/null; then
    ok "integrity.py loads cleanly"
else
    fail "integrity.py failed to import — check the file"
fi

# ── Done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}   Installation complete                                   ${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Next:${NC}"
echo -e "      ${CYAN}cd $PROJECT_ROOT${NC}"
echo -e "      ${CYAN}python3 main.py${NC}"
echo ""
echo -e "  ${DIM}On first launch you will be asked for a license key.${NC}"
echo -e "  ${DIM}Obtain one at:  https://t.me/monaimFp${NC}"
echo ""
echo -e "  ${YELLOW}AUTHORIZED USE ONLY.${NC} You must have written permission from"
echo -e "  the owner of any system you test."
echo ""

exit 0
INSTALLEOF

chmod +x ~/OmniCore/install.sh
bash -n ~/OmniCore/install.sh && echo "✓ install.sh: syntax OK"
