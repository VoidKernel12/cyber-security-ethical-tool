#!/data/data/com.termux/files/usr/bin/bash
# ============================================================================
#  SENTINEL-CLI — Termux Installation & Setup Script
#  Checks for Python 3, installs dependencies (including Flask, optional for
#  spinning up a local test target), sets permissions, and confirms install.
# ============================================================================

set -e

GREEN="\033[38;5;46m"
CYAN="\033[38;5;51m"
YELLOW="\033[38;5;226m"
RED="\033[38;5;196m"
MAGENTA="\033[38;5;201m"
BOLD="\033[1m"
RESET="\033[0m"

info()  { echo -e "${CYAN}${BOLD}[*]${RESET} $1"; }
ok()    { echo -e "${GREEN}${BOLD}[+]${RESET} $1"; }
warn()  { echo -e "${YELLOW}${BOLD}[!]${RESET} $1"; }
fail()  { echo -e "${RED}${BOLD}[-]${RESET} $1"; exit 1; }

echo -e "${CYAN}${BOLD}"
echo "  ==========================================="
echo "   SENTINEL-CLI — Termux Installer"
echo "  ==========================================="
echo -e "${RESET}"

# --- Step 1: Confirm Termux environment ---
if [ -z "$PREFIX" ] || [[ "$PREFIX" != *"com.termux"* ]]; then
    warn "This does not look like a Termux environment."
    warn "Continuing anyway, but some steps below are Termux-specific."
fi

# --- Step 2: Update package lists ---
info "Updating package lists..."
pkg update -y || fail "Failed to update package lists. Check your network connection."
ok "Package lists updated."

# --- Step 3: Check for / install Python 3 ---
info "Checking for Python 3..."
if command -v python3 >/dev/null 2>&1; then
    PY_VERSION=$(python3 --version 2>&1)
    ok "Python already installed: $PY_VERSION"
else
    info "Python 3 not found. Installing..."
    pkg install python -y || fail "Failed to install Python 3."
    ok "Python 3 installed: $(python3 --version)"
fi

# --- Step 4: Ensure pip is available ---
info "Checking for pip..."
if python3 -m pip --version >/dev/null 2>&1; then
    ok "pip is available."
else
    warn "pip not found — attempting to install via pkg..."
    pkg install python-pip -y || warn "Could not install pip automatically. Flask install may fail."
fi

# --- Step 5: Optional Flask install (for spinning up a local test target) ---
echo
info "SENTINEL-CLI's load-testing and audit modules work against any local"
info "server. If you don't already have a test target, Flask is a fast way"
info "to spin one up."
read -rp "$(echo -e "${CYAN}  Install Flask for local test targets? (y/n, default y): ${RESET}")" INSTALL_FLASK
INSTALL_FLASK=${INSTALL_FLASK:-y}

if [[ "$INSTALL_FLASK" =~ ^[Yy]$ ]]; then
    if python3 -c "import flask" >/dev/null 2>&1; then
        ok "Flask already installed."
    else
        info "Installing Flask..."
        python3 -m pip install --upgrade pip -q || warn "pip upgrade failed, continuing anyway."
        python3 -m pip install flask -q || warn "Flask install failed — you can install it manually later with: pip install flask"
        if python3 -c "import flask" >/dev/null 2>&1; then
            ok "Flask installed successfully."
        fi
    fi
else
    info "Skipping Flask install."
fi

# --- Step 6: Verify the main script is present ---
SCRIPT_NAME="secaudit.py"
if [ ! -f "$SCRIPT_NAME" ]; then
    fail "$SCRIPT_NAME not found in the current directory. Place install.sh next to secaudit.py and re-run."
fi
ok "Found $SCRIPT_NAME"

# --- Step 7: Set executable permissions ---
info "Setting permissions..."
chmod +x "$SCRIPT_NAME" 2>/dev/null || true
chmod +x install.sh 2>/dev/null || true
ok "Permissions set."

# --- Step 8: Optional storage access (for custom wordlists/logs) ---
if command -v termux-setup-storage >/dev/null 2>&1; then
    echo
    info "You may be prompted to grant storage access (used for custom"
    info "wordlists or exported logs). This is optional."
    termux-setup-storage || warn "Storage permission skipped or denied — built-in wordlists still work fine."
fi

# --- Step 9: Add a convenient launcher alias ---
SHELL_RC="$HOME/.bashrc"
LAUNCH_CMD="alias sentinel='python3 $(pwd)/$SCRIPT_NAME'"

if [ -f "$SHELL_RC" ] && ! grep -q "alias sentinel=" "$SHELL_RC"; then
    echo "$LAUNCH_CMD" >> "$SHELL_RC"
    ok "Added 'sentinel' shortcut command to $SHELL_RC"
    ALIAS_ADDED=1
else
    info "Launcher alias already present or shell rc not found — skipping."
    ALIAS_ADDED=0
fi

# --- Final banner ---
echo
echo -e "${MAGENTA}${BOLD}"
echo "  ==========================================="
echo "   SENTINEL-CLI — Installation Complete"
echo "  ==========================================="
echo -e "${RESET}"
ok "Python 3 ready."
ok "Permissions configured."
[[ "$INSTALL_FLASK" =~ ^[Yy]$ ]] && ok "Flask available for local test targets."
echo
echo -e "${CYAN}Run the tool with:${RESET}"
echo -e "  ${BOLD}python3 secaudit.py${RESET}"
if [ "$ALIAS_ADDED" = "1" ]; then
    echo -e "${CYAN}or, after reloading your shell:${RESET}"
    echo -e "  ${BOLD}source ~/.bashrc && sentinel${RESET}"
fi
echo
warn "Please read DISCLAIMER.md before use — authorized local testing only."
