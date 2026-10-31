#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  SUBMAP Installer
#  Advanced Subdomain Discovery, Reconnaissance & Attack Surface Mapping
#  Author: Kishore Baskaran (0xk1sh0re)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SUBMAP_VERSION="1.0.0"
INSTALL_DIR="$HOME/.local/share/submap"
VENV_DIR="$INSTALL_DIR/venv"
CONFIG_DIR="$HOME/.config/submap"
BIN_DIR="$HOME/.local/bin"

print_banner() {
cat << 'EOF'
  ____  _   _ ____  __  __    _    ____
 / ___|| | | | __ )|  \/  |  / \  |  _ \
 \___ \| | | |  _ \| |\/| | / _ \ | |_) |
  ___) | |_| | |_) | |  | |/ ___ \|  __/
 |____/ \___/|____/|_|  |_/_/   \_\_|

  Advanced Subdomain Discovery & Attack Surface Mapping
  Created by Kishore Baskaran (0xk1sh0re)  v1.0.0
EOF
}

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}── $* ──${NC}"; }

# ─── Step 1: Check Python ─────────────────────────────────────────────────────
step "Checking Python version"

PYTHON=""
for cmd in python3.12 python3.13 python3.14 python3; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 12 ]; then
            PYTHON="$cmd"
            success "Found Python $VER ($cmd)"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python 3.12+ is required. Install it with: sudo apt install python3.12"
fi

# ─── Step 2: Check system packages ───────────────────────────────────────────
step "Checking system dependencies"

MISSING_PKGS=()
for pkg in curl git build-essential libssl-dev libffi-dev; do
    if ! dpkg -l "$pkg" &>/dev/null 2>&1; then
        MISSING_PKGS+=("$pkg")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    warn "Missing packages: ${MISSING_PKGS[*]}"
    info "Installing missing packages..."
    sudo apt-get install -y "${MISSING_PKGS[@]}" || warn "Could not install some packages — continuing"
else
    success "All system packages present"
fi

# ─── Step 3: Create directories ───────────────────────────────────────────────
step "Creating directories"

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$BIN_DIR" "$CONFIG_DIR/wordlists" "$CONFIG_DIR/resolvers"
success "Directories created"

# ─── Step 4: Virtual environment ─────────────────────────────────────────────
step "Creating Python virtual environment"

if [ -d "$VENV_DIR" ]; then
    warn "Existing virtual environment found — removing"
    rm -rf "$VENV_DIR"
fi

"$PYTHON" -m venv "$VENV_DIR" || error "Failed to create virtual environment"
success "Virtual environment created at $VENV_DIR"

# Activate
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# ─── Step 5: Install Python dependencies ─────────────────────────────────────
step "Installing Python dependencies"

pip install --upgrade pip --quiet
pip install -e "." --quiet || error "Failed to install SUBMAP"
success "Python dependencies installed"

# ─── Step 6: Install SUBMAP CLI wrapper ──────────────────────────────────────
step "Installing SUBMAP CLI command"

WRAPPER="$BIN_DIR/submap"
cat > "$WRAPPER" << EOF
#!/usr/bin/env bash
# SUBMAP CLI wrapper
source "$VENV_DIR/bin/activate"
exec submap "\$@"
EOF
chmod +x "$WRAPPER"

# Ensure ~/.local/bin is in PATH
SHELL_RC=""
if [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
fi

if [ -n "$SHELL_RC" ]; then
    if ! grep -q 'export PATH.*\.local/bin' "$SHELL_RC" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
        info "Added ~/.local/bin to PATH in $SHELL_RC"
    fi
fi

success "SUBMAP CLI installed at $WRAPPER"

# ─── Step 7: Configuration ────────────────────────────────────────────────────
step "Writing default configuration"

cat > "$CONFIG_DIR/config.yaml" << 'YAML'
# SUBMAP Configuration
# Kishore Baskaran (0xk1sh0re)

defaults:
  threads: 10
  timeout: 10
  retries: 2
  rate_limit: 30

dns:
  resolvers:
    - 8.8.8.8
    - 8.8.4.4
    - 1.1.1.1
    - 9.9.9.9

passive_sources:
  - crt.sh
  - hackertarget
  - alienvault
  - urlscan

output:
  directory: results
YAML

success "Configuration written to $CONFIG_DIR/config.yaml"

# ─── Step 8: Check optional external tools ────────────────────────────────────
step "Checking optional external tools"

TOOLS=(subfinder amass findomain dnsx naabu nmap katana gau whatweb gitleaks)
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        success "$tool found"
    else
        warn "$tool not found (optional)"
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo ""
    warn "Optional tools not installed: ${MISSING_TOOLS[*]}"
    info "Install them for enhanced functionality:"
    echo ""
    echo "  # Go-based tools (requires Go 1.21+):"
    echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    echo "  go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    echo "  go install -v github.com/lc/gau/v2/cmd/gau@latest"
    echo ""
    echo "  # Kali Linux packages:"
    echo "  sudo apt install amass nmap -y"
    echo ""
fi

# ─── Step 9: Verify installation ─────────────────────────────────────────────
step "Verifying installation"

if "$WRAPPER" --version &>/dev/null 2>&1; then
    success "SUBMAP installed and working"
else
    # Try direct call via venv
    "$VENV_DIR/bin/submap" --version || error "Installation verification failed"
fi

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  SUBMAP v${SUBMAP_VERSION} installed successfully! ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "  Restart your terminal or run:"
echo "    source ~/.bashrc"
echo ""
echo "  Then use SUBMAP:"
echo "    submap --help"
echo "    submap --version"
echo "    submap -d example.com"
echo "    submap -d example.com --api --leaks -o results/"
echo ""
echo -e "  ${CYAN}Config:${NC} $CONFIG_DIR/config.yaml"
echo -e "  ${CYAN}DB:${NC}     $CONFIG_DIR/scans.db"
echo ""
echo -e "  ${YELLOW}⚠ Use only against authorized targets!${NC}"
echo ""
