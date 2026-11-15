#!/usr/bin/env bash
# ==============================================================================
#  ✻ Asterisk - Autonomous Pre-Production Code Defense Harness
#  Automated Installation Script with OS Auto-Detection & Symlink Creation
# ==============================================================================

set -e

# ANSI Color codes
BOLD="\033[1m"
GREEN="\033[38;2;120;255;120m"
CYAN="\033[38;2;80;200;255m"
YELLOW="\033[38;2;255;200;80m"
RED="\033[38;2;255;100;100m"
MUTED="\033[38;2;140;140;140m"
RESET="\033[0m"

log_info()    { echo -e " ${CYAN}ℹ${RESET}  ${BOLD}$1${RESET}"; }
log_ok()      { echo -e " ${GREEN}✓${RESET}  $1"; }
log_warn()    { echo -e " ${YELLOW}⚠${RESET}  $1"; }
log_error()   { echo -e " ${RED}✖${RESET}  $1"; }
log_step()    { echo -e "\n${BOLD}${CYAN}==>${RESET} ${BOLD}$1${RESET}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}"
cat << "EOF"
                   .============.                  
                   .============.                  
                   .====....====.                  
       ....        .====.  .====.        ....      
       .====:..    .====.  .====.    ..:====.      
     ..========:....====.  .====....:========..    
    ..====--======-:====.  .====:-======--====..   
   ..====:....======**==.  .==**======....:====..  
  .:=====:..  ...-==*##*.  .*##*==-...  ..:=====:. 
  ..-=======:..  ...=##*.  .*##=...  ..:=======-.. 
     ..:=======:...  ..-.  .-..  ...:=======:..    
        ..:======*=...        ...=*======:..       
           ..:*######+.      .+######*:..          
        ..:-====+*+:..        ..:+*+=====:..       
     ..:=======-...  ..-.  .-... ...-=======:..    
  ..:=======:..  ...=##*.  .*##=...  ..:=======:.. 
  .:=====:..  ...-==*##*.  .*##*==-...  ..:=====:. 
   ..====:....-=====**+=.  .=+**=====-....:====:.  
    ..====--======-:====.  .====:-======--====..   
     ..========-.. .====.  .====....-========..    
       .====:..    .====.  .====.    ..:====.      
       ....        .====.  .====.        ....      
                   .====....====.                  
                   .============.                  
                   .============.                  
EOF
echo -e "${RESET}"
echo -e "${BOLD} ✻ Asterisk Installer${RESET} ${MUTED}:: Autonomous Code Defense Harness${RESET}"
echo -e "${MUTED} ------------------------------------------------------------${RESET}"

# 1. Detect Operating System & Architecture
log_step "Detecting Operating System and Architecture..."

OS="$(uname -s)"
ARCH="$(uname -m)"
DISTRO="unknown"

case "$OS" in
    Linux*)
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO="${ID:-unknown}"
        elif type lsb_release >/dev/null 2>&1; then
            DISTRO="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
        else
            DISTRO="generic-linux"
        fi
        OS_NAME="Linux ($DISTRO)"
        ;;
    Darwin*)
        OS_NAME="macOS"
        DISTRO="macos"
        ;;
    *)
        OS_NAME="Unsupported ($OS)"
        ;;
esac

log_ok "Platform: ${BOLD}${OS_NAME}${RESET} [arch: ${ARCH}]"

# 2. Check and Install Native Build Dependencies
log_step "Checking native C/C++ compiler and SSL build tools..."

SUDO_CMD=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO_CMD="sudo"
    fi
fi

install_deps() {
    case "$DISTRO" in
        ubuntu|debian|kali|pop|mint|elementary)
            log_info "Detected Debian/Ubuntu family. Checking build-essential, pkg-config, libssl-dev, curl..."
            $SUDO_CMD apt-get update -y
            $SUDO_CMD apt-get install -y build-essential pkg-config libssl-dev curl git
            ;;
        arch|manjaro|endeavouros)
            log_info "Detected Arch Linux family. Checking base-devel, pkgconf, openssl, curl..."
            $SUDO_CMD pacman -S --needed --noconfirm base-devel pkgconf openssl curl git
            ;;
        fedora|rhel|centos|rocky|almalinux)
            log_info "Detected RedHat/Fedora family. Checking gcc, make, pkgconfig, openssl-devel, curl..."
            $SUDO_CMD dnf install -y gcc gcc-c++ make pkgconfig openssl-devel curl git
            ;;
        opensuse*|suse)
            log_info "Detected openSUSE family. Checking devel_basis, libopenssl-devel, pkg-config, curl..."
            $SUDO_CMD zypper install -y -t pattern devel_basis
            $SUDO_CMD zypper install -y libopenssl-devel pkg-config curl git
            ;;
        alpine)
            log_info "Detected Alpine Linux. Checking build-base, pkgconf, openssl-dev, curl..."
            $SUDO_CMD apk add --no-cache build-base pkgconf openssl-dev curl git bash
            ;;
        macos)
            log_info "Detected macOS. Checking Xcode Command Line Tools..."
            if ! xcode-select -p >/dev/null 2>&1; then
                log_info "Installing Xcode Command Line Tools..."
                xcode-select --install
            fi
            ;;
        *)
            log_warn "Unrecognized or generic distro ($DISTRO). Assuming standard build tools are present."
            ;;
    esac
}

# Only invoke package manager if essential tools are missing
if ! command -v cc >/dev/null 2>&1 || ! command -v pkg-config >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    log_info "Missing native compilation dependencies. Auto-installing..."
    install_deps
else
    log_ok "C compiler, pkg-config, and curl detected."
fi

# 3. Check and Install Rust Toolchain
log_step "Checking Rust & Cargo toolchain..."

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustc >/dev/null 2>&1; then
    log_info "Rust toolchain not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    log_ok "Rust installed: $(rustc --version)"
else
    log_ok "Rust toolchain detected: $(rustc --version)"
fi

# 4. Compile Release Binary
log_step "Compiling Asterisk release binary..."

cargo build --release
RELEASE_BIN="$SCRIPT_DIR/target/release/asterisk"

if [ ! -f "$RELEASE_BIN" ]; then
    log_error "Compilation failed: $RELEASE_BIN was not generated."
    exit 1
fi

log_ok "Compilation successful: $(du -h "$RELEASE_BIN" | cut -f1) binary generated."

# 5. Create Symlinks and Configure PATH
log_step "Creating symlinks and configuring environment..."

USER_BIN_DIR="$HOME/.local/bin"
mkdir -p "$USER_BIN_DIR"

USER_SYMLINK="$USER_BIN_DIR/asterisk"
ln -sf "$RELEASE_BIN" "$USER_SYMLINK"
log_ok "Symlink created: ${BOLD}$USER_SYMLINK${RESET} -> $RELEASE_BIN"

# Attempt system-wide symlink if privileges permit
SYSTEM_BIN_DIR="/usr/local/bin"
if [ -w "$SYSTEM_BIN_DIR" ]; then
    ln -sf "$RELEASE_BIN" "$SYSTEM_BIN_DIR/asterisk"
    log_ok "System symlink created: ${BOLD}$SYSTEM_BIN_DIR/asterisk${RESET} -> $RELEASE_BIN"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    sudo ln -sf "$RELEASE_BIN" "$SYSTEM_BIN_DIR/asterisk" 2>/dev/null
    log_ok "System symlink created: ${BOLD}$SYSTEM_BIN_DIR/asterisk${RESET} -> $RELEASE_BIN"
else
    log_info "User symlink active at ${BOLD}$USER_SYMLINK${RESET} (system-wide symlink can be created with: ${MUTED}sudo ln -sf $RELEASE_BIN $SYSTEM_BIN_DIR/asterisk${RESET})."
fi

# Ensure ~/.local/bin is in PATH in shell config files
if [[ ":$PATH:" != *":$USER_BIN_DIR:"* ]]; then
    log_info "Adding $USER_BIN_DIR to shell configuration files..."
    
    PATH_EXPORT="export PATH=\"\$HOME/.local/bin:\$PATH\""
    
    if [ -f "$HOME/.bashrc" ] && ! grep -q ".local/bin" "$HOME/.bashrc"; then
        echo -e "\n# Asterisk CLI path\n$PATH_EXPORT" >> "$HOME/.bashrc"
        log_ok "Updated ~/.bashrc"
    fi
    
    if [ -f "$HOME/.zshrc" ] && ! grep -q ".local/bin" "$HOME/.zshrc"; then
        echo -e "\n# Asterisk CLI path\n$PATH_EXPORT" >> "$HOME/.zshrc"
        log_ok "Updated ~/.zshrc"
    fi
fi

# 6. Verification
log_step "Verifying Asterisk installation..."

if "$RELEASE_BIN" --help >/dev/null 2>&1; then
    log_ok "Asterisk CLI verification passed."
else
    log_error "CLI verification test failed."
    exit 1
fi

echo -e "\n${GREEN}${BOLD}✓ Asterisk has been successfully installed!${RESET}\n"
echo -e "You can now run ${BOLD}asterisk${RESET} from any terminal:"
echo -e "  ${CYAN}asterisk${RESET}                 ${MUTED}Launch interactive TUI workspace${RESET}"
echo -e "  ${CYAN}asterisk /path/to/repo${RESET}   ${MUTED}Audit a specific codebase${RESET}"
echo -e "  ${CYAN}asterisk --ci [path]${RESET}     ${MUTED}Run in headless CI/CD mode${RESET}"
echo -e "  ${CYAN}asterisk --help${RESET}          ${MUTED}Show available flags and usage${RESET}"
echo ""
if [[ ":$PATH:" != *":$USER_BIN_DIR:"* ]]; then
    echo -e "${YELLOW}Note:${RESET} If 'asterisk' is not found immediately in your current terminal session, run:"
    echo -e "  ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}  or open a new terminal window."
    echo ""
fi
