#!/bin/bash
# Security Compliance Platform (SCP) - Installer
# Usage: curl -sSL https://raw.githubusercontent.com/maxwellsarpong/Code-Security-platform/main/install.sh | bash

set -e

# --- Configuration ---
REPO_URL="https://github.com/maxwellsarpong/Code-Security-platform.git"
INSTALL_DIR="$HOME/.scp-cli"
BIN_DIR="$HOME/.local/bin"
BINARY_NAME="scp-cli"

echo "Starting Security Compliance Platform CLI Installation..."

# --- Prerequisites Check ---
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed. Please install Python 3.8+ to continue."
    exit 1
fi

# --- Setup Directory ---
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# --- Virtual Environment (Optional but Recommended) ---
echo "Setting up isolated environment in $INSTALL_DIR..."
python3 -m venv venv
source venv/bin/activate

# --- Installation ---
echo "Installing scp-cli from GitHub..."
pip install --upgrade pip
pip install "git+$REPO_URL"

# --- Create Wrapper Script ---
echo "Creating executable wrapper..."
mkdir -p "$BIN_DIR"

cat <<EOF > "$BIN_DIR/$BINARY_NAME"
#!/bin/bash
source "$INSTALL_DIR/venv/bin/activate"
exec python -m app.cli "\$@"
EOF

chmod +x "$BIN_DIR/$BINARY_NAME"

# --- Update PATH ---
SHELL_RC=""
case "$SHELL" in
    */bash) SHELL_RC="$HOME/.bashrc" ;;
    */zsh) SHELL_RC="$HOME/.zshrc" ;;
    *) echo "Unknown shell. Please manually add $BIN_DIR to your PATH." ;;
esac

if [ -n "$SHELL_RC" ]; then
    if ! grep -q "$BIN_DIR" "$SHELL_RC"; then
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$SHELL_RC"
        echo "Added $BIN_DIR to $SHELL_RC"
    fi
fi

echo "---------------------------------------------------------------"
echo "Success! scp-cli has been installed."
echo "Please restart your terminal or run: source $SHELL_RC"
echo "Then run: scp-cli --help to get started."
echo "---------------------------------------------------------------"
