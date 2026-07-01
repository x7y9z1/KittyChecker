#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

WINEPREFIX_DIR="$SCRIPT_DIR/.wine_kitty"
export WINEPREFIX="$WINEPREFIX_DIR"
export WINEARCH=win64

PYTHON_VERSION="3.12.9"
PYTHON_INSTALLER="python-$PYTHON_VERSION-amd64.exe"
PYTHON_URL="https://www.python.org/ftp/python/$PYTHON_VERSION/$PYTHON_INSTALLER"
WINE_PYTHON="$WINEPREFIX_DIR/drive_c/users/$USER/AppData/Local/Programs/Python/Python312/python.exe"

if ! command -v wine &>/dev/null; then
    echo "Wine is not installed. Install it first:"
    echo "  Ubuntu/Debian: sudo apt install wine64"
    echo "  Arch: sudo pacman -S wine"
    echo "  Fedora: sudo dnf install wine"
    exit 1
fi

if [ ! -d "$WINEPREFIX_DIR" ]; then
    echo "Initializing Wine prefix..."
    wineboot -i 2>/dev/null
fi

if [ ! -f "$WINE_PYTHON" ]; then
    echo "Downloading Python $PYTHON_VERSION for Windows..."
    wget -q -O "$SCRIPT_DIR/$PYTHON_INSTALLER" "$PYTHON_URL"
    echo "Installing Python in Wine..."
    wine "$SCRIPT_DIR/$PYTHON_INSTALLER" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 2>/dev/null
    rm -f "$SCRIPT_DIR/$PYTHON_INSTALLER"
fi

echo "Installing PyInstaller in Wine Python..."
wine "$WINE_PYTHON" -m pip install pyinstaller==6.11.1 --quiet 2>/dev/null

echo "Building KittyChecker.exe..."
wine "$WINE_PYTHON" -m PyInstaller \
    --onefile \
    --console \
    --name KittyChecker \
    --noconfirm \
    --clean \
    --icon "$SCRIPT_DIR/image.ico" \
    --hidden-import ctypes.wintypes \
    --hidden-import winreg \
    --hidden-import glob \
    "$SCRIPT_DIR/kitty_checker.py" 2>/dev/null

echo "Cleaning up build artifacts..."
rm -f "$SCRIPT_DIR/KittyChecker.spec"
rm -rf "$SCRIPT_DIR/build"

echo ""
echo "Build complete. Output: $SCRIPT_DIR/dist/KittyChecker.exe"
