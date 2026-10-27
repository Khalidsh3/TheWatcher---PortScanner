#!/usr/bin/env bash
# setup.sh — install thewatcher so `thewatcher` runs from any directory.
#
# Usage:
#   ./setup.sh               # auto-detect best method (pipx if available, else symlink)
#   ./setup.sh --symlink     # symlink to ~/.local/bin (no privileges, no packaging)
#   ./setup.sh --pipx        # pipx install (isolated env, needs pipx)
#   ./setup.sh --pip         # pip --user install (user site-packages)
#   ./setup.sh --uninstall   # remove whichever method was used
#
# No sudo required. Everything installs under $HOME.
set -euo pipefail

SCRIPT_NAME="thewatcher"
PY_FILE="thewatcher.py"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_BIN="$HOME/.local/bin"

log() { printf '[setup] %s\n' "$*"; }
die() { printf '[setup] error: %s\n' "$*" >&2; exit 1; }

[[ -f "$SRC_DIR/$PY_FILE" ]] || die "$PY_FILE not found in $SRC_DIR"

find_python() {
    local c
    for c in python3 python; do
        if command -v "$c" >/dev/null 2>&1; then
            if "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)' 2>/dev/null; then
                echo "$c"
                return 0
            fi
        fi
    done
    return 1
}

PY="$(find_python)" || die "Python 3.9+ is required (install: apt install python3 or equivalent)"
log "using python: $(command -v "$PY")"

install_symlink() {
    log "installing via symlink -> $LOCAL_BIN/$SCRIPT_NAME"
    mkdir -p "$LOCAL_BIN"
    chmod +x "$SRC_DIR/$PY_FILE"
    local dst="$LOCAL_BIN/$SCRIPT_NAME"
    if [[ -e "$dst" && ! -L "$dst" ]]; then
        die "$dst exists and is not a symlink (remove it manually first)"
    fi
    ln -sf "$SRC_DIR/$PY_FILE" "$dst"
    log "created: $dst -> $SRC_DIR/$PY_FILE"
}

install_pipx() {
    command -v pipx >/dev/null 2>&1 || die "pipx not found (install: python3 -m pip install --user pipx)"
    log "installing via pipx"
    ( cd "$SRC_DIR" && pipx install --force . )
}

install_pip() {
    log "installing via pip --user"
    ( cd "$SRC_DIR" && "$PY" -m pip install --user --force-reinstall --quiet . )
}

uninstall_all() {
    log "uninstalling"
    local dst="$LOCAL_BIN/$SCRIPT_NAME"
    if [[ -L "$dst" ]]; then
        rm -f "$dst"
        log "removed symlink $dst"
    fi
    if command -v pipx >/dev/null 2>&1; then
        if pipx list --short 2>/dev/null | grep -q "^$SCRIPT_NAME"; then
            pipx uninstall "$SCRIPT_NAME" || true
            log "removed pipx package"
        fi
    fi
    if "$PY" -m pip show "$SCRIPT_NAME" >/dev/null 2>&1; then
        "$PY" -m pip uninstall -y "$SCRIPT_NAME" >/dev/null 2>&1 || true
        log "removed pip package"
    fi
    log "done"
}

check_path() {
    case ":$PATH:" in
        *":$LOCAL_BIN:"*) return 0 ;;
    esac
    log "note: $LOCAL_BIN is not on your PATH"
    log "add this line to ~/.bashrc or ~/.zshrc:"
    log "  export PATH=\"$LOCAL_BIN:\$PATH\""
    log "then reload: source ~/.bashrc"
}

verify() {
    hash -r 2>/dev/null || true
    if command -v "$SCRIPT_NAME" >/dev/null 2>&1; then
        log "OK: $SCRIPT_NAME is on PATH"
        "$SCRIPT_NAME" --version 2>/dev/null || true
    else
        log "installed, but $SCRIPT_NAME not found on PATH yet"
        log "run: hash -r   (or open a new terminal)"
    fi
}

case "${1:-auto}" in
    auto)
        if command -v pipx >/dev/null 2>&1; then
            install_pipx
        else
            install_symlink
        fi
        check_path
        verify
        ;;
    --symlink|symlink)
        install_symlink
        check_path
        verify
        ;;
    --pipx|pipx)
        install_pipx
        check_path
        verify
        ;;
    --pip|pip)
        install_pip
        check_path
        verify
        ;;
    --uninstall|uninstall)
        uninstall_all
        ;;
    -h|--help|help)
        sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
        ;;
    *)
        die "unknown argument: $1 (try --help)"
        ;;
esac