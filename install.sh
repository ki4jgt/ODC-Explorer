#!/bin/sh
# Install ODC Explorer for the current user on Linux (no root needed).
#
#   ./install.sh               install or update
#   ./install.sh --uninstall   remove the app, launcher and icons (keeps your data)
#   ./install.sh --purge       remove everything, including the block cache and node identity
#
# What goes where (XDG locations):
#   ~/.local/share/odc-explorer/app        the explorer and basilisk-ipfs
#   ~/.local/share/odc-explorer/venv       private Python environment with Flask
#   ~/.local/share/odc-explorer/launch.sh  start-or-open / stop / status helper
#   ~/.local/bin/odc-explorer              run the server in a terminal
#   ~/.local/bin/odc-explorer-launch       the launcher helper, from a terminal
#   ~/.local/share/applications/odc-explorer.desktop
#   ~/.local/share/icons/hicolor/*/apps/odc-explorer.{png,svg}
#   ~/.config/odc-explorer/config          web port and extra options for the launcher
#   ~/.local/state/odc-explorer/           server log and pid file
#   ~/.odc-explorer/                       data: block cache, node identity (kept on uninstall)

set -eu

APP_ID=odc-explorer
APP_NAME="ODC Explorer"
SRC=$(cd "$(dirname "$0")" && pwd)

DATA_HOME=${XDG_DATA_HOME:-$HOME/.local/share}
CONFIG_HOME=${XDG_CONFIG_HOME:-$HOME/.config}
STATE_HOME=${XDG_STATE_HOME:-$HOME/.local/state}
BIN_DIR=$HOME/.local/bin

PREFIX=$DATA_HOME/$APP_ID
APP_DIR=$PREFIX/app
VENV=$PREFIX/venv
LAUNCH=$PREFIX/launch.sh
DESKTOP_FILE=$DATA_HOME/applications/$APP_ID.desktop
ICON_ROOT=$DATA_HOME/icons/hicolor
CONFIG_DIR=$CONFIG_HOME/$APP_ID
STATE_DIR=$STATE_HOME/$APP_ID
USER_DATA=$HOME/.odc-explorer
ICON_SIZES="16 32 48 64 128 256 512"

say()  { printf '%s\n' "$*"; }
step() { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

refresh_desktop_caches() {
    command -v update-desktop-database >/dev/null 2>&1 &&
        update-desktop-database -q "$DATA_HOME/applications" 2>/dev/null || true
    if command -v gtk-update-icon-cache >/dev/null 2>&1 && [ -d "$ICON_ROOT" ]; then
        gtk-update-icon-cache -q -f -t "$ICON_ROOT" 2>/dev/null || true
    fi
}

uninstall() {
    purge=$1
    step "Stopping ODC Explorer if it is running"
    [ -x "$LAUNCH" ] && "$LAUNCH" stop >/dev/null 2>&1 || true

    step "Removing the app, launcher and icons"
    rm -rf "$PREFIX"
    rm -f "$BIN_DIR/odc-explorer" "$BIN_DIR/odc-explorer-launch" "$DESKTOP_FILE"
    for s in $ICON_SIZES; do rm -f "$ICON_ROOT/${s}x${s}/apps/$APP_ID.png"; done
    rm -f "$ICON_ROOT/scalable/apps/$APP_ID.svg"
    refresh_desktop_caches

    if [ "$purge" = yes ]; then
        step "Removing data, settings and logs"
        rm -rf "$USER_DATA" "$CONFIG_DIR" "$STATE_DIR"
    else
        say "Kept your data in $USER_DATA and settings in $CONFIG_DIR (use --purge to remove them)."
    fi
    say "$APP_NAME has been uninstalled."
}

case "${1:-}" in
    --uninstall) uninstall no; exit 0 ;;
    --purge)     uninstall yes; exit 0 ;;
    -h|--help)   sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    "")          ;;
    *)           die "unknown option: $1 (try --help)" ;;
esac

# ---- checks ------------------------------------------------------------------
[ "$(uname -s)" = Linux ] || die "this installer is for Linux"
[ -d "$SRC/odc_explorer" ] && [ -d "$SRC/basilisk_ipfs" ] ||
    die "run this script from the ODCclient folder (odc_explorer/ and basilisk_ipfs/ not found next to it)"
command -v python3 >/dev/null 2>&1 || die "python3 is not installed"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' ||
    die "Python 3.9 or newer is required (found $(python3 -V 2>&1))"

# ---- files -------------------------------------------------------------------
[ -x "$LAUNCH" ] && "$LAUNCH" stop >/dev/null 2>&1 || true     # updating a running copy

step "Copying the app to $APP_DIR"
mkdir -p "$PREFIX"
rm -rf "$APP_DIR.new" && mkdir -p "$APP_DIR.new"
cp -R "$SRC/odc_explorer" "$SRC/basilisk_ipfs" "$SRC/requirements.txt" "$APP_DIR.new/"
[ -f "$SRC/odc-chain-spec.md" ] && cp "$SRC/odc-chain-spec.md" "$APP_DIR.new/"
find "$APP_DIR.new" -name __pycache__ -type d -prune -exec rm -rf {} +
rm -rf "$APP_DIR"
mv "$APP_DIR.new" "$APP_DIR"

# ---- Python environment ----------------------------------------------------------
# A private venv keeps Flask off the system Python (PEP 668 distros refuse
# `pip install --user`). --system-site-packages lets a distro-packaged Flask
# (python3-flask) satisfy the requirement without downloading anything.
step "Setting up the Python environment"
PY=
if python3 -m venv --system-site-packages "$VENV" >/dev/null 2>&1; then
    PY=$VENV/bin/python
    if ! "$PY" -c 'import flask' 2>/dev/null; then
        say "    installing Flask into $VENV"
        "$PY" -m pip install --quiet --disable-pip-version-check -r "$APP_DIR/requirements.txt" ||
            die "could not install Flask. Check your internet connection, or install your distro's python3-flask package and run this again."
    fi
else
    rm -rf "$VENV"
    if python3 -c 'import flask' 2>/dev/null; then
        warn "python3 -m venv is unavailable; using the system Python, which already has Flask"
        PY=$(command -v python3)
    else
        die "couldn't create a Python virtual environment. Install the venv module and Flask, then run this again:
    Debian/Ubuntu: sudo apt install python3-venv     (or: sudo apt install python3-flask)
    Fedora:        sudo dnf install python3-flask
    Arch:          sudo pacman -S python-flask"
    fi
fi
"$PY" -c 'import flask' || die "Flask is still not importable with $PY"

# ---- commands ------------------------------------------------------------------------
step "Installing commands in $BIN_DIR"
mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$STATE_DIR"

cat > "$BIN_DIR/odc-explorer" <<EOF
#!/bin/sh
# Run the ODC Explorer server in this terminal. Options: odc-explorer --help
PYTHONPATH="$APP_DIR\${PYTHONPATH:+:\$PYTHONPATH}" exec "$PY" -m odc_explorer "\$@"
EOF
chmod 755 "$BIN_DIR/odc-explorer"

if [ ! -f "$CONFIG_DIR/config" ]; then
    cat > "$CONFIG_DIR/config" <<'EOF'
# Settings used by the ODC Explorer launcher (odc-explorer-launch / the app menu).
# Web UI port (the IPFS node picks its own port):
PORT=8181
# Any other options for odc-explorer, e.g. EXTRA_ARGS="--repo /data/odc"
EXTRA_ARGS=""
EOF
fi

cat > "$LAUNCH" <<EOF
#!/bin/sh
# ODC Explorer launcher: start the server in the background if needed, then
# open it in the browser.   Usage: launch.sh [start|open|stop|restart|status|log]
APP_NAME="$APP_NAME"
SERVER="$BIN_DIR/odc-explorer"
PY="$PY"
CONFIG="$CONFIG_DIR/config"
STATE_DIR="$STATE_DIR"
ICON="$APP_ID"
EOF
cat >> "$LAUNCH" <<'EOF'
PIDFILE=$STATE_DIR/server.pid
LOG=$STATE_DIR/server.log

PORT=8181
EXTRA_ARGS=""
[ -f "$CONFIG" ] && . "$CONFIG"
URL="http://127.0.0.1:$PORT/"
mkdir -p "$STATE_DIR"

notify() {   # desktop notification when available, otherwise stderr
    if command -v notify-send >/dev/null 2>&1; then
        notify-send -i "$ICON" "$APP_NAME" "$1" 2>/dev/null || printf '%s\n' "$1" >&2
    else
        printf '%s\n' "$1" >&2
    fi
}

running() {
    [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

responding() {
    "$PY" -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=2)' "$URL" 2>/dev/null
}

open_browser() {
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$URL" >/dev/null 2>&1 &
    else
        printf 'Open %s in your browser.\n' "$URL"
    fi
}

start() {
    if ! running; then
        if responding; then
            notify "Port $PORT is already used by another program. Change PORT in $CONFIG."
            exit 1
        fi
        # setsid: no controlling terminal, so closing a terminal won't stop it.
        printf '\n--- %s starting %s\n' "$(date '+%F %T')" "$APP_NAME" >> "$LOG"
        # shellcheck disable=SC2086
        setsid "$SERVER" --port "$PORT" $EXTRA_ARGS >> "$LOG" 2>&1 < /dev/null &
        echo $! > "$PIDFILE"
    fi
    # Wait for it to answer (also covers a second click while it's still starting).
    i=0
    while [ $i -lt 60 ]; do
        if responding; then return 0; fi
        if ! running; then
            rm -f "$PIDFILE"
            notify "Couldn't start: $(tail -n 3 "$LOG" | tr '\n' ' ')"
            exit 1
        fi
        sleep 0.5; i=$((i + 1))
    done
    notify "Still starting; opening the browser anyway. Log: $LOG"
}

stop() {
    if ! running; then
        rm -f "$PIDFILE"
        echo "$APP_NAME is not running."
        return 0
    fi
    pid=$(cat "$PIDFILE")
    kill -TERM "$pid" 2>/dev/null || true
    i=0
    # the explorer allows its IPFS node up to 10 s to stop cleanly
    while kill -0 "$pid" 2>/dev/null && [ $i -lt 60 ]; do sleep 0.25; i=$((i + 1)); done
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "$APP_NAME stopped."
}

case "${1:-start}" in
    start)   start; open_browser ;;
    open)    open_browser ;;
    stop)    stop ;;
    restart) stop; start; open_browser ;;
    status)  if running; then echo "running (pid $(cat "$PIDFILE")) at $URL"; else echo "not running"; exit 3; fi ;;
    log)     if command -v xdg-open >/dev/null 2>&1; then xdg-open "$LOG"; else ${PAGER:-less} "$LOG"; fi ;;
    *)       echo "usage: $0 [start|open|stop|restart|status|log]" >&2; exit 2 ;;
esac
EOF
chmod 755 "$LAUNCH"
ln -sf "$LAUNCH" "$BIN_DIR/odc-explorer-launch"

# ---- icons and the desktop launcher --------------------------------------------------
step "Installing the icon and the app-menu launcher"
ICONS=$APP_DIR/odc_explorer/static/icons
for s in $ICON_SIZES; do
    if [ -f "$ICONS/$APP_ID-$s.png" ]; then
        mkdir -p "$ICON_ROOT/${s}x${s}/apps"
        cp "$ICONS/$APP_ID-$s.png" "$ICON_ROOT/${s}x${s}/apps/$APP_ID.png"
    fi
done
mkdir -p "$ICON_ROOT/scalable/apps"
cp "$ICONS/$APP_ID.svg" "$ICON_ROOT/scalable/apps/$APP_ID.svg"

mkdir -p "$(dirname "$DESKTOP_FILE")"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.5
Name=$APP_NAME
GenericName=Domain Catalog Browser
Comment=Browse the Open Domain Catalog, read straight from IPFS
Exec="$LAUNCH" start
TryExec=$LAUNCH
Icon=$APP_ID
Terminal=false
StartupNotify=false
Categories=Network;
Keywords=IPFS;catalog;domains;library;directory;
Actions=open;stop;log;

[Desktop Action open]
Name=Open in Browser
Exec="$LAUNCH" start

[Desktop Action stop]
Name=Stop $APP_NAME
Exec="$LAUNCH" stop

[Desktop Action log]
Name=Show Server Log
Exec="$LAUNCH" log
EOF
chmod 644 "$DESKTOP_FILE"
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$DESKTOP_FILE" || warn "the launcher file has validation warnings (it should still work)"
fi
refresh_desktop_caches

# ---- done ----------------------------------------------------------------------------
say ""
say "$APP_NAME is installed."
say "  * Open it from your applications menu (Network), or run: odc-explorer-launch"
say "  * Stop it from the launcher's right-click menu, or run:  odc-explorer-launch stop"
say "  * Run it in a terminal instead:                          odc-explorer --open"
say "  * Port and options: $CONFIG_DIR/config"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) warn "$BIN_DIR is not on your PATH; the menu launcher still works, but add it to use the commands in a terminal." ;;
esac
