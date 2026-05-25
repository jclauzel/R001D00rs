#!/bin/bash
# Run tcp_geo_map.py with the venv Python under sudo.
# Scapy's L2 sniffer requires root (CAP_NET_RAW).
#
# Usage: ./run_as_root.sh [args...]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate the venv Python.
# Checks: repo dir itself (bin/python3), then .venv, venv, env sub-dirs.
VENV_PYTHON=""
for CANDIDATE in "$SCRIPT_DIR/bin/python3" \
                 "$SCRIPT_DIR/.venv/bin/python3" \
                 "$SCRIPT_DIR/venv/bin/python3" \
                 "$SCRIPT_DIR/env/bin/python3"; do
    if [ -x "$CANDIDATE" ]; then
        VENV_PYTHON="$CANDIDATE"
        break
    fi
done

if [ -z "$VENV_PYTHON" ]; then
    echo "ERROR: Could not find a venv Python. Tried:"
    echo "  $SCRIPT_DIR/bin/python3"
    echo "  $SCRIPT_DIR/{.venv,venv,env}/bin/python3"
    echo "Activate your venv first, then run: sudo \$(which python3) tcp_geo_map.py"
    exit 1
fi

VENV_ROOT="$(dirname "$(dirname "$VENV_PYTHON")")"
SITE_PACKAGES="$("$VENV_PYTHON" -c "import site; print(site.getsitepackages()[0])" 2>/dev/null)"

echo "Using Python : $VENV_PYTHON"
echo "Site-packages: $SITE_PACKAGES"

exec sudo PYTHONPATH="$SITE_PACKAGES" "$VENV_PYTHON" "$SCRIPT_DIR/tcp_geo_map.py" "$@"
