#!/bin/bash
# Run tcp_geo_map.py with the venv Python under sudo.
# Scapy's L2 sniffer requires root (CAP_NET_RAW).
#
# Usage: ./run_as_root.sh [args...]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate the venv Python — check common venv directory names.
for VENV_DIR in .venv venv env; do
    VENV_PYTHON="$SCRIPT_DIR/$VENV_DIR/bin/python3"
    if [ -x "$VENV_PYTHON" ]; then
        break
    fi
    VENV_PYTHON=""
done

if [ -z "$VENV_PYTHON" ]; then
    echo "ERROR: Could not find a venv Python under $SCRIPT_DIR (.venv, venv, env)."
    echo "       Activate your venv first, then re-run: sudo \$(which python3) tcp_geo_map.py"
    exit 1
fi

echo "Using Python: $VENV_PYTHON"
exec sudo "$VENV_PYTHON" "$SCRIPT_DIR/tcp_geo_map.py" "$@"
