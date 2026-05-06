#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== SecureFile Vault — VULNERABLE Version ==="
echo ""

# Build if needed
if [ ! -f "build/securefile_server" ]; then
    echo "[*] Building vulnerable version..."
    make vulnerable
fi

# Setup data directory
mkdir -p /tmp/securefile_data

echo "[*] Starting server on port ${1:-9000}..."
echo "[*] Data directory: /tmp/securefile_data"
echo "[*] Press Ctrl+C to stop"
echo "[!] WARNING: This version contains deliberate vulnerabilities!"
echo ""

exec ./build/securefile_server \
    -p "${1:-9000}" \
    -d /tmp/securefile_data \
    -c config.ini \
    -l securefile.log
