#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== SecureFile Vault Build Script ==="
echo ""

# Parse arguments
BUILD_TARGET="${1:-all}"
BUILD_DIR="build"

case "$BUILD_TARGET" in
    vulnerable)
        echo "[*] Building vulnerable version..."
        make vulnerable
        echo "[+] Build complete: $BUILD_DIR/securefile_server"
        ;;

    fixed)
        echo "[*] Building fixed (secure) version..."
        make fixed
        echo "[+] Build complete: $BUILD_DIR/securefile_server_fixed"
        ;;

    vuln-demos)
        echo "[*] Building vulnerability demonstrations..."
        make vuln-demos
        echo "[+] Built vulnerability demos in $BUILD_DIR/"
        ;;

    fixed-demos)
        echo "[*] Building fixed demonstrations..."
        make fixed-demos
        echo "[+] Built fixed demos in $BUILD_DIR/"
        ;;

    test)
        echo "[*] Building tests..."
        make fixed
        make test
        echo "[+] Tests built in $BUILD_DIR/"
        ;;

    all)
        echo "[*] Building all targets..."
        make vulnerable
        make fixed
        make vuln-demos
        make fixed-demos
        echo "[+] All targets built successfully"
        echo ""
        echo "Targets:"
        echo "  $BUILD_DIR/securefile_server        (vulnerable)"
        echo "  $BUILD_DIR/securefile_server_fixed  (fixed)"
        echo "  $BUILD_DIR/vuln_*                   (vuln demos)"
        echo "  $BUILD_DIR/fixed_*                  (fixed demos)"
        ;;

    clean)
        echo "[*] Cleaning..."
        make clean
        echo "[+] Clean complete"
        ;;

    *)
        echo "Usage: $0 {vulnerable|fixed|vuln-demos|fixed-demos|test|all|clean}"
        exit 1
        ;;
esac
