#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== SecureFile Vault — Test Suite ==="
echo ""

PASSED=0
FAILED=0

run_test() {
    local test_name="$1"
    local test_bin="$PROJECT_DIR/build/$test_name"

    echo -n "  [$test_name] "

    if [ ! -f "$test_bin" ]; then
        echo "SKIP (binary not found)"
        return
    fi

    if "$test_bin" > /dev/null 2>&1; then
        echo "PASS"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi
}

# Build fixed and tests
echo "[*] Building..."
make fixed 2>&1 | tail -1
make test 2>&1 | tail -1
echo ""

# Run unit tests
echo "[*] Running unit tests..."
run_test "test_auth"
run_test "test_protocol"
run_test "test_file_handler"
run_test "test_security"

echo ""
echo "=== Results ==="
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Some tests FAILED!"
    exit 1
fi

echo ""
echo "All tests passed."
exit 0
