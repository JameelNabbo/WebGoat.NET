#!/bin/bash
# =================================================================
# SAST Offline Scanner - Test Runner
# =================================================================
# Runs all pytest test suites with verbose output.
#
# Usage:
#   ./run_tests.sh              # Run all tests
#   ./run_tests.sh scanners     # Run scanner tests only
#   ./run_tests.sh ui           # Run UI tests only
# =================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "============================================================"
echo "  SAST Offline Scanner - Test Suite"
echo "  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""

# Check dependencies
echo "[*] Checking dependencies..."
python3 -c "import pytest" 2>/dev/null || {
    echo "  Installing pytest..."
    pip3 install --user pytest requests 2>&1 | tail -1
}
python3 -c "import requests" 2>/dev/null || {
    echo "  Installing requests..."
    pip3 install --user requests 2>&1 | tail -1
}
echo "  Dependencies OK."
echo ""

# Determine which tests to run
TESTS_TO_RUN="tests/"
if [ "$1" = "scanners" ]; then
    TESTS_TO_RUN="tests/test_scanners.py"
    echo "[*] Running scanner tests only..."
elif [ "$1" = "ui" ]; then
    TESTS_TO_RUN="tests/test_ui.py"
    echo "[*] Running UI tests only..."
else
    echo "[*] Running all tests..."
fi

echo ""

# Run tests
python3 -m pytest $TESTS_TO_RUN -v --tb=short -x 2>&1

EXIT_CODE=$?

echo ""
echo "============================================================"
if [ $EXIT_CODE -eq 0 ]; then
    echo "  ALL TESTS PASSED"
else
    echo "  SOME TESTS FAILED (exit code: $EXIT_CODE)"
fi
echo "============================================================"

exit $EXIT_CODE
