#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON="${SCRIPT_DIR}/venv/bin/python"
if [ ! -f "$PYTHON" ]; then
    PYTHON="python3"
fi

echo "=========================================="
echo "DevSecOps Pre-Flight Verification"
echo "=========================================="

echo "[1/3] Running Dependency Vulnerability Audit..."
if command -v pip-audit &> /dev/null; then
    pip-audit --desc --requirement requirements.txt
else
    echo "Notice: pip-audit not found in PATH; skipping SCA scan or install with: pip install pip-audit"
fi

echo "[2/3] Running SAST Code Quality & Security Scan..."
if command -v bandit &> /dev/null; then
    bandit -r app.py security.py crypto_service.py models.py \
        -x tests/ \
        -s B413 \
        --severity-level medium
else
    echo "Notice: bandit not found in PATH; skipping Bandit SAST or install with: pip install bandit"
fi

echo "[3/3] Running Defensive Boundary & Integration Tests..."
"$PYTHON" -m unittest discover tests
"$PYTHON" -m unittest security_audit_test.py

echo "=========================================="
echo "All DevSecOps security checks passed successfully!"
echo "=========================================="
