#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

echo "=== Running Node-Secure-API Client Simulator Verification ==="
cd "$ROOT_DIR"
./node_modules/.bin/tsx "$SCRIPT_DIR/client_simulator.ts"
