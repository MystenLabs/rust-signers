#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STARTED_EMULATOR=0

# shellcheck disable=SC2329
cleanup() {
    if [[ "$STARTED_EMULATOR" == "1" ]]; then
        echo "Stopping Ledger emulator..."
        (cd "$ROOT_DIR/ledger" && ./emulator.sh stop) >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker not found." >&2
    exit 1
fi

if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "ledger-emulator"; then
    echo "Using already-running Ledger emulator container: ledger-emulator"
else
    (cd "$ROOT_DIR/ledger" && ./emulator.sh background)
    STARTED_EMULATOR=1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required to wait for the Ledger emulator." >&2
    exit 1
fi

echo "Waiting for Ledger emulator at http://127.0.0.1:5001/events..."
for _ in {1..60}; do
    if curl --silent --fail --max-time 1 "http://127.0.0.1:5001/events" >/dev/null; then
        echo "Ledger emulator is ready."
        export RUST_TEST_THREADS=1
        echo "Running Ledger signer tests..."
        cargo test -p ledger-signer "$@" -- --nocapture
        exit
    fi
    sleep 1
done

echo "Error: Ledger emulator did not become ready after 60s." >&2
exit 1
