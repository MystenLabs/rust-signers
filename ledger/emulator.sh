#!/bin/bash

# Detect container runtime
if command -v podman >/dev/null 2>&1; then
    CONTAINER_CMD="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_CMD="docker"
else
    echo "Error: Neither podman nor docker found."
    exit 1
fi

CONTAINER_NAME="ledger-emulator"

start_emulator() {
    local detached=$1
    local flags="-it"
    
    if [[ "$detached" == "true" ]]; then
        flags="-d"
        echo "Starting emulator in background..."
    else
        echo "Starting emulator..."
    fi

    # pull image
    echo "Pulling image..."
    $CONTAINER_CMD pull ghcr.io/ledgerhq/speculos

    echo "Starting emulator..."
    $CONTAINER_CMD run --rm $flags \
        --name "$CONTAINER_NAME" \
        -v "$PWD/apps:/speculos/apps" \
        -p 5001:5000 \
        -p 9999:9999 \
        ghcr.io/ledgerhq/speculos \
        --seed "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
        --model nanosp \
        --display headless \
        apps/sui.elf
}

stop_emulator() {
    echo "Stopping emulator..."
    $CONTAINER_CMD stop "$CONTAINER_NAME"
}

case "$1" in
    background)
        start_emulator "true"
        ;;
    stop)
        stop_emulator
        ;;
    *)
        start_emulator "false"
        ;;
esac
