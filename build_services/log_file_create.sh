#!/bin/bash

set -uo pipefail

timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_DIR="/var/log"
LOG_FILE="/var/log/honeybridge_build_$timestamp.log"

SCRIPT_DIR="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
LINK_DIR="$SCRIPT_DIR"/build_services
CURRENT_LINK="$LINK_DIR/honeybridge_build_current.log"

mkdir -p "$LOG_DIR"
mkdir -p "$LINK_DIR"

touch "/var/log/honeybridge_build_$timestamp.log"
ln -sfn "$LOG_FILE" "$CURRENT_LINK"
