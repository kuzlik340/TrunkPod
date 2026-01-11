#!/bin/bash

set -uo pipefail

timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_DIR="/var/log"
LOG_FILE="/var/log/honeybridge_build_$timestamp.log"

LINK_FILE="$PROJECT_ROOT"/build_services/honeybridge_build_current.log

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
ln -sfn "$LOG_FILE" "$LINK_FILE"
