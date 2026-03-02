#!/bin/bash

set -uo pipefail

timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_DIR="/var/log"
LOG_FILE="/var/log/trunkpod_build_$timestamp.log"

LINK_FILE="$PROJECT_ROOT"/build_services/trunkpod_build_current.log

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
ln -sfn "$LOG_FILE" "$LINK_FILE"
