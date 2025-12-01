#!/bin/bash
# Colors

set -euo pipefail

ctr=$2
IMAGE_NAME=$1

source base_functions.sh
trap rollback ERR

run_buildah config \
    --cmd '["/usr/bin/supervisord","-c","/etc/supervisor/supervisord.conf"]' \
    "$ctr"

run_buildah commit "$ctr" "$IMAGE_NAME"

echo "[+] Build complete: $IMAGE_NAME"