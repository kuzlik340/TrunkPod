#!/bin/bash
# Colors

set -uo pipefail

ctr=$2
IMAGE_NAME=$1

source base_functions.sh
trap rollback ERR
run_buildah copy "$ctr" configs/supervisord.conf /etc/supervisor/supervisord.conf
run_buildah config \
    --cmd '["/usr/bin/supervisord","-c","/etc/supervisor/supervisord.conf"]' \
    "$ctr"

run_buildah commit "$ctr" "$IMAGE_NAME"
run_buildah rm $ctr
print_success "Build complete: $IMAGE_NAME"