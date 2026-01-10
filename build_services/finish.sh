#!/bin/bash
# Colors

set -uo pipefail

ctr="$2"
IMAGE_NAME="$1"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR"/base_functions.sh
trap rollback ERR
run_buildah copy "$ctr" "$SCRIPT_DIR"/configs/supervisord.conf /etc/supervisor/supervisord.conf
run_buildah config \
    --cmd '["/usr/bin/supervisord","-c","/etc/supervisor/supervisord.conf"]' \
    "$ctr"
if podman image exists localhost/"$IMAGE_NAME":latest; then
    podman image rm -f localhost/"$IMAGE_NAME":latest > /dev/null
fi
run_buildah commit --rm "$ctr" "$IMAGE_NAME"
print_success "Build complete: $IMAGE_NAME"