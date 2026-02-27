#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/supervisor_configs/supervisord.conf /etc/supervisor/supervisord.conf
run_buildah config \
    --cmd '["/usr/bin/supervisord","-c","/etc/supervisor/supervisord.conf"]' \
    "$ctr"
if podman image exists localhost/"$IMAGE_NAME":latest; then
    podman image rm -f localhost/"$IMAGE_NAME":latest > /dev/null
fi
run_buildah commit --rm "$ctr" "$IMAGE_NAME"
print_success "Build complete: $IMAGE_NAME"