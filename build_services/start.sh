#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR"/base_functions.sh

trap rollback ERR

IMAGE_NAME=$1

services=("${@:2}")
print_logfile_message
print_info "Starting build for $IMAGE_NAME"
ctr=$(buildah from localhost/honeypot-base 2>/dev/null)
run_buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr"

for service in "${services[@]}"; do
    print_info "Copying Supervisor configs"
    run_buildah copy "$ctr" "$SCRIPT_DIR"/configs/supervisor/"$service*".conf /etc/supervisor/conf.d/
    print_info "Building service: $service"
    trap - ERR
    "$SCRIPT_DIR"/build_"$service".sh "$IMAGE_NAME" "$ctr"
    trap rollback ERR
done
rm -rf configs/supervisor
"$SCRIPT_DIR"/finish.sh "$IMAGE_NAME" "$ctr"



