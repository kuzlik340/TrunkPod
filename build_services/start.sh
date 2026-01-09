#!/bin/bash
set -uo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
cd "$SCRIPT_DIR"

source base_functions.sh

trap rollback ERR

IMAGE_NAME=$1

services=("${@:2}")
print_logfile_message
print_info "Starting build for $IMAGE_NAME"
ctr=$(buildah from localhost/honeypot-base 2>/dev/null)
run_buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr"

for service in "${services[@]}"; do
    print_info "Copying Supervisor configs"
    run_buildah copy "$ctr" configs/supervisor/"$service*".conf /etc/supervisor/conf.d/
    print_info "Building service: $service"
    trap - ERR
    ./build_"$service".sh "$IMAGE_NAME" "$ctr"
    trap rollback ERR
done
rm -rf configs/supervisor
./finish.sh $IMAGE_NAME $ctr



