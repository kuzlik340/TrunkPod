#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source "$PROJECT_ROOT"/build_services/base_functions.sh
trap rollback ERR 

IMAGE_NAME=$1

services=("${@:2}")
print_logfile_message
print_info "Starting build for $IMAGE_NAME"
ctr=$(buildah from localhost/honeypot-base 2>/dev/null)
run_buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr"

for service in "${services[@]}"; do
    print_info "Copying Supervisor configs"
    run_buildah copy "$ctr" "$PROJECT_ROOT"/build_services/configs/supervisor/"$service*".conf /etc/supervisor/conf.d/
    print_info "Building service: $service"
    trap - ERR
    "$PROJECT_ROOT"/build_services/build_"$service".sh "$IMAGE_NAME" "$ctr"
    trap rollback ERR
done
rm -rf configs/supervisor
"$PROJECT_ROOT"/build_services/finish.sh "$IMAGE_NAME" "$ctr"



