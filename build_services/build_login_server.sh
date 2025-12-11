#!/bin/bash
set -uo pipefail

IMAGE_NAME="$1"
ctr="$2"

source base_functions.sh
trap rollback ERR 

finish=0
rest_services="none"

if [[ $# -eq 2 ]]; then # Check if finish
    finish=1
else
    rest_services=("${@:3}")
fi

print_info "Adding ${YELLOW}login_server${NC} service into your $IMAGE_NAME"

print_info "Creating /app directory for login service"
run_buildah run "$ctr" mkdir -p /app

print_info "Copying login_page.py"
run_buildah copy "$ctr" python_scripts/login_page.py /app/login_page.py

print_info "Copying Supervisor configs"
run_buildah copy "$ctr" configs/supervisor/login_server.conf /etc/supervisor/conf.d/login_server.conf

print_success "${YELLOW}login_server${NC} service was added to $IMAGE_NAME"
if [[ $finish -eq 1 ]]; then
    ./finish.sh $IMAGE_NAME $ctr
else
    trap - ERR
    ./build_"${rest_services[0]}".sh $IMAGE_NAME $ctr ${rest_services[@]:1}
fi