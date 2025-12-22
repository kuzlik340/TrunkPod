#!/bin/bash
set -uo pipefail

IMAGE_NAME=$1
ctr=$2

source base_functions.sh
trap rollback ERR 

print_info "Adding ${YELLOW}FAKE_SSH${NC} service into your $IMAGE_NAME"

finish=0
rest_services="none"

if [[ $# -eq 2 ]]; then # Check if finish
    finish=1
else
    rest_services=("${@:3}")
fi

run_buildah run "$ctr" virtualenv try-twisted
#run_buildah run "$ctr" . try-twisted/bin/activate
print_info "Installing dependencies into your $IMAGE_NAME"
run_buildah run "$ctr" /try-twisted/bin/pip install twisted[all] bcrypt cryptography
run_buildah run "$ctr" mkdir -p /app
run_buildah copy "$ctr" python_scripts/fake_ssh.py /app/fake_ssh.py

print_info "Copying Supervisor configs"
run_buildah copy "$ctr" configs/supervisor/fake_ssh.conf /etc/supervisor/conf.d/fake_ssh.conf

print_success "${YELLOW}FAKE_SSH${NC} service was added to $IMAGE_NAME"

if [[ $finish -eq 1 ]]; then
    ./finish.sh $IMAGE_NAME $ctr
else
    trap - ERR
    ./build_"${rest_services[0]}".sh $IMAGE_NAME $ctr ${rest_services[@]:1}
fi


