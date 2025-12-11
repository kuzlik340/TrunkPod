#!/bin/bash
set -uo pipefail

IMAGE_NAME=$1
ctr=$2

source base_functions.sh
trap rollback ERR 

echo "[+] Adding SSH service into your $IMAGE_NAME"

finish=0
rest_services="none"

if [[ $# -eq 2 ]]; then # Check if finish
    finish=1
else
    rest_services=("${@:3}")
fi

echo "[*] Generating SSH host keys"
run_buildah run "$ctr" mkdir -p /var/run/sshd
run_buildah run "$ctr" ssh-keygen -A

echo "[*] Copying sshd_config"
run_buildah copy "$ctr" configs/sshd_config /etc/ssh/sshd_config

echo "[*] Copying Supervisor configs"
run_buildah copy "$ctr" configs/supervisor/ssh.conf /etc/supervisor/conf.d/ssh.conf
run_buildah copy "$ctr" configs/supervisord.conf /etc/supervisor/supervisord.conf

if [[ $finish -eq 1 ]]; then
    ./finish.sh $IMAGE_NAME $ctr
else
    trap - ERR
    ./build_"${rest_services[0]}".sh $IMAGE_NAME $ctr ${rest_services[@]:1}
fi


