#!/bin/bash
set -euo pipefail

IMAGE_NAME=$1
ctr=$2
echo "[+] Adding SSH service into your $IMAGE_NAME"

finish=0
rest_services="none"
logfile="/var/log/honeybridge_build.log"

if [[ $# -eq 2 ]]; then # Check if finish
    finish=1
else
    rest_services=("${@:3}")
fi

echo "$@"

buildah_run() {
    echo "[buildah] $*" >> "$logfile"
    buildah "$@" >> "$logfile" 2>&1
}

# Get mount point for file operations
mnt=$(buildah_run mount "$ctr")

echo "[*] Generating SSH host keys"
buildah_run run "$ctr" mkdir -p /var/run/sshd
buildah_run run "$ctr" ssh-keygen -A

echo "[*] Copying sshd_config"
buildah_run copy "$ctr" configs/sshd_config /etc/ssh/sshd_config

echo "[*] Copying Supervisor configs"
buildah_run copy "$ctr" configs/supervisor/ssh.conf /etc/supervisor/conf.d/ssh.conf
buildah_run copy "$ctr" configs/supervisord.conf /etc/supervisor/supervisord.conf

if [[ $finish -eq 1 ]]; then
    ./finish.sh $IMAGE_NAME $ctr
else
    ./build_"${rest_services[0]}".sh $IMAGE_NAME $ctr ${rest_services[@]:1}
fi


