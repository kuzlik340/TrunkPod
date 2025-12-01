#!/bin/bash
set -euo pipefail

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

echo "[+] Adding LOGIN_SERVER service into your $IMAGE_NAME"

echo "[*] Creating /app directory for login service"
run_buildah run "$ctr" mkdir -p /app

echo "[*] Copying login_page.py"
run_buildah copy "$ctr" python_scripts/login_page.py /app/login_page.py

echo "[*] Copying Supervisor configs"
run_buildah copy "$ctr" configs/supervisor/login_server.conf /etc/supervisor/conf.d/login_server.conf

# Copy supervisord main config last (same as in SSH)
run_buildah copy "$ctr" configs/supervisord.conf /etc/supervisor/supervisord.conf

if [[ $finish -eq 1 ]]; then
    ./finish.sh $IMAGE_NAME $ctr
else
    ./build_"${rest_services[0]}".sh $IMAGE_NAME $ctr ${rest_services[@]:1}
fi