#!/bin/bash
set -euo pipefail

IMAGE_NAME="$1"
ctr="$2"
logfile="/var/log/honeybridge_build.log"

# Buildah logger: logs only buildah output, prints your echo normally
run_buildah() {
    buildah "$@" >> "$logfile" 2>&1
}

echo "[+] Adding LOGIN_SERVER service into your $IMAGE_NAME"

# Detect whether we are done or chaining to next service
finish=0
if [[ $# -eq 2 ]]; then
    finish=1
else
    rest_services=("${@:3}")
fi

# Mount rootfs
mnt=$(run_buildah mount "$ctr")

echo "[*] Creating /app directory for login service"
run_buildah run "$ctr" mkdir -p /app

echo "[*] Copying login_page.py"
run_buildah copy "$ctr" python_scripts/login_page.py /app/login_page.py

echo "[*] Copying Supervisor configs"
run_buildah copy "$ctr" configs/supervisor/login_server.conf /etc/supervisor/conf.d/login_server.conf

# Copy supervisord main config last (same as in SSH)
run_buildah copy "$ctr" configs/supervisord.conf /etc/supervisor/supervisord.conf

# Finished?
if [[ $finish -eq 1 ]]; then
    ./finish.sh "$IMAGE_NAME" "$ctr"
else
    next="${rest_services[0]}"
    echo "[*] Chaining build to next service: $next"
    ./build_"${next}".sh "$IMAGE_NAME" "$ctr" "${rest_services[@]:1}"
fi
