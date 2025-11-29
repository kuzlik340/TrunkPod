ctr=$2
IMAGE_NAME=$1
logfile="/var/log/honeybridge_build.log"

buildah_run() {
    echo "[buildah] $*" >> "$logfile"
    buildah "$@" >> "$logfile" 2>&1
}

buildah_run config \
    --cmd '["/usr/bin/supervisord","-c","/etc/supervisor/supervisord.conf"]' \
    "$ctr"

buildah_run commit "$ctr" "$IMAGE_NAME"

echo "[+] Build complete: $IMAGE_NAME"