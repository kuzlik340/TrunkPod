# build_base.sh


if sudo podman image exists honeypot-base; then
    echo "[+] Base image already exists, skipping build."
    exit 0
fi

ctr=$(buildah from debian:stable-slim)

buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr"
buildah run "$ctr" -- bash -c "
    apt-get update &&
    apt-get install -y --no-install-recommends \
        bash sudo ca-certificates supervisor \
        python3 python3-pip \
        openssh-server \
        && apt-get clean && rm -rf /var/lib/apt/lists/*
"
buildah_run run "$ctr" useradd -m -s /bin/bash -u 1000 -G sudo admin
buildah_run run "$ctr" bash -c "echo 'admin:admin' | chpasswd"
buildah commit "$ctr" honeypot-base
