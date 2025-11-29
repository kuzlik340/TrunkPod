# build_base.sh
ctr=$(buildah from debian:stable-slim)

buildah config --env DEBIAN_FRONTEND=noninteractive "$ctr"
buildah run "$ctr" -- bash -c "
    apt-get update &&
    apt-get install -y --no-install-recommends \
        bash sudo ca-certificates supervisor \
        && apt-get clean && rm -rf /var/lib/apt/lists/*
"
buildah commit "$ctr" honeypot-base
