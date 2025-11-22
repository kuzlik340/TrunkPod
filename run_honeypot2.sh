sudo podman run -d --name $1 \
  --hostname debian \
  --network none \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --tmpfs /tmp:rw,size=64m \
  --read-only=false \
  os-emulator:latest
