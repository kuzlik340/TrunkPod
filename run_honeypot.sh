sudo podman run -d --name $3 \
  --hostname debian \
  --network internal \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --ip $1 \
  --mac-address $2 \
  --tmpfs /tmp:rw,size=64m \
  --read-only=false \
  os-emulator:latest

  #--mac-address DA:FD:BE:EF:00:01 \