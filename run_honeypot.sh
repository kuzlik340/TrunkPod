sudo podman run -d --name $3 \
  --hostname debian \
  --network internal \
  --ip $1 \
  --mac-address $2 \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --tmpfs /tmp:rw,size=64m \
  --read-only=false \
  os-emulator:latest

  #--mac-address DA:FD:BE:EF:00:01 \

  #  --ip $1 \
  # --mac-address $2 \