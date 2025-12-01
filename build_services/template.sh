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

echo "[+] Adding SOME_SERVICE service into your $IMAGE_NAME"
# SOME run_buildah



if [[ $finish -eq 1 ]]; then
    ./finish.sh $IMAGE_NAME $ctr
else
    ./build_"${rest_services[0]}".sh $IMAGE_NAME $ctr ${rest_services[@]:1}
fi
