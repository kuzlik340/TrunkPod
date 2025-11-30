#!/bin/bash
GREEN='\033[0;32m'
NC='\033[0m' 

echo "[*] Checking tools"
if ! dpkg -s podman &>/dev/null; then
    echo "[*] Installing podman"
    echo ""
    sudo apt install -y podman
fi

if ! dpkg -s arping &>/dev/null; then
    echo "[*] Installing arping"
    echo ""
    sudo apt install -y arping
fi

if ! dpkg -s yq &>/dev/null; then
    echo "[*] Installing yq"
    echo ""
    sudo apt install -y yq
fi

if ! dpkg -s python3 &>/dev/null; then
    echo "[*] Installing python3"
    echo ""
    sudo apt install -y python3
fi

echo -e "[*] ${GREEN}Tools are installed${NC}"
echo ""