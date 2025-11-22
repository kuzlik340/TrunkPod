#!/bin/bash

RED='\033[0;31m'
NC='\033[0m'
STATE_FILE="/run/honeybridge.d/honeybridge_stage"
STATE_DIR="/run/honeybridge.d"

echo ""
cat <<'EOF'
    __  __                       ____       _     __          
   / / / /___  ____  ___  __  __/ __ )_____(_)___/ /___ ____  
  / /_/ / __ \/ __ \/ _ \/ / / / __  / ___/ / __  / __ `/ _ \ 
 / __  / /_/ / / / /  __/ /_/ / /_/ / /  / / /_/ / /_/ /  __/ 
/_/ /_/\____/_/ /_/\___/\__, /_____/_/  /_/\__,_/\__, /\___/  
                       /____/                   /____/        
EOF
echo ""
echo "HoneyBridge — Honeypot Management Toolkit"
echo ""

sudo mkdir -p /run/honeybridge.d

show_help() {
    echo "HoneyBridge Options:"
    echo "  --help       Show this help message"
    echo "  --clean      Remove previous configuration state and start fresh"
    echo "  --megaclean  Remove previous configuration state and running pods"
}

if [[ $# -gt 0 ]]; then
    case "$1" in
        --help)
            show_help
            exit 0
            ;;

        --clean)
            echo "[*] Resetting setup state..."
            sudo rm -rf $STATE_DIR
            echo -e "[+] Clean complete. ${GREEN}State reset to 0${NC}"
            exit 0
            ;;
        --megaclean)
            echo "[*] Resetting setup state..."
            sudo rm -rf $STATE_DIR
            echo -e "[+] ${GREEN}State reset to 0${NC}"
            sudo podman rm -f -a
            echo -e "[+] ${GREEN}All pods are deleted.${NC}"
            exit 0
            ;;

        *)
            echo -e "[!] ${RED}ERROR:${NC} Unknown option: $1"
            echo "Use --help for usage info."
            exit 1
            ;;
    esac
fi

sudo ./install_requirments.sh

save_stage() {
    echo "$1" | sudo tee "$STATE_FILE" >/dev/null
}

load_stage() {
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE"
    else
        echo 0
    fi
}

stage=$(load_stage)

if [[ $stage -eq 0 ]]; then
    if ! sudo bash -c ./setup_interfaces.sh; then
        echo -e "${RED}[!] interface setup exited with error. ${NC}Aborting configuration"
        exit 1
    fi
    save_stage 1
else
    echo "[*] Interfaces are already set up. Skipping interface configuration..."
fi

stage=$(load_stage)
if [[ $stage -eq 1 ]]; then
    if ! sudo bash -c ./ip_checker.sh; then
        echo -e "[!] ${RED}IP conflict detected. ${NC}Please change the honeypot IP. Aborting configuration"
        exit 1
    fi
    save_stage 2
else
    echo "[*] IP check already done. Skipping IP checking"
fi

stage=$(load_stage)
if [[ $stage -eq 2 ]]; then
    if ! sudo bash -c ./setup_pods.sh; then
        echo -e "[!] ${RED}Error while configuring pods. ${NC}Aborting configuration"
        exit 1
    fi
    save_stage 3
else
    echo "[*] The pods configuration is already done"
fi

#TODO: make the --info flag to see the containers that are running and what services are there (real info via exec ip a)


