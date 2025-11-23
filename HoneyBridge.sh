#!/bin/bash

RED='\033[0;31m'
NC='\033[0m'
STATE_FILE="/run/honeybridge.d/honeybridge_stage"
STATE_DIR="/run/honeybridge.d"
LOGO_DIR="logos"
finish=0

random_logo=$(find "$LOGO_DIR" -type f | shuf -n 1)
echo ""
cat "$random_logo"
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
echo ""

stage=$(load_stage)
if [[ $stage -eq 1 ]]; then
    if ! sudo bash -c ./ip_checker.sh; then
        echo -e "[!] ${RED}IP conflict detected. ${NC}Please change the honeypot IP. Aborting configuration"
        exit 1
    fi
    save_stage 2
else
    echo "[*] IP check already done. Skipping IP checking..."
fi
echo ""

stage=$(load_stage)
if [[ $stage -eq 2 ]]; then
    if ! sudo bash -c ./setup_pods.sh; then
        echo -e "[!] ${RED}Error while configuring pods. ${NC}Aborting configuration"
        exit 1
    fi
    save_stage 3
    finish=1
else
    echo "[*] The pods configuration is already done. Skipping pods checking..."
fi

if [[ $finish -eq 1 ]]; then
    echo ""
    random_quote=$(shuf -n 1 quotes.txt)
    echo "[*] The configuration is done. $random_quote :)"
fi


#TODO: make the --info flag to see the containers that are running and what services are there (real info via exec ip a)
#TODO JSON parser / CLI (Example docker-compose -> yaml)                                                                                DONE
#TODO 2-3 services (Simple HTTP server, LDAP, SSH). PORT THAT SENDS BANNER (SSH BANNER) SIMPLE SCRIPTS
#TODO IP checker in use                                                                                                                 DONE
#TODO make every IPTABLE entry perfect with the interfaces and other things                                                             DONE
#TODO create a directory with honeypots 
#TODO deletion of interfaces if misocnfigured LIKE TRANSACTION COMMIT                                                                   DONE

#TODO LOGS ENTIRELY NETFLOWS
#TODO NETWORK TELESCOPE
#TODO FIREWALL BETWEEN DEVICES ON PODMAN INTERNAL NETWORK                                                                               DONE
#TODO CAPABLITIES on the podman
#TODO EVERYTHING THAT GOES NOT TO CONTAINERS IP WE HAVE TO SEE IT AND LOG (stealth scan TCP:SYN) SOMETHING LIKE IDS




#TODO FIX
# =================================== STAGE 3: Pods configuration ======================================
# [*] Creating macvlan interface: macvlan_temp for honeypot1
# [+] Created macvlan_temp with honeypot MAC DA:FD:BE:EF:00:01
# [*] Starting honeypot honeypot1
# [+] Container honeypot1 started: b921ef65fd2cc62201846def1b146a296f0c359e495d49f01e1a8da6950f5aaf
# [*] Moving macvlan_temp into honeypot1 namespace
# [*] Configuring pod networking
# ./setup_pods.sh: line 96: service_script: unbound variable
# [!] Error while configuring pods. Aborting configuration