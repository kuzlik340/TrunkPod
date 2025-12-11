#!/bin/bash
# ------------------------------------------------
# HoneyBridge: Honeypot Deployment Orchestrator
# Controls staged setup, pod creation, interface
# management, service configuration, and recovery.
# ------------------------------------------------


set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

STATE_DIR="/run/honeybridge.d"  # Stores HoneyBridge stage progress for safe restarts
STATE_FILE="/run/honeybridge.d/honeybridge_stage"
LOGO_DIR="logos"    # Directory with the logos of the HoneyBridge project
finish=0 # Variable to check if the script was working and then finished to print the end of configuration statement

# Output project logo with some info
random_logo=$(find "$LOGO_DIR" -type f | shuf -n 1)
echo -e "\n"
cat "$random_logo"
echo -e "\n"
echo "HoneyBridge — Honeypot Management Toolkit"
echo ""

# Create dir for saving stage
sudo mkdir -p $STATE_DIR
sudo ./build_services/log_file_create.sh

# =================================== FUNCTIONS =========================================

show_help() {
    echo "HoneyBridge Options:"
    echo "  --help       Show this help message"
    echo "  --clean      Remove previous configuration state and start fresh"
    echo "  --megaclean  Remove previous configuration state and running pods" #TODO legacy
    echo "  honeypots show" #TODO make this
    echo "  honeypots ps" #TODO make this
}

save_stage() {
    echo "$1" | sudo tee "$STATE_FILE" > /dev/null
}

load_stage() {
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE"
    else
        echo 0
    fi
}

clean() {
    echo "[*] Resetting setup state..."
    sudo rm -rf $STATE_FILE
    sudo rm -rf $STATE_DIR/honeybridge_pods_stage
    echo -e "[-] ${GREEN}State reset to 0${NC}"
    container_hashes=$(sudo podman rm -f -a)
    echo -e "[+] ${GREEN}All pods are deleted.${NC}"
}

# =======================================================================================

# Check args
if [[ $# -gt 0 ]]; then
    case "$1" in
        --help)
            show_help
            exit 0
            ;;
        --clean)
            clean
            exit 0
            ;;
        --clean-logs)
            echo -e "[*] Cleaning logs..."
            rm -f /var/log/honeybridge*
            echo -e "${GREEN}[*]${NC} Logs are ${GREEN}succesfully${NC} cleaned"
            exit 0
            ;;
        *)
            echo -e "[!] ${RED}ERROR:${NC} Unknown option: $1"
            echo "Use --help for usage info."
            exit 1
            ;;
    esac
fi


if ! sudo bash -c ./check_changes.sh; then
    echo -e "[*] ${GREEN}The configs have been changed${NC}. Running configuration from scratch..."
    clean
fi

# Install all tools
sudo ./install_requirments.sh


stage=$(load_stage)

# Create the interfaces for VLANs
if [[ $stage -eq 0 ]]; then
    if ! sudo bash -c ./setup_interfaces.sh; then
        echo -e "[!] ${RED}interface setup exited with error. ${NC}Aborting configuration"
        exit 1
    fi
    save_stage 1
else
    echo "[*] Interfaces are already set up. Skipping interface configuration..."
fi
echo ""

# Check if desired honeypots IPs are free to use
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

# Setup pods that will be running on each VLAN
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

#================================================ 1 STAGE ===============================================
#TODO make the clean flags do what they are supposed to do not megaclean                                                                DONE
#TODO ssh twisted python (or strong passwd)                                                                                             
#TODO add errors handler in the build_services                                                                                          DONE                                                                            
#TODO what if exit 1 in builder chain                                                                                                   DONE
#TODO fix logs (Only errors to shell, other things to log file)                                                                         DONE
#TODO every start new log file                                                                                                          DONE
#TODO --clean-logs to clean all logs                                                                                                    
#TODO do not rebuild base image if hash is still same

#TODO check changes in yamls and base_image via hashes                                                                                  DONE
#TODO JSON parser / CLI (Example docker-compose -> yaml)                                                                                DONE
#TODO IP checker in use                                                                                                                 DONE
#TODO make every IPTABLE entry perfect with the interfaces and other things                                                             DONE
#TODO create a directory with honeypots                                                                                                 DONE
#TODO deletion of interfaces if misocnfigured LIKE TRANSACTION COMMIT                                                                   DONE
#TODO many services on one virtual device (2 HTTP servers 80 port and 4000 port)                                                        DONE
#TODO add dockerfile_builder and entrypoint_builder                                                                                     DONE
#TODO check PID 1 in all containers                                                                                                     DONE
#TODO add build stage before running every container and parser for list of services                                                    DONE

#================================================ 2 STAGE ===============================================
#TODO shellcheck everywhere
#TODO 2-3 services (Simple HTTP server, LDAP, SSH, TELNET). PORT THAT SENDS BANNER (SSH BANNER) SIMPLE SCRIPTS. 

#================================================ 3 STAGE ===============================================
#TODO LOGS ENTIRELY NETFLOWS
#TODO: make the --info flag to see the containers that are running and what services are there (real info via exec ip a)
#TODO NETWORK TELESCOPE (OTHER PACKETS that are not for honeypots we have to log)(SNORT or SURICATA)
#TODO EVERYTHING THAT GOES NOT TO CONTAINERS IP WE HAVE TO SEE IT AND LOG (stealth scan TCP:SYN) SOMETHING LIKE IDS

#================================================ 4 STAGE ===============================================
#TODO CAPABLITIES on the podman 
#TODO: map user and run without sudo
#TODO some pentests (Metasploit and others), lateral movement check
#TODO Mitre ATT&CK 

#================================================ Features ===============================================
#TODO MAC generator based on vendor
#TODO change IP while running
#TODO make IP checker check for same IPs in the yaml and same ports
#TODO multi-core to optimize time
#TODO sudo only where it is has to be
#TODO services:
    #   - name: login_server 
    #     port: 8000
    #   - name: login_server 
    #     port: 8300
    #   - name: ssh
    #     port: 22


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