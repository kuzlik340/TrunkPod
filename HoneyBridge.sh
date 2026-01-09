#!/bin/bash

# =================================================
# HoneyBridge: Honeypot Deployment Orchestrator.  |
# Controls staged setup, pod creation, interface. |
# management, service configuration, and recovery.|
# =================================================

set -euo pipefail

source global_functions.sh

STATE_DIR="/run/honeybridge.d"  # Stores HoneyBridge stage progress for safe restarts
STATE_FILE="/run/honeybridge.d/honeybridge_stage"
LOGO_DIR="assets/logos"    # Directory with the logos of the HoneyBridge project
finish=0 # Variable to check if the script was working and then finished to print the end of configuration statement
rebuild_base=0 # Variable to check if base_image script is changed (build_services/build_base.sh)

# Output project logo with some info
random_logo=$(find "$LOGO_DIR" -type f | shuf -n 1)
echo -e "\n"
cat "$random_logo"
echo -e "\n"
echo "HoneyBridge — Honeypot Management Toolkit"
echo ""

if [[ "$EUID" -ne 0 ]]; then
    print_error "This program must be run as root. Use sudo."
    exit 1
fi

# Create dir for saving stage
sudo mkdir -p $STATE_DIR
# =================================== FUNCTIONS =========================================

show_help() {
    cat <<'EOF'
HoneyBridge — Honeypot Deployment Framework

Usage:
  honeybridge [OPTIONS]

Options:
  --help            Show this help message and exit
  --clean           Remove previous configuration state and delete all deployed honeypots
  --clean-logs      Delete all produced logs, including honeypot alert logs

Behavior:
  If no options are provided, HoneyBridge reads configuration files from the
  'configs/' directory and deploys honeypots according to the configuration.

Examples:
  sudo ./HoneyBridge
  sudo ./HoneyBridge --clean
  sudo ./HoneyBridge --clean-logs

Notice! The program won't start until run with sudo.
EOF
}


# Helper functions to find where the program was stopped
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

# Clean up everything except logs and file hashes
clean() {
    print_info "Resetting setup state..."
    sudo rm -rf $STATE_FILE
    sudo rm -rf $STATE_DIR/honeybridge_pods_stage
    print_success "State reset to 0"
    container_hashes=$(sudo podman rm -f -a)
    print_success "All pods are deleted"
}

# =======================================================================================

# Checker for args
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
            print_info "Cleaning logs..."
            rm -f /var/log/honeybridge_build*
            rm -rf /var/log/honeybridge
            print_success "Logs are ${GREEN}succesfully${NC} cleaned"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage info."
            exit 1
            ;;
    esac
fi

# Check changes returns 1 if some config was changed and 2 if base_image was changed, 50 when error
set +e 
sudo bash -c ./check_changes.sh
rc=$?
set -e

# Check return code of check_changes
if [[ $rc -ne 0 ]]; then
    if [[ $rc -eq 2 ]]; then
        print_info "Base image changed. Base image will be rebuilt"
        rebuild_base=1
    elif [[ $rc -eq 50 ]]; then
        print_error "Probably your installation is corrupted. Please reinstall HoneyBridge"
    else
        print_info "The configs have been changed. Running configuration from scratch..."
    fi
    clean
fi

# Check installed tools
sudo ./install_requirements.sh


stage=$(load_stage)

#======== 1 stage =========
# Create the interfaces for VLANs 
if [[ $stage -eq 0 ]]; then
    if ! sudo bash -c ./setup_interfaces.sh; then
        print_error "Interface setup exited with error. Aborting configuration"
        exit 1
    fi
    save_stage 1
    echo ""
else
    print_info "Interfaces are already set up. Skipping interface configuration..."
fi

#======== 2 stage =========
# Check if desired honeypots IPs are free to use
stage=$(load_stage)
if [[ $stage -eq 1 ]]; then
    if ! sudo bash -c ./ip_checker.sh; then
        print_error "IP conflict detected. Please change the honeypot IP. Aborting configuration"
        exit 1
    fi
    save_stage 2
    echo ""
else
    print_info "IP check already done. Skipping IP checking..."
fi

#======== 3 stage =========
# Setup pods that will be running on each VLAN
stage=$(load_stage)
if [[ $stage -eq 2 ]]; then
    sudo ./build_services/log_file_create.sh
    if ! sudo bash -c "./setup_pods.sh $rebuild_base"; then
        print_error "Error while configuring pods. Aborting configuration"
        exit 1
    fi
    save_stage 3
    finish=1
else
    print_info "The pods configuration is already done. Skipping pods checking..."
fi

# Show some random quote at the end
if [[ $finish -eq 1 ]]; then
    echo ""
    random_quote=$(shuf -n 1 assets/quotes.txt)
    echo -e "The configuration is done. $random_quote :)"
    echo -e "Logs of honeypots themselves could be found in ${BLUE}/var/log/honeypots${NC}"
fi

#================================================ 1 STAGE ===============================================
#TODO make the clean flags do what they are supposed to do not megaclean                                                                DONE                                                                                           
#TODO add errors handler in the build_services                                                                                          DONE                                                                            
#TODO what if exit 1 in builder chain                                                                                                   DONE
#TODO fix logs (Only errors to shell, other things to log file)                                                                         DONE
#TODO every start new log file                                                                                                          DONE
#TODO --clean-logs to clean all logs                                                                                                    DONE                                                                                          
#TODO do not rebuild base image if hash is still same                                                                                   DONE                                                                                                         
#TODO refactor                                                                                                                          DONE
#TODO check for || true                                                                                                                 DONE                                                                                                  
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
#TODO shellcheck everywhere                                                                                                             DONE
#TODO 2-3 services (Simple HTTP server, LDAP, SSH, TELNET). PORT THAT SENDS BANNER (SSH BANNER) SIMPLE SCRIPTS.                         DONE
#TODO everytime new logs or somehow save old directory?                                                                                 DONE
#TODO error handler for yaml
#TODO error handler not in depth
#TODO check build_service    
#TODO Enable yaml conf checker
#TODO Log in one file, also with tcpdump or smth like that 
#TODO log into one file from nftablesODO create in logging commit transaction so won't be "HonHoneypot2 Null_scaneypot1 SYN scan"
#TODO maybe in clean delete hashes?     

#================================================ 3 STAGE ===============================================
#TODO LOGS ENTIRELY NETFLOWS Telescope
#TODO PORTS CLOSED RST SYNACK NOT REPLY
#TODO: make the --info flag to see the containers that are running and what services are there (real info via exec ip a)
#TODO NETWORK TELESCOPE (OTHER PACKETS that are not for honeypots we have to log)(SNORT or SURICATA)
#TODO EVERYTHING THAT GOES NOT TO CONTAINERS IP WE HAVE TO SEE IT AND LOG (stealth scan TCP:SYN) SOMETHING LIKE IDS

#================================================ 4 STAGE ===============================================
#TODO CAPABLITIES on the podman 
#TODO secure web page
#TODO: map user and run without sudo
#TODO some pentests (Metasploit and others), lateral movement check
#TODO Mitre ATT&CK 
#TODO Same services on different ports on one honeypot

#================================================ Features ===============================================
#TODO MAC generator based on vendor
#TODO change IP while running
#TODO make IP checker check for same IPs in the yaml and same ports
#TODO multi-core to optimize time
#TODO sudo only where it is has to be
#TODO ssh twisted python 
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