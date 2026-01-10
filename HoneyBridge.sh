#!/bin/bash

# =================================================
# HoneyBridge: Honeypot Deployment Orchestrator.  |
# Controls staged setup, pod creation, interface. |
# management, service configuration, and recovery.|
# =================================================

set -euo pipefail

source global_functions.sh

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" # Change directory to HoneyBridge and save it
LOGO_DIR="$SCRIPT_DIR/assets/logos" # Directory with the logos of the HoneyBridge project   
finish=0 # Variable to check if the script was working and then finished to print the end of configuration statement
rebuild_base=0 # Variable to check if base_image script is changed (build_services/build_base.sh)

# Create dir for saving stage
sudo mkdir -p $STATE_DIR

# =================================== FUNCTIONS =========================================

# Helper functions to find where the program was stopped
# =======================================================================================
# Save current stage that was done, so never return to it
save_stage() {
    echo "$1" | sudo tee "$STATE_FILE" > /dev/null
}

# Load current stage
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
    sudo rm -rf $STATE_FILE_PODS
    print_success "State reset to 0"
    sudo podman rm -f -a > /dev/null
    print_success "All pods are deleted"
}

# Same as clean but without prints to shell
clean_silent() {
    sudo rm -rf $STATE_FILE
    sudo rm -rf $STATE_FILE_PODS
    sudo podman rm -f -a > /dev/null
}

# Ask for running program from root
require_root () {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "This program must be run as root. Use sudo."
        exit 1
    fi
}

# Clean build logs
clean_build_logs () {
    print_info "Cleaning logs..."
    rm -f /var/log/honeybridge_build*
    print_success "Logs are ${GREEN}succesfully${NC} cleaned"
}

# =======================================================================================


# Helper functions for check_cnahges.sh
# =======================================================================================

# Drop a stage when rebuild base image should be done
downgrade_stage_if_needed () {
    stage=$(load_stage)
    if [[ $stage -eq 3 ]]; then # Drop stage to rebuilt base_image and honeypots
        save_stage 2
    fi
}

# Clean start from 0
reset_and_rebuild () {
    print_info "Detected first run or run after reboot, deploy from stage 0 and rebuilding base image."
    rebuild_base=1
    clean_silent
    save_stage 0
}

# Set variable to rebuild base image and drop stage if we already had done deploy
mark_base_for_rebuild () {
    print_info "Base image changed. Base image will be rebuilt."
    rebuild_base=1
    downgrade_stage_if_needed
}

# If there are missing files
fatal_installation_error () {
    print_error "Probably your installation is corrupted. Please reinstall HoneyBridge."
    exit 1
}

# Check crucial files if they were changed after last run
detect_changes() {
    set +e
    sudo "$SCRIPT_DIR/check_changes.sh"
    rc=$?
    set -e

    case "$rc" in
        0) return ;;
        1) reset_and_rebuild ;;
        2) mark_base_for_rebuild ;;
        50) fatal_installation_error ;;
        *) reset_and_rebuild ;;
    esac
}
# =======================================================================================


# STAGE MANAGING
# =======================================================================================

# Create the interfaces for VLANs 
run_stage_0 () {
    if ! sudo "$SCRIPT_DIR/setup_interfaces.sh"; then
        print_error "Interface setup exited with error. Aborting configuration"
        exit 1
    fi
    save_stage 1
    echo ""
}

# Check if desired honeypots IPs are free to use
run_stage_1 () {
    if ! sudo "$SCRIPT_DIR/ip_checker.sh"; then
        print_error "IP conflict detected. Please change the honeypot IP. Aborting configuration"
        exit 1
    fi
    save_stage 2
    echo ""
}

# Setup pods that will be running on each VLAN
run_stage_2 () {
    # Grab timestamp to display journalctl command in the end prompt
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    sudo "$SCRIPT_DIR/build_services/log_file_create.sh"
    if ! sudo "$SCRIPT_DIR"/setup_pods.sh $rebuild_base; then
        print_error "Error while configuring pods. Aborting configuration"
        exit 1
    fi
    save_stage 3
    finish=1
}

# Main function for running stages
run_stages() {
    local current_stage
    current_stage="$(load_stage)"
    local STAGE_NAMES=(
        "Interface setup"
        "IP validation"
        "Honeypots deployment"
    )

    for stage in 0 1 2; do
        if (( stage < current_stage )); then
            print_info "Stage $stage (${STAGE_NAMES[$stage]}) already completed. Skipping..."
            continue
        fi

        case "$stage" in
            0) run_stage_0 ;;
            1) run_stage_1 ;;
            2) run_stage_2 ;;
            *)
                print_error "Invalid stage: $stage"
                exit 1
                ;;
        esac
    done
}

# =======================================================================================

# Function to parse passed arguments
parse_args() {
    rebuild_base=0
    case "${1:-}" in
        --help) show_help; exit 0 ;;
        --clean) clean; exit 0 ;;
        --clean-build-logs) clean_build_logs; exit 0 ;;
        --force-rebuild-base)
            rebuild_base=1
            downgrade_stage_if_needed
            ;;
        "") ;;
        *) print_error "Unknown option: $1"; echo "Use --help for usage info." ; exit 1 ;;
    esac
}

show_banner () {
    # Output project logo with some info
    random_logo=$(find "$LOGO_DIR" -type f | shuf -n 1)
    echo -e "\n"
    cat "$random_logo"
    echo -e "\n"
    echo "HoneyBridge — Honeypot Management Toolkit"
    echo ""
}

show_help() {
    cat <<'EOF'
HoneyBridge — Honeypot Deployment Framework

Usage:
  sudo ./HoneyBridge [OPTIONS]

Options:
  --help                  Show this help message and exit
  --clean                 Remove previous configuration state and delete all deployed honeypots
  --clean-build-logs      Delete all build logs. Honeypot produced logs are still accesible in journalctl

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


main() {
    show_banner
    require_root
    parse_args "$@"
    detect_changes
    sudo "$SCRIPT_DIR/install_requirements.sh"
    run_stages
}

main "$@"

# Show some random quote at the end
if [[ $finish -eq 1 ]]; then
    echo ""
    random_quote=$(shuf -n 1 assets/quotes.txt)
    echo -e "The configuration is done. $random_quote :)"
    echo -e "Logs of honeypots themselves could be seen by running ${BLUE}sudo journalctl -f --since '$timestamp' | grep --line-buffered '\[HoneyBridge\]'${NC}"
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
#TODO Log in one file, also with tcpdump or smth like that                                                                              DONE
#TODO log into one file from nftablesODO create in logging commit transaction so won't be "HonHoneypot2 Null_scaneypot1 SYN scan"       DONE  
#TODO error handler for yaml
#TODO error handler not in depth
#TODO check build_service    
#TODO Enable yaml conf checker


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