#!/bin/bash

# =================================================
# TrunkPod: Honeypot Deployment Orchestrator.     |
# Controls staged setup, pod creation, interface. |
# management, service configuration, and recovery.|
# =================================================

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR"/set_project_root.sh
source "$PROJECT_ROOT"/global_functions.sh

LOGO_DIR="$PROJECT_ROOT"/assets/logos # Directory with the logos of the TrunkPod project   
finish=0 # Variable to check if the script was working and then finished to print the end of configuration statement
rebuild_base=0 # Variable to check if base_image script is changed (build_services/build_base.sh)
interface="eth0"

# =================================== FUNCTIONS =========================================

# Helper functions to find where the program was stopped
# =======================================================================================
# Save current stage that was done, so never return to it
save_stage() {
    echo "$1" | tee "$STATE_FILE" > /dev/null
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
    rm -f "$STATE_FILE"
    rm -f "$STATE_FILE_PODS"
    rm -f "$PROJECT_ROOT"/build_services/trunkpod_build_current.log
    print_success "State reset to 0"
    podman ps -q | xargs -r podman stop -t 0 >/dev/null 2>&1
    podman ps -aq | xargs -r podman rm >/dev/null 2>&1
    print_success "All pods are deleted"
}

# Same as clean but without prints to shell
clean_silent() {
    rm -f "$STATE_FILE"
    rm -f "$STATE_FILE_PODS"
    rm -f "$PROJECT_ROOT"/build_services/trunkpod_build_current.log
    podman rm -f -a > /dev/null
}

# Ask for running program from root
require_root () {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "Permission denied: root privileges required. Re-run with sudo."
        exit 1
    fi
}

# Clean build logs
clean_build_logs () {
    print_info "Cleaning build logs..."
    rm -f /var/log/trunkpod_build*
    print_success "TrunkPod build logs are ${GREEN}succesfully${NC} cleaned"
}

clean_honeypot_logs () {
    while true; do
        read -rp "[?] Are you sure you want to clean all honeypot produced logs? All deployed honeypots will be stopped with this action. [y/N]" CHOICE
        
        if [[ -z "$CHOICE" ]]; then # ENTER key
            print_info "Exiting, nothing will be deleted"
            exit 0
        fi

        # Normalize to lowercase
        CHOICE="${CHOICE,,}"

        case "$CHOICE" in
            y)
                break;
                ;;
            n)
                print_info "Exiting, nothing will be deleted"
                exit 0
                ;;
            *)
                echo "Invalid choice. Please enter y or n."
                ;;
        esac
    done
    clean
    print_info "Cleaning honeypot logs..."
    rm -rf /var/log/trunkpod/
    print_success "Honeypot logs are ${GREEN}succesfully${NC} cleaned"
}

# =======================================================================================


# Helper functions for check_cnahges.sh
# =======================================================================================

# Drop a stage when rebuild base image should be done
downgrade_stage_if_needed () {
    stage=$(load_stage)
    if [[ $stage -eq 4 ]]; then # Drop stage to rebuilt base_image and honeypots
        save_stage 3
    fi
}

# Clean start from 0
reset_and_rebuild () {
    print_info "Detected first run or run after reboot, deploy from stage 0 and rebuilding base image."
    rebuild_base=1
    clean_silent
    save_stage 0
}

reset () {
    print_info "Configs were changed. Rerunning from stage 0..."
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
    print_error "Probably your installation is corrupted or there are no files in ${BLUE}configs/${NC}. Please reinstall TrunkPod."
    exit 1
}

# Check crucial files if they were changed after last run
detect_changes() {
    set +e
    "$PROJECT_ROOT"/check_changes.sh
    rc=$?
    set -e

    case "$rc" in
        0) return ;;
        1) reset_and_rebuild ;;             # Case if the tool is running on the new machine, or if run was after reboot
        2) mark_base_for_rebuild ;;         # If the build_base was changed
        3) reset ;;                         # Something in configs/ was changed. Rerun from 0
        50) fatal_installation_error ;;     # Files are missing or configs folder is empty
        *) reset_and_rebuild ;;
    esac
}

check_config() {
    if ! python3 "$PROJECT_ROOT"/honeypots_config_checker.py; then
        print_error "Yaml config error detected. Aborting configuration"
        exit 1
    fi
}
# =======================================================================================


# STAGE MANAGING
# =======================================================================================

# Create dir for saving stage
make_state_dir () {
    mkdir -p $STATE_DIR
}
# Create the interfaces for VLANs 
run_stage_0 () {
    if ! "$PROJECT_ROOT"/generate_honeytokens.sh; then
        print_error "Honeytoken generation failed. Aborting configuration"
        exit 1
    fi
    save_stage 1
    echo ""
}

run_stage_1 () {
    if ! "$PROJECT_ROOT"/setup_interfaces.sh "$interface"; then
        print_error "Interface setup failed. Aborting configuration"
        exit 1
    fi
    save_stage 2
    echo ""
}

# Check if desired honeypots IPs are free to use
run_stage_2 () {
    if ! "$PROJECT_ROOT"/ip_checker.sh "$interface"; then
        print_error "IP conflict detected. Please change the honeypot IP. Aborting configuration"
        exit 1
    fi
    save_stage 3
    echo ""
}

# Setup pods that will be running on each VLAN
run_stage_3 () {
    # Grab timestamp to display journalctl command in the end prompt
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    "$PROJECT_ROOT"/build_services/log_file_create.sh
    if ! "$PROJECT_ROOT"/setup_pods.sh $rebuild_base "$interface"; then
        print_error "Error while configuring pods. Aborting configuration"
        exit 1
    fi
    save_stage 4
    finish=1
}

# Main function for running stages
run_stages() {
    local current_stage
    current_stage="$(load_stage)"
    local STAGE_NAMES=(
        "Honeytokens generation"
        "Interface setup"
        "IP validation"
        "Honeypots deployment"
    )

    for stage in 0 1 2 3; do
        if (( stage < current_stage )); then
            print_info "Stage $stage (${STAGE_NAMES[$stage]}) already completed. Skipping..."
            continue
        fi

        case "$stage" in
            0) print_stage "STAGE $stage: ${STAGE_NAMES[$stage]}"; run_stage_0 ;;
            1) print_stage "STAGE $stage: ${STAGE_NAMES[$stage]}"; run_stage_1 ;;
            2) print_stage "STAGE $stage: ${STAGE_NAMES[$stage]}"; run_stage_2 ;;
            3) print_stage "STAGE $stage: ${STAGE_NAMES[$stage]}"; run_stage_3 ;;
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

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help)
                show_help
                exit 0
                ;;
            --clean)
                clean
                shift
                [[ $# -eq 0 ]] && exit 0
                ;;
            --clean-build-logs)
                clean_build_logs
                shift
                [[ $# -eq 0 ]] && exit 0
                ;;
            --clean-honeypot-logs)
                clean_honeypot_logs
                shift
                [[ $# -eq 0 ]] && exit 0
                ;;
            --interface)
                if [[ -z "${2:-}" || "$2" == --* ]]; then
                    print_error "--interface requires a value"
                    exit 1
                fi

                interface="$2"
                shift 2
                ;;
            --force-rebuild-base)
                rebuild_base=1
                downgrade_stage_if_needed
                shift
                ;;
            "")
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage info."
                exit 1
                ;;
        esac
    done
}

show_banner () {
    # Output project logo with some info
    random_logo=$(find "$LOGO_DIR" -type f | shuf -n 1)
    echo -e "\n"
    cat "$random_logo"
    echo -e "\n"
    echo "TrunkPod — Honeypot Management Toolkit"
    echo ""
}

# Show some random quote at the end
show_quote () {
    if [[ $finish -eq 1 ]]; then
        echo ""
        random_quote=$(shuf -n 1 "$PROJECT_ROOT"/assets/quotes.txt)
        echo -e "The configuration is done. $random_quote :)"
        echo -e "Logs of honeypots themselves could be seen in ${BLUE}/var/log/trunkpod/${NC}"
    fi
}

show_help() {
    cat <<'EOF'
Usage:
  sudo ./TrunkPod [OPTIONS]

Options:
  --help                  Show this help message and exit
  --clean                 Remove previous configuration state and delete all deployed honeypots
  --clean-build-logs      Delete all build logs. Honeypot produced logs are still accesible in journalctl
  --clean-honeypot-logs   Delete all honeypot produced logs
  --force-rebuild-base    Rebuilds the base image forcefully
  --interface             Selects the interface on which TrunkPod will be deployed
Behavior:
  If no options are provided, TrunkPod reads configuration files from the
  'configs/' directory and deploys honeypots according to the configuration
  using the default eth0 interface.

Examples:
  sudo ./TrunkPod --interface eth0
  sudo ./TrunkPod --clean
  sudo ./TrunkPod --clean-build-logs
  sudo ./TrunkPod --force-rebuild-base --interface eth0

Notice! The program won't start until run from root.
EOF
}


main() {
    show_banner
    require_root
    make_state_dir
    parse_args "$@"
    "$PROJECT_ROOT"/install_requirements.sh
    detect_changes
    check_config
    run_stages
    show_quote
}

main "$@"