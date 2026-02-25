#!/bin/bash

# ==========================================================
# Module that is esponsible for building images, creating  |
# Podman-based oneypots, configuring macvlan networkink    |
# and assigning namespaces.                                |
# ==========================================================

set -Eeuo pipefail

source "$PROJECT_ROOT"/global_functions.sh

STATE_FILE_PODS="/run/honeybridge.d/honeybridge_pods_stage"
# The directory with all services that could be bundled into honeypot
rebuild_base=$1
# Length of the honeypots.yaml
len=$(yq '.honeypots | length' "$HONEYPOT_CONF")

print_stage "STAGE 2: Pods configuration"

macvlan_moved=0             # For safe rollback, shows if the macvlan is under hosts control or already in pod
container_running=0         # For safe rollback, shows if the pod already runs
current_container_name=""   # For safe rollback, shows name of honeypot that caused error
current_pos=0               # For state managment, shows what was the index of honeypot that caused error

# =================================== FUNCTIONS =========================================

save_pods_stage() { echo "$1" > "$STATE_FILE_PODS"; }
load_pods_stage() { [[ -f "$STATE_FILE_PODS" ]] && cat "$STATE_FILE_PODS" || echo 0; }


rollback () {
    print_error "Error occurred while setting up pods"

    if [[ $macvlan_moved -eq 0 ]]; then
        if ip link show macvlan_temp &>/dev/null; then
            print_info "Deleting macvlan_temp"
            ip link delete macvlan_temp
        fi
    fi
    if [[ $container_running -eq 1 ]]; then
        print_info "Deleting pod"
	podman kill "$current_container_name" >/dev/null 2>&1 || true
        podman rm "$current_container_name" >/dev/null 2>&1 || true
    fi
    print_info "Setup pods rollback completed"
    save_pods_stage "$current_pos"
    exit 1
}
trap rollback ERR # Will be called if error occurs

load_honeypot_config () {
    local idx="$1"

    yq_safe honeypot_name -r ".honeypots[$idx].name" "$HONEYPOT_CONF"
    yq_safe honeypot_ip -r ".honeypots[$idx].ip" "$HONEYPOT_CONF"
    yq_safe honeypot_vlan_id -r ".honeypots[$idx].vlan" "$HONEYPOT_CONF"
    yq_safe honeypot_mac_addr -r ".honeypots[$idx].mac" "$HONEYPOT_CONF"
    yq_safe network_range -r \
        ".vlans[] | select(.id == $honeypot_vlan_id) | .range" "$NETWORK_CONF"
    yq_safe gateway_ip -r \
        ".vlans[] | select(.id == $honeypot_vlan_id) | .gateway" "$NETWORK_CONF"
    mapfile -t service_names < <(yq -r ".honeypots[$idx].services[].name" "$HONEYPOT_CONF")
    mapfile -t service_ports < <(yq -r ".honeypots[$idx].services[].port" "$HONEYPOT_CONF")
}

prepare_supervisor_configs () {
    rm -rf "$PROJECT_ROOT"/build_services/configs/supervisor
    mkdir -p "$PROJECT_ROOT"/build_services/configs/supervisor
    print_info "Configuring $honeypot_name ports"
    for idx in "${!service_names[@]}"; do
        local name="${service_names[$idx]}"
        local port="${service_ports[$idx]}"

        # Copy template supervisor config
        cp "$PROJECT_ROOT"/build_services/configs/supervisor_templates/"${name}".conf \
        "$PROJECT_ROOT"/build_services/configs/supervisor/"${name}${port}".conf

        conf_path="$PROJECT_ROOT/build_services/configs/supervisor/"${name}${port}".conf"

        if [[ -f "$conf_path" ]]; then
            # Replace "insert_port" with the actual port
            sed -i "s/insert_ps_name/${name}${port}/g" "${conf_path}"
            sed -i "s/insert_port/${port}/g" "${conf_path}"
            sed -i "s/insert_honeypot_name/${honeypot_name}/g" "${conf_path}"
        else
            print_warning "No supervisor config for service '$name' (${conf_path})"
        fi
    done
}

setup_macvlan_for_container () {
    print_info "Creating macvlan interface: macvlan_temp for $honeypot_name"
    ip link add macvlan_temp link eth0."$honeypot_vlan_id" type macvlan mode bridge
    ip link set macvlan_temp address "$honeypot_mac_addr"
    print_success "Created macvlan_temp with honeypot MAC $honeypot_mac_addr"
}

start_container () {
    print_info "Starting honeypot $honeypot_name"
    container_hash=$("$PROJECT_ROOT"/run_honeypot.sh "$honeypot_name")
    print_success "Container $honeypot_name started: $container_hash"
    current_container_name="$honeypot_name"
    container_running=1 # Safe rollback if error occurs
}

configure_honeypot_network() {
    # Finding the pid to insert macvlan into its namespace
    pid=$( podman inspect -f '{{.State.Pid}}' "$honeypot_name")
    # Wait for container initializing
    sleep 0.5
    # Move macvlan interface into container namespace
    print_info "Moving macvlan_temp into $honeypot_name namespace"
    ip link set macvlan_temp netns "$pid"
    macvlan_moved=1
    # Configure macvlan inside container
    print_info "Configuring pod networking"
    nsenter -t "$pid" -n ip link set macvlan_temp name eth0
    # Read the network mask (Example: 192.168.20.0/24 -> 24)
    IFS=/ read -r _ mask <<< "$network_range"
    nsenter -t "$pid" -n ip addr add "${honeypot_ip}"/"${mask}" dev eth0
    nsenter -t "$pid" -n ip link set eth0 up
    nsenter -t "$pid" -n ip route add default via $gateway_ip dev eth0
    nsenter -t "$pid" -n arping -A -c 3 -I eth0 "$honeypot_ip" >> /dev/null || true
}

# =======================================================================================

# Load last stage
start_pos=$(load_pods_stage) 

# Build base image if it was changed
if [[ $rebuild_base -eq 1 ]]; then
    "$PROJECT_ROOT"/build_services/build_base.sh 
fi

# Enable logging for ngt
sysctl -w net.netfilter.nf_log_all_netns=1 > /dev/null
 
for i in $(seq "${start_pos}" $((len - 1))); do
    # Updating variables for safe rollback
    macvlan_moved=0
    container_running=0
    # ==================== Reading configuration ========================
    load_honeypot_config "$i"
    # ===================================================================
    # Deleting old supervisor config since it was overwritten and starting with template 
    prepare_supervisor_configs
    # Passing all services so the chain of build_"services".sh scripts will build the desired image
    "$PROJECT_ROOT"/build_services/start.sh "$honeypot_name" "${service_names[@]}"
    # Update already deployed honeypot counter
    current_pos=${i}
    setup_macvlan_for_container
    start_container
    configure_honeypot_network
  
    # Output info about the running honeypot
    print_success "Honeypot $honeypot_name ${GREEN}ready${NC}"
    echo -e "    MAC: ${YELLOW}$honeypot_mac_addr${NC}"
    echo -e "    IP: ${YELLOW}$honeypot_ip${NC}"
    echo -ne "    SERVICES: ${YELLOW}"
    printf "%s " "${service_names[@]}"
    echo -e "${NC}"
    echo ""
done
