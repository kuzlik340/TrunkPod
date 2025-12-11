#!/bin/bash

# ==============================================
# Module that creates interfaces for all VLANs |
# that are listed in NETWORK_CONF              |
# ==============================================

set -euo pipefail

source global_functions.sh

len=$(yq '.vlans | length' "$NETWORK_CONF")
# Array for rollback function
CREATED_INTERFACES=()

print_stage "STAGE 1: Interface configuration"
print_info "Configuring interfaces based on the $NETWORK_CONF"

# Function to handle rollback if error occures during setup
rollback() {
    print_error "Error occurred while interface setup.${NC} Rolling back..."
    for iface in "${CREATED_INTERFACES[@]}"; do
        print_deletion "Deleting $iface"
        sudo ip link delete "$iface" 2>/dev/null || true
    done
    print_info "Rollback finished"
    exit 1
}
trap rollback ERR


for i in $(seq 0 $((len - 1))); do
    # Reading configuration
    vlan_id=$(yq ".vlans[$i].id" "$NETWORK_CONF" | tr -d '"')
    iface="eth0.$vlan_id"
    
    # Check if interface already exists
    if ip link show "$iface" &>/dev/null; then
        print_warning "$iface already exists"

        while true; do
            read -rp "[?] Do you want to (k)eep or (o)verride this interface? [K/o]: " choice

            if [[ -z "$choice" ]]; then # ENTER key
                choice="k"
            fi

            case "$choice" in
                    k|K)
                        print_info "Keeping existing $iface"
                        continue 2   # go to next iteration of outer loop
                        ;;
                    o|O)
                        print_info "Overriding existing $iface"
                        sudo ip link delete "$iface" || true
                        break        # break inner loop and create interface
                        ;;
                    *)
                        print_error "Invalid choice. Enter k, o, or s"
                        ;;
            esac
        done
    fi

    print_info "[*] Creating $iface (VLAN $vlan_id)..."

    sudo ip link add link eth0 name eth0."$vlan_id" type vlan id "$vlan_id"
    CREATED_INTERFACES+=("$iface")
    sudo ip link set eth0."$vlan_id" up
    sudo ip link set eth0."$vlan_id" promisc on
    if ! ip link show "$iface" | grep -q "state UP"; then
        print_error "$iface failed to come UP"
        exit 1
    fi
    print_success "$iface created successfully and is UP in PROMISC mode"
done

print_success "All VLAN interfaces configured successfully"