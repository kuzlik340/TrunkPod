#!/bin/bash

# ==============================================
# Module that creates interfaces for all VLANs |
# that are listed in NETWORK_CONF              |
# ==============================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR"/global_functions.sh

# Array for rollback function
CREATED_INTERFACES=()

print_stage "STAGE 0: Interface configuration"
print_info "Configuring interfaces based on the $NETWORK_CONF"
yq_safe len '.vlans | length' "$NETWORK_CONF"
# Function to handle rollback if error occures during setup
rollback() {
    print_error "Error occurred while interface configuration"
    for iface in "${CREATED_INTERFACES[@]}"; do
        print_deletion "Deleting $iface"
        ip link delete "$iface" 2>/dev/null || true
    done
    print_info "Interface configuration rollback completed"
    exit 1
}
trap rollback ERR


for i in $(seq 0 $((len - 1))); do
    # Reading configuration
    yq_safe vlan_id -r ".vlans[$i].id" "$NETWORK_CONF"
    iface="eth0.$vlan_id"
    
    # Check if interface already exists
    if ip link show "$iface" &>/dev/null; then
        print_warning "$iface already exists"
        # Ask user if he wants to keep this interface or override it
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
                        ip link delete "$iface"
                        break        # break inner loop and create interface
                        ;;
                    *)
                        print_error "Invalid choice. Enter k, o, or s"
                        ;;
            esac
        done
    fi

    print_info "Creating $iface (VLAN $vlan_id)..."

    ip link add link eth0 name eth0."$vlan_id" type vlan id "$vlan_id"
    # Add into array for safe rollback if error occurs
    CREATED_INTERFACES+=("$iface")
    ip link set eth0."$vlan_id" up
    ip link set eth0."$vlan_id" promisc on
    if ! ip link show "$iface" | grep -q "state UP"; then
        print_error "$iface failed to come UP"
        exit 1
    fi
    print_success "$iface created successfully and is UP in PROMISC mode"
done

print_success "All VLAN interfaces configured successfully"