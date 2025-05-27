#!/bin/bash

# =================================================================================================
# Universal StrongSwan IKEv2 Client Setup Script for Debian/Ubuntu/RHEL/Fedora/Rocky Linux
# =================================================================================================
# 
# This script automatically:
# - Detects the Linux distribution and installs appropriate packages
# - Configures a StrongSwan IKEv2 client connection
# - Sets up XFRM interfaces for routing
# - Creates persistent connections with systemd
# - Works with both apt and dnf/yum package managers
#
# Author: Felix C Frank
# Version: 1.7.50.5
# Created: 2025-03-27
# Updated: 2025-03-27
# 
# Prerequisites:
# - For Red Hat-based systems (Rocky Linux, Red Hat), ensure EPEL is enabled if using dnf/yum.
#   Run `sudo dnf install epel-release` beforehand if needed.
# - Root privileges are required.
#
# =================================================================================================

set -e  # Exit on error

# Auto-detect main LAN interface (initial setup only)
detect_main_interface() {
    MAIN_IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -1)
    if [ -z "$MAIN_IFACE" ]; then
        echo "Failed to detect main interface, please enter it manually."
        read -p "Enter Default interface name (e.g. eth0): " MAIN_IFACE
    else
        echo "Detected main interface: $MAIN_IFACE"
    fi
}

# Detect OS type and package manager
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="$NAME"
        OS_ID="$ID"
        if [ -n "$ID_LIKE" ]; then
            OS_FAMILY="$ID_LIKE"
        else
            OS_FAMILY="$ID"
        fi
        
        echo "Detected OS: $OS_NAME ($OS_ID)"
        
        # Determine package manager
        if command -v apt-get >/dev/null; then
            PKG_MANAGER="apt"
            PKG_INSTALL="apt-get install -y"
            PKG_UPDATE="apt-get update -y"
        elif command -v dnf >/dev/null; then
            PKG_MANAGER="dnf"
            PKG_INSTALL="dnf install -y"
            PKG_UPDATE="dnf update -y"
        elif command -v yum >/dev/null; then
            PKG_MANAGER="yum"
            PKG_INSTALL="yum install -y"
            PKG_UPDATE="yum update -y"
        else
            echo "Unsupported package manager. This script requires apt, dnf, or yum."
            exit 1
        fi
        
        echo "Using package manager: $PKG_MANAGER"
    else
        echo "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
}

# Install required packages
install_packages() {
    echo "Updating package lists..."
    $PKG_UPDATE || { echo "Failed to update package lists"; exit 1; }
    
    echo "Installing required packages..."
    if [ "$PKG_MANAGER" = "apt" ]; then
        # Debian/Ubuntu
        $PKG_INSTALL strongswan openssl iproute2 strongswan-swanctl || { 
            echo "Failed to install packages on $OS_NAME"; 
            exit 1; 
        }
    elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
        # Rocky Linux, RHEL, Fedora
        if [ "$OS_ID" = "fedora" ]; then
            # Fedora might split packages differently
            $PKG_INSTALL strongswan openssl iproute strongswan-libcharon strongswan-charon || { 
                echo "Failed to install packages on Fedora. Check package availability."; 
                exit 1; 
            }
        else
            # Rocky Linux, RHEL (EPEL provides strongswan as a single package)
            $PKG_INSTALL strongswan openssl iproute || { 
                echo "Failed to install packages on $OS_NAME. Please ensure EPEL repository is enabled."
                echo "Run: sudo dnf install epel-release"
                exit 1; 
            }
        fi
    fi
    
    echo "Package installation complete."
}

# Prompt for inputs
prompt_for_inputs() {
    detect_main_interface
    read -p "Enter Connection name: " name
    read -p "Enter Server address: " vpn_server
    read -p "Enter PKCS#12 file path (.p12): " p12_file
    read -sp "Enter Password for the PKCS#12 file: " p12_password
    echo
    
    # Show confirmation
    echo "Configuration summary:"
    echo "  Interface:      $MAIN_IFACE"
    echo "  Connection:     $name"
    echo "  Server address: $vpn_server"
    echo "  PKCS#12 file:   $p12_file"
    echo "  Password:       ********"
    
    read -p "Proceed with client install? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Exiting..."
        exit 1
    fi
}

# Extract certificates from PKCS#12 file
extract_certificates() {
    echo "Extracting certificates from PKCS#12 file..."
    
    # Determine filenames for output
    certname="${name}.pem"
    keyname="${name}.key"
    caname="ca.pem"

    # Determine SwanCTL config directory based on distribution
    if [ "$PKG_MANAGER" = "apt" ]; then
        SWANCTL_DIR="/etc/swanctl"
    else
        SWANCTL_DIR="/etc/strongswan/swanctl"
    fi
    
    # Create certificate directories
    mkdir -p "$SWANCTL_DIR/x509" "$SWANCTL_DIR/private" "$SWANCTL_DIR/x509ca"
    
    echo "Using SwanCTL directory: $SWANCTL_DIR"
    
    # Extract certificates with error checking
    openssl pkcs12 -in "$p12_file" -passin pass:"$p12_password" -nokeys -out "$SWANCTL_DIR/x509/${certname}" || { 
        echo "Failed to extract certificate"; exit 1; 
    }
    
    openssl pkcs12 -in "$p12_file" -passin pass:"$p12_password" -nocerts -nodes -out "$SWANCTL_DIR/private/${keyname}" || { 
        echo "Failed to extract private key"; exit 1; 
    }
    
    openssl pkcs12 -in "$p12_file" -passin pass:"$p12_password" -cacerts -nokeys -out "$SWANCTL_DIR/x509ca/${caname}" || { 
        echo "Failed to extract CA certificate"; exit 1; 
    }
    
    # Set proper permissions
    chmod 644 "$SWANCTL_DIR/x509/${certname}" "$SWANCTL_DIR/x509ca/${caname}"
    chmod 600 "$SWANCTL_DIR/private/${keyname}"
    
    echo "Certificate, key, and CA certificate have been extracted and stored."
}

# Configure StrongSwan
configure_strongswan() {
    echo "Configuring StrongSwan..."
    
    # Determine proper strongswan.conf location
    if [ "$PKG_MANAGER" = "apt" ]; then
        STRONGSWAN_CONF="/etc/strongswan.conf"
    else
        STRONGSWAN_CONF="/etc/strongswan/strongswan.conf"
    fi
    
    # Write strongswan.conf
    cat > "$STRONGSWAN_CONF" <<'EOF'
charon {
    load_modular = yes
    plugins {
        kernel-netlink {
            mtu = 1400
            mss = 1360
        }
        include strongswan.d/charon/*.conf
    }
    syslog { identifier = charon }
    kernel-netlink { install_routes_xfrmi = yes }
}
include strongswan.d/*.conf
EOF

    # Determine swanctl.conf location
    if [ "$PKG_MANAGER" = "apt" ]; then
        SWANCTL_CONF="/etc/swanctl/swanctl.conf"
    else
        SWANCTL_CONF="/etc/strongswan/swanctl/swanctl.conf"
    fi
    
    # Write swanctl.conf
    cat > "$SWANCTL_CONF" <<EOF
authorities {
    ca {
        cacert = $SWANCTL_DIR/x509ca/ca.pem
    }
}
secrets {
    private-key {
        file = $SWANCTL_DIR/private/${keyname}
    }
}
connections {
    ike-$name {
        version = 2
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 300s
        proposals = aes256-sha256-ecp256, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521, aes256gcm16-sha256-ecp256
        remote_addrs = $vpn_server
        vips = 0.0.0.0
        local {
            auth = pubkey
            certs = $SWANCTL_DIR/x509/${certname}
            cacerts = ca.pem
        }
        remote {
            auth = pubkey
            revocation = relaxed
            id = $vpn_server
        }
        children {
            $name {
                if_id_in = 33 
                if_id_out = 33
                local_ts = 0.0.0.0/0
                remote_ts = 10.0.0.0/24
                mode = tunnel
                esp_proposals = aes256-sha256, aes256gcm16-ecp256, aes256gcm16, aes256-sha256-ecp256, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521
                updown = "/usr/libexec/strongswan/_updown"
            }
        }
        mobike = yes
        fragmentation = yes
    }
}
EOF

    echo "StrongSwan configuration written successfully."
}

# Setup routing table
setup_routing_table() {
    echo "Setting up routing table..."
    TABLE_ID=220
    if ! grep -q "$TABLE_ID vpn_table" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "$TABLE_ID vpn_table" >> /etc/iproute2/rt_tables || { 
            echo "Failed to add routing table to /etc/iproute2/rt_tables"; 
            exit 1; 
        }
        echo "Added routing table $TABLE_ID (vpn_table)"
    else
        echo "Routing table $TABLE_ID (vpn_table) already exists"
    fi
}

# Create the updown script
create_updown_script() {
    echo "Creating _updown script..."
    mkdir -p /usr/libexec/strongswan || { echo "Failed to create updown directory"; exit 1; }
    
    # Create log directory with appropriate permissions
    mkdir -p /var/log/strongswan
    chmod 755 /var/log/strongswan
    
    cat > /usr/libexec/strongswan/_updown << 'EOFUPDOWN'
#!/bin/bash

# --- Configuration ---
XFRM_INTERFACE="xfrm0"
XFRM_IF_ID="33"
TABLE_ID=220
MAIN_IFACE="MAIN_IFACE_PLACEHOLDER"
LOG_FILE="/var/log/strongswan/updown.log"
# ---------------------

# Ensure log file exists and is writable
touch "$LOG_FILE" 2>/dev/null || true
chmod 644 "$LOG_FILE" 2>/dev/null || true

log() {
    echo "$(date): $1" | tee -a "$LOG_FILE" 2>/dev/null || echo "$(date): $1"
}

log "Starting VPN setup script (PID: $$)..."
log "PLUTO_VERB: $PLUTO_VERB, PLUTO_MY_CLIENT: $PLUTO_MY_CLIENT, PLUTO_PEER: $PLUTO_PEER"

VPN_IP=$(echo "$PLUTO_MY_CLIENT" | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | head -1)
[ -z "$VPN_IP" ] && { log "ERROR: Failed to extract VPN_IP from $PLUTO_MY_CLIENT"; exit 1; }

already_setup() {
    ip link show "$XFRM_INTERFACE" &>/dev/null && \
    ip addr show "$XFRM_INTERFACE" | grep -q "$VPN_IP" && \
    ip route show table "$TABLE_ID" 2>/dev/null | grep -q "10.2.0.0/16" && \
    ip route show table "$TABLE_ID" 2>/dev/null | grep -q "10.0.0.0/16" && \
    ip rule show | grep -q "from $VPN_IP lookup $TABLE_ID" && \
    ip rule show | grep -q "to 10.2.0.0/16 lookup $TABLE_ID" && \
    ip rule show | grep -q "to 10.0.0.0/16 lookup $TABLE_ID"
}

manage_xfrm_interface() {
    if ! ip link show "$XFRM_INTERFACE" &>/dev/null; then
        log "Creating $XFRM_INTERFACE with if_id $XFRM_IF_ID..."
        ip link add "$XFRM_INTERFACE" type xfrm if_id "$XFRM_IF_ID" || { log "Failed to create $XFRM_INTERFACE"; return 1; }
        ip link set "$XFRM_INTERFACE" up || { log "Failed to bring up $XFRM_INTERFACE"; return 1; }
        log "Created $XFRM_INTERFACE successfully"
    fi
    
    if ! ip addr show "$XFRM_INTERFACE" | grep -q "$VPN_IP"; then
        log "Assigning $VPN_IP to $XFRM_INTERFACE"
        ip addr add "$VPN_IP/32" dev "$XFRM_INTERFACE" || log "Failed to add IP address"
    fi
    
    return 0
}

setup_routes() {
    log "Setting up routes..."
    
    # Routing table should already be set up by main script
    if ! grep -q "$TABLE_ID vpn_table" /etc/iproute2/rt_tables 2>/dev/null; then
        log "Warning: Routing table $TABLE_ID not found in /etc/iproute2/rt_tables. Should have been set up earlier."
    fi
    
    ip route show table "$TABLE_ID" 2>/dev/null | grep -q "10.250.0.0/16" || \
        ip route add 10.250.0.0/16 dev "$XFRM_INTERFACE" src "$VPN_IP" table "$TABLE_ID" || { log "Failed to add 10.250.0.0/16 route"; return 1; }
    
    ip route show table "$TABLE_ID" 2>/dev/null | grep -q "10.242.0.0/16" || \
        ip route add 10.242.0.0/16 dev "$XFRM_INTERFACE" src "$VPN_IP" table "$TABLE_ID" || { log "Failed to add 10.242.0.0/16 route"; return 1; }
    
    ip rule show | grep -q "from $VPN_IP lookup $TABLE_ID" || \
        ip rule add from "$VPN_IP" lookup "$TABLE_ID" prio 1000 || { log "Failed to add source rule"; return 1; }
    
    ip rule show | grep -q "to 10.250.0.0/16 lookup $TABLE_ID" || \
        ip rule add to 10.250.0.0/16 lookup "$TABLE_ID" prio 1001 || { log "Failed to add 10.250.0.0/16 rule"; return 1; }
    
    ip rule show | grep -q "to 10.242.0.0/16 lookup $TABLE_ID" || \
        ip rule add to 10.242.0.0/16 lookup "$TABLE_ID" prio 1002 || { log "Failed to add 10.242.0.0/16 rule"; return 1; }
    
    log "Routes setup complete"
    return 0
}

cleanup() {
    log "Cleaning up VPN resources..."
    
    if ip xfrm state | grep -q "if_id $XFRM_IF_ID"; then
        log "$XFRM_INTERFACE still in use by other SAs"
        return 0
    fi
    
    ip route flush table "$TABLE_ID" 2>/dev/null || log "Failed to flush table $TABLE_ID"
    ip rule del from "$VPN_IP" lookup "$TABLE_ID" prio 1000 2>/dev/null || true
    ip rule del to 10.250.0.0/16 lookup "$TABLE_ID" prio 1001 2>/dev/null || true
    ip rule del to 10.242.0.0/16 lookup "$TABLE_ID" prio 1002 2>/dev/null || true
    
    ip link show "$XFRM_INTERFACE" &>/dev/null && \
        ip link del "$XFRM_INTERFACE" 2>/dev/null && log "Removed $XFRM_INTERFACE" || log "Failed to delete $XFRM_INTERFACE"
}

case "$PLUTO_VERB" in
    up-client)
        already_setup && { log "VPN already configured"; exit 0; }
        manage_xfrm_interface && setup_routes || { log "Setup failed"; exit 1; }
        ;;
    down-client)
        cleanup
        ;;
    *)
        log "Unknown verb: $PLUTO_VERB"
        ;;
esac

log "Script completed for $PLUTO_VERB"
EOFUPDOWN

    sed -i "s/MAIN_IFACE_PLACEHOLDER/$MAIN_IFACE/g" /usr/libexec/strongswan/_updown
    chmod +x /usr/libexec/strongswan/_updown
    echo "_updown script created successfully."
}

# Create systemd service
create_systemd_service() {
    echo "Creating systemd service..."
    
    # Use command -v to find swanctl, with fallback
    SWANCTL_PATH=$(command -v swanctl || echo "/usr/sbin/swanctl")
    if [ ! -x "$SWANCTL_PATH" ]; then
        echo "Cannot find swanctl binary. Attempting to locate it..."
        SWANCTL_PATH="/usr/libexec/strongswan/swanctl"
        if [ ! -x "$SWANCTL_PATH" ]; then
            echo "swanctl not found in expected locations. Please ensure strongswan is installed correctly."
            exit 1
        fi
    fi
    echo "Using swanctl path: $SWANCTL_PATH"
    
    # Set a static STRONGSWAN_SERVICE name with fallback check
    STRONGSWAN_SERVICE="strongswan"
    if ! systemctl list-units --type=service | grep -q "$STRONGSWAN_SERVICE.service"; then
        echo "Warning: $STRONGSWAN_SERVICE.service not found. Checking alternatives..."
        if systemctl list-units --type=service | grep -q "strongswan-swanctl.service"; then
            STRONGSWAN_SERVICE="strongswan-swanctl"
        else
            echo "Using default $STRONGSWAN_SERVICE, but it may not exist yet."
        fi
    fi
    echo "Using StrongSwan service: $STRONGSWAN_SERVICE"
    
    cat > /etc/systemd/system/strongswan.client.service <<EOF
[Unit]
Description=StrongSwan IPsec VPN client connection
After=$STRONGSWAN_SERVICE.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "$SWANCTL_PATH --load-all && $SWANCTL_PATH --initiate --child $name"
ExecStop=/bin/bash -c "$SWANCTL_PATH --terminate --ike ike-$name"
RemainAfterExit=yes
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    echo "Systemd service created successfully."
}

# Enable and start services
start_services() {
    echo "Enabling and starting services..."
    
    # Stop and disable legacy starter if present
    if systemctl list-units --type=service | grep -q "strongswan-starter.service"; then
        systemctl stop strongswan-starter 2>/dev/null || true
        systemctl disable strongswan-starter 2>/dev/null || true
        echo "Disabled legacy strongswan-starter service."
    fi
    
    # Use a static STRONGSWAN_SERVICE name with verification
    STRONGSWAN_SERVICE="strongswan"
    if ! systemctl list-units --type=service | grep -q "$STRONGSWAN_SERVICE.service"; then
        if systemctl list-units --type=service | grep -q "strongswan-swanctl.service"; then
            STRONGSWAN_SERVICE="strongswan-swanctl"
        fi
    fi
    
    # Enable and start the strongswan service
    systemctl enable "$STRONGSWAN_SERVICE" || { 
        echo "Warning: Failed to enable $STRONGSWAN_SERVICE. It may not be installed correctly."; 
    }
    systemctl start "$STRONGSWAN_SERVICE" || { 
        echo "Warning: Failed to start $STRONGSWAN_SERVICE. Check 'systemctl status $STRONGSWAN_SERVICE' for details."; 
    }
    
    # Reload systemd
    systemctl daemon-reload || { echo "Warning: Failed to reload systemd daemon"; }
    
    # Enable and start the client service
    systemctl enable strongswan.client.service || { 
        echo "Warning: Failed to enable strongswan.client.service"; 
    }
    systemctl start strongswan.client.service || { 
        echo "Warning: Failed to start strongswan.client.service. Check logs with 'systemctl status strongswan.client.service' and 'journalctl -xeu strongswan.client.service'"; 
    }
    
    # Verify swanctl works
    SWANCTL_PATH=$(command -v swanctl || echo "/usr/sbin/swanctl")
    if [ -x "$SWANCTL_PATH" ]; then
        $SWANCTL_PATH --load-all || echo "Warning: Failed to load VPN configuration with swanctl"
    else
        echo "Warning: swanctl not found, skipping configuration load"
    fi
}

# Show final summary
show_summary() {
    IP_ADDRESS=$(ip -4 addr show dev "$MAIN_IFACE" | grep -oP 'inet \K[\d.]+' | head -1 || echo "unknown")
    HOSTNAME=$(hostname || echo "unknown")
    
    echo ""
    echo "=== VPN Client Setup Complete ==="
    echo "Host: $HOSTNAME ($IP_ADDRESS)"
    echo "Connection: $name to $vpn_server"
    echo "Interface: $MAIN_IFACE"
    echo "Target networks: 10.242.0.0/16, 10.250.0.0/16"
    echo ""
    echo "Commands to manage the VPN:"
    echo "  Check status:   systemctl status strongswan.client.service"
    echo "  View logs:      journalctl -u strongswan.client.service"
    echo "  Manual start:   systemctl start strongswan.client.service"
    echo "  Manual stop:    systemctl stop strongswan.client.service"
    echo "  Check tunnels:  swanctl --list-sas"
    echo ""
}

# Main function
main() {
    echo "=== Universal StrongSwan IKEv2 Client Setup ==="
    detect_os
    prompt_for_inputs
    install_packages
    extract_certificates
    configure_strongswan
    setup_routing_table  # New function call
    create_updown_script
    create_systemd_service
    start_services
    show_summary
    echo "Setup completed successfully."
}

main
