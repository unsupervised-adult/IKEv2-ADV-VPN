#!/bin/bash

# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
# =================================================================================================
# /usr/local/bin/ha_manager.sh
# HA Manager with dialog frontend that runs CLI scripts
#
# Author: Felix C Frank 2024
# Version: 1.7.50.1
# Created: 27-12-24
## feedback mailto:felix.c.frank@proton.me
###############################################################################
# Check for dialog
if ! command -v dialog &>/dev/null; then
    echo "Error: 'dialog' is not installed. Install it with 'sudo apt-get install dialog'."
    exit 1
fi

# Temporary file for dialog output
TEMP_FILE="/tmp/ha_manager_$$.tmp"
LOG_FILE="/var/log/ha_manager.log"
trap 'rm -f $TEMP_FILE' EXIT

# Default values
CONFIG_PATH="/etc/strongconn.conf"
PRIMARY_IP="192.168.1.100"
NGINX_IP="192.168.1.101"
SECONDARY_NODE="192.168.1.102"
HOSTNAME="vault-ha.example.com"
FLOATING_IPS="192.168.1.100,192.168.1.101"
DNS_NAMES="vault1.example.com,vault2.example.com"
TTL="85500h"

# Ensure running as root
[ "$EUID" -ne 0 ] && { echo "Run as root"; exit 1; }

# Function to display messages
show_msg() {
    dialog --msgbox "$1" 10 50
}

# Function to log actions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Main menu
main_menu() {
    while true; do
        dialog --menu "HA Manager" 15 50 6 \
            1 "Configure Parameters" \
            2 "Generate HA Server Certificate" \
            3 "Setup HA (Primary Node)" \
            4 "Setup HA (Secondary Node)" \
            5 "Teardown HA" \
            6 "Exit" 2> "$TEMP_FILE"
        
        choice=$(cat "$TEMP_FILE")
        case $choice in
            1) configure_params ;;
            2) generate_cert ;;
            3) setup_ha "primary" ;;
            4) setup_ha "secondary" ;;
            5) teardown_ha ;;
            6) break ;;
            *) show_msg "Invalid option" ;;
        esac
    done
}

# Configure parameters
configure_params() {
    dialog --form "Configure HA Parameters" 20 60 12 \
        "Config Path:" 1 1 "$CONFIG_PATH" 1 20 30 0 \
        "Primary IP (VPN):" 2 1 "$PRIMARY_IP" 2 20 15 0 \
        "NGINX IP:" 3 1 "$NGINX_IP" 3 20 15 0 \
        "Secondary Node IP:" 4 1 "$SECONDARY_NODE" 4 20 15 0 \
        "Certificate CN:" 5 1 "$HOSTNAME" 5 20 30 0 \
        "Floating IPs (comma-separated):" 6 1 "$FLOATING_IPS" 6 20 30 0 \
        "DNS Names (comma-separated):" 7 1 "$DNS_NAMES" 7 20 30 0 \
        "TTL (e.g., 85500h):" 8 1 "$TTL" 8 20 10 0 \
        2> "$TEMP_FILE"
    
    if [ $? -eq 0 ]; then
        mapfile -t params < "$TEMP_FILE"
        CONFIG_PATH="${params[0]}"
        PRIMARY_IP="${params[1]}"
        NGINX_IP="${params[2]}"
        SECONDARY_NODE="${params[3]}"
        HOSTNAME="${params[4]}"
        FLOATING_IPS="${params[5]}"
        DNS_NAMES="${params[6]}"
        TTL="${params[7]}"
        show_msg "Parameters updated successfully."
        log "Parameters updated: CONFIG_PATH=$CONFIG_PATH, PRIMARY_IP=$PRIMARY_IP, NGINX_IP=$NGINX_IP, SECONDARY_NODE=$SECONDARY_NODE, HOSTNAME=$HOSTNAME, FLOATING_IPS=$FLOATING_IPS, DNS_NAMES=$DNS_NAMES, TTL=$TTL"
    fi
}

# Generate HA server certificate
generate_cert() {
    # Write the certificate generation script with current parameters
    cat > /usr/local/bin/generate_ha_server_cert.sh <<EOF
#!/bin/bash
CONFIG_PATH="$CONFIG_PATH"
CERT_DIR="/opt/pki/x509"
PRIVATE_DIR="/opt/pki/private"
HOSTNAME="$HOSTNAME"
TTL="$TTL"
FLOATING_IPS="$FLOATING_IPS"
DNS_NAMES="$DNS_NAMES"

source "\$CONFIG_PATH"
if [[ -z "\$VAULT_TOKEN" || -z "\$PFX_PASSWORD" ]]; then
    echo "Error: VAULT_TOKEN or PFX_PASSWORD not set in \$CONFIG_PATH"
    exit 1
fi

echo "Checking for existing certificate for \$HOSTNAME..."
existing_cert=\$(sudo v-pki list | grep "\$HOSTNAME")
if [[ -n "\$existing_cert" ]]; then
    expiry=\$(echo "\$existing_cert" | grep -oP 'Expiry: \K.*GMT')
    if [[ -n "\$expiry" && \$(date -d "\$expiry" +%s) -gt \$(date +%s) ]]; then
        echo "Certificate for \$HOSTNAME is still valid. Expiry: \$expiry"
        exit 0
    fi
fi

echo "Generating HA server certificate for \$HOSTNAME with TTL \$TTL..."
response=\$(vault write -format=json pki/issue/vault \
    common_name="\$HOSTNAME" \
    ip_sans="\$FLOATING_IPS" \
    alt_names="\$DNS_NAMES" \
    ttl="\$TTL" \
    key_type="rsa" \
    key_bits=4096 \
    use_pss=true \
    key_usage="DigitalSignature,KeyEncipherment,KeyAgreement" \
    ext_key_usage="ServerAuth" \
    server_flag=true \
    client_flag=false)

if [[ \$? -ne 0 ]]; then
    echo "Error: Vault API request failed."
    echo "\$response"
    exit 1
fi

cert=\$(echo "\$response" | jq -r '.data.certificate')
key=\$(echo "\$response" | jq -r '.data.private_key')
ca_chain=\$(echo "\$response" | jq -r '.data.ca_chain[]')

if [[ -z "\$cert" || "\$cert" == "null" || -z "\$key" || "\$key" == "null" ]]; then
    echo "Error: Failed to retrieve certificate or key."
    exit 1
fi

mkdir -p "\$CERT_DIR" "\$PRIVATE_DIR"
cert_path="\$CERT_DIR/vault-ha.pem"
key_path="\$PRIVATE_DIR/vault-ha.key"
ca_path="\$CERT_DIR/ca.pem"

echo "\$cert" > "\$cert_path"
echo "\$key" > "\$key_path"
echo "\$ca_chain" > "\$ca_path"

p12_path="\$CERT_DIR/vault-ha.p12"
echo "Generating PKCS#12 file..."
openssl pkcs12 -export \
    -inkey "\$key_path" \
    -in "\$cert_path" \
    -certfile "\$ca_path" \
    -out "\$p12_path" \
    -password pass:"\$PFX_PASSWORD" || {
    echo "Error: Failed to generate PKCS#12 file."
    rm -f "\$cert_path" "\$key_path" "\$ca_path"
    exit 1
}

echo "Storing private key in Vault KV..."
vault kv put kv/private-keys/vault-ha private_key="\$(cat \$key_path)" || {
    echo "Error: Failed to store private key in Vault KV."
    exit 1
}

rm -f "\$cert_path" "\$key_path" "\$ca_path"
echo "HA server certificate generated successfully."
EOF

    chmod +x /usr/local/bin/generate_ha_server_cert.sh
    dialog --infobox "Generating HA server certificate..." 5 40
    /usr/local/bin/generate_ha_server_cert.sh >/tmp/cert_gen.log 2>&1
    if [ $? -eq 0 ]; then
        show_msg "Certificate generated successfully.\nCheck /tmp/cert_gen.log for details."
        log "Generated HA server certificate for $HOSTNAME"
    else
        dialog --textbox /tmp/cert_gen.log 20 60
        log "Failed to generate HA server certificate"
    fi
}

# Setup HA
setup_ha() {
    local role=$1
    dialog --yesno "Proceed with HA setup for $role node?" 7 40
    if [ $? -ne 0 ]; then return; fi

    # Write the setup script with current parameters
    cat > /usr/local/bin/setup_ha.sh <<EOF
#!/bin/bash
LOG_FILE="/var/log/ha_setup.log"
TIMESTAMP=\$(date '+%Y-%m-%d %H:%M:%S')
PRIMARY_IP="$PRIMARY_IP"
NGINX_IP="$NGINX_IP"
SECONDARY_NODE="$SECONDARY_NODE"
NODE_ROLE="$role"
# Store for other scripts
SECONDARY_NODE_IP="$SECONDARY_NODE"
WITNESS_IP=""  # Will be set during configuration if provided

log() { echo "[\$TIMESTAMP] \$1" | tee -a "\$LOG_FILE"; }
check_status() { [ \$? -eq 0 ] && log "SUCCESS: \$1" || { log "ERROR: \$1 failed"; exit 1; }; }

log "Starting HA setup for \$NODE_ROLE node"
apt-get update -y && apt-get install -y keepalived conntrackd
check_status "HA package installation"

# Create fencing script
cat > /usr/local/bin/fence_node.sh << 'EOF'
#!/bin/bash
# Simple fencing script for HA nodes
# Usage: fence_node.sh <target_ip> <action>
TARGET_IP="$1"
ACTION="$2"
LOG_FILE="/var/log/ha-fence.log"
FENCE_LOCK="/var/run/fence_in_progress.lock"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    logger -t ha-fence "$1"
}

# Prevent concurrent fence operations
if [ -f "$FENCE_LOCK" ]; then
    if [ $(( $(date +%s) - $(stat -c %Y "$FENCE_LOCK") )) -lt 300 ]; then
        log "Fence operation in progress, skipping"
        exit 1
    else
        log "Stale lock file found, removing"
        rm -f "$FENCE_LOCK"
    fi
fi

touch "$FENCE_LOCK"

case "$ACTION" in
    "status")
        # Check if target node is responsive
        if ping -c 3 -W 2 "$TARGET_IP" > /dev/null 2>&1; then
            log "Node $TARGET_IP is alive"
            rm -f "$FENCE_LOCK"
            exit 0
        else
            log "Node $TARGET_IP appears to be down"
            rm -f "$FENCE_LOCK"
            exit 1
        fi
        ;;
    "off")
        # First try a clean shutdown via SSH
        log "Attempting clean shutdown of $TARGET_IP via SSH"
        ssh -o ConnectTimeout=5 -o BatchMode=yes root@"$TARGET_IP" "systemctl stop keepalived; sleep 2; systemctl stop strongswan" > /dev/null 2>&1
        
        # Then try IPMI power off if available (would require additional setup)
        # ipmitool -H $TARGET_IP-ipmi -U admin -P password power off
        
        # Notify admin
        log "FENCING ACTION: Node $TARGET_IP has been fenced (services stopped)"
        rm -f "$FENCE_LOCK"
        exit 0
        ;;
    "on")
        # Start services on the target node
        log "Attempting to restart services on $TARGET_IP"
        ssh -o ConnectTimeout=5 -o BatchMode=yes root@"$TARGET_IP" "systemctl start strongswan; systemctl start keepalived" > /dev/null 2>&1
        log "Node $TARGET_IP services have been restarted"
        rm -f "$FENCE_LOCK"
        exit 0
        ;;
    *)
        log "Unknown action: $ACTION"
        rm -f "$FENCE_LOCK"
        exit 1
        ;;
esac
EOF
chmod +x /usr/local/bin/fence_node.sh
check_status "Fencing script installation"

# Create the witness check script if needed
setup_witness_node() {
    local WITNESS_IP="\$1"
    log "Setting up witness node configuration..."
    
    # Create the witness check script
    cat > /usr/local/bin/check_witness.sh << EOF
#!/bin/bash
# Script to check witness node for quorum
WITNESS_IP="\$WITNESS_IP"
LOG_FILE="/var/log/ha-witness.log"

log() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\$LOG_FILE"
}

# Check witness node availability
if ! ping -c 2 -W 1 "\$WITNESS_IP" > /dev/null 2>&1; then
    log "Witness node \$WITNESS_IP is unreachable"
    exit 1
fi

# Check witness node status file
WITNESS_STATUS=\$(ssh -o ConnectTimeout=2 -o BatchMode=yes root@"\$WITNESS_IP" "cat /var/lib/ha-witness/primary_node" 2>/dev/null)
if [ "\$WITNESS_STATUS" = "\$(hostname)" ]; then
    log "Witness confirms this node (\$(hostname)) should be primary"
    exit 0
else
    log "Witness does not confirm this node as primary (status: \$WITNESS_STATUS)"
    exit 1
fi
EOF
    chmod +x /usr/local/bin/check_witness.sh
    check_status "Witness check script"
}

# Ask about witness node
if [ "\$NODE_ROLE" = "primary" ]; then
    if [ -n "\$WITNESS_IP" ]; then
        setup_witness_node "\$WITNESS_IP"
    fi
fi

# Create split-brain detection and recovery script
cat > /usr/local/bin/detect_split_brain.sh <<'EOF'
#!/bin/bash
# Split-brain detection and recovery script
LOG_FILE="/var/log/split-brain.log"
CONFIG_FILE="/etc/ha_config.conf"

PRIMARY_NODE_IP=""
SECONDARY_NODE_IP=""
FLOATING_IP=""

# Source configuration if available
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
    logger -t split-brain "$1"
}

# Determine if we're in a split-brain state
detect_split_brain() {
    # If both nodes have the floating IP, we have a split-brain
    local my_status=$(ip addr show | grep -c "$FLOATING_IP")
    local other_ip="$SECONDARY_NODE_IP"
    
    # If this is the secondary node, check the primary
    if [ "$(hostname)" = "$SECONDARY_HOSTNAME" ]; then
        other_ip="$PRIMARY_NODE_IP"
    fi
    
    # If we have the floating IP, check if the other node also has it
    if [ "$my_status" -eq 1 ]; then
        if ping -c 1 -W 1 "$other_ip" > /dev/null 2>&1; then
            local other_status=$(ssh -o ConnectTimeout=2 -o BatchMode=yes root@"$other_ip" "ip addr show | grep -c '$FLOATING_IP'" 2>/dev/null)
            if [ "$other_status" -eq 1 ]; then
                log "SPLIT-BRAIN DETECTED: Both nodes have floating IP $FLOATING_IP"
                return 0
            fi
        fi
    fi
    
    return 1
}

# Resolve split-brain based on priority
resolve_split_brain() {
    local hostname=$(hostname)
    
    if [ "$hostname" = "$PRIMARY_HOSTNAME" ]; then
        log "This is the primary node, keeping services active"
        return 0
    elif [ "$hostname" = "$SECONDARY_HOSTNAME" ]; then
        log "This is the secondary node, stopping services to resolve split-brain"
        systemctl stop keepalived
        systemctl stop strongswan
        ip addr del "$FLOATING_IP/24" dev eth0 2>/dev/null
        log "Services stopped on secondary node to resolve split-brain"
        return 0
    else
        log "Unknown hostname: $hostname, cannot determine which node should be primary"
        return 1
    fi
}

# Main execution
if detect_split_brain; then
    log "Attempting to resolve split-brain condition"
    resolve_split_brain
else
    # No split-brain detected
    exit 0
fi
EOF
chmod +x /usr/local/bin/detect_split_brain.sh
check_status "Split-brain detection script"

# Create HA health check script with deadman switch
cat > /usr/local/bin/ha_health_check.sh <<'EOF'
#!/bin/bash
# HA node health check script with deadman switch
LOG_FILE="/var/log/ha-health.log"
DEADMAN_FILE="/var/run/ha_deadman"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Check system health indicators
check_health() {
    # Check CPU load
    local load=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' ')
    if (( $(echo "$load > 4.0" | bc -l) )); then
        log "High system load: $load"
        return 1
    fi
    
    # Check free memory
    local free_mem=$(free -m | awk '/^Mem:/ {print $4}')
    if [ "$free_mem" -lt 200 ]; then
        log "Low free memory: ${free_mem}MB"
        return 1
    fi
    
    # Check disk space
    local disk_space=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
    if [ "$disk_space" -gt 90 ]; then
        log "Low disk space: ${disk_space}%"
        return 1
    fi
    
    # Check strongswan process health
    if ! pgrep charon > /dev/null; then
        log "StrongSwan charon process not running"
        return 1
    fi
    
    # Check if IPsec connections can be listed
    if ! timeout 5 swanctl -l > /dev/null 2>&1; then
        log "Cannot list StrongSwan connections"
        return 1
    fi
    
    return 0
}

# Update deadman switch
update_deadman() {
    if check_health; then
        # Node is healthy, touch deadman file
        touch "$DEADMAN_FILE"
        log "Node health check passed, deadman file updated"
        return 0
    else
        log "Node health check failed"
        return 1
    fi
}

# Check deadman switch age
check_deadman() {
    if [ -f "$DEADMAN_FILE" ]; then
        local age=$(( $(date +%s) - $(stat -c %Y "$DEADMAN_FILE") ))
        if [ "$age" -gt 300 ]; then
            log "WARNING: Deadman switch expired (age: ${age}s)"
            return 1
        else
            return 0
        fi
    else
        log "WARNING: Deadman switch file not found"
        return 1
    fi
}

# Main execution
update_deadman
if ! check_deadman; then
    log "CRITICAL: Deadman check failed, forcing node to backup role"
    systemctl stop keepalived
    systemctl stop strongswan
    log "Services stopped to prevent split-brain"
fi
EOF
chmod +x /usr/local/bin/ha_health_check.sh
check_status "Health check script"

# Create fault handler script
cat > /usr/local/bin/vpn_fault.sh <<'EOF'
#!/bin/bash
# Fault handler script for keepalived
LOG_FILE="/var/log/ha-fault.log"
CONFIG_FILE="/etc/ha_config.conf"

# Source configuration if available
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
    logger -t ha-fault "$1"
}

log "FAULT condition detected - potential split-brain scenario"

# Check if other node is active before taking action
OTHER_NODE_IP="$SECONDARY_NODE_IP"
if [ "$(hostname)" = "$SECONDARY_HOSTNAME" ]; then
    OTHER_NODE_IP="$PRIMARY_NODE_IP"
fi

if ping -c 3 -W 2 "$OTHER_NODE_IP" > /dev/null 2>&1; then
    log "Other node is reachable, checking its status"
    
    # Check if the other node is already MASTER
    OTHER_NODE_STATE=$(ssh -o ConnectTimeout=3 -o BatchMode=yes root@"$OTHER_NODE_IP" "grep -A 1 'Keepalived' /var/log/ha_monitor.log | tail -1 | grep -c 'MASTER'" 2>/dev/null)
    
    if [ "$OTHER_NODE_STATE" = "1" ]; then
        log "Other node is already MASTER, stopping strongswan and keepalived on this node"
        systemctl stop strongswan
        systemctl stop keepalived
    else
        log "Other node is NOT master, continuing fail detection"
    fi
else
    log "Other node is unreachable, treating as legitimate failover scenario"
fi

# Record the fault for later analysis
echo "Fault detected at $(date)" >> /var/log/ha_faults.log
EOF
chmod +x /usr/local/bin/vpn_fault.sh
check_status "Fault handler script"

# Create configuration file for HA scripts
cat > /etc/ha_config.conf <<EOF
# HA configuration
PRIMARY_HOSTNAME=\$(hostname)
PRIMARY_NODE_IP=\$PRIMARY_IP
SECONDARY_HOSTNAME=\$SECONDARY_NODE
SECONDARY_NODE_IP=\$SECONDARY_NODE
FLOATING_IP=\$PRIMARY_IP
EOF
check_status "HA configuration file"

# Add cron jobs for split-brain prevention
echo "* * * * * root /usr/local/bin/detect_split_brain.sh >/dev/null 2>&1" > /etc/cron.d/split-brain-check
echo "* * * * * root /usr/local/bin/ha_health_check.sh >/dev/null 2>&1" > /etc/cron.d/ha-health-check
chmod 644 /etc/cron.d/split-brain-check /etc/cron.d/ha-health-check

# Create modified keepalived.conf with split-brain prevention
cat > /etc/keepalived/keepalived.conf <<KEEPALIVED
global_defs {
    router_id strongswan_ha
    script_user root
    enable_script_security
    
    # Force VRRP to use unicast to prevent multicast issues
    vrrp_strict
    vrrp_iptables
    
    # Unique instance names and router IDs
    max_auto_priority
}

# Adding nopreempt to prevent automatic failback
vrrp_instance VPN_1 {
    state \$( [ "\$NODE_ROLE" = "primary" ] && echo "MASTER" || echo "BACKUP" )
    interface eth0
    virtual_router_id 51
    priority \$( [ "\$NODE_ROLE" = "primary" ] && echo "100" || echo "90" )
    advert_int 1
    nopreempt
    
    # Use unicast for more reliable communication
    unicast_src_ip \$( [ "\$NODE_ROLE" = "primary" ] && echo "$PRIMARY_IP" || echo "$SECONDARY_NODE" )
    unicast_peer {
        \$( [ "\$NODE_ROLE" = "primary" ] && echo "$SECONDARY_NODE" || echo "$PRIMARY_IP" )
    }
    
    authentication {
        auth_type PASS
        auth_pass StrongSecretHere
    }
    virtual_ipaddress {
        $PRIMARY_IP/24
    }
    track_script {
        chk_strongswan
    }
    notify_master "/usr/local/bin/vpn_master.sh"
    notify_backup "/usr/local/bin/vpn_backup.sh"
    notify_fault "/usr/local/bin/vpn_fault.sh"
}

vrrp_script chk_strongswan {
    script "/usr/local/bin/check_strongswan.sh"
    interval 5
    weight 2
    fall 2
    rise 2
}

vrrp_instance WEB_1 {
    state \$( [ "\$NODE_ROLE" = "primary" ] && echo "MASTER" || echo "BACKUP" )
    interface eth0
    virtual_router_id 52
    priority \$( [ "\$NODE_ROLE" = "primary" ] && echo "100" || echo "90" )
    advert_int 1
    nopreempt
    unicast_src_ip \$( [ "\$NODE_ROLE" = "primary" ] && echo "$PRIMARY_IP" || echo "$SECONDARY_NODE" )
    unicast_peer {
        \$( [ "\$NODE_ROLE" = "primary" ] && echo "$SECONDARY_NODE" || echo "$PRIMARY_IP" )
    }
    authentication {
        auth_type PASS
        auth_pass NginxSecretHere
    }
    virtual_ipaddress {
        $NGINX_IP/24
    }
    track_script {
        chk_nginx
    }
    notify_master "/usr/local/bin/nginx_master.sh"
    notify_fault "/usr/local/bin/vpn_fault.sh"
}

vrrp_script chk_nginx {
    script "/usr/local/bin/check_nginx.sh"
    interval 5
    weight 2
    fall 2
    rise 2
}
KEEPALIVED
check_status "Enhanced Keepalived config with split-brain prevention"

# Add witness check to keepalived.conf if witness IP is provided
if [ -n "\$WITNESS_IP" ]; then
    sed -i '/track_script {/a\\        witness_check' /etc/keepalived/keepalived.conf
    sed -i '/vrrp_script chk_strongswan/i\\vrrp_script witness_check {\n    script "/usr/local/bin/check_witness.sh"\n    interval 5\n    weight 10\n    fall 2\n    rise 2\n}' /etc/keepalived/keepalived.conf
    check_status "Witness check configuration"
fi

cat > /usr/local/bin/check_strongswan.sh <<'EOF'
#!/bin/bash
systemctl is-active --quiet strongswan && timeout 5 swanctl -L >/dev/null 2>&1 && exit 0 || exit 1
EOF

cat > /usr/local/bin/vpn_master.sh <<'EOF'
#!/bin/bash
logger -t keepalived "Transitioning to MASTER"
systemctl start strongswan
arping -c 5 -U -I eth0 "$PRIMARY_IP"
sleep 2
swanctl --load-all
conntrackd -c /etc/conntrackd/conntrackd.conf -C -f -R -n
EOF

cat > /usr/local/bin/vpn_backup.sh <<'EOF'
#!/bin/bash
logger -t keepalived "Transitioning to BACKUP"
conntrackd -c /etc/conntrackd/conntrackd.conf -C
EOF

cat > /etc/conntrackd/conntrackd.conf <<EOF
General { HashSize 32768 MaxEntries 65536 FilterAccept ESTABLISHED -p udp FilterAccept ESTABLISHED -p esp }
Sync { Mode FTFW { DisableExternalCache Off } UDP { IPv4_address \$( [ "\$NODE_ROLE" = "primary" ] && echo "192.168.1.101" || echo "$SECONDARY_NODE" ) IPv4_Destination_Address $SECONDARY_NODE Port 3780 Interface eth0 } }
EOF
check_status "StrongSwan scripts and conntrackd config"

mkdir -p /etc/vault/tls /var/lib/vault/data
cat > /etc/vault/config.hcl <<EOF
storage "raft" {
    path = "/var/lib/vault/data"
    node_id = "vault_\$NODE_ROLE"
    retry_join { leader_api_addr = "https://vault1.example.com:8200" }
    retry_join { leader_api_addr = "https://vault2.example.com:8200" }
}
listener "tcp" { address = "0.0.0.0:8200" tls_cert_file = "/opt/pki/x509/vault-ha.pem" tls_key_file = "/opt/pki/private/vault-ha.key" }
api_addr = "https://vault\${NODE_ROLE}.example.com:8200"
cluster_addr = "https://vault\${NODE_ROLE}.example.com:8201"
ui = true
seal "awskms" { region = "us-west-2" kms_key_id = "alias/vault-unseal-key" }
EOF
check_status "Vault config"
systemctl disable vault-unseal.service 2>/dev/null || true
log "Disabled default vault-unseal.service"

cat > /usr/local/bin/check_nginx.sh <<'EOF'
#!/bin/bash
systemctl is-active --quiet nginx && exit 0 || exit 1
EOF

cat > /usr/local/bin/nginx_master.sh <<'EOF'
#!/bin/bash
logger -t keepalived "NGINX to MASTER"
v-pki set-permissions
systemctl restart nginx
EOF
check_status "NGINX scripts"

cat > /usr/local/bin/sync_ha_config.sh <<'EOF'
#!/bin/bash
PRIMARY_IP="$PRIMARY_IP"
SECONDARY_NODE="$SECONDARY_NODE"
LOG_TAG="ha_config_sync"

ip addr show eth0 | grep -q "\$PRIMARY_IP" || { logger -t "\$LOG_TAG" "Not primary, skipping"; exit 0; }
declare -A SYNC_PATHS=(
    ["/etc/swanctl/"]="StrongSwan configs"
    ["/etc/strongswan.d/"]="StrongSwan settings"
    ["/etc/strongswan.conf"]="StrongSwan main config"
    ["/etc/strongconn.conf"]="Connection config"
    ["/etc/nftables.conf"]="NFTables rules"
    ["/etc/nftables.d/"]="NFTables extras"
    ["/opt/pki/"]="All PKI certs and keys"
    ["/etc/suricata/rules/"]="Suricata rules"
    ["/var/lib/suricata/rules/"]="Suricata runtime"
    ["/etc/ha_config.conf"]="HA configuration"
)

sync_directory() {
    rsync -avz --delete "\$1" "root@\$SECONDARY_NODE:\$1" 2>/dev/null && \
    logger -t "\$LOG_TAG" "Synced \$2" || logger -t "\$LOG_TAG" "Failed \$2"
}

sync_nft_sets() {
    local tmp_dir="/tmp/nft_sync"; mkdir -p "\$tmp_dir"
    nft list set inet firewall blacklisted_ips > "\$tmp_dir/blacklisted_ips.txt"
    nft list set inet firewall whitelisted_ips > "\$tmp_dir/whitelisted_ips.txt"
    nft list map inet firewall zone_members > "\$tmp_dir/zone_members.txt"
    scp "\$tmp_dir/"*.txt "root@\$SECONDARY_NODE:\$tmp_dir/" 2>/dev/null
    ssh "root@\$SECONDARY_NODE" "nft flush set inet firewall blacklisted_ips; nft -f \$tmp_dir/blacklisted_ips.txt; \
        nft flush set inet firewall whitelisted_ips; nft -f \$tmp_dir/whitelisted_ips.txt; \
        nft flush map inet firewall zone_members; nft -f \$tmp_dir/zone_members.txt" 2>/dev/null && \
    logger -t "\$LOG_TAG" "Synced NFTables sets" || logger -t "\$LOG_TAG" "Failed NFTables sets"
    rm -rf "\$tmp_dir"
}

for path in "\${!SYNC_PATHS[@]}"; do sync_directory "\$path" "\${SYNC_PATHS[\$path]}"; done
sync_nft_sets
ssh "root@\$SECONDARY_NODE" "v-pki set-permissions" 2>/dev/null && logger -t "\$LOG_TAG" "Set permissions on secondary" || logger -t "\$LOG_TAG" "Failed to set permissions on secondary"
v-pki set-permissions 2>/dev/null && logger -t "\$LOG_TAG" "Set permissions on primary" || logger -t "\$LOG_TAG" "Failed to set permissions on primary"
logger -t "\$LOG_TAG" "Sync completed at \$(date)"
EOF
check_status "Sync script deployment"
echo "*/5 * * * * /usr/local/bin/sync_ha_config.sh" | crontab -

cat > /usr/local/bin/monitor_ha.sh <<'EOF'
#!/bin/bash
LOG_FILE="/var/log/ha_monitor.log"
echo "=== HA Status (\$(date)) ===" | tee -a "\$LOG_FILE"
echo "Node: \$(hostname)" | tee -a "\$LOG_FILE"
for svc in keepalived strongswan nginx suricata vault; do
    systemctl is-active --quiet "\$svc" && echo "\$svc: RUNNING" || echo "\$svc: STOPPED"
done | tee -a "\$LOG_FILE"
ip addr show | grep -q "$PRIMARY_IP" && echo "Role: ACTIVE" || echo "Role: STANDBY" | tee -a "\$LOG_FILE"
echo "VPN Connections: \$(swanctl -l | grep ESTABLISHED | wc -l)" | tee -a "\$LOG_FILE"
curl -s -o /dev/null https://127.0.0.1:8200/v1/sys/health && echo "Vault: HEALTHY" || echo "Vault: UNHEALTHY" | tee -a "\$LOG_FILE"
echo "Last Sync: \$(grep ha_config_sync /var/log/syslog | tail -1)" | tee -a "\$LOG_FILE"
echo "Split-Brain Checks: \$(grep -c 'split-brain' /var/log/split-brain.log 2>/dev/null || echo '0')" | tee -a "\$LOG_FILE"
echo "Deadman Switch: \$([ -f /var/run/ha_deadman ] && echo 'ACTIVE' || echo 'MISSING')" | tee -a "\$LOG_FILE"
EOF
check_status "Enhanced monitor script deployment"
echo "0 * * * * /usr/local/bin/monitor_ha.sh" | crontab -u root -

cat > /usr/local/bin/backup_vpn.sh <<'EOF'
#!/bin/bash
LOG_FILE="/var/log/ha_backup.log"
BACKUP_DIR="/backup/vpn_\$(date +%Y%m%d_%H%M)"
mkdir -p "\$BACKUP_DIR"
echo "[\$(date)] Starting backup" >> "\$LOG_FILE"
tar -czf "\$BACKUP_DIR/configs.tar.gz" /etc/swanctl /etc/strongswan* /etc/nftables* /etc/keepalived /etc/ha_config.conf 2>/dev/null && \
    echo "[\$(date)] Configs backed up" >> "\$LOG_FILE" || echo "[\$(date)] Configs backup failed" >> "\$LOG_FILE"
tar -czf "\$BACKUP_DIR/pki.tar.gz" /opt/pki 2>/dev/null && \
    echo "[\$(date)] PKI backed up" >> "\$LOG_FILE" || echo "[\$(date)] PKI backup failed" >> "\$LOG_FILE"
systemctl stop vault
tar -czf "\$BACKUP_DIR/vault.tar.gz" /var/lib/vault/data 2>/dev/null && \
    echo "[\$(date)] Vault data backed up" >> "\$LOG_FILE" || echo "[\$(date)] Vault data backup failed" >> "\$LOG_FILE"
systemctl start vault
sleep 5
if ! curl -s -o /dev/null https://127.0.0.1:8200/v1/sys/health; then
    echo "[\$(date)] Vault auto-unseal failed, attempting v-pki" >> "\$LOG_FILE"
    v-pki unseal-vault 2>/dev/null && echo "[\$(date)] Vault unsealed with v-pki" >> "\$LOG_FILE" || \
        echo "[\$(date)] Vault unseal failed, manual intervention required" >> "\$LOG_FILE"
else
    echo "[\$(date)] Vault auto-unsealed successfully" >> "\$LOG_FILE"
fi
rsync -avz "\$BACKUP_DIR" backup-server:/backups/ 2>/dev/null && \
    echo "[\$(date)] Backup synced" >> "\$LOG_FILE" || echo "[\$(date)] Backup sync failed" >> "\$LOG_FILE"
find /backup -type d -name "vpn_*" -mtime +7 -exec rm -rf {} \; 2>/dev/null
echo "[\$(date)] Backup completed" >> "\$LOG_FILE"
EOF
check_status "Backup script deployment"
echo "0 2 * * * /usr/local/bin/backup_vpn.sh" | crontab -u root -

# Set up SSH key-based authentication between nodes
if [ "\$NODE_ROLE" = "primary" ]; then
    # Generate SSH key if it doesn't exist
    if [ ! -f /root/.ssh/id_rsa ]; then
        ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa
    fi
    
    # Copy SSH key to secondary node
    ssh-copy-id -i /root/.ssh/id_rsa.pub root@\$SECONDARY_NODE 2>/dev/null || log "WARNING: SSH key copy failed - manual setup may be required"
    
    # Set up a witness node if specified
    if [ -n "\$WITNESS_IP" ]; then
        setup_witness_node "\$WITNESS_IP"
    fi
fi

if [ "\$NODE_ROLE" = "primary" ]; then
    v-pki set-permissions 2>/dev/null && log "Initial permissions set on primary" || log "WARNING: v-pki set-permissions failed on primary"
    rsync -avz --delete /opt/pki/ "root@\$SECONDARY_NODE:/opt/pki/" 2>/dev/null && log "Initial PKI sync to secondary" || log "WARNING: Initial PKI sync failed"
    ssh "root@\$SECONDARY_NODE" "v-pki set-permissions" 2>/dev/null && log "Initial permissions set on secondary" || log "WARNING: v-pki set-permissions failed on secondary"
else
    v-pki set-permissions 2>/dev/null && log "Initial permissions set on secondary" || log "WARNING: v-pki set-permissions failed on secondary"
fi

# Initialize deadman switch
touch /var/run/ha_deadman

chmod +x /usr/local/bin/{check_strongswan.sh,vpn_master.sh,vpn_backup.sh,check_nginx.sh,nginx_master.sh,sync_ha_config.sh,monitor_ha.sh,backup_vpn.sh,detect_split_brain.sh,ha_health_check.sh,vpn_fault.sh}
chmod 600 /etc/keepalived/keepalived.conf /etc/conntrackd/conntrackd.conf /etc/vault/config.hcl /etc/ha_config.conf
chown root:root /etc/keepalived/keepalived.conf /etc/conntrackd/conntrackd.conf /etc/vault/config.hcl /etc/ha_config.conf /usr/local/bin/*.sh
check_status "Permission settings"

systemctl enable keepalived strongswan nginx suricata vault
systemctl restart keepalived strongswan nginx suricata vault
sleep 5
curl -s -o /dev/null https://127.0.0.1:8200/v1/sys/health && log "Vault auto-unsealed" || \
    { log "Vault auto-unseal failed, trying v-pki"; v-pki unseal-vault 2>/dev/null && log "Vault unsealed with v-pki" || log "WARNING: Vault sealed, manual unseal needed"; }
check_status "Service startup"

log "HA setup completed for \$NODE_ROLE node with split-brain prevention mechanisms"
EOF

    chmod +x /usr/local/bin/setup_ha.sh
    dialog --infobox "Setting up HA for $role node..." 5 40
    /usr/local/bin/setup_ha.sh >/tmp/setup_ha.log 2>&1
    if [ $? -eq 0 ]; then
        show_msg "HA setup completed for $role node.\nCheck /var/log/ha_setup.log for details."
        log "HA setup completed for $role node with split-brain prevention"
    else
        dialog --textbox /tmp/setup_ha.log 20 60
        log "HA setup failed for $role node"
    fi
}

# Teardown HA
teardown_ha() {
    dialog --yesno "Are you sure you want to tear down the HA setup?\nThis will stop services and remove configurations." 10 50
    if [ $? -ne 0 ]; then return; fi

    dialog --infobox "Tearing down HA setup..." 5 40
    systemctl stop keepalived strongswan nginx suricata vault 2>/dev/null
    rm -f /etc/keepalived/keepalived.conf \
          /etc/conntrackd/conntrackd.conf \
          /etc/vault/config.hcl \
          /usr/local/bin/check_strongswan.sh \
          /usr/local/bin/vpn_master.sh \
          /usr/local/bin/vpn_backup.sh \
          /usr/local/bin/check_nginx.sh \
          /usr/local/bin/nginx_master.sh \
          /usr/local/bin/sync_ha_config.sh \
          /usr/local/bin/monitor_ha.sh \
          /usr/local/bin/backup_vpn.sh 2>/dev/null
    crontab -r 2>/dev/null
    log "HA setup torn down"
    show_msg "HA setup has been torn down."
}

# Start the main menu
main_menu