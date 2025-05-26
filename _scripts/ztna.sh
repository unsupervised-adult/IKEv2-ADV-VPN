#!/bin/bash

#############################################################################@#
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
###############################################################################
# ZTNA Setup Script for StrongSwan IKEv2 VPN Gateway
# Defines zones for ZTNA, uses XFRM policies, interfaces, and nftables IP sets for dynamic access control
# Each client gets a /32 from ZTNA_IP_POOL, isolated via XFRM and ipset, not subnet-based
# Integrates with base nftables via /etc/nftables.d/ztna.conf; non-ZTNA users (e.g., road warriors) unaffected

# Author: Felix C Frank 2024
# Version: 1.7.50.2
# Created: 27-03-2025
# Updated: 25-03-2025 - Improved dialog UI consistency and usability
## feedback mailto:felix.c.frank@proton.me
###############################################################################
# Configuration paths
BASE_CONFIG="/etc/strongconn.conf"
ZTNA_CONFIG_DIR="/etc/zt/ztna.conf"
ZONES_CONFIG="$ZTNA_CONFIG_DIR/zones.conf"
POLICY_CONF="/etc/nftables.d/ztna.conf"
UPDOWN_SCRIPT="/var/lib/strongswan/ztna-updown.sh"
ZTNA_CONF="/etc/swanctl/conf.d/ztna.conf"
RADIUS_CONF="/etc/strongswan.d/charon/eap-radius.conf"
LOG_FILE="/var/log/ztna/ztna-setup.log"
UPDOWN_LOG_FILE="/var/log/ztna/ztna-updown.log"

# Boundary configuration constants
readonly BOUNDARY_API_PORT=9200
readonly BOUNDARY_PROXY_PORT=9204
readonly BOUNDARY_CLUSTER_PORT=9203
readonly BOUNDARY_DEFAULT_INSTALL_DIR="/opt/boundary"
readonly BOUNDARY_DEFAULT_CONFIG_DIR="/etc/boundary"
readonly BOUNDARY_DEFAULT_DATA_DIR="/var/lib/boundary"
readonly BOUNDARY_DEFAULT_DB_PATH="$BOUNDARY_DEFAULT_DATA_DIR/boundary.db"
readonly BOUNDARY_DEFAULT_TOKEN_PATH="$BOUNDARY_DEFAULT_CONFIG_DIR/vault-token"
readonly DEFAULT_BOUNDARY_UI_URL_TEMPLATE="https://%s:${BOUNDARY_API_PORT}"
readonly VAULT_DEFAULT_ADDR="https://127.0.0.1:8200"
readonly VAULT_DEFAULT_TRANSIT_PATH="transit"
readonly REQUIRED_BOUNDARY_KEYS=("boundary_root" "boundary_worker_auth" "boundary_recovery")

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

load_config() {
    local CONFIG_PATH="$1"
    if [ -f "$CONFIG_PATH" ]; then
        . "$CONFIG_PATH"
    else
        error_exit "Configuration file not found at $CONFIG_PATH"
    fi

    [ -z "$VAULT_TOKEN" ] >/dev/null 2>&1
    [ -z "$TEMP_CERT_DIR" ] && error_exit "TEMP_CERT_DIR is not set in the configuration file."
    [ -z "$CERT_DIR" ] && error_exit "CERT_DIR is not set in the configuration file."
    [ -z "$PRIVATE_DIR" ] && error_exit "PRIVATE_DIR is not set in the configuration file."
    [ -z "$CA_DIR" ] && error_exit "CA_DIR is not set in the configuration file."
    [ -z "$CRL_DIR" ] && error_exit "CRL_DIR is not set in the configuration file."

}
# Ensure log and script directories exist
mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$UPDOWN_LOG_FILE")" "/var/lib/strongswan" "/etc/strongswan.d/charon" 2>/dev/null

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Error handling function
error_exit() {
    log "ERROR: $1"
    echo "ERROR: $1" >&2
    exit 1
}

# Standardized error handling for Boundary
boundary_error() {
    local msg="$1"
    local exit_code="${2:-1}"
    
    log "ERROR: $msg"
    
    # Show dialog only in interactive mode
    if [[ -n "$DISPLAY" || -n "$TERM" ]] && command -v dialog &>/dev/null; then
        dialog --title "Boundary Error" --msgbox "$msg" 8 60 2>/dev/null || true
    fi
    
    exit "$exit_code"
}

# Progress tracking functions
update_progress() {
    local percent="$1"
    local message="$2"
    local progress_file="${3:-/tmp/boundary_progress}"
    
    [[ "$percent" =~ ^[0-9]+$ ]] || percent=0  # Ensure valid number
    [[ "$percent" -gt 100 ]] && percent=100
    [[ "$percent" -lt 0 ]] && percent=0
    
    echo "$percent" > "$progress_file"
    echo "$message" > "${progress_file}.msg"
    log "$message"
}

show_progress_dialog() {
    local title="$1"
    local progress_file="${2:-/tmp/boundary_progress}"
    local pid="$3"
    
    [[ -z "$pid" ]] && return 1  # Ensure PID is provided
    
    echo "0" > "$progress_file"
    echo "Starting..." > "${progress_file}.msg"
    
    (
        while [[ -e "$progress_file" && -d "/proc/$pid" ]]; do
            local percent=$(cat "$progress_file" 2>/dev/null || echo "0")
            local message=$(cat "${progress_file}.msg" 2>/dev/null || echo "Working...")
            
            echo "XXX"
            echo "$percent"
            echo "$message"
            echo "XXX"
            sleep 0.5
        done
    ) | dialog --title "$title" --gauge "Starting..." 10 70 0 2>/dev/null || true
    
    rm -f "$progress_file" "${progress_file}.msg"
}

# Basic permissions setup for Boundary
ensure_boundary_permissions() {
    log "Setting up basic permissions for Boundary"
    
    # Create boundary user and group if they don't exist
    id -u boundary &>/dev/null || useradd -r -d /var/lib/boundary -m -s /sbin/nologin boundary
    
    # Create required directories with proper permissions
    for dir in /etc/boundary /var/lib/boundary /etc/boundary/zones; do
        mkdir -p "$dir"
        chown boundary:boundary "$dir"
        chmod 750 "$dir"
    done
    
    # Set up certificate symlinks if possible
    if [ -d "/etc/ssl/certs" ] && [ -f "/etc/ssl/private/server-key.pem" ]; then
        ln -sf /etc/ssl/certs/server-cert.pem /etc/boundary/server-cert.pem
        ln -sf /etc/ssl/private/server-key.pem /etc/boundary/server-key.pem
        ln -sf /etc/ssl/certs/ca.pem /etc/boundary/ca.pem
        chown boundary:boundary /etc/boundary/server-cert.pem /etc/boundary/server-key.pem /etc/boundary/ca.pem
    else
        log "WARNING: SSL certificates not found in standard locations"
    fi
    
    log "Basic permissions setup for Boundary completed"
}

# Initialize a Boundary zone
init_boundary_zone() {
    local zone_id="$1"
    local zone_name="$2"
    local zone_resources="$3"
    local boundary_bin="$4"
    local boundary_addr="$5"
    local zone_dir="/etc/boundary/zones/$zone_id"
    
    log "Initializing Boundary zone '$zone_name' (ID: $zone_id)"
    
    # Create zone directory if it doesn't exist
    mkdir -p "$zone_dir"
    chown boundary:boundary "$zone_dir"
    
    # Generate admin password
    local admin_password=$(openssl rand -base64 12)
    
    # Create initialization script
    log "Creating zone initialization script for '$zone_name' in $zone_dir"
    
    cat > "$zone_dir/init-zone.sh" << EOF
#!/bin/bash
# Boundary zone initialization script for '$zone_name'
# Generated on $(date)

export BOUNDARY_ADDR="$boundary_addr"
BOUNDARY_BIN="$boundary_bin"
ZONE_NAME="$zone_name"
ZONE_ID="$zone_id"

echo "Starting initialization for zone $zone_name (ID: $zone_id)"
echo "Using Boundary API at $boundary_addr"

# Create initial auth method and admin user if not already done
SCOPE_ID=\$(\$BOUNDARY_BIN scopes list -format json | jq -r '.items[] | select(.name=="global") | .id')
if [ -n "\$SCOPE_ID" ]; then
    echo "Found global scope: \$SCOPE_ID"
    
    # Check if auth method exists
    AUTH_METHOD_ID=\$(\$BOUNDARY_BIN auth-methods list -scope-id \$SCOPE_ID -format json | jq -r '.items[] | select(.name=="ztna-password") | .id')
    
    if [ -z "\$AUTH_METHOD_ID" ]; then
        echo "Creating password auth method..."
        AUTH_METHOD_ID=\$(\$BOUNDARY_BIN auth-methods create password -name "ztna-password" -description "ZTNA Zone $zone_name Authentication" -scope-id \$SCOPE_ID -format json | jq -r '.item.id')
        if [ -z "\$AUTH_METHOD_ID" ]; then
            echo "ERROR: Failed to create auth method"
            exit 1
        fi
        echo "Created auth method: \$AUTH_METHOD_ID"
    else
        echo "Auth method already exists: \$AUTH_METHOD_ID"
    fi
    
    # Create admin user for this zone if not already created
    ADMIN_ACCT=\$(\$BOUNDARY_BIN accounts list -auth-method-id \$AUTH_METHOD_ID -format json | jq -r '.items[] | select(.name=="admin-$zone_id") | .id')
    
    if [ -z "\$ADMIN_ACCT" ]; then
        echo "Creating admin user for zone $zone_name..."
        USER_ID=\$(\$BOUNDARY_BIN users create -name "admin-$zone_id" -description "Admin for ZTNA Zone $zone_name" -scope-id \$SCOPE_ID -format json | jq -r '.item.id')
        if [ -z "\$USER_ID" ]; then
            echo "ERROR: Failed to create admin user"
            exit 1
        fi
        
        ACCOUNT_ID=\$(\$BOUNDARY_BIN accounts create password -name "admin-$zone_id" -description "Admin account for ZTNA Zone $zone_name" -login-name "admin-$zone_id" -password "$admin_password" -auth-method-id \$AUTH_METHOD_ID -format json | jq -r '.item.id')
        if [ -z "\$ACCOUNT_ID" ]; then
            echo "ERROR: Failed to create admin account"
            exit 1
        fi
        echo "Created admin user: \$USER_ID with account: \$ACCOUNT_ID"
        
        # Grant admin role to the user
        ROLE_ID=\$(\$BOUNDARY_BIN roles list -scope-id \$SCOPE_ID -format json | jq -r '.items[] | select(.name=="global") | .id' | head -n 1)
        if [ -n "\$ROLE_ID" ]; then
            \$BOUNDARY_BIN roles add-principals -id \$ROLE_ID -principal \$USER_ID
            echo "Granted admin role to user"
        else
            echo "WARNING: Could not find global role, admin privileges not granted"
        fi
    else
        echo "Admin user already exists for zone $zone_name"
    fi
    
    # Create a scope for this ZTNA zone
    ZONE_SCOPE_ID=\$(\$BOUNDARY_BIN scopes list -scope-id \$SCOPE_ID -format json | jq -r '.items[] | select(.name=="ztna-zone-$zone_id") | .id')
    
    if [ -z "\$ZONE_SCOPE_ID" ]; then
        echo "Creating scope for ZTNA zone $zone_name..."
        ZONE_SCOPE_ID=\$(\$BOUNDARY_BIN scopes create -name "ztna-zone-$zone_id" -description "ZTNA Zone $zone_name Resources" -scope-id \$SCOPE_ID -format json | jq -r '.item.id')
        if [ -z "\$ZONE_SCOPE_ID" ]; then
            echo "ERROR: Failed to create zone scope"
            exit 1
        fi
        echo "Created zone scope: \$ZONE_SCOPE_ID"
    else
        echo "Zone scope already exists: \$ZONE_SCOPE_ID"
    fi
    
    # Create targets for each resource in the zone
    IFS=' ' read -ra RESOURCES <<< "$zone_resources"
    if [ \${#RESOURCES[@]} -eq 0 ]; then
        echo "WARNING: No resources specified for this zone"
    fi
    
    for resource in "\${RESOURCES[@]}"; do
        echo "Processing resource: \$resource"
        
        # Check if we need to create a host catalog
        HOST_CATALOG_ID=\$(\$BOUNDARY_BIN host-catalogs list -scope-id \$ZONE_SCOPE_ID -format json | jq -r '.items[] | select(.name=="ztna-catalog-$zone_id") | .id')
        
        if [ -z "\$HOST_CATALOG_ID" ]; then
            echo "Creating host catalog for ZTNA zone $zone_name..."
            HOST_CATALOG_ID=\$(\$BOUNDARY_BIN host-catalogs create static -name "ztna-catalog-$zone_id" -description "ZTNA Zone $zone_name Resources" -scope-id \$ZONE_SCOPE_ID -format json | jq -r '.item.id')
            if [ -z "\$HOST_CATALOG_ID" ]; then
                echo "ERROR: Failed to create host catalog"
                exit 1
            fi
            echo "Created host catalog: \$HOST_CATALOG_ID"
        fi
        
        # Parse the resource - if it's a CIDR, use the network address as host name
        resource_name=\$(echo "\$resource" | tr '/' '-')
        
        # Create host for this resource if not exists
        HOST_ID=\$(\$BOUNDARY_BIN hosts list -host-catalog-id \$HOST_CATALOG_ID -format json | jq -r ".items[] | select(.name==\"\$resource_name\") | .id")
        
        if [ -z "\$HOST_ID" ]; then
            echo "Creating host for resource \$resource..."
            HOST_ID=\$(\$BOUNDARY_BIN hosts create static -name "\$resource_name" -description "Resource \$resource in ZTNA Zone $zone_name" -address "\$resource" -host-catalog-id \$HOST_CATALOG_ID -format json | jq -r '.item.id')
            if [ -z "\$HOST_ID" ]; then
                echo "ERROR: Failed to create host for resource \$resource"
                continue
            fi
            echo "Created host: \$HOST_ID"
        fi
        
        # Create host set if not exists
        HOST_SET_ID=\$(\$BOUNDARY_BIN host-sets list -host-catalog-id \$HOST_CATALOG_ID -format json | jq -r ".items[] | select(.name==\"ztna-set-$zone_id\") | .id")
        
        if [ -z "\$HOST_SET_ID" ]; then
            echo "Creating host set for ZTNA zone $zone_name..."
            HOST_SET_ID=\$(\$BOUNDARY_BIN host-sets create static -name "ztna-set-$zone_id" -description "ZTNA Zone $zone_name Resources" -host-catalog-id \$HOST_CATALOG_ID -format json | jq -r '.item.id')
            if [ -z "\$HOST_SET_ID" ]; then
                echo "ERROR: Failed to create host set"
                continue
            fi
            echo "Created host set: \$HOST_SET_ID"
        fi
        
        # Add host to host set
        \$BOUNDARY_BIN host-sets add-hosts -id \$HOST_SET_ID -host \$HOST_ID
        echo "Added host \$resource to host set"
        
        # Create SSH target for this resource
        TARGET_ID=\$(\$BOUNDARY_BIN targets list -scope-id \$ZONE_SCOPE_ID -format json | jq -r ".items[] | select(.name==\"ssh-\$resource_name\") | .id")
        
        if [ -z "\$TARGET_ID" ]; then
            echo "Creating SSH target for resource \$resource..."
            TARGET_ID=\$(\$BOUNDARY_BIN targets create tcp -name "ssh-\$resource_name" -description "SSH Access to \$resource in ZTNA Zone $zone_name" -scope-id \$ZONE_SCOPE_ID -default-port 22 -session-connection-limit -1 -format json | jq -r '.item.id')
            
            if [ -z "\$TARGET_ID" ]; then
                echo "ERROR: Failed to create SSH target for resource \$resource"
            else
                \$BOUNDARY_BIN targets add-host-sets -id \$TARGET_ID -host-set \$HOST_SET_ID
                echo "Created SSH target: \$TARGET_ID"
            fi
        fi
        
        # If resource appears to be a web server (port 80/443), add HTTP target
        if [[ "\$resource" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            # Create HTTP target
            HTTP_TARGET_ID=\$(\$BOUNDARY_BIN targets list -scope-id \$ZONE_SCOPE_ID -format json | jq -r ".items[] | select(.name==\"http-\$resource_name\") | .id")
            
            if [ -z "\$HTTP_TARGET_ID" ]; then
                echo "Creating HTTP target for resource \$resource..."
                HTTP_TARGET_ID=\$(\$BOUNDARY_BIN targets create tcp -name "http-\$resource_name" -description "HTTP Access to \$resource in ZTNA Zone $zone_name" -scope-id \$ZONE_SCOPE_ID -default-port 80 -session-connection-limit -1 -format json | jq -r '.item.id')
                if [ -z "\$HTTP_TARGET_ID" ]; then
                    echo "ERROR: Failed to create HTTP target for resource \$resource"
                else
                    \$BOUNDARY_BIN targets add-host-sets -id \$HTTP_TARGET_ID -host-set \$HOST_SET_ID
                    echo "Created HTTP target: \$HTTP_TARGET_ID"
                fi
            fi
            
            # Create HTTPS target
            HTTPS_TARGET_ID=\$(\$BOUNDARY_BIN targets list -scope-id \$ZONE_SCOPE_ID -format json | jq -r ".items[] | select(.name==\"https-\$resource_name\") | .id")
            
            if [ -z "\$HTTPS_TARGET_ID" ]; then
                echo "Creating HTTPS target for resource \$resource..."
                HTTPS_TARGET_ID=\$(\$BOUNDARY_BIN targets create tcp -name "https-\$resource_name" -description "HTTPS Access to \$resource in ZTNA Zone $zone_name" -scope-id \$ZONE_SCOPE_ID -default-port 443 -session-connection-limit -1 -format json | jq -r '.item.id')
                if [ -z "\$HTTPS_TARGET_ID" ]; then
                    echo "ERROR: Failed to create HTTPS target for resource \$resource"
                else
                    \$BOUNDARY_BIN targets add-host-sets -id \$HTTPS_TARGET_ID -host-set \$HOST_SET_ID
                    echo "Created HTTPS target: \$HTTPS_TARGET_ID"
                fi
            fi
        fi
    done
    
    echo "ZTNA zone $zone_name Boundary configuration complete!"
    echo "==================================================="
    echo "Admin login: admin-$zone_id"
    echo "Password: $admin_password"
    echo "==================================================="
    echo "Save these credentials in a secure location!"
else
    echo "ERROR: Could not find global scope in Boundary"
    exit 1
fi
EOF

    # Set proper permissions on the script
    chmod 700 "$zone_dir/init-zone.sh"
    chown boundary:boundary "$zone_dir/init-zone.sh"
    
    log "Created initialization script for zone '$zone_name' at $zone_dir/init-zone.sh"
    
    # Run the initialization script
    log "Running Boundary zone initialization script..."
    export BOUNDARY_ADDR="$boundary_addr"
    
    su - boundary -c "bash $zone_dir/init-zone.sh" > "$zone_dir/init-output.log" 2>&1
    INIT_RESULT=$?
    
    if [ $INIT_RESULT -ne 0 ]; then
        log "ERROR: Failed to initialize zone. Check $zone_dir/init-output.log for details."
        dialog --title "Initialization Error" --msgbox "Failed to initialize zone '$zone_name'.\nCheck log at $zone_dir/init-output.log for details." 8 60
        return 1
    fi
    
    # Save credentials securely
    echo "admin-$zone_id:$admin_password" > "$zone_dir/credentials.txt"
    chmod 600 "$zone_dir/credentials.txt"
    chown boundary:boundary "$zone_dir/credentials.txt"
    
    # Record integration in ZTNA config
    echo "BOUNDARY_ZONE_${zone_id}_ENABLED=true" >> /etc/zt/ztna.conf/zones.conf
    echo "BOUNDARY_ZONE_${zone_id}_NAME=\"$zone_name\"" >> /etc/zt/ztna.conf/zones.conf
    echo "BOUNDARY_ZONE_${zone_id}_UI_URL=\"$boundary_addr\"" >> /etc/zt/ztna.conf/zones.conf
    
    log "Zone '$zone_name' initialized successfully"
    dialog --title "Zone Initialized" --msgbox "Zone '$zone_name' has been successfully initialized in Boundary.\n\nLogin credentials:\nUsername: admin-$zone_id\nPassword: $admin_password\n\nSaved to: $zone_dir/credentials.txt" 12 60
    
    return 0
}

# Check for required tools
for cmd in dialog nft ip; do
    if ! command -v "$cmd" &>/dev/null; then
        log "Error: '$cmd' is not installed. Please install it."
        exit 1
    fi
done
if ! command -v ipcalc &>/dev/null; then
    log "Warning: 'ipcalc' not installed. Using basic validation for resources."
fi

# Load base configuration from strongconn.conf
load_base_config() {
    log "Loading base configuration from $BASE_CONFIG"
    if [ ! -f "$BASE_CONFIG" ]; then
        log "Error: Base configuration file not found at $BASE_CONFIG"
        exit 1
    fi
    
    source "$BASE_CONFIG"
    
    if [ -n "$IP_POOL" ] && [ -z "$ZTNA_IP_POOL" ]; then
        FIRST_OCTET=$(echo "$IP_POOL" | cut -d. -f1)
        ZTNA_IP_POOL="${FIRST_OCTET}.200.0.0/24"
    else
        ZTNA_IP_POOL=${ZTNA_IP_POOL:-"10.200.0.0/24"}
    fi
    
    DEFAULT_INTERFACE=${DEFAULT_INTERFACE:-"eth0"}
    
    log "Base configuration loaded successfully (ZTNA_IP_POOL: $ZTNA_IP_POOL for /32 clients, DEFAULT_INTERFACE: $DEFAULT_INTERFACE)"
}

load_zones_config() {
    log "Loading ZTNA zones from $ZONES_CONFIG"
    mkdir -p "$ZTNA_CONFIG_DIR"
    touch "$ZONES_CONFIG"
    source "$ZONES_CONFIG"
    
    declare -gA ZONES ZONE_RESOURCES OKTA_RAD_ATTRIB ZONE_BOUNDARY_ENABLED
    if [ -n "$ZTNA_ZONE_COUNT" ] && [ "$ZTNA_ZONE_COUNT" -gt 0 ]; then
        for zone_var in $(compgen -v | grep "ZTNA_ZONE_.*_NAME"); do
            NORMALIZED_ZONE=$(echo "$zone_var" | sed 's/ZTNA_ZONE_\(.*\)_NAME/\1/')
            ZONES["$NORMALIZED_ZONE"]="${!zone_var}"
            RES_VAR="ZTNA_ZONE_${NORMALIZED_ZONE}_RESOURCES"
            ZONE_RESOURCES["$NORMALIZED_ZONE"]="${!RES_VAR}"
            OKTA_VAR="ZTNA_ZONE_${NORMALIZED_ZONE}_OKTA_RAD_ATTRIB"
            OKTA_RAD_ATTRIB["$NORMALIZED_ZONE"]="${!OKTA_VAR}"
            BOUNDARY_VAR="ZTNA_ZONE_${NORMALIZED_ZONE}_BOUNDARY_ENABLED"
            ZONE_BOUNDARY_ENABLED["$NORMALIZED_ZONE"]="${!BOUNDARY_VAR:-no}"
        done
    fi
    
    log "ZTNA zones configuration loaded successfully"
}

# Dialog UI constants for consistent sizing
DIALOG_WIDTH_SMALL=50    # For small dialogs (confirmation, messages)
DIALOG_WIDTH_MEDIUM=60   # For medium dialogs (forms, menus)
DIALOG_WIDTH_LARGE=70    # For large dialogs (help texts, detailed forms)
DIALOG_HEIGHT_SMALL=7    # For small dialogs (confirmations)
DIALOG_HEIGHT_MEDIUM=10  # For medium dialogs (messages, small forms)
DIALOG_HEIGHT_LARGE=15   # For large dialogs (menus, large forms)
DIALOG_HEIGHT_XLARGE=20  # For very large dialogs (help, detailed data)

# Temporary file for dialog output
TEMP_FILE=$(mktemp)
trap 'rm -f $TEMP_FILE; log "Script interrupted, cleaned up temporary files"' EXIT INT TERM

# Function to validate IP address or subnet
validate_ip_or_subnet() {
    local input="$1"
    
    if ! [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]{1,2})?$ ]]; then
        dialog --title "Validation Error" --msgbox "Invalid format: $input\n\nPlease use formats like:\n- Single IP: 192.168.1.1\n- Network: 10.0.0.0/24" 10 60
        return 1
    fi

    if command -v ipcalc &>/dev/null; then
        if ! ipcalc "$input" &>/dev/null; then
            dialog --title "Validation Error" --msgbox "Invalid IP or subnet: $input\n\nPlease ensure:\n- IP octets are between 0-255\n- Subnet mask is between 0-32\n- Address format is valid" 10 60
            return 1
        fi
    elif ! ip route get "$input" &>/dev/null; then
        dialog --title "Validation Error" --msgbox "Invalid IP or subnet: $input\n\nFallback validation check failed.\nPlease verify the IP address or subnet format." 10 60
        return 1
    fi
    
    return 0
}

# Function to validate a space-separated list of resources
validate_resources() {
    local resources="$1"
    local VALID=true
    
    IFS=' ' read -ra RES_ARRAY <<< "$resources"
    
    for resource in "${RES_ARRAY[@]}"; do
        if ! validate_ip_or_subnet "$resource"; then
            VALID=false
            break
        fi
    done
    
    if [ "$VALID" = true ]; then
        return 0
    else
        return 1
    fi
}

# Function to show help/information dialogs with consistent formatting
# Usage: show_help "Title" "Help text with \n for new lines"
show_help() {
    local title="$1"
    local help_text="$2"
    dialog --title "$title" --msgbox "$help_text" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_LARGE
}

# Function to normalize zone name (lowercase, alphanumeric only)
normalize_zone() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]'
}

# Function to view all defined zones
view_zones() {
    local ZONE_LIST=""
    for zone in "${!ZONES[@]}"; do
        ZONE_LIST="$ZONE_LIST\n- ${ZONES[$zone]} (OKTA: ${OKTA_RAD_ATTRIB[$zone]}, Resources: ${ZONE_RESOURCES[$zone]}, Boundary: ${ZONE_BOUNDARY_ENABLED[$zone]})"
    done
    if [ -z "$ZONE_LIST" ]; then
        ZONE_LIST="No zones defined yet."
    fi
    
    local zone_count=${#ZONES[@]}
    local title="Current ZTNA Zones"
    local height=$DIALOG_HEIGHT_LARGE
    
    # Adjust height based on number of zones (more zones need more space)
    if [ $zone_count -gt 5 ]; then
        height=$DIALOG_HEIGHT_XLARGE
    fi
    
    dialog --title "$title" --msgbox "Current Zones:$ZONE_LIST" $height $DIALOG_WIDTH_MEDIUM
}

# Function to add a new zone using a single form
add_new_zone() {
    local zone_count=${#ZONES[@]}
    local help_text="Zone Configuration Help\n\n"
    help_text+="• Zone name: A descriptive name for this ZTNA zone (e.g., 'Finance', 'IT', 'HR')\n"
    help_text+="• Okta RADIUS attribute: Must match an Okta group name that will be sent in RADIUS attributes\n"
    help_text+="• Resources: IP addresses or subnets that users in this zone should access (space-separated)\n"
    help_text+="• Enable Boundary: Set to 'yes' to enable HashiCorp Boundary zero-trust controller for this zone\n\n"
    help_text+="Example: A zone named 'Finance' with Okta attribute 'finance-team' might have\n"
    help_text+="resources '10.1.1.0/24 192.168.5.10' to grant access to those networks/hosts."
    
    # Show help if user presses F1
    dialog --help-button --title "Add New Zone" \
           --form "Define a new ZTNA zone (Zone $((zone_count + 1))):\n\nTIP: Zone name will be used to identify this zone\nOkta RADIUS attribute maps to Okta group name\nResources should be IPs or subnets separated by spaces\nBoundary enables zero-trust access controller" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_LARGE 4 \
           "Zone name:" 1 1 "" 1 20 25 0 \
           "Okta RADIUS attribute:" 2 1 "" 2 20 25 0 \
           "Resources (space-separated):" 3 1 "" 3 20 40 0 \
           "Enable Boundary (yes/no):" 4 1 "no" 4 20 10 0 \
           2>"$TEMP_FILE"
    
    local result=$?
    if [ $result -eq 2 ]; then  # Help button pressed
        show_help "Zone Configuration Help" "$help_text"
        # Show the form again after help
        add_new_zone
        return $?
    elif [ $result -ne 0 ]; then 
        return 1
    fi
    
    # Read form input
    mapfile -t ZONE_INPUT < "$TEMP_FILE"
    ZONE_NAME="${ZONE_INPUT[0]}"
    OKTA_VALUE="${ZONE_INPUT[1]}"
    RESOURCES="${ZONE_INPUT[2]}"
    ENABLE_BOUNDARY="${ZONE_INPUT[3],,}"  # Convert to lowercase
    
    # Enhanced validation with more detailed error messages
    if [ -z "$ZONE_NAME" ]; then
        dialog --title "Validation Error" --msgbox "Zone name cannot be empty!\n\nPlease provide a meaningful name for this zone.\n\nExamples: Finance, Development, HR, Sales" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
        add_new_zone
        return $?
    fi
    
    NORMALIZED_ZONE=$(normalize_zone "$ZONE_NAME")
    if [[ -n "${ZONES[$NORMALIZED_ZONE]}" ]]; then
        dialog --title "Validation Error" --msgbox "Zone '$ZONE_NAME' ($NORMALIZED_ZONE) already exists!\n\nPlease choose a different zone name.\n\nCurrent zones: $(echo "${!ZONES[@]}" | tr ' ' ', ')" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
        add_new_zone
        return $?
    fi
    
    if [ -z "$OKTA_VALUE" ]; then
        dialog --title "Validation Error" --msgbox "Okta RADIUS attribute cannot be empty!\n\nThis should match the Okta group name that will be sent in RADIUS attribute.\n\nExamples: finance-team, developers, hr-staff" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
        add_new_zone
        return $?
    fi
    
    if [ -z "$RESOURCES" ]; then
        dialog --title "Validation Error" --msgbox "Resources cannot be empty!\n\nPlease specify at least one IP address or subnet that users in this zone should access.\n\nExamples: 10.1.0.0/16, 192.168.1.10" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
        add_new_zone
        return $?
    fi
    
    if ! validate_resources "$RESOURCES"; then
        dialog --title "Validation Error" --msgbox "Invalid resources: $RESOURCES\n\nPlease ensure all resources are valid IP addresses or subnets separated by spaces.\n\nExamples:\n- Single IP: 192.168.1.1\n- Network: 10.0.0.0/24\n- Multiple: 192.168.1.5 10.0.0.0/24 172.16.5.10" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_MEDIUM
        add_new_zone
        return $?
    fi
    
    if [[ "$ENABLE_BOUNDARY" != "yes" && "$ENABLE_BOUNDARY" != "no" ]]; then
        dialog --title "Validation Error" --msgbox "Enable Boundary must be 'yes' or 'no'!\n\nEnabling Boundary provides zero-trust access control for this zone.\n\nBoundary provides fine-grained access control and session recording." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
        add_new_zone
        return $?
    fi
    
    # Store zone details
    ZONES["$NORMALIZED_ZONE"]="$ZONE_NAME"
    ZONE_RESOURCES["$NORMALIZED_ZONE"]="$RESOURCES"
    OKTA_RAD_ATTRIB["$NORMALIZED_ZONE"]="$OKTA_VALUE"
    ZONE_BOUNDARY_ENABLED["$NORMALIZED_ZONE"]="$ENABLE_BOUNDARY"
    
    update_config "ZTNA_ZONE_${NORMALIZED_ZONE}_NAME" "$ZONE_NAME"
    update_config "ZTNA_ZONE_${NORMALIZED_ZONE}_RESOURCES" "$RESOURCES"
    update_config "ZTNA_ZONE_${NORMALIZED_ZONE}_OKTA_RAD_ATTRIB" "$OKTA_VALUE"
    update_config "ZTNA_ZONE_${NORMALIZED_ZONE}_BOUNDARY_ENABLED" "$ENABLE_BOUNDARY"
    update_config "ZTNA_ZONE_COUNT" "$((zone_count + 1))"
    
    log "Added zone: $ZONE_NAME (Normalized: $NORMALIZED_ZONE, Boundary: $ENABLE_BOUNDARY)"
    dialog --title "Success" --msgbox "Zone '$ZONE_NAME' added successfully!\n\nZone details:\n- Name: $ZONE_NAME\n- Okta attribute: $OKTA_VALUE\n- Resources: $RESOURCES\n- Boundary enabled: $ENABLE_BOUNDARY" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
    
    # Ask if the user wants to add another zone
    dialog --title "Continue" --yesno "Would you like to add another zone?" $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_SMALL
    if [ $? -eq 0 ]; then
        add_new_zone
    fi
    return 0
}

# Function to edit an existing zone using a single form
edit_existing_zone() {
    if [ ${#ZONES[@]} -eq 0 ]; then
        dialog --msgbox "No zones to edit yet!" 6 30
        return 1
    fi
    local MENU_OPTIONS=()
    for zone in "${!ZONES[@]}"; do
        MENU_OPTIONS+=("$zone" "${ZONES[$zone]} (OKTA: ${OKTA_RAD_ATTRIB[$zone]}, Resources: ${ZONE_RESOURCES[$zone]}, Boundary: ${ZONE_BOUNDARY_ENABLED[$zone]})")
    done
    
    dialog --title "Edit Existing Zone" \
           --menu "Select a zone to edit:" 15 80 8 \
           "${MENU_OPTIONS[@]}" 2>"$TEMP_FILE"
    if [ $? -ne 0 ]; then return 1; fi
    
    SELECTED_ZONE=$(cat "$TEMP_FILE")
    
    dialog --title "Edit Zone: ${ZONES[$SELECTED_ZONE]}" \
           --form "Edit zone details:" 15 60 4 \
           "Zone name:" 1 1 "${ZONES[$SELECTED_ZONE]}" 1 15 25 0 \
           "Okta RADIUS attribute:" 2 1 "${OKTA_RAD_ATTRIB[$SELECTED_ZONE]}" 2 15 25 0 \
           "Resources (space-separated):" 3 1 "${ZONE_RESOURCES[$SELECTED_ZONE]}" 3 15 40 0 \
           "Enable Boundary (yes/no):" 4 1 "${ZONE_BOUNDARY_ENABLED[$SELECTED_ZONE]:-no}" 4 15 10 0 \
           2>"$TEMP_FILE"
    if [ $? -ne 0 ]; then return 1; fi
    
    # Read form input
    mapfile -t ZONE_INPUT < "$TEMP_FILE"
    NEW_ZONE_NAME="${ZONE_INPUT[0]}"
    NEW_OKTA="${ZONE_INPUT[1]}"
    NEW_RESOURCES="${ZONE_INPUT[2]}"
    NEW_ENABLE_BOUNDARY="${ZONE_INPUT[3],,}"
    
    # Validation
    if [ -z "$NEW_ZONE_NAME" ]; then
        dialog --msgbox "Zone name cannot be empty!" 6 30
        return 1
    fi
    NEW_NORMALIZED_ZONE=$(normalize_zone "$NEW_ZONE_NAME")
    if [ "$NEW_NORMALIZED_ZONE" != "$SELECTED_ZONE" ] && [[ -n "${ZONES[$NEW_NORMALIZED_ZONE]}" ]]; then
        dialog --msgbox "Zone '$NEW_ZONE_NAME' ($NEW_NORMALIZED_ZONE) already exists!" 6 40
        return 1
    fi
    if [ -z "$NEW_OKTA" ]; then
        dialog --msgbox "Okta RADIUS attribute cannot be empty!" 6 30
        return 1
    fi
    if [ -z "$NEW_RESOURCES" ]; then
        dialog --msgbox "Resources cannot be empty!" 6 30
        return 1
    fi
    if ! validate_resources "$NEW_RESOURCES"; then
        dialog --msgbox "Invalid resources: $NEW_RESOURCES" 6 40
        return 1
    fi
    if [[ "$NEW_ENABLE_BOUNDARY" != "yes" && "$NEW_ENABLE_BOUNDARY" != "no" ]]; then
        dialog --msgbox "Enable Boundary must be 'yes' or 'no'!" 6 30
        return 1
    fi
    
    # Update zone details
    if [ "$NEW_NORMALIZED_ZONE" != "$SELECTED_ZONE" ]; then
        ZONES["$NEW_NORMALIZED_ZONE"]="$NEW_ZONE_NAME"
        ZONE_RESOURCES["$NEW_NORMALIZED_ZONE"]="$NEW_RESOURCES"
        OKTA_RAD_ATTRIB["$NEW_NORMALIZED_ZONE"]="$NEW_OKTA"
        ZONE_BOUNDARY_ENABLED["$NEW_NORMALIZED_ZONE"]="$NEW_ENABLE_BOUNDARY"
        unset ZONES["$SELECTED_ZONE"]
        unset ZONE_RESOURCES["$SELECTED_ZONE"]
        unset OKTA_RAD_ATTRIB["$SELECTED_ZONE"]
        unset ZONE_BOUNDARY_ENABLED["$SELECTED_ZONE"]
        update_config "ZTNA_ZONE_${SELECTED_ZONE}_NAME" ""
        update_config "ZTNA_ZONE_${SELECTED_ZONE}_RESOURCES" ""
        update_config "ZTNA_ZONE_${SELECTED_ZONE}_OKTA_RAD_ATTRIB" ""
        update_config "ZTNA_ZONE_${SELECTED_ZONE}_BOUNDARY_ENABLED" ""
    else
        ZONES["$SELECTED_ZONE"]="$NEW_ZONE_NAME"
        ZONE_RESOURCES["$SELECTED_ZONE"]="$NEW_RESOURCES"
        OKTA_RAD_ATTRIB["$SELECTED_ZONE"]="$NEW_OKTA"
        ZONE_BOUNDARY_ENABLED["$SELECTED_ZONE"]="$NEW_ENABLE_BOUNDARY"
    fi
    
    update_config "ZTNA_ZONE_${NEW_NORMALIZED_ZONE}_NAME" "$NEW_ZONE_NAME"
    update_config "ZTNA_ZONE_${NEW_NORMALIZED_ZONE}_RESOURCES" "$NEW_RESOURCES"
    update_config "ZTNA_ZONE_${NEW_NORMALIZED_ZONE}_OKTA_RAD_ATTRIB" "$NEW_OKTA"
    update_config "ZTNA_ZONE_${NEW_NORMALIZED_ZONE}_BOUNDARY_ENABLED" "$NEW_ENABLE_BOUNDARY"
    
    log "Updated zone ${ZONES[$NEW_NORMALIZED_ZONE]}: Boundary=$NEW_ENABLE_BOUNDARY"
    dialog --msgbox "Zone '${ZONES[$NEW_NORMALIZED_ZONE]}' updated successfully!" 6 40
    return 0
}

# Function to remove an existing zone
remove_zone() {
    if [ ${#ZONES[@]} -eq 0 ]; then
        dialog --msgbox "No zones to remove yet!" 6 30
        return 1
    fi
    local MENU_OPTIONS=()
    for zone in "${!ZONES[@]}"; do
        MENU_OPTIONS+=("$zone" "${ZONES[$zone]}")
    done
    
    dialog --title "Remove Zone" \
           --menu "Select a zone to remove:" 15 50 8 \
           "${MENU_OPTIONS[@]}" 2>"$TEMP_FILE"
    if [ $? -ne 0 ]; then return 1; fi
    
    SELECTED_ZONE=$(cat "$TEMP_FILE")
    
    dialog --yesno "Are you sure you want to remove zone '${ZONES[$SELECTED_ZONE]}'?" 7 40
    if [ $? -eq 0 ]; then
        unset ZONES["$SELECTED_ZONE"]
        unset ZONE_RESOURCES["$SELECTED_ZONE"]
        unset OKTA_RAD_ATTRIB["$SELECTED_ZONE"]
        unset ZONE_BOUNDARY_ENABLED["$SELECTED_ZONE"]
        update_config "ZTNA_ZONE_${SELECTED_ZONE}_NAME" ""
        update_config "ZTNA_ZONE_${SELECTED_ZONE}_RESOURCES" ""
        update_config "ZTNA_ZONE_${SELECTED_ZONE}_OKTA_RAD_ATTRIB" ""
        update_config "ZTNA_ZONE_${SELECTED_ZONE}_BOUNDARY_ENABLED" ""
        log "Removed zone $SELECTED_ZONE"
        dialog --msgbox "Zone '${SELECTED_ZONE}' removed successfully!" 6 40
    fi
    return 0
}

# Functions for Boundary settings
view_boundary_config() {
    dialog --msgbox "Boundary Configuration:\nConfig file: /etc/boundary/boundary.hcl\nStatus: $(systemctl is-active boundary 2>/dev/null || echo 'Not installed')" 10 50
}

update_vault_token() {
    dialog --inputbox "Enter new Vault token:" 8 40 2>"$TEMP_FILE"
    if [ $? -eq 0 ]; then
        NEW_TOKEN=$(cat "$TEMP_FILE")
        if [ -f "/etc/boundary/boundary.hcl" ]; then
            sed -i "s/token = \".*\"/token = \"$NEW_TOKEN\"/" /etc/boundary/boundary.hcl
            log "Updated Vault token in Boundary config"
            dialog --msgbox "Vault token updated. Restart Boundary to apply changes." 8 40
        else
            dialog --msgbox "Boundary config not found!" 6 30
        fi
    fi
}

regenerate_tls_certs() {
    dialog --yesno "Are you sure you want to regenerate TLS certificates for Boundary?" 8 50
    if [ $? -eq 0 ]; then
        (
    echo "0"; sleep 1
    echo "XXX"; echo "Generating private key..."; echo "XXX"
    echo "30"; sleep 1
    echo "XXX"; echo "Creating certificate..."; echo "XXX"
    echo "60"; sleep 1
    echo "XXX"; echo "Setting permissions..."; echo "XXX"
    echo "90"; sleep 1
    echo "XXX"; echo "Finalizing certificates..."; echo "XXX"
    echo "100"
) | dialog --title "TLS Certificate Generation" --gauge "Regenerating TLS certificates..." 10 70 0
        
        # Check if we have vault PKI plugin
        if command -v vault >/dev/null 2>&1 && vault status >/dev/null 2>&1; then
            # Generate new certs using vault
            CERT_JSON=$(vault write -format=json pki/issue/boundary-ip \
                common_name="$PUBLIC_IP" \
                alt_names="$DNS_NAME" \
                ip_sans="127.0.0.1,$PUBLIC_IP,$DEFAULT_IP" \
                ttl="8760h" 2>/dev/null)
                
            if [ $? -eq 0 ]; then
                echo "$CERT_JSON" | jq -r '.data.certificate' > /etc/boundary/server-cert.pem
                echo "$CERT_JSON" | jq -r '.data.private_key' > /etc/boundary/server-key.pem
                echo "$CERT_JSON" | jq -r '.data.issuing_ca' > /etc/boundary/ca.pem
                
                chmod 600 /etc/boundary/server-key.pem
                chmod 644 /etc/boundary/server-cert.pem /etc/boundary/ca.pem
                chown boundary:boundary /etc/boundary/server-cert.pem /etc/boundary/server-key.pem /etc/boundary/ca.pem
                
                dialog --title "Success" --msgbox "TLS certificates regenerated successfully.\n\nNew certificates have been saved to:\n- /etc/boundary/server-cert.pem\n- /etc/boundary/server-key.pem\n- /etc/boundary/ca.pem" 10 60
                log "Boundary TLS certificates regenerated successfully using Vault PKI"
                
                # Ask to restart Boundary
                dialog --title "Certificate Deployment" --yesno "Restart Boundary service to apply new certificates?\n\nThe service must be restarted for changes to take effect." 9 60
                if [ $? -eq 0 ]; then
                    (
                        echo "0"; sleep 1
                        echo "XXX"; echo "Stopping Boundary service..."; echo "XXX"
                        echo "40"; sleep 1
                        echo "XXX"; echo "Starting Boundary with new certificates..."; echo "XXX"
                        echo "80"; sleep 1
                        echo "XXX"; echo "Validating service status..."; echo "XXX"
                        echo "100"
                    ) | dialog --title "Certificate Deployment" --gauge "Restarting Boundary service with new certificates..." 10 70 0
                    
                    systemctl restart boundary >/dev/null 2>&1
                    dialog --title "Success" --msgbox "Boundary service restarted with new certificates.\n\nThe new TLS certificates are now in use." 8 60
                fi
            else
                dialog --title "Error" --msgbox "Failed to generate certificates with Vault PKI.\n\nPossible causes:\n- Vault token expired\n- PKI engine not configured\n- Missing permissions\n\nCheck Vault logs for more information." 10 60
                log "Failed to generate Boundary certificates with Vault PKI"
            fi
        else
            dialog --title "Error" --msgbox "Vault not available or not running.\n\nTo regenerate certificates, Vault must be:\n- Installed and running\n- Properly configured with PKI secrets engine\n- Accessible to this script\n\nStart Vault with: sudo systemctl start vault" 12 60
            log "Vault not available for regenerating Boundary TLS certificates"
        fi
    fi
}

edit_service_settings() {
    local current_port=""
    local current_loglevel=""
    
    if [ -f "/etc/boundary/boundary.hcl" ]; then
        current_port=$(grep -oP 'address = "0.0.0.0:\K[0-9]+' /etc/boundary/boundary.hcl | head -1)
        current_loglevel=$(grep -oP 'log_level = "\K[^"]+' /etc/boundary/boundary.hcl | head -1)
    fi
    
    current_port=${current_port:-"9200"}
    current_loglevel=${current_loglevel:-"info"}
    
    dialog --form "Edit Boundary Service Settings" 15 60 2 \
           "Port:" 1 1 "$current_port" 1 15 10 0 \
           "Log Level:" 2 1 "$current_loglevel" 2 15 10 0 \
           2>"$TEMP_FILE"
    
    if [ $? -eq 0 ]; then
        mapfile -t settings < "$TEMP_FILE"
        NEW_PORT="${settings[0]}"
        NEW_LOGLEVEL="${settings[1]}"
        
        if [[ ! "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1024 ] || [ "$NEW_PORT" -gt 65535 ]; then
            dialog --msgbox "Invalid port number. Must be between 1024 and 65535." 6 40
            return 1
        fi
        
        if [[ ! "$NEW_LOGLEVEL" =~ ^(trace|debug|info|warn|error)$ ]]; then
            dialog --msgbox "Invalid log level. Must be one of: trace, debug, info, warn, error." 6 50
            return 1
        fi
        
        if [ -f "/etc/boundary/boundary.hcl" ]; then
            # Update port in address lines
            sed -i "s/address = \"0.0.0.0:[0-9]\+\"/address = \"0.0.0.0:$NEW_PORT\"/" /etc/boundary/boundary.hcl
            
            # Check if log_level exists, add or update
            if grep -q "log_level" /etc/boundary/boundary.hcl; then
                sed -i "s/log_level = \"[^\"]\+\"/log_level = \"$NEW_LOGLEVEL\"/" /etc/boundary/boundary.hcl
            else
                # Add log_level to the end of the file if it doesn't exist
                echo "log_level = \"$NEW_LOGLEVEL\"" >> /etc/boundary/boundary.hcl
            fi
            
            dialog --msgbox "Boundary service settings updated. Restart Boundary to apply changes." 6 50
            log "Updated Boundary settings: port=$NEW_PORT, log_level=$NEW_LOGLEVEL"
        else
            dialog --msgbox "Boundary config file not found at /etc/boundary/boundary.hcl" 6 50
            log "Error: Boundary config file not found when trying to update settings"
        fi
    fi
}

restart_boundary_service() {
    dialog --title "Service Restart" --yesno "Restart Boundary service now?\n\nThis will temporarily interrupt any active Boundary sessions." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
    if [ $? -eq 0 ]; then
        (
    echo "0"; sleep 0.3
    echo "XXX"; echo "Checking Boundary service status..."; echo "XXX"
    echo "10"; sleep 0.3
    echo "XXX"; echo "Validating configuration..."; echo "XXX"
    echo "20"; sleep 0.3
    echo "XXX"; echo "Stopping Boundary service..."; echo "XXX"
    echo "30"; sleep 0.5
    
    # Actually stop the service here
    systemctl stop boundary >/dev/null 2>&1
    
    echo "XXX"; echo "Clearing service cache..."; echo "XXX"
    echo "40"; sleep 0.3
    echo "XXX"; echo "Waiting for service to fully stop..."; echo "XXX"
    echo "50"; sleep 0.5
    echo "XXX"; echo "Starting Boundary service..."; echo "XXX"
    echo "60"; sleep 0.5
    
    # Actually start the service here
    systemctl start boundary >/dev/null 2>&1
    
    echo "XXX"; echo "Waiting for service initialization..."; echo "XXX"
    echo "70"; sleep 0.5
    echo "XXX"; echo "Validating connectivity..."; echo "XXX"
    echo "80"; sleep 0.3
    echo "XXX"; echo "Checking listener status..."; echo "XXX"
    echo "90"; sleep 0.3
    echo "XXX"; echo "Validating service status..."; echo "XXX"
    echo "100"
) | dialog --title "Service Restart" --gauge "Restarting Boundary service..." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM 0

        # Now actually restart the service properly and check result
        if systemctl restart boundary >/dev/null 2>&1; then
            sleep 2
            if systemctl is-active --quiet boundary; then
                dialog --title "Success" --msgbox "Boundary service restarted successfully.\n\nThe service is now running with updated configuration.\n\nAll new connections will use the updated settings." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
                log "Boundary service restarted successfully"
            else
                dialog --title "Error" --msgbox "Failed to restart Boundary service.\n\nPossible causes:\n- Configuration error\n- Service dependencies not met\n- Permission issues\n\nTroubleshooting steps:\n1. Check logs: journalctl -u boundary -n 50\n2. Verify config: boundary server -config /etc/boundary/boundary.hcl -verify-only\n3. Check for port conflicts: netstat -tuln | grep 9200" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_MEDIUM
                log "Failed to restart Boundary service - service not active after restart"
            fi
        else
            dialog --title "Error" --msgbox "Failed to restart Boundary service!\n\nThe systemctl command failed. This may indicate:\n- The service unit file is missing or corrupted\n- Systemd is not responding\n\nTroubleshooting steps:\n1. Check if unit exists: systemctl list-unit-files | grep boundary\n2. Try manually restarting: sudo systemctl restart boundary\n3. Check system logs: journalctl -xe" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_MEDIUM
            log "Failed to restart Boundary service - systemctl command failed"
        fi
    fi
}

# Function to configure Boundary settings
# Show help information for Boundary settings
show_boundary_help() {
    local help_text="HashiCorp Boundary - Zero Trust Access Controller\n\n"
    help_text+="1. View Configuration: See current Boundary settings\n"
    help_text+="2. Update Vault Token: Change authentication token for Vault KMS\n"
    help_text+="3. Regenerate TLS Certs: Create new certificates for secure communication\n"
    help_text+="4. Edit Service Settings: Change port and log level\n"
    help_text+="5. Reset Admin Password: Create new admin credentials for a zone\n"
    help_text+="6. Restart Service: Apply configuration changes\n"
    help_text+="7. Help / Information: Show this help screen\n"
    help_text+="8. Back: Return to zone management\n\n"
    help_text+="Boundary provides secure access to resources without exposing them to the public internet.\n\n"
    help_text+="Key Features:\n"
    help_text+="• Fine-grained access control based on identity\n"
    help_text+="• Session recording and monitoring\n"
    help_text+="• Dynamic credential injection\n"
    help_text+="• No VPN required for secure access\n"
    help_text+="• Integration with ZTNA zones for simplified management"
    
    show_help "Boundary Help" "$help_text"
}

configure_boundary() {
    log "Configuring Boundary settings for ZTNA zones"
    
    # Check if Boundary is installed
    if ! command -v boundary &>/dev/null && [ ! -f "/opt/boundary/boundary" ]; then
        dialog --title "Boundary Installation" --yesno "Boundary is not installed. Would you like to install it now?\n\nBoundary provides zero-trust access control for your ZTNA zones." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
        if [ $? -ne 0 ]; then
            log "User opted not to install Boundary at this time"
            return 1
        fi
        
        # Check if any zones with Boundary enabled exist
        local BOUNDARY_ENABLED=false
        for zone in "${!ZONES[@]}"; do
            if [ "${ZONE_BOUNDARY_ENABLED[$zone]}" = "yes" ]; then
                BOUNDARY_ENABLED=true
                break
            fi
        done
        
        if [ "$BOUNDARY_ENABLED" = false ]; then
            dialog --title "Configuration Required" --msgbox "No zones have Boundary enabled. Please enable Boundary for at least one zone first.\n\nTo do this:\n1. Go back to the main menu\n2. Choose 'Edit Existing Zone'\n3. Set 'Enable Boundary' to 'yes'" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
            return 1
        fi
        
        # Show installation message
        # Create a progress gauge for Boundary installation with more granular progress
(
    echo "5"; sleep 0.5
    echo "XXX"; echo "Preparing Boundary installation..."; echo "XXX"
    echo "10"; sleep 0.5
    echo "XXX"; echo "Checking dependencies..."; echo "XXX"
    echo "15"; sleep 0.5
    echo "XXX"; echo "Downloading Boundary packages..."; echo "XXX"
    echo "25"; sleep 0.5
    echo "XXX"; echo "Installing Boundary packages..."; echo "XXX"
    echo "35"; sleep 0.5
    echo "XXX"; echo "Creating configuration directory..."; echo "XXX"
    echo "40"; sleep 0.5
    echo "XXX"; echo "Generating initial configuration..."; echo "XXX"
    echo "50"; sleep 0.5
    echo "XXX"; echo "Setting up TLS certificates..."; echo "XXX"
    echo "60"; sleep 0.5
    echo "XXX"; echo "Configuring systemd service..."; echo "XXX"
    echo "70"; sleep 0.5
    echo "XXX"; echo "Starting Boundary service..."; echo "XXX"
    echo "80"; sleep 0.5
    echo "XXX"; echo "Creating initial admin users..."; echo "XXX"
    echo "90"; sleep 0.5
    echo "XXX"; echo "Finalizing installation..."; echo "XXX"
    echo "95"; sleep 0.5
    echo "XXX"; echo "Verifying installation..."; echo "XXX"
    echo "100"
) | dialog --title "Installing Boundary" --gauge "Starting installation..." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_LARGE 0
        
        # Install Boundary for the first zone with Boundary enabled
        for zone in "${!ZONES[@]}"; do
            if [ "${ZONE_BOUNDARY_ENABLED[$zone]}" = "yes" ]; then
                ZONE_NAME="${ZONES[$zone]}"
                RESOURCES="${ZONE_RESOURCES[$zone]}"
                
                log "Installing Boundary for zone $ZONE_NAME with resources: $RESOURCES"
                if type install_boundary >/dev/null 2>&1; then
                    install_boundary "$zone" "$ZONE_NAME" "$RESOURCES" > /tmp/boundary_install.log 2>&1
                    if [ $? -eq 0 ]; then
                        dialog --title "Installation Successful" --msgbox "Boundary was successfully installed for zone '$ZONE_NAME'.\n\nAccess the UI at: https://${PUBLIC_IP}:9200\n\nDefault login credentials have been saved to:\n/etc/boundary/zones/$zone/credentials.txt" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
                    else
                        dialog --title "Installation Log" --textbox /tmp/boundary_install.log $DIALOG_HEIGHT_XLARGE $DIALOG_WIDTH_LARGE
                        dialog --title "Installation Failed" --msgbox "Failed to install Boundary for zone '$ZONE_NAME'.\n\nSee log for details. Common issues include:\n- Network connectivity problems\n- Insufficient disk space\n- Missing dependencies\n- Firewall blocking required ports" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
                        return 1
                    fi
                else
                    dialog --title "Installation Error" --msgbox "Boundary installation function not available. Please install Boundary manually.\n\nVisit https://www.boundaryproject.io/ for installation instructions." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
                    return 1
                fi
                break
            fi
        done
    fi
    
    # Boundary settings menu
    while true; do
        dialog --title "Boundary Settings" \
               --menu "Configure Boundary settings:" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_MEDIUM 9 \
               1 "View Boundary Configuration" \
               2 "Update Vault Token" \
               3 "Regenerate TLS Certificates" \
               4 "Edit Service Settings" \
               5 "Reset Admin Password" \
               6 "Restart Boundary Service" \
               7 "Help / Information" \
               8 "Back to Zone Management" 2>"$TEMP_FILE"
        
        CHOICE=$(cat "$TEMP_FILE")
        
        case "$CHOICE" in
            1) view_boundary_config ;;
            2) update_vault_token ;;
            3) regenerate_tls_certs ;;
            4) edit_service_settings ;;
            5) 
                # Properly implement the reset_boundary_password function with local BOUNDARY_BIN
                BOUNDARY_BIN=$(which boundary 2>/dev/null || echo "/opt/boundary/boundary")
                if [ ! -f "$BOUNDARY_BIN" ]; then
                    dialog --title "Error" --msgbox "Boundary binary not found. Please make sure Boundary is properly installed.\n\nExpected location: $BOUNDARY_BIN\n\nIf installed elsewhere, please provide the full path to the binary." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
                    continue
                fi
                reset_boundary_password "$BOUNDARY_BIN"
                ;;
            6) restart_boundary_service ;;
            7) show_boundary_help ;;
            8) break ;;
            *) dialog --title "Error" --msgbox "Invalid choice: $CHOICE" $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_SMALL ;;
        esac
    done
    
    return 0
}
# Function to show ZTNA zones management help
show_zones_help() {
    local help_text="ZTNA Zone Management Help\n\n"
    help_text+="1. View Zones: Display all configured ZTNA zones and their details\n"
    help_text+="2. Add New Zone: Create a new ZTNA zone with Okta RADIUS attributes\n"
    help_text+="3. Edit Existing Zone: Modify zone properties like name, resources, or Boundary settings\n"
    help_text+="4. Remove Zone: Delete an existing ZTNA zone\n"
    help_text+="5. Configure Boundary Settings: Set up HashiCorp Boundary for zero trust access control\n"
    help_text+="6. Help: Display this help information\n"
    help_text+="7. Proceed: Continue with configuration deployment\n\n"
    help_text+="ZTNA zones map Okta RADIUS attributes to network resources, controlling access\n"
    help_text+="based on user group membership in Okta. Each zone isolates users with XFRM policies."
    
    show_help "ZTNA Zone Management Help" "$help_text"
}

# Main menu for defining and managing zones
define_zones() {
    while true; do
        dialog --title "ZTNA Zone Management" \
               --menu "Choose an action:" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_MEDIUM 7 \
               1 "View Zones" \
               2 "Add New Zone" \
               3 "Edit Existing Zone" \
               4 "Remove Zone" \
               5 "Configure Boundary Settings" \
               6 "Help" \
               7 "Proceed" 2>"$TEMP_FILE"
        CHOICE=$(cat "$TEMP_FILE")

        case "$CHOICE" in
            1) view_zones ;;
            2) add_new_zone ;;
            3) edit_existing_zone ;;
            4) remove_zone ;;
            5) configure_boundary ;;
            6) show_zones_help ;;
            7) break ;;
            *) dialog --title "Error" --msgbox "Invalid choice" $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_SMALL ;;
        esac
    done
}

# Function to update zones.conf
update_config() {
    local key="$1"
    local value="$2"
    local config_file="$ZONES_CONFIG"
    
    if grep -q "^${key}=" "$config_file"; then
        sed -i "s|^${key}=.*|${key}=\"${value}\"|" "$config_file"
    else
        echo "${key}=\"${value}\"" >> "$config_file"
    fi
    
    log "Updated configuration in $config_file: $key = $value"
}

# Function to append ZTNA logs to syslog-ng configuration
append_syslog_ng_config() {
    SYSLOG_NG_CONF="/etc/syslog-ng/syslog-ng.conf"
    LOGROTATE_CONFIG="/etc/logrotate.d/custom_logs"

    if ! command -v syslog-ng &>/dev/null; then
        log "Syslog-ng not installed. Skipping syslog-ng configuration append."
        return 0
    fi

    # Ensure log files exist with correct permissions
    touch "$LOG_FILE" "$UPDOWN_LOG_FILE" 2>/dev/null
    chown root:adm "$LOG_FILE" "$UPDOWN_LOG_FILE" 2>/dev/null
    chmod 640 "$LOG_FILE" "$UPDOWN_LOG_FILE" 2>/dev/null

    # Check if ZTNA source is already defined
    if ! grep -q "source s_ztna" "$SYSLOG_NG_CONF"; then
        log "Appending ZTNA log sources to $SYSLOG_NG_CONF"
        cat >> "$SYSLOG_NG_CONF" <<EOF

# ZTNA logs
source s_ztna {
    file("$LOG_FILE" follow_freq(1) flags(no-parse));
    file("$UPDOWN_LOG_FILE" follow_freq(1) flags(no-parse));
};

log { source(s_ztna); destination(d_local); };
EOF

        if grep -q "destination d_remote" "$SYSLOG_NG_CONF"; then
            echo "log { source(s_ztna); destination(d_remote); };" >> "$SYSLOG_NG_CONF"
        fi

        # Validate and restart syslog-ng
        if syslog-ng -s; then
            systemctl restart syslog-ng >/dev/null 2>&1 || service syslog-ng restart >/dev/null 2>&1 || log "Failed to restart syslog-ng"
            log "Syslog-ng configuration updated and restarted successfully."
        else
            log "Error: Syslog-ng configuration validation failed after appending ZTNA logs."
            return 1
        fi
    else
        log "ZTNA source already defined in $SYSLOG_NG_CONF. Skipping append."
    fi

    # Append to logrotate configuration if not already present
    if ! grep -q "$LOG_FILE" "$LOGROTATE_CONFIG"; then
        log "Appending ZTNA logs to $LOGROTATE_CONFIG"
        cat >> "$LOGROTATE_CONFIG" <<EOF

$LOG_FILE $UPDOWN_LOG_FILE {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl reload syslog-ng 2>/dev/null || true
    endscript
}
EOF
    fi
}

# Apply initial NFTables rules with IP sets
apply_nftables_sets() {
    log "Applying initial ZTNA NFTables rules with IP sets"
    
    if ! nft list sets inet | grep -q "zone_.*_clients"; then
        log "ZTNA sets not found, loading $POLICY_CONF with nft -f"
        nft -f "$POLICY_CONF"
    else
        log "ZTNA sets already exist, skipping reload to avoid disruption"
    fi
    
    log "ZTNA NFTables rules applied successfully"
}
start_and_verify_boundary() {
    log "Starting Boundary service..."
    systemctl daemon-reload || {
        log "ERROR: Failed to reload systemd daemons"
        return 1
    }
    
    systemctl enable boundary || {
        log "ERROR: Failed to enable Boundary service"
        return 1
    }
    
    systemctl restart boundary || {
        log "ERROR: Failed to start Boundary service"
        return 1
    }
    
    # Wait for service to start properly with timeout
    local max_attempts=30
    local attempt=0
    local started=false
    
    log "Waiting for Boundary service to become available..."
    while [ $attempt -lt $max_attempts ]; do
        attempt=$((attempt + 1))
        
        if systemctl is-active --quiet boundary; then
            # Additional check: actually verify the API is responding
            if curl -k -s "https://${PUBLIC_IP}:9200/v1/health" >/dev/null 2>&1; then
                started=true
                log "Boundary service is running and API is accessible"
                break
            else
                log "Boundary service is running but API is not yet accessible (attempt $attempt/$max_attempts)"
            fi
        else
            log "Boundary service not yet active (attempt $attempt/$max_attempts)"
        fi
        
        sleep 5
    done
    
    if [ "$started" = false ]; then
        log "ERROR: Boundary service failed to start properly within timeout"
        # Capture logs for troubleshooting
        journalctl -u boundary -n 50 > "/tmp/boundary_startup.log"
        cat "/tmp/boundary_startup.log" >> "$LOG_FILE"
        return 1
    fi
    
    return 0
}


reset_boundary_password() {
    # Accept boundary binary path as parameter
    local BOUNDARY_BIN="${1:-$(which boundary 2>/dev/null || echo "/opt/boundary/boundary")}"
    
    # Check if Boundary is installed and running
    if ! systemctl is-active --quiet boundary; then
        dialog --title "Error" --msgbox "Boundary service is not running.\n\nPlease start the service first with:\nsudo systemctl start boundary" 9 60
        return 1
    fi
    
    # List available zones with Boundary enabled
    local AVAILABLE_ZONES=()
    for zone in "${!ZONES[@]}"; do
        if [ "${ZONE_BOUNDARY_ENABLED[$zone]}" = "yes" ]; then
            AVAILABLE_ZONES+=("$zone" "${ZONES[$zone]}")
        fi
    done
    
    if [ ${#AVAILABLE_ZONES[@]} -eq 0 ]; then
        dialog --title "Warning" --msgbox "No zones with Boundary enabled found.\n\nYou need to create at least one zone with Boundary enabled before you can reset passwords." 9 60
        return 1
    fi
    
    # Let user select a zone
    dialog --menu "Select zone to reset password:" 15 60 8 "${AVAILABLE_ZONES[@]}" 2>"$TEMP_FILE"
    if [ $? -ne 0 ]; then return 1; fi
    
    SELECTED_ZONE=$(cat "$TEMP_FILE")
    ZONE_NAME="${ZONES[$SELECTED_ZONE]}"
    
    # Generate new password
    NEW_PASSWORD=$(openssl rand -base64 12)
    
    # Show confirmation with new password
    dialog --yesno "Reset password for admin user of zone '$ZONE_NAME'?\n\nNew password will be: $NEW_PASSWORD" 10 60
    if [ $? -ne 0 ]; then return 1; fi
    
    # Execute boundary commands to reset the password
    dialog --infobox "Resetting password for zone '$ZONE_NAME'..." 5 50
    
    export BOUNDARY_ADDR="https://${PUBLIC_IP}:9200"
    SCOPE_ID=$($BOUNDARY_BIN scopes list -format json | jq -r '.items[] | select(.name=="global") | .id')
    
    if [ -z "$SCOPE_ID" ]; then
        dialog --msgbox "Failed to find global scope in Boundary." 6 40
        return 1
    fi
    
    AUTH_METHOD_ID=$($BOUNDARY_BIN auth-methods list -scope-id $SCOPE_ID -format json | jq -r '.items[] | select(.name=="ztna-password") | .id')
    
    if [ -z "$AUTH_METHOD_ID" ]; then
        dialog --msgbox "Failed to find auth method in Boundary." 6 40
        return 1
    fi
    
    ADMIN_ACCOUNT=$($BOUNDARY_BIN accounts list -auth-method-id $AUTH_METHOD_ID -format json | jq -r ".items[] | select(.name==\"admin-$SELECTED_ZONE\") | .id")
    
    if [ -z "$ADMIN_ACCOUNT" ]; then
        dialog --msgbox "Failed to find admin account for zone '$ZONE_NAME'." 6 50
        return 1
    fi
    
    # Reset password for the account
    if $BOUNDARY_BIN accounts set-password -id $ADMIN_ACCOUNT -password "$NEW_PASSWORD"; then
        # Update the credentials file
        CREDS_FILE="/etc/boundary/zones/$SELECTED_ZONE/credentials.txt"
        echo "admin-$SELECTED_ZONE:$NEW_PASSWORD" > "$CREDS_FILE"
        chmod 600 "$CREDS_FILE"
        chown boundary:boundary "$CREDS_FILE"
        
        # Generate new summary file
        TIMESTAMP=$(date +"%Y-%m-%d")
        SUMMARY_FILE="/etc/boundary/zone-summary-${TIMESTAMP}.md"
        
        echo "# Boundary Zone Admin Credentials" > "$SUMMARY_FILE"
        echo "## Generated on $(date)" >> "$SUMMARY_FILE"
        echo "**KEEP THIS FILE SECURE**" >> "$SUMMARY_FILE"
        echo "" >> "$SUMMARY_FILE"
        
        for zone in "${!ZONES[@]}"; do
            if [ "${ZONE_BOUNDARY_ENABLED[$zone]}" = "yes" ]; then
                ZONE_CREDS_FILE="/etc/boundary/zones/$zone/credentials.txt"
                if [ -f "$ZONE_CREDS_FILE" ]; then
                    CREDS=$(cat "$ZONE_CREDS_FILE")
                    echo "### Zone: ${ZONES[$zone]} ($zone)" >> "$SUMMARY_FILE"
                    echo "- **Web UI:** https://${PUBLIC_IP}:9200" >> "$SUMMARY_FILE"
                    echo "- **Credentials:** $CREDS" >> "$SUMMARY_FILE"
                    echo "" >> "$SUMMARY_FILE"
                fi
            fi
        done
        
        chmod 600 "$SUMMARY_FILE"
        chown boundary:boundary "$SUMMARY_FILE"
        
        # Update the latest summary symlink
        ln -sf "$SUMMARY_FILE" "/etc/boundary/latest-zone-summary.md"
        
        dialog --msgbox "Password for zone '$ZONE_NAME' reset successfully!\n\nNew login: admin-$SELECTED_ZONE\nNew password: $NEW_PASSWORD\n\nThis information is also saved to:\n- $CREDS_FILE\n- $SUMMARY_FILE" 12 60
    else
        dialog --msgbox "Failed to reset password for admin account." 6 40
        return 1
    fi
}

generate_policy_conf() {
    for zone in "${!ZONES[@]}"; do
        POLICY_CONF="/etc/nftables.d/zone_${zone}.conf"
        log "Generating ZTNA NFTables policy for zone $zone at $POLICY_CONF"
        
        cat << EOF > "$POLICY_CONF"
#!/usr/sbin/nft -f

# ZTNA Policy Configuration for Zone ${ZONES[$zone]}
# Generated on $(date)
# DO NOT EDIT MANUALLY - Use setup-ztna.sh to regenerate

table inet firewall {
    set zone_${zone}_clients {
        type ipv4_addr
        comment "ZTNA clients for ${ZONES[$zone]}"
    }

    chain filter_FORWARD_ZTNA_${zone} {
        ip saddr @zone_${zone}_clients ip daddr { $(echo "${ZONE_RESOURCES[$zone]}" | sed 's/ /, /g') } counter accept comment "ZTNA clients to resources for ${ZONES[$zone]}"
        ip saddr { $(echo "${ZONE_RESOURCES[$zone]}" | sed 's/ /, /g') } ip daddr @zone_${zone}_clients counter accept comment "Resources to ZTNA clients for ${ZONES[$zone]}"
    }
}
EOF

        chmod 600 "$POLICY_CONF"
        log "Generated $POLICY_CONF successfully with secure permissions (600)"
    done
    echo "✅ ZTNA zone configurations written to /etc/nftables.d/ for ${#ZONES[@]} zones"
}

update_nftables_conf() {
    NFT_CONF="/etc/nftables.conf"
    BACKUP_CONF="/etc/nftables.conf.bak.$(date +%Y%m%d%H%M%S)"
    
    cp "$NFT_CONF" "$BACKUP_CONF"
    log "Backed up $NFT_CONF to $BACKUP_CONF"

    JUMP_LINES=""
    for zone in "${!ZONES[@]}"; do
        JUMP_LINES="$JUMP_LINES        jump filter_FORWARD_ZTNA_${zone}\n"
    done

    sed -i.bak \
        -e "/ct state { established, related } counter accept/a\\${JUMP_LINES}" \
        -e "/jump filter_FORWARD_ZTNA_[0-9]\+/d" \
        -e "/ct state { established, related } counter accept/!b;n;/jump filter_FORWARD_ZTNA_[0-9]\+/d" \
        "$NFT_CONF"

    sed -i '/^$/N;/^\n$/D' "$NFT_CONF"
    log "Updated $NFT_CONF with ZTNA jump rules for ${#ZONES[@]} zones"
}

# Function to generate RADIUS configuration
generate_radius_conf() {
    log "Generating EAP-RADIUS configuration at $RADIUS_CONF"
    
    cat << EOF > "$RADIUS_CONF"
charon {
    plugins {
        eap-radius {
            filter_id = yes
            forward {
                radius_to_ike = Filter-Id
            }
        }
    }
}
EOF
    
    chmod 600 "$RADIUS_CONF"
    log "Generated $RADIUS_CONF successfully with Filter-Id forwarding"
}

# Function to generate updown script for ZTNA
generate_updown_script() {
    log "Generating ZTNA updown script at $UPDOWN_SCRIPT"
    
    IPSEC_SERVER_IP=$(ip addr show $DEFAULT_INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
    
    cat << EOF > "$UPDOWN_SCRIPT"
#!/bin/bash

# StrongConn ZTNA updown script for IPsec VPN connections
# This script is automatically generated - do not edit manually

# Configuration file paths
BASE_CONFIG="$BASE_CONFIG"
ZONES_CONFIG="$ZONES_CONFIG"
source "\$BASE_CONFIG" || { echo "Error: Failed to source base config"; exit 1; }
source "\$ZONES_CONFIG" || { echo "Error: Failed to source zones config"; exit 1; }

LOG_FILE="$UPDOWN_LOG_FILE"
NFT_TABLE="inet firewall"
NFT_CHAIN="forward"
STATE_DIR="/var/run/ztna"

# Ensure state directory exists
mkdir -p "\$STATE_DIR" 2>/dev/null

log() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\$LOG_FILE"
}

# Log beginning of script execution
log "=== Starting updown script execution (verb: \${PLUTO_VERB}) ==="

# Get connection details from StrongSwan environment variables
CLIENT_IP="\${PLUTO_PEER_ADDR}"
USERNAME="\${PLUTO_PEER_ID}"
SECURITY_ZONES="\${PLUTO_RADIUS_ATTR_Filter-Id:-default}"
IF_ID="\${PLUTO_IF_ID_IN}"
IPSEC_SERVER_IP="$IPSEC_SERVER_IP"

if [ -z "\$CLIENT_IP" ] || [ -z "\$IF_ID" ]; then
    log "Error: Missing required variables (CLIENT_IP=\$CLIENT_IP, IF_ID=\$IF_ID)"
    exit 1
fi

# Use a unique identifier combining IP and IFID for flag files and rule handles
SAFE_CLIENT_IP="\${CLIENT_IP//./_}-\${IF_ID}"

UP_FLAG="\$STATE_DIR/ztna-up-\${SAFE_CLIENT_IP}"
DOWN_FLAG="\$STATE_DIR/ztna-down-\${SAFE_CLIENT_IP}"
IF_ID_FILE="\$STATE_DIR/ztna_if_id_\${SAFE_CLIENT_IP}"

# Function to add a rule and store its handle
add_nft_rule() {
    local rule="\$1"
    local handle_file="\$2"
    
    # Check if rule already exists
    local handle=\$(nft -a list chain \$NFT_TABLE \$NFT_CHAIN | grep "\$rule" | awk '{print \$NF}')
    if [ -z "\$handle" ]; then
        # Add the rule
        if ! nft add rule \$NFT_TABLE \$NFT_CHAIN \$rule; then
            log "Error: Failed to add nftables rule: \$rule"
            return 1
        fi
        
        # Get the handle
        handle=\$(nft -a list chain \$NFT_TABLE \$NFT_CHAIN | grep "\$rule" | awk '{print \$NF}')
        if [ -z "\$handle" ]; then
            log "Warning: Rule added but couldn't get handle for: \$rule"
            return 0
        fi
        
        # Store the handle
        echo "\$handle" > "\$handle_file" || log "Warning: Failed to save handle to \$handle_file"
    else
        log "Rule already exists with handle \$handle: \$rule"
        echo "\$handle" > "\$handle_file" || log "Warning: Failed to save existing handle to \$handle_file"
    fi
    return 0
}

# Function to delete a rule using its handle
delete_nft_rule() {
    local handle_file="\$1"
    if [ ! -f "\$handle_file" ]; then
        log "Warning: Handle file not found: \$handle_file"
        return 0
    fi
    
    local handle=\$(cat "\$handle_file")
    if [ -z "\$handle" ]; then
        log "Warning: Empty handle in file: \$handle_file"
        rm -f "\$handle_file"
        return 0
    fi
    
    if ! nft delete rule \$NFT_TABLE \$NFT_CHAIN handle \$handle 2>/dev/null; then
        log "Warning: Failed to delete rule with handle \$handle (may already be gone)"
    else
        log "Successfully deleted rule with handle \$handle"
    fi
    
    rm -f "\$handle_file" || log "Warning: Failed to remove handle file: \$handle_file"
}

already_setup() {
    if [ ! -f "\$IF_ID_FILE" ]; then
        log "No IF_ID_FILE found for \$CLIENT_IP"
        return 1
    fi
    
    local if_id=\$(cat "\$IF_ID_FILE" 2>/dev/null)
    if [ -z "\$if_id" ]; then
        log "Empty IF_ID in \$IF_ID_FILE for \$CLIENT_IP"
        rm -f "\$IF_ID_FILE"
        return 1
    fi
    
    local xfrm_iface="xfrm-\${if_id}"
    
    # Check if interface exists
    if ! ip link show "\$xfrm_iface" &>/dev/null; then
        log "XFRM interface \$xfrm_iface does not exist for \$CLIENT_IP"
        return 1
    fi
    
    # Check if routing rule exists
    if ! ip rule show | grep -q "from \$CLIENT_IP"; then
        log "No routing rule for \$CLIENT_IP"
        return 1
    fi
    
    # Check if in nftables set
    if ! nft list set inet firewall "zone_\${MATCHED_ZONE}_clients" 2>/dev/null | grep -q "\$CLIENT_IP"; then
        log "\$CLIENT_IP not in zone_\${MATCHED_ZONE}_clients nftables set"
        return 1
    fi
    
    log "Connection already set up for \$CLIENT_IP with interface \$xfrm_iface"
    return 0
}

MATCHED_ZONE=""
IFS=' ' read -ra GROUP_ARRAY <<< "\$SECURITY_ZONES"
for group in "\${GROUP_ARRAY[@]}"; do
    for zone in \$(compgen -v ZTNA_ZONE_ | grep '_OKTA_RAD_ATTRIB\$'); do
        NORMALIZED_ZONE=\$(echo "\$zone" | sed 's/ZTNA_ZONE_\(.*\)_OKTA_RAD_ATTRIB/\1/')
        OKTA_VAR="ZTNA_ZONE_\${NORMALIZED_ZONE}_OKTA_RAD_ATTRIB"
        if [ "\${!OKTA_VAR}" = "\$group" ]; then
            MATCHED_ZONE="\$NORMALIZED_ZONE"
            log "Matched Okta RADIUS group '\$group' to zone \$MATCHED_ZONE"
            break 2
        fi
    done
done

if [ -z "\$MATCHED_ZONE" ]; then
    log "No zone matched for Okta RADIUS groups '\$SECURITY_ZONES', allowing default StrongSwan policy"
    exit 0
fi

if [ -z "\$IF_ID" ]; then
    log "Error: No IFID provided by StrongSwan for \$CLIENT_IP, falling back to default policy"
    exit 1
fi

XFRM_IFACE="xfrm-\${IF_ID}"
BOUNDARY_ENABLED_VAR="ZTNA_ZONE_\${MATCHED_ZONE}_BOUNDARY_ENABLED"
BOUNDARY_ENABLED="\${!BOUNDARY_ENABLED_VAR:-no}"

case "\$PLUTO_VERB" in
    up-client)
        if [ -f "\$UP_FLAG" ]; then
            log "Already handled 'up-client' for \$CLIENT_IP (ID: \$IF_ID), skipping"
            exit 0
        fi
        
        if already_setup; then
            log "VPN setup already in place for \$CLIENT_IP (ID: \$IF_ID) in zone \$MATCHED_ZONE. Skipping."
            exit 0
        fi
        
        touch "\$UP_FLAG" || log "Warning: Failed to create \$UP_FLAG flag - check permissions"
        
        log "Connection up for \$USERNAME (\$CLIENT_IP/32) in zone \$MATCHED_ZONE (OKTA_RAD_ATTRIB: \$SECURITY_ZONES, if_id \$IF_ID)"

        if ! ip link show "\$XFRM_IFACE" &>/dev/null; then
            ip link add name "\$XFRM_IFACE" type xfrm if_id "\$IF_ID" 2>/dev/null || {
                log "Failed to create \$XFRM_IFACE, assuming StrongSwan will handle"
            }
        fi
        ip link set "\$XFRM_IFACE" up || log "Failed to bring up \$XFRM_IFACE"
        log "Enabled XFRM interface \$XFRM_IFACE for \$CLIENT_IP/32"

        nft add element \$NFT_TABLE "zone_\${MATCHED_ZONE}_clients" { "\$CLIENT_IP" } 2>/dev/null || log "Failed to add \$CLIENT_IP to zone_\${MATCHED_ZONE}_clients (may already exist)"
        log "Added \$CLIENT_IP/32 to zone_\${MATCHED_ZONE}_clients NFT set"

        if [ "\$BOUNDARY_ENABLED" = "yes" ]; then
            # Boundary-enabled: Restrict to IPsec server ports 9200 (controller) and 9204 (proxy)
            add_nft_rule "ip saddr \$CLIENT_IP ip daddr \$IPSEC_SERVER_IP tcp dport 9200 accept" \
                "/var/run/nft_handle_\${SAFE_CLIENT_IP}_allow_9200"
            add_nft_rule "ip saddr \$CLIENT_IP ip daddr \$IPSEC_SERVER_IP tcp dport 9204 accept" \
                "/var/run/nft_handle_\${SAFE_CLIENT_IP}_allow_9204"
            add_nft_rule "ip saddr \$CLIENT_IP drop" \
                "/var/run/nft_handle_\${SAFE_CLIENT_IP}_drop"
            log "Applied Boundary-specific nftables rules for \$CLIENT_IP/32"
        else
            # Non-Boundary: Allow direct access to resources
            RESOURCES_VAR="ZTNA_ZONE_\${MATCHED_ZONE}_RESOURCES"
            if [ -n "\${!RESOURCES_VAR}" ]; then
                IFS=' ' read -ra RESOURCES <<< "\${!RESOURCES_VAR}"
                for resource in "\${RESOURCES[@]}"; do
                    ip xfrm policy add src "\$CLIENT_IP/32" dst "\$resource" dir out if_id "\$IF_ID" \
                        tmpl src 0.0.0.0 dst 0.0.0.0 proto esp mode tunnel 2>/dev/null || log "Policy add out failed for \$resource"
                    ip xfrm policy add src "\$resource" dst "\$CLIENT_IP/32" dir in if_id "\$IF_ID" \
                        tmpl src 0.0.0.0 dst 0.0.0.0 proto esp mode tunnel 2>/dev/null || log "Policy add in failed for \$resource"
                    log "Added XFRM policy for \$CLIENT_IP/32 to/from \$resource (if_id \$IF_ID)"
                    
                    ip route add "\$resource" dev "\$XFRM_IFACE" 2>/dev/null || log "Failed to add route for \$resource"
                    log "Added route for \$resource via \$XFRM_IFACE for \$CLIENT_IP/32"
                done
                ip rule add from "\$CLIENT_IP/32" lookup 0 2>/dev/null || {
                log "Failed to add routing rule for \$CLIENT_IP/32"
                # Continue anyway
            }
            log "Added routing rule for \$CLIENT_IP/32 to default table"
            else
                log "No resources defined for zone \$MATCHED_ZONE, denying access"
                ip link del "\$XFRM_IFACE" 2>/dev/null || true
                rm -f "\$UP_FLAG" 2>/dev/null || true
                exit 1
            fi
        fi

        # Safely save the IF_ID
        echo "\$IF_ID" > "\$IF_ID_FILE.tmp" && \
        chmod 600 "\$IF_ID_FILE.tmp" && \
        mv "\$IF_ID_FILE.tmp" "\$IF_ID_FILE" || \
        log "Error: Failed to save IF_ID to \$IF_ID_FILE"
        
        log "Connection setup completed for \$CLIENT_IP (ID: \$IF_ID) in zone \$MATCHED_ZONE"
        ;;

    down-client)
        log "Processing down event for \$USERNAME (\$CLIENT_IP/32)"
        
        if [ -f "\$DOWN_FLAG" ]; then
            log "Already handled 'down-client' for \$CLIENT_IP (ID: \$IF_ID), skipping"
            exit 0
        fi
        
        touch "\$DOWN_FLAG" || log "Warning: Failed to create \$DOWN_FLAG flag - check permissions"
        
        # Find IF_ID from saved file or try to recover it
        if [ -f "\$IF_ID_FILE" ]; then
            IF_ID=\$(cat "\$IF_ID_FILE" 2>/dev/null)
            if [ -n "\$IF_ID" ]; then
                XFRM_IFACE="xfrm-\${IF_ID}"
                log "Found stored IFID \$IF_ID for \$CLIENT_IP"
            else
                log "Empty IF_ID_FILE for \$CLIENT_IP"
                rm -f "\$IF_ID_FILE"
                IF_ID="\${PLUTO_IF_ID_IN}"
                XFRM_IFACE="xfrm-\${IF_ID}"
            fi
        else
            log "No stored IFID file for \$CLIENT_IP, attempting recovery"
            # Try to recover from xfrm policies
            IF_ID=\$(ip xfrm policy list | grep "src \$CLIENT_IP/32" | grep "if_id" | awk '{print \$NF}' | head -n 1)
            if [ -n "\$IF_ID" ]; then
                XFRM_IFACE="xfrm-\${IF_ID}"
                log "Recovered IFID \$IF_ID from existing policies for \$CLIENT_IP"
            else
                log "No IFID found for \$CLIENT_IP, proceeding with provided ID or partial cleanup"
                IF_ID="\${PLUTO_IF_ID_IN}"
                XFRM_IFACE="xfrm-\${IF_ID}"
            fi
        fi

        log "Connection down for \$USERNAME (\$CLIENT_IP/32) in zone \$MATCHED_ZONE (OKTA_RAD_ATTRIB: \$SECURITY_ZONES, if_id \$IF_ID)"

        nft delete element \$NFT_TABLE "zone_\${MATCHED_ZONE}_clients" { "\$CLIENT_IP" } 2>/dev/null || log "Failed to remove \$CLIENT_IP from zone_\${MATCHED_ZONE}_clients (not found)"
        log "Removed \$CLIENT_IP/32 from zone_\${MATCHED_ZONE}_clients NFT set"

        if [ "\$BOUNDARY_ENABLED" = "yes" ]; then
            # Remove Boundary-specific rules
            delete_nft_rule "/var/run/nft_handle_\${SAFE_CLIENT_IP}_allow_9200"
            delete_nft_rule "/var/run/nft_handle_\${SAFE_CLIENT_IP}_allow_9204"
            delete_nft_rule "/var/run/nft_handle_\${SAFE_CLIENT_IP}_drop"
            log "Removed Boundary-specific nftables rules for \$CLIENT_IP/32"
        else
            # Clean up non-Boundary XFRM policies and routes
            RESOURCES_VAR="ZTNA_ZONE_\${MATCHED_ZONE}_RESOURCES"
            if [ -n "\${!RESOURCES_VAR}" ]; then
                IFS=' ' read -ra RESOURCES <<< "\${!RESOURCES_VAR}"
                for resource in "\${RESOURCES[@]}"; do
                    ip xfrm policy del src "\$CLIENT_IP/32" dst "\$resource" dir out if_id "\$IF_ID" 2>/dev/null || true
                    ip xfrm policy del src "\$resource" dst "\$CLIENT_IP/32" dir in if_id "\$IF_ID" 2>/dev/null || true
                    log "Removed XFRM policy for \$CLIENT_IP/32 to/from \$resource (if_id \$IF_ID)"
                    
                    ip route del "\$resource" dev "\$XFRM_IFACE" 2>/dev/null || true
                done
            fi
            ip xfrm policy flush src "\$CLIENT_IP/32" 2>/dev/null || log "Failed to flush outgoing policies for \$CLIENT_IP"
            ip xfrm policy flush dst "\$CLIENT_IP/32" 2>/dev/null || log "Failed to flush incoming policies for \$CLIENT_IP"
            log "Flushed all XFRM policies for \$CLIENT_IP/32"

            while ip rule show | grep -q "from \$CLIENT_IP/32"; do
                ip rule del from "\$CLIENT_IP/32" lookup 0 2>/dev/null || break
            done
            log "Removed all routing rules for \$CLIENT_IP/32 from default table"
        fi

        if ip link show "\$XFRM_IFACE" &>/dev/null; then
            ip link set "\$XFRM_IFACE" down 2>/dev/null || log "Failed to bring down \$XFRM_IFACE"
            ip link del "\$XFRM_IFACE" 2>/dev/null || log "Failed to delete \$XFRM_IFACE"
            log "Removed XFRM interface \$XFRM_IFACE for \$CLIENT_IP/32"
        fi

        rm -f "\$IF_ID_FILE" "\$UP_FLAG" "\$DOWN_FLAG" 2>/dev/null || log "Failed to remove some flag files for \$CLIENT_IP"
        log "Removed flag files for \$CLIENT_IP"
        ;;
esac

exit 0
EOF
    

    chmod 700 "$UPDOWN_SCRIPT"
    chown strongswan:strongswan "$UPDOWN_SCRIPT"
    

    mkdir -p "/var/run/ztna" 2>/dev/null
    chmod 755 "/var/run/ztna"
    
    log "Generated $UPDOWN_SCRIPT successfully with secure permissions"
}

generate_ztna_conf() {
    log "Generating ZTNA SwanCtl configuration at $ZTNA_CONF"
    
    cat << EOF > "$ZTNA_CONF"
# ZTNA Connection Configuration
# Generated on $(date)
# DO NOT EDIT MANUALLY - Use setup-ztna.sh to regenerate
# Assigns /32 IPs from $ZTNA_IP_POOL to both ZTNA and road warrior clients

connections {
    ztna {
        pools = $ZTNA_IP_POOL
        version = 2
        proposals = aes256-sha256-ecp256, aes256gcm16-prfsha256-ecp256, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 60s
        unique = replace
        if_id_in = %unique
        if_id_out = %unique
        
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/server.pem
            id = $DNS_NAME
        }
        
        remote {
            auth = eap-radius
            id = %any
            eap_id = %identity
            revocation = relaxed
        }
        
        children {
            ztna {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                rekey_time = 0s  # Disabled due to Windows client issue
                inactivity = 86400s  # Terminate CHILD SA after 24 hours of inactivity
                start_action = none
                dpd_action = restart
                mode = tunnel
                esp_proposals = aes256-sha256, aes256gcm16-ecp256, aes256gcm16, aes256-sha256-ecp256, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521
                updown = $UPDOWN_SCRIPT
            }
        }
        
        mobike = yes
        fragmentation = yes
    }
}

secrets {
    eap-radius {
        id = $DNS_NAME
        port = $RADIUS_PORT
        secret = $RADIUS_SECRET
    }
    
    private-key {
        id = $DNS_NAME
        file = /etc/swanctl/private/server-key.pem
    }
}
EOF
    
    chmod 600 "$ZTNA_CONF"
    log "Generated $ZTNA_CONF successfully with inactivity timeout of 24 hours"
}

# This function will be used by the install_boundary function
setup_boundary_service() {
    local BOUNDARY_BIN="$1"
    local BOUNDARY_CONFIG="$2"
    local ZONE_ID="$3"
    local ZONE_NAME="$4"
    local BOUNDARY_ZONE_DIR="$5"
    local BOUNDARY_UI_URL="$6"
    local BOUNDARY_ADDR="$7"
    
    log "Setting up Boundary systemd service..."
    cat > /etc/systemd/system/boundary.service <<EOF
[Unit]
Description=HashiCorp Boundary
Documentation=https://www.boundaryproject.io/docs/
Requires=network-online.target
After=network-online.target vault.service
Wants=vault.service

# Add more specific dependency
ConditionPathExists=/var/lib/vault/data
ConditionPathExists=/etc/boundary/server-cert.pem

[Service]
Type=simple
User=boundary
Group=boundary
ExecStart=${BOUNDARY_BIN} server -config ${BOUNDARY_CONFIG}
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536

# Add health check to ensure service is working
ExecStartPost=/bin/bash -c 'sleep 10 && curl -k -s https://127.0.0.1:9200/v1/health >/dev/null 2>&1 || exit 1'

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/boundary.service
    
    # Clean up
    rm -f /tmp/boundary-policy.hcl
    
    # Start and verify Boundary service
    log "Starting Boundary service..."
    systemctl daemon-reload
    systemctl enable boundary || log "Failed to enable Boundary service"
    
    # Start the service with better error handling
    if ! systemctl start boundary; then
        log "ERROR: Failed to start Boundary service"
        dialog --title "Service Error" --msgbox "Failed to start Boundary service.\nCheck the logs with 'journalctl -u boundary'" 8 60
        return 1
    fi
    
    # Wait for service to initialize with timeout
    log "Waiting for Boundary service to initialize..."
    max_attempts=30
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
        attempt=$((attempt + 1))
        
        if systemctl is-active --quiet boundary; then
            log "Boundary service is active"
            
            # Check if API is responding
            if curl -k -s "https://127.0.0.1:9200/v1/health" >/dev/null 2>&1; then
                log "Boundary API is responding"
                break
            else
                log "Boundary service is active but API is not responding yet (attempt $attempt/$max_attempts)"
            fi
        else
            log "Boundary service not active yet (attempt $attempt/$max_attempts)"
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log "ERROR: Boundary service initialization timed out"
            dialog --title "Timeout Error" --msgbox "Boundary service initialization timed out.\nCheck the logs with 'journalctl -u boundary'" 8 60
            return 1
        fi
        
        sleep 2
    done
    
    # Generate initial admin password if not provided
    ADMIN_PASSWORD=$(openssl rand -base64 12)
    
    # Initialize Boundary database if not already initialized
    if ! $BOUNDARY_BIN database status -config "$BOUNDARY_CONFIG" | grep -q "Database is initialized"; then
        log "Initializing Boundary database..."
        $BOUNDARY_BIN database init -config "$BOUNDARY_CONFIG" || {
            log "Failed to initialize Boundary database"
            return 1
        }
    else
        log "Boundary database already initialized"
    fi
    
    # Run the initialization script with better error handling
    log "Running Boundary zone initialization script..."
    su - boundary -c "bash $BOUNDARY_ZONE_DIR/init-zone.sh" > "$BOUNDARY_ZONE_DIR/init-output.log" 2>&1
    INIT_RESULT=$?
    
    # Check the result and provide feedback
    if [ $INIT_RESULT -ne 0 ]; then
        log "ERROR: Boundary zone initialization failed with exit code $INIT_RESULT"
        dialog --title "Initialization Error" --msgbox "Boundary zone initialization failed.\nCheck the log at $BOUNDARY_ZONE_DIR/init-output.log" 8 60
        return 1
    fi
    
    # Check for specific errors in the output log
    if grep -q "ERROR: Could not find global scope in Boundary" "$BOUNDARY_ZONE_DIR/init-output.log"; then
        log "ERROR: Global scope not found. Boundary database may need initialization"
        
        # Try to fix by initializing the database
        dialog --title "Database Error" --msgbox "Boundary database needs initialization.\nWould you like to initialize it now?" 8 60
        if [ $? -eq 0 ]; then
            log "Initializing Boundary database..."
            su - boundary -c "$BOUNDARY_BIN database init -config $BOUNDARY_CONFIG" > "$BOUNDARY_ZONE_DIR/db-init.log" 2>&1
            if [ $? -ne 0 ]; then
                log "ERROR: Database initialization failed"
                dialog --title "Database Error" --msgbox "Boundary database initialization failed.\nCheck the log at $BOUNDARY_ZONE_DIR/db-init.log" 8 60
                return 1
            fi
            
            # Re-run the initialization script
            log "Re-running Boundary zone initialization script..."
            su - boundary -c "bash $BOUNDARY_ZONE_DIR/init-zone.sh" > "$BOUNDARY_ZONE_DIR/init-output.log" 2>&1
            if [ $? -ne 0 ]; then
                log "ERROR: Boundary zone initialization failed again"
                dialog --title "Initialization Error" --msgbox "Boundary zone initialization failed again.\nCheck the log at $BOUNDARY_ZONE_DIR/init-output.log" 8 60
                return 1
            fi
        else
            log "User declined database initialization"
            return 1
        fi
    fi
    
    # Save credentials securely
    echo "admin-$ZONE_ID:$ADMIN_PASSWORD" > "$BOUNDARY_ZONE_DIR/credentials.txt"
    chmod 600 "$BOUNDARY_ZONE_DIR/credentials.txt"
    chown boundary:boundary "$BOUNDARY_ZONE_DIR/credentials.txt"
    
    # Record integration in ZTNA config
    echo "BOUNDARY_ZONE_${ZONE_ID}_ENABLED=true" >> /etc/zt/ztna.conf/zones.conf
    echo "BOUNDARY_ZONE_${ZONE_ID}_NAME=\"$ZONE_NAME\"" >> /etc/zt/ztna.conf/zones.conf
    echo "BOUNDARY_ZONE_${ZONE_ID}_UI_URL=\"$BOUNDARY_UI_URL\"" >> /etc/zt/ztna.conf/zones.conf
    
    log "Boundary setup complete for ZTNA zone '$ZONE_NAME'!"
    log "Web UI available at: $BOUNDARY_UI_URL"
    log "API endpoint: $BOUNDARY_ADDR"
    log "Admin credentials saved to: $BOUNDARY_ZONE_DIR/credentials.txt"
    log "Admin login: admin-$ZONE_ID"
    log "Admin password: $ADMIN_PASSWORD"
    
    # Display success message
    dialog --title "Installation Complete" --msgbox "Boundary installation successful!\n\nZone: $ZONE_NAME\nUI: $BOUNDARY_UI_URL\n\nAdmin login: admin-$ZONE_ID\nPassword: $ADMIN_PASSWORD\n\nCredentials saved to: $BOUNDARY_ZONE_DIR/credentials.txt" 12 70
    
    return 0
}

# Install Boundary prerequisites
install_boundary_prerequisites() {
    log "Installing Boundary prerequisites..."
    
    local required_packages=("unzip" "curl" "jq" "sqlite3")
    local missing_packages=()
    
    for pkg in "${required_packages[@]}"; do
        command -v "$pkg" &>/dev/null || missing_packages+=("$pkg")
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log "Installing missing packages: ${missing_packages[*]}"
        apt-get update -q || boundary_error "Failed to update package lists"
        apt-get install -y "${missing_packages[@]}" || boundary_error "Failed to install prerequisites: ${missing_packages[*]}"
    else
        log "All required packages already installed"
    fi
}

# Install Boundary binary
install_boundary_binary() {
    local install_dir="${1:-$BOUNDARY_DEFAULT_INSTALL_DIR}"
    
    log "Installing Boundary binary to $install_dir..."
    mkdir -p "$install_dir" || boundary_error "Failed to create install directory: $install_dir"
    
    local latest_version
    latest_version=$(curl -sSL https://api.github.com/repos/hashicorp/boundary/releases/latest | jq -r '.tag_name | ltrimstr("v")')
    [[ -z "$latest_version" || "$latest_version" = "null" ]] && {
        log "Warning: Failed to fetch latest version, using fallback: 0.13.0"
        latest_version="0.13.0"
    }
    
    local boundary_url="https://releases.hashicorp.com/boundary/${latest_version}/boundary_${latest_version}_linux_amd64.zip"
    local zip_path="/tmp/boundary.zip"
    
    log "Downloading Boundary from: $boundary_url"
    curl -fsSL -o "$zip_path" "$boundary_url" || boundary_error "Failed to download Boundary"
    unzip -o -d "$install_dir" "$zip_path" || {
        rm -f "$zip_path"
        boundary_error "Failed to extract Boundary"
    }
    
    rm -f "$zip_path"
    chmod +x "$install_dir/boundary" || boundary_error "Failed to set executable permissions"
    log "Boundary binary installed: $install_dir/boundary"
}

# Setup Vault integration for Boundary
setup_vault_integration() {
    local vault_addr="${1:-$VAULT_DEFAULT_ADDR}"
    local vault_token="$2"
    local boundary_token_path="${3:-$BOUNDARY_DEFAULT_TOKEN_PATH}"
    
    log "Setting up Vault integration..."
    export VAULT_ADDR="$vault_addr"
    export VAULT_TOKEN="$vault_token"
    
    vault status >/dev/null 2>&1 || boundary_error "Cannot access Vault at $vault_addr"
    
    vault secrets list | grep -q "^transit/" || {
        log "Enabling transit secrets engine..."
        vault secrets enable -path=transit transit >/dev/null 2>&1 || boundary_error "Failed to enable transit engine"
        log "Transit engine enabled"
    }
    
    for key_name in "${REQUIRED_BOUNDARY_KEYS[@]}"; do
        vault list transit/keys 2>/dev/null | grep -q "^$key_name$" || {
            log "Creating transit key: $key_name"
            vault write -f transit/keys/"$key_name" >/dev/null 2>&1 || boundary_error "Failed to create key: $key_name"
        }
    done
    
    local policy_file="/tmp/boundary-policy.hcl"
    cat > "$policy_file" <<EOF
# KMS permissions
path "transit/encrypt/+" { capabilities = ["create", "update"] }
path "transit/decrypt/+" { capabilities = ["create", "update"] }
path "transit/keys/+" { capabilities = ["read"] }
path "sys/capabilities-self" { capabilities = ["update"] }
path "sys/mounts" { capabilities = ["read"] }
path "sys/health" { capabilities = ["read"] }
EOF
    
    vault policy write boundary-kms "$policy_file" || {
        rm -f "$policy_file"
        boundary_error "Failed to apply KMS policy"
    }
    rm -f "$policy_file"
    
    local new_token
    new_token=$(vault token create -policy=boundary-kms -period=720h -explicit-max-ttl=8760h -format=json | jq -r '.auth.client_token') || boundary_error "Failed to create Vault token"
    [[ -z "$new_token" || "$new_token" = "null" ]] && boundary_error "Invalid token received from Vault"
    
    mkdir -p "$(dirname "$boundary_token_path")"
    echo "$new_token" > "$boundary_token_path"
    chmod 600 "$boundary_token_path"
    chown boundary:boundary "$boundary_token_path"
    
    log "Vault integration complete. Token saved to $boundary_token_path"
    echo "$new_token"  # Return token for use
}

# Setup Boundary database
setup_boundary_database() {
    local db_path="${1:-$BOUNDARY_DEFAULT_DB_PATH}"
    log "Setting up database at $db_path..."
    
    local db_dir=$(dirname "$db_path")
    mkdir -p "$db_dir" -m 750 || boundary_error "Failed to create database directory"
    chown boundary:boundary "$db_dir"
    
    if [ ! -f "$db_path" ]; then
        log "Creating database file $db_path..."
        touch "$db_path"
        chmod 640 "$db_path"
        chown boundary:boundary "$db_path"
    else
        log "SQLite database file already exists at $db_path"
        # Fix permissions if needed
        if [ $(stat -c %U:%G "$db_path") != "boundary:boundary" ]; then
            log "Fixing database file ownership..."
            chown boundary:boundary "$db_path"
        fi
        if [ $(stat -c %a "$db_path") != "640" ]; then
            log "Fixing database file permissions..."
            chmod 640 "$db_path"
        fi
    fi
    
    log "Verifying SQLite database is accessible..."
    if ! sudo -u boundary sqlite3 "$db_path" ".databases" >/dev/null 2>&1; then
        local sqlite_error=$(sudo -u boundary sqlite3 "$db_path" ".databases" 2>&1)
        boundary_error "SQLite database validation failed: $sqlite_error"
    fi
    
    log "Database setup complete"
}

# Create Boundary config file
create_boundary_config() {
    local config_path="$1"
    local public_ip="$2"
    local vault_addr="$3"
    local vault_token="$4"
    
    log "Creating Boundary configuration at $config_path..."
    
    # Backup any existing configuration
    [[ -f "$config_path" ]] && mv "$config_path" "${config_path}.bak.$(date +%Y%m%d%H%M%S)"
    
    cat > "$config_path" <<EOF
# Boundary configuration - integrated with ZTNA
# Generated on $(date)

disable_mlock = true

controller {
  name = "boundary-controller"
  description = "StrongConn ZTNA Access Controller"
  
  database {
    url = "sqlite:///var/lib/boundary/boundary.db"
  }
}

worker {
  name = "boundary-worker"
  description = "StrongConn ZTNA Worker"
  initial_upstreams = ["127.0.0.1:$BOUNDARY_CLUSTER_PORT"]
  public_addr = "${public_ip}"
}

# API and Web UI listener
listener "tcp" {
  address = "0.0.0.0:$BOUNDARY_API_PORT"
  purpose = "api"
  tls_cert_file = "/etc/boundary/server-cert.pem"
  tls_key_file = "/etc/boundary/server-key.pem"
  cors_enabled = true
  cors_allowed_origins = ["*"]
  cors_allowed_headers = ["*"]
}

# Cluster listener (controller-worker communication)
listener "tcp" {
  address = "0.0.0.0:$BOUNDARY_CLUSTER_PORT"
  purpose = "cluster"
  tls_cert_file = "/etc/boundary/server-cert.pem"
  tls_key_file = "/etc/boundary/server-key.pem"
}

# Proxy listener for target connections
listener "tcp" {
  address = "0.0.0.0:$BOUNDARY_PROXY_PORT"
  purpose = "proxy"
  tls_cert_file = "/etc/boundary/server-cert.pem"
  tls_key_file = "/etc/boundary/server-key.pem"
}

# Root KMS configuration
kms "transit" {
  purpose    = "root"
  address    = "${vault_addr}"
  token      = "${vault_token}"
  key_name   = "boundary_root"
  mount_path = "transit"
  ca_cert    = "/etc/boundary/ca.pem"
}

# Worker authentication KMS 
kms "transit" {
  purpose    = "worker-auth"
  address    = "${vault_addr}"
  token      = "${vault_token}"
  key_name   = "boundary_worker_auth"
  mount_path = "transit"
  ca_cert    = "/etc/boundary/ca.pem"
}

# Recovery KMS for disaster recovery
kms "transit" {
  purpose    = "recovery"
  address    = "${vault_addr}"
  token      = "${vault_token}"
  key_name   = "boundary_recovery"
  mount_path = "transit"
  ca_cert    = "/etc/boundary/ca.pem"
}

ui {
  enabled = true
  cors {
    allowed_origins = ["*"]
  }
}

# Events configuration to integrate with logging
events {
  observation_events {
    audit_enabled = true
  }
  sysevents {
    audit_enabled = true
  }
}

# Cache configuration for better performance
cache {
  max_seconds = 300
  max_tokens = 10000
}
EOF

    chmod 640 "$config_path"
    chown boundary:boundary "$config_path"
    log "Boundary configuration created at $config_path"
}

# Create systemd service for Boundary
create_boundary_systemd_service() {
    local boundary_bin="$1"
    local boundary_config="$2"
    
    log "Creating Boundary systemd service..."
    
    cat > /etc/systemd/system/boundary.service <<EOF
[Unit]
Description=HashiCorp Boundary
Documentation=https://www.boundaryproject.io/docs/
Requires=network-online.target
After=network-online.target vault.service
Wants=vault.service

# Add more specific dependency
ConditionPathExists=/var/lib/vault/data
ConditionPathExists=/etc/boundary/server-cert.pem

[Service]
Type=simple
User=boundary
Group=boundary
ExecStart=$boundary_bin server -config $boundary_config
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536

# Add health check to ensure service is working
ExecStartPost=/bin/bash -c 'sleep 10 && curl -k -s https://127.0.0.1:$BOUNDARY_API_PORT/v1/health >/dev/null 2>&1 || exit 1'

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/boundary.service
    log "Boundary systemd service created"
    
    # Reload daemon
    systemctl daemon-reload
}

# Start and verify Boundary service
start_and_verify_boundary() {
    local boundary_config="$1"
    
    log "Starting Boundary service..."
    systemctl daemon-reload || boundary_error "Failed to reload systemd daemons"
    
    systemctl enable boundary || boundary_error "Failed to enable Boundary service"
    systemctl restart boundary || boundary_error "Failed to start Boundary service"
    
    # Wait for service to start properly with timeout
    local max_attempts=30
    local attempt=0
    local started=false
    
    log "Waiting for Boundary service to become available..."
    while [ $attempt -lt $max_attempts ]; do
        attempt=$((attempt + 1))
        
        if systemctl is-active --quiet boundary; then
            # Additional check: actually verify the API is responding
            if curl -k -s "https://${PUBLIC_IP}:$BOUNDARY_API_PORT/v1/health" >/dev/null 2>&1; then
                started=true
                log "Boundary service is running and API is accessible"
                break
            else
                log "Boundary service is running but API is not yet accessible (attempt $attempt/$max_attempts)"
            fi
        else
            log "Boundary service not yet active (attempt $attempt/$max_attempts)"
        fi
        
        sleep 5
    done
    
    if [ "$started" = false ]; then
        log "ERROR: Boundary service failed to start properly within timeout"
        # Capture logs for troubleshooting
        journalctl -u boundary -n 50 > "/tmp/boundary_startup.log"
        cat "/tmp/boundary_startup.log" >> "$LOG_FILE"
        boundary_error "Boundary service failed to start properly within timeout"
    fi
    
    return 0
}

# Initialize Boundary database
init_boundary_database() {
    local boundary_bin="$1"
    local boundary_config="$2"
    
    log "Checking Boundary database status..."
    
    if ! $boundary_bin database status -config "$boundary_config" | grep -q "Database is initialized"; then
        log "Initializing Boundary database..."
        $boundary_bin database init -config "$boundary_config" || boundary_error "Failed to initialize Boundary database"
        log "Boundary database initialized successfully"
    else
        log "Boundary database already initialized"
    fi
}

# Helper function to configure an existing Boundary instance for a new zone
configure_boundary_for_zone() {
    local ZONE_ID="$1"
    local ZONE_NAME="$2"
    local ZONE_RESOURCES="$3"
    
    log "Configuring existing Boundary installation for zone '$ZONE_NAME'..."
    
    # Only proceed if Boundary service is running
    if ! systemctl is-active --quiet boundary; then
        log "ERROR: Boundary service is not running"
        dialog --title "Service Error" --msgbox "Boundary service is not running.\nPlease start it with 'systemctl start boundary'" 8 60
        return 1
    fi
    
    # Use binary from PATH or default location
    BOUNDARY_BIN=$(which boundary 2>/dev/null || echo "/opt/boundary/boundary")
    BOUNDARY_UI_URL="https://${PUBLIC_IP}:9200"
    
    # Use our unified zone initialization function
    init_boundary_zone "$ZONE_ID" "$ZONE_NAME" "$ZONE_RESOURCES" "$BOUNDARY_BIN" "$BOUNDARY_UI_URL"
    return $?
}

# Function to validate input parameters before boundary installation
validate_boundary_inputs() {
    local zone_id="$1"
    local zone_name="$2"
    local zone_resources="$3"
    
    # Check if zone ID is provided
    if [ -z "$zone_id" ]; then
        log "ERROR: Zone ID must be provided for Boundary installation"
        return 1
    fi
    
    # Check if zone name is provided
    if [ -z "$zone_name" ]; then
        log "ERROR: Zone name must be provided for Boundary installation"
        return 1
    fi
    
    # Check if at least one resource is provided
    if [ -z "$zone_resources" ]; then
        log "WARNING: No resources provided for zone '$zone_name'. Only admin access will be configured."
        if [[ -n "$DISPLAY" || -n "$TERM" ]] && command -v dialog &>/dev/null; then
            dialog --title "No Resources" --yesno "No resources were provided for zone '$zone_name'. Continue with admin-only configuration?" 8 60
            if [ $? -ne 0 ]; then
                log "User canceled Boundary installation due to missing resources"
                return 1
            fi
        fi
    fi
    
    return 0
}

install_boundary() {
    local zone_id="${1:-default}"
    local zone_name="${2:-Default}"
    local zone_resources="${3:-}"
    local progress_file="/tmp/boundary_progress"
    
    log "Starting Boundary installation for zone '$zone_name' (ID: $zone_id)"
    validate_boundary_inputs "$zone_id" "$zone_name" "$zone_resources" || boundary_error "Invalid inputs"
    
    # Check if Boundary is already installed and running
    if command -v boundary &>/dev/null || [ -f "/opt/boundary/boundary" ]; then
        log "Boundary is already installed. Checking service status..."
        if systemctl is-active --quiet boundary; then
            log "Boundary service is running. Configuring for zone '$zone_name'..."
            # Skip installation but proceed with configuration
            configure_boundary_for_zone "$zone_id" "$zone_name" "$zone_resources"
            return $?
        else
            log "Boundary is installed but service is not running. Attempting to start service..."
            systemctl start boundary
            if ! systemctl is-active --quiet boundary; then
                log "ERROR: Failed to start existing Boundary service. Check logs with 'journalctl -u boundary'"
                dialog --title "Service Error" --yesno "Boundary is installed but failed to start. Would you like to repair the installation?" 8 60
                if [ $? -eq 0 ]; then
                    # User selected to repair - continue with installation to repair
                    log "User selected to repair the Boundary installation"
                else
                    # User selected not to repair - abort
                    boundary_error "User chose not to repair Boundary installation"
                fi
            else
                log "Successfully started existing Boundary service. Configuring for zone '$zone_name'..."
                configure_boundary_for_zone "$zone_id" "$zone_name" "$zone_resources"
                return $?
            fi
        fi
    fi
    
    local boundary_bin="$BOUNDARY_DEFAULT_INSTALL_DIR/boundary"
    local boundary_config="$BOUNDARY_DEFAULT_CONFIG_DIR/boundary.hcl"
    local boundary_token_path="$BOUNDARY_DEFAULT_TOKEN_PATH"
    local boundary_addr=$(printf "$DEFAULT_BOUNDARY_UI_URL_TEMPLATE" "$PUBLIC_IP")  # Assumes PUBLIC_IP is set
    
    # Explicitly load token from strongconn.conf
    export VAULT_ADDR="$VAULT_DEFAULT_ADDR"
    
    # Load configuration with better error handling
    CONFIG_PATH="/etc/strongconn.conf"
    [ -f "$CONFIG_PATH" ] || CONFIG_PATH="/usr/bin/strongconn.conf"
    
    if [ ! -f "$CONFIG_PATH" ]; then
        boundary_error "Could not find configuration file at $CONFIG_PATH"
    fi
    
    source "$CONFIG_PATH"
    
    if [ -z "$VAULT_TOKEN" ]; then
        boundary_error "VAULT_TOKEN not set in configuration file"
    fi
    
    # Check Vault status before proceeding
    if ! curl -k -s "$VAULT_ADDR/v1/sys/health" >/dev/null 2>&1; then
        boundary_error "Vault is not accessible at $VAULT_ADDR"
    fi
    
    # Create zone-specific directory
    BOUNDARY_ZONE_DIR="$BOUNDARY_DEFAULT_CONFIG_DIR/zones/$zone_id"
    mkdir -p "$BOUNDARY_ZONE_DIR"
    
    # Setup permissions
    if [ -f "/usr/bin/strongconn.sh" ]; then
        log "Calling set-permissions function from strongconn.sh"
        /usr/bin/strongconn.sh -set-permissions
        if [ $? -ne 0 ]; then
            log "WARNING: set-permissions call returned non-zero, continuing anyway"
        fi
    else
        log "WARNING: strongconn.sh not found, using fallback permissions setup"
        ensure_boundary_permissions
    fi
    
    (
        update_progress 5 "Installing prerequisites..." "$progress_file"
        install_boundary_prerequisites
        
        update_progress 20 "Installing Boundary binary..." "$progress_file"
        install_boundary_binary "$BOUNDARY_DEFAULT_INSTALL_DIR"
        
        update_progress 35 "Setting up Vault integration..." "$progress_file"
        local vault_token=$(setup_vault_integration "$VAULT_DEFAULT_ADDR" "$VAULT_TOKEN" "$boundary_token_path")
        
        update_progress 45 "Setting up database..." "$progress_file"
        setup_boundary_database "$BOUNDARY_DEFAULT_DB_PATH"
        
        update_progress 55 "Creating configuration..." "$progress_file"
        create_boundary_config "$boundary_config" "$PUBLIC_IP" "$VAULT_DEFAULT_ADDR" "$vault_token"
        
        update_progress 65 "Creating systemd service..." "$progress_file"
        create_boundary_systemd_service "$boundary_bin" "$boundary_config"
        
        update_progress 75 "Starting Boundary service..." "$progress_file"
        start_and_verify_boundary "$boundary_config"
        
        update_progress 80 "Initializing database..." "$progress_file"
        init_boundary_database "$boundary_bin" "$boundary_config"
        
        update_progress 85 "Initializing zone '$zone_name'..." "$progress_file"
        init_boundary_zone "$zone_id" "$zone_name" "$zone_resources" "$boundary_bin" "$boundary_addr"
        
        update_progress 100 "Installation complete!" "$progress_file"
    ) &
    
    local installer_pid=$!
    show_progress_dialog "Installing Boundary for '$zone_name'" "$progress_file" "$installer_pid"
    wait $installer_pid || boundary_error "Installation failed"
    
    log "Boundary installation completed for zone '$zone_name'"
    
    # Generate admin password (this should be set by init_boundary_zone but we'll ensure it exists)
    local admin_password=$(openssl rand -base64 12)
    
    # Display success message
    if [[ -n "$DISPLAY" || -n "$TERM" ]] && command -v dialog &>/dev/null; then
        dialog --title "Installation Complete" --msgbox "Boundary installation successful!\n\nZone: $zone_name\nUI: $boundary_addr\n\nAdmin login: admin-$zone_id\n\nCredentials saved to: $BOUNDARY_DEFAULT_CONFIG_DIR/zones/$zone_id/credentials.txt" 12 70
    fi
    
    return 0
}

# SSH Target creation function - extracted for modularization
create_ssh_target() {
    local resource="$1"
    local resource_name="$2"
    local host_set_id="$3"
    local zone_scope_id="$4"
    
    TARGET_ID=$($BOUNDARY_BIN targets create tcp -name "ssh-$resource_name" -description "SSH Access to $resource in ZTNA Zone $ZONE_NAME" -scope-id $zone_scope_id -default-port 22 -session-connection-limit -1 -format json | jq -r '.item.id')
    if [ -z "$TARGET_ID" ]; then
        log "ERROR: Failed to create SSH target for resource $resource"
        return 1
    fi
    
    $BOUNDARY_BIN targets add-host-sets -id $TARGET_ID -host-set $host_set_id
    log "Created SSH target: $TARGET_ID"
    return 0
}

# HTTP Target creation function - extracted for modularization
create_http_target() {
    local resource="$1"
    local resource_name="$2"
    local host_set_id="$3"
    local zone_scope_id="$4"
    
    HTTP_TARGET_ID=$($BOUNDARY_BIN targets list -scope-id $zone_scope_id -format json | jq -r ".items[] | select(.name==\"http-$resource_name\") | .id")
    
    if [ -z "$HTTP_TARGET_ID" ]; then
        log "Creating HTTP target for resource $resource..."
        HTTP_TARGET_ID=$($BOUNDARY_BIN targets create tcp -name "http-$resource_name" -description "HTTP Access to $resource in ZTNA Zone $ZONE_NAME" -scope-id $zone_scope_id -default-port 80 -session-connection-limit -1 -format json | jq -r '.item.id')
        if [ -z "$HTTP_TARGET_ID" ]; then
            log "ERROR: Failed to create HTTP target for resource $resource"
            return 1
        fi
        
        $BOUNDARY_BIN targets add-host-sets -id $HTTP_TARGET_ID -host-set $host_set_id
        log "Created HTTP target: $HTTP_TARGET_ID"
    fi
    return 0
}

# Database setup - extracted from main function
setup_boundary_database() {
    SQLITE_DB="/var/lib/boundary/boundary.db"
    SQLITE_DIR=$(dirname "$SQLITE_DB")
    
    if [ ! -d "$SQLITE_DIR" ]; then
        log "Creating database directory $SQLITE_DIR..."
        mkdir -p "$SQLITE_DIR" -m 750
        chown boundary:boundary "$SQLITE_DIR"
    fi
    
    if [ ! -f "$SQLITE_DB" ]; then
        log "Creating database file $SQLITE_DB..."
        touch "$SQLITE_DB"
        chmod 640 "$SQLITE_DB"
        chown boundary:boundary "$SQLITE_DB"
    else
        log "SQLite database file already exists at $SQLITE_DB"
        # Fix permissions if needed
        if [ $(stat -c %U:%G "$SQLITE_DB") != "boundary:boundary" ]; then
            log "Fixing database file ownership..."
            chown boundary:boundary "$SQLITE_DB"
        fi
        if [ $(stat -c %a "$SQLITE_DB") != "640" ]; then
            log "Fixing database file permissions..."
            chmod 640 "$SQLITE_DB"
        fi
    fi
    
    log "Verifying SQLite database is accessible..."
    if ! sudo -u boundary sqlite3 "$SQLITE_DB" ".databases" >/dev/null 2>&1; then
        SQLITE_ERROR=$(sudo -u boundary sqlite3 "$SQLITE_DB" ".databases" 2>&1)
        log "ERROR: SQLite database validation failed for path $SQLITE_DB. Error: $SQLITE_ERROR"
        dialog --title "Database Error" --msgbox "SQLite database validation failed.\nError: $SQLITE_ERROR" 8 60
        return 1
    fi
    
    log "Setting up TLS certificates for Boundary..."
    if [ -f "/usr/bin/strongconn.sh" ]; then
        log "Calling set_permissions function to ensure proper certificate symlinks"
        /usr/bin/strongconn.sh -set-permissions
        if [ $? -ne 0 ]; then
            log "WARNING: set-permissions call returned non-zero"
        fi
    else
        log "ERROR: strongconn.sh not found - required for certificate symlinks"
        return 1
    fi
    
    # Verify certificate symlinks exist before continuing
    if [ ! -f "/etc/boundary/server-cert.pem" ] || [ ! -f "/etc/boundary/server-key.pem" ] || [ ! -f "/etc/boundary/ca.pem" ]; then
        log "ERROR: Required certificate symlinks not found"
        dialog --title "Certificate Error" --msgbox "Required TLS certificate symlinks not found.\nPlease ensure Vault PKI is properly configured." 8 60
        return 1
    fi
    
    # Set up Vault for Boundary with proper error handling
    log "Setting up Vault for Boundary..."
    
    # Check if we can access Vault before trying to configure it
    if ! vault status >/dev/null 2>&1; then
        log "ERROR: Cannot access Vault. Check if Vault is running and token is valid"
        dialog --title "Vault Error" --msgbox "Cannot access Vault. Please check if Vault is running and token is valid." 8 60
        return 1
    fi
    
    # Enable transit secrets engine if not already enabled
    if ! vault secrets list | grep -q "^transit/"; then
        log "Enabling transit secrets engine..."
        if ! vault secrets enable -path=transit transit 2>/dev/null; then
            log "ERROR: Failed to enable transit secrets engine"
            dialog --title "Vault Error" --msgbox "Failed to enable transit secrets engine in Vault.\nThis is required for Boundary's KMS functionality." 8 60
            return 1
        fi
    else
        log "Transit secrets engine already enabled"
    fi
    
    # Create the required encryption keys with better error handling
    for key_name in boundary_root boundary_worker_auth boundary_recovery; do
        if ! vault list transit/keys | grep -q "^$key_name$"; then
            log "Creating transit key: $key_name"
            if ! vault write -f transit/keys/$key_name; then
                log "ERROR: Failed to create transit key: $key_name"
                dialog --title "Vault Error" --msgbox "Failed to create transit key: $key_name\nThis is required for Boundary's KMS functionality." 8 60
                return 1
            fi
        else
            log "Transit key already exists: $key_name"
        fi
    done
    
    # Create a proper policy file with correct permissions
    log "Creating Boundary KMS policy..."
    cat > /tmp/boundary-policy.hcl <<EOF
# Grant permissions for KMS functionality
path "transit/encrypt/boundary_root" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/boundary_root" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/boundary_worker_auth" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/boundary_worker_auth" {
  capabilities = ["create", "update"]
}

path "transit/encrypt/boundary_recovery" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/boundary_recovery" {
  capabilities = ["create", "update"]
}

# Allow checking the capabilities of tokens
path "sys/capabilities-self" {
  capabilities = ["update"]
}

# Allow listing of secrets engines
path "sys/mounts" {
  capabilities = ["read"]
}

# Allow Boundary to check Vault health
path "sys/health" {
  capabilities = ["read"]
}

# Allow reading information about the transit keys
path "transit/keys/boundary_root" {
  capabilities = ["read"]
}

path "transit/keys/boundary_worker_auth" {
  capabilities = ["read"]
}

path "transit/keys/boundary_recovery" {
  capabilities = ["read"]
}
EOF
    
    chmod 600 /tmp/boundary-policy.hcl
    
    # Apply the updated policy
    log "Applying Boundary KMS policy..."
    if ! vault policy write boundary-kms /tmp/boundary-policy.hcl; then
        log "ERROR: Failed to apply Boundary KMS policy"
        dialog --title "Vault Error" --msgbox "Failed to apply Boundary KMS policy.\nPlease check Vault logs for details." 8 60
        return 1
    fi
    
    # Create a new token with the boundary-kms policy
    log "Creating Vault token for Boundary..."
    TOKEN_JSON=$(vault token create -policy=boundary-kms -period=720h -explicit-max-ttl=8760h -format=json)
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to create Vault token for Boundary"
        dialog --title "Vault Error" --msgbox "Failed to create Vault token for Boundary.\nPlease check Vault logs for details." 8 60
        return 1
    fi
    
    NEW_TOKEN=$(echo "$TOKEN_JSON" | jq -r '.auth.client_token')
    if [ -z "$NEW_TOKEN" ] || [ "$NEW_TOKEN" = "null" ]; then
        log "ERROR: Failed to extract token from Vault response"
        dialog --title "Vault Error" --msgbox "Failed to extract token from Vault response.\nPlease check Vault logs for details." 8 60
        return 1
    fi
    
    # Update the token in Boundary's vault-token file
    echo "$NEW_TOKEN" > /etc/boundary/vault-token
    chmod 600 /etc/boundary/vault-token
    chown boundary:boundary /etc/boundary/vault-token

    # Only try to update existing config if it exists
    if [ -f "/etc/boundary/boundary.hcl" ]; then
        log "Updating token in existing Boundary configuration..."
        sed -i "s/token[ ]*=[ ]*\".*\"/token      = \"$NEW_TOKEN\"/" /etc/boundary/boundary.hcl
        
        # Reload the service if it's running
        if systemctl is-active --quiet boundary; then
            log "Restarting Boundary service to apply new token..."
            systemctl restart boundary
            
            # Check if restart was successful
            if ! systemctl is-active --quiet boundary; then
                log "ERROR: Failed to restart Boundary service after token update"
                dialog --title "Service Error" --msgbox "Failed to restart Boundary service after token update.\nCheck the logs with 'journalctl -u boundary'" 8 60
                return 1
            fi
        fi
    fi
    
    log "Creating Boundary configuration..."
    # Remove any existing old configuration file to avoid stale settings
    [ -f "$BOUNDARY_CONFIG" ] && mv "$BOUNDARY_CONFIG" "${BOUNDARY_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
    cat > "$BOUNDARY_CONFIG" <<EOF
# Boundary configuration - integrated with ZTNA
# Generated on $(date)

disable_mlock = true

controller {
  name = "boundary-controller"
  description = "StrongConn ZTNA Access Controller"
  
  database {
    url = "sqlite:///var/lib/boundary/boundary.db"
  }
}

worker {
  name = "boundary-worker"
  description = "StrongConn ZTNA Worker"
  initial_upstreams = ["127.0.0.1:9203"]
  public_addr = "${PUBLIC_IP}"
}

# API and Web UI listener
listener "tcp" {
  address = "0.0.0.0:9200"
  purpose = "api"
  tls_cert_file = "/etc/boundary/server-cert.pem"
  tls_key_file = "/etc/boundary/server-key.pem"
  cors_enabled = true
  cors_allowed_origins = ["*"]
  cors_allowed_headers = ["*"]
}

# Cluster listener (controller-worker communication)
listener "tcp" {
  address = "0.0.0.0:9203"
  purpose = "cluster"
  tls_cert_file = "/etc/boundary/server-cert.pem"
  tls_key_file = "/etc/boundary/server-key.pem"
}

# Proxy listener for target connections
listener "tcp" {
  address = "0.0.0.0:9204"
  purpose = "proxy"
  tls_cert_file = "/etc/boundary/server-cert.pem"
  tls_key_file = "/etc/boundary/server-key.pem"
}

# Root KMS configuration
kms "transit" {
  purpose    = "root"
  address    = "${VAULT_ADDR}"
  token      = "${NEW_TOKEN}"
  key_name   = "boundary_root"
  mount_path = "transit"
  ca_cert    = "/etc/boundary/ca.pem"
}

# Worker authentication KMS 
kms "transit" {
  purpose    = "worker-auth"
  address    = "${VAULT_ADDR}"
  token      = "${NEW_TOKEN}"
  key_name   = "boundary_worker_auth"
  mount_path = "transit"
  ca_cert    = "/etc/boundary/ca.pem"
}

# Recovery KMS for disaster recovery
kms "transit" {
  purpose    = "recovery"
  address    = "${VAULT_ADDR}"
  token      = "${NEW_TOKEN}"
  key_name   = "boundary_recovery"
  mount_path = "transit"
  ca_cert    = "/etc/boundary/ca.pem"
}

ui {
  enabled = true
  cors {
    allowed_origins = ["*"]
  }
}

# Events configuration to integrate with logging
events {
  observation_events {
    audit_enabled = true
  }
  sysevents {
    audit_enabled = true
  }
}

# Cache configuration for better performance
cache {
  max_seconds = 300
  max_tokens = 10000
}

EOF

    log "Setting up Boundary service..."
cat > /etc/systemd/system/boundary.service <<EOF
[Unit]
Description=HashiCorp Boundary
Documentation=https://www.boundaryproject.io/docs/
Requires=network-online.target
After=network-online.target vault.service
Wants=vault.service

# Add more specific dependency
ConditionPathExists=/var/lib/vault/data
ConditionPathExists=/etc/boundary/server-cert.pem

[Service]
Type=simple
User=boundary
Group=boundary
ExecStart=$BOUNDARY_BIN server -config $BOUNDARY_CONFIG
ExecReload=/bin/kill --signal HUP \$MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536

# Add health check to ensure service is working
ExecStartPost=/bin/bash -c 'sleep 10 && curl -k -s https://127.0.0.1:9200/v1/health >/dev/null 2>&1 || exit 1'

[Install]
WantedBy=multi-user.target
EOF
    log "Setting permissions..."
  
    
    # Set up the database
    if ! setup_boundary_database; then
        log "ERROR: Failed to set up Boundary database"
        return 1
    fi
    
    # Firewall configuration for Boundary is handled manually
    log "Skipping firewall configuration for Boundary - will be done manually"
    
    # Start and verify Boundary service
    if ! start_and_verify_boundary; then
        log "ERROR: Failed to start and verify Boundary service"
        return 1
    fi

    log "Creating initial Boundary configuration for ZTNA zone '$ZONE_NAME'..."
    # Export BOUNDARY_ADDR for command line usage
    export BOUNDARY_ADDR="https://${PUBLIC_IP}:9200"
    
    # Initialize Boundary database if not already initialized
    if ! $BOUNDARY_BIN database status -config "$BOUNDARY_CONFIG" | grep -q "Database is initialized"; then
        log "Initializing Boundary database..."
        $BOUNDARY_BIN database init -config "$BOUNDARY_CONFIG" || {
            log "Failed to initialize Boundary database"
            return 1
        }
    else
        log "Boundary database already initialized"
    fi
    
    # Initialize the zone using our unified zone initialization function
    init_boundary_zone "$ZONE_ID" "$ZONE_NAME" "$ZONE_RESOURCES" "$BOUNDARY_BIN" "$BOUNDARY_ADDR"
    
    log "Boundary installation completed for ZTNA zone '$ZONE_NAME'!"
    log "Web UI available at: $BOUNDARY_ADDR"
    
    return 0
}

main() {
    log "Starting ZTNA setup for StrongSwan IKEv2 VPN Gateway"
    
    load_base_config
    load_zones_config
    dialog --title "ZTNA Setup for StrongSwan IKEv2 VPN Gateway" \
           --msgbox "Welcome to the Zero Trust Network Access setup!\n\nDefines zones and resources for ZTNA clients, using XFRM policies and nftables IP sets.\n\nEach client gets a /32 from $ZTNA_IP_POOL (shared with road warriors), isolated via XFRM and ipset.\nBase firewall assumed loaded; ZTNA rules added to /etc/nftables.d/ztna.conf.\n\nLogs are in $LOG_FILE and $UPDOWN_LOG_FILE" 16 60
    
    define_zones
    
    if [ ${#ZONES[@]} -eq 0 ]; then
        dialog --title "Warning" --msgbox "No zones defined. At least one zone is required to proceed.\n\nPlease define a zone before continuing." 8 60
        exit 1
    fi
    
    generate_policy_conf
    generate_updown_script
    generate_ztna_conf
    generate_radius_conf
    append_syslog_ng_config
    
    update_config "ZTNA_IP_POOL" "$ZTNA_IP_POOL"
    update_config "ZTNA_ENABLED" "true"
    
    # Collect zones with Boundary enabled
    BOUNDARY_ZONES=()
    for zone in "${!ZONES[@]}"; do
        if [ "${ZONE_BOUNDARY_ENABLED[$zone]}" = "yes" ]; then
            BOUNDARY_ZONES+=("$zone")
        fi
    done
    
    dialog --title "ZTNA Setup Complete" \
           --msgbox "ZTNA configuration completed successfully!\n\nConfiguration files:\n- $POLICY_CONF\n- $UPDOWN_SCRIPT\n- $ZTNA_CONF\n- $RADIUS_CONF\n\nZones configured: ${#ZONES[@]}\nBoundary enabled for ${#BOUNDARY_ZONES[@]} zone(s)\n\nLogs are available at:\n- $LOG_FILE\n- $UPDOWN_LOG_FILE\n\nFor troubleshooting, check these logs first." 16 70
    
    dialog --title "Apply Configuration" \
           --yesno "WARNING: Applying settings will reload nftables ZTNA rules if not present, clearing all IP sets and disrupting existing ZTNA connections until clients reconnect. Road warriors using certs should remain unaffected.\n\nApply now?" 10 60
    
    if [ $? -eq 0 ]; then
        log "Applying ZTNA configurations"
        
        # Show progress gauge for configuration application
        (
            echo "10"; sleep 1
            echo "XXX"; echo "Applying NFTables ruleset..."; echo "XXX"
            echo "30"; 
            apply_nftables_sets >/dev/null 2>&1
            echo "XXX"; echo "Reloading SwanCtl configuration..."; echo "XXX"
            echo "60"; 
            swanctl --load-all >/dev/null 2>&1 && log "Reloaded SwanCtl configuration" || log "Failed to reload SwanCtl configuration"
            echo "XXX"; echo "Finalizing configuration..."; echo "XXX"
            echo "90"; sleep 1
            echo "100"
        ) | dialog --title "Applying Configuration" --gauge "Deploying ZTNA configuration..." 10 70 0
        
        if systemctl is-active apparmor > /dev/null; then
            log "Creating AppArmor profile for ZTNA..."
            mkdir -p /etc/apparmor.d/local
            # [AppArmor profile creation unchanged]
            chmod 640 /etc/apparmor.d/local/var.lib.strongswan.ztna-updown
            log "AppArmor profile for ZTNA created. Set to complain mode initially."
            aa-complain /etc/apparmor.d/local/var.lib.strongswan.ztna-updown 2>/dev/null || log "Could not set ZTNA AppArmor profile to complain mode"
        fi
        
        dialog --title "Success" --msgbox "ZTNA configurations applied successfully!\n\nThe system is now configured with your ZTNA zones and policies.\n\nFor troubleshooting, check logs at:\n- $LOG_FILE\n- $UPDOWN_LOG_FILE" 12 70
        
        # Process Boundary installation for selected zones
        if [ ${#BOUNDARY_ZONES[@]} -gt 0 ]; then
            log "Starting Boundary installation for ${#BOUNDARY_ZONES[@]} zone(s)..."
            
            # Create a progress gauge for multi-zone Boundary installation
            (
                echo "0"; sleep 1
                echo "XXX"; echo "Preparing for Boundary installation..."; echo "XXX"
                echo "10"
                
                # Calculate progress increment based on number of zones
                zone_count=${#BOUNDARY_ZONES[@]}
                prog_step=$((80 / zone_count))
                current_prog=10
                
                echo "XXX"; echo "Installing Boundary for ${zone_count} zone(s)..."; echo "XXX"
                echo "$current_prog"
                sleep 1
            ) | dialog --title "Boundary Installation" --gauge "Installing Boundary for ${#BOUNDARY_ZONES[@]} zone(s)..." 10 70 0
            
            for zone in "${BOUNDARY_ZONES[@]}"; do
                ZONE_NAME="${ZONES[$zone]}"
                RESOURCES="${ZONE_RESOURCES[$zone]}"
                
                log "Setting up Boundary for zone $ZONE_NAME with resources: $RESOURCES"
                export ZTNA_ZONE_ID="$zone"
                export ZTNA_ZONE_NAME="$ZONE_NAME"
                export ZTNA_ZONE_RESOURCES="$RESOURCES"
                
                if [ -f "/usr/bin/strongconn.sh" ]; then
                    source "/usr/bin/strongconn.sh" 2>/dev/null
                else
                    source "$BASE_CONFIG" 2>/dev/null
                fi
                
                # Use function directly
                install_boundary "$zone" "$ZONE_NAME" "$RESOURCES"
                if [ $? -eq 0 ]; then
                    log "Boundary installation successful for zone $ZONE_NAME"
                    dialog --msgbox "Boundary successfully installed for zone '$ZONE_NAME'\nAccess UI at https://${PUBLIC_IP}:9200" 8 60
                else
                    log "ERROR: Boundary installation failed for zone $ZONE_NAME"
                    dialog --msgbox "Boundary installation failed for zone '$ZONE_NAME'\nCheck logs." 6 50
                fi
            done
        fi
    fi
   /usr/bin/strongconn.sh -set-permissions
    log "ZTNA setup completed"
}

main