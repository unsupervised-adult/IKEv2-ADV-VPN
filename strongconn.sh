#!/bin/bash
#
# Script: strongconn.sh
# Location: /strongconn/strongconn.sh
#
#
# Usage:
#   ./strongconn.sh -install -debug -update 
#
#   2 Okta Auth Requires Okta Radius Agent to be installed Post Installation
#
# Author: Felix C Frank 2024
# Version: 1.7.50.1
# Created: 27-12-24
#
# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
# 
# This file is the main installation script for StrongSwan IKEv2 Server
# it also has a series of helper functions to help with maintenance and configuration
# 
# This script is designed to be used on Debian based virtualised vm only aws,vmware,proxmox etc
# =================================================================================================
# 
# 
# feedback mailto:felix.c.frank@proton.me
# =================================================================================================
CONFIG_PATH="/etc/strongconn.conf"
HELPER_PATH="/usr/bin"


log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1"
}

error_exit() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" 1>&2
    exit 1
}

    if [ ! -f "$CONFIG_PATH" ]; then
        log "Configuration file not found. Creating default configuration file..."
        cp ./strongconn.conf "$CONFIG_PATH" || error_exit "Failed to copy config to /etc"
        cp ./classifications.conf /etc/classifications.conf || error_exit "Failed to copy classifications to /etc"
        chmod 640 "$CONFIG_PATH" || error_exit "Failed to set permissions on config"
    fi
 
load_config() {
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

function wait_for_apt_lock() {
    local retries=10
    local wait_time=5
    local count=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [ $count -ge $retries ]; then
            log "Could not acquire dpkg lock after $((retries*wait_time)) seconds. Aborting."
            return 1
        fi
        log "Another apt process is running. Waiting $wait_time seconds (-attempt $((count+1))/$retries)."
        sleep $wait_time
        count=$((count+1))
    done
    return 0
}

kernel_updates() {
    if [ "$1" = "true" ]; then
        apt-mark unhold linux-image* linux-headers*
        echo "Kernel updates via apt have been enabled."
    elif [ "$1" = "false" ]; then
        apt-mark hold linux-image* linux-headers*
        echo "Kernel updates via apt have been disabled."
    else
        echo "Invalid option. Use 'true' or 'false'."
    fi
}

install_helper(){
    if [ ! -f "$HELPER_PATH/v-pki" ]; then
        echo "v-pki file not found. Creating default helper file..."
    cd ~/ || error_exit "Failed to change directory to home"
    cd "$SCRIPT_DIR" || error_exit "failed to return to script dir"
    cp "$SCRIPT_DIR/_scripts/v-pki" /usr/bin/v-pki || error_exit "failed to copy helper to /usr/bin"
    chmod 640 /usr/bin/v-pki || error_exit "failed to set helper permissions"
    chmod +x /usr/bin/v-pki || error_exit "failed to set  helper executable"
    fi
}

reload_swanctl() {
    log "Reloading swanctl configuration..."
    swanctl --load-all
    swanctl --load-creds
    log "swanctl configuration reloaded."
}


detect_vpn_mode() {
    if is_nat_needed; then
        VPN_MODE="NAT"
    elif is_dhcp_proxy_enabled; then
        VPN_MODE="DHCP"
    else
        VPN_MODE="ROUTED"
    fi
}

detect_vps_environment() {
    log "Detecting if running in VPS environment..."
    INTERFACE_COUNT=$(ip -4 addr show | grep -v "127.0.0.1" | grep "inet" | wc -l)
    DEFAULT_IP=$(ip -4 addr show dev "$DEFAULT_INTERFACE" | awk '/inet/ {print $2}' | cut -d/ -f1)
    PUBLIC_IP=$(get_public_ip)
    if [ "$INTERFACE_COUNT" -le 1 ] || [ "$DEFAULT_IP" = "$PUBLIC_IP" ]; then
        log "VPS environment detected."
        IS_VPS_ENVIRONMENT=true
    else
        log "Standard environment detected (not a VPS)."
        IS_VPS_ENVIRONMENT=false
    fi
    export IS_VPS_ENVIRONMENT
    echo "IS_VPS_ENVIRONMENT=\"$IS_VPS_ENVIRONMENT\"" >> "$CONFIG_PATH"
}

configure_dns() {

    if [ -f "$CONFIG_PATH" ]; then
        . "$CONFIG_PATH"
        echo "Configuration file loaded."
    else
        echo "Configuration file not found at $CONFIG_PATH. Exiting."
        exit 1
    fi


    if [ -z "$DNS_SERVERS" ]; then
        echo "ERROR: DNS_SERVERS variable is empty. Please specify at least one nameserver."
        exit 1
    fi

  
    echo "Received DNS servers: $DNS_SERVERS"

    dns_array=(${DNS_SERVERS//,/ })


    echo "dns_array has ${#dns_array[@]} elements:"
    for dns in "${dns_array[@]}"; do
        echo "dns_array element: '$dns'"
    done

    echo "Configuring DNS..."


    echo "# Generated by configure_dns function" | tee /etc/resolv.conf > /dev/null

  
    for dns in "${dns_array[@]}"; do
        echo "Adding nameserver: $dns"
        echo "nameserver $dns" | tee -a /etc/resolv.conf > /dev/null
    done


    if [ -s /etc/resolv.conf ]; then
        echo "DNS configuration successful. Contents of /etc/resolv.conf:"
        cat /etc/resolv.conf
    else
        echo "ERROR: Failed to update /etc/resolv.conf"
    fi

    echo "Writing /etc/hosts file with configured variables..."

  
    local hostname=$(echo "$DNS_NAME" | cut -d '.' -f 1)

    echo "$DNS_NAME" | tee /etc/hostname > /dev/null
    hostname "$DNS_NAME"


    cp /etc/hosts /etc/hosts.bak

  
    cat <<EOF | tee /etc/hosts > /dev/null
# /etc/hosts file generated by configure_dns function
127.0.0.1       localhost
127.0.1.1       $DNS_NAME $hostname

# The following lines are desirable for IPv6 capable hosts
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

# Custom host entries
$DEFAULT_IP     $DNS_NAME $hostname
$PUBLIC_IP      $DNS_NAME $hostname
EOF

    echo "Hosts file updated successfully."
}

       # Trim whitespace function
trim_value() {
        local value="$1"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        echo "$value"
 }

get_public_ip() {
    local ip=""
    local timeout=3
    local retries=2

    # Check if curl is available
    if ! command -v curl >/dev/null 2>&1; then
        log "ERROR: curl is not installed. Installing..." >&2
        apt-get update >/dev/null 2>&1 && apt-get install -y curl >/dev/null 2>&1
    fi

    for service in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com" "https://ipinfo.io/ip"; do
        for ((i=1; i<=retries; i++)); do
            ip=$(curl -s --connect-timeout "$timeout" "$service" 2>/dev/null)
            if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                log "Detected public IP from $service: $ip" >&2  # Redirect log to stderr
                echo "$ip"
                return 0
            fi
            [ $i -lt $retries ] && sleep 1
        done
    done

    if command -v dig >/dev/null 2>&1; then
        for ((i=1; i<=retries; i++)); do
            ip=$(dig +short +timeout="$timeout" myip.opendns.com @resolver1.opendns.com 2>/dev/null)
            if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                log "Detected public IP via dig" >&2
                echo "$ip"
                return 0
            fi
            [ $i -lt $retries ] && sleep 1
        done
    fi
    
    if [ -n "$DEFAULT_INTERFACE" ]; then
        ip=$(ip -4 addr show dev "$DEFAULT_INTERFACE" 2>/dev/null | awk '/inet/ {print $2}' | cut -d/ -f1)
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log "WARNING: Using local IP from $DEFAULT_INTERFACE" >&2
            echo "$ip"
            return 0
        fi
    fi
    
    ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n1)
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "WARNING: Using first available non-loopback IP" >&2
        echo "$ip"
        return 0
    fi

    log "ERROR: Could not determine any valid IP address" >&2
    return 1
}

    
# Auto-detection function
autopopulate_config() {
    log "Autopopulating configuration..."    
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' || ip link | grep -v "lo:" | head -n1 | awk -F': ' '{print $2}')
    DEFAULT_IP=$(ip -4 addr show dev "$DEFAULT_INTERFACE" | awk '/inet/ {print $2}' | cut -d/ -f1)
    DEFAULT_GATEWAY=$(ip route | grep default | awk '{print $3}')
    PUBLIC_IP=$(get_public_ip)
    DNS_SERVERS=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | grep -v "127.0.0.1" | paste -sd, - || echo "1.1.1.1,8.8.8.8")
    IP_POOL="192.168.100.0/24"
    IP_RANGE="192.168.100.1-192.168.100.254"
    INTERFACE_COUNT=$(ip -4 addr show | grep -v "127.0.0.1" | grep "inet" | wc -l)
    DEFAULT_IP=$(ip -4 addr show dev "$DEFAULT_INTERFACE" | awk '/inet/ {print $2}' | cut -d/ -f1)
    PUBLIC_IP=$(get_public_ip)
    # Simplified VPS detection - if public IP is same as interface IP, it's a VPS
    if [ "$DEFAULT_IP" = "$PUBLIC_IP" ]; then
        log "VPS environment detected (public IP matches interface IP)"
        ROUTE_SUBNETS="192.168.100.0/24"
        IS_VPS_ENVIRONMENT=true
    else
        log "Standard environment detected (public IP differs from interface IP)"
        ROUTE_SUBNETS=$(ip -4 addr show | grep -v "127.0.0.1" | grep "inet" | awk '{print $2}' | cut -d'/' -f1 | sed 's/\.[0-9]*$/.0\/24/' | tr '\n' ',' | sed 's/,$//')
        IS_VPS_ENVIRONMENT=false
    fi
    DNS_NAME=$(hostname -f || echo "vpn-$(hostname).local")
    RADIUS_SECRET=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
    RADIUS_SECRET2="$RADIUS_SECRET"
    RADIUS_PORT="1812"
    RADIUS_PORT2="1813"
    ARCTICWOLF_IP=""
    S_DOMAIN=$(grep -E "^search" /etc/resolv.conf | awk '{print $2}' | head -n1 || echo "local")
    REPORT_EMAIL="admin@example.com"
    COUNTRY=$(locale | grep "LC_TIME" | cut -d= -f2 | cut -d_ -f2 | cut -d. -f1 || echo "US")
    STATE=""
    CITY=""
    ORGANIZATION=""
    ORG_UNIT="IT Security"
    PFX_PASSWORD=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12)
    CA_NAME="$ORGANIZATION Authority"
}


# Update config file using sed
update_config() {
    log "Updating config file with sed: $CONFIG_PATH"
    
    update_var() {
        local var="$1"
        local value="$2"
        local trimmed=$(trim_value "$value")
        trimmed=$(echo "$trimmed" | sed 's/[\/&]/\\&/g')
        sed -i "/^${var}=/c\\${var}=\"${trimmed}\"" "$CONFIG_PATH"
    }
    
    update_var "VPN_MODE" "$VPN_MODE"
    update_var "DEFAULT_INTERFACE" "$DEFAULT_INTERFACE"
    update_var "DEFAULT_IP" "$DEFAULT_IP"
    update_var "DEFAULT_GATEWAY" "$DEFAULT_GATEWAY"
    update_var "PUBLIC_IP" "$PUBLIC_IP"
    update_var "DNS_SERVERS" "$DNS_SERVERS"
    update_var "IP_POOL" "$IP_POOL"
    update_var "IP_RANGE" "$IP_RANGE"
    update_var "ROUTE_SUBNETS" "$ROUTE_SUBNETS"
    update_var "DNS_NAME" "$DNS_NAME"
    update_var "RADIUS_SECRET" "$RADIUS_SECRET"
    update_var "RADIUS_SECRET2" "$RADIUS_SECRET2"
    update_var "RADIUS_PORT" "$RADIUS_PORT"
    update_var "RADIUS_PORT2" "$RADIUS_PORT2"
    update_var "ARCTICWOLF_IP" "$ARCTICWOLF_IP"
    update_var "S_DOMAIN" "$S_DOMAIN"
    update_var "REPORT_EMAIL" "$REPORT_EMAIL"
    update_var "COUNTRY" "$COUNTRY"
    update_var "STATE" "$STATE"
    update_var "CITY" "$CITY"
    update_var "ORGANIZATION" "$ORGANIZATION"
    update_var "ORG_UNIT" "$ORG_UNIT"
    update_var "PFX_PASSWORD" "$PFX_PASSWORD"
    update_var "CA_NAME" "$CA_NAME"
    
    log "Config updated. Current content:"
    cat "$CONFIG_PATH" >> "$LOG_FILE"
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        if [[ ${octets[0]} -le 255 && ${octets[1]} -le 255 && ${octets[2]} -le 255 && ${octets[3]} -le 255 ]]; then
            return 0
        fi
    fi
    return 1
}

validate_cidr() {
    local cidr="$1"
    if [[ "$cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        local ip=$(echo "$cidr" | cut -d/ -f1)
        local prefix=$(echo "$cidr" | cut -d/ -f2)
        if validate_ip "$ip" && [[ "$prefix" -ge 0 && "$prefix" -le 32 ]]; then
            return 0
        fi
    fi
    return 1
}

check_dns_resolution() {
    local test_domain="google.com"
    log "checking DNS resolution..."
    if ! ping -c 1 "$test_domain" &> /dev/null; then
        error_exit "DNS resolution check failed. Please check your DNS is correctly configured."
    fi
}

check_root() {
    if [ "$(id -u)" != 0 ]; then
        error_exit "Script must be run as root. Try 'bash $0'."
    fi
}


check_os() {
    log "Checking OS compatibility..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release  
        if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
            log "Unsupported OS. This script only supports Debian-based systems."
            exit 1  
        fi
    else
        error_exit "Unable to determine OS type. This script only supports Debian-based systems."
    fi
    log "OS check completed. System is compatible."
}

check_network() {
    log "checking network connectivity..."
    if ! ping -c 3 google.com; then
        error_exit "Network connectivity check failed. Please check you have an active internet connection."
    fi
}

check_strongswan_group() {

    if ! getent group vault > /dev/null; then
        echo "Creating 'vault' group..."
        groupadd vault || {
            echo "Error: Failed to create 'vault' group."
            exit 1
        }
    else
        echo "'vault' group already exists."
    fi


    if ! id -u vault > /dev/null 2>&1; then
        echo "Creating 'vault' user..."
        useradd -r -g vault -s /sbin/nologin vault || {
            echo "Error: Failed to create 'vault' user."
            exit 1
        }
    else
        echo "'vault' user already exists."
    fi
      echo "Setting up users and groups for StrongSwan and OCSP..."

    if ! getent group boundary > /dev/null; then
        groupadd boundary || {
            echo "Error: Failed to create 'boundary' group."
            exit 1
        }
    fi
    
    if ! id "boundary" &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin -g boundary "boundary"
        log "Created boundary service user and group"
    fi
    if ! getent group strongswan > /dev/null; then
        echo "Creating 'strongswan' group..."
        groupadd strongswan || {
            echo "Error: Failed to create 'strongswan' group."
            exit 1
        }
    else
        echo "'strongswan' group already exists."
    fi

    if ! id -u strongswan > /dev/null 2>&1; then
        echo "Creating 'strongswan' user..."
        useradd -r -g strongswan -s /sbin/nologin strongswan || {
            echo "Error: Failed to create 'strongswan' user."
            exit 1
        }
    else
        echo "'strongswan' user already exists."
    fi
    if ! getent group okta-service > /dev/null; then
        echo "Creating 'okta-service' group..."
        groupadd okta-service || {
            echo "Error: Failed to create 'okta-service' group."
            exit 1
        }
    fi
    if ! id -u okta-service > /dev/null 2>&1; then
        echo "Creating Okta service user..."
        useradd -r -g okta-service -s /sbin/nologin okta-service || {
            echo "Error: Failed to create 'okta-service' user."
            exit 1
        }
    else
        echo "'Okta service' user already exists."
    fi
        if ! getent group suricatawatchdog > /dev/null; then
        echo "Creating 'suricatawatchdog' group..."
        groupadd suricatawatchdog || {
            echo "Error: Failed to create 'suricatawatchdog' group."
            exit 1
        }
    fi
    if ! id -u suricatawatchdog > /dev/null 2>&1; then
        echo "Creating suricatawatchdog user..."
        useradd -r -g suricatawatchdog -s /sbin/nologin suricatawatchdog || {
            echo "Error: Failed to create 'suricatawatchdog' user."
            exit 1
        }
    else
        echo "'suricatawatchdog' user already exists."
    fi
    
        if ! getent group suricata > /dev/null; then
        echo "Creating 'suricata' group..."
        groupadd suricata || {
            echo "Error: Failed to create 'suricata' group."
            exit 1
        }
    fi
    if ! id -u suricata > /dev/null 2>&1; then
        echo "Creating suricata user..."
        useradd -r -g suricata -s /sbin/nologin suricata || {
            echo "Error: Failed to create 'suricata' user."
            exit 1
        }
    else
        echo "'suricata' user already exists."
    fi
       
}

check_charon_socket_permissions() {
    touch /var/run/charon.vici
    chown root:strongswan /var/run/charon.vici
    chmod 770 /var/run/charon.vici
}


# Set permissions for Boundary zone credentials

set_permissions() {
    log "Applying permissions, ACLs, creating missing directories, and repairing symlinks..."
    local errors=0
    local warnings=0

    # === SECTION 1: CREATE DIRECTORIES ===
    log "Creating necessary directories if missing..."
    # Base directories
    mkdir -p /opt/pki/private /opt/pki/x509 /opt/pki/crl 2>/dev/null
    mkdir -p /etc/nftables.d 2>/dev/null
    mkdir -p /etc/swanctl/x509 /etc/swanctl/private 2>/dev/null
    mkdir -p /etc/nginx/crl 2>/dev/null
    mkdir -p /var/lib/vault/data /etc/vault 2>/dev/null
    mkdir -p /etc/apparmor.d/local 2>/dev/null
    mkdir -p /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null
    mkdir -p /var/log/aide 2>/dev/null
    mkdir -p /etc/zt/ztna.conf.d 2>/dev/null
    mkdir -p /var/lib/boundary /etc/boundary/zones 2>/dev/null
    mkdir -p /var/lib/suricata/rules 2>/dev/null
    mkdir -p /var/log/suricata 2>/dev/null
    mkdir -p /etc/suricata/rules/custom 2>/dev/null
    mkdir -p /opt/pki/crl 2>/dev/null
    mkdir -p /etc/nginx/conf.d 2>/dev/null
    mkdir -p /etc/nginx/sites-available 2>/dev/null
    mkdir -p /var/lib/strongswan 2>/dev/null
    mkdir -p /var/lib/strongswan/charon 2>/dev/null
    mkdir -p /var/www/html 2>/dev/null
    mkdir -p /etc/nginx/conf.d/ 2>/dev/null
    mkdir -p /var/log/nginx 2>/dev/null
    mkdir -p /var/cache/nginx 2>/dev/null
    mkdir -p /etc/nginx/modules-enabled 2>/dev/null
    mkdir -p /etc/nginx/sites-enabled 2>/dev/null
    mkdir -p /usr/share/nginx/html 2>/dev/null


    # === SECTION 2: BASE PERMISSIONS ===
    log "Setting base ownership and permissions..."
    # Core directories
    chown -R root:root /opt/pki /etc/swanctl >/dev/null 2>&1 || ((warnings++))
    chmod 751 /opt/pki/private /etc/swanctl /etc/swanctl/x509 /etc/nginx >/dev/null 2>&1 || ((warnings++))
    chmod 750 /etc/swanctl/private >/dev/null 2>&1 || ((warnings++))
    chmod 755 /opt/pki/x509 /opt/pki/crl >/dev/null 2>&1 || ((warnings++))
    chmod 755 /etc/nginx/crl >/dev/null 2>&1 || ((warnings++))
    chmod 644 /etc/nftables.d/* >/dev/null 2>&1 || ((warnings++))
    
    # Boundary DB permissions
    if [ -f "/var/lib/boundary/boundary.db" ]; then 
        chown boundary:boundary /var/lib/boundary/boundary.db >/dev/null 2>&1 || ((warnings++))
        chmod 640 /var/lib/boundary/boundary.db >/dev/null 2>&1 || ((warnings++))
    fi
    # Set proper ownership and permissions
    chown -R suricata:suricata /var/log/suricata /var/lib/suricata /etc/suricata >/dev/null 2>&1 || ((warnings++))
    chmod -R 755 /var/log/suricata /var/lib/suricata /etc/suricata >/dev/null 2>&1 || ((warnings++))

    # Apply ACLs
    setfacl -R -m u:suricata:rwx /var/log/suricata /var/lib/suricata /etc/suricata >/dev/null 2>&1 || ((warnings++))

    # === SECTION 3: VAULT DIRECTORIES ===
    log "Setting Vault directory permissions..."
    # Vault directories with specific permissions
    chown vault:vault /var/lib/vault /var/lib/vault/data /etc/vault /etc/vault/config.hcl >/dev/null 2>&1 || ((warnings++))
    chmod 750 /var/lib/vault /etc/vault /var/lib/vault/data >/dev/null 2>&1 || ((warnings++))
    chmod 750 /etc/vault >/dev/null 2>&1 || ((warnings++))
    chmod 640 /etc/vault/config.hcl >/dev/null 2>&1 || ((warnings++))
    chown -R vault:vault /var/lib/vault /etc/vault >/dev/null 2>&1 || ((warnings++))
 
    # === SECTION 4: SECURITY HARDENING ===
    log "Setting security-hardened permissions for system files..."
    # SSH and cron security
    chmod 600 /etc/ssh/sshd_config >/dev/null 2>&1 || ((warnings++))
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly >/dev/null 2>&1 || ((warnings++))
    chmod 600 /etc/crontab >/dev/null 2>&1 || ((warnings++))
    chmod 750 /var/lib/boundary /etc/boundary/zones >/dev/null 2>&1 || ((warnings++))
    
    # Cron scripts
    find /etc/cron.daily -type f -exec chmod 700 {} \; >/dev/null 2>&1
    
    # AppArmor profiles
    if [ -d "/etc/apparmor.d/local" ]; then
        chmod 750 /etc/apparmor.d/local >/dev/null 2>&1 || ((warnings++))
        find /etc/apparmor.d/local -type f -exec chmod 640 {} \; >/dev/null 2>&1
    fi
    
    # System config files
    find /etc/sysctl.d -type f -name "*.conf" -exec chmod 644 {} \; >/dev/null 2>&1
    find /etc/systemd/system.conf.d -type f -exec chmod 644 {} \; >/dev/null 2>&1 
    find /etc/systemd/system -path "*/service.d/*.conf" -exec chmod 644 {} \; >/dev/null 2>&1
    
    # === SECTION 5: SYMLINK REPAIR ===
    log "Repairing broken symlinks..."
    # Clean up broken symlinks
    find /etc -type l -exec test ! -e {} \; -delete >/dev/null 2>&1
    find /opt -type l -exec test ! -e {} \; -delete >/dev/null 2>&1
    find /var -type l -exec test ! -e {} \; -delete >/dev/null 2>&1
    
    # Create required symlinks if missing
    if [ ! -e "/etc/nginx/sites-enabled" ] && [ -d "/etc/nginx/sites-available" ]; then
        ln -sf /etc/nginx/sites-available /etc/nginx/sites-enabled >/dev/null 2>&1 || ((warnings++))
    fi
    if [ -d "/etc/boundary/zones" ]; then
        find /etc/boundary/zones -name "credentials.txt" -exec chown boundary:boundary {} \; -exec chmod 600 {} \; >/dev/null 2>&1
    fi

    # === SECTION 6: LOG DIRECTORY PERMISSIONS ===
    log "Setting log directory permissions..."
    # Nginx logs
    chown -R root:adm /var/log/nginx >/dev/null 2>&1 || ((warnings++))
    chmod -R 750 /var/log/nginx >/dev/null 2>&1 || ((warnings++))

    # Suricata logs
    chown -R suricata:suricata /var/log/suricata >/dev/null 2>&1 || ((warnings++))
    chmod -R 750 /var/log/suricata >/dev/null 2>&1 || ((warnings++))
    
    # Specific Suricata log files for syslog-ng
    for suricata_log in /var/log/suricata/eve.json /var/log/suricata/fast.log /var/log/suricata/suricata.log /var/log/suricata/stats.log; do
        [ -f "$suricata_log" ] || touch "$suricata_log" >/dev/null 2>&1
        chown suricata:adm "$suricata_log" >/dev/null 2>&1 || ((warnings++))
        chmod 640 "$suricata_log" >/dev/null 2>&1 || ((warnings++))
    done
    
    # Watchdog logs
    [ -d /var/log/suricata_watchdog_actions ] || mkdir -p /var/log/suricata_watchdog_actions >/dev/null 2>&1
    [ -f /var/log/suricata_watchdog_actions/actions.log ] || touch /var/log/suricata_watchdog_actions/actions.log >/dev/null 2>&1
    chown suricatawatchdog:adm /var/log/suricata_watchdog_actions/actions.log >/dev/null 2>&1 || ((warnings++))
    chmod 640 /var/log/suricata_watchdog_actions/actions.log >/dev/null 2>&1 || ((warnings++))

    # System logs
    for sys_log in /var/log/auth.log /var/log/cron.log /var/log/charon.log /var/log/swanctl_user_check.log; do
        [ -f "$sys_log" ] || touch "$sys_log" >/dev/null 2>&1
        chown root:adm "$sys_log" >/dev/null 2>&1 || ((warnings++))
        chmod 640 "$sys_log" >/dev/null 2>&1 || ((warnings++))
    done

    # === SECTION 7: ACCESS CONTROL LISTS ===
    log "Setting up ACLs for service accounts..."
    # Suricata watchdog ACLs
    setfacl -d -m u:suricatawatchdog:r /var/log/suricata >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:suricatawatchdog:rx /var/log/suricata >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:suricatawatchdog:r /var/log/suricata/eve.json >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:suricatawatchdog:rwx /var/log/suricata_watchdog_actions/actions.log >/dev/null 2>&1 || ((warnings++))

    # Config file ACLs
    setfacl -m u:suricatawatchdog:r /etc/strongconn.conf /etc/classifications.conf >/dev/null 2>&1 || ((warnings++))

    # Execution ACLs
    setfacl -m u:suricatawatchdog:rx /usr/bin/python3 >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:vault:rx /usr/bin/v-pki >/dev/null 2>&1 || ((warnings++))

    # StrongSwan & Okta service ACLs
    setfacl -R -m u:okta-service:rwx /opt/pki /var/lib/strongswan /etc/swanctl /etc/strongconn.conf /usr/bin/v-pki >/dev/null 2>&1 || ((warnings++))

    # Python files ACLs
    if [ -f "/var/lib/strongswan/local_event.py" ]; then
        chmod 644 /var/lib/strongswan/local_event.py >/dev/null 2>&1 || ((warnings++))
        chown okta-service:okta-service /var/lib/strongswan/local_event.py >/dev/null 2>&1 || ((warnings++))
        setfacl -m u:okta-service:rwx /var/lib/strongswan/local_event.py >/dev/null 2>&1 || ((warnings++))
    fi
    
    if [ -f "/var/lib/strongswan/tasks.py" ]; then
        chmod 644 /var/lib/strongswan/tasks.py >/dev/null 2>&1 || ((warnings++))
        chown okta-service:okta-service /var/lib/strongswan/tasks.py >/dev/null 2>&1 || ((warnings++))
        setfacl -m u:okta-service:rwx /var/lib/strongswan/tasks.py >/dev/null 2>&1 || ((warnings++))
    fi
    
    # Boundary ACLs
    setfacl -m u:boundary:r /opt/pki/x509/boundary-ip.pem /opt/pki/private/boundary-ip-key.pem /opt/pki/x509/ca.pem /etc/boundary/zones >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:boundary:r /etc/boundary/server-cert.pem /etc/boundary/server-key.pem /etc/boundary/ca.pem >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:boundary:r /etc/boundary/zones >/dev/null 2>&1 || ((warnings++))
    # For Vault
    setfacl -R -m u:vault:rwx /var/lib/vault /etc/vault >/dev/null 2>&1 || ((warnings++))
    setfacl -R -m u:vault:rwx /var/lib/vault/data >/dev/null 2>&1 || ((warnings++))
    setfacl -R -m u:vault:rwx /var/lib/vault/tls >/dev/null 2>&1 || ((warnings++))
    setfacl -R -m u:vault:rwx /var/lib/vault/tls/vault.pem /var/lib/vault/tls/vault-key.pem >/dev/null 2>&1 || ((warnings++))
    setfacl -R -m u:vault:rwx /etc/vault/config.hcl >/dev/null 2>&1 || ((warnings++))

# For Suricata
    setfacl -R -m u:suricata:rwx /var/log/suricata /var/lib/suricata >/dev/null 2>&1 || ((warnings++))
    setfacl -d -m u:suricata:rxw /var/lib/suricata >/dev/null 2>&1 || ((warnings++))
    setfacl -d -m u:suricata:rxw /etc/suricata >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:suricata:rxw /var/lib/suricata >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:suricata:rxw /etc/suricata >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:suricata:rxw /var/log/suricata/eve.json >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:suricata:rxw /var/log/suricata/fast.log >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:suricata:rxw /var/log/suricata/stats.log >/dev/null 2>&1 || ((warnings++))
    setfacl -m u:suricata:rxw /var/log/suricata/suricata.log >/dev/null 2>&1 || ((warnings++))

    # Other service ACLs
    setfacl -R -m u:suricatawatchdog:rx /opt/pki /var/lib/strongswan >/dev/null 2>&1 || ((warnings++))
    setfacl -R -m g:strongswan:rx /etc/swanctl >/dev/null 2>&1 || ((warnings++))
    setfacl -R -m u:www-data:rwx /var/log/nginx /var/cache/nginx >/dev/null 2>&1 || ((warnings++))
    setfacl -R -m d:u:www-data:rwx /var/log/nginx /var/cache/nginx >/dev/null 2>&1 || ((warnings++))
    setfacl -R -m u:boundary:rwx -m g:boundary:rx /var/lib/boundary /etc/boundary/zones >/dev/null 2>&1 || ((warnings++))
    
    # Vault access ACLs
    setfacl -m u:vault:r /opt/pki/x509/vault.pem /opt/pki/x509/ca.pem /opt/pki/crl/crl.der /opt/pki/private/vault-key.pem /etc/strongconn.conf >/dev/null 2>&1 || ((warnings++))

        # Nginx ACLs
    setfacl -R -m u:www-data:rwx,g:www-data:rwx,o:r-x /var/www/html >/dev/null 2>&1 || ((warnings++))
    setfacl -R -d -m u:www-data:rwx,g:www-data:rwx,o:r-x /var/www/html >/dev/null 2>&1 || ((warnings++))
    # Set ACLs for NGINX configuration directory
    setfacl -R -m u:www-data:rwx,g:www-data:rwx,o:r-x /etc/nginx >/dev/null 2>&1 || ((warnings++))
    setfacl -R -d -m u:www-data:rwx,g:www-data:rwx,o:r-x /etc/nginx >/dev/null 2>&1 || ((warnings++))

    # Set ACLs for NGINX log directory
    setfacl -R -m u:www-data:rwx,g:www-data:rwx,o:r-x /var/log/nginx >/dev/null 2>&1 || ((warnings++))
    setfacl -R -d -m u:www-data:rwx,g:www-data:rwx,o:r-x /var/log/nginx >/dev/null 2>&1 || ((warnings++))

    # Set ACLs for NGINX cache directory
    setfacl -R -m u:www-data:rwx,g:www-data:rwx,o:r-x /var/cache/nginx >/dev/null 2>&1 || ((warnings++))
    setfacl -R -d -m u:www-data:rwx,g:www-data:rwx,o:r-x /var/cache/nginx  >/dev/null 2>&1 || ((warnings++))

    # Set ACLs for 404 error page
    setfacl -m u:www-data:rw-,g:www-data:rw-,o:r-- /usr/share/nginx/html/404.html >/dev/null 2>&1 || ((warnings++))
    # Private key ACLs
    find /opt/pki/private -type f -name "*.key.pem" -exec setfacl -m g:strongswan:r {} + >/dev/null 2>&1 || ((warnings++))

    setfacl -m u:www-data:rwx /usr/share/nginx/html/404.htm >/dev/null 2>&1 || ((warnings++))
    
    # === SECTION 8: SYMLINK CREATION ===
    log "Creating required symlinks..."
    
    # Define and create all required symlinks
    declare -A symlinks=(
        ["/etc/swanctl/x509/server.pem"]="/opt/pki/x509/server-ip.pem"
        ["/etc/swanctl/x509/${DNS_NAME}.server.pem"]="/opt/pki/x509/server-dns.pem"
        ["/etc/swanctl/private/${DNS_NAME}.server.key.pem"]="/opt/pki/private/server-dns-key.pem"
        ["/etc/swanctl/private/server-key.pem"]="/opt/pki/private/server-ip-key.pem"
        ["/etc/swanctl/x509ca/ca.pem"]="/opt/pki/x509/ca.pem"
        ["/etc/swanctl/x509ocsp/ocsp.pem"]="/opt/pki/x509/ocsp.pem"
        ["/etc/swanctl/x509crl/crl.der"]="/opt/pki/crl/crl.der"
        ["/etc/nginx/crl/crl.der"]="/opt/pki/crl/crl.der"
        ["/etc/nginx/nginx.pem"]="/opt/pki/x509/vault.pem"
        ["/etc/nginx/nginx-key.pem"]="/opt/pki/private/vault-key.pem"
        ["/etc/ssl/certs/ca.pem"]="/opt/pki/x509/ca.pem"
        ["/usr/local/share/ca-certificates/vault-ca.crt"]="/opt/pki/x509/ca.pem"
        ["/etc/boundary/server-cert.pem"]="/opt/pki/x509/boundary-ip.pem"
        ["/etc/boundary/server-key.pem"]="/opt/pki/private/boundary-ip-key.pem"
        ["/etc/boundary/ca.pem"]="/opt/pki/x509/ca.pem"
        ["/etc/vault/tls/vault.pem"]="/opt/pki/x509/vault.pem"
        ["/etc/vault/tls/vault-key.pem"]="/opt/pki/private/vault-key.pem"
    )

    for link in "${!symlinks[@]}"; do
        target="${symlinks[$link]}"
        mkdir -p "$(dirname "$link")" >/dev/null 2>&1
        if [[ -e "$target" ]]; then
            ln -sf "$target" "$link" >/dev/null 2>&1 || log "Failed to create symlink $link -> $target" && ((warnings++))
        else
            log "Target $target for symlink $link does not exist"
            ((warnings++))
        fi
    done

    # === SECTION 9: FILE-SPECIFIC ACLS ===
    log "Setting file-specific ACLs..."

    # Vault-specific files
    for file in /etc/vault/tls/vault-key.pem /etc/vault/tls/vault.pem /etc/vault/config.hcl; do
        if [[ -f "$file" ]]; then
            setfacl -m u:root:rw,u:vault:r "$file" >/dev/null 2>&1 || ((warnings++))
            chmod 640 "$file" >/dev/null 2>&1 || ((warnings++))
        fi
    done
    
    # Set proper permissions on Boundary symlinks
    for boundary_file in /etc/boundary/server-cert.pem /etc/boundary/server-key.pem /etc/boundary/ca.pem; do
        if [[ -L "$boundary_file" && -e "$boundary_file" ]]; then
            chown -h boundary:boundary "$boundary_file" >/dev/null 2>&1 || ((warnings++))
            # Set permissions on the target file
            target_file=$(readlink -f "$boundary_file")
            if [[ -f "$target_file" ]]; then
                # For key files, more restrictive permissions
                if [[ "$boundary_file" == *"key"* ]]; then
                    chmod 600 "$target_file" >/dev/null 2>&1 || ((warnings++))
                    setfacl -m u:boundary:r "$target_file" >/dev/null 2>&1 || ((warnings++))
                else
                    chmod 644 "$target_file" >/dev/null 2>&1 || ((warnings++))
                    setfacl -m u:boundary:r "$target_file" >/dev/null 2>&1 || ((warnings++))
                fi
            fi
        fi
    done
    find /etc/nginx/conf.d/ -type f -name "*.conf" -exec chmod 644 {} \; 2>/dev/null || true >/dev/null 2>&1 || ((warnings++))
    find /etc/nginx/modules-enabled/ -type f -name "*.conf" -exec chmod 644 {} \; 2>/dev/null || true >/dev/null 2>&1 || ((warnings++))
    find /etc/nginx/sites-enabled/ -type f -exec chmod 644 {} \; 2>/dev/null || true >/dev/null 2>&1 || ((warnings++))

    # === SUMMARY ===
    if [ $errors -gt 0 ]; then
        log "WARNING: $errors critical errors occurred during permission setup"
        return 1
    elif [ $warnings -gt 0 ]; then
        log "NOTICE: $warnings non-critical issues occurred during permission setup"
    else
        log "Permissions, ACLs, and symlinks setup completed successfully!"
    fi
    
    return 0
}

check_directories() {
    load_config
    log "Ensuring necessary directories exist..."

    # 1) Base directories
    mkdir -p /opt/pki
    chmod 755 /opt/pki
    mkdir -p /etc/swanctl
    chmod 751 /etc/swanctl
    mkdir -p /etc/ssl
    mkdir -p "$CERT_DIR" || error_exit "Failed to create $CERT_DIR"
    mkdir -p "$PRIVATE_DIR" || error_exit "Failed to create $PRIVATE_DIR"
    mkdir -p "$CRL_DIR" || error_exit "Failed to create $CRL_DIR"
    mkdir -p /etc/swanctl/ocsp
    mkdir -p /etc/swanctl/crls
    mkdir -p /etc/vault
    mkdir -p /var/lib/vault/data
    mkdir -p /etc/zt
    mkdir -p /opt/pki 2>/dev/null
    mkdir -p /etc/swanctl 2>/dev/null
    mkdir -p /etc/ssl 2>/dev/null
    mkdir -p /var/lib/vault/data 2>/dev/null
    mkdir -p /etc/vault 2>/dev/null
    mkdir -p /opt/pki/private 2>/dev/null
    mkdir -p /opt/pki/x509 2>/dev/null
    mkdir -p /opt/pki/crl 2>/dev/null
    mkdir -p /opt/pki/ocsp 2>/dev/null
    mkdir -p /opt/pki/tmp 2>/dev/null
    mkdir -p /etc/swanctl/x509 2>/dev/null
    mkdir -p /etc/swanctl/x509ca 2>/dev/null
    mkdir -p /etc/swanctl/private 2>/dev/null
    mkdir -p /etc/swanctl/x509crl 2>/dev/null
    mkdir -p /etc/swanctl/x509ocsp 2>/dev/null
    mkdir -p /etc/nftables.d 2>/dev/null
    mkdir -p /etc/nginx/crl 2>/dev/null
    mkdir -p /etc/apparmor.d/local 2>/dev/null
    mkdir -p /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null
    mkdir -p /var/log/aide 2>/dev/null
    mkdir -p /etc/zt/ztna.conf.d 2>/dev/null
    mkdir -p /var/lib/boundary /etc/boundary/zones 2>/dev/null
    mkdir -p /var/lib/suricata/rules 2>/dev/null
    mkdir -p /var/log/suricata 2>/dev/null
    mkdir -p /etc/suricata/rules/custom 2>/dev/null
    mkdir -p /etc/nginx/conf.d 2>/dev/null
    mkdir -p /etc/nginx/sites-available 2>/dev/null
    mkdir -p /var/lib/strongswan 2>/dev/null
    mkdir -p /var/lib/strongswan/charon 2>/dev/null
    mkdir -p /var/www/html 2>/dev/null
    mkdir -p /etc/nginx/conf.d/ 2>/dev/null
    mkdir -p /var/log/nginx 2>/dev/null
    mkdir -p /var/cache/nginx 2>/dev/null
    mkdir -p /etc/nginx/modules-enabled 2>/dev/null
    mkdir -p /etc/nginx/sites-enabled 2>/dev/null
    mkdir -p /usr/share/nginx/html 2>/dev/null
    log "All necessary directories have been created under /opt/pki and /etc/swanctl. No permissions were modified."
}


check_and_compile_modules() {
    log "Checking required kernel modules..."

    required_modules=("af_key" "xfrm_user" "iptable_nat" "xfrm_algo" "xfrm4_tunnel" "nf_nat" "esp4" "nf_conntrack" "nf_defrag_ipv4" "xfrm_interface" )
    missing_modules=()


    cmds=(depmod modprobe make)
    packages=(kmod kmod build-essential)

    apt-get update -y

    for i in "${!cmds[@]}"; do
        cmd="${cmds[$i]}"
        package="${packages[$i]}"
        if ! command -v "$cmd" &> /dev/null; then
            log "Command $cmd not found. Installing package $package..."
            apt-get install -y "$package"
        fi
    done

    for module in "${required_modules[@]}"; do
        if ! lsmod | grep -qw "^$module"; then
            log "Kernel module $module not loaded, attempting to load..."
            if modprobe "$module"; then
                log "Kernel module loaded successfully: $module"
            else
                log "Failed to load kernel module: $module"
                missing_modules+=("$module")
            fi
        else
            log "Kernel module already loaded: $module"
        fi

        if ! grep -qw "^$module$" /etc/modules; then
            echo "$module" | tee -a /etc/modules > /dev/null
            log "Added kernel module to /etc/modules: $module"
        else
            log "Kernel module already in /etc/modules: $module"
        fi
    done

    if [ ${#missing_modules[@]} -ne 0 ]; then
        log "Some modules are missing or failed to load, compiling the missing modules..."

        log "Installing build tools and dependencies..."
        apt-get install -y build-essential libncurses-dev bison flex libssl-dev libelf-dev bc dwarves kmod
        apt-get install -y linux-headers-"$(uname -r)"

        KERNEL_VERSION=$(uname -r)
        KERNEL_HEADERS_DIR="/usr/src/linux-headers-$KERNEL_VERSION"

        if [ ! -d "$KERNEL_HEADERS_DIR" ]; then
            log "Kernel headers directory not found: $KERNEL_HEADERS_DIR"
            exit 1
        fi

        cd "$KERNEL_HEADERS_DIR" || { log "Failed to enter kernel headers directory."; exit 1; }

        log "Preparing for module compilation..."
        make modules_prepare


        for module in "${missing_modules[@]}"; do
            case "$module" in
                af_key)
                    MODULE_PATH="net/key/af_key"
                    CONFIG_OPTION="CONFIG_NET_KEY"
                    ;;
                xfrm_user)
                    MODULE_PATH="net/xfrm"
                    CONFIG_OPTION="CONFIG_XFRM_USER"
                    ;;
                xfrm_algo)
                    MODULE_PATH="crypto/xfrm_algo"
                    CONFIG_OPTION="CONFIG_XFRM_ALGO"
                    ;;
                esp4)
                    MODULE_PATH="net/ipv4/esp4"
                    CONFIG_OPTION="CONFIG_INET_ESP"
                    ;;
                xfrm4_tunnel)
                    MODULE_PATH="net/ipv4/xfrm4_tunnel"
                    CONFIG_OPTION="CONFIG_INET_XFRM_TUNNEL"
                    ;;
                xfrm_interface)
                    MODULE_PATH="net/xfrm/xfrm_interface"
                    CONFIG_OPTION="CONFIG_XFRM_INTERFACE"
                    ;;
                nf_nat)
                    MODULE_PATH="net/ipv4/netfilter/nf_nat"
                    CONFIG_OPTION="CONFIG_NF_NAT"
                    ;;
                nf_conntrack)
                    MODULE_PATH="net/netfilter/nf_conntrack"
                    CONFIG_OPTION="CONFIG_NF_CONNTRACK"
                    ;;
                nf_defrag_ipv4)
                    MODULE_PATH="net/ipv4/netfilter/nf_defrag_ipv4"
                    CONFIG_OPTION="CONFIG_NF_DEFRAG_IPV4"
                    ;;
                *)
                    log "No specific compilation instructions for module: $module"
                    continue
                    ;;
            esac


            sed -i "s/# $CONFIG_OPTION is not set/$CONFIG_OPTION=m/" .config
            echo "$CONFIG_OPTION=m" | tee -a .config > /dev/null

            log "Compiling module $module..."
            if make M=./"$MODULE_PATH" modules; then
                log "Module $module compiled successfully."
            else
                log "Failed to compile module: $module"
                continue
            fi

            log "Installing module $module..."
            if make M=./"$MODULE_PATH" modules_install; then
                log "Module $module installed successfully."
            else
                log "Failed to install module: $module"
                continue
            fi

            if modprobe "$module"; then
                log "Loaded kernel module after compilation: $module"
            else
                log "Failed to load kernel module after compilation: $module"
            fi
        done

        log "Running depmod to update module dependencies..."
        depmod -a
        log "depmod completed."

        cd ~ || exit
    else
        log "All required kernel modules are loaded."
    fi
}


command_exists() {
    command -v "$1" >/dev/null 2>&1
}
   
check_ip() {
    local ip=$1
    local stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=("$ip")
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && \
           ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

get_default_ip() {
    local default_iface
    default_iface=$(ip -4 route list 0/0 | awk '{print $5}' | head -n1)
    public_ip=$(ip -4 addr show "$default_iface" | awk '/inet/ {print $2}' | cut -d'/' -f1 | head -n1)
}

get_server_ip() {
    public_ip=${VPN_PUBLIC_IP:-''}

    log "Trying to auto discover IP of this server..."
    check_ip "$public_ip" || public_ip=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)
    check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ipv4.icanhazip.com)
    check_ip "$public_ip" || public_ip=$(wget -t 2 -T 10 -qO- http://ip1.dynupdate.no-ip.com)

    if ! check_ip "$public_ip"; then
        error_exit "Could not detect this server's public IP. Please manually set the VPN_PUBLIC_IP variable in the configuration file."
    fi
}

install_dependencies() {
    log "Installing dependencies..."
    apt-get update -y || error_exit "Failed to update package lists."
    apt-get install -y \
        build-essential \
        libgmp-dev \
        libssl-dev \
        libcap-ng-dev \
        jq \
        libpam0g-dev \
        freeradius-utils \
        libnftables1 \
        iproute2 \
        ipcalc \
        gettext \
        nftables \
        python3-inotify \
        python3-flask \
        python3-redis \
        python3-celery \
        uuid-runtime \
        util-linux \
        tmux \
        bridge-utils \
        openssl \
        libcurl4-openssl-dev \
        libjson-c-dev \
        pkg-config \
        libsystemd-dev \
        bind9utils \
        iftop \
        tcpdump \
        libnss3-tools \
        btop \
        lsof \
        net-tools \
        chrony \
        vnstat \
        swaks \
        mailutils \
        cron \
        locate \
        debsums \
        traceroute \
        acl \
        ethtool \
        tree \
        acct \
        wget \
        curl\
        unzip \
        syslog-ng \
        libcurl4-openssl-dev \
        libjansson-dev \
        automake \
        net-tools \
        rkhunter \
        apparmor-utils \
        apparmor-profiles \
        gawk \
        flex \
        bison \
        gperf \
        apt-transport-https \
        software-properties-common \
        dnsutils || error_exit "Failed to install dependencies."
   

       apt update
  
    log "Dependencies installed successfully."
}

compile_strongswan() {
    
    log "Compiling Latest Version of StrongSwan from source..."


    SCRIPT_SOURCE="${BASH_SOURCE[0]}"
    while [ -h "$SCRIPT_SOURCE" ]; do
        DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" && pwd)"
        SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
        [[ $SCRIPT_SOURCE != /* ]] && SCRIPT_SOURCE="$DIR/$SCRIPT_SOURCE"
    done
    ORIGINAL_SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" && pwd)"
    VAULT_PLUGIN_DIR="$ORIGINAL_SCRIPT_DIR/src/plugins/vault"

    cd /usr/src/ || error_exit "Failed to change directory to /usr/src/."
    latest_version=$(curl -s https://download.strongswan.org/ \
        | grep -oP 'strongswan-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.bz2)' \
        | sort -V | tail -1)

    if [ -z "$latest_version" ]; then
        error_exit "Failed to determine the latest StrongSwan version."
    fi
    log "Latest StrongSwan version is $latest_version"
    tarball="strongswan-$latest_version.tar.bz2"
    download_url="https://download.strongswan.org/$tarball"
    wget "$download_url" || error_exit "Failed to download StrongSwan source."
    tar xjf "$tarball" || error_exit "Failed to extract StrongSwan source."

    cd "strongswan-$latest_version" || error_exit "Failed to enter StrongSwan source directory."
    STRONGSWAN_DIR="/usr/src/strongswan-$latest_version"
    log "Configuring StrongSwan with Vault plugin..."
    ./configure --prefix=/usr \
        --sysconfdir=/etc \
        --disable-test-vectors \
        --enable-aes \
        --enable-sha1 \
        --enable-sha2 \
        --enable-random \
        --enable-x509 \
        --enable-pubkey \
        --enable-openssl \
        --enable-gmp \
        --enable-kernel-netlink \
        --enable-socket-default \
        --enable-vici \
        --enable-updown \
        --enable-eap-identity \
        --enable-eap-md5 \
        --enable-eap-mschapv2 \
        --enable-eap-tls \
        --enable-eap-ttls \
        --enable-eap-gtc \
        --enable-eap-radius \
        --enable-dhcp \
        --enable-farp \
        --enable-charon \
        --enable-systemd \
        --enable-curl \
        --enable-cmd \
        --enable-swanctl \
        --enable-curve25519 \
        --enable-files \
        --enable-lookip \
        --enable-revocation \
        --enable-constraints \
        --enable-pki \
        --enable-pem \
        --enable-pkcs8 \
        --enable-pkcs1 \
        --enable-pem \
        --enable-gcm \
        --enable-aesni \
        --with-systemdsystemunitdir=/lib/systemd/system || error_exit "Failed to configure StrongSwan."



    make || error_exit "Failed to compile StrongSwan."
    make install || error_exit "Failed to install StrongSwan."
    
    log "StrongSwan compiled and installed successfully."
    systemctl daemon-reload

}



setup_cockpit() {  
    log "Setting up Cockpit with 45drives repository..."


    mkdir -p /usr/share/cockpit/strongswan

    log "Adding 45Drives repository key..."
    wget -qO - https://repo.45drives.com/key/gpg.asc | \
        gpg --dearmor -o /usr/share/keyrings/45drives-archive-keyring.gpg || \
        error_exit "Failed to add 45Drives GPG key."

    log "Adding 45Drives repository..."
    cat > /etc/apt/sources.list.d/45drives.sources <<EOF
X-Repolib-Name: 45Drives
Enabled: yes
Types: deb
URIs: https://repo.45drives.com/debian
Suites: focal
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/45drives-archive-keyring.gpg
EOF

    log "Updating package list..."
    TMPDIR=/var/tmp apt-get update -y || error_exit "Failed to update package list."

    log "Installing cockpit-navigator..."
    TMPDIR=/var/tmp apt-get install cockpit-navigator -y || error_exit "Failed to install cockpit-navigator."

    log "Cockpit setup complete."
}

configure_swanctl() {
    log "Configuring StrongSwan with swanctl..."
    mkdir -p /etc/swanctl/conf.d
    mkdir -p /etc/swanctl/x509/{cacerts,certs,private}
    mkdir -p /etc/strongswan.d/charon
    mkdir -p /var/run/charon
    chown root:strongswan /var/run/charon
    chmod 770 /var/run/charon
    touch /var/run/charon.vici
    chown root:strongswan /var/run/charon.vici
    chmod 770 /var/run/charon.vici
    mkdir -p /var/lib/strongswan
    chown root:strongswan /var/lib/strongswan
    chmod 770 /var/lib/strongswan

    cat <<EOF | tee /etc/strongswan.d/charon.conf
charon {
    dos_protection = yes
    prefer_configured_proposals = yes
    load_crls = yes
    cache_crls = yes
    group = strongswan
    replay_window = 128
    tls {

        send_certreq_authorities = yes
    }

}
EOF
    chmod 600 /etc/strongswan.d/charon.conf
    chown root:strongswan /etc/strongswan.d/charon.conf


    cat <<EOF | tee /etc/strongswan.d/charon/revocation.conf
revocation {
            enable_crl = yes
            enable_ocsp = yes
            timeout = 10s
           }
EOF
    chmod 600 /etc/strongswan.d/charon/revocation.conf
    chown root:strongswan /etc/strongswan.d/charon/revocation.conf

    cat <<EOF | tee /etc/strongswan.d/charon/eap-radius.conf
eap-radius {
    load = yes
    servers {
        okta-radius-eap-ttls {
            address = 127.0.0.1
            secret = ${RADIUS_SECRET}
            auth_port = ${RADIUS_PORT}
            pass_radius_attrs = yes
        }
    }
        dae {
        enable = yes
        listen = 127.0.0.1  
        port = 3799
        secret = ${COA_SECRET}
    }
}

EOF
    chmod 600 /etc/strongswan.d/charon/eap-radius.conf
    chown root:strongswan /etc/strongswan.d/charon/eap-radius.conf

       local pool_name="main-pool"
    if [ "$VPN_MODE" = "DHCP" ]; then
        pool_name="dhcp"
    fi

    cat <<EOF | tee /etc/swanctl/swanctl.conf
pools {
    main-pool {
        addrs = ${IP_RANGE}
        dns = ${DNS_SERVERS}
    }
    v6-pool {
        addrs = fd12:3456:789a::/64
    }
}

authorities {
    vault-ca {
            cacert = /etc/swanctl/x509ca/ca.pem
            crl_uris = [ file:///opt/pki/crl/crl.der ]
            ocsp_uris = [ http://127.0.0.1:8201/v1/pki/ocsp ]

    }
}
include conf.d/*.conf
EOF

    chmod 600 /etc/swanctl/swanctl.conf
    chown root:strongswan /etc/swanctl/swanctl.conf

 cat <<EOF | tee /etc/swanctl/conf.d/pubkey.conf
connections {
    ikev2-cert {
        version = 2
        proposals = aes256-sha256-ecp256 aes256gcm16-prfsha256-ecp256
        dpd_delay = 30s
        dpd_timeout = 180s
        encap = yes
        unique = replace
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/server.pem
            id = ${PUBLIC_IP}
        }
        remote {
            auth = pubkey
            revocation = relaxed
            id = %any
            cacerts = ca.pem

    
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                rekey_time = 0s
                start_action = none
                dpd_action = restart
                mode = tunnel
                esp_proposals = aes256-sha256, aes256gcm16
            }
        }
        pools = $pool_name, v6-pool
        mobike = yes
        fragmentation = yes
    }
}
secrets {
    private-key {
        id = ${PUBLIC_IP}
        file = /etc/swanctl/private/server.pem
    }
}
EOF
       local dhcp="no"
    if [ "$VPN_MODE" = "DHCP" ]; then
             dhcp="yes"
    fi


    cat <<EOF | tee /etc/strongswan.conf
charon {
    load_modular = yes
 
    plugins {
        kernel-netlink {
            mtu = 1400
            mss = 1360
        }
        include strongswan.d/charon/*.conf
    }
    syslog {
        identifier = charon
    }
    start-scripts {
        creds = /usr/local/sbin/strongswan-creds
    }
    attr {
           dns = $DNS_SERVERS
    }
    eap-ttls {
            fragment_size = 1024
            include_length = yes
            max_message_count = 32
            phase2_piggyback = no
             }
    farp {
        load = $dhcp
    }
    dhcp {
        load = $dhcp
        server = $DEFAULT_GATEWAY
        force_server_address = no
        identity_lease = yes
        interface = $DEFAULT_INTERFACE
    }
    kernel-netlink {
        install_xfrmi = yes
    }
}
include strongswan.d/*.conf
EOF
    chmod 600 /etc/strongswan.conf
    chown root:strongswan /etc/strongswan.conf

    cat <<EOF | tee /usr/local/sbin/strongswan-creds
#!/bin/sh
swanctl --load-all
EOF
    chmod +x /usr/local/sbin/strongswan-creds
    cat <<EOF | tee /etc/strongswan.d/charon-vici.conf
charon {
    vici {
        socket = unix:///var/run/charon.vici
        group = strongswan
    }
}
EOF
    cat <<EOF | tee /etc/systemd/system/swanctl-load.service > /dev/null
[Unit]
Description=Load all StrongSwan configurations using swanctl
After=ssh.service strongswan.service
Wants=ssh.service strongswan.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/swanctl --load-all
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable swanctl-load.service
    cat <<EOF | tee /lib/systemd/system/strongswan.service
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using swanctl
After=network.target

[Service]
Type=notify
ExecStartPre=/bin/mkdir -p /var/run/charon
ExecStartPre=/bin/chown root:strongswan /var/run/charon
ExecStartPre=/bin/chmod 770 /var/run/charon
ExecStartPre=/bin/touch /var/run/charon.vici
ExecStartPre=/bin/chown root:strongswan /var/run/charon.vici
ExecStartPre=/bin/chmod 770 /var/run/charon.vici
ExecStart=/usr/sbin/charon-systemd
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

    log "Reloading systemd configuration and starting StrongSwan service..."
    systemctl daemon-reload
    systemctl enable strongswan
    systemctl start strongswan

    log "Waiting for StrongSwan service to start..."
    for i in {1..30}; do
        if [ -S /var/run/charon.vici ]; then
            log "VICI socket created successfully."
            break
        fi
        sleep 1
    done

    if [ ! -S /var/run/charon.vici ]; then
        log "ERROR: VICI socket not created after 30 seconds. check StrongSwan service status."
        systemctl status strongswan
        exit 1
    fi
    log "Reloading swanctl configuration..."
    swanctl --load-all
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to load swanctl configuration. check logs for details."
        exit 1
    fi
    log "swanctl configuration reloaded."

    log "StrongSwan configuration complete swanctl."
}

configure_vault() {

    VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}
    VAULT_API=${VAULT_API:-"${VAULT_ADDR}/v1/pki"}
    # 1) Install prerequisites
    apt-get update -y
    apt-get install -y unzip curl jq nginx || {
        echo "Failed installing prerequisites."
        exit 1
    }

    # 2) Load config & do basic checks
    CONFIG_PATH="/etc/strongconn.conf"
    if [[ ! -f $CONFIG_PATH ]]; then
        echo "Missing $CONFIG_PATH. Exiting."
        exit 1
    fi
    source "$CONFIG_PATH"
    unset VAULT_NAMESPACE


    if [[ -z "$CERT_DIR" || -z "$PRIVATE_DIR" || -z "$CRL_DIR" || -z "$NGINX_CRL_DIR" || -z "$OCSP_CRL_DIR" ]]; then
        echo "Required directory variables (CERT_DIR, PRIVATE_DIR, CRL_DIR, NGINX_CRL_DIR, OCSP_CRL_DIR) not set in $CONFIG_PATH."
        exit 1
    fi

    check_directories > /dev/null 

    set_permissions > /dev/null


    VAULT_BIN="/usr/bin/vault"
    echo "Fetching latest Vault version..."
    LATEST_VERSION="$(curl -sSL https://api.github.com/repos/hashicorp/vault/releases/latest | jq -r '.tag_name' | sed 's/^v//')"
    if [[ -z "$LATEST_VERSION" ]]; then
        echo "Failed to fetch Vault version."
        exit 1
    fi
    echo "Installing Vault version: $LATEST_VERSION"
    curl -fsSL "https://releases.hashicorp.com/vault/${LATEST_VERSION}/vault_${LATEST_VERSION}_linux_amd64.zip" -o /tmp/vault.zip
    unzip -o -d /usr/bin /tmp/vault.zip
    chmod +x "$VAULT_BIN" || error_exit "Failed to install Vault binary."
    rm -f /tmp/vault.zip
    mkdir -p /etc/vault /var/lib/vault /var/log/vault
    # 4) Vault config + systemd
    VAULT_CONFIG="/etc/vault/config.hcl"
    VAULT_DATA_DIR="/var/lib/vault"
    VAULT_SCRIPTS_DIR="/var/lib/vault/scripts"
    mkdir -p /etc/vault "$VAULT_DATA_DIR" "$VAULT_SCRIPTS_DIR"

    cat > "$VAULT_CONFIG" <<EOF || error_exit "Failed to create Vault config file."
storage "file" {
  path = "$VAULT_DATA_DIR"
}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
api_addr = "http://127.0.0.1:8200"
disable_mlock = true
ui = true
EOF

cat > /etc/systemd/system/vault.service <<EOF || error_exit "Failed to create Vault service file."
[Unit]
Description=HashiCorp Vault
After=network.target

[Service]
Environment="VAULT_TOKEN_HELPER=/dev/null"
ExecStart=/usr/bin/vault server -config=/etc/vault/config.hcl
Restart=on-failure
User=vault
Group=vault
LimitMEMLOCK=infinity

# Hardening directives
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/etc/vault /var/log/vault /var/lib/vault /run
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateDevices=yes
UMask=0077

[Install]
WantedBy=multi-user.target
EOF


cat > /etc/systemd/system/vault-unseal.service <<EOF || error_exit "Failed to create Vault unseal service file."                                                                     
[Unit]
Description=Unseal HashiCorp Vault
After=vault.service
Requires=vault.service


[Service]
Type=oneshot
ExecStartPre=/usr/bin/sleep 10
ExecStart=/usr/bin/v-pki unseal-vault
User=vault
Group=vault

# Hardening directives
ProtectSystem=full
ProtectHome=no
PrivateTmp=yes
ReadWritePaths=/etc/vault /var/lib/vault /etc/strongconn.conf
BindReadOnlyPaths=/usr
NoNewPrivileges=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateDevices=yes
UMask=0077

[Install]
WantedBy=multi-user.target


EOF

    systemctl daemon-reload

    systemctl enable vault-unseal.service || error_exit "Failed to enable Vault unseal service."



    set_permissions > /dev/null 2>&1
    v-pki check_directories > /dev/null 2>&1
    getfacl /var/lib/vault
    mkdir -p "$CERT_DIR" "$PRIVATE_DIR"
    chmod 700 "$CERT_DIR" "$PRIVATE_DIR"
    
    systemctl daemon-reload 
    systemctl enable vault  || error_exit "Failed to enable Vault service."
    systemctl start vault || error_exit "Failed to start Vault service."
    


    # 5) Wait for Vault
    echo "Waiting for Vault to respond..."
    for i in {1..30}; do
        http_code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8200/v1/sys/health)"
        [[ "$http_code" == "200" || "$http_code" == "503" ]] && { echo "Vault is responding."; break; }
        echo "Vault not ready yet..."
        sleep 3
    done

    # 6) Initialize & unseal (no interactive prompts)
    export VAULT_ADDR="http://127.0.0.1:8200"

    INIT_CHECK="$(vault status -format=json | jq -r '.initialized')"
    if [[ "$INIT_CHECK" != "true" ]]; then
        echo "Initializing Vault (non-interactive)..."
        INIT_OUT="$(vault operator init -format=json | tr -d '\r')" || echo "Failed to initialize Vault."
        ROOT_TOKEN="$(echo "$INIT_OUT" | jq -r '.root_token' | tr -d '\n\r')" || echo "Failed to get root token."

        echo "Vault initialized. Appending root token + unseal keys to $CONFIG_PATH"
        echo "VAULT_TOKEN=\"$ROOT_TOKEN\"" >> "$CONFIG_PATH"

        i=1
        echo "$INIT_OUT" | jq -r '.unseal_keys_b64[]' | while read -r key; do
            key_clean="$(echo "$key" | tr -d '\n\r')"  || echo "Failed to clean unseal key $i."
            echo "VAULT_UNSEAL_KEY_$i=\"$key_clean\"" >> "$CONFIG_PATH" || echo "Failed to append unseal key $i."
            ((i++)) 
        done

        echo "Vault root token and unseal keys stored in $CONFIG_PATH"

        
    fi
    echo "$INIT_OUT" | jq -r '.unseal_keys_b64[]' | while read -r key; do
         echo "Key length = ${#key}"
    done


    echo "Unsealing Vault (non-interactive)..."
    for i in {1..3}; do
        KEY="$(grep "VAULT_UNSEAL_KEY_$i" "$CONFIG_PATH" | cut -d= -f2 | tr -d '"\r\n')"
        vault operator unseal "$KEY" || echo "Failed to unseal with key $i."
    done
    # Get the Vault token from config
    export VAULT_TOKEN="$(grep "VAULT_TOKEN" "$CONFIG_PATH" | cut -d= -f2 | tr -d '"\r\n')"
    
   
    # 7) Configure PKI
    echo "Configuring PKI secrets engine..."
    CA_NAME="${CA_NAME:-Default CA}"
    CA_DURATION="${CA_DURATION:-8760h}"



vault secrets enable -path=pki pki || echo "PKI already enabled."
vault secrets tune -max-lease-ttl=87600h pki
vault secrets enable -path=kv kv || echo "KV already enabled."




echo "Creating role ca..."

vault write "pki/roles/ca" \
    allowed_domains="*" \
    allow_subdomains=true \
    max_ttl="87600h" \
    use_pss=true \
    key_usage="CertSign,CRLSign" \
    server_flag=false \
    client_flag=false \
    country="[\"${COUNTRY//,/\",\"}\"]" \
    locality="[\"${STATE//,/\",\"}\"]" \
    province="[\"${CITY//,/\",\"}\"]" \
    organization="[\"${ORGANIZATION//,/\",\"}\"]" \
    ou="[\"${ORG_UNIT//,/\",\"}\"]"

vault write pki/config/urls \
        issuing_certificates="http://$PUBLIC_IP/ca" \
        crl_distribution_points="http://$PUBLIC_IP/crl" \
        ocsp_servers="http://$PUBLIC_IP/ocsp"



cat <<EOF > /tmp/pki-access.hcl
path "pki/crl" {
	capabilities = ["read", "list"]
}

path "pki/ocsp/*" {
	capabilities = ["read"]
}

path "pki/cert/*" {
	capabilities = ["read"]
}
EOF

vault policy write pki-access /tmp/pki-access.hcl
rm -f /tmp/pki-access.hcl

cat <<EOF > /tmp/kv-ocsp-key-policy.hcl
path "kv/private-keys/ocsp" {
	capabilities = ["create", "update", "read"]
}
EOF

vault policy write kv-ocsp-key-policy /tmp/kv-ocsp-key-policy.hcl
rm -f /tmp/kv-ocsp-key-policy.hcl

echo "Generating Root CA certificate..."
ROOT_CA_JSON=$(vault write -format=json pki/root/generate/internal \
    common_name="$CA_NAME" \
    ttl="87600h" \
    key_type="rsa" \
    key_bits=4096 \
    use_pss="true" \
    key_usage="KeyCertSign,CRLSign")

ISSUER_ID=$(echo "$ROOT_CA_JSON" | jq -r '.data.issuer_id')
echo "New CA Issuer ID: $ISSUER_ID"

MAX_RETRIES=10
COUNT=0
while [[ -z "$(vault list pki/issuers | grep "$ISSUER_ID")" && $COUNT -lt $MAX_RETRIES ]]; do
    echo "Waiting for issuer $ISSUER_ID to be available..."
    sleep 2
    ((COUNT++))
done

if [[ -z "$(vault list pki/issuers | grep "$ISSUER_ID")" ]]; then
    echo "Issuer $ISSUER_ID did not become available. Exiting."
    exit 1
fi

if [[ -n "$ISSUER_ID" ]]; then
    echo "Setting issuer $ISSUER_ID as default..."
    vault write pki/config/issuers default="$ISSUER_ID"
else
    echo "Failed to get issuer ID. Default issuer not set!"
    exit 1
fi

vault read pki/config/issuers

if [[ $? -ne 0 ]]; then
    echo "Failed to generate Root CA. Vault response:"
    echo "$ROOT_CA_JSON"
    exit 1
fi

mkdir -p "$CERT_DIR" "$PRIVATE_DIR"

echo "$ROOT_CA_JSON" | jq -r '.data.certificate' > "$CERT_DIR/ca.pem"

if [[ ! -s "$CERT_DIR/ca.pem" ]]; then
    echo "Root CA certificate file is empty. Exiting."
    exit 1
fi
CA_CERT="$CERT_DIR/ca.pem"

if [ ! -f "$CA_CERT" ]; then
    echo "Root CA certificate not found at $CA_CERT."
    exit 1
fi


if [ -d "/usr/local/share/ca-certificates" ]; then
    TRUSTED_CERT_DIR="/usr/local/share/ca-certificates"
elif [ -d "/etc/ca-certificates/trust-source/anchors" ]; then
    TRUSTED_CERT_DIR="/etc/ca-certificates/trust-source/anchors"
else
    echo "Could not find a suitable system CA trust store directory."
    exit 1
fi


CUSTOM_CA_DIR="$TRUSTED_CERT_DIR/custom"
 mkdir -p "$CUSTOM_CA_DIR"


 cp "$CA_CERT" "$CUSTOM_CA_DIR/strongswan-ca.crt" || {
    echo "Failed to copy CA certificate to $CUSTOM_CA_DIR."
    exit 1
}

chmod 644 "$CUSTOM_CA_DIR/strongswan-ca.crt"

if command -v update-ca-certificates &> /dev/null; then
     update-ca-certificates || {
        echo "Failed to update CA certificates."
        exit 1
    }
elif command -v update-ca-trust &> /dev/null; then
     update-ca-trust extract || {
        echo "Failed to update CA trust."
        exit 1
    }
else
    echo "Could not find a command to update the CA trust store."
    exit 1
fi

c_rehash /etc/ssl/certs
update-ca-certificates
echo "Root CA certificate installed to the system's trusted store successfully."


vault write pki/config/urls \
    issuing_certificates="http://$PUBLIC_IP/ca" \
    crl_distribution_points="http://$PUBLIC_IP/crl" \
    ocsp_servers="http://$PUBLIC_IP/ocsp"

    declare -A roles=(
        [ocsp]='{
            "allowed_domains": ["'"$PUBLIC_IP"'", "*"],
            "allow_ip_sans": true,
            "allow_any_name": true,
            "max_ttl": "85500h",
            "key_usage": "DigitalSignature",
            "ext_key_usage": "OCSPSigning",
            "ext_key_usage_oids": "1.3.6.1.5.5.7.3.9",
            "use_pss": true,
            "key_bits": 4096,
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"],
            "issuer_ref": "'"${ISSUER_ID}"'"
        }'
        [vault]='{
            "allowed_domains": ["'"$PUBLIC_IP"'", "*"],
            "allow_ip_sans": true,
            "allow_subdomains": false,
            "allow_any_name": true,
            "max_ttl": "85500h",
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement,DataEncipherment",
            "ext_key_usage": "ServerAuth",
            "use_pss": true,
            "key_bits": 4096,
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"],
            "issuer_ref": "'"${ISSUER_ID}"'"
        }'
        [server-dns]='{
            "allowed_domains": ["'"$DNS_NAME"'", "*"],
            "allow_subdomains": true,
            "allow_any_name": true,
            "use_pss": true,
            "max_ttl":"'"85500h"'",
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement,DataEncipherment",
            "ext_key_usage": "ServerAuth,IPsecTunnel,IPsecIntermediate",
            "ext_key_usage_oids": "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.6",
            "key_bits": 4096,
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"],
            "issuer_ref": "'"${ISSUER_ID}"'"
        }'
        [server-ip]='{
            "allowed_domains": ["'"$PUBLIC_IP"'", "*"],
            "use_pss": true,
            "allow_subdomains": false,
            "allow_any_name": true,
            "allow_ip_sans": true,
            "max_ttl":"'"85500h"'",
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement,DataEncipherment",
            "ext_key_usage": "ServerAuth,IPsecTunnel,IPsecIntermediate",
            "ext_key_usage_oids": "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.6",
            "allow_ip_sans": true,
            "key_bits": 4096,
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"],
            "issuer_ref": "'"${ISSUER_ID}"'"
        }'
        [hostname]='{
            "allowed_domains": "*",
            "allow_subdomains": true,
            "allow_any_name": true,
            "use_pss": true,
            "max_ttl": "25920h",
            "key_usage": "DigitalSignature,KeyAgreement,KeyEncipherment,DataEncipherment",
            "ext_key_usage": "clientAuth,IPsecEndSystem,IPSecUser",
            "ext_key_usage_oids": "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.5",
            "enforce_hostnames": true,
            "key_bits": 4096,
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"],
            "issuer_ref": "'"${ISSUER_ID}"'"
        }'
        [boundary-ip]='{
            "allowed_domains": "*",
            "allow_ip_sans": true,
            "allow_subdomains": false,
            "allow_any_name": true,
            "max_ttl":"'"85500h"'",
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement,DataEncipherment",
            "ext_key_usage": "ServerAuth",
            "max_ttl": "87600h",
            "use_pss": true,
            "key_bits": 4096,
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"],
            "issuer_ref": "'"${ISSUER_ID}"'"
        }'
        [db-server]='{
            "allowed_domains": ["localhost", "'"$DB_HOST"'"],
            "allow_ip_sans": true,
            "require_cn": false,
            "allow_subdomains": false,
            "allow_any_name": true,
            "max_ttl":"'"85500h"'",
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement,DataEncipherment",
            "ext_key_usage": "ServerAuth",
            "max_ttl": "87600h",
            "use_pss": true,
            "key_bits": 4096,
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"],
            "issuer_ref": "'"${ISSUER_ID}"'"
        }'
        [client]='{
            "allowed_domains": "*",
            "allow_subdomains": false,
            "allow_any_name": true,
            "max_ttl": "25920h",
            "use_pss": true,
            "key_usage": "DigitalSignature,KeyAgreement,KeyEncipherment,DataEncipherment",
            "ext_key_usage": "clientAuth,IPsecUser",
            "ext_key_usage_oids": "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.7",
            "enforce_hostnames": false,
            "key_bits": 4096,
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"],
            "issuer_ref": "'"${ISSUER_ID}"'"
        }'
    )

    for role in "${!roles[@]}"; do
    echo "Creating role: $role"
    echo "${roles[$role]}" | vault write "pki/roles/$role" - || {
        echo "Failed to create role: $role"
        exit 1
    }
    done

vault read pki/config/urls

echo "Generating OCSP responder certificate with IP..."
OCSP_JSON=$(vault write -format=json pki/issue/ocsp \
    common_name="$PUBLIC_IP" \
    ttl="85500h" \
    key_usage="DigitalSignature" \
    ext_key_usage="OCSPSigning" \
    use_pss="true" \
    key_bits="4096" \
    ip_sans="$PUBLIC_IP" \
    country="$COUNTRY" \
    locality="$STATE" \
    province="$CITY" \
    organization="$ORGANIZATION" \
    ou="$ORG_UNIT")

if [[ $? -ne 0 || -z "$OCSP_JSON" ]]; then
    echo "Failed to issue OCSP responder certificate."
    echo "$OCSP_JSON"
    exit 1
fi


CERT_PATH="$CERT_DIR/ocsp.pem"
echo "$OCSP_JSON" | jq -r '.data.certificate' > "$CERT_PATH"

if [[ ! -s "$CERT_PATH" ]]; then
    echo "OCSP certificate file is empty. Exiting."
    exit 1
fi

echo "OCSP certificate saved locally at $CERT_PATH for StrongSwan."

echo "Storing OCSP private key in Vault KV..."
echo "$OCSP_JSON" | jq -r '.data.private_key' | vault kv put kv/private-keys/ocsp key=- || {
    echo "Failed to store OCSP private key in Vault."
    exit 1
}

OCSP_POLICY_PATH="/tmp/ocsp-policy.hcl"
echo 'path "kv/private-keys/ocsp" {
  capabilities = ["read"]
}' > "$OCSP_POLICY_PATH"


if vault policy write ocsp-policy "$OCSP_POLICY_PATH"; then
    echo "OCSP policy created successfully."
else
    echo "Failed to create OCSP policy."
    exit 1
fi

rm -f "$OCSP_POLICY_PATH"

echo "OCSP responder certificate stored locally  at $CERT_PATH."
echo "Private key securely stored in Vault under kv/private-keys/ocsp."

    declare -A server_cert_params=(
        [server-ip]='{
            "common_name": "'"$PUBLIC_IP"'",
            "ttl": "'"85500h"'",
            "ip_sans": "'"$PUBLIC_IP"'",
            "key_type": "rsa",
            "key_bits": 4096,
            "use_pss": true,
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement",
            "ext_key_usage": "ServerAuth,IPsecTunnel,IPsecIntermediate",
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"]
        }'
        [server-dns]='{
            "common_name": "'"$DNS_NAME"'",
            "ttl": "'"85500h"'",
            "alt_names": "'"$DNS_NAME"'",
            "key_type": "rsa",
            "key_bits": 4096,
            "use_pss": true,
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement",
            "ext_key_usage": "ServerAuth,IPsecTunnel,IPsecIntermediate",
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"]
        }'
        [db-server]='{
            "common_name": "'"localhost"'",
            "ttl": "'"85500h"'",
            "ip_sans": "127.0.0.1,'"$DEFAULT_IP"','"$PUBLIC_IP"'",
            "key_type": "rsa",
            "key_bits": 4096,
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement",
            "ext_key_usage": "ServerAuth,ClientAuth",
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"]
        }'
        [boundary-ip]='{
            "common_name": "'"$DNS_NAME"'",
            "ttl": "85500h",
            "ip_sans": "127.0.0.1,'"$DEFAULT_IP"','"$PUBLIC_IP"'",
            "alt_names": "boundary.local",
            "key_type": "rsa",
            "key_bits": 4096,
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement",
            "ext_key_usage": "ServerAuth",
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"]
        }'
        [vault]='{
            "common_name": "'"$DNS_NAME"'",
            "ttl": "'"85500h"'",
            "ip_sans": "127.0.0.1,'"$DEFAULT_IP"','"$PUBLIC_IP"'",
            "key_type": "rsa",
            "key_bits": 4096,
            "use_pss": true,
            "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement",
            "ext_key_usage": "ServerAuth",
            "country": ["'"${COUNTRY//,/\",\"}"'"],
            "locality": ["'"${STATE//,/\",\"}"'"],
            "province": ["'"${CITY//,/\",\"}"'"],
            "organization": ["'"${ORGANIZATION//,/\",\"}"'"],
            "ou": ["'"${ORG_UNIT//,/\",\"}"'"]
        }'
)
    
for cert in "server-ip" "server-dns" "vault" "boundary-ip" ; do
    echo "Generating $cert certificate..."


    CERT_JSON=$(echo "${server_cert_params[$cert]}" | vault write -format=json "pki/issue/$cert" -)

    if [[ $? -ne 0 || -z "$CERT_JSON" ]]; then
        echo "Failed to issue $cert certificate."
        echo "$CERT_JSON"
        exit 1
    fi

    KEY_PATH="$PRIVATE_DIR/$cert-key.pem"
    CERT_PATH="$CERT_DIR/$cert.pem"

    echo "$CERT_JSON" | jq -r '.data.private_key' > "$KEY_PATH"

    if [[ ! -s "$KEY_PATH" ]]; then
        echo "$cert private key file is empty."
        exit 1
    fi

    echo "$CERT_JSON" | jq -r '.data.certificate' > "$CERT_PATH"

    if [[ ! -s "$CERT_PATH" ]]; then
        echo "$cert certificate file is empty."
        exit 1
    fi

    echo "Storing $cert private key in Vault KV..."
    vault kv put kv/private-keys/$cert key=@"$KEY_PATH" || {
        echo "Failed to store $cert private key in Vault."
        exit 1
    }

    echo "$cert certificate issued and stored successfully."
    echo "Private key securely stored in Vault under kv/private-keys/$cert."
    echo "Certificate stored in Vault's PKI under pki/certs/$serial_number."
    echo "Certificate saved locally for StrongSwan in $CERT_PATH."
done

mkdir -p "$NGINX_CRL_DIR" "$OCSP_CRL_DIR"
chmod 755 "$NGINX_CRL_DIR" "$OCSP_CRL_DIR"



vault write pki/config/crl expiry="72h" auto_rebuild=true auto_rebuild_grace_period="8h"


curl -s -o /opt/pki/crls/crl.der http://127.0.0.1:8200/v1/pki/crl

 cat > "$VAULT_CONFIG" <<EOF || error_exit "Failed to create Vault config file."
storage "file" {
  path = "$VAULT_DATA_DIR"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault/tls/vault.pem"
  tls_key_file  = "/etc/vault/tls/vault-key.pem"
  tls_client_ca_file = "/etc/ssl/certs/ca-certificates.crt"
}
 
listener "tcp" {
  address     = "0.0.0.0:8201"
  tls_disable = true
}

api_addr = "https://127.0.0.1:8200"
disable_mlock = true
ui = true

disable_clustering = true

EOF

set_permissions 2>&1

    systemctl restart vault || error_exit "Failed to reload Vault."

    systemctl enable vault-unseal || error_exit "Failed to enable Vault unseal service."

    VAULT_ADDR=${VAULT_ADDR:-"https://127.0.0.1:8200"}
    VAULT_API=${VAULT_API:-"${VAULT_ADDR}/v1/pki"}
    echo "Vault initialized & all certificates generated successfully."
    echo "Vault is running at: https://$DEFAULT_IP:8200"
    VAULT_ADDR=https://127.0.0.1:8200
    chmod 644 /etc/ssl/certs/ca-certificates.crt
    
openssl pkcs12 -export -legacy \
     -in /opt/pki/x509/server-dns.pem \
     -inkey /opt/pki/private/server-dns-key.pem \
     -certfile /opt/pki/x509/ca.pem \
     -out /opt/pki/server.p12 \
     -name "$DNS_NAME" \
     -caname "CA" \
     -passout pass:"$PFX_PASSWORD" || error_exit "Failed to create PKCS#12 bundle."


}

install_nginx() {
    NGINX_CONF="/etc/nginx/sites-available/vault_ocsp"
    CRL_SCRIPT_PATH="${VAULT_SCRIPTS_DIR}/update_crl.sh"

    echo "Configuring NGINX for CRL/OCSP..."
    source /etc/strongconn.conf || error_exit "Failed to load configuration file."

    cat > "$NGINX_CONF" <<EOF || error_exit "Failed to create NGINX config file."
server {
    listen 80;
    server_name ${PUBLIC_IP};

    client_max_body_size 4M;

    location /ocsp {
        limit_req zone=ocsp_rate_limit burst=20 nodelay;
        proxy_pass http://127.0.0.1:8201/v1/pki/ocsp;
        proxy_set_header Content-Type "application/ocsp-request";
        proxy_set_header Accept "application/ocsp-response";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_request_buffering off;
        proxy_redirect off;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires 0;
        proxy_cache_bypass \$http_pragma \$http_cache_control;
        proxy_no_cache \$http_pragma \$http_cache_control;
        access_log /var/log/nginx/ocsp_requests.log;
    }

    location /crl {
        limit_req zone=crl_rate_limit burst=10 nodelay;
        proxy_pass http://127.0.0.1:8201/v1/pki/crl;
        default_type application/pkix-crl;
        add_header Content-Disposition "attachment; filename=crl.der";
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires 0;
        proxy_cache_bypass \$http_pragma \$http_cache_control;
        proxy_no_cache \$http_pragma \$http_cache_control;
        access_log /var/log/nginx/crl_requests.log;
    }

    location /ca {
        limit_req zone=ca_rate_limit burst=10 nodelay;
        proxy_pass http://127.0.0.1:8201/v1/pki/ca/pem;
        default_type application/x-pem-file;
        add_header Content-Disposition "attachment; filename=ca.pem";
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires 0;
        proxy_cache_bypass \$http_pragma \$http_cache_control;
        proxy_no_cache \$http_pragma \$http_cache_control;
        access_log /var/log/nginx/ca_requests.log;
    }

    location / {
        return 404;
    }

    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    error_page 404 /404.html;
    location = /404.html {
        root /usr/share/nginx/html;
    }

    access_log /var/log/nginx/ocsp_crl_access.log;
    error_log /var/log/nginx/ocsp_crl_error.log;
}
EOF

    cat > /etc/nginx/nginx.conf <<EOF || error_exit "Failed to create global NGINX config file."
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;

    limit_req_zone \$binary_remote_addr zone=ocsp_rate_limit:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=crl_rate_limit:5m rate=5r/s;
    limit_req_zone \$binary_remote_addr zone=ca_rate_limit:5m rate=5r/s;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    if [ -f "$SCRIPT_DIR/../_images/favicon.ico" ]; then
        cp "$SCRIPT_DIR/../_images/favicon.ico" /var/www/html/favicon.ico
        chmod 644 /var/www/html/favicon.ico
        echo "favicon.ico copied successfully."
    else
        echo "favicon.ico not found in the expected location."
    fi
    echo "Creating custom 404 error page..."
cat > /usr/share/nginx/html/404.html <<'EOF' || error_exit "Failed to create 404 error page."
<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">

    <style>
        body {
            background-color: #1a1a1a;
            color: #ffffff;
            font-family: monospace;
            text-align: center;
            padding: 50px;
        }
        pre {
            font-size: 16px;
        }
        .glitch {
            animation: glitch 0.5s infinite;
        }
        @keyframes glitch {
            0% { transform: translate(0); }
            20% { transform: translate(-2px, 2px); }
            40% { transform: translate(2px, -2px); }
            60% { transform: translate(-2px, -2px); }
            80% { transform: translate(2px, 2px); }
            100% { transform: translate(0); }
        }
        a {
            color: #ff00ff;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>404 Not Found</h1>
    <pre class="glitch">
 💾  Computer Go  Brrrrrrrrrrrr!  💾
    .-""""""""-.
   /         \
  :  4 0 4  :  :
   | *  *|  ; 
   `._-     _.' 
      | 404 |
      |----|
    NOT FOUND
    🖥️🔧
    </pre>
    <p>The certificate or page you seek has glitched out of existence.</p>
</body>
</html>
EOF
    chmod 644 /usr/share/nginx/html/404.html || error_exit "Failed to set permissions for 404 error page."

    set_permissions 2>&1
    
    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/vault_ocsp
    unlink /etc/nginx/sites-enabled/default || true

    echo "Creating and setting permissions for Nginx directories..."
    mkdir -p /var/log/nginx /var/cache/nginx /run

    nginx -t || error_exit "NGINX configuration test failed."
    systemctl enable --now nginx || error_exit "Failed to start NGINX initially."
    echo 'export VAULT_ADDR="https://127.0.0.1:8200"' |  tee -a /etc/profile.d/vault.sh

    echo "Hardening nginx.service systemd configuration..."
    mkdir -p /etc/systemd/system/nginx.service.d
    cat > /etc/systemd/system/nginx.service.d/override.conf <<EOF || error_exit "Failed to create nginx.service override."                           
[Service]
# Run in foreground for better systemd management
Type=simple
ExecStart=
ExecStart=/usr/sbin/nginx -g "daemon off; master_process on;"
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_FOWNER
NoNewPrivileges=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log/nginx /var/cache/nginx /var/www/html /run
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictSUIDSGID=yes
UMask=0077

EOF
    mv /etc/systemd/system/nginx.service.d/override.conf ~/
    systemctl daemon-reload || error_exit "Failed to reload systemd after nginx.service override."
    systemctl restart nginx || error_exit "Failed to restart nginx after hardening."
    set_permissions 2>&1
    
    # Fix NGINX log directory permissions
    log "Fixing NGINX log directory permissions..."
    mkdir -p /var/log/nginx
    chown -R www-data:adm /var/log/nginx
    chmod -R 750 /var/log/nginx
    
    # Add proper logrotate configuration for NGINX with su directive
    cat > /etc/logrotate.d/nginx << 'EOF'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    su www-data adm
    prerotate
        if [ -d /etc/logrotate.d/httpd-prerotate ]; then \
            run-parts /etc/logrotate.d/httpd-prerotate; \
        fi \
    endscript
    postrotate
        invoke-rc.d nginx rotate >/dev/null 2>&1
    endscript
}
EOF
    
    echo "Creating CRL update script and systemd timer..."
    chmod 644 /opt/pki/crl/crl.der
    chmod 755 /opt/pki /opt/pki/crl
    ln -sf /opt/pki/crl/crl.der /etc/nginx/crl/crl.der
    set_permissions 2>&1
    mkdir -p "$VAULT_SCRIPTS_DIR"
    cat > "$CRL_SCRIPT_PATH" <<'EOF' || error_exit "Failed to create CRL update script."
#!/bin/bash
VAULT_CRL_URL="http://127.0.0.1:8201/v1/pki/crl"
CRL_DEST="/opt/pki/crl/crl.der"
echo "Fetching CRL from Vault..."
if curl -s -o "$CRL_DEST" "$VAULT_CRL_URL"; then
    echo "CRL fetched successfully and saved to $CRL_DEST."
    systemctl reload nginx || echo "Warning: Failed to reload NGINX."
else
    echo "Error: Failed to fetch CRL from Vault."
    exit 1
fi
EOF

    chmod +x "$CRL_SCRIPT_PATH"

    cat > /etc/systemd/system/update_crl.service <<EOF || error_exit "Failed to create CRL update service."
[Unit]
Description=Fetch CRL from Vault
After=vault-unseal.service
Requires=vault-unseal.service

[Service]
Type=oneshot
ExecStart=$CRL_SCRIPT_PATH

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/update_crl.timer <<EOF || error_exit "Failed to create CRL update timer."
[Unit]
Description=Run CRL Fetcher Periodically

[Timer]
OnCalendar=*-*-* 00/6:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    set_permissions 2>&1
    systemctl daemon-reload
    systemctl enable --now update_crl.timer || error_exit "Failed to enable CRL update timer."
    systemctl start update_crl.timer || error_exit "Failed to start CRL update timer."
    systemctl enable --now update_crl.service || error_exit "Failed to enable CRL update service."
    systemctl start update_crl.service || error_exit "Failed to start CRL update service."
    set_permissions > /dev/null

    echo "NGINX + CRL setup complete with hardened systemd configuration!"
    echo "You can check logs with: journalctl -u nginx.service -u update_crl.timer -u update_crl.service -f"
    echo "Check security score with: systemd-analyze security nginx.service"
}


setup_firewalld() {

    log "Default gateway and interface updated in $CONFIG_PATH"
    log "Setting up Firewall rules for $DEFAULT_INTERFACE..."
 

    log "Disabling ICMP redirects for IPv4..."
    echo "net.ipv4.conf.all.send_redirects = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.default.rp_filter = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects = 0" | tee -a /etc/sysctl.conf
    log "Disabling ICMP redirects for IPv4 on $DEFAULT_INTERFACE..."
    echo "net.ipv4.conf.${DEFAULT_INTERFACE}.send_redirects = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.${DEFAULT_INTERFACE}.accept_redirects = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.${DEFAULT_INTERFACE}.rp_filter = 0" | tee -a /etc/sysctl.conf
    log "Disabling ICMP redirects for IPv6 on $DEFAULT_INTERFACE..."
    echo "net.ipv6.conf.${DEFAULT_INTERFACE}.accept_redirects = 0" | tee -a /etc/sysctl.conf
    log  "ICMP redirects permanently disabled on $DEFAULT_INTERFACE."
    if modprobe -q tcp_bbr 2>/dev/null \
    && printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V; then
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    fi
    log "Disabling ICMP redirects for IPv6..."
    echo "net.ipv6.conf.all.accept_redirects = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv6.conf.default.accept_redirects = 0" | tee -a /etc/sysctl.conf

    log  "ICMP redirects permanently disabled on all interfaces."

    log "Enabling IP forwarding..."
    echo "net.ipv4.ip_forward=1" | tee -a /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=1
    sysctl --system
    sysctl -p



    chmod 640 /etc/nftables.conf || error_exit "failed to set permissions"
    systemctl enable nftables.service || error_exit "could not enable nftables service"
    systemctl start nftables.service || error_exit "could not start nftables"
    mkdir -p /etc/nftables.d || error_exit "could not create nftables.d directory"
    log "Firewall configuration for $VPN_MODE mode has been updated successfully."

    add_ip_pool_rules="no"
    if [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ]; then
        add_ip_pool_rules="yes"
    fi
    whitelist_elements="$PUBLIC_IP, 127.0.0.1"
    
    if [ "$add_ip_pool_rules" = "yes" ]; then
        whitelist_elements="$whitelist_elements, $IP_POOL"
    fi
    
    if [ -n "$ROUTE_SUBNETS" ] && [ "$ROUTE_SUBNETS" != "$PUBLIC_IP/32" ]; then
        whitelist_elements="$whitelist_elements, $ROUTE_SUBNETS"
    fi

    cat <<EOF | tee /etc/nftables.conf >/dev/null
#!/usr/sbin/nft -f

flush ruleset

table inet firewall {

    set blacklisted_ips {
        type ipv4_addr;
        flags timeout;
    }

     set whitelisted_ips {
        type ipv4_addr;
        flags interval;
        elements = { $whitelist_elements }
    }

        chain mangle_PREROUTING {
        type filter hook prerouting priority mangle + 10;
        jump mangle_PRE_policy_allow-host-ipv6
        jump mangle_PREROUTING_ZONES
    }

    chain mangle_PRE_policy_allow-host-ipv6 {
        return
    }

    chain mangle_PREROUTING_ZONES {
        ip saddr @blacklisted_ips log prefix "BLACKLIST DROP: " limit rate 10/second counter drop
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "ip saddr $IP_POOL counter goto mangle_PRE_client")
        ip saddr 127.0.0.1 counter goto mangle_PRE_trusted
        iifname "lo" counter goto mangle_PRE_trusted
        iifname "$DEFAULT_INTERFACE" counter goto mangle_PRE_public
        counter goto mangle_PRE_public
    }

    chain mangle_PRE_client {
        return
    }

    chain mangle_PRE_trusted {
        return
    }

    chain mangle_PRE_public {
        return
    }

    chain nat_PREROUTING {
        type nat hook prerouting priority dstnat + 10;
        jump nat_PREROUTING_POLICIES_pre
        jump nat_PREROUTING_ZONES
        jump nat_PREROUTING_POLICIES_post
    }

    chain nat_PREROUTING_POLICIES_pre {
        jump nat_PRE_policy_allow-host-ipv6
    }

    chain nat_PRE_policy_allow-host-ipv6 {
        return
    }

    chain nat_PREROUTING_ZONES {
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "ip saddr $IP_POOL counter goto nat_PRE_client")
        ip saddr 127.0.0.1 counter goto nat_PRE_trusted
        iifname "lo" counter goto nat_PRE_trusted
        iifname "$DEFAULT_INTERFACE" counter goto nat_PRE_public
        counter goto nat_PRE_public
    }

    chain nat_PRE_client {
        return
    }

    chain nat_PRE_trusted {
        return
    }

    chain nat_PRE_public {
        return
    }

    chain nat_PREROUTING_POLICIES_post {
        return
    }

    chain nat_POSTROUTING {
        type nat hook postrouting priority srcnat + 10;
        jump nat_POSTROUTING_POLICIES_pre
        jump nat_POSTROUTING_ZONES
        jump nat_POSTROUTING_POLICIES_post
    }

    chain nat_POSTROUTING_POLICIES_pre {
        return
    }

    chain nat_POSTROUTING_ZONES {
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "ip saddr $IP_POOL counter goto nat_POST_client")
        ip daddr 127.0.0.1 counter goto nat_POST_trusted
        oifname "lo" counter goto nat_POST_trusted
        oifname "$DEFAULT_INTERFACE" counter goto nat_POST_public
        counter goto nat_POST_public
    }

    chain nat_POST_client {      
        $( [ "$add_ip_pool_rules" = "yes" ] && echo  "iifname $DEFAULT_INTERFACE ip saddr $IP_POOL counter masquerade;")
        return
    }

    chain nat_POST_trusted {
        return
    }

    chain nat_POST_public {
        return
    }

    chain nat_POSTROUTING_POLICIES_post {
        return
    }

    chain filter_PREROUTING {
        type filter hook prerouting priority filter + 10;
        icmpv6 type { nd-router-advert, nd-neighbor-solicit } accept
        meta nfproto ipv6 fib saddr . mark . iif oif missing drop
    }

    chain filter_INPUT {
        type filter hook input priority filter + 10; policy accept;
        ip saddr @blacklisted_ips log prefix "BLACKLIST DROP: " limit rate 10/second counter drop
        ct state invalid counter drop
        ct state { established, related } counter accept
        iifname "lo" counter accept
        jump filter_INPUT_ZONES
        ip saddr @whitelisted_ips counter accept
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop
        ip6 saddr { fc00::/7 } counter drop
        counter reject with icmpx admin-prohibited
    }

    chain filter_FORWARD {
        type filter hook forward priority filter + 10; policy accept;
        ip saddr @blacklisted_ips log prefix "BLACKLIST DROP: " limit rate 10/second counter drop
        ct state invalid counter drop
        ct state { established, related } counter accept
        iifname "lo" counter accept
        jump filter_FORWARD_ZONES
        ip saddr @whitelisted_ips counter accept
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop
        ip6 saddr { fc00::/7 } counter drop
        counter reject with icmpx admin-prohibited
    }

    chain filter_FORWARD_ZONES {
        $( [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ] && echo "ip saddr $IP_POOL counter goto filter_FWD_client")
        return
    }

    chain filter_FWD_client {
        $( [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ] && echo "ip daddr $IP_POOL counter accept")
        $( [ "$VPN_MODE" = "NAT" ] || [ "$VPN_MODE" = "ROUTED" ] && echo "ip saddr $IP_POOL counter accept")
    }

    chain filter_OUTPUT {
        type filter hook output priority filter + 10; policy accept;
        ip daddr @blacklisted_ips log prefix "OUTGOING BLACKLIST DROP: " limit rate 10/second counter drop
        ct state { established, related } counter accept
        oifname "lo" counter accept
        ip6 daddr { ::/96, ::ffff:0.0.0.0/96, 2002::/24, 2002:a00::/24, 2002:7f00::/24, 2002::/16 } counter drop
    }

    chain filter_INPUT_ZONES {
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "ip saddr $IP_POOL counter goto filter_IN_client")
        ip saddr 127.0.0.1 counter goto filter_IN_trusted
        iifname "lo" counter goto filter_IN_trusted
        iifname "$DEFAULT_INTERFACE" counter goto filter_IN_public
        counter goto filter_IN_public
    }

    chain filter_IN_public {
        meta l4proto { icmp, ipv6-icmp } counter accept
        tcp dport 22 counter accept
        udp dport { 500, 4500, 53 } counter accept
        tcp dport { 80, 53, 9090, 8200, 9200, 9203 } counter accept
        meta l4proto esp counter accept
        ip saddr @whitelisted_ips counter accept
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop
        ip6 saddr { fc00::/7 } counter drop
        counter reject with icmpx admin-prohibited
    }

    chain filter_IN_trusted {
        counter accept
    }

    chain filter_IN_client {
        counter accept
    }

}

table ip mangle {
    chain mangle_FORWARD {
        type filter hook forward priority mangle + 10; policy accept;
        oifname "$DEFAULT_INTERFACE" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
    }

    chain mangle_POSTROUTING {
        type filter hook postrouting priority mangle + 10; policy accept;
        oifname "$DEFAULT_INTERFACE" tcp flags syn / syn,rst tcp option maxseg size set rt mtu
    }
}

table ip filter {
    chain FORWARD {
        type filter hook forward priority filter; policy accept; counter
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "oifname \"$DEFAULT_INTERFACE\" ip saddr $IP_POOL counter accept")
        $( [ "$add_ip_pool_rules" = "yes" ] && echo "iifname \"$DEFAULT_INTERFACE\" ip daddr $IP_POOL counter accept")
    }
}

include "/etc/nftables.d/*.conf"

EOF

        chmod 640 /etc/nftables.conf  || error_exit "failed to set permissions"
        nft -c -f /etc/nftables.conf || error_exit "failed nftables syntax config check"
        systemctl enable nftables.service || error_exit "could not enable nf tables service"
        systemctl start nftables.service || error_exit "could not start nf tables"
        nft -f /etc/nftables.conf || error_exit "failed to load nftables configuration"
        echo "firewall configuration has been updated successfully."   
      
      
 
    log "Disabling Hardware offloading on $DEFAULT_INTERFACE..."
    ethtool -K "$DEFAULT_INTERFACE" rx off tx off sg off tso off gso off gro off lro off || error_exit "Failed to disable offloading on $DEFAULT_INTERFACE"

    echo "Default interface detected: $DEFAULT_INTERFACE"


    INTERFACES_FILE="/etc/network/interfaces"


    if ! grep -q "iface $DEFAULT_INTERFACE inet" "$INTERFACES_FILE"; then
        echo "Interface $DEFAULT_INTERFACE not found in $INTERFACES_FILE. Adding configuration."


        echo -e "\nauto $DEFAULT_INTERFACE\niface $DEFAULT_INTERFACE inet dhcp\n    post-up /sbin/ethtool -K $DEFAULT_INTERFACE rx off tx off sg off tso off gso off gro off lro off" | tee -a "$INTERFACES_FILE" > /dev/null
        echo "Offloading settings added to $INTERFACES_FILE for $DEFAULT_INTERFACE."
    else
        echo "Interface $DEFAULT_INTERFACE found in $INTERFACES_FILE. Checking for offloading settings."
        if ! grep -q "post-up /sbin/ethtool -K $DEFAULT_INTERFACE rx off tx off sg off tso off gso off gro off lro off" "$INTERFACES_FILE"; then
            sed -i "/iface $DEFAULT_INTERFACE inet/a \ \ \ \ post-up /sbin/ethtool -K $DEFAULT_INTERFACE rx off tx off sg off tso off gso off gro off lro off" "$INTERFACES_FILE"
            echo "Offloading settings added to existing configuration in $INTERFACES_FILE for $DEFAULT_INTERFACE."
        else
            echo "Offloading settings already exist in $INTERFACES_FILE for $DEFAULT_INTERFACE."
        fi
    fi

}

save_nft_config() {
    echo "Saving nftables configuration for persistence..."

    nft list ruleset > /etc/nftables.conf

    systemctl restart nftables

    echo "Nftables configuration saved and service restarted."
}


debug_strongswan() {
    run_command() {
        local cmd="$1"
        local description="$2"

        log "Running: $description"
        echo "-----------------------------------------------------------------------------------------------------"
        if ! eval "$cmd"; then
            log "ERROR: Failed to execute: $description"
        fi
        echo "-----------------------------------------------------------------------------------------------------"
    }

    check_service() {
        local service_name="$1"
        if ! systemctl is-active --quiet "$service_name"; then
            log "ERROR: $service_name is not running. Starting it now..."
            systemctl start "$service_name"
            sleep 5
        else
            log "$service_name is running."
        fi
        run_command "systemctl status $service_name --no-pager -l" "$service_name status"
    }

    log "Starting Gateway service status & log debug..."
    check_service "strongswan.service"
    check_service "ragent"
    check_service "nginx"
    check_service "fail2ban"
    check_service "vault"
    check_service "suricata"
    #check_service "cron"
    #check_service "celery"
    #check_status  "okta-gunicorn"
    crontab -l
    check_service "suricata_watchdog.service"
    run_command "swanctl --list-conns" "Loaded connections"
    run_command "swanctl --list-certs" "Loaded certificates"
    run_command "swanctl --list-sas" "Active IKE SAs"
    run_command "swanctl --list-auth" "Loaded authorities"
    run_command "ip xfrm policy show" "XFRM policies"
    run_command "ip xfrm state show" "XFRM states"
    run_command "ss -tuln" "Open TCP/UDP ports and listening services"
    run_command "ip route show" "IP routing table"
    run_command "route -n" "IP routing table"
    run_command "fail2ban-client status"

    if command -v nft &> /dev/null; then
        run_command "nft list ruleset" "Full nftables ruleset"
     
        else
        log "NFTables is not installed. Skipping nftables checks."
    fi

 

    run_command "journalctl -u strongswan.service --no-pager -n 50" "Last 50 lines of StrongSwan logs"
    echo "-----------------------------------------------------------------------------------------------------"
    log "suricata logs last 20 lines"
    echo "-----------------------------------------------------------------------------------------------------"
    tail -n 20 /var/log/suricata/stats.log
    tail -n 20 /var/log/suricata/fast.log
    tail -n 20 /var/log/suricata/eve.json
    echo "-----------------------------------------------------------------------------------------------------"
    echo "-----------------------------------------------------------------------------------------------------"
    log "last 20 Suricata watchdog logs"
    echo "-----------------------------------------------------------------------------------------------------"
    tail -n 20 /var/log/suricata_watchdog_actions/actions.log
    echo "-----------------------------------------------------------------------------------------------------"
    log "IPsec Gateway debug output."
}


load_and_export_config() {
    local CONFIG_PATH="/etc/strongconn.conf"
    
    if [ ! -f "$CONFIG_PATH" ]; then
        echo "Configuration file not found!"
        return 1
    fi

    source "$CONFIG_PATH"
    export EMAIL_ADDRESS
    export DNS_NAME
    export ROUTE_SUBNETS
    export DNS_SERVERS
    export RADIUS_SECRET
    export PUBLIC_IP
    export IP_POOL
    export IP_RANGE
    export PFX_PASSWORD
}

inject_Banner(){

cat << EOF > /etc/motd
======================================================================================================
StrongSwan IKEv2 VPN Gateway v1.7.65.2   Public IP: $PUBLIC_IP  Hostname: $DNS_NAME VPN Mode: $VPN_MODE
======================================================================================================
Hashi Corp Vault
login to vault: https://$DEFAULT_IP:8200
PKI management:
          pki tool usage: 
                v-pki     
                    generate-client EMAIL TTL *ROLE 
                    generate-host HOSTNAME TTL      
                    revoke-pki SERIAL_NUMBER
                    export EMAIL/HOSTNAME /path/to/export              
                    list
                    unseal-vault
                    seal-vault
                
            vault credentials are stored in /etc/strongconn.conf  
            *role (ztna-pki specifiy the zone/role) 
Load changes:
    swanctl -q
    swanctl -L
    
Debugging output:
    strongconn.sh -debug

Extended debugging output:
    debug.sh 

displays xfrm state, policy, related services routes firewall rules & recent logs
=======================================================================================================
sudo ztna.sh Okta based ZTNA (MUST BE IN ROUTED MODE)
-------------------------------------------------------------------------------------------------------
sudo ztna-pki.sh PKI based ZTNA (MUST BE IN ROUTED MODE)
--------------------------------------------------------------------------------------------------------
sudo replace-pki.sh  replace CA certificates with Intermediate CA/CSR
=======================================================================================================
adv-ha.sh   Advanced High Availability (experimental)
======================================================================================================
Update strongswan package from source:
------------------------------------------------------------------------------------------------------
    systemctl stop strongswan 
    sudo -u root   
    cd  /usr/src/strongswan-CURRENT_VERSION/ 
             make uninstall   
    cd ~/ 
    strongconn.sh -update
======================================================================================================
User tar Bundles@ /opt/pki
======================================================================================================
EOF

echo "/etc/motd updated"
}

start_vpn() {
    log "Starting IPsec services..."
    systemctl enable strongswan.service
    systemctl start strongswan.service
    sleep 5
    if systemctl is-active --quiet strongswan.service; then
        swanctl --load-all
        log "VPN services started."
    else
        log "Failed to start VPN services. check systemctl status or debug for more details."
        exit 1
    fi
}

backup_config() {

    CONFIG_ITEMS=("/etc/swanctl" "/etc/strongswan.d" "/etc/strongswan.conf")
    BACKUP_DIR="/var/backups/strongswan-config-LATEST_BACKUP"

    log "Removing existing backup directory: $BACKUP_DIR"
    rm -rf "$BACKUP_DIR" 2>/dev/null

    log "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"

    for ITEM in "${CONFIG_ITEMS[@]}"; do
        if [ -e "$ITEM" ]; then
            log "Backing up $ITEM to $BACKUP_DIR"
            cp -a "$ITEM" "$BACKUP_DIR"
        else
            log "Warning: $ITEM does not exist and will not be backed up."
        fi
    done

    local date=$(date +%Y%m%d_%H%M%S)
    tar -czpf "/var/backups/strongswan-backup-$date.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")"
    log "Backup complete: /var/backups/strongswan-backup-$date.tar.gz"
}

restore_config() {

    CONFIG_ITEMS=("/etc/swanctl" "/etc/strongswan.d" "/etc/strongswan.conf")
    BACKUP_DIR="/var/backups/strongswan-config-LATEST_BACKUP"
    
    if [ ! -d "$BACKUP_DIR" ]; then
        echo "Backup directory $BACKUP_DIR does not exist. Cannot restore."
        return 1
    fi

    for ITEM in "${CONFIG_ITEMS[@]}"; do
        BASENAME=$(basename "$ITEM")
        if [ -e "$BACKUP_DIR/$BASENAME" ]; then
            log "Restoring $ITEM from $BACKUP_DIR..."
            rsync -a "$BACKUP_DIR/$BASENAME" "$(dirname "$ITEM")/"
            log "Restored $ITEM successfully."
        else
            log "Warning: $ITEM does not exist in the backup. Skipping..."
    
        fi
        done
    log "Reloading systemd configuration..."
    cat <<EOF | tee /lib/systemd/system/strongswan.service
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using swanctl
After=network.target

[Service]
Type=notify
ExecStartPre=/bin/mkdir -p /var/run/charon
ExecStartPre=/bin/chown root:strongswan /var/run/charon
ExecStartPre=/bin/chmod 770 /var/run/charon
ExecStartPre=/bin/touch /var/run/charon.vici
ExecStartPre=/bin/chown root:strongswan /var/run/charon.vici
ExecStartPre=/bin/chmod 770 /var/run/charon.vici
ExecStart=/usr/sbin/charon-systemd
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
    log "Reloading systemd configuration and starting StrongSwan service..."
    systemctl daemon-reload
    systemctl enable strongswan
    systemctl start strongswan
    tree -a -p -h -D /etc/swanctl
    tree -a -p -h -D /etc/strongswan.d
    log "config restore complete."
  
}


export_cert_to_p12_tar() {
    local OUTPUT_DIR="/root"
    local P12_FILE="${OUTPUT_DIR}/${DNS_NAME}.p12"
    local TAR_FILE="${OUTPUT_DIR}/${DNS_NAME}_certs.tar.gz"
    local CERT_PATH="/etc/letsencrypt/live/${DNS_NAME}/fullchain.pem"
    local KEY_PATH="/etc/letsencrypt/live/${DNS_NAME}/privkey.pem"
    local CONFIG_PATH="/etc/strongconn.conf"
   
    if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
        echo "Certificate or key file not found for domain ${DNS_NAME}."
        return 1
    fi
    openssl pkcs12 -export -out "$P12_FILE" -inkey "$KEY_PATH" -in "$CERT_PATH" -name "Okta Cert" -passout pass:"$PFX_PASSWORD"
    if [ $? -ne 0 ]; then
        echo "Failed to export certificate to PKCS#12 format."
        return 1
    fi
    tar -czf "$TAR_FILE" -C "$OUTPUT_DIR" "$(basename "$P12_FILE")"
    if [ $? -ne 0 ]; then
        echo "Failed to create tar.gz archive."
        return 1
    fi
    rm -f "$P12_FILE"
    echo "Certificate exported and packaged successfully to ${TAR_FILE}."
    return 0
}

write_okta_profile() {

    load_and_export_config

    local oktapowershell_script="/opt/pki/okta_vpn_profile_setup.ps1"

    
    cat <<EOF > "$oktapowershell_script"
# Variables
\$vpnName = "$DNS_NAME"
\$serverAddress = "$DNS_NAME"
\$dnsSuffix = "$S_DOMAIN"
\$destinationPrefix = "$ROUTE_SUBNETS"

function Remove-VpnConnectionIfExists {
    try {
        \$existingVpn = Get-VpnConnection -Name \$vpnName -ErrorAction SilentlyContinue
        if (\$existingVpn) {
            Write-Host "Removing existing VPN profile '\$vpnName'."
            Remove-VpnConnection -Name \$vpnName -Force
        }
    } catch {
        Write-Host "No existing VPN connection found with the name '\$vpnName'. Proceeding to add new connection."
    }
}

Add-RegistryKey
Remove-VpnConnectionIfExists

# Create the EAP configuration XML content
\$eapXmlContent = @"
<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
  <EapMethod>
    <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">21</Type>
    <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
    <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
    <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">311</AuthorId>
  </EapMethod>
  <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
    <EapTtls xmlns="http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1">
      <ServerValidation>
        <ServerNames></ServerNames>
        <DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation>
      </ServerValidation>
      <Phase2Authentication>
        <PAPAuthentication />
      </Phase2Authentication>
      <Phase1Identity>
        <IdentityPrivacy>false</IdentityPrivacy>
        <AnonymousIdentity>false</AnonymousIdentity>
      </Phase1Identity>
    </EapTtls>
  </Config>
</EapHostConfig>
"@

# Convert the XML string to an XML object
\$eapXml = [xml]\$eapXmlContent

# Create the VPN connection with the specified EAP configuration
try {
    # Remove existing VPN connection if it exists
    Remove-VpnConnectionIfExists

    # Add the VPN connection with the chosen DH group
    Add-VpnConnection -Name \$vpnName \`
        -ServerAddress \$serverAddress \`
        -TunnelType IKEv2 \`
        -EncryptionLevel Maximum \`
        -AuthenticationMethod Eap \`
        -EapConfigXmlStream \$eapXml.OuterXml \`
        -RememberCredential \$False \`
        -SplitTunneling \`
        -DnsSuffix \$dnsSuffix \`
        -Force

 
   Set-VpnConnectionIPsecConfiguration -ConnectionName "\$vpnname" \`
        -AuthenticationTransformConstants GCMAES256 \`
        -CipherTransformConstants GCMAES256 \`
        -EncryptionMethod AES256 \`
        -IntegrityCheckMethod SHA256 \`
        -DHGroup ECP256 \`
        -PfsGroup ECP256 \`
        -PassThru -Force 
    
    Write-Host "VPN profile '\$vpnName' created successfully. It will prompt for username and password."

    # Add the route to the VPN connection
    Add-VpnConnectionRoute -ConnectionName \$vpnName \`
        -DestinationPrefix \$destinationPrefix \`
        -PassThru

    Write-Host "Route added to VPN profile '\$vpnName'."

    # Display the VPN profile details
    \$vpnProfile = Get-VpnConnection -Name \$vpnName
    Write-Host "VPN Profile Details:"
    \$vpnProfile | Format-List
} catch {
    Write-Host "Failed to configure the VPN profile: \$_"
    Exit 1
}

EOF
     log "Okta IPsec EAP-TTLS-PAP profile written to $oktapowershell_script"
}

write_okta_config() {
    local CONFIG_PATH="/etc/swanctl/conf.d/okta.conf"

    load_and_export_config

    local OKTA_CONFIG="
connections {
    ikv2-okta {
        version = 2
        proposals = aes256-sha256-ecp256 aes256gcm16-prfsha256-ecp256
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 120s
        unique = replace
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/${DNS_NAME}.${DNS}server.pem
            id = ${DNS_NAME}
        }
        remote {
            auth = eap-radius
            id = %any
            eap_id = 1
        }
        children {
            eap-ttls-pap {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                rekey_time = 0s
                start_action = none
                dpd_action = restart
                mode = tunnel
                esp_proposals = aes256gcm16
            }
        }
        pools = main-pool, v6-pool
        mobike = yes
        fragmentation = yes
    }
}

pools {
        addrs = ${IP_POOL}
        dns = ${DNS_SERVERS}
    }
}

secrets {
    eap-radius {
        id = ${DNS_NAME}
        port = ${RADIUS_PORT}
        secret = ${RADIUS_SECRET}
        pass_radius_attrs = yes
    }
    private-key {
        id = ${DNS_NAME}
        file = /etc/swanctl/private/${DNS_NAME}.server.key.pem
    }
}
"
cat <<EOF > /etc/swanctl/conf.d/okta.conf
$OKTA_CONFIG
EOF
    log "Okta configuration written to /etc/swanctl/conf.d/okta.conf"


cat << EOF >/opt/pki/vpn-tool-1.7.50.0.exe.config    
<?xml version="1.0" encoding="utf-8" ?> 
<configuration> 
    <startup useLegacyV2RuntimeActivationPolicy="true"> 
        <supportedRuntime version="v4.0" />    
	    <supportedRuntime version="v2.0" />
    </startup> 
	<appSettings>
  <add key="EnableWindowsFormsHighDpiAutoResizing" value="true" />
      <add key="vpnName" value="${DNS_NAME}" />
    <add key="serverAddress" value="${DNS_NAME}" />
    <add key="destinationPrefixes" value="${ROUTE_SUBNETS}" />
    <add key="dnsSuffixes" value="${S_DOMAIN}" />
    <add key="caUrl" value="http://${PUBLIC_IP}/ca" />
    <add key="crlUrl" value="http://${PUBLIC_IP}/crl" />
    <add key="pullCA" value="true" />
    <add key="pullCRL" value="true" />
    <add key="useDnsSuffixInDnsRegistration" value="true" />
 </appSettings>
    <runtime>
        <AppContextSwitchOverrides value="Switch.System.IO.BlockLongPaths=false;Switch.System.IO.UseLegacyPathHandling=false"/>
    </runtime>
</configuration>
EOF
    cp $SCRIPT_DIR/_client/vpn-tool-1.7.50.0.exe /opt/pki/
    
    tar -C /opt/pki -czf /opt/pki/${hostname}-installer.tar.gz \
        vpn-tool-1.7.50.0.exe \
        vpn-tool-1.7.50.0.exe.config
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create installer package."
    fi
    
    echo "Adding Okta VPN connection configuration..."
   

    echo "Reloading StrongSwan configuration..."
    swanctl --reload-settings 
    swanctl --load-all
    swanctl --list-conns
    swanctl --list-certs
    swanctl --list-authorities

    apt install redis-server podman python3-gunicorn -y

    systemctl enable redis-server
    systemctl start redis-server

    echo "okta-service ALL=(ALL) NOPASSWD: /usr/bin/v-pki" | tee /etc/sudoers.d/okta-service
    echo "okta-service ALL=(ALL) NOPASSWD: /usr/sbin/nft" | tee /etc/sudoers.d/okta-service
    echo "okta-service ALL=(ALL) NOPASSWD: /usr/sbin/swanctl" | tee /etc/sudoers.d/okta-service


    chmod 440 /etc/sudoers.d/okta-service

    # Copy Python scripts and ensure correct naming (using underscore instead of hyphen)
    if [ -f "$SCRIPT_DIR/_scripts/local-event.py" ]; then
        cp "$SCRIPT_DIR/_scripts/local-event.py" /var/lib/strongswan/local_event.py
        log "Copied local-event.py as local_event.py (with underscore)"
    elif [ -f "$SCRIPT_DIR/_scripts/local_event.py" ]; then
        cp "$SCRIPT_DIR/_scripts/local_event.py" /var/lib/strongswan/local_event.py
        log "Copied local_event.py"
    else
        log "Warning: local_event.py or local-event.py not found in $SCRIPT_DIR/_scripts/"
        # Create a basic local_event.py to prevent startup failures
        cat > /var/lib/strongswan/local_event.py <<EOF
#!/usr/bin/env python3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "ok"})

@app.route('/okta-webhook', methods=['POST'])
def webhook():
    # Handle Okta webhook events
    return jsonify({"status": "received"})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
EOF
        log "Created basic local_event.py file"
    fi

    # Set the right permissions for our Python scripts
    chmod 644 /var/lib/strongswan/local_event.py
    chown okta-service:okta-service /var/lib/strongswan/local_event.py

# Create okta-flask.service with Gunicorn
cat <<EOF > /etc/systemd/system/okta-gunicorn.service
[Unit]
Description=Okta Gunicorn Event Hook Service
After=network.target

[Service]
Environment="PYTHONPATH=/var/lib/strongswan"
User=okta-service
Group=okta-service
WorkingDirectory=/var/lib/strongswan
ExecStart=/usr/bin/python3 -m gunicorn --workers 2 --bind 127.0.0.1:5000 local_event:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

EOF
  
    # Copy the tasks.py file for Celery
    if [ -f "$SCRIPT_DIR/_scripts/tasks.py" ]; then
        cp "$SCRIPT_DIR/_scripts/tasks.py" /var/lib/strongswan/tasks.py
        log "Copied tasks.py to /var/lib/strongswan/"
    else
        log "Warning: tasks.py not found in $SCRIPT_DIR/_scripts/"
        # Create a basic tasks.py to prevent startup failures
        cat > /var/lib/strongswan/tasks.py <<EOF
#!/usr/bin/env python3
import os
from celery import Celery
import logging

# Configure Celery
CELERY_BROKER_URL = 'redis://127.0.0.1:6379/0'
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/0'

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

# Create Celery app
celery_app = Celery(
    'tasks',
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND
)
celery_app.conf.update({
    'broker_url': CELERY_BROKER_URL,
    'result_backend': CELERY_RESULT_BACKEND
})

@celery_app.task(name="tasks.process_okta_event_task")
def process_okta_event_task(event_data):
    """Process Okta Event Hook (placeholder)"""
    logger.info(f"Received Okta event: {event_data}")
    return True
EOF
        log "Created basic tasks.py file"
    fi

    # Set the right permissions for tasks.py
    chmod 644 /var/lib/strongswan/tasks.py
    chown okta-service:okta-service /var/lib/strongswan/tasks.py

cat <<EOF > /etc/systemd/system/celery.service
[Unit]
Description=Okta Celery Worker Service
After=network.target

[Service]
Environment="PYTHONPATH=/var/lib/strongswan"
User=okta-service
Group=okta-service
WorkingDirectory=/var/lib/strongswan
ExecStartPre=/usr/bin/redis-cli FLUSHALL
ExecStart=/usr/bin/python3 -m celery -A tasks worker --loglevel=info --concurrency=2 -n worker1@${DNS_NAME}
Restart=always
RestartSec=10  
[Install]
WantedBy=multi-user.target

EOF


    systemctl daemon-reload
    
    # Verify Python files exist before starting services
    if [ -f "/var/lib/strongswan/local_event.py" ] && [ -f "/var/lib/strongswan/tasks.py" ]; then
        log "Python files exist, enabling services"
        systemctl enable okta-gunicorn.service
        systemctl enable celery.service
    else
        log "Warning: Python files are missing, services will be disabled until files are present"
        systemctl disable okta-gunicorn.service
        systemctl disable celery.service
    fi
    
    # Add required Python packages if not installed
    log "Installing required Python packages"
    apt-get install -y python3-flask python3-redis python3-celery python3-gunicorn
    # Try to start services (they will auto-restart if they fail)
    if [ -f "/var/lib/strongswan/local_event.py" ] && [ -f "/var/lib/strongswan/tasks.py" ]; then
        log "Starting Okta services"
        systemctl start okta-gunicorn.service || log "Warning: Failed to start okta-gunicorn service"
        systemctl start celery.service || log "Warning: Failed to start celery service"
    fi
    
    echo "Okta configuration complete."
}

write_eap_gtc(){
       
       load_and_export_config

    local pool_name="main-pool"
  
    if [ "$VPN_MODE" = "DHCP" ]; then
        pool_name="dhcp"
    fi

cat << EOF | tee -a /etc/swanctl/conf.d/eap-gtc.conf
connections {
    eap-gtc-connection {
        version = 2
        proposals = aes256-sha256-ecp256
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 120s
        unique = replace
        local {
            auth = pubkey
            certs = /etc/swanctl/x509/server.pem
            id = ${PUBLIC_IP}
        }
        remote {
            auth = eap-gtc
            id = %any
        }
        children {
            net {
                local_ts = 0.0.0.0/0
                remote_ts = dynamic
                rekey_time = 0s
                start_action = none
                dpd_action = restart
                mode = tunnel
                esp_proposals = aes256-sha256, aes256gcm16-ecp256
            }
        }
        pools = $pool_name
        mobike = yes
        fragmentation = yes
    }
}

secrets {
    eap-radius {
        id = ${PUBLIC_IP}
        port = 1814
        secret = ${RADIUS_SECRET2}
        pass_radius_attrs = yes
    }
    private-key {
        id = ${PUBLIC_IP}
        file = /etc/swanctl/private/server.key.pem
    }
}
EOF
    cat <<EOF > /etc/strongswan.d/charon/eap-radius.conf
eap-radius {
    load = yes
    servers {
        okta-radius-eap {
            address = 127.0.0.1
            secret = ${RADIUS_SECRET}
            auth_port = ${RADIUS_PORT}
            nas_identifier = ${DNS_NAME}

        }
        okta-radius-pap {
            address = 127.0.0.1
            secret = ${RADIUS_SECRET2}
            auth_port = ${RADIUS_PORT2}
            nas_identifier = ${PUBLIC_IP}
        }
    }
        dae {
        enable = yes
        listen = 127.0.0.1  
        port = 3799
        secret = ${COA_SECRET}
    }
}

EOF

    swanctl --reload-settings 
    swanctl --load-all
    swanctl --list-conns
    swanctl --list-certs
    swanctl --list-authorities


}

setup_postfix() {
   
    echo "postfix postfix/main_mailer_type select Internet Site" |  debconf-set-selections
    echo "postfix postfix/mailname string $DNS_NAME" |  debconf-set-selections
     apt-get install  postfix  -y

    log "Installing and configuring Postfix for send-only email setup..."



     postconf -e "myhostname = $DNS_NAME"
     postconf -e "myorigin = /etc/mailname"
     postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost"
     postconf -e "inet_interfaces = loopback-only"
     postconf -e "inet_protocols = all"
     postconf -e "relayhost = "
     postconf -e "mynetworks = 127.0.0.0/8 [::1]/128"
     postconf -e "home_mailbox = Maildir/"


     systemctl restart postfix
    log "Postfix configured successfully on $DNS_NAME."
}

function wait_for_apt_lock() {
    local retries=10
    local wait_time=5
    local count=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [ $count -ge $retries ]; then
            log "Could not acquire dpkg lock after $((retries*wait_time)) seconds. Aborting."
            return 1
        fi
        log "Another apt process is running. Waiting $wait_time seconds (attempt $((count+1))/$retries)."
        sleep $wait_time
        count=$((count+1))
    done
    return 0
}



install_suricata() {
 load_config
 load_and_export_config 
    # Create suricatawatchdog user
    if ! id -u suricatawatchdog >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin suricatawatchdog
    fi

    # Install dependencies and Suricata
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        suricata suricata-update libpcre3-dev libpcap-dev libnet1-dev \
        libyaml-dev libjansson-dev libcap-ng-dev libmagic-dev \
        python3-pip python3-yaml python3-inotify rustc cargo tcpdump git

    # Install suricata-update via pip if APT version fails
    if ! command -v suricata-update >/dev/null 2>&1; then
        pip3 install suricata-update || echo "Warning: Failed to install suricata-update via pip"
    fi

    # Set up directories with proper permissions
    mkdir -p /etc/suricata /var/lib/suricata/rules /var/log/suricata \
             /var/lib/strongswan /var/log/suricata_watchdog_actions \
             /etc/suricata/rules/custom
    # Ensure clean slate for log and rule directories
    rm -f /var/log/suricata/* /var/lib/suricata/rules/* /etc/suricata/rules/custom/*
    chown suricata:suricata /etc/suricata /var/lib/suricata /var/log/suricata \
                            /etc/suricata/rules/custom
    chown suricatawatchdog:suricatawatchdog /var/lib/strongswan /var/log/suricata_watchdog_actions
    chmod 750 /etc/suricata /var/lib/suricata /var/log/suricata \
              /var/lib/strongswan /var/log/suricata_watchdog_actions \
              /etc/suricata/rules/custom
    # Set ACLs for suricata user on log directory
    setfacl -m u:suricata:rwx /var/log/suricata
    setfacl -m d:u:suricata:rwx /var/log/suricata  # Default for new files

    # Suricata config with corrected settings
    cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[${ROUTE_SUBNETS},${IP_POOL},${DEFAULT_GATEWAY}]"
    EXTERNAL_NET: "!\$HOME_NET"
    DNS_SERVERS: "[${DNS_SERVERS},${DEFAULT_GATEWAY}]"
    HTTP_SERVERS: "[${ROUTE_SUBNETS},${DEFAULT_GATEWAY}]"
    SQL_SERVERS: "[${ROUTE_SUBNETS}]"
    SMTP_SERVERS: "[${ROUTE_SUBNETS}]"
    FTP_SERVERS: "[${ROUTE_SUBNETS}]"
    SSH_SERVERS: "[${ROUTE_SUBNETS}]"
    TELNET_SERVERS: "[${ROUTE_SUBNETS}]"
    RDP_SERVERS: "[${ROUTE_SUBNETS}]"
    VNC_SERVERS: "[${ROUTE_SUBNETS}]"
    DC_SERVERS:  "[${ROUTE_SUBNETS}]"

  port-groups:
    HTTP_PORTS: "80,443,8080,8443"
    SSH_PORTS: "22"
    TELNET_PORTS: "23"
    FTP_PORTS: "20,21"
    SMTP_PORTS: "25,465,587"
    DNS_PORTS: "53"
    IKE_PORTS: "500,4500"
    MYSQL_PORTS: "3306"
    POSTGRESQL_PORTS: "5432"
    MSSQL_PORTS: "1433,1434"
    ORACLE_PORTS: "1521,2483,2484"
    RDP_PORTS: "3389"
    VNC_PORTS: "5900:5903"
    IMAP_PORTS: "143,993"
    POP3_PORTS: "110,995"
    SNMP_PORTS: "161,162"
    NTP_PORTS: "123"
    KRB5_PORTS: "88"
    MQTT_PORTS: "1883,8883"
    SIP_PORTS: "5060,5061"
    NFS_PORTS: "2049"
    SMB_PORTS: "137:139,445"
    DHCP_PORTS: "67,68"
    TFTP_PORTS: "69"
    ENIP_PORTS: "44818"
    DCERPC_PORTS: "135"
    SHELLCODE_PORTS: "80,443,8080,8443"

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

app-layer:
  protocols:
    http:
      enabled: yes
    http2:
      enabled: yes
    tls:
      enabled: yes
    dns:
      enabled: yes
    ssh:
      enabled: yes
    ftp:
      enabled: yes
    smtp:
      enabled: yes
    imap:
      enabled: yes
    pop3:
      enabled: yes
    snmp:
      enabled: yes
    ntp:
      enabled: yes
    mqtt:
      enabled: yes
    sip:
      enabled: yes
    nfs:
      enabled: yes
    smb:
      enabled: yes
    dhcp:
      enabled: yes
    tftp:
      enabled: yes
    enip:
      enabled: yes
    dcerpc:
      enabled: yes
    rdp:
      enabled: yes
    vnc:
      enabled: yes
    rfb:
      enabled: yes
    krb5:
      enabled: yes
    ikev2:
      enabled: yes
    modbus:
      enabled: no
    dnp3:
      enabled: no

flowbit:
  required: yes

af-packet:
  - interface: $DEFAULT_INTERFACE
    threads: auto
    cluster-type: cluster_flow
    cluster-id: 97  
    defrag: yes
    use-mmap: yes
    ring-size: 4096

detect-engine:
  profile: medium
  rule-reload: yes

stream:
  memcap: 1gb

outputs:
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log
  - eve-log:
      enabled: yes
      filename: /var/log/suricata/eve.json
      types:
        - alert
  - stats:
      enabled: yes
      filename: /var/log/suricata/stats.log
      interval: 120

logging:
  default-log-level: info
  outputs:
    - file:
        enabled: yes
        filename: /var/log/suricata/suricata.log
    - syslog:
        enabled: yes
        facility: local0

EOF
    mkdir -p /var/lib/suricata/rules
    cat > /etc/suricata/disable.conf << EOF
3301136
3301137
3301138
3306862
3306863
3321359
3321360
3321387
3321388
3321389
2610869
EOF
    chmod 644 /etc/suricata/disable.conf
    chown suricata:suricata /etc/suricata/disable.conf
    suricata-update update-sources
    suricata-update enable-source et/open
    suricata-update enable-source oisf/trafficid
    suricata-update enable-source abuse.ch/sslbl-blacklist
    suricata-update enable-source abuse.ch/sslbl-ja3
    suricata-update enable-source abuse.ch/sslbl-c2
    suricata-update enable-source abuse.ch/feodotracker
    suricata-update enable-source abuse.ch/urlhaus
    suricata-update enable-source etnetera/aggressive
    suricata-update enable-source tgreen/hunting
    suricata-update enable-source stamus/lateral
    suricata-update enable-source pawpatrules
    suricata-update enable-source aleksibovellan/nmap
    suricata-update enable-source ptrules/open


    suricata-update


    suricata -T -c /etc/suricata/suricata.yaml -i $DEFAULT_INTERFACE -v
    if [ $? -ne 0 ]; then
        log "Error: Suricata configuration test failed. Please check the configuration."
        return 1
    fi
    cp "$SCRIPT_DIR/_scripts/suricata_watchdog.py" /var/lib/strongswan/ || {
        echo "ERROR: suricata_watchdog.py not found"; exit 1
    }
    chmod 755 /var/lib/strongswan/suricata_watchdog.py

    # Watchdog service
    cat > /etc/systemd/system/suricata_watchdog.service << EOF
[Unit]
Description=Suricata Watchdog Service
After=network.target suricata.service
Wants=suricata.service

[Service]
Type=simple
User=suricatawatchdog
Group=suricatawatchdog
ExecStart=/usr/bin/python3 /var/lib/strongswan/suricata_watchdog.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    # Sudoers for watchdog
    mkdir -p /etc/sudoers.d
    echo "suricatawatchdog ALL=(ALL) NOPASSWD: /usr/sbin/nft" > /etc/sudoers.d/suricatawatchdog
    chmod 440 /etc/sudoers.d/suricatawatchdog

    systemctl enable suricata
    systemctl start suricata 

    # Enable and start watchdog
    systemctl enable suricata_watchdog
    systemctl start suricata_watchdog


    if [ ! -f "/usr/bin/suricata" ] || [ ! -f "/etc/suricata/suricata.yaml" ]; then
        log "Error: Suricata or its configuration file is missing"
        return 1
    fi

    # Ensure DEFAULT_INTERFACE is set
    if [ -z "$DEFAULT_INTERFACE" ]; then
        DEFAULT_INTERFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
        if [ -z "$DEFAULT_INTERFACE" ]; then
            log "Error: Could not determine default interface"
            return 1
        fi
    fi

    # Test configuration
    if ! suricata -T -c /etc/suricata/suricata.yaml -i "$DEFAULT_INTERFACE" -v; then
        log "Warning: Suricata config test failed, check /var/log/suricata/suricata.log for details"
        return 1
    else
        log "Suricata configuration test passed successfully"
    fi

    echo "Suricata installed and configured with all rule sources for VPN gateway"
}

syslog-ng_config() {
    LOGROTATE_CONFIG="/etc/logrotate.d/custom_logs"
    load_config  # Assuming this sets ARCTICWOLF_IP and other vars

    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi

    log "Installing syslog-ng and required modules..."
    apt-get update -y >/dev/null 2>&1
    apt-get install -y syslog-ng-core syslog-ng-mod-json || error_exit "Failed to install syslog-ng or its modules."

    # Create required directories for logs
    mkdir -p /var/log/syslog-ng /var/log/suricata_watchdog_actions
    
    # Ensure log files exist
    for log_file in /var/log/suricata/eve.json /var/log/suricata/fast.log /var/log/suricata/suricata.log \
                   /var/log/suricata/stats.log /var/log/suricata_watchdog_actions/actions.log \
                   /var/log/auth.log /var/log/cron.log /var/log/charon.log /var/log/swanctl_user_check.log; do
        touch "$log_file" 2>/dev/null
    done

    # Set permissions for all log files before configuring syslog-ng
    chown -R suricata:suricata /var/log/suricata 2>/dev/null
    chown suricatawatchdog:suricatawatchdog /var/log/suricata_watchdog_actions/actions.log 2>/dev/null
    chown root:adm /var/log/auth.log /var/log/cron.log /var/log/charon.log /var/log/swanctl_user_check.log 2>/dev/null
    chmod 640 /var/log/auth.log /var/log/cron.log /var/log/charon.log /var/log/swanctl_user_check.log 2>/dev/null
    chmod 640 /var/log/suricata/*.log /var/log/suricata_watchdog_actions/actions.log 2>/dev/null

    log "Writing enhanced syslog-ng configuration..."
    # Backup existing config if it exists
    if [ -f /etc/syslog-ng/syslog-ng.conf ]; then
        cp /etc/syslog-ng/syslog-ng.conf /etc/syslog-ng/syslog-ng.conf.bak.$(date +%Y%m%d%H%M%S)
    fi
    
    # Writing a simpler, more compatible configuration file
    cat > /etc/syslog-ng/syslog-ng.conf <<EOF
@version: 3.38
@include "scl.conf"

# Global options
options {
    chain_hostnames(off);
    flush_lines(0);
    use_dns(no);
    use_fqdn(no);
    owner("root");
    group("adm");
    perm(0640);
    stats_freq(0);
    time_reopen(10);
    log_fifo_size(1000);
};

source s_system {
    system();
    internal();
};

source s_kernel { file("/proc/kmsg" program_override("kernel")); };

source s_auth { file("/var/log/auth.log"); };
source s_cron { file("/var/log/cron.log"); };
source s_strongswan { 
    file("/var/log/charon.log");
    file("/var/log/swanctl_user_check.log"); 
};
source s_suricata { 
    file("/var/log/suricata/eve.json"); 
    file("/var/log/suricata/fast.log");
    file("/var/log/suricata/suricata.log");
};
source s_suricata_stats { file("/var/log/suricata/stats.log"); };
source s_watchdog { file("/var/log/suricata_watchdog_actions/actions.log"); };

destination d_local { file("/var/log/syslog-ng/messages"); };
EOF

    # Only add remote syslog if ARCTICWOLF_IP is set
    if [ -n "$ARCTICWOLF_IP" ]; then
        cat >> /etc/syslog-ng/syslog-ng.conf <<EOF
destination d_remote {
    tcp("$ARCTICWOLF_IP" port(514) 
        keep-alive(yes)
        so_keepalive(yes));
};

log { source(s_system); destination(d_remote); };
log { source(s_kernel); destination(d_remote); };
log { source(s_auth); destination(d_remote); };
log { source(s_cron); destination(d_remote); };
log { source(s_strongswan); destination(d_remote); };
log { source(s_suricata); destination(d_remote); };
log { source(s_suricata_stats); destination(d_remote); };
log { source(s_watchdog); destination(d_remote); };
EOF
    fi

    # Add local logging
    cat >> /etc/syslog-ng/syslog-ng.conf <<EOF
# Local logging for all sources
log { source(s_system); source(s_kernel); destination(d_local); };
log { source(s_auth); source(s_cron); destination(d_local); };
log { source(s_strongswan); destination(d_local); };
log { source(s_suricata); source(s_suricata_stats); destination(d_local); };
log { source(s_watchdog); destination(d_local); };
EOF

    # Configure log rotation for important files
    if [ ! -f "$LOGROTATE_CONFIG" ]; then
        cat > "$LOGROTATE_CONFIG" <<EOF
/var/log/suricata/*.log /var/log/suricata_watchdog_actions/actions.log /var/log/swanctl_user_check.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        systemctl reload syslog-ng 2>/dev/null || true
    endscript
}

/var/log/charon.log /var/log/auth.log /var/log/cron.log /var/log/syslog-ng/messages {
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
        log "Log rotation configured with secure permissions."
    else
        log "Using existing log rotation configuration at $LOGROTATE_CONFIG"
    fi

    # Validate and restart syslog-ng
    log "Validating syslog-ng configuration..."
    if ! syslog-ng -s; then
        log "Configuration validation failed. Using fallback configuration..."
        
        # Write fallback minimal config
        cat > /etc/syslog-ng/syslog-ng.conf <<EOF
@version: 3.38
@include "scl.conf"
options { chain_hostnames(off); flush_lines(0); perm(0640); };
source s_system { system(); internal(); };
destination d_local { file("/var/log/syslog-ng/messages"); };
log { source(s_system); destination(d_local); };
EOF
        
        # Try validating again
        if ! syslog-ng -s; then
            log "Fallback configuration failed too. Please check syslog-ng installation."
            return 1
        fi
    fi

    # Check if systemctl is available
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart syslog-ng >/dev/null 2>&1 || {
            log "Failed to restart syslog-ng with systemctl. Trying legacy method..."
            service syslog-ng restart >/dev/null 2>&1 || true
        }
        
        systemctl enable syslog-ng >/dev/null 2>&1 || {
            log "Failed to enable syslog-ng service. Continuing anyway..."
        }
    else
        log "systemctl not available. Trying legacy service method..."
        service syslog-ng restart >/dev/null 2>&1 || true
    fi

    # Final verification
    sleep 2
    if pgrep -f syslog-ng >/dev/null; then
        log "Syslog-ng is running successfully."
    else
        log "Warning: syslog-ng process not found after restart attempt."
    fi

    log "Syslog-ng configuration complete."
    return 0
}

ensure_apparmor_abstractions() {
    log "Ensuring AppArmor abstractions are properly installed..."
    
    # Check if the abstractions directory and daemon file exist
    if [ ! -d "/etc/apparmor.d/abstractions" ] || [ ! -f "/etc/apparmor.d/abstractions/daemon" ]; then
        log "AppArmor abstractions missing or incomplete. Installing required packages..."
        
        # Try to fix permissions in case that's the issue
        mkdir -p /etc/apparmor.d/abstractions
        
        # Install or reinstall all AppArmor related packages
        if ! wait_for_apt_lock; then
            log "Could not acquire apt lock. Manual intervention may be required."
            return 1
        fi
        
        # Install packages with automatic yes and force reinstall
        apt-get update -y
        apt-get install -y --reinstall apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
        
        # Check again if the abstractions are now available
        if [ ! -f "/etc/apparmor.d/abstractions/daemon" ]; then
            log "Warning: Could not install AppArmor abstractions. AppArmor profile application will be skipped."
            return 1
        fi
    fi
    
    log "AppArmor abstractions verified successfully."
    return 0
}

harden_system() {
    log "Starting enhanced system hardening process per Lynis recommendations..."

    export APT_LISTBUGS_FRONTEND=none

    # === Implement Lynis recommendations ===
    
    # HRDN-7222: Install and configure rkhunter (malware detection)
    log "Installing and configuring rkhunter..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    
    # Install rkhunter
    apt-get install -y rkhunter || error_exit "Failed to install rkhunter"
    
    # Configure rkhunter
    log "Configuring rkhunter settings..."
    if [ -f /etc/rkhunter.conf ]; then
        # Update common settings to avoid false positives
        sed -i 's/^MAIL-ON-WARNING=.*/MAIL-ON-WARNING=root/' /etc/rkhunter.conf
        sed -i 's/^ALLOW_SSH_ROOT_USER=.*/ALLOW_SSH_ROOT_USER=no/' /etc/rkhunter.conf
        sed -i 's/^DISABLE_TESTS=.*/DISABLE_TESTS=suspscan hidden_ports hidden_procs deleted_files packet_cap_apps apps/' /etc/rkhunter.conf
        
        # Set UPDATE_MIRRORS to true
        sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
        
        # Set PKGMGR to 'dpkg'
        sed -i 's/^PKGMGR=.*/PKGMGR=DPKG/' /etc/rkhunter.conf
        
        # Fix the WEB_CMD path to use absolute path with usr
        sed -i 's|^#WEB_CMD=/bin/false|WEB_CMD=/usr/bin/false|' /etc/rkhunter.conf
        sed -i 's|^WEB_CMD=/bin/false|WEB_CMD=/usr/bin/false|' /etc/rkhunter.conf
    fi
    
    # Run initial update
    log "Running initial rkhunter update..."
    rkhunter --update || log "rkhunter update reported errors."
    
    # Create baseline for the system
    log "Creating rkhunter baseline properties..."
    rkhunter --propupd || log "rkhunter property update reported errors."
    
    # Setup cron jobs for regular scans
    if ! crontab -l 2>/dev/null | grep -q 'rkhunter'; then
        log "Setting up rkhunter cron jobs..."
        (crontab -l 2>/dev/null; echo "30 3 */3 * * /usr/bin/rkhunter --update") | crontab -
        (crontab -l 2>/dev/null; echo "0 4 */3 * * /usr/bin/rkhunter --check --sk --report-warnings-only --appendlog") | crontab -
        (crontab -l 2>/dev/null; echo "0 5 */3 * * /usr/bin/rkhunter --propupd") | crontab -
        log "rkhunter cron jobs configured successfully."
    else
        log "rkhunter cron jobs are already configured."
    fi
    
    # Test rkhunter
    log "Running rkhunter check to verify installation..."
    rkhunter --check --sk --report-warnings-only || log "rkhunter check reported warnings or errors."

    # Fix for Lynis MAIL-8818 (Postfix banner information disclosure)
    log "Fixing Postfix banner information disclosure..."
    if [ -f /etc/postfix/main.cf ]; then
        # Backup the original config if not already backed up
        if [ ! -f /etc/postfix/main.cf.bak ]; then
            cp -a /etc/postfix/main.cf /etc/postfix/main.cf.bak
        fi
        
        # Update or add the smtpd_banner parameter to hide version information
        if grep -q "^smtpd_banner" /etc/postfix/main.cf; then
            sed -i 's/^smtpd_banner.*/smtpd_banner = $myhostname ESMTP/' /etc/postfix/main.cf
        else
            echo "smtpd_banner = \$myhostname ESMTP" >> /etc/postfix/main.cf
        fi
        
        log "Restarting Postfix to apply banner changes..."
        systemctl restart postfix
        log "Postfix banner updated to hide version information"
    fi

    # KRNL-6000: Enhanced kernel security settings
    log "Applying comprehensive sysctl hardening for Lynis audit recommendations..."
    cat > /etc/sysctl.d/99-lynis-fixes.conf << EOF
# Kernel hardening parameters identified by Lynis audit

# TTY settings
dev.tty.ldisc_autoload = 0

# Filesystem protections
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Kernel hardening
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1

# Crypto settings
kernel.random.read_wakeup_threshold = 64
kernel.random.write_wakeup_threshold = 128

# BPF hardening
net.core.bpf_jit_harden = 2

# Network security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0

# IPv6 security
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

    log "Applying kernel settings..."
    sysctl --system

    # ACCT-9622, ACCT-9626: Enable process accounting
    log "Installing and configuring process accounting..."
    apt-get install -y acct || log "Failed to install process accounting tools."
    
    if systemctl start acct; then
        systemctl enable acct || log "Failed to enable acct service."
    else
        log "Failed to start acct service."
    fi

    # TEST-6222: Security enhancement for /proc
    log "Enhancing /proc mount security with hidepid=2..."
    if ! grep -q "hidepid=2" /etc/fstab && ! mount | grep -q "hidepid=2"; then
        # Backup fstab if not already backed up
        if [ ! -f /etc/fstab.bak ]; then
            cp -a /etc/fstab /etc/fstab.bak
        fi
        
        # Update proc mount options
        if grep -q "/proc" /etc/fstab; then
            # Modify existing entry
            sed -i 's|proc\s\+/proc\s\+proc\s\+.*|proc /proc proc defaults,hidepid=2,gid=adm 0 0|' /etc/fstab
        else
            # Add new entry
            echo "proc /proc proc defaults,hidepid=2,gid=adm 0 0" >> /etc/fstab
        fi
        
        # Apply the change without reboot
        log "Remounting /proc with hidepid=2 option..."
        mount -o remount,hidepid=2,gid=adm /proc
        log "/proc remounted with hidepid=2"
    fi
    
    # PKGS-7370: Install debsums for package integrity checking
    log "Installing and configuring debsums for package integrity..."
    apt-get install -y debsums || log "Failed to install debsums."
    
    # Configure regular debsums checks
    if [ ! -f "/etc/cron.daily/debsums_integrity_check" ]; then
        log "Creating daily debsums integrity check..."
        cat > /etc/cron.daily/debsums_integrity_check << 'EOF'
#!/bin/bash
# Daily integrity check using debsums - Added by StrongConn hardening
/usr/bin/debsums -c 2>&1 | grep -v "OK$" > /var/log/debsums_$(date +%Y%m%d).log
# Only send mail if there are issues
if [ -s /var/log/debsums_$(date +%Y%m%d).log ]; then
    echo "Package integrity issues found. Check /var/log/debsums_$(date +%Y%m%d).log" | \
    mail -s "Debsums Integrity Issues - $(hostname)" root
fi
EOF
        chmod 700 /etc/cron.daily/debsums_integrity_check
    fi
    
    # LOGG-2190: Script to clean up deleted files still in use
    if [ ! -f "/etc/cron.daily/cleanup_deleted_files" ]; then
        log "Creating script to manage deleted files still in use..."
        cat > /etc/cron.daily/cleanup_deleted_files << 'EOF'
#!/bin/bash
# Identify and log deleted files still in use - Added by StrongConn hardening
LOGFILE="/var/log/deleted_files_$(date +%Y%m%d).log"
echo "Deleted files still in use as of $(date)" > $LOGFILE
/usr/bin/lsof +L1 | grep 'DEL' >> $LOGFILE

# Log count of found files
COUNT=$(grep -c 'DEL' $LOGFILE)
logger -t deleted_files "Found $COUNT deleted files still in use"

# For non-critical services, check and restart if needed
if [ $COUNT -gt 0 ]; then
    if /usr/bin/lsof +L1 | grep 'DEL' | grep -q 'syslog-ng'; then
        logger -t deleted_files "Restarting syslog-ng to release deleted files"
        systemctl restart syslog-ng
    fi
fi
EOF
        chmod 700 /etc/cron.daily/cleanup_deleted_files
    fi
    
    # AUTH-9282: Configure password expiration policies
    log "Setting secure password aging policies..."
    if [ -f /etc/login.defs ]; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
    fi
    
    # Set secure umask in shell configuration
    log "Setting secure umask in bash configuration..."

# HRDN-7222: Set secure umask and restrict compiler access
for profile_file in /etc/profile /etc/bash.bashrc; do
    if [ -f "$profile_file" ]; then
        if ! grep -q "^umask 027" "$profile_file"; then
            echo "# Set secure umask - added by StrongConn hardening" >> "$profile_file"
            echo "umask 027" >> "$profile_file"
        fi
    fi
done

# HRDN-7222: Restrict compiler access
    log "Hardening compiler access..."
    
    if [ ! -f "/etc/sudoers.d/compiler_access" ]; then
        cat > /etc/sudoers.d/compiler_access << 'EOF'
# Restrict compiler access - added by StrongConn hardening
Cmnd_Alias COMPILER_CMDS = /usr/bin/as, /usr/bin/gcc, /usr/bin/cc, /usr/bin/c++, /usr/bin/g++, /usr/bin/make
# Only allow root to use compilers directly
Defaults:ALL !exempt_group
%sudo ALL=(root) COMPILER_CMDS
EOF
        chmod 440 /etc/sudoers.d/compiler_access
    fi
    
    # Disable unnecessary and potentially dangerous kernel modules
    log "Disabling unnecessary and potentially risky kernel modules..."
    
    cat > /etc/modprobe.d/disable-unused-modules.conf << 'EOF'
# Disable unnecessary kernel modules - added by StrongConn hardening
# Based on Lynis recommendations and security hardening best practices

# Disable unused filesystem drivers
install cramfs /bin/true        # Legacy compressed filesystem
install freevxfs /bin/true      # Veritas filesystem
install jffs2 /bin/true         # Journaling Flash File System
install hfs /bin/true           # Apple HFS filesystem
install hfsplus /bin/true       # Apple HFS+ filesystem
install squashfs /bin/true      # Squashfs - only enable if needed
install udf /bin/true           # Universal Disk Format (DVD filesystem)

# Disable unused network protocols
install dccp /bin/true          # Datagram Congestion Control Protocol
install sctp /bin/true          # Stream Control Transmission Protocol
install rds /bin/true           # Reliable Datagram Sockets
install tipc /bin/true          # Transparent Inter-Process Communication
install ax25 /bin/true          # Amateur Radio protocols
install netrom /bin/true        # Amateur Radio protocol
install x25 /bin/true           # X.25 protocol
install rose /bin/true          # Amateur Radio X.25 PLP
install decnet /bin/true        # DECnet protocol
install econet /bin/true        # Acorn Econet protocol
install af_802154 /bin/true     # IEEE 802.15.4 protocol
install ipx /bin/true           # Novell network protocol
install appletalk /bin/true     # AppleTalk protocol
install psnap /bin/true         # SNAP protocol
install p8023 /bin/true         # Obsolete 802.3 protocol
install llc /bin/true           # LLC protocol
install p8022 /bin/true         # IEEE 802.2 protocol

# Disable Bluetooth if not needed
install bluetooth /bin/true     # Bluetooth subsystem
install btusb /bin/true         # Bluetooth USB driver

# Disable unused hardware protocols
install can /bin/true           # Controller Area Network
install atm /bin/true           # Asynchronous Transfer Mode

# Disable unused storage protocols
install usb-storage /bin/true   # USB storage
install firewire-core /bin/true # FireWire (IEEE 1394)
install firewire-ohci /bin/true # FireWire OHCI driver

EOF

    # Blacklist modules for immediate effect
    cat > /etc/modprobe.d/blacklist-unused.conf << 'EOF'
# Blacklist unused modules - added by StrongConn hardening

# Blacklist exotic filesystems
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf

# Blacklist uncommon network protocols
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
blacklist ax25
blacklist netrom
blacklist x25
blacklist rose
blacklist decnet
blacklist econet
blacklist af_802154
blacklist ipx
blacklist appletalk

# Blacklist unused hardware protocols
blacklist can
blacklist atm

# Blacklist unused storage protocols
blacklist usb-storage
blacklist firewire-core

EOF

    for module in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc ax25 netrom x25 rose; do
        rmmod "$module" 2>/dev/null || true
    done

    if ! mount | grep -q "/dev/sd[a-z]"; then
        rmmod usb-storage 2>/dev/null || true
    fi


    # Unload modules if currently loaded (when safe to do so)
    log "Attempting to unload disabled modules safely..."
    for module in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc ax25 netrom x25 rose \
                 decnet econet af_802154 ipx appletalk can atm firewire-core firewire-ohci; do
        if lsmod | grep -q "^$module "; then
            rmmod "$module" 2>/dev/null || log "Could not unload module $module - might be in use"
        fi
    done

    if ! mount | grep -q "/dev/sd[a-z]"; then
        if lsmod | grep -q "^usb_storage "; then
            rmmod usb_storage 2>/dev/null || log "Could not unload usb_storage - might be in use"
        fi
    fi

    log "Updating initramfs to apply kernel module restrictions..."
    update-initramfs -u || log "Failed to update initramfs"
    
    log "Setting up minimal system profile with restricted permissions..."

    cat > /etc/sysctl.d/90-ipsec-router.conf << 'EOF'
# IPsec router specific sysctl hardening

# Enable IP forwarding (required for IPsec site-to-site)
net.ipv4.ip_forward = 1

# Disable non-critical network capabilities
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Apply reverse path filtering (strict for non-VPN interfaces)
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Enable logging of spoofed, source-routed, and redirect packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Increase connection tracking table size for high traffic volume
net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_tcp_timeout_established = 86400

# Protect against SYN flood attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Reduce timeouts to clear dead connections faster
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 9

# Security hardening for networking
net.ipv4.tcp_timestamps = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IPv6 security settings
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

    # Apply sysctl changes
    log "Applying IPsec router network hardening parameters..."
    sysctl --system || log "Failed to apply some sysctl parameters, might need manual review"
    
 
    cat > /usr/local/bin/ipsec-config-check.sh << 'EOF'
#!/bin/bash
# Daily check for IPsec VPN configuration integrity
# This script verifies that critical IPsec configuration hasn't been modified

REPORT_FILE="/var/log/ipsec-config-check-$(date +%Y%m%d).log"
ALERT=0

echo "IPsec VPN Configuration Check - $(date)" > $REPORT_FILE
echo "==========================================" >> $REPORT_FILE

# Check strongswan config files for unauthorized changes (assuming AIDE is running)
if [ -f /var/lib/aide/aide.db ]; then
    echo "Checking IPsec configuration integrity..." >> $REPORT_FILE
    aide --check-part=/etc/strongswan.conf,/etc/strongswan.d,/etc/swanctl,/opt/pki >> $REPORT_FILE 2>&1
    if [ $? -ne 0 ]; then
        echo "WARNING: IPsec configuration changes detected!" >> $REPORT_FILE
        ALERT=1
    fi
fi

# Check nftables ruleset for unauthorized changes
CURRENT_RULES=$(nft list ruleset | md5sum | cut -d' ' -f1)
if [ -f /var/lib/ipsec-router/nft-ruleset-hash ]; then
    SAVED_RULES=$(cat /var/lib/ipsec-router/nft-ruleset-hash)
    if [ "$CURRENT_RULES" != "$SAVED_RULES" ]; then
        echo "WARNING: Firewall ruleset has changed!" >> $REPORT_FILE
        echo "Current ruleset:" >> $REPORT_FILE
        nft list ruleset >> $REPORT_FILE
        ALERT=1
    else
        echo "Firewall ruleset integrity verified." >> $REPORT_FILE
    fi
else
    # First run, save the current hash
    mkdir -p /var/lib/ipsec-router
    echo "$CURRENT_RULES" > /var/lib/ipsec-router/nft-ruleset-hash
    echo "Initial firewall ruleset hash stored." >> $REPORT_FILE
fi

# Check active tunnels and report
echo "Current IPsec tunnel status:" >> $REPORT_FILE
swanctl --list-sas >> $REPORT_FILE 2>&1

# Alert if issues found
if [ $ALERT -eq 1 ]; then
    logger -t ipsec-check -p auth.warning "IPsec configuration integrity issues detected. See $REPORT_FILE"
    if [ -x /usr/bin/mail ]; then
        cat $REPORT_FILE | mail -s "ALERT: IPsec Configuration Changes on $(hostname)" root
    fi
else
    logger -t ipsec-check -p auth.info "IPsec configuration integrity check passed"
fi

# Rotate logs (keep last 30 days)
find /var/log -name "ipsec-config-check-*.log" -type f -mtime +30 -delete
EOF

    chmod 700 /usr/local/bin/ipsec-config-check.sh

    cat > /etc/cron.daily/ipsec-config-check << 'EOF'
#!/bin/sh
/usr/local/bin/ipsec-config-check.sh
EOF

    chmod 700 /etc/cron.daily/ipsec-config-check
    
   
    log "Hardening SSH configuration (keeping default port)..."
    if [ -f "/etc/ssh/sshd_config" ]; then
        log "Backing up original SSH configuration..."
        cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)
        
        # Apply SSH hardening settings
        for option in "PermitRootLogin no" "X11Forwarding no" "MaxAuthTries 3" \
                      "PermitEmptyPasswords no" "ClientAliveInterval 300" \
                      "ClientAliveCountMax 2" "LoginGraceTime 60" \
                      "PermitUserEnvironment no" "UsePAM yes" \
                      "IgnoreRhosts yes" "StrictModes yes" \
                      "PrintLastLog yes" "LogLevel VERBOSE"; do
            key=$(echo "$option" | cut -d' ' -f1)
            value=$(echo "$option" | cut -d' ' -f2-)
            
            if grep -q "^#\?${key}" /etc/ssh/sshd_config; then
                # Replace or uncomment the existing setting
                sed -i "s/^#\?${key}.*/${key} ${value}/" /etc/ssh/sshd_config
            else
                # Add the setting if it doesn't exist
                echo "${key} ${value}" >> /etc/ssh/sshd_config
            fi
        done
        
        log "Restarting SSH service to apply changes..."
        systemctl restart ssh
    fi
    
    # Install and configure AIDE for file integrity monitoring
    log "Installing and configuring enhanced AIDE file integrity monitoring..."
    if ! dpkg -l | grep -q aide; then
        apt-get install -y aide aide-common || log "Failed to install AIDE"
        
        # Configure AIDE with optimized settings
        log "Creating optimized AIDE configuration..."
        
        # Backup original config
        if [ -f /etc/aide/aide.conf ]; then
            cp -a /etc/aide/aide.conf /etc/aide/aide.conf.bak
        fi
        
        # Create enhanced configuration with focus on security-critical files
        cat > /etc/aide/aide.conf.strongconn << 'EOF'
# StrongConn enhanced AIDE configuration
# Focused on IPsec VPN security with optimized rule sets

# Define common groups for AIDE checks
Binlib = p+i+n+u+g+s+b+m+c+md5+sha1
Logs = p+i+n+u+g+ftype
Databases = p+i+n+u+g
VPNConfig = p+i+n+u+g+s+acl+xattrs+md5+sha1
StaticConfig = p+i+n+u+g+s+acl+xattrs+md5+sha1
IgnoreNone = R
VarTime = p+i+n+u+g+s+acl+xattrs+md5+sha1
VarFile = p+i+n+u+g+ftype

# Standard system binaries
/bin Binlib
/sbin Binlib
/usr/bin Binlib
/usr/sbin Binlib
/usr/local/bin Binlib
/usr/local/sbin Binlib
/lib Binlib
/lib64 Binlib
/usr/lib Binlib
/usr/lib64 Binlib
/usr/local/lib Binlib
/usr/local/lib64 Binlib

# StrongSwan VPN configuration critical files
/etc/swanctl VPNConfig
/etc/strongswan.d VPNConfig
/etc/strongswan.conf VPNConfig
/opt/pki VPNConfig

# System configuration files
/etc/passwd StaticConfig
/etc/group StaticConfig
/etc/shadow StaticConfig
/etc/gshadow StaticConfig
/etc/login.defs StaticConfig
/etc/inittab StaticConfig
/etc/hosts StaticConfig
/etc/networks StaticConfig
/etc/protocols StaticConfig
/etc/services StaticConfig
/etc/localtime StaticConfig
/etc/ld.so.conf StaticConfig
/etc/hostname StaticConfig
/etc/fstab StaticConfig
/etc/environment StaticConfig
/etc/ssh StaticConfig
/etc/crontab StaticConfig
/etc/cron.d StaticConfig
/etc/cron.daily StaticConfig
/etc/cron.hourly StaticConfig
/etc/cron.weekly StaticConfig
/etc/cron.monthly StaticConfig
/etc/security StaticConfig
/etc/pam.d StaticConfig
/etc/modprobe.d StaticConfig
/etc/sysctl.d StaticConfig
/etc/udev/rules.d StaticConfig
/etc/firewalld/zones StaticConfig
/etc/ssl/certs StaticConfig
/etc/systemd StaticConfig
/etc/logrotate.d StaticConfig
/etc/fail2ban StaticConfig
/etc/apparmor StaticConfig
/etc/apparmor.d StaticConfig
/etc/nginx/nginx.conf StaticConfig
/etc/nginx/sites-enabled StaticConfig
/etc/postfix/main.cf StaticConfig
/etc/resolv.conf VarFile

# Critical log files to monitor
/var/log/auth.log Logs
/var/log/secure Logs
/var/log/syslog Logs
/var/log/aide Logs
/var/log/strongswan.log Logs
/var/log/audit Logs
/var/log/suricata Logs
/var/log/fail2ban.log Logs
/var/log/rkhunter.log Logs

# Exclude frequently changing files/dirs that aren't security critical
!/var/log/lastlog
!/var/log/wtmp
!/var/log/btmp
!/var/log/suricata/eve.json
!/var/cache
!/var/tmp
!/tmp
!/proc
!/sys
!/run
!/dev
!/var/lib/dhcp
!/var/lib/docker
!/var/log/journal
!/var/log/nginx/access.log
!/var/log/nginx/error.log
!/var/spool/postfix
!/var/lib/apt
!/var/lib/dpkg/info
!/root/.bash_history
!/home/*/.*history
EOF

        # Link the new configuration
        ln -sf /etc/aide/aide.conf.strongconn /etc/aide/aide.conf
        
        # Create directories for logs
        mkdir -p /var/log/aide
        
        # Initialize AIDE database
        log "Initializing AIDE database (this may take a while)..."
        aideinit || log "Initial AIDE database creation failed, will retry later"
        
        # Move the initial database to the right location
        if [ -f /var/lib/aide/aide.db.new ]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            log "AIDE database initialized successfully"
        fi
        
        # Configure daily checks with better reporting
        if [ ! -f /etc/cron.daily/aide-check ]; then
            cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# Enhanced daily AIDE integrity check - Added by StrongConn hardening
DATE=$(date +%Y%m%d)
LOGDIR="/var/log/aide"
LOGFILE="$LOGDIR/aide-check-$DATE.log"
SUMMARY="$LOGDIR/aide-summary-$DATE.log"

# Create log directory if it doesn't exist
mkdir -p $LOGDIR
chmod 750 $LOGDIR

echo "=== AIDE Integrity Check - $(date) ===" > $LOGFILE
/usr/bin/aide.wrapper --check >> $LOGFILE 2>&1
RESULT=$?

# Create a summary report
echo "AIDE Integrity Check Summary for $(hostname) - $(date)" > $SUMMARY
echo "------------------------------------------------" >> $SUMMARY
echo "" >> $SUMMARY

if [ $RESULT -ne 0 ]; then
    echo "INTEGRITY VIOLATIONS DETECTED!" >> $SUMMARY
    echo "" >> $SUMMARY
    
    # Extract and summarize the changes
    echo "Summary of changes:" >> $SUMMARY
    grep -A 2 "Added files:" $LOGFILE 2>/dev/null >> $SUMMARY
    grep -A 2 "Removed files:" $LOGFILE 2>/dev/null >> $SUMMARY
    grep -A 2 "Changed files:" $LOGFILE 2>/dev/null >> $SUMMARY
    
    echo "" >> $SUMMARY
    echo "See full report at $LOGFILE" >> $SUMMARY
    
    # Send notification
    if [ -x /usr/bin/mail ]; then
        cat $SUMMARY | mail -s "WARNING: File Integrity Violations on $(hostname)" root
    fi
    
    logger -t aide -p auth.warning "File integrity violations detected. See $LOGFILE for details."
else
    echo "No integrity violations detected." >> $SUMMARY
    logger -t aide -p auth.info "File integrity check completed successfully. No violations found."
fi

# Rotate logs (keep 30 days)
find $LOGDIR -name "aide-check-*.log" -type f -mtime +30 -delete
find $LOGDIR -name "aide-summary-*.log" -type f -mtime +30 -delete

# Update the database if requested (weekly)
if [ $(date +%u) -eq 7 ]; then  # Sunday
    echo "Updating AIDE database..." >> $SUMMARY
    /usr/bin/aide.wrapper --update >> $LOGFILE 2>&1
    if [ -f /var/lib/aide/aide.db.new ]; then
        # Ensure AIDE is installed
        log "Installing AIDE for file integrity monitoring..."
        apt-get install -y aide || log "Failed to install AIDE."
        
        # Initialize AIDE database
        log "Initializing AIDE database (this may take some time)..."
        if aide --init; then
            log "AIDE database initialized successfully."
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || log "Failed to move AIDE database to the correct location."
        else
            log "AIDE database initialization failed. Creating an empty database as a fallback..."
            mkdir -p /var/lib/aide
            touch /var/lib/aide/aide.db
            chmod 600 /var/lib/aide/aide.db
            log "Empty AIDE database created at /var/lib/aide/aide.db."
        fi
        
        # Set up a daily cron job for AIDE checks
        if [ ! -f "/etc/cron.daily/aide_integrity_check" ]; then
            log "Creating daily AIDE integrity check cron job..."
            cat > /etc/cron.daily/aide_integrity_check << 'EOF'
#!/bin/bash
# Daily integrity check using AIDE
/usr/bin/aide --check > /var/log/aide/aide_check_$(date +%Y%m%d).log
if [ $? -ne 0 ]; then
    echo "AIDE integrity check failed. Check /var/log/aide/aide_check_$(date +%Y%m%d).log for details."
fi
EOF
            chmod +x /etc/cron.daily/aide_integrity_check
            log "Daily AIDE integrity check cron job created."
        fi
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        logger -t aide -p auth.info "AIDE database updated successfully"
    fi
fi
            chmod 700 /etc/cron.daily/aide-check
    else
        # If AIDE is already installed, just improve the configuration
        log "AIDE already installed, enhancing configuration..."
        
        # Backup original config if not already done
        if [ -f /etc/aide/aide.conf ] && [ ! -f /etc/aide/aide.conf.bak ]; then
            cp -a /etc/aide/aide.conf /etc/aide/aide.conf.bak
        fi
        
        # Check if our custom config exists
        if [ ! -f /etc/aide/aide.conf.strongconn ]; then
            log "Creating enhanced AIDE configuration..."
            # (The previous config file content would be created here)
        fi
    fi
log "Installing and configuring AppArmor..."
if ! wait_for_apt_lock; then
    error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
fi

# Install AppArmor and related packages
apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra || error_exit "Failed to install AppArmor."

# Make sure AppArmor is enabled in GRUB
if [ -f /etc/default/grub ]; then
    if ! grep -q "apparmor=1" /etc/default/grub; then
        # Add AppArmor parameters to GRUB_CMDLINE_LINUX_DEFAULT - safer approach
        current_cmdline=$(grep 'GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | cut -d'"' -f2)
        if [[ ! $current_cmdline =~ apparmor=1 ]]; then
            # Backup original grub file
            cp /etc/default/grub /etc/default/grub.bak.$(date +%Y%m%d%H%M%S)
            # Create a cleaner replacement
            sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=".*"/GRUB_CMDLINE_LINUX_DEFAULT="'"$current_cmdline apparmor=1 security=apparmor"'"/' /etc/default/grub
        fi
        # Update GRUB configuration
        update-grub || log "Failed to update GRUB configuration. AppArmor might not load at boot."
    fi
fi
log "Starting AppArmor service..."
systemctl enable apparmor 2>/dev/null || log "Failed to enable AppArmor service."
systemctl start apparmor 2>/dev/null || log "Failed to start AppArmor service."

# Function to ensure abstractions exist (define if not already present elsewhere)
ensure_apparmor_abstractions

# Enhanced AppArmor configuration
if systemctl is-active apparmor >/dev/null 2>&1; then
    log "AppArmor is active. Setting up more secure profiles for services..."

    # Create directory for custom profiles
    mkdir -p /etc/apparmor.d/local || log "Failed to create /etc/apparmor.d/local directory."

log "Starting AppArmor profile fixes..."

# ==== StrongSwan Profile Fix ====
log "Creating fixed AppArmor profile for StrongSwan services..."
 tee /etc/apparmor.d/local/usr.lib.ipsec.charon >/dev/null << 'EOF'
#include <tunables/global>

profile /usr/lib/ipsec/charon {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>
  # Removed the problematic 'daemon' abstraction

  # Basic capabilities
  capability net_admin,
  capability net_raw,
  capability ipc_lock,
  capability setuid,
  capability setgid,

  # Network access
  network raw,
  network packet,
  network inet,
  network inet6,
  network netlink,
  
  # Configuration files
  /etc/strongswan/** r,
  /etc/strongswan.conf r,
  /etc/strongswan.d/** r,
  /etc/swanctl/** r,
  /etc/ipsec.conf r,
  /etc/ipsec.secrets r,
  /etc/ipsec.d/** r,
  
  # PKI directories
  /opt/pki/x509/** r,
  /opt/pki/private/** r,
  /opt/pki/crl/** r,
  
  # Data and log directories
  /var/lib/strongswan/ rw,
  /var/lib/strongswan/** rwk,
  /var/log/strongswan/ rw,
  /var/log/strongswan/** rw,
  
  # Runtime files
  /run/systemd/journal/socket rw,
  /run/systemd/journal/stdout rw,
  /run/charon.ctl rw,
  /run/charon.pid rw,
  /run/strongswan/ rw,
  /run/strongswan/** rwk,
  
  # Libraries and binaries
  /usr/lib/ipsec/charon mr,
  /usr/lib/ipsec/* mr,
  /usr/lib/** mr,
  /usr/local/lib/** mr,
  /lib/x86_64-linux-gnu/** mr,
  
  # System files
  /proc/sys/net/ipv4/** r,
  /proc/sys/net/ipv6/** r,
  /proc/sys/net/core/xfrm_acq_expires rw,
  /proc/net/** r,
  /sys/devices/system/cpu/ r,
  /sys/devices/system/cpu/** r,
  
  # Common files
  /tmp/** rwk,
  /dev/null rw,
  /dev/random r,
  /dev/urandom r,
  
  # Allow Unix socket communication
  unix,
}
EOF

# ==== Vault Profile Fix ====
log "Creating fixed AppArmor profile for HashiCorp Vault..."
 tee /etc/apparmor.d/local/usr.bin.vault >/dev/null << 'EOF'
#include <tunables/global>

profile /usr/bin/vault {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>
  #include <abstractions/user-tmp>
  
  # Basic capabilities needed
  capability ipc_lock,
  capability net_bind_service,
  capability setgid,
  capability setuid,
  capability dac_override,
  
  # Network access
  network tcp,
  network unix,
  
  # Configuration files
  /etc/vault/** r,
  /etc/vault/tls/** r,
  /etc/vault/config.hcl r,
  /etc/strongconn.conf r,
  /etc/vault-sh.conf r,
  
  # PKI directories
  /opt/pki/x509/** r,
  /opt/pki/private/vault-key.pem r,
  /opt/pki/crl/crl.der r,
  
  # SSL certificates
  /etc/ssl/** r,
  /etc/ssl/certs/** r,
  /usr/local/share/ca-certificates/** r,
  
  # Vault data
  /var/lib/vault/ rw,
  /var/lib/vault/** rwk,
  /var/log/vault/ rw,
  /var/log/vault/** rwk,
  
  # Libraries and binaries
  /usr/bin/vault mr,
  /usr/bin/v-pki ix,
  /usr/lib/** mr,
  /usr/local/lib/** mr,
  /lib/x86_64-linux-gnu/** mr,
  
  # Plugins
  /usr/local/lib/vault/plugins/** mr,
  /usr/lib/vault/plugins/** mr,
  
  # System files
  /sys/devices/system/cpu/ r,
  /sys/devices/system/cpu/** r,
  /proc/sys/crypto/fips/enabled r,
  /proc/[0-9]*/status r,
  /proc/[0-9]*/net/** r,
  /proc/[0-9]*/fd/ r,
  /sys/kernel/mm/transparent_hugepage/hpage_pmd_size r,
  /proc/sys/net/core/somaxconn r,         
  
  # Common files
  /tmp/** rwk,
  /run/vault/ rw,
  /run/vault/** rwk,
  /run/vault.pid rw,
  /dev/null rw,
  /dev/random r,
  /dev/urandom r,
  
  # Allow mlock syscall
  deny capability block_suspend,
  deny capability sys_ptrace,
  
  # Allow plugin loading
  /usr/{,local/}lib{,32,64}/vault/plugins/*.so mr,
}
EOF

# ==== Nginx Profile Fix ====
log "Creating fixed AppArmor profile for Nginx web server..."
 tee /etc/apparmor.d/local/usr.sbin.nginx >/dev/null << 'EOF'
#include <tunables/global>

profile /usr/sbin/nginx {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>
  #include <abstractions/user-tmp>
  
  # Basic capabilities
  capability net_bind_service,
  capability setgid,
  capability setuid,
  capability dac_override,
  
  # Network access
  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,
  
  # Configuration files
  /etc/nginx/ r,
  /etc/nginx/** r,
  /etc/nginx/crl/** r,
  /etc/ssl/** r,
  /etc/letsencrypt/** r,
  /etc/passwd r,
  /etc/group r,

  # PKI directories
  /opt/pki/x509/** r,
  /opt/pki/private/vault-key.pem r,
  /opt/pki/crl/crl.der r,
  
  # Web content
  /var/www/ r,
  /var/www/** r,
  /usr/share/nginx/ r,
  /usr/share/nginx/** r,
  
  # Cache and logs
  /var/cache/nginx/ rw,
  /var/cache/nginx/** rw,
  /var/log/nginx/ rw,
  /var/log/nginx/** rw,
  
  # Libraries and binaries
  /usr/sbin/nginx mr,
  /usr/lib/** mr,
  /usr/local/lib/** mr,
  /lib/x86_64-linux-gnu/** mr,
  
  # System files
  /proc/sys/net/core/somaxconn r,
  /proc/sys/net/ipv4/ip_local_port_range r,
  /proc/sys/net/ipv4/tcp_fastopen r,
  /sys/devices/system/cpu/ r,
  /sys/devices/system/cpu/** r,
  
  # Runtime files
  /run/ rw,
  /run/nginx.pid rw,
  /run/nginx/ rw,
  /run/nginx/** rw,
  
  # Common files
  /tmp/** rw,
  /dev/null rw,
  /dev/random r,
  /dev/urandom r,
  
  # Additional permissions for specific configurations
  /etc/nginx/conf.d/ r,
  /etc/nginx/conf.d/** r,
  /etc/nginx/sites-available/ r,
  /etc/nginx/sites-available/** r,
  /etc/nginx/sites-enabled/ r,
  /etc/nginx/sites-enabled/** r,
  
  # Allow Unix socket communication
  unix,
}
EOF

# Reload profiles
log "Reloading AppArmor profiles..."
 apparmor_parser -r /etc/apparmor.d/local/usr.lib.ipsec.charon
 apparmor_parser -r /etc/apparmor.d/local/usr.bin.suricata
 apparmor_parser -r /etc/apparmor.d/local/usr.bin.vault
 apparmor_parser -r /etc/apparmor.d/local/usr.sbin.nginx

# Optional: Restart the AppArmor service
log "Restarting AppArmor service..."
 systemctl restart apparmor

# Restart affected services
log "Restarting services..."
 systemctl restart suricata
 systemctl restart strongswan
 systemctl restart vault
 systemctl restart nginx

log "AppArmor profile fixes have been applied."
    # Apply profiles in complain mode
    log "Applying enhanced AppArmor profiles in complain mode..."
    for profile in usr.lib.ipsec.charon usr.bin.suricata usr.bin.vault usr.sbin.nginx; do
        if [ -f "/etc/apparmor.d/local/$profile" ]; then
            main_profile="/etc/apparmor.d/$profile"
            if [ ! -f "$main_profile" ]; then
                # Create a minimal main profile if it doesn't exist
                 tee "$main_profile" >/dev/null << 'EOF'
#include <tunables/global>
EOF
                log "Created minimal main profile for $profile"
            fi
            if ! grep -q "include <local/$profile>" "$main_profile" 2>/dev/null; then
                echo "include <local/$profile>" |  tee -a "$main_profile" >/dev/null || \
                    log "Could not modify $profile, check permissions"
            fi
            aa-complain "$main_profile" 2>/dev/null || \
                log "Could not set $profile to complain mode"
            log "Enhanced profile for $profile applied in complain mode"
        fi
    done

    # Core services in complain mode
    for service in strongswan-starter strongswan charon swanctl ipsec vault nginx; do
        if aa-status | grep -q "$service" 2>/dev/null; then
            log "Setting core service $service to complain mode"
            aa-complain "/etc/apparmor.d/$service" 2>/dev/null || \
                log "Could not set $service to complain mode"
        fi
    done

    # Standard utilities in enforce mode
    log "Setting standard utilities to enforce mode..."
    aa-enforce /etc/apparmor.d/usr.bin.man 2>/dev/null || log "Could not enforce man profile"
    aa-enforce /etc/apparmor.d/usr.sbin.ntpd 2>/dev/null || log "Could not enforce ntpd profile"
    aa-enforce /etc/apparmor.d/usr.sbin.tcpdump 2>/dev/null || log "Could not enforce tcpdump profile"

    # Learning mode script
    cat > /usr/local/bin/apparmor-learning-mode.sh << 'EOFLEARNING'
#!/bin/bash
# Script to put AppArmor in learning mode for 24 hours and generate improved profiles
aa-complain /etc/apparmor.d/* 2>/dev/null || echo "Failed to set profiles to complain mode"
cat > /etc/cron.d/apparmor-learning << 'EOF'
0 0 * * * root /usr/sbin/aa-logprof -f /var/log/syslog && /usr/sbin/aa-enforce /etc/apparmor.d/* 2>/dev/null
EOF
chmod 644 /etc/cron.d/apparmor-learning
echo "AppArmor set to learning mode for 24 hours"
echo "After 24 hours, profiles will be refined and enforced"
echo "Run 'aa-logprof' manually to refine profiles earlier"
EOFLEARNING
    chmod +x /usr/local/bin/apparmor-learning-mode.sh
    log "Created AppArmor learning mode script at /usr/local/bin/apparmor-learning-mode.sh"
    log "Run this script later to refine AppArmor profiles"
else
    log "Warning: AppArmor service is not active. You may need to reboot."
fi

# Verify AppArmor is running
if ! systemctl is-active --quiet apparmor; then
    log "Warning: AppArmor service did not start properly. Check 'systemctl status apparmor'."
else
    log "AppArmor service is running."
fi

# Check AppArmor status
log "Checking AppArmor status..."
if command -v aa-status >/dev/null 2>&1; then
    aa-status || log "Failed to get AppArmor status."
else
    log "AppArmor status command not found."
fi

# Critical profiles in complain mode
log "Setting up AppArmor profiles..."
if command -v aa-complain >/dev/null 2>&1; then
    for critical_service in strongswan swanctl vault ; do
        for profile in /etc/apparmor.d/*"$critical_service"*; do
            if [[ -f "$profile" && "$profile" != *"disable"* ]]; then
                log "Setting $profile to complain mode..."
                aa-complain "$profile" || log "Failed to set $profile to complain mode."
            fi
        done
    done

    # Enforce standard profiles
    log "Setting standard profiles to enforce mode..."
    aa-enforce /etc/apparmor.d/usr.bin.man || log "Failed to enforce man profile."
    aa-enforce /etc/apparmor.d/usr.sbin.ntpd || log "Failed to enforce ntpd profile."
    aa-enforce /etc/apparmor.d/usr.sbin.tcpdump || log "Failed to enforce tcpdump profile."
else
    log "AppArmor aa-complain utility not found."
fi
    # Install entropy generation tools
    log "Installing entropy generation tools..."
    apt-get install -y rng-tools haveged
    systemctl enable haveged
    systemctl start haveged
    
    # Verify entropy is sufficient for cryptographic operations
    log "Checking entropy pool size..."
    cat /proc/sys/kernel/random/entropy_avail || log "Failed to check entropy pool size."

   
    log "Hardening fstab..."


    cp /etc/fstab /etc/fstab.bak || { log "Failed to back up /etc/fstab. Aborting."; exit 1; }


    if grep -q "/.*/" /etc/fstab; then
        # Get the current root line
        ROOT_LINE=$(grep -E "[[:space:]]/[[:space:]]|/dev/[[:alnum:]]+ /" /etc/fstab)
        # Extract the device and other parts
        DEVICE=$(echo "$ROOT_LINE" | awk '{print $1}')
        # Replace the line with hardened options
        sed -i "s|$ROOT_LINE|$DEVICE / ext4 defaults,noatime, 0 1|" /etc/fstab
        log "Hardened the root (/) filesystem entry in /etc/fstab."
    else
        log "Warning: Root (/) entry not found in /etc/fstab. Skipping fstab hardening."
 
    fi

    if grep -q "^tmpfs /dev/shm" /etc/fstab; then
        log "/dev/shm already present in /etc/fstab."
    else
        echo "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0" >> /etc/fstab
        log "Added /dev/shm entry to /etc/fstab."
    fi

  
    log "Verifying fstab changes..."
    if mount -a 2>/dev/null; then
        log "fstab changes applied successfully."
    else
        log "Error in /etc/fstab syntax. Restoring backup..."
        cp /etc/fstab.bak /etc/fstab
        mount -a || log "Failed to restore previous fstab configuration. Manual intervention required."
        exit 1
    fi

    log "Configuring core dump settings..."
    LIMITS_CONF="/etc/security/limits.conf"
    CORE_DUMP_SETTING="* hard core 0"

    if grep -Fxq "$CORE_DUMP_SETTING" "$LIMITS_CONF"; then
        echo "Core dump setting already exists in $LIMITS_CONF"
    else
        echo "Adding core dump setting to $LIMITS_CONF..."
        echo "$CORE_DUMP_SETTING" | tee -a "$LIMITS_CONF" >/dev/null
        if [ $? -eq 0 ]; then
            echo "Successfully added core dump setting to $LIMITS_CONF"
        else
            echo "Failed to add core dump setting. Please check your permissions."
        fi
    fi
    echo "fs.suid_dumpable = 0" | tee -a /etc/sysctl.conf
    sysctl -p

    log "Configuring default umask..."
    if grep -q "^UMASK" /etc/login.defs; then
        current_umask=$(grep "^UMASK" /etc/login.defs | awk '{print $2}')
        if [ "$current_umask" != "027" ]; then
            sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
        fi
    else
        echo "UMASK 027" | tee -a /etc/login.defs > /dev/null
    fi
    echo "Default umask in /etc/login.defs is now 027."
    
    
    log "Configuring password hashing rounds..."
    if grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs; then
        sed -i '/^SHA_CRYPT_MIN_ROUNDS/c\SHA_CRYPT_MIN_ROUNDS 5000' /etc/login.defs
    else
        echo "SHA_CRYPT_MIN_ROUNDS 5000" >> /etc/login.defs
    fi

    if grep -q "^SHA_CRYPT_MAX_ROUNDS" /etc/login.defs; then
        sed -i '/^SHA_CRYPT_MAX_ROUNDS/c\SHA_CRYPT_MAX_ROUNDS 50000' /etc/login.defs
    else
        echo "SHA_CRYPT_MAX_ROUNDS 50000" >> /etc/login.defs
    fi
    echo "deny = 5" >> /etc/security/faillock.conf
    echo "unlock_time = 900" >> /etc/security/faillock.conf

    log "Installing and configuring PAM module for password strength testing (pam_pwquality)..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get install -y libpam-pwquality
    if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        sed -i '/^password.*pam_unix\.so/ s/$/ remember=5 minlen=12/' /etc/pam.d/common-password
        sed -i '/^password.*pam_unix\.so/ i\password required pam_pwquality.so retry=3' /etc/pam.d/common-password
    fi

    log "Configuring minimum password age..."
    sed -i '/^PASS_MIN_DAYS/c\PASS_MIN_DAYS 1' /etc/login.defs
    
    # Fix for Lynis AUTH-9286 (Password expiration)
    log "Configuring maximum password age..."
    if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
        sed -i '/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 90' /etc/login.defs
    else
        echo "PASS_MAX_DAYS 90" >> /etc/login.defs
    fi

 
    log "Installing and configuring system update tools..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get install -y unattended-upgrades apt-listchanges apticron apt-transport-https apt-show-versions apt-listbugs
    log "Configuring apt-listchanges to be non-interactive..."
    debconf-set-selections <<< 'apt-listchanges apt-listchanges/which string both'
    debconf-set-selections <<< 'apt-listchanges apt-listchanges/email-address string root'
    debconf-set-selections <<< 'apt-listchanges apt-listchanges/frontend select mail'
    dpkg-reconfigure -f noninteractive apt-listchanges
    dpkg-reconfigure -f noninteractive apticron

    log "Updating the system packages..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get update
    apt-get upgrade -y
    apt-get dist-upgrade -y

    log "Purging old/removed packages..."
    apt-get autoremove --purge -y
    
    # Fix for Lynis PKGS-7346 (purging old/removed packages)
    log "Purging packages marked as rc (removed but config remains)..."
    dpkg_rc_packages=$(dpkg -l | grep "^rc" | awk '{print $2}')
    if [ -n "$dpkg_rc_packages" ]; then
        apt-get -y purge $dpkg_rc_packages
        log "Purged remaining config files from removed packages"
    else
        log "No packages with remaining config files found"
    fi
    
    # Fix for Lynis LOGG-2190 (Deleted files still in use)
    log "Checking for deleted files still in use..."
    deleted_files=$(lsof +L1 | grep -v "\(mem\|COMMAND\)")
    if [ -n "$deleted_files" ]; then
        log "Found deleted files still in use. Attempting to restart affected services."
        # Extract service names from lsof output and restart them
        lsof +L1 | grep -v "\(mem\|COMMAND\)" | awk '{print $1}' | sort | uniq > /tmp/services_to_restart.txt
        while read -r service; do
            if systemctl list-units --type=service | grep -q "$service"; then
                log "Restarting $service to release deleted files..."
                systemctl restart "$service" || log "Failed to restart $service"
            fi
        done < /tmp/services_to_restart.txt
        rm -f /tmp/services_to_restart.txt
    fi

 
    log "Installing and enabling sysstat..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get install -y sysstat
    sed -i 's/ENABLED="false"/ENABLED="true"/g' /etc/default/sysstat
    systemctl enable sysstat
    systemctl start sysstat

 

    cat > /etc/modprobe.d/unused-protocols.conf <<EOF
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
EOF

    log "Blacklisting protocols that are typically not needed..."
    if [ ! -f /etc/modprobe.d/blacklist.conf ]; then
        touch /etc/modprobe.d/blacklist.conf
    fi
    for module in dccp sctp rds tipc firewire-core firewire-ohci firewire-sbp2; do
        if ! grep -q "^install $module /bin/false$" /etc/modprobe.d/blacklist.conf; then
            echo "install $module /bin/false" |  tee -a /etc/modprobe.d/blacklist.conf > /dev/null
        fi
    done
    log "Blacklisting unnecessary kernel modules..."

    for module in dccp sctp rds tipc; do
        if ! grep -q "blacklist $module" /etc/modprobe.d/blacklist.conf; then
            echo "blacklist $module" | tee -a /etc/modprobe.d/blacklist.conf
        fi
        if lsmod | grep -qw "$module"; then
            log "Unloading module: $module"
            modprobe -r "$module" || log "Failed to unload $module"
        fi
    done
log "Disabling USB storage completely..."

# 1. Create modprobe configuration to disable USB storage
cat > /etc/modprobe.d/usb-storage.conf <<EOF
# Completely disable USB storage modules
install usb-storage /bin/true
blacklist usb-storage
install uas /bin/true
blacklist uas
EOF

# 2. Add to blacklist.conf as well for redundancy
for module in usb_storage uas usb_libusual; do
    if ! grep -q "blacklist $module" /etc/modprobe.d/blacklist.conf; then
        echo "blacklist $module" >> /etc/modprobe.d/blacklist.conf
    fi
done

# 3. Remove the modules if they're currently loaded
modprobe -r usb-storage uas usb_libusual 2>/dev/null

# 4. Disable all existing USB devices
for usb in /sys/bus/usb/devices/usb*/authorized; do
    echo 0 > "$usb" 2>/dev/null || log "Failed to disable $usb"
done

# 5. Apply the changes to initramfs
update-initramfs -u

log "USB storage has been completely disabled"
    log "Installing and configuring AIDE..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    
    # Install AIDE 
    apt-get install -y aide aide-common || error_exit "Failed to install AIDE"
    
    # Configure AIDE
    if command -v aide >/dev/null 2>&1; then
        log "Configuring AIDE database..."
        
        # Customize AIDE configuration before initialization if needed
        if ! grep -q '^Checksums = sha512' /etc/aide/aide.conf; then
            echo "Checksums = sha512" | tee -a /etc/aide/aide.conf
        fi
        
        # Initialize AIDE database with appropriate options
        log "Initializing AIDE database (this may take a while)..."
        aideinit -y -f || log "AIDE initialization reported errors, but continuing..."
        
        # Note: aide.db.new is now created, need to copy it to the active database
        if [ -f /var/lib/aide/aide.db.new ]; then
            cp -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            log "AIDE database initialized successfully."
        else
            log "Warning: AIDE database initialization did not create the expected file."
        fi
        
        # Add a daily cron job to check file integrity
        if ! grep -q 'aide' /etc/crontab; then
            echo "0 3 * * * root /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" | tee -a /etc/crontab > /dev/null
            log "Added AIDE daily check to crontab."
        fi
        
        # Test that AIDE is working
        log "Testing AIDE configuration..."
        if aide --check > /dev/null 2>&1; then
            log "AIDE check completed successfully."
        else
            log "AIDE check reported changes or errors. This is expected on first run."
        fi
        
        cat > /etc/cron.d/aide-checks << EOF
# Daily AIDE check
0 3 * * * root /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check

# Monthly AIDE database update
0 2 1 * * root /usr/bin/aide.wrapper --config /etc/aide/aide.conf --update
EOF

    chmod 644 /etc/cron.d/aide-checks
    chown root:root /etc/cron.d/aide-checks
        
        log "AIDE installation and setup complete."
    else
        log "AIDE command not found. Possibly not installed or not supported on this system."
    fi
    echo "kernel.kptr_restrict = 2" | tee -a /etc/sysctl.conf
    echo "kernel.dmesg_restrict = 1" | tee -a /etc/sysctl.conf
    echo "kernel.randomize_va_space = 2" | tee -a /etc/sysctl.conf
    echo "kernel.panic = 60" | tee -a /etc/sysctl.conf
    echo "kernel.panic_on_oops = 60" | tee -a /etc/sysctl.conf 
    echo "kernel.pid_max = 65536" | tee -a /etc/sysctl.conf
    echo "kernel.core_uses_pid = 1" | tee -a /etc/sysctl.conf
    echo "kernel.sysrq = 0" | tee -a /etc/sysctl.conf
    echo "kernel.ctrl-alt-del = 0" | tee -a /etc/sysctl.conf
    sysctl -p

    log "Cleaning up package system..."
   
    apt-get --purge autoremove -y

    log "Installing and configuring debsums for file integrity checking (addressing Lynis PKGS-7370)..."
    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    
    # Install debsums
    apt-get install -y debsums || error_exit "Failed to install debsums"
    
    # Configure debsums
    cat > /etc/default/debsums <<EOF
# Enable regular integrity checking - addressing Lynis PKGS-7370
CRON_CHECK=yes
EOF

    # Create required directories and files
    mkdir -p /var/lib/debsums
    touch /var/lib/debsums/local.md5
    chmod 644 /var/lib/debsums/local.md5
    
    # Run initial debsums check to establish baseline
    log "Running initial debsums check..."
    debsums -as > /dev/null || log "Initial debsums check reported missing or altered files. This is normal for the first run."
    
    # Generate checksums for local files
    log "Generating checksums for local files..."
    find /etc -type f -name "*.conf" -exec md5sum {} \; | grep -v "^/etc/debsums" > /var/lib/debsums/local.md5 || log "Failed to generate checksums for local files."
    
    # Create a dedicated cron job for debsums to ensure it runs regularly (Lynis PKGS-7370)
    log "Setting up dedicated debsums cron job..."
    cat > /etc/cron.daily/debsums_integrity_check << 'EOF'
#!/bin/bash
# Daily check of file integrity using debsums - for Lynis PKGS-7370
debsums -c 2>&1 | grep -v "OK$" > /var/log/debsums_errors.log
# If there are errors, mail the admin
if [ -s /var/log/debsums_errors.log ]; then
    mail -s "Debsums integrity check failed on $(hostname)" root < /var/log/debsums_errors.log
fi
EOF
    chmod 700 /etc/cron.daily/debsums_integrity_check

    log "Configuring sshd_config..."

    cat << EOF | tee /etc/ssh/sshd_config
# Secure SSH Configuration
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTH
LogLevel VERBOSE
LoginGraceTime 1m
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PrintMotd no
UsePAM yes
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no
Banner /etc/ssh/ssh_banner
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms diffie-hellman-group-exchange-sha256
MACs hmac-sha2-256,hmac-sha2-512
Subsystem sftp  /usr/lib/openssh/sftp-server
EOF


    systemctl daemon-reload

    chmod 600 /etc/ssh/sshd_config
    if systemctl restart ssh; then

        log "SSHD configuration rewritten and SSH service restarted."
    else
        error_exit "Failed to restart SSH service with new configuration. Check /etc/ssh/sshd_config for errors."
    fi

    mkdir -p /etc/systemd/system/cron.service.d/

    systemctl daemon-reload
    mkdir -p /var/lib/debsums
    touch /var/lib/debsums/local.md5
    chmod 644 /var/lib/debsums/local.md5

    log "Installing Fail2Ban for SSH"

    if ! wait_for_apt_lock; then
        error_exit "Could not acquire apt lock. Another process is using apt. Run the script again once apt is free."
    fi
    apt-get install -y fail2ban || error_exit "Failed to install Fail2Ban."

    systemctl enable fail2ban
    systemctl restart fail2ban || error_exit "Failed to restart Fail2Ban service."

    echo "Configuring Fail2Ban to add banned IPs to nftables set 'blacklisted_ips' with a timeout..."
    cat << EOF | tee /etc/fail2ban/jail.local
[DEFAULT]
bantime = 24h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
action = nftables[name=sshd, port=ssh, protocol=tcp, chain=input, set=blacklisted_ips]
EOF
    
    echo "Fail2Ban configured to use the nftables set 'blacklisted_ips' for SSH bans with a timeout of 10 minutes."
    echo "Restarting Fail2Ban service to apply changes and waiting for socket creation..."
    
    systemctl restart fail2ban
    
    # Wait for fail2ban to fully start and create its socket
    max_attempts=10
    attempt=0
    while [ $attempt -lt $max_attempts ] && [ ! -S /var/run/fail2ban/fail2ban.sock ]; do
        log "Waiting for fail2ban socket to be created (attempt $((attempt+1))/$max_attempts)..."
        sleep 2
        attempt=$((attempt+1))
    done
    
    if [ -S /var/run/fail2ban/fail2ban.sock ]; then
        chmod 666 /var/run/fail2ban/fail2ban.sock
        log "Fail2Ban socket permissions set successfully"
        
        # Verify fail2ban status
        echo "Checking Fail2Ban status for the sshd jail..."
        fail2ban-client status sshd || log "Failed to retrieve Fail2Ban status. Please check fail2ban configuration."
    else
        log "Failed to create fail2ban socket after $max_attempts attempts"
    fi


    log "Setting legal banners..."
    cat << 'EOF' | tee /etc/issue
-----------------------------------------------------------------------
              Authorized access only!
-----------------------------------------------------------------------

If you are not authorized to access or use this system, disconnect now!

Unauthorized access or use of this system is strictly prohibited 
        and subject to criminal prosecution.
EOF

    cat << 'EOF' | tee /etc/issue.net
-----------------------------------------------------------------------
              Authorized access only!
-----------------------------------------------------------------------

If you are not authorized to access or use this system, disconnect now!

Unauthorized access or use of this system is strictly prohibited 
            and subject to criminal prosecution.
EOF
    log "Fixing permissions for security-sensitive directories (addressing Lynis FILE-7524)..."
    chmod 750 /etc/sudoers.d
    chown root:root /etc/sudoers.d
    
    # Check and fix other important directory permissions
    log "Verifying permissions on critical system directories..."
    chmod 700 /root
    # Set stricter permissions on cron directories (addressing Lynis FILE-7524)
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
    chmod 600 /etc/crontab  # Change to 600 for better security
    chmod 600 /etc/ssh/sshd_config  # Change to 600 for better security
    
    # Verify that no world-writable files exist
    log "Checking for world-writable files in system directories..."
    find /etc /usr/bin /usr/sbin /bin /sbin -type f -perm -0002 -exec chmod o-w {} \; 2>/dev/null || log "No world-writable files found or failed to check."
    
    # Update locate database for faster file searching
    log "Updating 'locate' database..."

        updatedb



    # Add this code to your harden-system() function in strongconn.sh

    log "Configuring debsums for custom configuration files..."

    # Create the directory for custom checksums if it doesn't exist
    mkdir -p /var/lib/debsums

    # Create or update the local.md5 file which stores custom file checksums
    custom_files_md5="/var/lib/debsums/local.md5"
    touch "$custom_files_md5"

    # Add your specific files to be monitored
    echo "# Generated checksums for custom configuration files" > "$custom_files_md5"

    # Generate MD5 checksums for key StrongSwan and other important files
    find /etc/swanctl -type f -name "*.conf" -exec md5sum {} \; >> "$custom_files_md5"
    find /etc/strongswan.d -type f -exec md5sum {} \; >> "$custom_files_md5"
    md5sum /etc/strongconn.conf >> "$custom_files_md5" 2>/dev/null
    md5sum /etc/strongswan.conf >> "$custom_files_md5" 2>/dev/null
    md5sum /etc/classifications.conf >> "$custom_files_md5" 2>/dev/null
    md5sum /etc/nftables.conf >> "$custom_files_md5" 2>/dev/null
    find /etc/nftables.d -type f -exec md5sum {} \; >> "$custom_files_md5" 2>/dev/null
    find /var/lib/strongswan -type f -name "*.py" -exec md5sum {} \; >> "$custom_files_md5" 2>/dev/null
    find /var/lib/strongswan -type f -name "*.sh" -exec md5sum {} \; >> "$custom_files_md5" 2>/dev/null

    # Set proper permissions
    chmod 644 "$custom_files_md5"

# Create a dedicated cron file for debsums in /etc/cron.d/
cat | tee /etc/cron.d/debsums-integrity << EOF
# Run debsums checks daily
0 4 * * * root /usr/bin/debsums --all --changed > /var/log/debsums_changes.log 2>&1

# Weekly check for changes to custom files
0 5 * * 0 root /usr/bin/debsums --no-installed --list > /var/log/debsums_custom_changes.log 2>&1

# Custom file integrity check script
30 4 * * * root /usr/local/bin/check_custom_files.sh
EOF

# Set proper permissions
chmod 644 /etc/cron.d/debsums-integrity
chown root:root /etc/cron.d/debsums-integrity

# Create a dedicated cron file for filesystem checks
cat > /etc/cron.d/filesystem-check << EOF
# Weekly filesystem check
0 2 * * 0 root /sbin/fsck -A -T
EOF

# Set proper permissions
chmod 644 /etc/cron.d/filesystem-check
chown root:root /etc/cron.d/filesystem-check
# Create a script to process debsums output for custom files
cat > /usr/local/bin/check_custom_files.sh << 'EOF'
#!/bin/bash
# Script to check custom files not tracked by Debian packages

CHANGED_FILES=$(debsums --no-installed --changed)
if [ -n "$CHANGED_FILES" ]; then
    echo "=== Custom File Changes Detected $(date) ===" >> /var/log/file_integrity.log
    echo "$CHANGED_FILES" >> /var/log/file_integrity.log
    echo "" >> /var/log/file_integrity.log
    
    # Optional: Update checksums for changed files (comment out if you want alerts only)
    for file in $CHANGED_FILES; do
        if [ -f "$file" ]; then
            echo "Updating checksum for $file"
            md5sum "$file" >> /var/lib/debsums/local.md5.new
        fi
    done
    
    # Merge original and new checksums, removing duplicates
    if [ -f /var/lib/debsums/local.md5.new ]; then
        cat /var/lib/debsums/local.md5 /var/lib/debsums/local.md5.new | sort | uniq > /var/lib/debsums/local.md5.tmp
        mv /var/lib/debsums/local.md5.tmp /var/lib/debsums/local.md5
        rm /var/lib/debsums/local.md5.new
    fi
fi
EOF

    chmod +x /usr/local/bin/check_custom_files.sh



# Configure log rotation for integrity check logs
cat > /etc/logrotate.d/file_integrity << EOF
/var/log/file_integrity.log /var/log/debsums_changes.log /var/log/debsums_custom_changes.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

 

log "Implementing compiler restrictions for HRDN-7222..."

# Create a group for authorized compiler users
groupadd -f compiler_users
log "Created compiler_users group for restricted access."

# List of compilers to restrict
COMPILERS="gcc g++ cc"

# Create directory for real compilers if needed
mkdir -p /usr/local/compiler-wrappers
chmod 755 /usr/local/compiler-wrappers

# Move and restrict original compilers
for COMPILER in $COMPILERS; do
    if [ -f "/usr/bin/$COMPILER" ]; then
        # Move the original compiler to a .real version
        mv "/usr/bin/$COMPILER" "/usr/bin/$COMPILER.real"
        # Restrict permissions to root only
        chown root:root "/usr/bin/$COMPILER.real"
        chmod 700 "/usr/bin/$COMPILER.real"
        log "Moved and restricted /usr/bin/$COMPILER to /usr/bin/$COMPILER.real (root-only access)."
    else
        log "Compiler /usr/bin/$COMPILER not found, skipping..."
    fi
done

# Create compiler wrapper script
cat > /usr/local/compiler-wrappers/compiler-wrapper.sh <<'EOF'
#!/bin/bash
COMPILER=$(basename "$0")
REAL_COMPILER="/usr/bin/$COMPILER.real"
LOG_FILE="/var/log/compiler_usage.log"

# Check if user is root or in compiler_users group
if [ "$(id -u)" -eq 0 ] || groups | grep -qw "compiler_users"; then
    # Log the usage
    echo "$(date '+%Y-%m-%d %H:%M:%S') - User: $USER - Command: $COMPILER $*" >> "$LOG_FILE"
    # Execute the real compiler
    "$REAL_COMPILER" "$@"
else
    echo "Error: You do not have permission to use $COMPILER. Contact your system administrator." >&2
    exit 1
fi
EOF
chmod 755 /usr/local/compiler-wrappers/compiler-wrapper.sh
log "Created compiler wrapper script with access checks."

# Replace original compiler locations with wrapper
for COMPILER in $COMPILERS; do
    if [ -f "/usr/bin/$COMPILER.real" ]; then
        ln -sf /usr/local/compiler-wrappers/compiler-wrapper.sh "/usr/bin/$COMPILER"
        chown root:root "/usr/bin/$COMPILER"
        chmod 755 "/usr/bin/$COMPILER"
        log "Linked /usr/bin/$COMPILER to wrapper script."
    fi
done

# Configure audit rules for compiler usage
if [ -d /etc/audit/rules.d ]; then
    cat > /etc/audit/rules.d/compiler.rules <<EOF
-a exit,always -F dir=/usr/bin -F perm=x -F path=/usr/bin/gcc.real -k compiler_usage
-a exit,always -F dir=/usr/bin -F perm=x -F path=/usr/bin/g++.real -k compiler_usage
-a exit,always -F dir=/usr/bin -F perm=x -F path=/usr/bin/cc.real -k compiler_usage
EOF
    auditctl -R /etc/audit/rules.d/compiler.rules || log "Failed to load audit rules."
    log "Configured auditd rules for compiler usage."
fi

# Configure sudo access (optional, if you want sudo for compiler_users)
cat > /etc/sudoers.d/compiler_access <<EOF
%compiler_users ALL=(root) NOPASSWD: /usr/bin/gcc.real
%compiler_users ALL=(root) NOPASSWD: /usr/bin/g++.real
%compiler_users ALL=(root) NOPASSWD: /usr/bin/cc.real
EOF
chmod 440 /etc/sudoers.d/compiler_access
log "Configured sudo access for compiler_users group (optional)."

# Configure log rotation for compiler usage logs
cat > /etc/logrotate.d/compiler_usage <<EOF
/var/log/compiler_usage.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
EOF
log "Configured log rotation for compiler usage logs."

log "Compiler restrictions implemented successfully."

    log "Applying additional sysctl hardening settings..."
    
    # Create a comprehensive sysctl hardening file to avoid duplicates
    cat > /etc/sysctl.d/99-hardening.conf << EOF
# Network security settings
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_no_pmtu_disc = 0
EOF

   
    if modprobe -q tcp_bbr 2>/dev/null && printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.d/99-hardening.conf
    fi
    
    # Apply all sysctl settings once
    log "Applying all sysctl settings from all configuration files..."
    sysctl --system



        echo "Configuring GRUB password..."

            hashed_password=$(echo -e "$GRUB_PSSWD\n$GRUB_PSSWD" | grub-mkpasswd-pbkdf2 | awk '/PBKDF2 hash of your password is/ {print $NF}')
            
            if [ -z "$hashed_password" ]; then
                echo "Error: Could not generate PBKDF2 hash for GRUB password. Ensure grub-mkpasswd-pbkdf2 output is correct."
                exit 1
            fi

            cp /etc/grub.d/40_custom /etc/grub.d/40_custom.bak

       
            sed -i '/set superusers/d' /etc/grub.d/40_custom
            sed -i '/password_pbkdf2/d' /etc/grub.d/40_custom

            bash -c "cat > /etc/grub.d/40_custom" <<EOF
#!/bin/sh
exec tail -n +3 \$0
# Custom GRUB password protection

set superusers="root"
password_pbkdf2 root ${hashed_password}
EOF

   
            chmod +x /etc/grub.d/40_custom

            sed -i "/\$os/s/grub_quote)'/grub_quote)' --unrestricted/" /etc/grub.d/10_linux


            # Create a backup of grub config before modifying
            cp /etc/default/grub /etc/default/grub.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null
            
            # Use a more reliable approach to update GRUB configuration
            # First, remove old settings to avoid duplicates
            sed -i '/GRUB_DEFAULT=/d; /GRUB_TIMEOUT=/d; /GRUB_TIMEOUT_STYLE=/d' /etc/default/grub
            
            # Now add the new clean settings at the beginning of the file
            # Add as separate commands to avoid mistakes with quotes and backticks
            grep -q "^GRUB_DEFAULT=" /etc/default/grub || echo "GRUB_DEFAULT=0" >> /etc/default/grub
            grep -q "^GRUB_TIMEOUT=" /etc/default/grub || echo "GRUB_TIMEOUT=5" >> /etc/default/grub
            grep -q "^GRUB_TIMEOUT_STYLE=" /etc/default/grub || echo "GRUB_TIMEOUT_STYLE=menu" >> /etc/default/grub

        
            update-grub
            if [ $? -ne 0 ]; then
                echo "Warning: Failed to update GRUB configuration. Check /etc/grub.d/40_custom and grub config for errors."
            else
                echo "GRUB password set and GRUB configuration updated."
            fi

        syslog-ng_config
     
        echo "Running debsums re-baseline..."
    CHANGED_FILES=$(debsums --all --changed | awk '{print $1}')

    for file in $CHANGED_FILES; do
        if [ -f "$file" ]; then
            echo "Re-baselining checksum for $file"
            md5sum "$file" >> /var/lib/debsums/local.md5
        else
            echo "File $file does not exist; skipping..."
        fi
    done

    echo "Re-baselining completed. Verifying changes..."
    debsums --all --changed || echo "All files are compliant with the new baseline."

    log "Installing and configuring Auditd..."
    if ! dpkg-query -W auditd audispd-plugins >/dev/null 2>&1; then
        apt-get install -y auditd audispd-plugins || error_exit "Failed to install Auditd."
    fi

    log "Starting Auditd service..."
if systemctl status auditd >/dev/null 2>&1; then
   systemctl enable auditd || log "Failed to enable Auditd service."
   systemctl start auditd || log "Failed to start Auditd service."

    log "Configuring basic Auditd rules..."
    mkdir -p /etc/audit/rules.d
    cat <<EOF > /etc/audit/rules.d/99-default.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
EOF
   augenrules --load
   systemctl restart auditd || log "Failed to restart Auditd service after applying rules."
else
   log "Auditd service is not available. Skipping further configuration."
fi
log "System hardening completed."

}

enable_unattended_security_updates() {
    log "Enabling unattended security updates..."

  
    apt-get update
    apt-get install -y unattended-upgrades

    dpkg-reconfigure -fnoninteractive unattended-upgrades

    sed -i '/^Unattended-Upgrade::Allowed-Origins {/a \
        "${distro_id}:${distro_codename}-security";' /etc/apt/apt.conf.d/50unattended-upgrades

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
    APT::Periodic::Update-Package-Lists "1";
    APT::Periodic::Unattended-Upgrade "1";
EOF

    systemctl enable --now unattended-upgrades

    log "Running unattended-upgrades dry-run for validation..."
    unattended-upgrades --debug --dry-run

 
    if systemctl is-active --quiet unattended-upgrades; then
        log "Unattended-upgrades service is running."
    else
        log "Unattended-upgrades service is NOT running. Check the configuration."
    fi

    log "Unattended security updates enabled."
}




ssh_keycheck() {
    log "Checking for existing SSH keys..."
    KEY_INSTALLED="false"
    if [ -f "/root/.ssh/authorized_keys" ] && [ -s "/root/.ssh/authorized_keys" ]; then
        KEY_INSTALLED="true"
    else
        for user_home in /home/*; do
            if [ -d "$user_home" ] && [ -f "$user_home/.ssh/authorized_keys" ] && [ -s "$user_home/.ssh/authorized_keys" ]; then
                KEY_INSTALLED="true"
                break
            fi
        done
    fi
}

update_progress() {
    local progress="$1"
    local message="$2"
    echo "$progress" > /tmp/install_progress
    echo "$message" > /tmp/install_message
}

loading_screen() {
    local pid=$1
    local progress_file="/tmp/install_progress"
    local message_file="/tmp/install_message"

    echo "0" >"$progress_file"
    echo "Starting installation..." >"$message_file"

    dialog --title "Installing Advantive Access Gateway" \
        --gauge "Starting installation..." 10 70 0 < <(
            while kill -0 "$pid" 2>/dev/null; do
                progress=$(cat "$progress_file" 2>/dev/null || echo "0")
                message=$(cat "$message_file" 2>/dev/null || echo "Working...")
                echo "$progress"
                echo "XXX"
                echo "$message"
                echo "XXX"
                sleep 1
            done
            echo 100
        )
}

help() {
    echo "Advantive Access Gateway Installation & Management Script"
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  -install                Install StrongSwan Gateway with interactive mode" 
    echo "  -debug                  Display debug information and logs"
    echo "  -write-okta-config      Write Okta IKEv2 configuration files"
    echo "  -write-okta-gtc         Write Okta IKEv2 configuration for GTC authentication"    
    echo "  -check-comp             Check and compile required kernel modules"
    echo "  -export-cert            Export certificates as PKCS#12 bundle"
    echo "  -update                 Update StrongSwan installation"
    echo "  -harden                 Apply system hardening"
    echo "  -setup-nftables         Configure nftables firewall"
    echo "  -syslog-ng              Install and configure syslog-ng"
    echo "  -vault                  Install and configure HashiCorp Vault"
    echo "  -install-suricata       Install and configure Suricata IDS"
    echo "  -set-permissions        Set permissions on system files"
    echo ""
}


install() {
    LOG_FILE="/var/log/strongconn.log"  

    update_progress 0 "Starting installation..." 
    log "Starting installation..." >> "$LOG_FILE" 2>&1

    update_progress 5 "Checking prerequisites..." 
    log "Checking for ipcalc..." >> "$LOG_FILE" 2>&1
    if ! command -v ipcalc &>/dev/null; then
        log "ipcalc not found, installing it..." >> "$LOG_FILE" 2>&1
        apt-get update -y >> "$LOG_FILE" 2>&1
        apt-get install -y ipcalc >> "$LOG_FILE" 2>&1 || error_exit "Failed to install ipcalc"
    else
        log "ipcalc found." >> "$LOG_FILE" 2>&1
    fi

    CONFIG_PATH="/etc/strongconn.conf"
    if [ ! -f "$CONFIG_PATH" ]; then
        update_progress 8 "Creating configuration file..."
        log "Configuration file not found. Creating default configuration file..." >> "$LOG_FILE" 2>&1
        cp ./strongconn.conf "$CONFIG_PATH" >> "$LOG_FILE" 2>&1 || error_exit "Failed to copy config to /etc"
        chmod 640 "$CONFIG_PATH" >> "$LOG_FILE" 2>&1 || error_exit "Failed to set permissions on config"
    fi

    update_progress 10 "Setting up directories..." 
    log "Configuration updated. Current settings:" >> "$LOG_FILE" 2>&1
    cat "$CONFIG_PATH" >> "$LOG_FILE" 2>&1
    mkdir -p /var/lib/strongswan >> "$LOG_FILE" 2>&1 || error_exit "Failed to create directory /var/lib/strongswan"

    SCRIPT_SOURCE="${BASH_SOURCE[0]}"
    while [ -h "$SCRIPT_SOURCE" ]; do
        DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
        SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
        [[ $SCRIPT_SOURCE != /* ]] && SCRIPT_SOURCE="$DIR/$SCRIPT_SOURCE"
    done

    SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
    cd "$SCRIPT_DIR" >> "$LOG_FILE" 2>&1 || error_exit "Failed to navigate to script directory: $SCRIPT_DIR"
    update_progress 5 "Checking enviroenment..."
    detect_vps_environment >> "$LOG_FILE" 2>&1
    if [ "$IS_VPS_ENVIRONMENT" == "true" ]; then
        update_progress 8 "VPS environment detected." 
    else
        update_progress 8 "Non-VPS environment detected." 
    fi
    update_progress 10 "Running system checks..." 
    log "StrongSwan IKEv2 VPN Gateway Installing..." >> "$LOG_FILE" 2>&1
    check_root >> "$LOG_FILE" 2>&1
    sleep 5
    update_progress 12 "Checking OS and DNS resolution..." 
    check_os >> "$LOG_FILE" 2>&1
    configure_dns >> "$LOG_FILE" 2>&1
    sleep 5
    update_progress 15 "Checking network interfaces..." 
    check_network >> "$LOG_FILE" 2>&1
    check_dns_resolution >> "$LOG_FILE" 2>&1
    sleep 5
    update_progress 20 "Checking kernel modules and loading on boot..."  
    check_and_compile_modules >> "$LOG_FILE" 2>&1
    update_progress 22 "Checking StrongSwan group..." 
    check_strongswan_group >> "$LOG_FILE" 2>&1
    sleep 5
    update_progress 23 "Checking Charon socket permissions..." 
    sleep 5
    check_charon_socket_permissions >> "$LOG_FILE" 2>&1
    update_progress 25 "Installing dependencies & tools..." 
    sleep 10 
    update_progress 30 "Installing dependencies & tools..."
    install_dependencies >> "$LOG_FILE" 2>&1
    update_progress 35 "Compiling StrongSwan..." 
    sleep 10
    update_progress 40 "Compiling StrongSwan..."
    sleep 10
    update_progress 44 "Compiling StrongSwan..."
    compile_strongswan >> "$LOG_FILE" 2>&1
    update_progress 50 "Copying files..."
    sleep 3 
    install_helper >> "$LOG_FILE" 2>&1
    update_progress 55 "Downloading Hashi Corp Vault..."
    sleep 5
    update_progress 57 "Installing & Initializing Vault" 
    sleep 2  
    update_progress 60 "Setting up PKI & Generating Certificates..."  
    configure_vault >> "$LOG_FILE" 2>&1
    sleep 2
    update_progress 62 "Generating server CN= $PUBLIC_IP certificate..." 
    install_nginx >> "$LOG_FILE" 2>&1
    sleep 2
    update_progress 57 "Generating CA..." 
    sleep 2
    update_progress 65 "Configuring nftables & swanctl..." 
    setup_firewalld >> "$LOG_FILE" 2>&1
    configure_swanctl >> "$LOG_FILE" 2>&1
    inject_Banner >> "$LOG_FILE" 2>&1
    sleep 2
    update_progress 67 "Starting Strongswan..." 
    start_vpn >> "$LOG_FILE" 2>&1
    update_progress 68 "Configuring Syslog-ng..." 
    sleep 5
    update_progress 70 "Installing script components..." 
    cd "$SCRIPT_DIR" >> "$LOG_FILE" 2>&1 || error_exit "Failed to return to script directory"
    
    scripts=("tunnel.sh" "ztna.sh" "adv-ha.sh" "debug.sh" "tunnel-watchdog.sh" "ztna-pki.sh")
    for script in "${scripts[@]}"; do
        src_path="$SCRIPT_DIR/_scripts/$script"
        dest_path="/usr/bin/$script"
        cp "$src_path" "$dest_path" >> "$LOG_FILE" 2>&1 || error_exit "Failed to copy '$script' to /usr/bin/."
        chmod +x "$dest_path" >> "$LOG_FILE" 2>&1 || error_exit "Failed to set execute permission on '$dest_path'."
        log "Successfully installed '$script' to /usr/bin/." >> "$LOG_FILE" 2>&1
    done
    echo $SCRIPT_DIR >> "$LOG_FILE" 2>&1
    cp $SCRIPT_DIR/strongconn.sh /usr/bin/strongconn.sh >> "$LOG_FILE" 2>&1
    chmod +x /usr/bin/strongconn.sh >> "$LOG_FILE" 2>&1
    chmod +x /usr/bin/debug.sh >> "$LOG_FILE" 2>&1
    chmod +x /usr/bin/tunnel.sh >> "$LOG_FILE" 2>&1
    chmod +x /usr/bin/ztna.sh >> "$LOG_FILE" 2>&1
    chmod +x /usr/bin/adv-ha.sh >> "$LOG_FILE" 2>&1
    update_progress 72 "Configuring crontab entries..."
    sleep 5
    # Create a temporary file for crontab entries
    TEMP_CRON=$(mktemp) >> "$LOG_FILE" 2>&1
    # Export existing crontab
    crontab -l 2>/dev/null > "$TEMP_CRON" || true >> "$LOG_FILE" 2>&1
    # Add new entries if they don't exist
    grep -q "@reboot /usr/bin/debug.sh" "$TEMP_CRON" || echo "@reboot /usr/bin/debug.sh" >> "$TEMP_CRON" >> "$LOG_FILE" 2>&1
    grep -q "0 0 \*/3 \* \* /usr/bin/debug.sh" "$TEMP_CRON" || echo "0 0 */3 * * /usr/bin/debug.sh" >> "$TEMP_CRON" >> "$LOG_FILE" 2>&1
    # Install new crontab
    crontab "$TEMP_CRON" >> "$LOG_FILE" 2>&1
    # Clean up
    rm -f "$TEMP_CRON" >> "$LOG_FILE" 2>&1
    update_progress 75 "Installing Suricata IDS..."
    if [ "$IS_VPS_ENVIRONMENT" = "true" ]; then
        log "Detected VPS environment, installing VPS-optimized Suricata..."
        install_suricata >> "$LOG_FILE" 2>&1
    else
        log "Lan environment detected, installing Gateway-optimized Suricata..."
        install_suricata >> "$LOG_FILE" 2>&1
    fi
    set_permissions >> "$LOG_FILE" 2>&1
    sleep 10
    update_progress 80 "Installing Python Script... "
    sleep 2
    update_progress 85 "Configuring Suricata IDS "
    sleep 3
    update_progress 88 "Updating Suricata IDS"
    updatedb >> "$LOG_FILE" 2>&1 || error_exit "Failed to update locate database."
    setup_postfix >> "$LOG_FILE" 2>&1
    update_progress 90 "Configuring Postfix..."
    sleep 5
    update_progress 92 "Configuring debsums for custom configuration files..."
    sleep 5
    update_progress 95 "Hardening system, enabling unattended security updates..." 
    harden-system >> "$LOG_FILE" 2>&1
    update_progress 98 "Enabling unattended security updates..." 
    enable_unattended_security_updates >> "$LOG_FILE" 2>&1
    set_permissions >> "$LOG_FILE" 2>&1
    sleep 10
    update_progress 99 "Installation complete! \
    "
    apt-get autoremove -y >> "$LOG_FILE" 2>&1
        update_progress 100 "Install complete. Press Enter to reboot... \
        you can view installaton logs at /var/log/strongconn.log \
        "
        log "Installation complete" >> "$LOG_FILE" 2>&1
        dialog --msgbox "Installation complete! Press Enter to reboot..." 8 50
        dialog --clear
        reboot
}
 


#====================================================================================================================================================================
#END
#====================================================================================================================================================================




case "$1" in

    -install)

        load_config
        # Install dialog if not present
        if ! command -v dialog >/dev/null 2>&1; then
            log "Installing dialog..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y && apt-get install -y dialog || {
                log "ERROR: Failed to install dialog"
                exit 1
            }
        fi
        apt-get install curl -y
        # Initial VPN mode selection
        VPN_MODE=$(dialog --backtitle "Advantive Ipsec Gateway Setup" \
            --title "VPN Routing Selection" \
            --menu "Choose Access Gateway Route operating mode:" 15 70 3 \
            1 "NAT Mode - Client IP masquerading private pool" \
            2 "Routed Mode - ZNTA/Boundary or private pool & return routes" \
            3 "DHCP Mode - Local lan ARP & DHCP proxy to clients" 2>&1 >/dev/tty)

        [ -z "$VPN_MODE" ] && { log "No VPN mode selected"; exit 1; }
        case $VPN_MODE in
            1) VPN_MODE="NAT" ;;
            2) VPN_MODE="ROUTED" ;;
            3) VPN_MODE="DHCP" ;;
            *) log "Invalid VPN mode"; exit 1 ;;
        esac
        autopopulate_config


        echo "VPN_MODE=$VPN_MODE" >> "$CONFIG_PATH"

        autopopulate_config
        PUBLIC_IP=$(get_public_ip)
        if [ $? -eq 0 ]; then
            echo "Got public IP: $PUBLIC_IP"
        else
            echo "Failed to get IP"
        fi
        while true; do
            temp_file=$(mktemp)
            dialog --backtitle "Advantive Access Gateway Setup" \
                --title "Configuration Variables;" \
                --form "Edit Settings(comma-separated for multiple values):" 20 80 13 \
                "Interface:" 1 1 "$DEFAULT_INTERFACE" 1 25 50 0 \
                "Local IP:" 2 1 "$DEFAULT_IP" 2 25 50 0 \
                "Gateway:" 3 1 "$DEFAULT_GATEWAY" 3 25 50 0 \
                "Public IP:" 4 1 "$PUBLIC_IP" 4 25 50 0 \
                "DNS Servers:" 5 1 "$DNS_SERVERS" 5 25 50 0 \
                "IP Pool:" 6 1 "$IP_POOL" 6 25 50 0 \
                "IP Range:" 7 1 "$IP_RANGE" 7 25 50 0 \
                "Route Subnets:" 8 1 "$ROUTE_SUBNETS" 8 25 50 0 \
                "DNS Name:" 9 1 "$DNS_NAME" 9 25 50 0 \
                "RADIUS Secret:" 10 1 "$RADIUS_SECRET" 10 25 50 0 \
                "RADIUS Secret 2:" 11 1 "$RADIUS_SECRET2" 11 25 50 0 \
                "RADIUS Port:" 12 1 "$RADIUS_PORT" 12 25 50 0 \
                "RADIUS Port 2:" 13 1 "$RADIUS_PORT2" 13 25 50 0 \
                "Syslog Server IP:" 14 1 "$ARCTICWOLF_IP" 14 25 50 0 \
                "Search Domain:" 15 1 "$S_DOMAIN" 15 25 50 0 \
                "Report Email:" 16 1 "$REPORT_EMAIL" 16 25 50 0 \
                2> "$temp_file"

            [ $? -ne 0 ] && { rm "$temp_file"; break; }

            mapfile -t values < "$temp_file"
            DEFAULT_INTERFACE=$(trim_value "${values[0]}")
            DEFAULT_IP=$(trim_value "${values[1]}")
            DEFAULT_GATEWAY=$(trim_value "${values[2]}")
            PUBLIC_IP=$(trim_value "${values[3]}")
            DNS_SERVERS=$(trim_value "${values[4]}")
            IP_POOL=$(trim_value "${values[5]}")
            IP_RANGE=$(trim_value "${values[6]}")
            ROUTE_SUBNETS=$(trim_value "${values[7]}")
            DNS_NAME=$(trim_value "${values[8]}")
            RADIUS_SECRET=$(trim_value "${values[9]}")
            RADIUS_SECRET2=$(trim_value "${values[10]}")
            RADIUS_PORT=$(trim_value "${values[11]}")
            RADIUS_PORT2=$(trim_value "${values[12]}")
            ARCTICWOLF_IP=$(trim_value "${values[13]}")
            S_DOMAIN=$(trim_value "${values[14]}")
            REPORT_EMAIL=$(trim_value "${values[15]}")
            rm "$temp_file"

            errors=""
            validate_ip "$DEFAULT_IP" || errors="$errors- Invalid Local IP\n"
            validate_ip "$DEFAULT_GATEWAY" || errors="$errors- Invalid Gateway\n"
            validate_ip "$PUBLIC_IP" || errors="$errors- Invalid Public IP\n"
            for subnet in ${ROUTE_SUBNETS//,/ }; do
                validate_cidr "$subnet" || errors="$errors- Invalid subnet: $subnet\n"
            done
            validate_cidr "$IP_POOL" || errors="$errors- Invalid IP Pool\n"
            [ -z "$DEFAULT_INTERFACE" ] && errors="$errors- Interface required\n"
            [ -z "$DNS_NAME" ] && errors="$errors- DNS Name required\n"
            [ -z "$RADIUS_SECRET" ] && errors="$errors- RADIUS Secret required\n"

            if [ -n "$errors" ]; then
                dialog --msgbox "Errors:\n$errors" 15 60
                continue
            fi
            break
        done

        # Second Dialog: CA and Certificate Settings
        while true; do
            temp_file=$(mktemp)
            dialog --backtitle "Advantive Access Gateway Setup" \
                --title "Vault PKI Setup" \
                --form "Edit CA/Certificate Settings:" 15 80 7 \
                "Country (2-letter):" 1 1 "$COUNTRY" 1 25 50 0 \
                "State:" 2 1 "$STATE" 2 25 50 0 \
                "City:" 3 1 "$CITY" 3 25 50 0 \
                "Organization:" 4 1 "$ORGANIZATION" 4 25 50 0 \
                "Org Unit:" 5 1 "$ORG_UNIT" 5 25 50 0 \
                "CA Name:" 6 1 "$CA_NAME" 6 25 50 0 \
                "Cert Password:" 7 1 "$PFX_PASSWORD" 7 25 50 0 \
                2> "$temp_file"

            [ $? -ne 0 ] && { rm "$temp_file"; break; }

            mapfile -t values < "$temp_file"
            COUNTRY=$(trim_value "${values[0]}")
            STATE=$(trim_value "${values[1]}")
            CITY=$(trim_value "${values[2]}")
            ORGANIZATION=$(trim_value "${values[3]}")
            ORG_UNIT=$(trim_value "${values[4]}")
            CA_NAME=$(trim_value "${values[5]}")
            PFX_PASSWORD=$(trim_value "${values[6]}")
            rm "$temp_file"

            errors=""
            [ ${#COUNTRY} -ne 2 ] && errors="$errors- Country must be 2 letters\n"
            [ -z "$STATE" ] && errors="$errors- State required\n"
            [ -z "$CITY" ] && errors="$errors- City required\n"
            [ -z "$ORGANIZATION" ] && errors="$errors- Organization required\n"
            [ -z "$ORG_UNIT" ] && errors="$errors- Org Unit required\n"
            [ -z "$CA_NAME" ] && errors="$errors- CA Name required\n"
            [ -z "$PFX_PASSWORD" ] && errors="$errors- Cert Password required\n"

            if [ -n "$errors" ]; then
                dialog --msgbox "Errors:\n$errors" 15 60
                continue
            fi
            break
        done


        update_config

        # Final confirmation
        dialog --yesno "Proceed with Installation?\n$(cat "$CONFIG_PATH")" 20 70
        [ $? -ne 0 ] && exit 1

        log "Installation proceeding with config: $(cat "$CONFIG_PATH")"

            
        # Confirmation dialog to start installation
        dialog --backtitle "Advantive Access Gateway Setup" \
            --yesno "Configuration validated. Start Installation?" 8 50
        
        # Check dialog exit status - 0 is Yes, 1 is No
        dialog_status=$?
        if [ $dialog_status -ne 0 ]; then
            log "Installation canceled by user"
            dialog --backtitle "Advantive VPN Gateway Setup" \
                --msgbox "Installation canceled." 8 50
            exit 0
        fi

        # Check if SSH key is installed
        ssh_keycheck
        if [ "$KEY_INSTALLED" != "true" ]; then
            dialog --backtitle "Advantive VPN Gateway Setup" \
                --msgbox "No SSH keys found. Please install an SSH key before continuing." 8 50

            error_exit "No SSH keys found. Please install an SSH key before continuing."
        fi
       
        LOG_FILE="/var/log/strongconn.log"
        {
            install >"$LOG_FILE" 
        } &
        installer_pid=$!
        loading_screen $installer_pid
        wait $installer_pid
        
        # Check installation result
        if [ $? -eq 0 ]; then
            dialog --backtitle "Advantive VPN Gateway Setup" \
                --msgbox "Installation completed successfully!" 8 50
        else
            dialog --backtitle "Advantive VPN Gateway Setup" \
                --msgbox "Installation Failed. Check /var/log/strongconn.log for details." 8 50
        fi
        ;;
    -debug)
        debug_strongswan
        ;;
    -write-okta-config)
        read -p "Are you sure you want to write Okta ipsec config? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Writing Okta config aborted."
            exit 0
        fi
        log "Writing Okta config..."
        load_and_export_config
        write_okta_config
        write_okta_profile
        ;;
    -write-okta-gtc)
        read -p "Are you sure you want to write Okta eap-gtc config? (y/n): " confirm
         if [[ "$confirm" != "y" ]]; then
            log "Writing Okta config aborted."
            exit 0
        fi
        load_and_export_config
        write_eap_gtc
        ;;
    -check-comp)
        check_and_compile_modules
            log "Module check and compile (if necessary)"
            log "..."
        ;;
    -kernel_updates)
        log "Setting kernel update option from conf"
        kernel-updates
        ;;
    -export-cert)
        load_and_export_config
        export_cert_to_p12_tar
        ;;
    -update)
        read -p "DO NOT RUN WITH SUDO! (sudo su) first Proceed to Update StrongSwan? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Update Aborted."
            exit 0
        fi
            if [ -f /usr/local/bin/swanctl ] || [ -f /usr/sbin/swanctl ]; then
        log "StrongSwan with swanctl is already installed."
        cd /usr/src/ || exit
        ls -lah
        log  "stop strongswan service & go to the source directory (i.e., /usr/src/strongswanVERSION) and run 'make uninstall' then run upgrade again." 
        exit 1
      
        else
        load_and_export_config
        log "StrongSwan with swanctl is not installed. proceeding with compile....." |
        backup_config || error_exit "Failed to back up StrongSwan configuration......"
        log "StrongSwan config backup complete."
        log "Invoking Compile Function..."
        compile_strongswan || error_exit "Failed to compile StrongSwan."
        log "StrongSwan installation complete.........."
        check_charon_socket_permissions        
        restore_config || error_exit "Failed to restore StrongSwan configuration."
        log "StrongSwan config back up restored complete........."
        start_vpn
        fi
        ;;
    -install-boundary)
        read -p "Are you sure you want to install Boundary? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Installation Aborted."
            exit 0
        fi
        load_and_export_config
        install_boundary
        ;;
    -harden)
        read -p "Are you sure you want to harden the system? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Hardening Aborted."
            exit 0
        fi
        load_and_export_config
        harden-system
        ;;
    -setup-nftables)
        read -p "Are you sure you want to setup nft"

        apt-get remove firewalld -y
        apt-get install nftables -y
        setup_firewalld 
        ;;
    -syslog-ng)
        read -p "install syslog-ng? (y/n):" confirm
        if [[ "$confirm" != "y" ]]; then
            log "aborted syslog-ng"
            exit 0
        fi
        load_and_export_config
        syslog-ng_config
        ;;
    -vault)
        read -p "Are you sure you want to install Vault? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Installation Aborted."
            exit 0
        fi
        load_and_export_config
        configure_vault
        install_nginx
        ;;
    -set-permissions)
        set_permissions
        ;; 
    -install-suricata)
        read -p "Are you sure you want to install Suricata? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            log "Installation Aborted."
            exit 0
        fi
        load_and_export_config
        install_suricata
        log "Installing suricata, updating firewall and installing suricata watchdog service"
        ;;        
     *)   
      
        help
        exit 1
        ;;
esac
log "------------------------------------------------------------------------------------"
log     "\o/.-.-.-.-.-.-.-.-.-.\o/\o/.-.-.-.-.-.-.-.-.-.\o/\o/.-.-.-.-.-.-.-.-.-.\o/"
log "------------------------------------------------------------------------------------"