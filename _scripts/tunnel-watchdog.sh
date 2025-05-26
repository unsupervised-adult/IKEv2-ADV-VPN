#!/bin/bash
#
# StrongSwan IKEv2 Tunnel Watchdog
# 
# This script monitors site-to-site VPN tunnels created by tunnel.sh
# and ensures they remain operational by:
#  - Checking if tunnel interfaces are up
#  - Verifying traffic can pass through the tunnel
#  - Automatically restarting tunnels that are down or half-open
#
# Author: Felix C Frank
# Version: 1.0
# Created: April 2025
#
# Usage: 
#   ./tunnel-watchdog.sh [--config /path/to/config] [--verbose] [--interval 60]
#   or run as a systemd service

set -e

CONFIG_PATH="/etc/strongconn.conf"
VERBOSE=false
CHECK_INTERVAL=60 # seconds between checks
PING_COUNT=3
PING_TIMEOUT=2
MAX_RESTART_ATTEMPTS=3
RESTART_COOLDOWN=30 # seconds to wait after restart before checking again
LOG_FILE="/var/log/tunnel-watchdog.log"
LOCK_FILE="/var/run/tunnel-watchdog.lock"
TUNNEL_CONF_DIR="/etc/swanctl/conf.d"
TUNNEL_PREFIX="site-2site-"
SYSTEMD_SVC_PREFIX="strongswan-client-"

# Process command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG_PATH="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --interval)
            CHECK_INTERVAL="$2"
            shift 2
            ;;
        --help|-h)
            echo "🛠️  StrongSwan IKEv2 Tunnel Watchdog"
            echo
            echo "Usage: $0 [--config /path/to/config] [--verbose] [--interval seconds]"
            echo
            echo "Options:"
            echo "  --config     Path to strongconn.conf (default: /etc/strongconn.conf)"
            echo "  --verbose    Enable verbose logging"
            echo "  --interval   Seconds between checks (default: 60)"
            echo
            echo "Example:"
            echo "  $0 --verbose --interval 30"
            exit 0
            ;;
        *)
            echo "❌ Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Ensure we're running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Create the log file if it doesn't exist
if [ ! -f "$LOG_FILE" ]; then
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
fi

# Load configuration
if [ ! -f "$CONFIG_PATH" ]; then
    echo "Configuration file not found: $CONFIG_PATH" | tee -a "$LOG_FILE"
    exit 1
fi

source "$CONFIG_PATH"

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local emoji=""
    
    # Add fun emojis based on log level
    case "$level" in
        "INFO")  emoji="ℹ️ ";;
        "WARN")  emoji="⚠️ ";;
        "ERROR") emoji="🛑 ";;
        "DEBUG") emoji="🔍 ";;
        *)       emoji="💬 ";;
    esac
    
    if [[ "$level" == "DEBUG" && "$VERBOSE" != "true" ]]; then
        return 0
    fi
    
    echo "[$timestamp] [$level] $emoji $message" >> "$LOG_FILE"
    
    if [[ "$VERBOSE" == "true" || "$level" != "DEBUG" ]]; then
        echo "[$timestamp] [$level] $emoji $message"
    fi
}

acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid=$(cat "$LOCK_FILE")
        if ps -p "$pid" > /dev/null; then
            log "WARN" "🔒 Another instance of tunnel-watchdog is already running (PID: $pid)"
            return 1
        else
            log "WARN" "🗑️ Removing stale lock file for PID $pid"
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $ > "$LOCK_FILE"
    return 0
}

release_lock() {
    if [ -f "$LOCK_FILE" ] && [ "$(cat $LOCK_FILE)" == "$$" ]; then
        rm -f "$LOCK_FILE"
    fi
}

# Clean up when the script exits
cleanup() {
    log "INFO" "🛑 Watchdog shutting down"
    release_lock
    exit 0
}

trap cleanup EXIT INT TERM

# Discover active tunnels configured with tunnel.sh
discover_tunnels() {
    local tunnels=()
    
    log "DEBUG" "🔎 Searching for tunnel configurations in $TUNNEL_CONF_DIR"
    for conf_file in "$TUNNEL_CONF_DIR"/${TUNNEL_PREFIX}*.conf; do
        if [ -f "$conf_file" ]; then
            local tunnel_name=$(basename "$conf_file" | sed "s/^$TUNNEL_PREFIX//;s/\.conf$//")
            tunnels+=("$tunnel_name")
            log "DEBUG" "🔗 Found tunnel: $tunnel_name"
        fi
    done
    
    echo "${tunnels[@]}"
}

# Check if a tunnel's interface is up
is_interface_up() {
    local tunnel_name="$1"
    local interface="xfrm-${tunnel_name}"
    
    if ip link show "$interface" &>/dev/null; then
        local state=$(ip link show "$interface" | grep -oP 'state \K\w+')
        if [ "$state" == "UP" ]; then
            log "DEBUG" "🟢 Interface $interface is UP"
            return 0
        else
            log "DEBUG" "🔴 Interface $interface exists but state is $state"
        fi
    else
        log "DEBUG" "❓ Interface $interface does not exist"
    fi
    
    return 1
}

# Check if we can ping through the tunnel
can_ping_through_tunnel() {
    local tunnel_name="$1"
    local test_ips=()
    
    # Find the initiator config for this tunnel
    local initiator_id=""
    log "DEBUG" "🔎 Looking for initiator config files for tunnel $tunnel_name"
    for init_file in /var/lib/strongswan/initiator-*.conf; do
        if grep -q "REMOTE_SUBNET" "$init_file"; then
            # Extract remote subnets
            local remote_subnets=$(grep "REMOTE_SUBNET" "$init_file" | cut -d= -f2)
            if [ -n "$remote_subnets" ]; then
                log "DEBUG" "📡 Found remote subnets: $remote_subnets"
                # For each subnet, try to extract a pingable IP
                IFS=',' read -ra subnet_array <<< "$remote_subnets"
                for subnet in "${subnet_array[@]}"; do
                    # Try to get the first usable IP from the subnet (simple heuristic)
                    # This works for common subnet sizes but isn't foolproof
                    local base_ip=$(echo "$subnet" | cut -d/ -f1)
                    local last_octet=$(echo "$base_ip" | cut -d. -f4)
                    
                    if [ "$last_octet" == "0" ]; then
                        # If the subnet ends in .0, try .1 as gateway
                        local test_ip=$(echo "$base_ip" | sed 's/\.[0-9]*$/.1/')
                        test_ips+=("$test_ip")
                        log "DEBUG" "💡 Using $test_ip as test IP (gateway)"
                    else
                        # Otherwise use the network address
                        test_ips+=("$base_ip")
                        log "DEBUG" "💡 Using $base_ip as test IP (network)"
                    fi
                done
            fi
        fi
    done
    
    # If we couldn't find IPs from config, use the REMOTE_IP
    if [ ${#test_ips[@]} -eq 0 ]; then
        log "DEBUG" "⚠️ No subnet-based IPs found, falling back to REMOTE_IP"
        for init_file in /var/lib/strongswan/initiator-*.conf; do
            if grep -q "REMOTE_IP" "$init_file"; then
                local remote_ip=$(grep "REMOTE_IP" "$init_file" | cut -d= -f2)
                if [ -n "$remote_ip" ]; then
                    test_ips+=("$remote_ip")
                    log "DEBUG" "💡 Using remote gateway IP: $remote_ip"
                fi
            fi
        done
    fi
    
    log "DEBUG" "🎯 Will try to ping these IPs for tunnel $tunnel_name: ${test_ips[*]}"
    
    # Try to ping each IP
    for ip in "${test_ips[@]}"; do
        log "DEBUG" "🔄 Testing connectivity to $ip through tunnel $tunnel_name"
        if ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -I "xfrm-${tunnel_name}" "$ip" &>/dev/null; then
            log "DEBUG" "✅ Successfully pinged $ip through tunnel $tunnel_name"
            return 0
        else
            log "DEBUG" "❌ Failed to ping $ip through tunnel $tunnel_name"
        fi
    done
    
    log "DEBUG" "🚫 Failed to ping any targets through tunnel $tunnel_name"
    return 1
}

# Check the status of a strongSwan connection
check_sa_status() {
    local tunnel_name="$1"
    local conn_name="site_to_site_${tunnel_name}"
    
    if sudo swanctl --list-sas | grep -q "$conn_name"; then
        log "DEBUG" "🔒 Found active SA for $conn_name"
        return 0
    fi
    
    log "DEBUG" "🔓 No active SA found for $conn_name"
    return 1
}

# Restart a tunnel
restart_tunnel() {
    local tunnel_name="$1"
    local service_name="${SYSTEMD_SVC_PREFIX}${tunnel_name}"
    local conn_name="site_to_site_${tunnel_name}"
    
    log "INFO" "🔄 Restarting tunnel $tunnel_name..."
    
    # Use sudo for privileged operations
    if sudo swanctl --list-sas | grep -q "$conn_name"; then
        log "DEBUG" "🔽 Terminating existing IKE SA for $conn_name"
        sudo swanctl --terminate --ike "$conn_name" &>/dev/null || true
        sleep 2
    fi
    
    # Check if the systemd service exists
    if systemctl list-unit-files | grep -q "$service_name"; then
        log "DEBUG" "🔄 Restarting systemd service $service_name"
        sudo systemctl restart "$service_name"
    else
        # If no service, try manual initiation
        log "DEBUG" "⚡ No systemd service found, using swanctl for $tunnel_name"
        sudo swanctl --load-all
        sudo swanctl --initiate --child "$tunnel_name" &>/dev/null
    fi
    
    # Wait for the restart to take effect
    log "DEBUG" "⏱️ Waiting $RESTART_COOLDOWN seconds for tunnel restart to complete"
    sleep "$RESTART_COOLDOWN"
}

# Check tunnel health and restart if needed
check_tunnel() {
    local tunnel_name="$1"
    local restart_attempts=0
    
    log "INFO" "🔍 Checking tunnel $tunnel_name"
    
    # First check if SA exists
    if ! check_sa_status "$tunnel_name"; then
        log "WARN" "🚫 Tunnel $tunnel_name has no active SA"
        restart_tunnel "$tunnel_name"
        return
    fi
    
    # Check if interface is up
    if ! is_interface_up "$tunnel_name"; then
        log "WARN" "🔌 Interface xfrm-$tunnel_name is down or missing"
        restart_tunnel "$tunnel_name"
        return
    fi
    
    # Check if we can ping through tunnel
    if ! can_ping_through_tunnel "$tunnel_name"; then
        log "WARN" "🚧 Cannot ping through tunnel $tunnel_name (half-open state)"
        
        # Attempt to recover with multiple restarts if needed
        while (( restart_attempts < MAX_RESTART_ATTEMPTS )); do
            restart_attempts=$((restart_attempts + 1))
            log "INFO" "🔄 Restart attempt $restart_attempts of $MAX_RESTART_ATTEMPTS for tunnel $tunnel_name"
            
            restart_tunnel "$tunnel_name"
            
            # Check if restart fixed the problem
            if is_interface_up "$tunnel_name" && can_ping_through_tunnel "$tunnel_name"; then
                log "INFO" "✅ Tunnel $tunnel_name successfully recovered after restart"
                return
            fi
            
            log "WARN" "⚠️ Tunnel $tunnel_name still not working after restart attempt $restart_attempts"
        done
        
        log "ERROR" "❌ Failed to recover tunnel $tunnel_name after $MAX_RESTART_ATTEMPTS attempts"
        return
    fi
    
    log "INFO" "✅ Tunnel $tunnel_name is healthy"
}

# Main loop
main() {
    log "INFO" "🚀 Starting tunnel watchdog"
    
    while true; do
        if ! acquire_lock; then
            log "ERROR" "🔒 Could not acquire lock file. Exiting."
            exit 1
        fi
        
        tunnels=($(discover_tunnels))
        log "INFO" "📊 Found ${#tunnels[@]} tunnels to monitor: ${tunnels[*]}"
        
        if [ ${#tunnels[@]} -eq 0 ]; then
            log "INFO" "💤 No tunnels to monitor. Will check again in $CHECK_INTERVAL seconds"
        else
            for tunnel in "${tunnels[@]}"; do
                check_tunnel "$tunnel"
            done
        fi
        
        release_lock
        log "DEBUG" "⏱️ Sleeping for $CHECK_INTERVAL seconds"
        sleep "$CHECK_INTERVAL"
    done
}

main