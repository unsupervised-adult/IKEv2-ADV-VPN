#!/bin/bash

# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
# =================================================================================================
#LOG Collector for StrongSwan VPN with ZTNA and Boundary
# This script collects various network, system, and component logs for debugging VPN issues.
# It gathers logs from StrongSwan, Vault, Boundary, ZTNA, and Suricata components.
# It creates an encrypted archive with the collected logs and sends it via email.
# The script requires the 'mail' command to send emails and 'openssl' for encryption.
# The 'pki' tool is used to print certificate details if available.
# The script should be run as root or with sudo privileges.
# Usage: bash debug.sh
# Note: The script requires configuration in /etc/strongconn.conf with REPORT_EMAIL and PFX_PASSWORD.
###############################################################################
# Script: debug.sh
# Author: Felix C Frank 2024
# Version: 1.7.50.2
# Created: 27-12-24
# Updated: 24-03-25
## feedback mailto:felix.c.frank@proton.me
###############################################################################
# Directory and file setup
LOG_DIR=~/logs
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
LOG_FILE="$LOG_DIR/network_debug_$TIMESTAMP.tar.gz"
ENCRYPTED_LOG_FILE="$LOG_DIR/network_debug_$TIMESTAMP.tar.gz.enc"
SUMMARY_FILE="$LOG_DIR/summary_report_$TIMESTAMP.txt"

# Source configuration from /etc/strongconn.conf
if [ -f /etc/strongconn.conf ]; then
    source /etc/strongconn.conf
else
    echo "Error: /etc/strongconn.conf not found."
    exit 1
fi

# Check required variables
[ -z "$REPORT_EMAIL" ] && { echo "Error: REPORT_EMAIL not set in /etc/strongconn.conf."; exit 1; }
[ -z "$PFX_PASSWORD" ] && { echo "Error: PFX_PASSWORD not set in /etc/strongconn.conf."; exit 1; }

# Email settings
EMAIL_SUBJECT="Network Debug Report (Encrypted) - $TIMESTAMP"
# Use postfix MTA installed by strongconn

# Time filters
START_DATE=$(date -d "2 days ago 14:00" +%m/%d/%Y)
LAST_24H=$(date -d "24 hours ago" +"%Y-%m-%d %H:%M:%S")

# Create log directory
mkdir -p "$LOG_DIR" || { echo "Failed to create $LOG_DIR"; exit 1; }

echo "Collecting logs..."

# Function to collect logs
collect_log() {
    local cmd="$1"
    local output_file="$2"
    local desc="$3"
    echo "Collecting $desc..."
    sudo bash -c "$cmd" > "$output_file" 2>/dev/null || echo "Warning: Failed to collect $desc." > "$output_file"
}

# System information
collect_log "uname -a" "$LOG_DIR/system_info.txt" "system information"
collect_log "lsb_release -a" "$LOG_DIR/os_release.txt" "OS release information"
collect_log "uptime" "$LOG_DIR/uptime.txt" "system uptime"

# System resources and performance
collect_log "ps aux --sort=-%cpu" "$LOG_DIR/psstat.txt" "process list"
collect_log "top -b -n 1" "$LOG_DIR/top_output.txt" "top snapshot"
collect_log "free -h" "$LOG_DIR/memory_usage.txt" "memory usage"
collect_log "df -h" "$LOG_DIR/disk_usage.txt" "disk usage"
collect_log "vmstat 1 5" "$LOG_DIR/vmstat.txt" "virtual memory statistics"
collect_log "iostat -x 1 5" "$LOG_DIR/iostat.txt" "IO statistics"
collect_log "systemctl --failed" "$LOG_DIR/failed_services.txt" "failed systemd services"
collect_log "systemctl list-units --type=service --state=running" "$LOG_DIR/running_services.txt" "running services"

# System logs
collect_log "dmesg | grep -iE 'net|route|ipsec|strongswan|xfrm|vault|boundary'" "$LOG_DIR/kernel_network_log.txt" "kernel network logs"
collect_log "journalctl --since '-48 hours'" "$LOG_DIR/journal_48h.txt" "system journal (last 48 hours)"
collect_log "journalctl --since '-48 hours' -p err" "$LOG_DIR/journal_errors_48h.txt" "system journal errors (last 48 hours)"
collect_log "ausearch -i | grep -A 10000 '$START_DATE' 2>/dev/null || echo 'No audit logs found'" "$LOG_DIR/audit_log.txt" "audit logs (last 2 days)"
# Check for traditional logs if they exist
if [ -f /var/log/syslog ]; then
    collect_log "tail -n 1000 /var/log/syslog" "$LOG_DIR/syslog_last_1000.txt" "last 1000 syslog entries"
fi
if [ -f /var/log/auth.log ]; then
    collect_log "tail -n 1000 /var/log/auth.log" "$LOG_DIR/auth_log_last_1000.txt" "last 1000 auth log entries"
fi

# Network configuration and status
collect_log "netstat -rn" "$LOG_DIR/routing_table.txt" "routing table"
collect_log "ip route show" "$LOG_DIR/ip_route.txt" "IP routing table"
collect_log "ip a" "$LOG_DIR/ip_addr.txt" "IP addresses"
collect_log "ip xfrm state" "$LOG_DIR/xfrm_state.txt" "XFRM state table"
collect_log "ip xfrm policy" "$LOG_DIR/xfrm_policy.txt" "XFRM policy table"
collect_log "ip link show" "$LOG_DIR/ip_link.txt" "network interfaces"
collect_log "ss -tuln" "$LOG_DIR/ss_listening.txt" "listening sockets"
collect_log "ss -tan" "$LOG_DIR/ss_tcp_connections.txt" "TCP connections"
collect_log "ss -uan" "$LOG_DIR/ss_udp_connections.txt" "UDP connections"

# StrongSwan logs and current connections
collect_log "journalctl -u strongswan --since '-48 hours'" "$LOG_DIR/strongswan_service_log.txt" "StrongSwan service logs"
collect_log "cat /var/log/charon.log" "$LOG_DIR/charon_log.txt" "StrongSwan charon log"
collect_log "strongconn.sh -debug" "$LOG_DIR/strongswan_status.txt" "StrongSwan debug status"
collect_log "swanctl -l" "$LOG_DIR/swanctl_current_connections.txt" "current StrongSwan VPN connections"
collect_log "swanctl --list-conns" "$LOG_DIR/swanctl_connections.txt" "configured StrongSwan connections"
collect_log "swanctl --list-certs" "$LOG_DIR/swanctl_certificates.txt" "StrongSwan certificates"
collect_log "cat /etc/swanctl/conf.d/* 2>/dev/null" "$LOG_DIR/swanctl_config.txt" "StrongSwan configuration"

# Specific active connections with user emails
collect_log "swanctl -l | grep -A 1 -B 1 '@'" "$LOG_DIR/active_users.txt" "active VPN users with emails"

# Detailed connection analytics
{
    echo "=== VPN CONNECTION ANALYSIS ==="
    echo "Generated: $(date)"
    echo ""
    
    echo "1. ACTIVE CONNECTIONS"
    echo "---------------------"
    swanctl -l | grep -E "remote|local|initiator|responder|established|encr|CHILD_SA|reqid|mode" | sed 's/^[\t ]\+//'
    
    echo ""
    echo "2. CONNECTION STATISTICS (Last 48 Hours)"
    echo "----------------------------------------"
    
    # Total connection attempts and successful connections
    echo "Connection attempts: $(journalctl -u strongswan --since '-48 hours' | grep -c "initiating")"
    echo "Successful connections: $(journalctl -u strongswan --since '-48 hours' | grep -c "IKE_SA.*established")"
    
    # Count failures by type
    echo ""
    echo "3. ERROR ANALYSIS"
    echo "-----------------"
    echo "Authentication failures: $(journalctl -u strongswan --since '-48 hours' | grep -c "authentication failed")"
    echo "Timeout errors: $(journalctl -u strongswan --since '-48 hours' | grep -c "timeout")"
    echo "Certificate errors: $(journalctl -u strongswan --since '-48 hours' | grep -c "certificate")"
    echo "Crypto errors: $(journalctl -u strongswan --since '-48 hours' | grep -c "decrypt")"
    
    # Most active users (top 15)
    echo ""
    echo "4. MOST ACTIVE USERS (Last 48 Hours)"
    echo "------------------------------------"
    journalctl -u strongswan --since '-48 hours' | grep -E "established" | grep -oE "[^ ]*@[^ ]+" | sort | uniq -c | sort -nr | head -15
    
    # Most recent failures (last 20)
    echo ""
    echo "5. RECENT CONNECTION FAILURES"
    echo "-----------------------------"
    journalctl -u strongswan --since '-48 hours' | grep -E "failed|error|timeout|invalid" | grep -v "retransmit" | tail -20
    
    # Connection time distribution
    echo ""
    echo "6. CONNECTION TIME DISTRIBUTION"
    echo "-------------------------------"
    echo "Connections by hour (UTC):"
    journalctl -u strongswan --since '-48 hours' | grep "established" | awk '{print $3}' | cut -d: -f1 | sort | uniq -c | sort -n
    
    echo ""
    echo "7. RECENT CONNECTIONS (Last 20)"
    echo "--------------------------------"
    journalctl -u strongswan --since '-48 hours' | grep "established" | tail -20
} > "$LOG_DIR/connection_analysis.txt"

# Certificate store details
if command -v pki >/dev/null 2>&1; then
    {
        echo "StrongSwan Certificate Store Details"
        echo "------------------------------------"
        for cert_dir in /etc/ipsec.d/cacerts /etc/swanctl/x509ca; do
            if [ -d "$cert_dir" ]; then
                for cert in "$cert_dir"/*.cer "$cert_dir"/*.crt "$cert_dir"/*.pem; do
                    if [ -f "$cert" ]; then
                        echo "Certificate: $cert"
                        sudo pki --print --in "$cert" | grep -E "subject:|issuer:|validity:" | sed 's/^/  /'
                        echo ""
                    fi
                done
            fi
        done
        echo "------------------------------------"
    } > "$LOG_DIR/certificate_store.txt" 2>/dev/null || echo "Failed to collect certificate details." > "$LOG_DIR/certificate_store.txt"
else
    echo "pki tool not found, skipping certificate details..." > "$LOG_DIR/certificate_store.txt"
fi

# ZTNA logs and configuration (if available)
if [ -d /etc/zt/ztna.conf ] || [ -f /var/lib/strongswan/ztna-updown.sh ]; then
    mkdir -p "$LOG_DIR/ztna"
    collect_log "cat /etc/zt/ztna.conf/zones.conf 2>/dev/null" "$LOG_DIR/ztna/zones.txt" "ZTNA zone definitions"
    collect_log "ls -la /etc/nftables.d/zone_* 2>/dev/null" "$LOG_DIR/ztna/zone_files.txt" "ZTNA zone files"
    collect_log "cat /etc/nftables.d/zone_* 2>/dev/null" "$LOG_DIR/ztna/zone_configs.txt" "ZTNA zone configurations"
    collect_log "cat /var/lib/strongswan/ztna-updown.sh 2>/dev/null" "$LOG_DIR/ztna/updown_script.txt" "ZTNA updown script"
    collect_log "cat /etc/swanctl/conf.d/ztna.conf 2>/dev/null" "$LOG_DIR/ztna/swanctl_config.txt" "ZTNA SwanCtl configuration"
    
    # ZTNA logs
    if [ -d /var/log/ztna ]; then
        collect_log "cat /var/log/ztna/ztna-setup.log 2>/dev/null || echo 'Log not found'" "$LOG_DIR/ztna/setup_log.txt" "ZTNA setup log"
        collect_log "cat /var/log/ztna/ztna-updown.log 2>/dev/null || echo 'Log not found'" "$LOG_DIR/ztna/updown_log.txt" "ZTNA updown log"
    fi
    
    # XFRM interfaces for ZTNA
    collect_log "ip link show | grep xfrm" "$LOG_DIR/ztna/xfrm_interfaces.txt" "ZTNA XFRM interfaces"
    collect_log "ip xfrm state | grep -v 'auth-trunc' | grep -v 'enc '" "$LOG_DIR/ztna/xfrm_states_filtered.txt" "ZTNA XFRM states (filtered)"
    collect_log "ls -la /var/run/ztna* 2>/dev/null" "$LOG_DIR/ztna/runtime_files.txt" "ZTNA runtime files"
fi

# Boundary logs and configuration (if available)
if [ -d /etc/boundary ] || command -v boundary >/dev/null 2>&1; then
    mkdir -p "$LOG_DIR/boundary"
    collect_log "systemctl status boundary 2>/dev/null || echo 'Boundary service not found'" "$LOG_DIR/boundary/service_status.txt" "Boundary service status"
    collect_log "journalctl -u boundary --since '-48 hours' 2>/dev/null || echo 'No Boundary logs found'" "$LOG_DIR/boundary/journal_log.txt" "Boundary journal logs"
    collect_log "cat /etc/boundary/boundary.hcl 2>/dev/null || echo 'Config not found'" "$LOG_DIR/boundary/config.txt" "Boundary configuration"
    collect_log "ls -la /etc/boundary/zones/ 2>/dev/null" "$LOG_DIR/boundary/zones_dir.txt" "Boundary zones directory"
    collect_log "ls -la /etc/boundary/ 2>/dev/null" "$LOG_DIR/boundary/files.txt" "Boundary files"
    collect_log "cat /etc/boundary/boundary-policy.hcl 2>/dev/null || echo 'Policy not found'" "$LOG_DIR/boundary/vault_policy.txt" "Boundary Vault policy"
    
    # Boundary certificates
    collect_log "ls -la /etc/boundary/server-cert.pem /etc/boundary/server-key.pem /etc/boundary/ca.pem 2>/dev/null" "$LOG_DIR/boundary/cert_files.txt" "Boundary certificate files"
    
    # Database check
    collect_log "ls -la /var/lib/boundary/boundary.db 2>/dev/null" "$LOG_DIR/boundary/database.txt" "Boundary database file"
    collect_log "file /var/lib/boundary/boundary.db 2>/dev/null || echo 'Database not found'" "$LOG_DIR/boundary/database_type.txt" "Boundary database type"
    
    # If the boundary binary is available, collect some info
    if command -v boundary >/dev/null 2>&1; then
        collect_log "boundary version 2>/dev/null" "$LOG_DIR/boundary/version.txt" "Boundary version"
    fi
fi

# Vault logs and configuration (if available)
if [ -d /etc/vault ] || command -v vault >/dev/null 2>&1; then
    mkdir -p "$LOG_DIR/vault"
    collect_log "systemctl status vault 2>/dev/null || echo 'Vault service not found'" "$LOG_DIR/vault/service_status.txt" "Vault service status"
    collect_log "journalctl -u vault --since '-48 hours' 2>/dev/null || echo 'No Vault logs found'" "$LOG_DIR/vault/journal_log.txt" "Vault journal logs"
    collect_log "cat /etc/vault/config.hcl 2>/dev/null || echo 'Config not found'" "$LOG_DIR/vault/config.txt" "Vault configuration"
    collect_log "ls -la /etc/vault/ 2>/dev/null" "$LOG_DIR/vault/files.txt" "Vault files"
    
    # Vault status (if token available)
    if grep -q "VAULT_TOKEN" /etc/strongconn.conf 2>/dev/null; then
        token=$(grep "VAULT_TOKEN" /etc/strongconn.conf | cut -d '=' -f2 | tr -d '"' | tr -d "'")
        if [ -n "$token" ]; then
            collect_log "VAULT_TOKEN='$token' VAULT_ADDR='https://127.0.0.1:8200' vault status 2>/dev/null || echo 'Could not get Vault status'" "$LOG_DIR/vault/status.txt" "Vault status"
            collect_log "VAULT_TOKEN='$token' VAULT_ADDR='https://127.0.0.1:8200' vault secrets list 2>/dev/null || echo 'Could not list secrets'" "$LOG_DIR/vault/secrets_engines.txt" "Vault secrets engines"
            collect_log "VAULT_TOKEN='$token' VAULT_ADDR='https://127.0.0.1:8200' vault policy list 2>/dev/null || echo 'Could not list policies'" "$LOG_DIR/vault/policies.txt" "Vault policies"
        fi
    fi
fi

# Suricata logs (if available)
if [ -d /var/log/suricata ]; then
    mkdir -p "$LOG_DIR/suricata"
    collect_log "cat /var/log/suricata/stats.log 2>/dev/null || echo 'Log not found'" "$LOG_DIR/suricata/stats.txt" "Suricata stats log"
    collect_log "tail -n 1000 /var/log/suricata/eve.json 2>/dev/null || echo 'Log not found'" "$LOG_DIR/suricata/eve_last_1000.json" "last 1000 Suricata EVE events"
    collect_log "cat /var/log/suricata/fast.log 2>/dev/null || echo 'Log not found'" "$LOG_DIR/suricata/fast.txt" "Suricata fast log"
    collect_log "systemctl status suricata 2>/dev/null || echo 'Suricata service not found'" "$LOG_DIR/suricata/service_status.txt" "Suricata service status"
    collect_log "ls -la /etc/suricata/ 2>/dev/null" "$LOG_DIR/suricata/config_files.txt" "Suricata configuration files"
    collect_log "cat /etc/suricata/suricata.yaml 2>/dev/null | grep -v '#' | grep -v '^$' || echo 'Config not found'" "$LOG_DIR/suricata/config_filtered.txt" "Suricata configuration (filtered)"
    
    # Suricata rules
    collect_log "ls -la /etc/suricata/rules/ 2>/dev/null" "$LOG_DIR/suricata/rules_files.txt" "Suricata rules files"
    collect_log "find /etc/suricata -name '*.rules' -type f -exec grep -l 'alert' {} \\; 2>/dev/null | xargs cat | grep -v '#' | wc -l || echo 'No rules found'" "$LOG_DIR/suricata/rules_count.txt" "Suricata rules count"
    
    # Python watchdog script status
    if [ -f /var/log/suricata/suricata_watchdog.log ]; then
        collect_log "cat /var/log/suricata/suricata_watchdog.log 2>/dev/null || echo 'Log not found'" "$LOG_DIR/suricata/watchdog_log.txt" "Suricata watchdog log"
    fi
fi

# Firewall rules and network security
collect_log "iptables -S 2>/dev/null || echo 'iptables not found or no rules defined'" "$LOG_DIR/iptables_rules.txt" "iptables rules"
collect_log "nft list ruleset 2>/dev/null || echo 'nftables not found or no rules defined'" "$LOG_DIR/nftables_rules.txt" "nftables ruleset"
collect_log "nft list sets 2>/dev/null || echo 'No nftables sets defined'" "$LOG_DIR/nftables_sets.txt" "nftables sets"
collect_log "cat /etc/nftables.conf 2>/dev/null || echo 'nftables.conf not found'" "$LOG_DIR/nftables_config.txt" "nftables configuration"
collect_log "ls -la /etc/nftables.d/ 2>/dev/null" "$LOG_DIR/nftables_d_files.txt" "nftables.d files"

# System security status
collect_log "sestatus 2>/dev/null || echo 'SELinux not found'" "$LOG_DIR/selinux_status.txt" "SELinux status"
collect_log "apparmor_status 2>/dev/null || echo 'AppArmor not found'" "$LOG_DIR/apparmor_status.txt" "AppArmor status"
collect_log "cat /proc/sys/kernel/unprivileged_* 2>/dev/null" "$LOG_DIR/kernel_security.txt" "Kernel security settings"

# Summary report with StrongSwan users and component status
echo "Generating summary report..."
{
    echo "Advantive VPN Network Debug Summary - $TIMESTAMP"
    echo "=============================================="
    echo ""
    echo "SYSTEM STATUS:"
    echo "-------------"
    uptime=$(cat "$LOG_DIR/uptime.txt" 2>/dev/null || echo "Not available")
    echo "System uptime: $uptime"
    
    echo ""
    echo "STRONGSWAN VPN STATUS:"
    echo "--------------------"
    
    # Get current active connections count
    active_count=$(swanctl -l | grep -c "remote.*@" || echo "0")
    echo "Currently Active VPN Connections: $active_count"
    
    if [ "$active_count" -gt 0 ]; then
        echo ""
        echo "Active VPN Users:"
        swanctl -l | grep "remote" | grep -E "@|EAP:" | grep -v '127\.0\.0\.1' | sed 's/.*remote //' | sort | while read -r conn; do
            # Extract just the email address part 
            if [[ "$conn" == *"EAP:"* ]]; then
                email=$(echo "$conn" | grep -o "EAP: '[^']*'" | cut -d"'" -f2)
                ip=$(echo "$conn" | grep -o "\[[0-9.]*\]" | tr -d '[]')
                echo "  - $email ($ip)"
            elif [[ "$conn" == *"CN="* ]]; then
                email=$(echo "$conn" | grep -o "CN=[^ ]*" | cut -d= -f2)
                ip=$(echo "$conn" | grep -o "\[[0-9.]*\]" | tr -d '[]' | head -1)
                echo "  - $email ($ip)"
            fi
        done
    fi
    
    echo ""
    echo "VPN CONNECTION ANALYTICS (Last 48 Hours):"
    echo "--------------------------------------"
    
    # Create temp files for analysis
    VPN_LOG_TEMP=$(mktemp)
    VPN_STATS_TEMP=$(mktemp)
    VPN_USERS_TEMP=$(mktemp)
    VPN_FAILURES_TEMP=$(mktemp)
    
    # Extract logs for analysis
    sudo journalctl -u strongswan --since '-48 hours' > "$VPN_LOG_TEMP"
    
    # Check if we have logs
    if [ -s "$VPN_LOG_TEMP" ]; then
        # Count total connection attempts and successful connections
        total_attempts=$(grep -c "initiating" "$VPN_LOG_TEMP")
        successful_conns=$(grep -c "IKE_SA.*established" "$VPN_LOG_TEMP")
        current_active=$(swanctl -l | grep -c "remote.*@" || echo "0")
        
        # Count unique users
        grep -E "established|initiating" "$VPN_LOG_TEMP" | grep -oE "[^ ]*@[^ ]+" | sort -u > "$VPN_USERS_TEMP"
        unique_users=$(wc -l < "$VPN_USERS_TEMP")
        
        # Analyze connection failures
        grep -E "failed|error|timeout|invalid" "$VPN_LOG_TEMP" | grep -v "retransmit" > "$VPN_FAILURES_TEMP"
        failed_auth=$(grep -c "authentication failed" "$VPN_FAILURES_TEMP")
        timeout_errors=$(grep -c "timeout" "$VPN_FAILURES_TEMP")
        crypto_errors=$(grep -c "decrypt" "$VPN_FAILURES_TEMP")
        total_errors=$(wc -l < "$VPN_FAILURES_TEMP")
        
        # Calculate success rate
        if [ "$total_attempts" -gt 0 ]; then
            success_rate=$((successful_conns * 100 / total_attempts))
        else
            success_rate=0
        fi
        
        # Output statistics
        echo "Connection Statistics:"
        echo "  - Total Connection Attempts: $total_attempts"
        echo "  - Successful Connections: $successful_conns"
        echo "  - Current Active Connections: $current_active"
        echo "  - Unique Users: $unique_users"
        echo "  - Connection Success Rate: $success_rate%"
        echo ""
        echo "Error Analysis:"
        echo "  - Authentication Failures: $failed_auth"
        echo "  - Timeout Errors: $timeout_errors"
        echo "  - Cryptographic Errors: $crypto_errors"
        echo "  - Total Error Events: $total_errors"
        
        # Most frequent connection times
        echo ""
        echo "Connection Time Analysis:"
        # Extract hours and count frequency
        grep "established" "$VPN_LOG_TEMP" | awk '{print $3}' | cut -d: -f1 | sort | uniq -c | sort -nr > "$VPN_STATS_TEMP"
        echo "  Peak Connection Hours (UTC):"
        head -5 "$VPN_STATS_TEMP" | while read -r count hour; do
            echo "    - Hour $hour:00: $count connections"
        done
        
        # Most frequent user connections
        echo ""
        echo "Most Active Users (Last 48 Hours):"
        grep -E "established" "$VPN_LOG_TEMP" | grep -oE "[^ ]*@[^ ]+" | sort | uniq -c | sort -nr | head -10 | while read -r count user; do
            echo "  - $user: $count connections"
        done
        
        # Recent connection failures
        if [ "$failed_auth" -gt 0 ] || [ "$timeout_errors" -gt 0 ]; then
            echo ""
            echo "Recent Connection Issues:"
            tail -5 "$VPN_FAILURES_TEMP" | while read -r line; do
                timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
                error=$(echo "$line" | sed 's/.*charon\[[0-9]*\]: //')
                echo "  - [$timestamp] $error"
            done
        fi
        
        # Clean up temp files
        rm -f "$VPN_LOG_TEMP" "$VPN_STATS_TEMP" "$VPN_USERS_TEMP" "$VPN_FAILURES_TEMP"
    else
        echo "No StrongSwan journal logs found for the last 48 hours."
    fi
    
    echo ""
    echo "StrongSwan Users (Last 24 Hours, since $LAST_24H):"
    if sudo journalctl -u strongswan --since "$LAST_24H" | grep -i "established" > /dev/null 2>&1; then
        sudo journalctl -u strongswan --since "$LAST_24H" | grep -iE "established|initiating" | grep -oE "[^ ]*@[^ ]+" | sort -u > "$LOG_DIR/strongswan_users_24h.txt"
        cat "$LOG_DIR/strongswan_users_24h.txt" | while read -r user; do echo "  - $user"; done
    elif [ -f /var/log/charon.log ]; then
        sudo tac /var/log/charon.log | awk -v date="$LAST_24H" '$0 >= date' | grep -iE "established|initiating" | grep -oE "[^ ]*@[^ ]+" | sort -u > "$LOG_DIR/strongswan_users_24h.txt"
        cat "$LOG_DIR/strongswan_users_24h.txt" | while read -r user; do echo "  - $user"; done
    else
        echo "  No connection data found."
    fi
    
    # Check for ZTNA
    if [ -d /etc/zt/ztna.conf ] || [ -f /var/lib/strongswan/ztna-updown.sh ]; then
        echo ""
        echo "ZTNA STATUS:"
        echo "-----------"
        if [ -f /etc/zt/ztna.conf/zones.conf ]; then
            echo "ZTNA Zone Configuration: Found"
            zone_count=$(grep -c "ZTNA_ZONE_.*_NAME" /etc/zt/ztna.conf/zones.conf 2>/dev/null || echo "0")
            echo "Defined zones: $zone_count"
        else
            echo "ZTNA Zone Configuration: Not found"
        fi
        
        # Check XFRM interfaces
        xfrm_count=$(ip link show | grep -c "xfrm" 2>/dev/null || echo "0")
        echo "Active XFRM interfaces: $xfrm_count"
    fi
    
    # Check for Boundary
    if [ -d /etc/boundary ] || command -v boundary >/dev/null 2>&1; then
        echo ""
        echo "BOUNDARY STATUS:"
        echo "--------------"
        if systemctl is-active boundary >/dev/null 2>&1; then
            echo "Boundary service: Active"
        else
            echo "Boundary service: Inactive or not found"
        fi
        
        # Check for Boundary configuration
        if [ -f /etc/boundary/boundary.hcl ]; then
            echo "Boundary configuration: Found"
        else
            echo "Boundary configuration: Not found"
        fi
        
        # Check for zone configurations
        if [ -d /etc/boundary/zones ]; then
            zone_count=$(ls -la /etc/boundary/zones/ 2>/dev/null | grep -c "^d" || echo "0")
            echo "Boundary zone directories: $zone_count"
        fi
    fi
    
    # Check for Vault
    if [ -d /etc/vault ] || command -v vault >/dev/null 2>&1; then
        echo ""
        echo "VAULT STATUS:"
        echo "------------"
        if systemctl is-active vault >/dev/null 2>&1; then
            echo "Vault service: Active"
        else
            echo "Vault service: Inactive or not found"
        fi
        
        # Check for vault token
        if grep -q "VAULT_TOKEN" /etc/strongconn.conf 2>/dev/null; then
            echo "Vault token in configuration: Found"
        else
            echo "Vault token in configuration: Not found"
        fi
    fi
    
    # Check for Suricata
    if [ -d /var/log/suricata ]; then
        echo ""
        echo "SURICATA STATUS:"
        echo "--------------"
        if systemctl is-active suricata >/dev/null 2>&1; then
            echo "Suricata service: Active"
        else
            echo "Suricata service: Inactive or not found"
        fi
        
        # Check for watchdog
        if [ -f /var/log/suricata/suricata_watchdog.log ]; then
            echo "Suricata watchdog: Active"
        else
            echo "Suricata watchdog: Not found"
        fi
    fi
    
    # Failed services
    failed_services=$(systemctl --failed --no-pager | grep -c "loaded units listed" 2>/dev/null || echo "Not available")
    echo ""
    echo "SYSTEM HEALTH:"
    echo "-------------"
    echo "Failed services: $failed_services"
    
    # Check syslog-ng
    if systemctl is-active syslog-ng >/dev/null 2>&1; then
        echo "Syslog-ng: Active"
    else
        echo "Syslog-ng: Inactive or not installed (using journald)"
    fi
    
    echo ""
    echo "=============================================="
    echo "Attached file is encrypted with PFX_PASSWORD from /etc/strongconn.conf."
    echo "Decrypt with: openssl enc -d -aes-256-cbc -in network_debug_$TIMESTAMP.tar.gz.enc -out network_debug_$TIMESTAMP.tar.gz -pass pass:<your_PFX_PASSWORD>"
    echo "Extract with: tar -xzf network_debug_$TIMESTAMP.tar.gz"
    echo "=============================================="
} > "$SUMMARY_FILE"

# Copy summary into archive directory
cp "$SUMMARY_FILE" "$LOG_DIR/summary_report.txt"

# Archive logs
echo "Creating archive..."
tar -czf "$LOG_FILE" -C "$LOG_DIR" . || { echo "Failed to create archive"; exit 1; }

# Encrypt archive
echo "Encrypting archive..."
echo "$PFX_PASSWORD" | openssl enc -aes-256-cbc -salt -in "$LOG_FILE" -out "$ENCRYPTED_LOG_FILE" -pass stdin || { echo "Failed to encrypt archive"; exit 1; }

# Clean up unencrypted archive
rm "$LOG_FILE"

# Send email using postfix MTA installed by strongconn
echo "Sending encrypted report to $REPORT_EMAIL..."

# Create email content with attachment
EMAIL_TEMP=$(mktemp)
BOUNDARY="==boundary_$RANDOM$RANDOM=="

cat > "$EMAIL_TEMP" << EOF
Subject: $EMAIL_SUBJECT
To: $REPORT_EMAIL
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="$BOUNDARY"

--$BOUNDARY
Content-Type: text/plain
Content-Transfer-Encoding: 7bit

$(cat "$SUMMARY_FILE")

--$BOUNDARY
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="network_debug_$TIMESTAMP.tar.gz.enc"

$(base64 "$ENCRYPTED_LOG_FILE")

--$BOUNDARY--
EOF

# Send using sendmail from postfix
if [ -x /usr/sbin/sendmail ]; then
    /usr/sbin/sendmail -t < "$EMAIL_TEMP" && echo "Email sent successfully via Postfix." || echo "Failed to send email. Check Postfix logs."
else
    echo "Postfix sendmail not found. Trying alternatives..."
    # Try alternatives if postfix isn't available
    if command -v mail >/dev/null 2>&1; then
        cat "$SUMMARY_FILE" | mail -s "$EMAIL_SUBJECT" -a "$ENCRYPTED_LOG_FILE" "$REPORT_EMAIL" && echo "Email sent successfully via mail command." || echo "Failed to send email with mail command."
    else
        echo "No mail tools found. Please check your MTA configuration."
    fi
fi

# Clean up temp file
rm -f "$EMAIL_TEMP"

# Clean up temporary files
rm -f "$LOG_DIR"/*.txt "$LOG_DIR"/*.json "$SUMMARY_FILE"

echo "Done. Encrypted archive: $ENCRYPTED_LOG_FILE"