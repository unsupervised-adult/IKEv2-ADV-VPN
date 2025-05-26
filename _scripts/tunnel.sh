#!/bin/bash

###################################################################################################
###################################################################################################
# StrongSwan IKEv2 Site-to-Site VPN Tunnel Management Script
###################################################################################################

# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
# =================================================================================================
# Description:
#   This script manages and configures site-to-site VPN tunnels between two StrongSwan IKEv2 
#   gateways. It provides automated setup and management of IPsec connections using IKEv2 protocol.
#
# Usage:
#   ./tunnel.sh [options]
#
# Important Notes:
#   - Requires root/ sudo privileges
#
# Disclaimer:
#   This script is provided as-is without warranty. Use at your own risk.
#   Author assumes no liability for any damages or losses.
#
# Author: Felix C Frank
# Email: felix.c.frank@proton.me
# Version: 1.7.50.2
# Created: 27-12-24
###################################################################################################
CONFIG_PATH="/etc/strongconn.conf"
trap - ERR EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

error_exit() {
    echo "⚠️ Error ⚠️: $1" >&2
    exit 1
}

cleanup() {
    local tunnel_name="$1"
    echo "Cleaning up due to an error or interruption..."
    if [[ -n "$tunnel_name" ]]; then
        tear_down_vpn "$tunnel_name"
        echo "Cleanup completed for tunnel: $tunnel_name"
    else
        echo "⚠️ No tunnel name provided for cleanup"
    fi
}


load_config() {
    if [ ! -f "$CONFIG_PATH" ]; then
        echo "Configuration file not found at $CONFIG_PATH" >&2
        return 1
    fi
    source "$CONFIG_PATH"
    return 0
}

get_client_vpn_subnet() {
    CLIENT_VPN_SUBNET=$(awk -F= '/^CLIENT_VPN_SUBNET=/ {print $2}' /etc/strongconn.conf)
    if [ -z "$CLIENT_VPN_SUBNET" ]; then
        echo "⚠️ Error: CLIENT_VPN_SUBNET not found in /etc/strongconn.conf." >&2
        exit 1
    fi
    echo "Client VPN Subnet: $CLIENT_VPN_SUBNET"
}

update_config() {
    local key="$1"
    local value="$2"
    local config_file="$CONFIG_PATH"

    if [[ "$value" =~ [[:space:]] || "$value" =~ [^a-zA-Z0-9_/.-] ]]; then
        value="\"$value\""
    fi


    if [[ -z "$value" ]]; then
        case "$key" in
            REQID|XFRM_INTERFACE)
                value="unset"
                ;;
        esac
    fi


    if grep -q "^${key}=" "$config_file"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$config_file"
    else
        echo "${key}=${value}" >> "$config_file"
    fi
}

fetch_ca() {
    local REMOTE_IP="$1"
    local NAME="$2"
    local CA_DEST="/etc/swanctl/x509ca/${NAME}-ca.pem"

    echo "Fetching CA from remote endpoint ($REMOTE_IP)..."
    curl -s -o "${CA_DEST}" "http://${REMOTE_IP}/ca"

    if [[ -s "${CA_DEST}" ]]; then
        echo "CA successfully downloaded and saved to ${CA_DEST}"
        chmod 644 "${CA_DEST}"
        chown root:root "${CA_DEST}"
        
        echo "Reloading StrongSwan authorities..."
        swanctl --load-authorities
    else
        echo "⚠️ Warning ⚠️: Failed to fetch CA from ${REMOTE_IP}!"
        exit 1
    fi
}

update_tun_ifid() {
    local new_ifid=$1
    local config_file="$CONFIG_PATH"

  
    if grep -q "^TUN_IFID=" "$config_file"; then
        sed -i "s|^TUN_IFID=.*|TUN_IFID=${new_ifid}|" "$config_file"
        echo "Updated TUN_IFID to ${new_ifid} in ${config_file}."
    else
        echo "TUN_IFID=${new_ifid}" | tee -a "$config_file" > /dev/null
        echo "Added TUN_IFID=${new_ifid} to ${config_file}."
    fi
}

save_nft_config() {
    echo "Merging nftables rules..."
    if [ -f /etc/nftables.conf ]; then
        nft -f /etc/nftables.conf  
    fi
    nft list ruleset > /etc/nftables.conf 
    systemctl reload nftables
}

tear_down_vpn() {
	local NAME="$1"
	local INITIATOR_ID="$2"
	local CONF_FILE="/etc/swanctl/conf.d/site-2site-${NAME}.conf"
	local INITIATOR_CONF="/var/lib/strongswan/initiator-${INITIATOR_ID}.conf"
	local INITIATORS_CONF="/var/lib/strongswan/initiators.conf"
	local SYSTEMD_SERVICE="/etc/systemd/system/strongswan-client-${NAME}.service"
	local NFT_TABLE="inet vpn_${NAME}"
	local CA_CERT="/etc/swanctl/x509ca/${NAME}.pem"
	local INITIATOR_ROUTER_ID="10.255.255.${INITIATOR_ID}"

	echo "🔻 Starting VPN teardown for ${NAME} (Initiator ID: ${INITIATOR_ID})..."

	# **Ensure VPN is fully terminated**
	echo "🛑 Stopping and unloading StrongSwan connection for ${NAME}..."
	swanctl --load-all "${NAME}" || echo "⚠️ Warning: Failed to unload VPN configuration ${NAME}"
    swanctl -t -i site_to_site_${NAME} || echo "⚠️ Warning: Failed to terminate IKE ${NAME}"
	# **Flush nftables table if it exists**
	if nft list table "$NFT_TABLE" &>/dev/null; then
		echo "🗑 Flushing nftables rules for ${NAME}..."
		nft flush table "$NFT_TABLE"
		nft delete table "$NFT_TABLE"
	fi

    # **Remove systemd service**
    if [[ -f "$SYSTEMD_SERVICE" ]]; then
        echo "🗑 Removing systemd service: $SYSTEMD_SERVICE"
        systemctl stop "strongswan-client-${NAME}"
        systemctl disable "strongswan-client-${NAME}"
        rm -f "$SYSTEMD_SERVICE"
        systemctl daemon-reload
    fi


	# **Remove only the `xfrm` interface (without touching loopback)**
	if ip link show "xfrm-${NAME}" &>/dev/null; then
		echo "❌ Removing XFRM interface xfrm-${NAME}."
		ip link set "xfrm-${NAME}" down
		ip link del "xfrm-${NAME}"
	fi
    
	# **Remove initiator-specific tracking files**
	echo "🗑 Removing VPN configuration files..."
	[[ -f "${CONF_FILE}" ]] && rm -f "${CONF_FILE}"
	[[ -f "${INITIATOR_CONF}" ]] && rm -f "${INITIATOR_CONF}"
	[[ -f "${CA_CERT}" ]] && rm -f "${CA_CERT}"
    rm -f "/etc/swanctl/x509ca/${NAME}-ca.pem" &>/dev/null
    rm -f /var/lib/strongswan/updown-${NAME}.sh &>/dev/null
    rm -f /etc/swanctl/conf.d/initiator-${INITIATOR_ID}.conf &>/dev/null
    rm -f /etc/swanctl/conf.d/site-2site-${NAME}.conf &>/dev/null
    rm -f /etc/nftables.d/vpn_nat.conf &>/dev/null
    rm -f /etc/nftables.d/vpn_${NAME}.conf &>/dev/null
    rm -f /etc/systemd/system/strongswan-client-${NAME}.service &>/dev/null
	if [[ -f "$INITIATORS_CONF" && -n "$INITIATOR_ID" ]]; then
		echo "📄 Removing initiator-${INITIATOR_ID} entry from ${INITIATORS_CONF}..."
		sed -i "/^INITIATOR_ID=${INITIATOR_ID}$/d" "$INITIATORS_CONF"
	fi
    nft delete table inet vpn_${NAME} &>/dev/null    
    swanctl --load-all
    swanctl --list-conns    
	echo "✅ VPN teardown completed for ${NAME}."
}


create_updown_script() {
    
	local NAME=$1
    local INITIATOR_ID=$2
    local IF_ID=$3
    local ROLE=$4
    local REMOTE_IP=$5
	local UPDOWN_SCRIPT="/var/lib/strongswan/updown-${NAME}.sh"
   
	echo "📄 Creating updown script: $UPDOWN_SCRIPT"

	tee "$UPDOWN_SCRIPT" > /dev/null <<EOF
#!/bin/bash

INITIATOR_CONF="/var/lib/strongswan/initiator-$INITIATOR_ID.conf"

if [[ -f "\$INITIATOR_CONF" ]]; then
    source "\$INITIATOR_CONF"
else
    echo "⚠️ Error ⚠️: Initiator config \$INITIATOR_CONF not found. Exiting."
    exit 1
fi

setup_xfrm_interface() {
    echo "🔧 Setting up XFRM interface xfrm-$NAME with if_id $IF_ID"

    if ! ip link show "xfrm-$NAME" &>/dev/null; then
        echo "🔧 Creating new XFRM interface xfrm-$NAME"
        ip link add name "xfrm-$NAME" type xfrm if_id "$IF_ID" || exit 1
    fi

    echo "✅ Bringing up XFRM interface xfrm-$NAME..."
    ip link set "xfrm-$NAME" up || exit 1

    ATTEMPTS=0
    MAX_ATTEMPTS=30
    while ! ip link show "xfrm-$NAME" | grep -q "UP"; do
        if [ \$ATTEMPTS -ge \$MAX_ATTEMPTS ]; then
            echo "❌ Timeout waiting for xfrm-$NAME interface to come up"
            exit 1
        fi
        echo "⏳ Waiting for xfrm-$NAME interface to come up... (attempt \$((ATTEMPTS+1))/\$MAX_ATTEMPTS)"
        sleep 1
        ((ATTEMPTS++))
    done

    echo "✅ XFRM interface xfrm-$NAME is up and running with IP:"
    ip a show "xfrm-$NAME" | grep "inet "
}


remove_xfrm_interface() {
    echo "❌ Removing XFRM interface xfrm-$NAME."
    if ip link show "xfrm-$NAME" &> /dev/null; then
        ip link set "xfrm-$NAME" down
        ip link del "xfrm-$NAME"
    else
        echo "⚠️ XFRM ⚠️ interface xfrm-$NAME does not exist."
    fi
}

manage_firewall_whitelist() {
    local action="\$1"  
    local remote_ip="\${REMOTE_IP}"
    local remote_subnets="\${REMOTE_SUBNET},\${LOCAL_SUBNET}"
    
    # Function to check if an element exists in the set
    check_element_exists() {
        local element="\$1"
        if nft list set inet firewall whitelisted_ips 2>/dev/null | grep -q "\$element"; then
            return 0 
        else
            return 1  
        fi
    }

    if [[ "\$action" == "add" ]]; then
        echo "✅ Adding remote IP \$remote_ip and subnets to whitelist..."
        
        # Check and add REMOTE_IP if it's not empty and doesn't exist
        if [ -n "\$remote_ip" ] && ! check_element_exists "\$remote_ip"; then
            nft add element inet firewall whitelisted_ips { "\$remote_ip" } || echo "Failed to add \$remote_ip to whitelist"
        else
            echo "🔍 \$remote_ip already present in whitelist or is empty, skipping..."
        fi

        # Process each subnet
        IFS=',' read -ra subnets <<< "\$remote_subnets"
        for subnet in "\${subnets[@]}"; do
            if ! check_element_exists "\$subnet"; then
                nft add element inet firewall whitelisted_ips { "\$subnet" } || echo "Failed to add \$subnet to whitelist"
            else
                echo "🔍 Subnet \$subnet already present in whitelist, skipping..."
            fi
        done

    elif [[ "\$action" == "remove" ]]; then
        echo "🗑️ Removing remote IP \$remote_ip and subnets from whitelist..."
        
        # Remove REMOTE_IP if it exists
        if [ -n "\$remote_ip" ] && check_element_exists "\$remote_ip"; then
            nft delete element inet firewall whitelisted_ips { "\$remote_ip" } || echo "Failed to remove \$remote_ip from whitelist"
        else
            echo "🔍 \$remote_ip not present in whitelist or is empty, skipping..."
        fi

        # Process each subnet for removal
        IFS=',' read -ra subnets <<< "\$remote_subnets"
        for subnet in "\${subnets[@]}"; do
            if check_element_exists "\$subnet"; then
                nft delete element inet firewall whitelisted_ips { "\$subnet" } || echo "Failed to remove \$subnet from whitelist"
            else
                echo "🔍 Subnet \$subnet not present in whitelist, skipping..."
            fi
        done
    fi
}

case "\$PLUTO_VERB" in
    up-client)
        if [[ "\${NAME}" =~ [^a-zA-Z0-9_] ]]; then
            NAME=$(echo "\${NAME}" | tr -cd '[:alnum:]_')
        fi
        NAME=\${NAME:0:15}

        echo "🛠 Tunnel is up. Setting up XFRM interface, routes, and nftables rules."
        manage_firewall_whitelist "add"
        
        if ! ip link show "xfrm-$NAME" &>/dev/null; then
            setup_xfrm_interface
        else
            echo "✅ XFRM interface xfrm-$NAME already exists"
        fi
        IFS=',' read -ra REMOTE_NETS <<< "\${REMOTE_SUBNET}"
        for remote_net in "\${REMOTE_NETS[@]}"; do
            if ! ip route show | grep -q "^\${remote_net} dev xfrm-${NAME}"; then
                ip route del "\${remote_net}" 2>/dev/null || true
                ip route add "\${remote_net}" dev "xfrm-${NAME}"
            fi
        done
     
        ;;

    down-client)
        if [[ "\${NAME}" =~ [^a-zA-Z0-9_] ]]; then
            NAME=$(echo "\${NAME}" | tr -cd '[:alnum:]_')
        fi
        NAME=\${NAME:0:15}

        echo "🔽 Tunnel is down. Cleaning up XFRM interface, routes, and nftables rules."
        manage_firewall_whitelist "remove"
        remove_xfrm_interface
        IFS=',' read -ra REMOTE_NETS <<< "\${REMOTE_SUBNET}"
        for remote_net in "\${REMOTE_NETS[@]}"; do
            ip route del "\${remote_net}" 2>/dev/null || true
        done
  
        ;;
esac

EOF

	chown root:strongswan "$UPDOWN_SCRIPT"
	chmod 750 "$UPDOWN_SCRIPT"
}

set_initiator() {
	local INITIATOR_ID="$1"
	local LOCAL_SUBNET="$2"
	local REMOTE_SUBNET="$3"
    local REMOTE_IP="$4"
	local INITIATOR_CONF="/var/lib/strongswan/initiator-${INITIATOR_ID}.conf"

	echo "📄 Writing initiator config: ${INITIATOR_CONF}"
	cat > "$INITIATOR_CONF" <<EOF
INITIATOR_ID=${INITIATOR_ID}
LOCAL_SUBNET=${LOCAL_SUBNET}
REMOTE_SUBNET=${REMOTE_SUBNET}
REMOTE_IP=${REMOTE_IP}
VPN_MODE=${VPN_MODE}
IP_POOL=${IP_POOL}
STUB_AREA=${STUB_AREA} 
EOF


}

set_master() {
	local INITIATOR_ID="$1"
	local LOCAL_SUBNET="$2"
	local REMOTE_SUBNET="$3"
    local REMOTE_IP="$4"
	local MASTER_CONF="/var/lib/strongswan/master.conf"
	local INITIATORS_FILE="/var/lib/strongswan/initiators.conf"
	local INITIATOR_CONF="/var/lib/strongswan/initiator-${INITIATOR_ID}.conf"	

	if ! grep -q "^INITIATOR_ID=${INITIATOR_ID}$" "$INITIATORS_FILE"; then
		echo "📄 Writing initiator-${INITIATOR_ID} to ${INITIATORS_FILE}"
		cat >> "$INITIATORS_FILE" <<EOF

INITIATOR_ID=${INITIATOR_ID}
LOCAL_SUBNET=${LOCAL_SUBNET}
REMOTE_SUBNET=${REMOTE_SUBNET}
REMOTE_IP=${REMOTE_IP}
VPN_MODE=${VPN_MODE}



EOF
	fi

	echo "📄 Writing initiator config: ${INITIATOR_CONF}"
	cat > "$INITIATOR_CONF" <<EOF
INITIATOR_ID=${INITIATOR_ID}
LOCAL_SUBNET=${LOCAL_SUBNET}
REMOTE_SUBNET=${REMOTE_SUBNET}
REMOTE_IP=${REMOTE_IP}
VPN_MODE=${VPN_MODE}
IP_POOL=${IP_POOL}
EOF
	
	echo "✅ Master Configuration Complete and UpDown config written."
}




generate_if_id() {
    local name="$1"
    local hash
    hash=$(echo -n "$name$(date +%s%N)" | md5sum | cut -c 29-32)
    local decimal=$((16#$hash))
    local ifid=$((decimal % 65535 + 1))
    echo "$ifid"
}


write_nft_table()
{
    local NAME="$1"
    local LOCAL_SUBNETS="$2"
    local REMOTE_SUBNETS="$3"
    cat > "/etc/nftables.d/vpn_${NAME}.conf" <<EOF
#!/usr/sbin/nft -f
table inet vpn_${NAME} {
    chain forward {
        type filter hook forward priority filter - 5; policy accept;

        tcp flags syn tcp option maxseg size set 1360
$( for local in $(echo "$LOCAL_SUBNETS" | tr ',' ' '); do
    for remote in $(echo "$REMOTE_SUBNETS" | tr ',' ' '); do
        echo "        ip saddr ${local} ip daddr ${remote} counter accept"
        echo "        ip saddr ${remote} ip daddr ${local} counter accept"
    done
done )
    }
    chain input {
        type filter hook input priority filter - 5; policy accept;
        ct state established,related counter accept
        ct state invalid counter drop
        iifname "xfrm-${NAME}" counter accept
    }
    chain output {
        type filter hook output priority filter - 5; policy accept;
        ct state established,related counter accept
        ct state invalid counter drop
        oifname "xfrm-${NAME}" counter accept
    }
    chain postrouting {
        type nat hook postrouting priority srcnat - 5; policy accept;
        
$( if [ "$VPN_MODE" = "NAT" ]; then
    echo "        oifname \"xfrm-${NAME}\" masquerade"
    for remote in $(echo "$REMOTE_SUBNETS" | tr ',' ' '); do
        echo "        oifname \"${DEFAULT_INTERFACE}\" ip saddr ${remote} masquerade"
    done
fi )
    }
}
EOF
    echo "✅ NFT table vpn_${NAME} configuration written to /etc/nftables.d/vpn_${NAME}.conf"
}

save_vpn_config() {
    echo "Saving VPN config to ${CONFIG_PATH}..."
    update_config "NAME" "$NAME"
    update_config "REMOTE_IP" "$REMOTE_IP"
    update_config "LOCAL_SUBNET" "$LOCAL_SUBNET"
    update_config "REMOTE_SUBNET" "$REMOTE_SUBNET"
    update_config "IF_ID" "$IF_ID"
    update_config "XFRM_INTERFACE" "$XFRM_INTERFACE"
    update_config "ROLE" "$ROLE"
}

create_systemd_service() {
	local NAME="$1"
	local CONNECTION_NAME="site_to_site_${NAME}"
	local SYSTEMD_SERVICE="/etc/systemd/system/strongswan-client-${NAME}.service"

	echo "Creating systemd service: strongswan-client-${NAME}..."

	cat <<EOF | sudo tee "${SYSTEMD_SERVICE}"
[Unit]
Description=StrongSwan IPsec Tunnel ${NAME} Service
After=network-online.target
Wants=network-online.target strongswan.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "/usr/sbin/swanctl --load-all && /usr/sbin/swanctl --initiate --child ${NAME}"
ExecStop=/bin/bash -c "/usr/sbin/swanctl --terminate --ike ${CONNECTION_NAME}"
Restart=on-failure
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
EOF

	
	sudo systemctl daemon-reload
	sudo systemctl enable "strongswan-client-${NAME}"
    sudo swanctl --load-all
    sudo swanctl --terminate --ike "${CONNECTION_NAME}"


}

create_site_to_site_conf() {
    local REMOTE_IP=$1
    local LOCAL_SUBNET=$2
    local REMOTE_SUBNET=$3
    local IF_ID=$4
    local UPDOWN_SCRIPT="/var/lib/strongswan/updown-${NAME}.sh"
    CONNECTION_NAME="site_to_site_${NAME}"

    cat > "/etc/swanctl/conf.d/site-2site-${NAME}.conf" <<EOF
connections {
    $CONNECTION_NAME {
        version = 2
        proposals = aes256gcm16-prfsha512-ecp521
        encap = yes
        dpd_delay = 30s
        dpd_timeout = 300s
        local_addrs = $DEFAULT_IP
        remote_addrs = $REMOTE_IP

        local {
            auth = pubkey
            certs = /etc/swanctl/x509/server.pem
            id = ${PUBLIC_IP}
        }

        remote {
            auth = pubkey
            id = $REMOTE_IP
            cacerts = /etc/swanctl/x509ca/${NAME}-ca.pem
        }

        children {
EOF
    

    IFS=',' read -ra LOCAL_NETS <<< "$LOCAL_SUBNET"
    IFS=',' read -ra REMOTE_NETS <<< "$REMOTE_SUBNET"

    local counter=1
    for local_net in "${LOCAL_NETS[@]}"; do
        for remote_net in "${REMOTE_NETS[@]}"; do
            cat >> "/etc/swanctl/conf.d/site-2site-${NAME}.conf" <<EOF
            ${NAME}_${counter} {
                if_id_in = $IF_ID
                if_id_out = $IF_ID
                local_ts = ${local_net}
                remote_ts = ${remote_net}
                rekey_time = 28800s
                start_action = trap
                close_action = trap
                mode = tunnel
                dpd_action = clear
                esp_proposals = aes256gcm16-ecp521
                updown = ${UPDOWN_SCRIPT}
            }
EOF
            ((counter++))
        done
    done

    cat >> "/etc/swanctl/conf.d/site-2site-${NAME}.conf" <<EOF
       }
       mobike = no
       fragmentation = yes
    }
}

secrets {
    private-key {
        id = ${PUBLIC_IP}
        file = /etc/swanctl/private/server-key.pem
    }
}

authorities {
    vpn-ca {
        cacert = /etc/swanctl/x509ca/ca.pem
        ocsp_uris = [ "http://$PUBLIC_IP/ocsp" ]
        crl_uris = [ "http://$PUBLIC_IP/crl/crl.pem" ]
    }
    ${NAME}-ca {
        cacert = /etc/swanctl/x509ca/${NAME}-ca.pem
        ocsp_uris = [ "http://$REMOTE_IP/ocsp" ]
        crl_uris = [ "http://$REMOTE_IP/crl/crl.pem" ]
    }
}
EOF

    echo "Site-to-Site VPN configuration ${CONNECTION_NAME}.conf created successfully."
    chmod 640 "/etc/swanctl/conf.d/site-2site-${NAME}.conf"
    chown root:strongswan "/etc/swanctl/conf.d/site-2site-${NAME}.conf"
}

NAME=""
REMOTE_IP=""
LOCAL_SUBNET=""
REMOTE_SUBNET=""
ROLE=""
IF_ID=""
INITIATOR_ID=""
ROUTE_SUBNETS=""
ACTION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)
            NAME="$2"
            shift 2
            ;;
        --remote-ip)
            REMOTE_IP="$2"
            shift 2
            ;;
        --local-subnet)
            LOCAL_SUBNET="$2"
            shift 2
            ;;
        --remote-subnet)
            REMOTE_SUBNET="$2"
            shift 2
            ;;
        --role)
            ROLE="$2"
            shift 2
            ;;
        --if-id)
            IF_ID="$2"
            shift 2
            ;;
        --initiator-id)
            INITIATOR_ID="$2"
            shift 2
            ;;
        --route-subnets)
            ROUTE_SUBNETS="$2"
            shift 2
            ;;
        --teardown)
            ACTION="teardown"
            shift
            ;;
        --help|-h)
            cat <<EOF
Usage: tunnel.sh [options]

Options:
  --name            Name of the VPN connection (e.g., site1)
  --remote-ip       Remote VPN gateway IP address
  --local-subnet    Local subnets for the VPN tunnel (comma-separated)
  --remote-subnet   Remote subnets for the VPN tunnel (comma-separated)
  --role            Role of the tunnel (master or initiator)
  --if-id           Interface ID (generated if not provided)
  --initiator-id    Numeric ID used to build loopback for OSPF (required for initiators)
  --route-subnets   Additional local route subnets for initiator (comma-separated)
  --teardown        Removes the VPN tunnel configuration
  --help            Show this usage info

EOF
            exit 0
            ;;
        *)
            echo "⚠️ Error ⚠️: Unknown option $1" >&2
            exit 1
            ;;
    esac
done


if [[ "$ACTION" == "teardown" ]]; then
    if [[ -z "$NAME" ]]; then
        echo "⚠️ Error ⚠️: --name is required for teardown" >&2
        exit 1
    fi
    tear_down_vpn "$NAME" "$INITIATOR_ID"
    exit 0
fi


load_config || error_exit "Failed to load configuration"
if [[ -z "$REMOTE_IP" ]]; then
    echo "⚠️ Error ⚠️: --remote-ip is required" >&2
    exit 1
fi

if [[ -z "$NAME" || -z "$ROLE" ]]; then
    echo "⚠️ Error ⚠️: --name and --role are required" >&2
    exit 1
fi

if [[ "$ROLE" != "master" && "$ROLE" != "initiator" ]]; then
    echo "⚠️ Error ⚠️: --role must be either 'master' or 'initiator'" >&2
    exit 1
fi

if [[ "$ROLE" == "initiator" ]]; then
    if [[ -z "$INITIATOR_ID" ]]; then
        echo "⚠️ Error ⚠️: --initiator-id is required for initiator role." >&2
        exit 1
    fi
    if [[ "$INITIATOR_ID" -eq 1 ]]; then
        echo "⚠️ Error ⚠️: Initiator ID 1 is reserved for the master. Use ID 2 or higher." >&2
        exit 1
    fi
    if [[ -z "$REMOTE_IP" ]]; then
        echo "⚠️ Error ⚠️: --remote-ip is required for initiator role." >&2
        exit 1
    fi
   
fi


if [[ "$ROLE" == "master" ]]; then
    if [[ -z "$INITIATOR_ID" ]]; then
        echo "⚠️ Error ⚠️: Master must specify --initiator-id to manage a specific initiator." >&2
        exit 1
    fi
    if [[ "$INITIATOR_ID" -lt 1 ]]; then
        echo "⚠️ Error ⚠️: Master cannot use an Initiator ID less than 1." >&2
        exit 1
    fi
if [[ -z "$REMOTE_IP" ]]; then
        echo "⚠️ Error ⚠️: --remote-ip is required." >&2
        exit 1
    fi
fi

if [[ -z "$LOCAL_SUBNET" || -z "$REMOTE_SUBNET" ]]; then
    echo "⚠️ Error ⚠️: --local-subnet and --remote-subnet are required" >&2
    exit 1
fi


if [[ -z "$IF_ID" ]]; then
    IF_ID="$(generate_if_id "$NAME")"
fi

if [[ -f "/etc/swanctl/conf.d/site-2site-${NAME}.conf" ]]; then
    echo "Config for '${NAME}' already exists. Use --teardown first." >&2
    exit 1
fi


load_config || error_exit "Failed to load configuration"

save_vpn_config
create_site_to_site_conf "$REMOTE_IP" "$LOCAL_SUBNET" "$REMOTE_SUBNET" "$IF_ID" 


create_updown_script "$NAME" "$INITIATOR_ID" "$IF_ID" "$ROLE" "$REMOTE_IP"

if [[ "$ROLE" == "master" ]]; then
    echo "Configuring master role with IF_ID=${IF_ID}..."
    fetch_ca "$REMOTE_IP" "$NAME"
    set_master "$INITIATOR_ID" "$LOCAL_SUBNET" "$REMOTE_SUBNET" "$REMOTE_IP"
    write_nft_table "$NAME" "$LOCAL_SUBNET" "$REMOTE_SUBNET"
    nft -f /etc/nftables.d/vpn_${NAME}.conf
    swanctl --load-all
else
    echo "Configuring initiator role with IF_ID=${IF_ID}"
    fetch_ca "$REMOTE_IP" "$NAME"
    set_initiator "$INITIATOR_ID" "$LOCAL_SUBNET" "$REMOTE_SUBNET" "$REMOTE_IP"
    write_nft_table "$NAME" "$LOCAL_SUBNET" "$REMOTE_SUBNET"
    nft -f /etc/nftables.d/vpn_${NAME}.conf
    create_systemd_service "$NAME"
    swanctl --load-all
    systemctl start "strongswan-client-${NAME}".service
    systemctl status "strongswan-client-${NAME}".service
fi

echo "Site to site completed successfully."
