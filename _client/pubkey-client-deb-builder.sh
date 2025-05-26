#!/bin/bash

# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
#
# Author: Felix C Frank 2024
# Version: 1.7.50.1
# Created: 27-12-24
## feedback mailto:felix.c.frank@proton.me
###############################################################################
# Function to handle errors
error_exit() {
    echo "Error: $1" 1>&2
    exit 1
}

# Logging function
log() {
    echo "Log: $1"
}

# Ensure the script runs as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

# Prompt the builder for server address, remote subnets, and DNS
read -p "Enter the VPN server address: " server_address
if [ -z "$server_address" ]; then
    error_exit "Server address cannot be empty."
fi

read -p "Enter the remote subnets (e.g., 192.168.1.0/24): " remote_subnets
if [ -z "$remote_subnets" ]; then
    error_exit "Remote subnets cannot be empty."
fi
# Update package lists and install build dependencies
apt-get update || error_exit "Failed to update package lists."
apt-get install -y build-essential libgmp-dev libssl-dev libcap2-dev \
    libcurl4-openssl-dev libsystemd-dev libjson-c-dev libnss3-tools pkg-config \
    automake gawk flex bison gperf wget curl bzip2 || error_exit "Failed to install build dependencies."

# Change to the source directory
cd /usr/src/ || error_exit "Failed to change directory to /usr/src/."

# Determine the latest StrongSwan version
latest_version=$(curl -s https://download.strongswan.org/ \
    | grep -oP 'strongswan-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.bz2)' \
    | sort -V | tail -1)
if [ -z "$latest_version" ]; then
    error_exit "Failed to determine the latest StrongSwan version."
fi
log "Latest StrongSwan version is $latest_version"

# Download and extract the StrongSwan source
tarball="strongswan-$latest_version.tar.bz2"
download_url="https://download.strongswan.org/$tarball"
wget "$download_url" || error_exit "Failed to download StrongSwan source."
tar xjf "$tarball" || error_exit "Failed to extract StrongSwan source."

# Enter the source directory
cd "strongswan-$latest_version" || error_exit "Failed to enter StrongSwan source directory."

# Define the package build directory
PACKAGE_NAME="strongswan-gtc-$latest_version"
VERSION="$latest_version"
BUILD_DIR="/usr/src/$PACKAGE_NAME-$VERSION"

# Configure StrongSwan with required features
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
        --with-systemdsystemunitdir=/lib/systemd/system  || error_exit "Failed to configure StrongSwan."

# Compile and install StrongSwan into the package directory
make || error_exit "Failed to compile StrongSwan."
make install DESTDIR="$BUILD_DIR" || error_exit "Failed to install StrongSwan."

# Create the DEBIAN control file for the package
mkdir -p "$BUILD_DIR/DEBIAN" || error_exit "Failed to create DEBIAN directory."
cat > "$BUILD_DIR/DEBIAN/control" <<EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Conflicts: strongswan, strongswan-charon, strongswan-starter, strongswan-swanctl, strongswan-libcharon, strongswan-pki, strongswan-nm, charon-systemd, charon-cmd, libcharon-extauth-plugins, libcharon-extra-plugins, libstrongswan, libstrongswan-extra-plugins, libstrongswan-standard-plugins
Depends: libc6, libgmp10, libssl3, libcurl4, libsystemd0, libcap2, libjson-c5, libnss3, iproute2, wget
Maintainer: Felix Frank <felix.frank@advantive.com>
Description: StrongSwan package with eap-gtc, hardcoded subnets and DNS
EOF

mkdir -p "$BUILD_DIR/ect/swanctl/x509ca"
mkdir -p "$BUILD_DIR/ect/swanctl/x509"
mkdir -p "$BUILD_DIR/ect/swanctl/private"
mkdir -p "$BUILD_DIR/ect/swanctl/conf.d"
mkdir -p "$BUILD_DIR/ect/strongswan.d/"
mkdir -p "$BUILD_DIR/etc/strongswan" || error_exit "Failed to create strongswan directory."
cat > "$BUILD_DIR/etc/ipsec.conf" <<EOF
include ipsec.d/*.conf
EOF

# Create StrongSwan configuration file
cat <<'EOF' > $BUILD_DIR/etc/strongswan/strongswan.conf"
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



cat > "$BUILD_DIR/etc/systemd/system/strongswan.client.service" <<EOF
[Unit]
Description=StrongSwan IPsec client
After=strongswan.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/usr/sbin/swanctl --load-all && /usr/sbin/swanctl --initiate --child $name"
ExecStop=/bin/bash -c "/usr/sbin/swanctl --terminate --ike ike-$name"
RemainAfterExit=yes
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF


cat > "$BUILD_DIR/etc/strongswan/swanctl/swanctl.conf" <<EOF
authorities {
	ca {
		cacert = /etc/strongswan/swanctl/x509ca/ca.pem
	}
}
secrets {
	private-key {
		file = /etc/strongswan/swanctl/private/${keyname}-key.pem
	}
}
connections {
	ike-$name {
		version = 2
		encap = yes
		dpd_delay = 30s
		dpd_timeout = 300s
		proposals =  aes256-sha256-ecp256, aes256-sha256-ecp384, aes256-sha384-ecp384, aes256-sha256-ecp521, aes256gcm16-sha256-ecp256
		remote_addrs = $vpn_server
		vips = 0.0.0.0 
		local {
			auth = pubkey
			certs = /etc/strongswan/swanctl/x509/${certname}.pem
			cacerts = ca.pem
		}
		remote {
			auth = pubkey
            revocation = ifuri
			id = $vpn_server
		}
		children {
			$name {
				if_id_in = 33 
				if_id_out = 33
				local_ts = 0.0.0.0/0
				remote_ts = 10.250.0.0/16,10.240.0.0/16,10.242.0.0/16
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



cat > "$BUILD_DIR/usr/libexec/strongswan/_updown" << EOF
#!/bin/bash
VPN_IP=\$(echo "\$PLUTO_MY_CLIENT" | cut -d'/' -f1)
XFRM_INTERFACE="xfrm0"
XFRM_IF_ID="33"
TABLE_ID=220

create_xfrm_interface() {
    if ! ip link show "\$XFRM_INTERFACE" &>/dev/null; then
        ip link add "\$XFRM_INTERFACE" type xfrm if_id "\$XFRM_IF_ID"
        ip link set "\$XFRM_INTERFACE" up
    fi
}

ensure_fib_table() {
    ip rule show | grep -q "lookup \$TABLE_ID" || ip rule add lookup \$TABLE_ID
}

case "\$PLUTO_VERB" in
    up-client)
        create_xfrm_interface
        ensure_fib_table
        VPN_IP=\${VPN_IP:-\$(ip addr show dev xfrm0 | awk '/inet / {print \$2}' | cut -d'/' -f1)}
        ip route add 10.240.0.0/16 dev \XFRM_INTERFACE" table \$TABLE_ID 2>/dev/null || true
        ip route add 10.242.0.0/16 dev "\$XFRM_INTERFACE" table \$TABLE_ID 2>/dev/null || true
        ip route add 10.250.0.0/16 dev "\$XFRM_INTERFACE" table \$TABLE_ID 2>/dev/null || true
        ip rule add from "\$VPN_IP" lookup \$TABLE_ID 2>/dev/null || true
        ip rule add to 10.240.0.0/16 lookup \$TABLE_ID 2>/dev/null || true
        ip rule add to 10.242.0.0/16 lookup \$TABLE_ID 2>/dev/null || true
        ip rule add to 10.250.0.0/16 lookup \$TABLE_ID 2>/dev/null || true
        ;;
    down-client)
        ip route del 10.240.0.0/16 table \$TABLE_ID 2>/dev/null || true
        ip route del 10.242.0.0/16 table \$TABLE_ID 2>/dev/null || true
        ip route del 10.250.0.0/16 table \$TABLE_ID 2>/dev/null || true
        ip rule del from "\$VPN_IP" lookup \$TABLE_ID 2>/dev/null || true
        ip rule del to 10.240.0.0/16 lookup \$TABLE_ID 2>/dev/null || true
        ip rule del to 10.242.0.0/16 lookup \$TABLE_ID 2>/dev/null || true
        ip rule del to 10.250.0.0/16 lookup \$TABLE_ID 2>/dev/null || true
        ip link del "\$XFRM_INTERFACE" 2>/dev/null || true
        ;;
esac
EOF

chmod +x "$BUILD_DIR/usr/libexec/strongswan/_updown"

# Create post-installation script
cat > "$BUILD_DIR/DEBIAN/postinst" <<EOF
#!/bin/bash

server_address=$server_address
ca_url="http://\$server_address/ca"
ca_cert_path="/etc/swanctl/x509ca/ca.pem"

error_exit() {
    echo "Error: \$1" 1>&2
    exit 1
}


mkdir -p /etc/ || error_exit "Failed to create cacerts directory."

# Fetch the CA certificate automatically
if ! wget -q "\$ca_url" -O "\$ca_cert_path"; then
    echo "WARNING: Failed to fetch CA certificate from \$ca_url"
    echo "Please manually place the CA certificate in: \$ca_cert_path"
fi
systemctl daemon-reload

systemctl disable strongswan-starter &>/dev/null

systemctl enable strongswan
systemctl start strongswan
swanctl --load-all

systemctl enable strongswan.client.service



EOF

# Make the postinst script executable
chmod +x "$BUILD_DIR/DEBIAN/postinst" || error_exit "Failed to make postinst script executable."

# Build the Debian package
dpkg-deb --build "$BUILD_DIR" || error_exit "Failed to build the Debian package."

