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
        --enable-xauth \
        --enable-updown \
        --enable-eap-identity \
        --enable-hasher \
        --enable-nonce-gen \
        --enable-eap-tls \
        --enable-eap-gtc \
        --enable-systemd \
        --enable-curl \
        --enable-cmd \
        --enable-swanctl \
        --enable-curve25519 \
        --enable-revocation \
        --enable-constraints \
        --enable-pki \
        --enable-pem \
        --enable-pkcs8 \
        --enable-pkcs1 \
        --enable-gcm \
        --enable-stroke \
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

# Create custom EAP-GTC configuration with hardcoded values
mkdir -p "$BUILD_DIR/etc/ipsec.d" || error_exit "Failed to create ipsec.d directory."
cat > "$BUILD_DIR/etc/ipsec.d/eap-gtc.conf" <<EOF
config setup
    strictcrlpolicy=yes
    uniqueids=yes

conn eap-gtc
    eap_identity=%identity
    leftauth=eap-gtc
    rightauth=pubkey
    keyexchange=ikev2
    auto=start
    type=tunnel
    left=%defaultroute
    leftsourceip=%config
    leftsubnet=0.0.0.0/0
    right=${server_address}
    rightid=${server_address}
    rightauth=pubkey
    rightsubnet=${remote_subnets}
    rightdns=%dns
    dpdaction=restart
    ike=aes256-sha256-ecp256,aes256gcm16-prfsha256-ecp256!
    esp=aes256-sha256,aes256gcm16!

EOF

# Create ipsec.conf to include the custom configuration
mkdir -p "$BUILD_DIR/etc/strongswan" || error_exit "Failed to create strongswan directory."
cat > "$BUILD_DIR/etc/ipsec.conf" <<EOF
include ipsec.d/*.conf
EOF

# Create StrongSwan configuration file
cat > "$BUILD_DIR/etc/strongswan/strongswan.conf" <<EOF
charon {
    load_modular = yes
    plugins {
        kernel-netlink {
            mtu = 1400
            mss = 1360
          }
        }
        include strongswan.d/charon/*.conf
    }
EOF

# Create post-installation script
cat > "$BUILD_DIR/DEBIAN/postinst" <<EOF
#!/bin/bash

server_address=$server_address
ca_url="http://\$server_address/ca"
ca_cert_path="/etc/ipsec.d/cacerts/ca.crt"

error_exit() {
    echo "Error: \$1" 1>&2
    exit 1
}

# Ensure the CA certificate directory exists
mkdir -p /etc/ipsec.d/cacerts || error_exit "Failed to create cacerts directory."

# Fetch the CA certificate automatically
if ! wget -q "\$ca_url" -O "\$ca_cert_path"; then
    echo "WARNING: Failed to fetch CA certificate from \$ca_url"
    echo "Please manually place the CA certificate in: \$ca_cert_path"
fi

# Display instructions for setting up credentials manually
cat <<EOM

==========================================
   StrongSwan EAP-GTC Setup Complete
==========================================

1️⃣  Please manually create the authentication file:
    sudo nano /etc/ipsec.secrets

2️⃣  Add the following line (replace with actual Okta credentials):
    your_username@example.com : EAP "your_password"

3️⃣  Restart the VPN service:
    sudo systemctl restart strongswan
    sudo ipsec start
    
3️⃣  Connect VPN service:
    sudo ipsec up eap-gtc

==========================================

EOM

EOF

# Make the postinst script executable
chmod +x "$BUILD_DIR/DEBIAN/postinst" || error_exit "Failed to make postinst script executable."

# Build the Debian package
dpkg-deb --build "$BUILD_DIR" || error_exit "Failed to build the Debian package."
log "StrongSwan package built successfully at /usr/src/$PACKAGE_NAME.deb"