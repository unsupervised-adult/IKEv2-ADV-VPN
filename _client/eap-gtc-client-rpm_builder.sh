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
    echo "This script must be run as root." 1>&2
    exit 1
fi

# Prompt for VPN configuration details
read -p "Enter the VPN server address: " server_address
if [ -z "$server_address" ]; then
    error_exit "Server address cannot be empty."
fi

read -p "Enter the remote subnets (e.g., 192.168.1.0/24): " remote_subnets
if [ -z "$remote_subnets" ]; then
    error_exit "Remote subnets cannot be empty."
fi

# Update package lists and install dependencies
dnf update -y || error_exit "Failed to update package lists."
dnf install -y gcc gmp-devel openssl-devel libcap-devel \
    libcurl-devel systemd-devel json-c-devel nss-tools pkg-config \
    automake gawk flex bison gperf wget curl bzip2 rpm-build \
    || error_exit "Failed to install build dependencies."

# Set up RPM build directories
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS} || error_exit "Failed to create RPM build directories."

# Determine the latest StrongSwan version
latest_version=$(curl -s https://download.strongswan.org/ | grep -oP 'strongswan-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.bz2)' | sort -V | tail -1)
if [ -z "$latest_version" ]; then
    error_exit "Failed to determine the latest StrongSwan version."
fi
log "Latest StrongSwan version is $latest_version"

# Download and extract the StrongSwan source
tarball="strongswan-$latest_version.tar.bz2"
download_url="https://download.strongswan.org/$tarball"
wget -P ~/rpmbuild/SOURCES/ "$download_url" || error_exit "Failed to download StrongSwan source."

# Create the RPM spec file
cat > ~/rpmbuild/SPECS/strongswan-gtc.spec <<EOF
Name: strongswan-gtc
Version: 6.0.0
Release: 1%{?dist}
Summary: StrongSwan VPN package with EAP-GTC authentication
License: GPL-2.0-or-later
URL: https://www.strongswan.org
Source0: strongswan-6.0.0.tar.bz2
BuildRequires: gcc, gmp-devel, openssl-devel, libcap-devel, libcurl-devel, systemd-devel, json-c-devel, nss-tools, pkg-config, gperf, wget, curl, bzip2
Requires: iproute, systemd, curl, nss-tools
Conflicts: strongswan, strongswan-charon, strongswan-libcharon, strongswan-ipsec, strongswan-starter, charon-systemd, strongswan-swanctl

%description
This package provides StrongSwan with EAP-GTC authentication support, configured for VPN connections.

%prep
# Ensure correct directory name
%setup -q -n strongswan-6.0.0

%build
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
    --with-systemdsystemunitdir=/lib/systemd/system

make -j$(nproc)

%install
# Ensure buildroot exists and is empty
rm -rf %{buildroot}
mkdir -p %{buildroot}

make install DESTDIR=%{buildroot}

mkdir -p %{buildroot}/etc/ipsec.d
mkdir -p %{buildroot}/etc/strongswan

cat > %{buildroot}/etc/ipsec.d/eap-gtc.conf <<EOC
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
EOC

cat > %{buildroot}/etc/ipsec.conf <<EOC
include ipsec.d/*.conf
EOC

cat > %{buildroot}/etc/strongswan/strongswan.conf <<EOC
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
EOC

%post
cat > "/etc/ipsec.d/post-setup.sh" <<'EOP'
#!/bin/bash

server_address=${server_address}
ca_url="http://$server_address/ca"
ca_cert_path="/etc/ipsec.d/cacerts/ca.crt"

mkdir -p /etc/ipsec.d/cacerts
wget -q "$ca_url" -O "$ca_cert_path" || echo "Failed to fetch CA certificate."

cat <<EOM

==========================================
   StrongSwan EAP-GTC Setup Complete
==========================================

1️⃣  Create authentication file:
    sudo nano /etc/ipsec.secrets

2️⃣  Add:
    your_username@example.com : EAP "your_password"

3️⃣  Restart VPN service:
    sudo systemctl restart strongswan
    sudo ipsec start

4️⃣  Connect VPN:
    sudo ipsec up eap-gtc

==========================================
EOM
EOP
chmod +x /etc/ipsec.d/post-setup.sh
bash /etc/ipsec.d/post-setup.sh

%files
%config(noreplace) /etc/strongswan/ipsec.conf
%config(noreplace) /etc/ipsec.d/eap-gtc.conf
/usr/lib/systemd/system/strongswan.service

%changelog
* Tue Feb 26 2025 Your Name <you@example.com> - 6.0.0-1
- Initial build for StrongSwan with EAP-GTC support

EOF

# Build the RPM package
rpmbuild -bb ~/rpmbuild/SPECS/strongswan-gtc.spec || error_exit "Failed to build RPM package."

log "RPM package built successfully. You can find it in ~/rpmbuild/RPMS/."
