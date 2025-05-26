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

set -e

read -p "Enter the path to your PKCS#12 file (.p12): " p12_file
read -s -p "Enter the password for the .p12 file: " p12_password
echo ""
read -p "Enter the VPN server address: " vpn_server

echo "PKCS#12 file: $p12_file"
echo "VPN Server: $vpn_server"
read -p "Proceed with client install? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Exiting..."
    exit 1
fi

if [ ! -f "$p12_file" ] || [ ! -r "$p12_file" ]; then
    echo "ERROR: PKCS#12 file '$p12_file' not found or unreadable" >&2
    exit 1
fi

p12_basename=$(basename "$p12_file" | sed 's/\.[^.]*$//')
certname="${p12_basename}-cert"
keyname="${p12_basename}-key"
remote_subnets="10.250.0.0/16,10.242.0.0/16"

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: OpenSSL is required but not installed. Please install it (e.g., 'brew install openssl')" >&2
    exit 1
fi

if command -v ipsec >/dev/null 2>&1; then
    echo "strongSwan appears to be installed (found 'ipsec' command). Skipping Homebrew install."
else
    if ! command -v brew >/dev/null 2>&1; then
        echo "Installing Homebrew (you may be prompted for your password)..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    echo "Installing strongSwan via Homebrew..."
    brew install strongswan
fi


brew_prefix=$(brew --prefix)
strongswan_etc="$brew_prefix/etc"
ipsec_path=$(command -v ipsec)
if [ -z "$ipsec_path" ]; then
    echo "ERROR: ipsec not found after installation" >&2
    exit 1
fi


sudo mkdir -p "$strongswan_etc/ipsec.d/private" "$strongswan_etc/ipsec.d/certs" "$strongswan_etc/ipsec.d/cacerts"

echo "Extracting private key, certificate, and CA from $p12_file..."

tmp_key="/tmp/${keyname}-key.pem"
tmp_cert="/tmp/${certname}.pem"
tmp_ca="/tmp/ca.pem"

openssl pkcs12 -in "$p12_file" -nocerts -nodes -out "$tmp_key" -passin "pass:$p12_password" || {
    echo "ERROR: Failed to extract private key from $p12_file (check password)" >&2
    rm -f "$tmp_key"
    exit 1
}

openssl pkcs12 -in "$p12_file" -clcerts -nokeys -out "$tmp_cert" -passin "pass:$p12_password" || {
    echo "ERROR: Failed to extract certificate from $p12_file" >&2
    rm -f "$tmp_key" "$tmp_cert"
    exit 1
}

openssl pkcs12 -in "$p12_file" -cacerts -nokeys -out "$tmp_ca" -passin "pass:$p12_password" || {
    echo "ERROR: Failed to extract CA certificate from $p12_file" >&2
    rm -f "$tmp_key" "$tmp_cert" "$tmp_ca"
    exit 1
}


sudo mv "$tmp_key" "$strongswan_etc/ipsec.d/private/${keyname}-key.pem"
sudo mv "$tmp_cert" "$strongswan_etc/ipsec.d/certs/${certname}.pem"
sudo mv "$tmp_ca" "$strongswan_etc/ipsec.d/cacerts/ca.pem"
sudo chown root:wheel "$strongswan_etc/ipsec.d/private/${keyname}-key.pem" "$strongswan_etc/ipsec.d/certs/${certname}.pem" "$strongswan_etc/ipsec.d/cacerts/ca.pem"
sudo chmod 600 "$strongswan_etc/ipsec.d/private/${keyname}-key.pem"
sudo chmod 644 "$strongswan_etc/ipsec.d/certs/${certname}.pem" "$strongswan_etc/ipsec.d/cacerts/ca.pem"


sudo tee "$strongswan_etc/ipsec.conf" >/dev/null <<EOF
config setup
    strictcrlpolicy=yes
    uniqueids=yes

conn aws-ikev2
    keyexchange=ikev2
    left=%defaultroute
    leftid=%fromcert
    leftauth=pubkey
    leftcert=${certname}.pem
    leftsubnet=0.0.0.0/0
    leftsourceip=%config
    right=${vpn_server}
    rightid=${vpn_server}
    rightauth=pubkey
    rightsubnet=${remote_subnets}
    rightdns=%dns
    ike=aes256-sha256-ecp256,aes256gcm16-prfsha256-ecp256!
    esp=aes256-sha25,aes256gcm16!
    auto=start
    dpdaction=restart
    type=tunnel
    
EOF

sudo tee "$strongswan_etc/ipsec.secrets" >/dev/null <<EOF
: RSA $strongswan_etc/ipsec.d/private/${keyname}-key.pem
EOF



echo "Installation complete!"
echo "You can control IPsec connection below:"
echo "  sudo $ipsec_path start"
echo "  sudo $ipsec_path status"
echo "  sudo $ipsec_path stop"
echo "Logs in /var/log/ipsec.log or run '$ipsec_path statusall' to check."
echo "Service status: launchctl list | grep strongswan"
echo "Enjoy your secure VPN connection!"