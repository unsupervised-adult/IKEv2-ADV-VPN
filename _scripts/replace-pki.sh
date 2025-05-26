#!/bin/bash
# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
# =================================================================================================
# StrongConn Intermediate CA CSR and Import Tool
# This script has two main operations:
# 1. Generate a CSR for an intermediate CA using Vault
# 2. Import a signed certificate and configure for signing

# Environment
source /etc/strongconn.conf

# Directly set Vault environment variables from config
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_TOKEN="$VAULT_TOKEN"

working_dir="/tmp/intermediate_ca_op"
mkdir -p "$working_dir"

# Function to generate a CSR using Vault
generate_intermediate_csr() {
    echo "=================================================================================================="
    echo "             StrongConn Intermediate CA CSR Generation Tool                                       "
    echo "=================================================================================================="
    echo "This will generate a CSR for an intermediate CA using Vault to submit to your root CA."
    echo ""
    
    # Enable a new PKI mount for the intermediate CA if not already enabled
    if ! vault secrets list -format=json | jq -r '.["pki_int/"]' &>/dev/null; then
        echo "Enabling PKI secrets engine at pki_int..."
        vault secrets enable -path=pki_int pki
        vault secrets tune -max-lease-ttl=43800h pki_int  # 5 years max TTL
    fi
    
    read -p "Common Name for Intermediate CA [StrongConn Intermediate CA]: " common_name
    common_name=${common_name:-"StrongConn Intermediate CA"}
    
    read -p "Organization [StrongConn VPN]: " organization
    organization=${organization:-"StrongConn VPN"}
    
    read -p "Country Code [US]: " country
    country=${country:-"US"}
    
    read -p "State/Province: " state
    read -p "City/Locality: " locality
    read -p "Email Address: " email
    
    read -p "Key Size (2048/4096) [4096]: " key_size
    key_size=${key_size:-4096}
    
    read -p "CSR Output Path [/root/strongconn_intermediate.csr]: " csr_path
    csr_path=${csr_path:-"/root/strongconn_intermediate.csr"}
    
    echo "Generating intermediate CA CSR in Vault..."
    vault write -format=json pki_int/intermediate/generate/internal \
        common_name="$common_name" \
        organization="$organization" \
        country="$country" \
        province="$state" \
        locality="$locality" \
        email="$email" \
        key_bits="$key_size" \
        ttl="43800h" > "$working_dir/intermediate.json"
    
    if [ $? -ne 0 ]; then
        echo "Failed to generate CSR in Vault!"
        return 1
    fi
    
    # Extract CSR from Vault response
    cat "$working_dir/intermediate.json" | jq -r '.data.csr' > "$csr_path"
    
    echo ""
    echo "CSR generation complete!"
    echo "Your CSR has been saved to: $csr_path"
    echo "The private key is securely stored in Vault's pki_int backend."
    echo ""
    echo "Submit this CSR to your root CA to get it signed."
    echo "After receiving the signed certificate, run this script again with the import option."
    echo "=================================================================================================="
    
    rm -f "$working_dir/intermediate.json"
}

# Function to import signed certificate and configure for signing
import_signed_certificate() {
    local int_cert_file="$1"
    local root_cert_file="$2"
    local chain_file="$3"
    
    echo "=================================================================================================="
    echo "             StrongConn Intermediate CA Import Tool                                               "
    echo "=================================================================================================="
    echo "This script will:"
    echo "  1. Stop StrongSwan and related services"
    echo "  2. Clear the existing Vault PKI backends (pki and pki_int)"
    echo "  3. Import the signed intermediate certificate and CA chain"
    echo "  4. Configure roles for signing"
    echo "  5. Restart services"
    echo ""
    echo "NOTE: All existing client certificates will need to be regenerated!"
    echo "=================================================================================================="
    read -p "Do you want to proceed? (yes/no): " proceed
    
    if [[ "$proceed" != "yes" ]]; then
        echo "Operation cancelled."
        return 1
    fi
    
    if [ ! -f "$int_cert_file" ] || [ ! -f "$root_cert_file" ] || [ ! -f "$chain_file" ]; then
        echo "Error: One or more certificate files not found."
        return 1
    fi
    
    echo "Stopping StrongSwan and related services..."
    systemctl stop strongswan nginx
    
    echo "WARNING: This will clear the existing Vault PKI engines (pki and pki_int) and all certificates."
    read -p "Are you sure you want to clear Vault PKI? (yes/no): " clear_vault
    if [[ "$clear_vault" != "yes" ]]; then
        echo "Operation cancelled."
        return 1
    fi
    
    echo "Clearing Vault PKI backends..."
    vault secrets disable pki 2>/dev/null
    vault secrets disable pki_int 2>/dev/null
    vault secrets enable -path=pki_int pki
    vault secrets tune -max-lease-ttl=43800h pki_int
    
    echo "Importing signed intermediate certificate with CA chain to Vault..."
    # Import with the full chain to establish trust
    vault write pki_int/intermediate/set-signed certificate=@"$chain_file"
    if [ $? -ne 0 ]; then
        echo "Failed to import signed intermediate certificate to Vault"
        return 1
    fi

    echo "Signed intermediate certificate imported successfully."
    
    echo "Setting default issuer..."
    ISSUER_ID=$(vault list -format=json pki_int/issuers | jq -r '.[0]')
    if [ -z "$ISSUER_ID" ]; then
        echo "Failed to get issuer ID. Aborting operation!"
        return 1
    fi
    
    vault write pki_int/config/issuers default="$ISSUER_ID"
    
    echo "Configuring URLs for the new CA..."
    vault write pki_int/config/urls \
        issuing_certificates="http://$PUBLIC_IP/v1/pki_int/ca" \
        crl_distribution_points="http://$PUBLIC_IP/v1/pki_int/crl" \
        ocsp_servers="http://$PUBLIC_IP/v1/pki_int/ocsp"

    echo "Configuring roles for signing..."
    declare -A roles
    roles=(
        ["ocsp"]='{"allowed_domains": ["'"$PUBLIC_IP"'", "*"], "allow_ip_sans": true, "allow_any_name": true, "max_ttl": "85500h", "key_usage": "DigitalSignature", "ext_key_usage": "OCSPSigning", "ext_key_usage_oids": "1.3.6.1.5.5.7.3.9", "use_pss": true, "server_flag": false, "client_flag": false, "key_bits": 4096}'
        ["server-ip"]='{"allowed_domains": ["'"$PUBLIC_IP"'", "*"], "use_pss": true, "allow_subdomains": false, "allow_any_name": true, "allow_ip_sans": true, "max_ttl":"'"85500h"'", "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement,DataEncipherment", "ext_key_usage": "ServerAuth,IPsecTunnel,IPsecIntermediate", "ext_key_usage_oids": "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.6", "server_flag": true, "client_flag": false}'
        ["server-dns"]='{"allowed_domains": ["'"$DNS_NAME"'", "*"], "allow_subdomains": true, "allow_any_name": true, "use_pss": true, "max_ttl":"'"85500h"'", "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement,DataEncipherment", "ext_key_usage": "ServerAuth,IPsecTunnel,IPsecIntermediate", "ext_key_usage_oids": "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.6", "server_flag": true, "client_flag": false}'
        ["vault"]='{"allowed_domains": ["'"$PUBLIC_IP"'", "*"], "allow_ip_sans": true, "allow_subdomains": false, "allow_any_name": true, "max_ttl":"'"85500h"'", "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement,DataEncipherment", "ext_key_usage": "ServerAuth", "max_ttl": "87600h", "use_pss": true, "server_flag": true, "client_flag": false}'
        ["boundary-ip"]='{"allowed_domains": "*", "allow_ip_sans": true, "allow_subdomains": false, "allow_any_name": true, "max_ttl":"'"85500h"'", "key_usage": "DigitalSignature,KeyEncipherment,KeyAgreement,DataEncipherment", "ext_key_usage": "ServerAuth", "max_ttl": "87600h", "use_pss": true, "server_flag": true, "client_flag": false}'
        ["client"]='{"allowed_domains": "*", "allow_subdomains": false, "allow_any_name": true, "max_ttl": "25920h", "use_pss": true, "key_usage": "DigitalSignature,KeyAgreement,KeyEncipherment,DataEncipherment", "ext_key_usage": "clientAuth,IPsecUser", "ext_key_usage_oids": "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.7", "enforce_hostnames": false, "key_bits": 4096, "server_flag": false, "client_flag": true}'
        ["hostname"]='{"allowed_domains": "*", "allow_subdomains": true, "allow_any_name": true, "use_pss": true, "max_ttl": "25920h", "key_usage": "DigitalSignature,KeyAgreement,KeyEncipherment,DataEncipherment", "ext_key_usage": "clientAuth,IPsecEndSystem,IPSecUser", "ext_key_usage_oids": "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.5", "enforce_hostnames": true, "key_bits": 4096, "server_flag": false, "client_flag": true}'
    )

    for role in "${!roles[@]}"; do
        echo "Creating role: $role"
        echo "${roles[$role]}" | vault write "pki_int/roles/$role" -
    done

    # After creating roles, regenerate certificates
    echo "Regenerating critical certificates..."
    
    # Generate OCSP responder certificate
    echo "Generating OCSP responder certificate..."
    vault write -format=json pki_int/issue/ocsp \
        common_name="OCSP Responder" \
        ttl="85500h" > "$working_dir/ocsp.json"
    
    if [ $? -eq 0 ]; then
        cat "$working_dir/ocsp.json" | jq -r '.data.certificate' > "$CERT_DIR/ocsp.pem"
        cat "$working_dir/ocsp.json" | jq -r '.data.private_key' > "$PRIVATE_DIR/ocsp-key.pem"
    else
        echo "Warning: Failed to generate OCSP certificate."
    fi
    
    # Generate Vault server certificate
    echo "Generating Vault server certificate..."
    vault write -format.json pki_int/issue/vault \
        common_name="$PUBLIC_IP" \
        alt_names="localhost" \
        ip_sans="127.0.0.1,$PUBLIC_IP" \
        ttl="87600h" > "$working_dir/vault.json"
    
    if [ $? -eq 0 ]; then
        cat "$working_dir/vault.json" | jq -r '.data.certificate' > "$CERT_DIR/vault.pem"
        cat "$working_dir/vault.json" | jq -r '.data.private_key' > "$PRIVATE_DIR/vault-key.pem"
    else
        echo "Warning: Failed to generate Vault certificate."
    fi
    
    # Generate VPN server certificate (server-ip role)
    echo "Generating VPN server certificate..."
    vault write -format=json pki_int/issue/server-ip \
        common_name="$PUBLIC_IP" \
        ip_sans="$PUBLIC_IP" \
        ttl="85500h" > "$working_dir/server-ip.json"
    
    if [ $? -eq 0 ]; then
        cat "$working_dir/server-ip.json" | jq -r '.data.certificate' > "$CERT_DIR/server.pem"
        cat "$working_dir/server-ip.json" | jq -r '.data.private_key' > "$PRIVATE_DIR/server-key.pem"
    else
        echo "Warning: Failed to generate server-ip certificate."
    fi
    
    # Generate server-dns certificate if DNS_NAME is defined
    if [ -n "$DNS_NAME" ]; then
        echo "Generating DNS server certificate..."
        vault write -format=json pki_int/issue/server-dns \
            common_name="$DNS_NAME" \
            ttl="85500h" > "$working_dir/server-dns.json"
        
        if [ $? -eq 0 ]; then
            cat "$working_dir/server-dns.json" | jq -r '.data.certificate' > "$CERT_DIR/dns.pem"
            cat "$working_dir/server-dns.json" | jq -r '.data.private_key' > "$PRIVATE_DIR/dns-key.pem"
        else
            echo "Warning: Failed to generate server-dns certificate."
        fi
    fi
    
    # Generate Boundary certificate
    echo "Generating Boundary certificate..."
    vault write -format=json pki_int/issue/boundary-ip \
        common_name="$PUBLIC_IP" \
        ip_sans="$PUBLIC_IP" \
        ttl="85500h" > "$working_dir/boundary.json"
    
    if [ $? -eq 0 ]; then
        cat "$working_dir/boundary.json" | jq -r '.data.certificate' > "$CERT_DIR/boundary.pem"
        cat "$working_dir/boundary.json" | jq -r '.data.private_key' > "$PRIVATE_DIR/boundary-key.pem"
    else
        echo "Warning: Failed to generate boundary certificate."
    fi

    echo "Generating example server certificate..."
    vault write -format=json pki_int/issue/server \
        common_name="$PUBLIC_IP" \
        ttl="85500h" > "$working_dir/server.json"
    
    if [ $? -eq 0 ]; then
        cat "$working_dir/server.json" | jq -r '.data.certificate' > "$CERT_DIR/server.pem"
        cat "$working_dir/server.json" | jq -r '.data.private_key' > "$PRIVATE_DIR/server-key.pem"
    else
        echo "Warning: Failed to generate test server certificate. Roles may need adjustment."
    fi
    
    # Store all certificates in the appropriate locations
    echo "Storing certificates in the appropriate locations..."
    cp "$int_cert_file" "$CERT_DIR/ca.pem"  # Intermediate CA
    cp "$root_cert_file" "$CERT_DIR/root_ca.pem"  # Root CA
    cp "$chain_file" "$CERT_DIR/ca_chain.pem"  # Full CA chain
    
    # Backup old certificates
    backup_dir="/var/backups/strongswan-certs-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    cp -a "$CERT_DIR" "$backup_dir/"
    cp -a "$PRIVATE_DIR" "$backup_dir/"
    echo "Original certificates backed up to $backup_dir"
    
    # Cleanup
    rm -rf "$working_dir"
    
    echo "Fixing permissions..."
    strongconn.sh -set-permissions
    
    echo "Restarting services..."
    systemctl start strongswan nginx
    
    echo "Reloading SwanCtl configuration..."
    swanctl --load-all
    
    echo "Checking StrongSwan status..."
    swanctl --list-authorities
    swanctl --list-certs
    
    echo "Intermediate CA import complete and configured for signing!"
    return 0
}

# Main script
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

echo "StrongConn Intermediate CA Tool"
echo "-------------------------------"
echo "1. Generate CSR for Intermediate CA"
echo "2. Import Signed Intermediate Certificate"
echo ""
read -p "Select operation (1 or 2): " operation

case $operation in
    1)
        generate_intermediate_csr
        ;;
    2)
        read -p "Path to the signed intermediate certificate file: " int_cert_file
        read -p "Path to the root CA certificate file: " root_cert_file
        
        if [ ! -f "$int_cert_file" ]; then
            echo "Error: Intermediate certificate file not found: $int_cert_file"
            exit 1
        fi
        
        if [ ! -f "$root_cert_file" ]; then
            echo "Error: Root CA certificate file not found: $root_cert_file"
            exit 1
        fi
        
        # Create certificate chain - intermediate followed by root
        echo "Creating certificate chain bundle..."
        cat "$int_cert_file" "$root_cert_file" > "$working_dir/ca_chain.pem"
        
        import_signed_certificate "$int_cert_file" "$root_cert_file" "$working_dir/ca_chain.pem"
        ;;
    *)
        echo "Invalid option. Please select 1 or 2."
        exit 1
        ;;
esac

# Exit status
if [ $? -eq 0 ]; then
    echo ""
    echo "=================================================================================================="
    echo "Operation completed successfully."
    if [ "$operation" -eq 2 ]; then
        echo ""
        echo "Next steps:"
        echo "  1. Verify that StrongSwan is operating correctly"
        echo "  2. Regenerate client certificates using 'vault write pki_int/issue/client ...'"
        echo "  3. Regenerate server certificates using 'vault write pki_int/issue/server ...'"
    fi
    echo "=================================================================================================="
    exit 0
else
    echo ""
    echo "=================================================================================================="
    echo "Operation failed. Check logs for details."
    echo "=================================================================================================="
    exit 1
fi