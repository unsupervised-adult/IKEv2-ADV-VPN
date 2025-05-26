1. Create Zone-Specific Certificate Roles
You can create a script that duplicates the existing client role for each security zone, adding the appropriate zone attribute. Since your Vault setup already has comprehensive role capabilities, this would fit perfectly:
bashCopy#!/bin/bash
# Script to create zone-specific certificate roles in Vault

# Load configuration
source /etc/strongconn.conf
source /etc/zt/ztna.conf/zones.conf

# Base parameters from existing client role
BASE_ROLE_PARAMS=$(vault read -format=json pki/roles/client | jq '.data')

# For each defined ZTNA zone
for zone_var in $(compgen -v ZTNA_ZONE_ | grep '_NAME$'); do
    ZONE_ID=$(echo "$zone_var" | sed 's/ZTNA_ZONE_\(.*\)_NAME/\1/')
    ZONE_NAME="${!zone_var}"
    ZONE_ATTRIB_VAR="ZTNA_ZONE_${ZONE_ID}_OKTA_RAD_ATTRIB"
    ZONE_ATTRIB="${!ZONE_ATTRIB_VAR}"
    
    if [ -z "$ZONE_ATTRIB" ]; then
        echo "No OKTA attribute found for zone $ZONE_NAME, skipping"
        continue
    fi
    
    echo "Creating certificate role for zone: $ZONE_NAME (attribute: $ZONE_ATTRIB)"
    
    # Create JSON for the new role with zone-specific OU
    ROLE_JSON=$(echo "$BASE_ROLE_PARAMS" | jq --arg zone "$ZONE_ATTRIB" '.ou = ["ZTNAZone:\($zone)"]')
    
    # Create the role in Vault
    echo "$ROLE_JSON" | vault write "pki/roles/client-zone-${ZONE_ID}" -
    
    echo "Created certificate role: client-zone-${ZONE_ID}"
done

echo "Zone-specific certificate roles created"
2. Integrate with Okta Provisioning
Since Okta already provisions the certificates, you could modify the certificate generation task in your tasks.py to use the appropriate zone-specific role:
pythonCopy@celery_app.task(name="tasks.process_certificate_task")
def process_certificate_task(user_email, action, security_zone=None):
    """Handle certificate generation & revocation with zone awareness."""
    if action == "generate":
        logger.info(f"Generating certificate for {user_email}")
        
        # Determine which certificate role to use based on security zone
        cert_role = "client"  # default role
        if security_zone:
            # Normalize zone name to match role naming
            zone_id = security_zone.lower().replace(' ', '')
            zone_role = f"client-zone-{zone_id}"
            
            # Check if zone-specific role exists
            try:
                subprocess.run(["vault", "read", f"pki/roles/{zone_role}"], 
                              check=True, capture_output=True)
                cert_role = zone_role
                logger.info(f"Using zone-specific certificate role: {cert_role}")
            except subprocess.CalledProcessError:
                logger.warning(f"Zone role {zone_role} not found, using default client role")
        
        # Generate certificate using appropriate role
        subprocess.run(["sudo", VPKI_SCRIPT, "generate-client", user_email, "2555", cert_role], check=True)
        send_certificate_email(user_email)
        
    elif action == "revoke":
        logger.info(f"Revoking certificate for {user_email}")
        serial = get_serial_for_user(user_email)
        if serial:
            subprocess.run(["sudo", VPKI_SCRIPT, "revoke-pki", serial], check=True)
3. Update the v-pki Tool
Modify your v-pki script to accept the certificate role as an optional parameter:
bashCopyfunction generate_client() {
    local email=$1
    local ttl=$2
    local cert_role=${3:-"client"}  # Use 'client' as default role
    source "$CONFIG_PATH"  # Load config variables
    
    if [[ -z "$email" || -z "$ttl" ]]; then
        echo "Usage: generate-client EMAIL TTL(in days) [CERT_ROLE]"
        exit 1
    fi
    
    # Rest of your existing code...
    
    echo "Generating client certificate for $email with TTL $ttl using role $cert_role..."
    local response=$(vault write -format=json \
        "pki/issue/$cert_role" \
        common_name="$email" \
        ttl="${ttl}d" \
        server_flag=false \
        client_flag=true \
        alt_names="email:$email")
        
    # Rest of your existing code...
}
4. Update ZTNA Updown Script
Enhance the ztna-updown.sh script to detect the zone from certificate attributes:
bashCopy# Extract security zone from authentication method
if [ -n "${PLUTO_RADIUS_ATTR_Security_Zone}" ]; then
    # RADIUS-based auth
    SECURITY_ZONE="${PLUTO_RADIUS_ATTR_Security_Zone}"
    log "Using RADIUS attribute for zone: $SECURITY_ZONE"
elif [ -n "${PLUTO_CERT}" ]; then
    # Certificate-based auth
    CERT_TEMP="/tmp/cert_${PLUTO_UNIQUEID}.pem"
    echo "${PLUTO_CERT}" > "$CERT_TEMP"
    
    CERT_DATA=$(openssl x509 -noout -subject -in "$CERT_TEMP" 2>/dev/null)
    rm -f "$CERT_TEMP"
    
    if [[ "$CERT_DATA" =~ OU=ZTNAZone:([^/,]+) ]]; then
        SECURITY_ZONE="${BASH_REMATCH[1]}"
        log "Extracted security zone from certificate OU: $SECURITY_ZONE"
    else
        log "No security zone found in certificate OU, using default"
        SECURITY_ZONE="default"
    fi
else
    log "No zone information available, using default"
    SECURITY_ZONE="default"
fi
5. Complete the Flow
To complete the flow:

Okta event hook triggers certificate issuance
Your script determines the appropriate security zone for the user
The certificate is issued using the zone-specific role, embedding the zone in the OU
When the user connects via EAP-TLS, StrongSwan passes the certificate data to your updown script
The script extracts the zone information and applies the same ZTNA policies
