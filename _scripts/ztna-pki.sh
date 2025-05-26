#!/bin/bash
# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
# =================================================================================================
# /usr/local/bin/ha_manager.sh
# HA Manager with dialog frontend that runs CLI scripts
#
# Author: Felix C Frank 2024
# Version: 1.7.50.1
# Created: 27-12-24
## feedback mailto:felix.c.frank@proton.me
###############################################################################
# ================================================
# ztna-cert-zones.sh
# 
# Dialog-based UI for managing zone-specific certificates
# Integrates with existing ZTNA zones and v-pki functionality
# ================================================

CONFIG_PATH="/etc/strongconn.conf"
ZONES_CONFIG="/etc/zt/ztna.conf/zones.conf"
LOG_FILE="/var/log/ztna/cert-zones.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

error_exit() {
    log "ERROR: $1"
    echo "ERROR: $1" >&2
    exit 1
}

# Check if dialog is installed
if ! command -v dialog >/dev/null; then
    log "Installing dialog package..."
    apt-get update -y && apt-get install -y dialog || error_exit "Failed to install dialog"
fi

# Load required configuration
source "$CONFIG_PATH" 2>/dev/null || error_exit "Failed to load $CONFIG_PATH"
source "$ZONES_CONFIG" 2>/dev/null || log "Warning: ZTNA zones configuration not found at $ZONES_CONFIG"

# Check if Vault token is available
if [ -z "$VAULT_TOKEN" ]; then
    error_exit "VAULT_TOKEN not found in configuration. Cannot proceed."
fi

export VAULT_ADDR="https://127.0.0.1:8200"

# Dialog UI constants for consistent sizing
DIALOG_WIDTH_SMALL=50    # For small dialogs (confirmation, messages)
DIALOG_WIDTH_MEDIUM=60   # For medium dialogs (forms, menus)
DIALOG_WIDTH_LARGE=70    # For large dialogs (help texts, detailed forms)
DIALOG_HEIGHT_SMALL=7    # For small dialogs (confirmations)
DIALOG_HEIGHT_MEDIUM=10  # For medium dialogs (messages, small forms)
DIALOG_HEIGHT_LARGE=15   # For large dialogs (menus, large forms)
DIALOG_HEIGHT_XLARGE=20  # For very large dialogs (help, detailed data)

# Temporary file for dialog output
TEMP_FILE=$(mktemp)
trap 'rm -f $TEMP_FILE; log "Script interrupted, cleaned up temporary files"' EXIT INT TERM

# Function to create zone-specific certificate roles
create_zone_roles() {
    log "Creating zone-specific certificate roles in Vault..."
    
    # Get base parameters from existing client role
    BASE_ROLE_JSON=$(vault read -format=json pki/roles/client | jq '.data') || {
        log "Failed to read base client role from Vault"
        dialog --title "Error" --msgbox "Failed to read base client role from Vault. Make sure Vault is running and the client role exists." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 1
    }
    
    # Count of created roles
    local created_count=0
    local progress=0
    local total_zones=0
    
    # Count total zones first for progress calculation
    for zone_var in $(compgen -v | grep "^ZTNA_ZONE_.*_NAME$"); do
        ((total_zones++))
    done
    
    if [ $total_zones -eq 0 ]; then
        dialog --title "No Zones Found" --msgbox "No ZTNA zones found in configuration. Please define zones first using 'ztna.sh'." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 1
    fi
    
    # Progress dialog
    (
        echo "0"
        echo "XXX"
        echo "Preparing to create zone roles..."
        echo "XXX"
        
        # Process each defined ZTNA zone
        for zone_var in $(compgen -v | grep "^ZTNA_ZONE_.*_NAME$"); do
            ZONE_ID=$(echo "$zone_var" | sed 's/ZTNA_ZONE_\(.*\)_NAME$/\1/')
            ZONE_NAME="${!zone_var}"
            
            progress=$((progress + 100 / total_zones))
            echo "$progress"
            echo "XXX"
            echo "Creating role for zone: $ZONE_NAME ($ZONE_ID)"
            echo "XXX"
            
            # Create JSON for role with zone-specific OU field
            ROLE_JSON=$(echo "$BASE_ROLE_JSON" | jq --arg zone "$ZONE_ID" '.ou = ["ZTNA-Zone:\($zone)"]')
            
            # Create the role in Vault
            if echo "$ROLE_JSON" | vault write "pki/roles/zone-${ZONE_ID}" - >/dev/null 2>&1; then
                log "Created certificate role: zone-${ZONE_ID}"
                ((created_count++))
            else
                log "Failed to create role for zone: $ZONE_NAME ($ZONE_ID)"
            fi
            
            sleep 0.5  # Add slight delay for progress visibility
        done
        
        echo "100"
        echo "XXX"
        echo "Completed creating $created_count zone roles"
        echo "XXX"
        sleep 1
    ) | dialog --title "Creating Zone Roles" --gauge "Creating certificate roles for ZTNA zones..." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM 0
    
    if [ $created_count -eq 0 ]; then
        dialog --title "Warning" --msgbox "No zone-specific certificate roles created. Check the logs for details." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 1
    else
        dialog --title "Success" --msgbox "Successfully created $created_count zone-specific certificate roles." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 0
    fi
}

# Function to list all zone-specific roles
list_zone_roles() {
    log "Listing zone-specific certificate roles..."
    
    # Get all zone roles
    local roles=$(vault list pki/roles 2>/dev/null | grep "zone-" || echo "")
    local role_info=""
    local count=0
    
    if [ -z "$roles" ]; then
        dialog --title "No Zone Roles" --msgbox "No zone-specific certificate roles found. You can create them by selecting 'Create Zone Roles'." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 1
    fi
    
    # Build role information
    while read -r role; do
        if [ -n "$role" ]; then
            local zone_info=$(vault read -format=json "pki/roles/$role" | jq -r '.data.ou[0]' 2>/dev/null)
            role_info="${role_info}\n${role}: ${zone_info}"
            ((count++))
        fi
    done <<< "$roles"
    
    dialog --title "Zone Certificate Roles" --msgbox "Found $count zone-specific certificate roles:\n$role_info" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_MEDIUM
    return 0
}

# Function to patch the ZTNA updown script
patch_updown_script() {
    log "Patching ZTNA updown script for certificate-based zone detection..."
    
    UPDOWN_SCRIPT="/var/lib/strongswan/ztna-updown.sh"
    BACKUP_FILE="${UPDOWN_SCRIPT}.bak.$(date +%Y%m%d%H%M%S)"
    
    # Check if script exists
    if [ ! -f "$UPDOWN_SCRIPT" ]; then
        log "Error: ZTNA updown script not found at $UPDOWN_SCRIPT"
        dialog --title "Error" --msgbox "ZTNA updown script not found at $UPDOWN_SCRIPT. Make sure ZTNA is properly configured." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 1
    fi
    
    # Check if already patched
    if grep -q "ZTNA-Zone:" "$UPDOWN_SCRIPT"; then
        log "ZTNA updown script already patched for certificate-based zone detection"
        dialog --title "Already Patched" --msgbox "ZTNA updown script is already patched for certificate-based zone detection." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 0
    fi
    
    # Backup original script
    cp -f "$UPDOWN_SCRIPT" "$BACKUP_FILE" || {
        log "Error: Failed to back up existing updown script"
        dialog --title "Backup Failed" --msgbox "Failed to create backup of ZTNA updown script. Aborting patch operation." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 1
    }
    
    # Show progress dialog
    (
        echo "10"
        echo "XXX"
        echo "Creating backup of updown script..."
        echo "XXX"
        sleep 1
        
        echo "30"
        echo "XXX"
        echo "Updating SECURITY_ZONES line..."
        echo "XXX"
        
        # Add certificate-based zone detection
        if sed -i '/^SECURITY_ZONES=/c\# Default to RADIUS attribute if available\nSECURITY_ZONES="${PLUTO_RADIUS_ATTR_Filter-Id:-}"' "$UPDOWN_SCRIPT"; then
            log "Updated SECURITY_ZONES line in updown script"
        else
            log "Failed to update SECURITY_ZONES line"
            cp -f "$BACKUP_FILE" "$UPDOWN_SCRIPT"  # Restore from backup
            echo "100"
            return 1
        fi
        sleep 1
        
        echo "60"
        echo "XXX"
        echo "Adding certificate parsing logic..."
        echo "XXX"
        
        # Add certificate parsing logic
        if sed -i '/^SECURITY_ZONES=/a\
# If no RADIUS attribute, try to extract zone from certificate\
if [ -z "$SECURITY_ZONES" ] && [ -n "${PLUTO_CERT}" ]; then\
    # Certificate-based auth\
    CERT_TEMP="/tmp/cert_${PLUTO_UNIQUEID}.pem"\
    echo -n "${PLUTO_CERT}" > "$CERT_TEMP"\
    \
    # Extract OU field\
    CERT_SUBJECT=$(openssl x509 -noout -subject -in "$CERT_TEMP" 2>/dev/null)\
    rm -f "$CERT_TEMP"\
    \
    # Look for ZTNA-Zone: pattern in OU\
    if [[ "$CERT_SUBJECT" =~ OU=ZTNA-Zone:([^/,[:space:]]+) ]]; then\
        ZONE_ID="${BASH_REMATCH[1]}"\
        log "Extracted zone ID from certificate: $ZONE_ID"\
        SECURITY_ZONES="$ZONE_ID"\
    else\
        log "No zone information found in certificate OU"\
    fi\
fi\
\
# If still no security zone, use default\
[ -z "$SECURITY_ZONES" ] && SECURITY_ZONES="default"' "$UPDOWN_SCRIPT"; then
            log "Added certificate parsing logic to updown script"
        else
            log "Failed to add certificate parsing logic"
            cp -f "$BACKUP_FILE" "$UPDOWN_SCRIPT"  # Restore from backup
            echo "100"
            return 1
        fi
        sleep 1
        
        echo "100"
        echo "XXX"
        echo "Patch completed successfully"
        echo "XXX"
        sleep 1
    ) | dialog --title "Patching ZTNA Updown Script" --gauge "Patching script for certificate-based zone detection..." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM 0
    
    dialog --title "Success" --msgbox "Successfully patched ZTNA updown script for certificate-based zone detection.\nOriginal backup saved to: $BACKUP_FILE" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
    return 0
}

# Function to generate zone-specific certificate
generate_zone_certificate() {
    log "Generating zone-specific certificate..."
    
    # Get list of available zones
    local zone_options=()
    for zone_var in $(compgen -v | grep "^ZTNA_ZONE_.*_NAME$"); do
        ZONE_ID=$(echo "$zone_var" | sed 's/ZTNA_ZONE_\(.*\)_NAME$/\1/')
        ZONE_NAME="${!zone_var}"
        zone_options+=("$ZONE_ID" "$ZONE_NAME")
    done
    
    if [ ${#zone_options[@]} -eq 0 ]; then
        dialog --title "No Zones" --msgbox "No ZTNA zones found in configuration. Please define zones first using 'ztna.sh'." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 1
    fi
    
    # Ask user to select a zone
    dialog --title "Select Zone" \
           --menu "Choose a zone for the certificate:" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_MEDIUM 8 \
           "${zone_options[@]}" 2>"$TEMP_FILE"
    
    if [ $? -ne 0 ]; then
        log "Zone selection cancelled"
        return 1
    fi
    
    SELECTED_ZONE=$(cat "$TEMP_FILE")
    SELECTED_ZONE_NAME=""
    
    for ((i=0; i<${#zone_options[@]}; i+=2)); do
        if [ "${zone_options[$i]}" = "$SELECTED_ZONE" ]; then
            SELECTED_ZONE_NAME="${zone_options[$i+1]}"
            break
        fi
    done
    
    # Check if zone role exists
    if ! vault read "pki/roles/zone-${SELECTED_ZONE}" &>/dev/null; then
        log "Certificate role 'zone-${SELECTED_ZONE}' does not exist"
        dialog --title "Role Not Found" --msgbox "Certificate role 'zone-${SELECTED_ZONE}' does not exist.\n\nPlease create zone roles first by selecting 'Create Zone Roles'." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
        return 1
    fi
    
    # Ask for email address and TTL
    dialog --title "Certificate Details" \
           --form "Enter certificate details:" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM 2 \
           "Email address:" 1 1 "" 1 20 40 0 \
           "TTL (days):" 2 1 "365" 2 20 10 0 \
           2>"$TEMP_FILE"
    
    if [ $? -ne 0 ]; then
        log "Certificate details input cancelled"
        return 1
    fi
    
    # Read form input
    mapfile -t inputs < "$TEMP_FILE"
    EMAIL="${inputs[0]}"
    TTL="${inputs[1]}"
    
    # Validate inputs
    if [ -z "$EMAIL" ]; then
        dialog --title "Error" --msgbox "Email address cannot be empty." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_SMALL
        return 1
    fi
    
    if ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        dialog --title "Error" --msgbox "Invalid email address format." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_SMALL
        return 1
    fi
    
    if ! [[ "$TTL" =~ ^[0-9]+$ ]] || [ "$TTL" -lt 1 ] || [ "$TTL" -gt 3650 ]; then
        dialog --title "Error" --msgbox "TTL must be a number between 1 and 3650." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_SMALL
        return 1
    fi
    
    # Confirm certificate generation
    dialog --title "Confirm Certificate Generation" \
           --yesno "Generate certificate with the following details?\n\nEmail: $EMAIL\nTTL: $TTL days\nZone: $SELECTED_ZONE_NAME ($SELECTED_ZONE)" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
    
    if [ $? -ne 0 ]; then
        log "Certificate generation cancelled"
        return 1
    fi
    
    # Generate certificate
    log "Generating certificate for $EMAIL with zone $SELECTED_ZONE (TTL: $TTL days)"
    
    # Show progress dialog
    (
        echo "10"
        echo "XXX"
        echo "Starting certificate generation..."
        echo "XXX"
        sleep 1
        
        echo "30"
        echo "XXX"
        echo "Generating certificate for $EMAIL..."
        echo "XXX"
        
        # Generate certificate with zone-specific role
        local output_file="/tmp/cert_gen_output.log"
        if v-pki generate-client "$EMAIL" "$TTL" "zone-${SELECTED_ZONE}" > "$output_file" 2>&1; then
            log "Certificate generated successfully"
            success=true
        else
            log "Certificate generation failed"
            success=false
        fi
        
        echo "70"
        echo "XXX"
        echo "Finalizing certificate..."
        echo "XXX"
        sleep 1
        
        echo "100"
        echo "XXX"
        if [ "$success" = true ]; then
            echo "Certificate generated successfully"
        else
            echo "Certificate generation failed"
        fi
        echo "XXX"
        sleep 1
    ) | dialog --title "Generating Certificate" --gauge "Generating certificate for $EMAIL..." $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM 0
    
    if [ -f "/opt/pki/${EMAIL}.tar.gz" ]; then
        dialog --title "Success" --msgbox "Certificate generated successfully for $EMAIL with zone $SELECTED_ZONE_NAME ($SELECTED_ZONE).\n\nCertificate package available at:\n/opt/pki/${EMAIL}.tar.gz" $DIALOG_HEIGHT_MEDIUM $DIALOG_WIDTH_MEDIUM
    else
        dialog --title "Error" --msgbox "Failed to generate certificate. Check logs for details." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        if [ -f "/tmp/cert_gen_output.log" ]; then
            dialog --title "Error Details" --textbox "/tmp/cert_gen_output.log" $DIALOG_HEIGHT_XLARGE $DIALOG_WIDTH_LARGE
        fi
        rm -f "/tmp/cert_gen_output.log"
        return 1
    fi
    
    rm -f "/tmp/cert_gen_output.log"
    return 0
}

# Function to view existing certificates by zone
view_certificates_by_zone() {
    log "Viewing certificates by zone..."
    
    # Get all certificates
    local certs_output="/tmp/certs_output.txt"
    v-pki list > "$certs_output" 2>&1
    
    # Check if any certificates exist
    if ! grep -q "Serial:" "$certs_output"; then
        dialog --title "No Certificates" --msgbox "No certificates found in the system." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        rm -f "$certs_output"
        return 1
    fi
    
    # Temporary storage for certificates by zone
    local zone_certs=()
    local zones_found=()
    
    # Process certificates to find zone information
    while IFS= read -r line; do
        if [[ "$line" =~ ^Serial:\ ([0-9a-fA-F]+) ]]; then
            current_serial="${BASH_REMATCH[1]}"
            current_subject=""
            current_zone=""
        elif [[ "$line" =~ ^Subject:\ (.*) ]]; then
            current_subject="${BASH_REMATCH[1]}"
            if [[ "$current_subject" =~ OU=ZTNA-Zone:([^/,[:space:]]+) ]]; then
                current_zone="${BASH_REMATCH[1]}"
                if ! printf '%s\0' "${zones_found[@]}" | grep -Fxqz "$current_zone"; then
                    zones_found+=("$current_zone")
                fi
            else
                current_zone="default"
                if ! printf '%s\0' "${zones_found[@]}" | grep -Fxqz "default"; then
                    zones_found+=("default")
                fi
            fi
        elif [[ "$line" =~ ^Expiry:\ (.*) ]]; then
            expiry="${BASH_REMATCH[1]}"
            # Extract common name from subject
            if [[ "$current_subject" =~ CN=([^/,]+) ]]; then
                common_name="${BASH_REMATCH[1]}"
                # Store certificate info by zone
                zone_certs+=("$current_zone" "$common_name" "$current_serial" "$expiry")
            fi
        fi
    done < "$certs_output"
    
    # Clean up temp file
    rm -f "$certs_output"
    
    if [ ${#zones_found[@]} -eq 0 ]; then
        dialog --title "No Zones" --msgbox "No zone-specific certificates found." $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_MEDIUM
        return 1
    fi
    
    # Show zone selection menu
    local zone_menu_options=()
    for zone in "${zones_found[@]}"; do
        # Count certificates in this zone
        local count=0
        for ((i=0; i<${#zone_certs[@]}; i+=4)); do
            if [ "${zone_certs[$i]}" = "$zone" ]; then
                ((count++))
            fi
        done
        zone_menu_options+=("$zone" "($count certificates)")
    done
    
    dialog --title "Select Zone" \
           --menu "Choose a zone to view certificates:" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_MEDIUM 10 \
           "${zone_menu_options[@]}" 2>"$TEMP_FILE"
    
    if [ $? -ne 0 ]; then
        log "Zone selection cancelled"
        return 1
    fi
    
    SELECTED_ZONE=$(cat "$TEMP_FILE")
    
    # Build certificate listing for selected zone
    local cert_listing=""
    for ((i=0; i<${#zone_certs[@]}; i+=4)); do
        if [ "${zone_certs[$i]}" = "$SELECTED_ZONE" ]; then
            cert_listing="${cert_listing}\n${zone_certs[$i+1]} (Serial: ${zone_certs[$i+2]}, Expiry: ${zone_certs[$i+3]})"
        fi
    done
    
    dialog --title "Certificates in Zone: $SELECTED_ZONE" \
           --msgbox "Certificates:$cert_listing" $DIALOG_HEIGHT_XLARGE $DIALOG_WIDTH_LARGE
    
    return 0
}

# Function to show help information
show_help() {
    dialog --title "Certificate Zones Help" \
           --msgbox "ZTNA Certificate Zones Management\n\nThis tool allows you to:\n\n1. Create certificate roles for each ZTNA zone\n2. Generate certificates with zone information embedded\n3. View existing certificates by zone\n4. Patch the ZTNA updown script for certificate-based zone detection\n\nZone information is embedded in the certificate's OU field, which allows the ZTNA system to automatically detect which zone a user belongs to based on their certificate.\n\nThis works alongside RADIUS-based authentication, providing a seamless experience regardless of authentication method." \
           $DIALOG_HEIGHT_XLARGE $DIALOG_WIDTH_LARGE
}

# Main menu function
main_menu() {
    while true; do
        dialog --title "ZTNA Certificate Zones Management" \
               --menu "Choose an action:" $DIALOG_HEIGHT_LARGE $DIALOG_WIDTH_MEDIUM 7 \
               1 "Create Zone Certificate Roles" \
               2 "List Zone Certificate Roles" \
               3 "Generate Zone Certificate" \
               4 "View Certificates by Zone" \
               5 "Patch ZTNA Updown Script" \
               6 "Help" \
               7 "Exit" 2>"$TEMP_FILE"
        
        if [ $? -ne 0 ]; then
            log "User cancelled operation"
            break
        fi
        
        choice=$(cat "$TEMP_FILE")
        
        case $choice in
            1) create_zone_roles ;;
            2) list_zone_roles ;;
            3) generate_zone_certificate ;;
            4) view_certificates_by_zone ;;
            5) patch_updown_script ;;
            6) show_help ;;
            7) break ;;
            *) dialog --title "Error" --msgbox "Invalid choice" $DIALOG_HEIGHT_SMALL $DIALOG_WIDTH_SMALL ;;
        esac
    done
}

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "This script must be run as root."
fi

# Run the main menu
main_menu

# Clean up
rm -f "$TEMP_FILE"
log "ZTNA Certificate Zones Management script completed."
exit 0