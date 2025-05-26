#!/bin/bash

# Check if the script is run with sudo privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo."
    exit 1
fi

# Check if the output file is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 /path/to/shh_output.txt"
    echo "Provide the full output from 'shh service finish-profile' in the specified file."
    exit 1
fi

OUTPUT_FILE="$1"

# Array of services to exclude (e.g., ssh.service)
EXCLUDED_SERVICES=("ssh.service")

# Array to store processed services for restarting later
PROCESSED_SERVICES=()

# Variables to track parsing state
current_service=""
override_file=""
in_options=0

# Read and parse the output file line by line
while IFS= read -r line; do
    # Extract service name from 'stop <service_name>.service' line
    if [[ $line =~ stop\ (.+)\.service ]]; then
        service_name="${BASH_REMATCH[1]}.service"
        # Check if the service is not in the excluded list
        if [[ ! " ${EXCLUDED_SERVICES[@]} " =~ " $service_name " ]]; then
            current_service="$service_name"
            echo "Processing $current_service"
            # Create the systemd override directory
            override_dir="/etc/systemd/system/$current_service.d"
            mkdir -p "$override_dir" || { echo "Failed to create $override_dir"; continue; }
            override_file="$override_dir/shh.conf"
            # Initialize the override file with the [Service] section
            echo "[Service]" > "$override_file" || { echo "Failed to write to $override_file"; continue; }
            # Add the service to the list for restarting
            PROCESSED_SERVICES+=("$current_service")
            in_options=0
        else
            echo "Skipping $service_name ."
        fi
    # Detect the start of the options section
    elif [[ $line == "INFO  [shh] Resolved systemd options:" ]]; then
        in_options=1
    # Process lines within the options section
    elif [ "$in_options" -eq 1 ] && ! [[ $line =~ ^INFO ]]; then
        # Handle SystemCallFilter to remove @sandbox:EPERM
        if [[ $line == SystemCallFilter=* ]]; then
            value=${line#*=}  # Extract everything after the equals sign
            IFS=' ' read -r -a groups <<< "$value"  # Split the value into an array by spaces
            filtered_groups=()
            # Filter out @sandbox:EPERM
            for group in "${groups[@]}"; do
                if [ "$group" != "@sandbox:EPERM" ]; then
                    filtered_groups+=("$group")
                fi
            done
            # Reconstruct the SystemCallFilter line
            new_value=$(IFS=' '; echo "${filtered_groups[*]}")
            echo "SystemCallFilter=$new_value" >> "$override_file"
        else
            # Write other option lines as-is
            echo "$line" >> "$override_file"
        fi
    # Stop collecting options when a new INFO line is encountered
    elif [[ $line =~ ^INFO ]]; then
        in_options=0
    fi
done < "$OUTPUT_FILE"

# Reload systemd daemon to apply the new override files
echo "Reloading systemd daemon..."
systemctl daemon-reload || echo "WARNING: Failed to reload systemd daemon"

# Restart all processed services to apply the configurations
for service in "${PROCESSED_SERVICES[@]}"; do
    echo "Restarting $service..."
    systemctl restart "$service" || echo "WARNING: Failed to restart $service"
done

# Display a summary of the processed services
echo "Override files created and installed successfully for the following services:"
for service in "${PROCESSED_SERVICES[@]}"; do
    echo "- $service"
done
