#!/usr/bin/env python3

# =================================================================================================
# THIS SCRIPT IS PROVIDED AS IS WITH NO WARRANTY OR SUPPORT
# The author is not responsible for any damage or loss caused by the use of this script
# Use at your own risk
#
# StrongSwan Configuration IKEv2 Gateway
# This Python script acts as a watchdog for the Suricata IDS, blocking malicious traffic
# based on classification and internal network rules.
# =================================================================================================
# Author: Felix C Frank 2024
# Modified by: [Your Name] 2025 - Added whitelist alert notification
# Version: 1.7.50.  Updated: 2025-03-25
# =================================================================================================
# Created: 27-12-24
## feedback mailto:felix.c.frank@proton.me
# =================================================================================================
import json
import time
import subprocess
import os
import re
import socket
import smtplib
from datetime import datetime
import ipaddress
import inotify.adapters
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

# Path to eve.json log file
LOG_FILE = "/var/log/suricata/eve.json"

# Path to actions log file
LOG_ACTIONS_FILE = "/var/log/suricata_watchdog_actions/actions.log"

# Path to configuration file
CONFIG_FILE = "/etc/strongconn.conf"

# Path to classification file
CLASSIFICATION_FILE = "/etc/classifications.conf"

def load_config(config_path):
    """
    Load configuration variables from a file.
    Expected format per line: KEY="value"
    Lines starting with '#' are ignored as comments.
    """
    config = {}
    try:
        with open(config_path, "r") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        config[key.strip()] = value.strip().strip('"')
    except FileNotFoundError:
        log(f"Configuration file not found: {config_path}")
    except Exception as e:
        log(f"Error loading configuration file {config_path}: {e}")
    return config

def load_classifications(classification_path):
    """
    Load and normalize classifications from a file.
    Each classification should be on a separate line.
    Returns a set of normalized classification names.
    """
    classifications = set()
    try:
        with open(classification_path, "r") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    normalized_name = normalize_classification(line)
                    classifications.add(normalized_name)
    except FileNotFoundError:
        log(f"Classification file not found: {classification_path}")
    except Exception as e:
        log(f"Error loading classification file {classification_path}: {e}")
    return classifications

def normalize_classification(name):
    """
    Normalize classification names by removing all non-alphanumeric characters
    and converting to lowercase. This allows matching regardless of formatting.
    """
    return re.sub(r'[^a-zA-Z0-9]', '', name).lower()

def log(message):
    """
    Log messages with a timestamp to both the console and the actions log file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {message}\n"
    print(log_entry, end='') 
    try:
        os.makedirs(os.path.dirname(LOG_ACTIONS_FILE), exist_ok=True)
        with open(LOG_ACTIONS_FILE, "a") as log_file:
            log_file.write(log_entry)
            log_file.flush()  
    except Exception as e:
        print(f"Failed to write to log file: {e}")

def load_nft_set(set_name):
    """
    Load IP addresses or networks from an nftables set.
    Returns a list of ipaddress objects.
    """
    try:
        result = subprocess.run(
            ["sudo", "nft", "-j", "list", "set", "inet", "firewall", set_name],
            capture_output=True, text=True, check=True
        )
        data = result.stdout
        json_data = json.loads(data)

        nft_set = []

        for item in json_data.get('nftables', []):
            if 'set' in item:
                elements = item['set'].get('elem', [])
                for elem in elements:

                    if isinstance(elem, dict) and 'prefix' in elem:
                        network = elem['prefix']
                        nft_set.append(f"{network['addr']}/{network['len']}")
                    elif isinstance(elem, str):
                        nft_set.append(elem)

      
        return [ipaddress.ip_network(elem, strict=False) for elem in nft_set]

    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "No error message provided."
        log(f"Failed to load nft set '{set_name}': {stderr_output}")
        return []
    except Exception as e:
        log(f"Unexpected error loading nft set '{set_name}': {e}")
        return []

def is_ip_in_set(ip, set_name):
    """
    Check if an IP address is present in a specified nftables set.
    """
    try:
        ip_addr = ipaddress.ip_address(ip)
        nft_set = load_nft_set(set_name) 
        for subnet in nft_set:
            if ip_addr in subnet:
                return True
    except ValueError:
        log(f"Invalid IP address format: {ip}")
    except Exception as e:
        log(f"Error checking set '{set_name}' for IP {ip}: {e}")
    return False

def blacklist_ip(ip, timeout):
    try:
        cmd = ["sudo", "nft", "add", "element", "inet", "firewall", "blacklisted_ips", "{", ip, "timeout", timeout, "}"]
        result = subprocess.run(
            cmd,
            capture_output=True,  # Capture stdout and stderr
            text=True,            # Return strings, not bytes
            check=True            # Raise exception on failure
        )
        log(f"Successfully added IP {ip} to blacklist with timeout {timeout}. Output: {result.stdout}")
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "No error message provided."
        log(f"Failed to add IP {ip} to blacklist: {stderr_output}")
    except Exception as e:
        log(f"Unexpected error adding IP {ip} to blacklist: {e}")

def send_whitelisted_alert(log_entry, src_ip, dest_ip, classification, whitelisted_ip):
    """
    Send an email alert for suspicious traffic from/to a whitelisted IP address.
    """
    try:
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get swanctl active connections
        swanctl_output = subprocess.run(
            ["swanctl", "-l", "|", "grep", "@"],
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        ).stdout.strip()
        
        # Format email subject and body
        subject = f"WARNING: Suspicious Activity from Whitelisted IP on {socket.gethostname()}"
        
        # Extract additional useful information from the log entry
        signature = log_entry.get("alert", {}).get("signature", "Unknown")
        severity = log_entry.get("alert", {}).get("severity", "Unknown")
        category = log_entry.get("alert", {}).get("category", "Unknown")
        
        body = f"""
WHITELISTED IP ALERT - {timestamp}

Suspicious traffic was detected from/to a whitelisted IP address.
This IP was NOT automatically blocked due to its presence in the whitelist.

DETAILS:
- Source IP: {src_ip}
- Destination IP: {dest_ip}
- Whitelisted IP: {whitelisted_ip}
- Classification: {classification}
- Signature: {signature}
- Severity: {severity}
- Category: {category}

ACTIVE VPN CONNECTIONS:
{swanctl_output}

ACTION REQUIRED:
Please investigate this activity as it may indicate a legitimate but misconfigured service,
or a compromised trusted system.
"""
        
        # Load recipient email from config
        config = load_config(CONFIG_FILE)
        recipient = config.get("REPORT_EMAIL", "root")
        
        # Create email message
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = f"Suricata-Watchdog@{socket.gethostname()}"
        msg['To'] = recipient
        
        # Add main message body
        msg.attach(MIMEText(body))
        
        # Add JSON alert as attachment
        alert_attachment = MIMEText(json.dumps(log_entry, indent=2))
        alert_attachment.add_header('Content-Disposition', 'attachment', filename="alert_details.json")
        msg.attach(alert_attachment)
        
        # Send email using the local MTA
        with smtplib.SMTP('localhost') as smtp:
            smtp.send_message(msg)
            
        log(f"Whitelisted IP alert email sent to {recipient}")
        return True
    
    except Exception as e:
        log(f"Error sending whitelisted IP alert: {e}")
        # Ensure the error doesn't prevent normal processing
        return False

def send_internal_threat_alert(log_entry, src_ip, dest_ip, classification):
    """
    Send an email alert for internal-to-internal suspicious traffic using the local MTA.
    """
    try:
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get swanctl active connections
        swanctl_output = subprocess.run(
            ["swanctl", "-l", "|", "grep", "@"],
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        ).stdout.strip()
        
        # Get debug info
        debug_output = subprocess.run(
            ["strongconn.sh", "-debug"],
            capture_output=True,
            text=True,
            timeout=30
        ).stdout.strip()
        
        # Format email subject and body
        subject = f"ALERT: Internal Threat Activity Detected on {socket.gethostname()}"
        
        # Extract additional useful information from the log entry
        signature = log_entry.get("alert", {}).get("signature", "Unknown")
        severity = log_entry.get("alert", {}).get("severity", "Unknown")
        category = log_entry.get("alert", {}).get("category", "Unknown")
        
        body = f"""
INTERNAL THREAT ALERT - {timestamp}

An internal client has generated suspicious traffic that matches security rules.
This traffic was NOT automatically blocked to prevent operational disruption.

DETAILS:
- Source IP: {src_ip}
- Destination IP: {dest_ip}
- Classification: {classification}
- Signature: {signature}
- Severity: {severity}
- Category: {category}

ACTIVE VPN CONNECTIONS:
{swanctl_output}

ACTION REQUIRED:
Please investigate this activity immediately as it may indicate a compromised ZTNA client.
"""
        
        # Load recipient email from config
        config = load_config(CONFIG_FILE)
        recipient = config.get("REPORT_EMAIL", "root")
        
        # Create email message
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = f"Suricata-Watchdog@{socket.gethostname()}"
        msg['To'] = recipient
        
        # Add main message body
        msg.attach(MIMEText(body))
        
        # Add JSON alert as attachment
        alert_attachment = MIMEText(json.dumps(log_entry, indent=2))
        alert_attachment.add_header('Content-Disposition', 'attachment', filename="alert_details.json")
        msg.attach(alert_attachment)
        
        # Add debug output as attachment
        debug_attachment = MIMEText(debug_output)
        debug_attachment.add_header('Content-Disposition', 'attachment', filename="system_status.txt")
        msg.attach(debug_attachment)
        
        # Send email using the local MTA
        with smtplib.SMTP('localhost') as smtp:
            smtp.send_message(msg)
            
        log(f"Internal threat alert email sent to {recipient}")
        return True
    
    except Exception as e:
        log(f"Error sending internal threat alert: {e}")
        # Ensure the error doesn't prevent normal processing
        return False

def handle_log_entry(log_entry, internal_networks, blocked_classifications, debug, timeout):
    """
    Process a single log entry from eve.json.
    """
    classification_raw = log_entry.get("alert", {}).get("category", "")
    classification = normalize_classification(classification_raw)

    if debug:
        log(f"Extracted classification: '{classification_raw}' (normalized as '{classification}')")

    src_ip = log_entry.get("src_ip", "").strip()
    dest_ip = log_entry.get("dest_ip", "").strip()
    if not classification or (not src_ip and not dest_ip):
        if debug:
            log(f"Missing necessary fields in log entry: {log_entry}")
        return

    if classification not in blocked_classifications:
        if debug:
            log(f"Classification '{classification_raw}' is NOT in the block list. Skipping entry.")
        return

    try:
        src_ip_addr = ipaddress.ip_address(src_ip)
        dest_ip_addr = ipaddress.ip_address(dest_ip)

        # Determine if both source and destination are internal
        src_is_internal = any(src_ip_addr in subnet for subnet in internal_networks)
        dest_is_internal = any(dest_ip_addr in subnet for subnet in internal_networks)
        
        # If both source and destination are internal, send alert instead of blocking
        if src_is_internal and dest_is_internal:
            log(f"Internal-to-internal suspicious traffic detected: {src_ip} -> {dest_ip} with classification '{classification_raw}'")
            send_internal_threat_alert(log_entry, src_ip, dest_ip, classification_raw)
            return

        if src_is_internal:
            ip_to_check = dest_ip  
            direction = "outbound"
        else:
            ip_to_check = src_ip 
            direction = "inbound"
    except ValueError:
        log(f"Invalid IP address in log entry: src_ip={src_ip}, dest_ip={dest_ip}")
        return

    if not ip_to_check:
        if debug:
            log(f"No IP available for blacklisting. Skipping entry.")
        return

    # Check if the IP is whitelisted
    if is_ip_in_set(ip_to_check, "whitelisted_ips"):
        log(f"⚠️ IP {ip_to_check} is whitelisted but triggered '{classification_raw}' alert ({direction} traffic). Sending notification instead of blocking.")
        send_whitelisted_alert(log_entry, src_ip, dest_ip, classification_raw, ip_to_check)
        return

    if is_ip_in_set(ip_to_check, "blacklisted_ips"):
        if debug:
            log(f"IP {ip_to_check} is already blacklisted. Skipping adding to blacklist.")
        return

    log(f"Blacklisting IP {ip_to_check} with classification '{classification_raw}' ({direction} traffic).")
    blacklist_ip(ip_to_check, timeout)

def handle_log_rotation(current_inode):
    """
    Check if the log file has been rotated by comparing inode numbers.
    Returns True if rotated, False otherwise.
    """
    try:
        new_inode = os.stat(LOG_FILE).st_ino
        if new_inode != current_inode:
            return True
    except FileNotFoundError:
        log(f"Log file {LOG_FILE} not found during rotation check.")
    except Exception as e:
        log(f"Error checking log rotation: {e}")
    return False

def monitor_log(internal_networks, blocked_classifications, debug, timeout):
    """
    Monitor the eve.json log file for new entries using inotify.
    Process each new log entry accordingly.
    """
    
    i = inotify.adapters.Inotify()
    i.add_watch(LOG_FILE)

    try:
    
        with open(LOG_FILE, "r") as f:
            f.seek(0, os.SEEK_END)  
            current_inode = os.fstat(f.fileno()).st_ino

            while True:
                events = i.event_gen(yield_nones=False, timeout_s=1)
                for event in events:
                    (_, type_names, path, filename) = event

                    if 'IN_MODIFY' in type_names:
                        if debug:
                            log(f"Detected modification event in {LOG_FILE}")

                        while True:
                            line = f.readline()
                            if not line:
                                break

                            line = line.strip()
                            if debug:
                                log(f"Read line from {LOG_FILE}: {line}")

                            if not line:
                                continue

                            try:
                                log_entry = json.loads(line)
                                if debug:
                                    log(f"Parsed log entry: {log_entry}")
                            except json.JSONDecodeError:
                                if debug:
                                    log(f"Failed to parse JSON line: {line}")
                                continue

                            handle_log_entry(log_entry, internal_networks, blocked_classifications, debug, timeout)

      
                if handle_log_rotation(current_inode):
                    if debug:
                        log("Log file has been rotated. Reopening the log file.")
                    f.close()
                    with open(LOG_FILE, "r") as f_new:
                        f_new.seek(0, os.SEEK_END)
                        current_inode = os.fstat(f_new.fileno()).st_ino
                        f = f_new

                time.sleep(0.1) 

    except Exception as e:
        log(f"Unexpected error in main log monitoring loop: {e}")
    finally:
        log("Suricata watchdog script terminated.")


if __name__ == "__main__":

    config = load_config(CONFIG_FILE)

    DEBUG = config.get("DEBUG", "false").lower() == "true"

    try:
        internal_network_str = config.get("ROUTE_SUBNETS", "").strip()
        # Add IP_POOL to internal_networks for proper detection
        ip_pool_str = config.get("IP_POOL", "").strip()
        combined_networks = internal_network_str
        if ip_pool_str:
            combined_networks = f"{internal_network_str},{ip_pool_str}" if internal_network_str else ip_pool_str
            
        if not combined_networks:
            log("Neither ROUTE_SUBNETS nor IP_POOL is defined in the configuration file. Exiting.")
            sys.exit(1)

        internal_networks = [
            ipaddress.ip_network(subnet.strip()) 
            for subnet in combined_networks.split(",") 
            if subnet.strip()
        ]

        if not internal_networks:
            log("No valid subnets found in ROUTE_SUBNETS or IP_POOL. Exiting.")
            sys.exit(1)
            
        if DEBUG:
            log(f"Internal networks defined: {combined_networks}")
            log(f"Parsed {len(internal_networks)} networks: {internal_networks}")
            
    except ValueError as ve:
        log(f"Invalid subnet value in config: '{combined_networks}'. Error: {ve}. Exiting.")
        sys.exit(1)
    except Exception as e:
        log(f"Error processing network subnets: {e}. Exiting.")
        sys.exit(1)


    blocked_classifications = load_classifications(CLASSIFICATION_FILE)
    if not blocked_classifications:
        log("No classifications loaded. Please check the classifications.conf file. Exiting.")
        sys.exit(1)

    WATCHDOG_TIMEOUT = config.get("WATCHDOG_TIMEOUT", "").strip()
    if not WATCHDOG_TIMEOUT:
        log("WATCHDOG_TIMEOUT is not defined in the configuration file. Exiting.")
        sys.exit(1)

    if not re.match(r'^\d+[smhd]$', WATCHDOG_TIMEOUT):
        log(f"Invalid WATCHDOG_TIMEOUT format: '{WATCHDOG_TIMEOUT}'. Expected formats like '24h', '1d', '30m'. Exiting.")
        sys.exit(1)

    log("Suricata watchdog script initialized and monitoring started.")


    monitor_log(internal_networks, blocked_classifications, DEBUG, WATCHDOG_TIMEOUT)