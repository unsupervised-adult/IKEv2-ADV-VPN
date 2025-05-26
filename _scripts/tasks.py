#!/usr/bin/env python3
import os
from celery import Celery
import subprocess
import logging
import re
import time
from email.message import EmailMessage
import smtplib

# Constants
CELERY_BROKER_URL = 'redis://127.0.0.1:6379/0'
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/0'
VPKI_SCRIPT = '/usr/bin/v-pki'
TASK_BLK_TIMEOUT = '3600s'
ALLOWED_GROUP = 'Allowed VPN Users'
SMTP_SERVER = '127.0.0.1'
SMTP_PORT = 587
SMTP_USER = 'your_smtp_user'
SMTP_PASSWORD = 'your_smtp_password'
SEND_EMAILS = False

celery_app = Celery(
    'tasks',
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND
)
celery_app.conf.update({
    'broker_url': CELERY_BROKER_URL,
    'result_backend': CELERY_RESULT_BACKEND
})

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

def send_certificate_email(user_email):
    """Send PKI certificate via email if SEND_EMAILS is True."""
    if not SEND_EMAILS:
        logger.info(f"Email sending is disabled. Skipping email for {user_email}")
        return True

    OUTPUT_DIR = "/opt/pki"
    CERT_SUFFIX = ".tar.gz"
    filename = f"{user_email}{CERT_SUFFIX}"
    file_path = f"{OUTPUT_DIR}/{filename}"
    
    timeout = 10
    while not os.path.exists(file_path) and timeout > 0:
        time.sleep(1)
        timeout -= 1

    if not os.path.exists(file_path):
        logger.error(f"Certificate file {file_path} not found for {user_email}")
        return False

    msg = EmailMessage()
    msg['Subject'] = 'Your PKI Certificate'
    msg['From'] = SMTP_USER
    msg['To'] = user_email
    msg.set_content('Attached is your certificate package.')

    try:
        with open(file_path, 'rb') as f:
            msg.add_attachment(f.read(),
                               maintype='application',
                               subtype='octet-stream',
                               filename=filename)
    except Exception as e:
        logger.error(f"Error reading certificate file {file_path}: {e}")
        return False

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)
        logger.info(f"Email sent to {user_email}")
        return True
    except Exception as e:
        logger.error(f"Error sending email to {user_email}: {e}")
        return False

# Remaining functions unchanged
def get_serial_for_user(user_email):
    """Get certificate serial for a user."""
    command = ["sudo", VPKI_SCRIPT, "list"]
    try:
        output = subprocess.check_output(command, universal_newlines=True)
        lines = output.splitlines()
        for i, line in enumerate(lines):
            if "Subject:" in line and user_email in line:
                for j in range(i - 1, -1, -1):
                    if lines[j].strip().startswith("Serial:"):
                        serial = lines[j].split("Serial:")[1].strip()
                        logger.info(f"Found serial for {user_email}: {serial}")
                        return serial
        logger.warning(f"No certificate found for {user_email}")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Error listing certificates: {e}")
        return None

def get_active_ip_for_user(user_email):
    """Get active IP address for a user via swanctl."""
    try:
        output = subprocess.check_output(["swanctl", "--list-sas"], universal_newlines=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error retrieving active SAs: {e}")
        return None

    pattern = rf".*CN\s*=\s*{re.escape(user_email)}.*\n.*Remote:\s*([\d.]+)"
    match = re.search(pattern, output)
    if match:
        ip = match.group(1)
        logger.info(f"Found active IP for {user_email}: {ip}")
        return ip
    else:
        logger.info(f"No active connection found for {user_email}")
        return None

def block_ip(ip, timeout, dry_run=False):
    """Block a user's IP via nftables."""
    element = f'{{ {ip} timeout {timeout} }}'
    command = ["sudo", "nft", "add", "element", "inet", "firewall", "blacklisted_ips", element]
    try:
        if dry_run:
            logger.info(f"[DRY RUN] Would execute: {' '.join(command)}")
        else:
            subprocess.run(command, check=True)
            logger.info(f"Blocked IP {ip} with timeout {timeout}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error blocking IP {ip}: {e}")
        return False
    return True

@celery_app.task(name="tasks.process_okta_event_task")
def process_okta_event_task(event_data):
    """Process Okta Event Hook for user changes (deactivation, group removal, etc.)."""
    event_type = event_data.get("eventType")
    target = event_data.get("target", [])

    if len(target) < 1:
        logger.error("Invalid Okta event format")
        return

    user_email = target[0].get("alternateId")

    group_name = None
    for entry in target:
        if entry.get("type") == "UserGroup":
            group_name = entry.get("displayName")

    if event_type == "user.lifecycle.deactivate":
        if group_name == ALLOWED_GROUP:
            logger.info(f"User {user_email} is deactivated but still in {ALLOWED_GROUP}. Revoking access.")
            process_certificate_task.delay(user_email, "revoke")
            process_deactivation_task.delay(user_email)
        else:
            logger.info(f"Skipping deactivation for {user_email} (Not in '{ALLOWED_GROUP}').")
    elif event_type == "group.user_membership.add":
        if group_name == ALLOWED_GROUP:
            logger.info(f"User {user_email} added to {group_name}. Granting access.")
            process_certificate_task.delay(user_email, "generate")
    elif event_type == "group.user_membership.remove":
        if group_name == ALLOWED_GROUP:
            logger.info(f"User {user_email} removed from {group_name}. Revoking access.")
            process_certificate_task.delay(user_email, "revoke")
    else:
        logger.warning(f"Unhandled event type: {event_type}")

@celery_app.task(name="tasks.process_certificate_task")
def process_certificate_task(user_email, action):
    """Handle certificate generation & revocation."""
    if action == "generate":
        logger.info(f"Generating certificate for {user_email}")
        subprocess.run(["sudo", VPKI_SCRIPT, "generate-client", user_email, "2555"], check=True)
        send_certificate_email(user_email)
    elif action == "revoke":
        logger.info(f"Revoking certificate for {user_email}")
        serial = get_serial_for_user(user_email)
        if serial:
            subprocess.run(["sudo", VPKI_SCRIPT, "revoke-pki", serial], check=True)

@celery_app.task(name="tasks.process_deactivation_task")
def process_deactivation_task(user_email):
    """Block deactivated users still in VPN group."""
    active_ip = get_active_ip_for_user(user_email)
    if active_ip:
        block_ip(active_ip, TASK_BLK_TIMEOUT, dry_run=False)
        logger.info(f"Blocked VPN access for deactivated user: {user_email}")