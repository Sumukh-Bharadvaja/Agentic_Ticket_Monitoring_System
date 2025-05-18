import os
import io
import csv
import logging
import boto3
import smtplib
import json
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = '' #enter port number
EMAIL_SENDER = os.environ.get("EMAIL_SENDER", "") #input smtp email
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "") #input smtp password

# CC email will be copied on every outgoing email
CC_EMAIL = os.environ.get("CC_EMAIL", "atmdean@gmail.com")  # Change to your desired CC address

def send_email(assignee_email, assignee_name, ticket_id, summary, description, created, status):
    subject = f"Urgent: SLA Breach - Ticket {ticket_id}"
    email_body = f"""
Dear {assignee_name},

This is an automated notification regarding a service ticket that has exceeded its SLA timeframe.
Ticket Details:
- Ticket ID: {ticket_id}
- Summary: {summary}
- Description: {description}
- Created On: {created}
- Status: {status}

Please address this issue immediately.

Best regards,
JIRA Notifications
"""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = assignee_email
        msg["Cc"] = CC_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(email_body, "plain"))
        
        # Combine primary recipient and CC
        recipients = [assignee_email, CC_EMAIL]
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, recipients, msg.as_string())
        server.quit()
        logger.info(f"Email sent to {assignee_email} (CC: {CC_EMAIL}) for Ticket {ticket_id}")
    except Exception as e:
        logger.error(f"Error sending email to {assignee_email} (Ticket {ticket_id}): {e}")

def process_alerts_csv(bucket, key):
    s3_client = boto3.client("s3")
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        csv_text = response["Body"].read().decode("utf-8")
        csv_file = io.StringIO(csv_text)
        reader = csv.DictReader(csv_file)
        
        for row in reader:
            # Normalize keys to lowercase and replace spaces with underscores
            normalized_row = {k.strip().lower().replace(" ", "_"): v for k, v in row.items()}
            
            # Read fields from CSV
            ticket_id = normalized_row.get("ticket_id", "").strip()
            summary = normalized_row.get("summary", "").strip()
            description = normalized_row.get("description", "").strip()
            created = normalized_row.get("created", "").strip()
            status = normalized_row.get("ticket_status", "").strip()
            assignee = normalized_row.get("assignee", "").strip()
            assignee_email = normalized_row.get("assignee_email", "").strip()
            sla_compliance = normalized_row.get("sla_compliance", "").strip().lower()
            
            # Check the SLA compliance flag: send email only if non-compliant.
            if sla_compliance == "compliant":
                logger.info(f"Ticket {ticket_id} is compliant. Skipping email.")
                continue
            
            if not assignee_email or "@" not in assignee_email:
                logger.warning(f"Skipping ticket {ticket_id}: Invalid email for assignee {assignee}")
                continue
            
            send_email(assignee_email, assignee, ticket_id, summary, description, created, status)
    except Exception as e:
        logger.error(f"Error processing CSV from S3: {e}")

def lambda_handler(event, context):
    s3_client = boto3.client("s3")
    try:
        record = event["Records"][0]
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]
        logger.info(f"Triggered by file: {key} in bucket: {bucket}")
    except Exception as e:
        logger.error(f"Error parsing event: {e}")
        return {"statusCode": 400, "body": "Invalid event format."}
    
    if key != "sla_tickets_alerts.csv":
        logger.info(f"File {key} is not the expected SLA alerts CSV. Exiting.")
        return {"statusCode": 200, "body": "Not the expected SLA alerts CSV file. No action taken."}
    
    process_alerts_csv(bucket, key)
    
    # Upload log file with a unique name
    log_contents = ""
    for handler in logger.handlers:
        if hasattr(handler, "stream") and hasattr(handler.stream, "getvalue"):
            value = handler.stream.getvalue()
            if isinstance(value, str):
                log_contents += value
    log_filename = f"email_sender_log_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.log"
    try:
        s3_client.put_object(Bucket=bucket, Key=log_filename, Body=log_contents.encode("utf-8"))
        logger.info(f"Log file uploaded as s3://{bucket}/{log_filename}")
    except Exception as e:
        logger.error(f"Error uploading log file: {e}")
    
    return {"statusCode": 200, "body": "Emails processed successfully."}

if __name__ == "__main__":
    # For local testing, update bucket and key as needed
    bucket = "ticketmasters"
    key = "sla_tickets_alerts.csv"
    process_alerts_csv(bucket, key)