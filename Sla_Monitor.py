import os
import json
import csv
import io
import re
import random
import requests
import logging
from urllib.parse import urljoin
import boto3
from botocore.exceptions import ClientError
from datetime import datetime 
import warnings
warnings.filterwarnings("ignore")




# Jira configuration (Source Project only)
JIRA_DOMAIN = os.environ.get("SOURCE_JIRA_DOMAIN", "securegpt-agenticai.atlassian.net") ##'secure-agenticai.atlassian.net'
JIRA_EMAIL = os.environ.get("SOURCE_JIRA_EMAIL", "")
JIRA_API_TOKEN = os.environ.get("SOURCE_JIRA_API_TOKEN", "") #input token
PROJECT_KEY = os.environ.get("SOURCE_PROJECT_KEY", "Secure-AgenticAI")  # Source project key

# SecureGPT configuration (if used in classification)
SECUREGPT_URL = os.environ.get("SECUREGPT_URL", "https://tis.accure.ai:9001")
SECUREGPT_TOKEN = os.environ.get("SECUREGPT_TOKEN", "") #input token for futionality
SECUREGPT_ORG = os.environ.get("SECUREGPT_ORG", "1740434887629_TicketMasters")

##############################
# Helper Functions           #
##############################
##############################
# Logging Configuration      #
##############################

log_stream = io.StringIO()
logger = logging.getLogger()
logger.setLevel(logging.INFO)



# StreamHandler for in-memory log capture
memory_handler = logging.StreamHandler(log_stream)
memory_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(memory_handler)

# Optional: also stream to console (so logs show in CloudWatch)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(console_handler)

s3_client = boto3.client("s3")
OUTPUT_BUCKET = os.environ.get("OUTPUT_BUCKET", "ticketmasters") 

def upload_log_file(content, prefix="sla_responses"):
    filename = f"{prefix}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.log"
    try:
        s3_client.put_object(Bucket=OUTPUT_BUCKET, Key=filename, Body=content.encode("utf-8"))
        logger.info(f"Log file uploaded as s3://{OUTPUT_BUCKET}/{filename}")
    except Exception as e:
        logger.error(f"Error uploading log file: {e}")

def extract_plain_text_from_description(desc):
    if isinstance(desc, dict) and "content" in desc:
        texts = []
        def extract_text(item):
            if isinstance(item, dict):
                if item.get("type") == "text" and "text" in item:
                    texts.append(item["text"])
                elif "content" in item:
                    for sub_item in item["content"]:
                        extract_text(sub_item)
            elif isinstance(item, list):
                for sub_item in item:
                    extract_text(sub_item)
        extract_text(desc)
        return " ".join(texts)
    return desc

def extract_json(text):
    match = re.search(r"```json(.*?)```", text, re.DOTALL)
    if match:
        json_str = match.group(1).strip()
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return {}
    else:
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            return {}

##############################
# Jira                       #
##############################

class JiraClient:
    def __init__(self, domain, api_token, email, project_key):
        self.base_url = f"https://{domain}"
        self.session = requests.Session()
        self.session.auth = (email, api_token)
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        self.project_key = project_key

    def fetch_issues(self):
        url = f"{self.base_url}/rest/api/3/search"
        payload = {
            "jql": f"project = \"{self.project_key}\" ORDER BY created DESC",
            "maxResults": 55,  # Still fetch 10 issues from Jira
            "fields": ["summary", "description", "key", "assignee", "timetracking", "created", "status"]
        }
        response = self.session.get(url, params=payload)
        if response.status_code == 200:
            valid_tickets = []
            for issue in response.json().get("issues", []):
                fields = issue.get("fields", {})
                # Check if the assignee field is None (or evaluates to False)
                if not fields.get("assignee"):
                    logger.info(f"Skipping ticket {issue.get('key')} due to missing assignee.")
                    continue
                ticket = {
                    "key": issue.get("key"),
                    "summary": fields.get("summary", ""),
                    "description": extract_plain_text_from_description(fields.get("description", "")),
                    "originalEstimate": fields.get("timetracking", {}).get("originalEstimate", "Not Specified"),
                    "assignee": fields.get("assignee", {}).get("displayName", "Unassigned"),
                    "created": fields.get("created", "Not Specified"),
                    "status": fields.get("status", {}).get("name", "Not Specified")
                }
                logger.info(f"Fetched ticket: {ticket}")
                valid_tickets.append(ticket)
                # Stop after collecting 9 tickets with a valid assignee
                #if len(valid_tickets) == 9:
                #    break
            return valid_tickets
        else:
            logger.error(f"Failed to fetch issues: {response.status_code}, {response.text}")
            return []

##############################
# SecureGPT Classification   #
##############################

def call_securegpt_generate(prompt):
    url = f"{SECUREGPT_URL}/generate"
    headers = {
        "Authorization": SECUREGPT_TOKEN,
        "Content-Type": "application/json"
    }
    payload = {"inputs": prompt}
    response = requests.post(url, headers=headers, json=payload, verify=False)
    if response.status_code == 498:
        raise Exception("SecureGPT API token is invalid or expired.")
    elif response.status_code == 200:
        try:
            result = response.json()
            return result if isinstance(result, dict) else result.strip()
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format", "raw_response": response.text.strip()}
    else:
        raise Exception(f"SecureGPT error: {response.status_code} {response.text}")

def analyze_ticket(ticket): 
    prompt = (
        "You are an AI assistant that evaluates SLA compliance. "
        "Consider the ticket's overall estimated time as its resolution indicator, its creation timestamp, and its current status. "
        "Determine whether the ticket meets SLA requirements. "
        "Return a JSON object with exactly the following keys: 'ticket_id', 'sla_compliance' (Compliant or Non-Compliant), "
        "and 'sla_message' (a short sentence explaining the decision). Do not include extra text.\n\n"
        f"Ticket ID: {ticket.get('key')}\n"
        f"Overall Estimated Time: {ticket.get('originalEstimate')}\n"
        f"Created: {ticket.get('created')}\n"
        f"Ticket Status: {ticket.get('status')}\n"
    )
    logger.info(f"Sending to SecureGPT:\n{prompt}")
    result_sla_raw = call_securegpt_generate(prompt)
    if isinstance(result_sla_raw, dict) and "generated_text" in result_sla_raw:
        result_sla_raw = result_sla_raw["generated_text"]
    parsed = extract_json(result_sla_raw)
    if not parsed or "ticket_id" not in parsed:
        logger.warning(f"Invalid JSON from SecureGPT for ticket {ticket.get('key')}")
        return {
            "ticket_id": ticket.get("key"),
            "sla_compliance": "Unknown",
            "sla_message": "Could not evaluate SLA"
        }
    logger.info(f"Result for {ticket.get('key')}: {parsed}")
    return parsed

##############################
# Save to CSV                #
##############################

def save_to_csv(tickets, filename="/tmp/sla_tickets_alerts.csv"):
    USER_MAPPING = {
        "SATYA DURGESH KEERTHI": "skeerth2@gmu.edu",
        "Ritesh": "rsomashe@gmu.edu",
        "mounish yeshwanth allu": "mallu@gmu.edu",
        "Laxmi Abhay Prakash Salagrama": "lsalagra@gmu.edu",
        "Pritham Mahajan": "pmahaja@gmu.edu",
        "Sumukh Bharadvaja Shivaram": "sbharadv@gmu.edu"
    }
    rows = []
    for ticket in tickets:
        sla_result = analyze_ticket(ticket)
        assignee_email = USER_MAPPING.get(ticket["assignee"], ticket["assignee"])
        rows.append({
            "Ticket ID": ticket["key"],
            "Summary": ticket["summary"],
            "Description": ticket["description"],
            "Original Estimate": ticket["originalEstimate"],
            "Assignee": ticket["assignee"],
            "Assignee Email": assignee_email,
            "Created": ticket["created"],
            "Ticket Status": ticket["status"],
            "SLA Compliance": sla_result.get("sla_compliance", "Unknown"),
            "SLA Compliance Text": sla_result.get("sla_message", "")
        })
        logger.info(f"Appended ticket {ticket['key']} to CSV.")
    fieldnames = rows[0].keys() if rows else []
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    logger.info(f"CSV saved to {filename}")

##############################
# Lambda Handler             #
##############################
def lambda_handler(event, context):
    logger.info("Lambda triggered.")

    # Explicitly create S3 client and define output bucket
    s3_client = boto3.client("s3")
    bucket = "ticketmasters"

    try:
        record = event['Records'][0]
        key = record['s3']['object']['key']
        logger.info(f"Triggered by file: {key} in bucket: {bucket}")
    except Exception as e:
        logger.error(f"Event error: {e}")
        return {"statusCode": 400, "body": "Invalid event format."}

    if key != "categorized_tickets.csv":
        logger.info("Exiting: not the trigger file.")
        return {"statusCode": 200, "body": "Not the trigger file."}

    # Fetch and process Jira tickets
    jira_client = JiraClient(JIRA_DOMAIN, JIRA_API_TOKEN, JIRA_EMAIL, PROJECT_KEY)
    tickets = jira_client.fetch_issues()
    if not tickets:
        logger.info("No tickets found.")
        return {"statusCode": 200, "body": "No tickets found."}

    alerts_filename = "/tmp/sla_tickets_alerts.csv"
    save_to_csv(tickets, alerts_filename)

    # ---- CSV Uploads ----
    # Read CSV into memory
    try:
        with open(alerts_filename, "rb") as f:
            data = f.read()
    except Exception as e:
        logger.error(f"Error reading CSV file: {e}")
        return {"statusCode": 500, "body": "Failed to read CSV."}

    # 1) Upload to primary bucket
    try:
        s3_client.put_object(
            Bucket=bucket,
            Key="sla_tickets_alerts.csv",
            Body=data
        )
        logger.info(f"CSV uploaded to s3://{bucket}/sla_tickets_alerts.csv")
    except Exception as e:
        logger.error(f"Error uploading CSV to primary bucket: {e}")
        return {"statusCode": 500, "body": "CSV upload to primary bucket failed."}

    # 2) Upload ONLY the CSV to the second bucket under stored_alerts/
    # Here we add a UTC timestamp to the filename
    second_bucket = os.environ.get("SECOND_BUCKET", "daen690-output-bucket")
    second_prefix = "stored_alerts/"
    timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    second_key = f"{second_prefix}{timestamp}_sla_tickets_alerts.csv"
    try:
        s3_client.put_object(
            Bucket=second_bucket,
            Key=second_key,
            Body=data,
            ACL="bucket-owner-full-control"
        )
        logger.info(f"CSV uploaded to s3://{second_bucket}/{second_key}")
    except Exception as e:
        logger.error(f"Error uploading CSV to second bucket: {e}")
        # Do not return here; we still want to upload logs

    # ---- Log Upload ----
    try:
        log_contents = log_stream.getvalue()
        filename = f"sla_responses_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.log"
        s3_client.put_object(Bucket=bucket, Key=filename, Body=log_contents.encode("utf-8"))
        logger.info(f"Log file uploaded to s3://{bucket}/{filename}")
    except Exception as e:
        logger.error(f"Error uploading log file: {e}")

    return {
        "statusCode": 200,
        "body": f"Alerts CSV and log file uploaded to s3://{bucket}/ (and CSV to s3://{second_bucket}/{second_prefix})"
    }