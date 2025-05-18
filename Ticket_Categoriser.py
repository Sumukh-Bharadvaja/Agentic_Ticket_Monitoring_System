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


# ----------------------------
# Configuration Variables
# ----------------------------
JIRA_DOMAIN = os.environ.get("SOURCE_JIRA_DOMAIN", "securegpt-agenticai.atlassian.net") ##'secure-agenticai.atlassian.net'
JIRA_EMAIL = os.environ.get("SOURCE_JIRA_EMAIL", "") #email
JIRA_API_TOKEN = os.environ.get("SOURCE_JIRA_API_TOKEN", "") #input token
PROJECT_KEY = os.environ.get("SOURCE_PROJECT_KEY", "Secure-AgenticAI")

SECUREGPT_URL = os.environ.get("SECUREGPT_URL", "https://tis.accure.ai:9001")
SECUREGPT_TOKEN = os.environ.get("SECUREGPT_TOKEN", "")#input token
SECUREGPT_ORG = os.environ.get("SECUREGPT_ORG", "1740434887629_TicketMasters")

TICKETS_LIMIT = 55

VALID_PRIORITIES = ["Highest", "High", "Medium", "Low"]
VALID_COMPONENTS = [
    "Active Directory", "Analytics and Reporting Service", "Billing Services",
    "Cloud Storage Services", "Data Center Services", "Email and Collaboration Services",
    "Financial Services", "HR Services", "Intranet", "Jira", "Office Network",
    "Payroll Services", "Printers", "Public Website", "VPN Server", "Webstore Purchasing Services"
]
VALID_URGENCIES = ["Critical", "High", "Medium", "Low"]
VALID_SEVERITIES = ["Sev-0", "Sev-1", "Sev-2", "Sev-3"]
VALID_TEAMS = ["Development", "Networking", "Security"]
FALLBACK_COMPONENT = "Intranet"
FALLBACK_URGENCY = "Medium"
FALLBACK_SEVERITY = "Sev-3"
FALLBACK_TEAM = "Development"

TEAM_FIELD_KEY = "customfield_10001"
URGENCY_FIELD_KEY = "customfield_10037"
SEVERITY_FIELD_KEY = "customfield_10044"
ESTIMATE_MAPPING = {
    "Sev-0": "1h",
    "Sev-1": "2h",
    "Sev-2": "8h",
    "Sev-3": "2d"
}

TEAM_MAPPING = {
    "Development": "db18b9b1-ae99-480b-89fd-77e406cbcef4",
    "Networking": "a6e9c331-7721-46c7-864b-93478ef7b519",
    "Security": "9258c41a-ee45-463c-a4cb-94462386fd0e"
}

USER_MAPPING = {
    "SATYA DURGESH KEERTHI": "712020:4fbf4d68-e17f-43b9-9be1-e570b9687038",
    "Ritesh": "712020:3663206f-93ba-49ff-b870-ee2520904fee",
    "mounish yeshwanth allu": "712020:62481974-0f86-467b-ad40-343972d01649",
    "Laxmi Abhay Prakash Salagrama": "712020:ccfb7f1e-e892-4947-b004-d3a0e7f3112f",
    "Pritham Mahajan": "712020:cd7fce9e-ca27-4baa-aaf9-74e172196e5e",
    "Sumukh Bharadvaja Shivaram": "712020:9e2be9f9-df28-43fb-a413-73674d4af71f"
}

REPORTER_MAPPING = {
    "samhita": "712020:3e4f77e0-76d7-45aa-9f10-1efcf31dcaed",
    "Sathwik Reddy Bethi": "712020:61a46754-da49-4287-ba31-c4fdc571cbe2"
}


# ----------------------------
# Logging Configuration
# ----------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)

log_stream = io.StringIO()
memory_handler = logging.StreamHandler(log_stream)

memory_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(memory_handler)

# S3 client for uploads (logs, CSV)
s3_client = boto3.client("s3")
OUTPUT_BUCKET = os.environ.get("OUTPUT_BUCKET", "ticketmasters")
SECOND_BUCKET = os.environ.get("SECOND_BUCKET", "daen690-output-bucket")
SECOND_PREFIX = os.environ.get("SECOND_PREFIX", "task_database/")  # e.g., your S3 bucket for outputs

def upload_log_file(content, prefix):
    filename = f"{prefix}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.log"
    try:
        s3_client.put_object(Bucket=OUTPUT_BUCKET, Key=filename, Body=content.encode("utf-8"))
        logger.info(f"Log file uploaded as s3://{OUTPUT_BUCKET}/{filename}")
    except Exception as e:
        logger.error(f"Error uploading log file: {e}")

class JiraIssueFetcher:
    """Handles Jira API requests."""
    def __init__(self, domain, api_token, email, project_key):
        self.base_url = f"https://{domain}"
        self.session = requests.Session()
        self.session.auth = (email, api_token)
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self.project_key = project_key

    def get_project_key(self):
        url = f"{self.base_url}/rest/api/3/project"
        response = self.session.get(url)
        if response.status_code == 200:
            for project in response.json():
                if project['key'].lower() == self.project_key.lower():
                    return project['key']
            logger.warning(f"Project '{self.project_key}' not found.")
        else:
            logger.error(f"Failed to fetch projects: {response.status_code}, {response.text}")
        return self.project_key

    def extract_plain_text(self, description_field):
        text = ""
        if isinstance(description_field, dict) and "content" in description_field:
            for block in description_field.get("content", []):
                if "content" in block:
                    for piece in block["content"]:
                        if piece.get("type") == "text":
                            text += piece.get("text", "")
        else:
            text = str(description_field)
        return text

    def fetch_issues(self):
        self.project_key = self.get_project_key()
        url = f"{self.base_url}/rest/api/3/search"
        payload = {
            "jql": f'project = "{self.project_key}"',
            "maxResults": 100,
            "fields": [
                "summary",
                "description",
                "key",
                "priority",
                "issuetype",
                "created",
                "timetracking"
            ]
        }
        logger.info(f"Fetching up to {TICKETS_LIMIT} issues from project: {self.project_key}")
        response = self.session.post(url, data=json.dumps(payload))
        logger.info(f"Response Status Code: {response.status_code}")
        if response.status_code == 200:
            issues = response.json().get("issues", [])
            structured = []
            for issue in issues[:TICKETS_LIMIT]:
                f = issue["fields"]
                structured.append({
                    "key":            issue["key"],
                    "summary":        f.get("summary", ""),
                    "description":    self.extract_plain_text(f.get("description", "")),
                    "issue_type":     f.get("issuetype", {}).get("name", ""),
                    "created":        f.get("created", ""),
                    "orig_estimate":  f.get("timetracking", {}).get("originalEstimate", "")
                })
            return structured
        else:
            logger.error(f"Failed to fetch issues: {response.status_code}, {response.text}")
            return []

def call_securegpt_generate(prompt, parameters=None):
    url = f"{SECUREGPT_URL}/generate"
    headers = {"Authorization": SECUREGPT_TOKEN, "Content-Type": "application/json"}
    payload = {"inputs": prompt}
    if parameters:
        payload["parameters"] = parameters
    response = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"SecureGPT error: {response.status_code} {response.text}")

def extract_json_from_generated_text(generated_text):
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", generated_text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception as e:
            logger.error(f"Error parsing JSON: {e}")
    return None

# ----------------------------
# Prompt Building (Original prompt + Reflection Instruction)
# ----------------------------
def build_dynamic_prompt(ticket):
    allowed_priorities = ", ".join(VALID_PRIORITIES)
    allowed_urgencies = ", ".join(VALID_URGENCIES)
    allowed_severities = ", ".join(VALID_SEVERITIES)
    allowed_components = ", ".join(VALID_COMPONENTS)
    allowed_teams = ", ".join(VALID_TEAMS)
    
    base_prompt = (
        "You are an AI assistant that classifies Jira tickets. For the following ticket, determine the priority, urgency, severity, and team. "
        "Return your answer as a JSON object with keys: 'priority', 'urgency', 'component', 'severity', and 'team'.\n\n"
        f"Priority options: {allowed_priorities}\n"
        f"Urgency options: {allowed_urgencies}\n"
        f"Severity options: {allowed_severities}\n"
        f"Components: {allowed_components}\n"
        f"Teams: {allowed_teams}\n\n"
    )
    
    reflexion_text = (
        "Before providing your final answer, please reflect on the ticket description for any explicit classification values. "
        "If the description contains phrases like 'Priority: High', 'Urgency: Critical', etc., consider those values and explain your reasoning. "
        "Also, if the summary contains gibberish or non-sensical text, or if the description is null/empty, handle it gracefully by defaulting to safe fallback values. "
        "For gibberish text, return the word 'jibberish' for all classification fields."
    )
    
    ticket_details = (
        "Ticket Details:\n"
        "Key: " + ticket.get("key", "N/A") + "\n"
        "Summary: " + ticket.get("summary", "N/A") + "\n"
        "Description: " + ticket.get("description", "N/A") + "\n"
    )
    
    prompt = base_prompt + reflexion_text + "\n\n" + ticket_details
    return prompt

def analyze_ticket(ticket, retries=3):
    prompt = build_dynamic_prompt(ticket)
    parameters = {"max_new_tokens": 1024}

    logger.info(f"Ticket {ticket.get('key', 'N/A')} - Sending to SecureGPT with prompt:\n{prompt}\n")
    for attempt in range(retries):
        try:
            result = call_securegpt_generate(prompt, parameters)
            generated_text = result.get("generated_text", "")
            logger.info(f"Ticket {ticket.get('key', 'N/A')} - Received response:\n{generated_text}\n--------------------")
            classification = extract_json_from_generated_text(generated_text)
            if classification:
                logger.info(f"Ticket {ticket.get('key', 'N/A')} classified successfully.")
                return classification
            else:
                logger.warning(f"Ticket {ticket.get('key', 'N/A')} - Attempt {attempt+1} failed to classify.")
        except Exception as e:
            logger.error(f"Ticket {ticket.get('key', 'N/A')} - Error during classification: {e}")
    logger.warning(f"Classification failed for ticket {ticket.get('key', 'N/A')} after {retries} attempts.")
    return None

def update_ticket_source(ticket_key, classification, original_description, original_summary):
    base_url = f"https://{JIRA_DOMAIN}"
    url = urljoin(base_url, f"/rest/api/3/issue/{ticket_key}")

    raw_priority  = classification.get("priority", "Medium")
    raw_component = classification.get("component", "")
    raw_urgency   = classification.get("urgency", "")
    raw_severity  = classification.get("severity", "")
    raw_team      = classification.get("team", "")

    # Check if gibberish is indicated in key fields (component or team)
    is_gibberish = (raw_component.lower() == "jibberish" or raw_team.lower() == "jibberish")
    
    if not is_gibberish:
        if raw_priority not in VALID_PRIORITIES:
            raw_priority = "Medium"
        if raw_component not in VALID_COMPONENTS:
            raw_component = FALLBACK_COMPONENT
        if raw_urgency not in VALID_URGENCIES:
            raw_urgency = FALLBACK_URGENCY
        if raw_severity not in VALID_SEVERITIES:
            raw_severity = FALLBACK_SEVERITY
        if raw_team not in VALID_TEAMS:
            raw_team = FALLBACK_TEAM

    # Build payload differently if gibberish is detected:
    if is_gibberish:
        # Create a valid Atlassian Document Format for the description.
        new_description = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "Jibberish text present"}
                    ]
                }
            ]
        }
        fields_data = {
            "description": new_description,
            "assignee": {"accountId": random.choice(list(REPORTER_MAPPING.values()))}
        }
    else:
        fields_data = {"priority": {"name": raw_priority}}
        if raw_component:
            fields_data["components"] = [{"name": raw_component}]
        fields_data[TEAM_FIELD_KEY]     = TEAM_MAPPING.get(raw_team, TEAM_MAPPING[FALLBACK_TEAM])
        fields_data[URGENCY_FIELD_KEY]  = {"value": raw_urgency}
        fields_data[SEVERITY_FIELD_KEY] = {"value": raw_severity}
        estimate_value = ESTIMATE_MAPPING.get(raw_severity, "")
        if estimate_value:
            fields_data["timetracking"] = {"originalEstimate": estimate_value}
        fields_data["assignee"] = {"accountId": random.choice(list(USER_MAPPING.values()))}

    payload = {"fields": fields_data}
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        response = requests.put(url, auth=(JIRA_EMAIL, JIRA_API_TOKEN), headers=headers, json=payload, timeout=15)
        if response.status_code in [200, 204]:
            if is_gibberish:
                logger.info(f"Ticket {ticket_key} updated as gibberish; assignee set from reporter mapping.")
            else:
                logger.info(f"Ticket {ticket_key} updated successfully; assignee set to USER_MAPPING.")
            return True
        else:
            logger.error(f"Failed to update ticket {ticket_key}: {response.status_code} {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error updating ticket {ticket_key}: {e}")
        return False

def process_tickets():
    fetcher = JiraIssueFetcher(JIRA_DOMAIN, JIRA_API_TOKEN, JIRA_EMAIL, PROJECT_KEY)
    tickets = fetcher.fetch_issues()
    if not tickets:
        logger.info("No tickets found.")
        return None
    logger.info(f"Fetched {len(tickets)} tickets.")

    updated_ticket_records = []
    for ticket in tickets:
        key = ticket.get("key", "N/A")
        logger.info(f"Processing ticket {key}")

        classification = analyze_ticket(ticket, retries=3)
        if not classification:
            logger.error(f"Failed to classify ticket {key}")
            continue

        if not update_ticket_source(key, classification, ticket.get("description", ""), ticket.get("summary", "")):
            logger.error(f"Failed to update ticket {key}")
            continue

        # Re-fetch the ticket to get updated fields
        issue_url = f"https://{JIRA_DOMAIN}/rest/api/3/issue/{key}"
        resp = fetcher.session.get(issue_url, params={
            "fields": [
                "summary", "description", "issuetype", "created", "timetracking",
                "priority", URGENCY_FIELD_KEY, SEVERITY_FIELD_KEY, "components",
                TEAM_FIELD_KEY, "assignee", "reporter"
            ]
        })
        if resp.status_code != 200:
            logger.error(f"Failed to re-fetch ticket {key}: {resp.status_code}")
            continue
        data = resp.json()["fields"]

        raw_team_id = data.get(TEAM_FIELD_KEY)
        team_name = next(
            (name for name, tid in TEAM_MAPPING.items() if tid == raw_team_id),
            None
        )
        if not team_name:
            team_name = classification.get("team", FALLBACK_TEAM)

        assignee = data.get("assignee", {}).get("displayName", "")
        reporter = data.get("reporter", {}).get("displayName", "")

        updated_ticket_records.append({
            "ticket_id": key,
            "summary": data.get("summary", ""),
            "original_description": fetcher.extract_plain_text(data.get("description", "")),
            "original_estimate": data.get("timetracking", {}).get("originalEstimate", ""),
            "issue_type": data.get("issuetype", {}).get("name", ""),
            "created": data.get("created", ""),
            "Priority": data.get("priority", {}).get("name", ""),
            "Urgency": data.get(URGENCY_FIELD_KEY, {}).get("value", ""),
            "Component": ", ".join(c.get("name", "") for c in data.get("components", [])),
            "Severity": data.get(SEVERITY_FIELD_KEY, {}).get("value", ""),
            "Team": team_name,
            "Assignee": assignee,
            "Reporter": reporter
        })

    if not updated_ticket_records:
        logger.info("No tickets were updated.")
        return None

    output = io.StringIO()
    fieldnames = [
        "ticket_id", "summary", "original_description", "original_estimate", "issue_type",
        "created", "Priority", "Urgency", "Component", "Severity", "Team", "Assignee", "Reporter"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(updated_ticket_records)
    csv_content = output.getvalue()
    output.close()

    logger.info(f"{len(updated_ticket_records)} tickets updated and fetched successfully.")
    return csv_content


def lambda_handler(event, context):
    logger.info("Ticket Categoriser triggered via API Gateway or S3 event.")
    csv_content = process_tickets()

    if csv_content:
        output_key = "categorized_tickets.csv"
        s3 = boto3.client("s3")
        extra_args = {
            "ContentType": "text/csv",
            "ServerSideEncryption": "AES256"
        }

        # 1) Upload to your own bucket (ticketmasters) — no ACL
        try:
            s3.put_object(
                Bucket=OUTPUT_BUCKET,
                Key=output_key,
                Body=csv_content.encode("utf-8"),
                **extra_args
            )
            logger.info(f"CSV uploaded to s3://{OUTPUT_BUCKET}/{output_key}")
        except Exception as e:
            logger.error(f"Error uploading CSV to {OUTPUT_BUCKET}: {e}")

        # 2) Upload ONLY the CSV to the second bucket under task_database/ with ACL.
        # Add SECOND_PREFIX here
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
        second_output_key = f"{SECOND_PREFIX}{timestamp}_categorized_tickets.csv"

        try:
            s3.put_object(
                Bucket=SECOND_BUCKET,
                Key=second_output_key,
                Body=csv_content.encode("utf-8"),
                ACL="bucket-owner-full-control",  # set ACL here
                **extra_args
            )
            logger.info(
                f"CSV uploaded with bucket-owner-full-control ACL to "
                f"s3://{SECOND_BUCKET}/{second_output_key}"
            )
        except Exception as e:
            logger.error(f"Error uploading CSV to {SECOND_BUCKET}: {e}")

    # Logs still go only to OUTPUT_BUCKET
    log_contents = log_stream.getvalue()
    upload_log_file(log_contents, "ticket_categoriser_log")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Tickets processed.",
            "csv": csv_content or ""
        })
    }



if __name__ == "__main__":
    print(process_tickets())
