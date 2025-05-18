# Agentic AI for Intelligent Service Ticket Management and SLA Compliance Monitoring

## Introduction  

### About Secure AgenticAI  

Agentic AI is a probabilistic intelligence system designed to adapt dynamically to changing data and operational environments. Unlike deterministic automation tools like RPA (Robotic Process Automation), Agentic AI makes decisions based on pattern recognition, context awareness, and statistical likelihoods, enabling it to automate complex workflows where traditional systems fall short.

### Context within Agentic AI Project

This work is part of a broader cybersecurity initiative titled **"Agentic AI using Secure AgenticAI"**, which is a four-part solution for real-time cybersecurity compliance and threat response. Developed in partnership with **Momentum** and **SecureGPT**, the project leverages large language models and intelligent agents to ensure organizations maintain cybersecurity compliance and mitigate risks effectively.

### About Goal 2 – Service Ticket Management Agent

Our team, **Agentic Ticket Masters**, is responsible for **Goal 2** of the project — building an **AI-powered Service Ticket Management Agent** that automates the lifecycle of service tickets, from categorization and team assignment to SLA tracking and breach notifications.

Our solution improves IT service responsiveness, ensures SLA compliance, and enhances overall support operations using agentic reasoning.

---

## Solution Overview

This solution leverages **SecureGPT** for intelligent classification and decision-making. It is deployed as a **modular, serverless pipeline on AWS**, triggered through S3 events and manual invocations, allowing real-time processing and alerting without human intervention.

! [Deployment] (deployment.svg)

We have provided the prompts to generate the specific code modules:

1. **Ticket Categoriser** — [Ticket_categoriser_prompt.txt](./Ticket_categoriser_prompt.txt)  
2. **SLA Monitor** — [Sla_monitor_prompt.txt](./Sla_monitor_prompt.txt)  
3. **Email Sender** — [Email_sender_prompt.txt](./Email_sender_prompt.txt)
---

##  Data Flow Diagram

The following diagram illustrates the flow of data and interactions between the components of the system:

![Data Flow Diagram](img/data.svg)

---

###  Workflow Components

1. **Jira Ticket Ingestion**  
   Tickets are retrieved from Jira Cloud using the Jira REST API.

2. **Ticket Categorization (`Ticket_Categoriser.py`)**  
   - Runs as an AWS Lambda function.
   - Sends ticket data to **SecureGPT** to classify priority, severity, urgency, component, and team.
   - Updates Jira and uploads `categorized_tickets.csv` to S3.

![Ticket Categoriser](img/ticket.svg)

3. **SLA Monitoring (`Sla_Monitor.py`)**  
   - Triggered by the upload of `categorized_tickets.csv`.
   - Evaluates whether each ticket meets SLA conditions using SecureGPT.
   - Outputs results in `sla_tickets_alerts.csv`.

![Sla Monitor](img/data.svg)

4. **Email Alerts (`Email_sender.py`)**  
   - Triggered by the upload of `sla_tickets_alerts.csv`.
   - Sends automated SLA breach notifications via SMTP to ticket assignees and CC'd stakeholders.
![Email Sender](img/email.svg)
---

## Deployment and Security

- All modules are deployed as **AWS Lambda functions** with **event-driven automation** via S3 triggers.
- All credentials and tokens are securely handled via **environment variables**.
- GitHub Push Protection ensures secrets never reach version control.
- Logs and outputs are securely stored in Amazon S3 for transparency and traceability.

The overall Architecture is as shown below
![AWS Architecture](img/architecture.svg)

---

## 📁 Code Modules

| Script                | Description                                                   |
|------------------------|---------------------------------------------------------------|
| `Ticket_Categoriser.py` | Fetches and classifies Jira tickets via SecureGPT              |
| `Sla_Monitor.py`       | Assesses SLA compliance and generates alert CSVs               |
| `Email_sender.py`      | Sends SLA breach notifications via SMTP email                  |

---

## 🧪 Local Testing

Ensure environment variables are set or `.env` file is loaded, then run:

```bash
python Ticket_Categoriser.py
python Sla_Monitor.py
python Email_sender.py
