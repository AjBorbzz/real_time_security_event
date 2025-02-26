# Automated Incident Response System for AWS

This project provides a production-ready, automated incident response system for EC2 instances in AWS, built with Python. It demonstrates a transformation from a basic Proof-of-Concept (POC) to a robust, object-oriented, and microservice-inspired solution.

## Overview

The system is designed to automatically detect and respond to security incidents involving EC2 instances.  It features:

*   **Instance Isolation:** Isolates compromised instances by moving them to a pre-configured "isolation" security group that blocks all inbound and outbound traffic.
*   **Forensic Data Collection:**  Collects forensic data, including system logs (via `journalctl`) and memory dumps (using LiME – *requires pre-installation on the instance*).
*   **Email Notifications:** Sends email alerts to designated recipients (e.g., CISO).
*   **Object-Oriented Design:** Uses classes and inheritance for modularity, maintainability, and testability.
*   **Microservice-Inspired Architecture:**  Decouples detection, response coordination, and specific response actions into separate components.
*   **Dependency Injection:**  Improves testability and flexibility.
*   **Factory Pattern:** Simplifies object creation.
*   **Comprehensive Error Handling:** Includes robust error handling with detailed logging.
*   **Secure Configuration:** Uses environment variables for all sensitive data (credentials, configuration settings).
*   **Thorough Testing:** Includes a comprehensive `unittest` suite with extensive mocking.

## Architecture

The system comprises the following key components:

*   **`IncidentDetectionService`:**  Simulates incident detection.  In a real-world scenario, this would integrate with AWS GuardDuty, a SIEM, or other threat detection tools.
*   **`IncidentResponseService`:**  Coordinates the response workflow, receiving the instance ID from the detection service and orchestrating the actions of the responders.
*   **`IncidentResponder` (Abstract Base Class):**  Defines a common interface (`respond`) for all responder classes.
*   **`InstanceIsolator`:**  Isolates a compromised instance by changing its security group.
*   **`ForensicDataCollector`:** Collects forensic data (logs and memory dump) from the isolated instance.
*   **`EmailNotifier`:** Sends email notifications.
*   **`ResponderFactory`:**  Creates instances of responder classes.

## Prerequisites

*   **Python 3.7+:**  The code is written in Python 3.
*   **AWS Account:** You need an AWS account with appropriate permissions.
*   **AWS CLI Configured:**  The AWS CLI must be installed and configured with credentials that have the necessary permissions (see IAM Permissions section below).
*   **LiME (Optional but Recommended):**  For memory dumps, LiME (Linux Memory Extractor) should be pre-installed on your EC2 instances.  See [LiME Documentation](https://github.com/504ensicsLabs/LiME) for installation instructions.  Without LiME, the memory dump functionality will not work.
*   **Isolation Security Group:** Create a security group in your AWS account that denies *all* inbound and outbound traffic.  This will be used to isolate compromised instances.  Note the security group ID; you'll need it for the `ISOLATION_SECURITY_GROUP_ID` environment variable.
*  **SMTP server:** You will need access to an SMTP server that can send emails.

## Installation and Setup

1.  **Clone the Repository:**

    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Create a Virtual Environment (Recommended):**

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate  # On Windows
    ```

3.  **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```
    (Create a `requirements.txt` file with `boto3` in it if you haven't already).

4.  **Configure Environment Variables:**

    Create a `.env` file (or set environment variables directly) with the following:

    ```
    AWS_ACCESS_KEY_ID=<your_aws_access_key>
    AWS_SECRET_ACCESS_KEY=<your_aws_secret_key>
    AWS_REGION=<your_aws_region> (e.g., us-west-1)
    ISOLATION_SECURITY_GROUP_ID=<your_isolation_security_group_id>
    EMAIL_FROM=alerts@yourcompany.com
    EMAIL_TO=ciso@yourcompany.com
    SMTP_SERVER=smtp.yourcompany.com
    SMTP_PORT=587
    SMTP_USER=<your_smtp_username> (optional, if required by your SMTP server)
    SMTP_PASS=<your_smtp_password> (optional, if required by your SMTP server)
    LOG_LEVEL=INFO  (optional, defaults to INFO)

    ```
    **Important:** Replace the placeholder values with your actual credentials and configuration.  *Never* hardcode credentials in the code.

    You can load these environment variables using a library like `python-dotenv`:

    ```bash
    pip install python-dotenv
    ```

    Then, add these lines at the beginning of your `your_script.py` file (before importing other modules):
    ```python
    from dotenv import load_dotenv
    load_dotenv()
    ```

5. **Update LiME Path (if necessary):**

    In `ForensicDataCollector._collect_memory_dump()`, update the `/path/to/lime.ko` placeholder with the actual path to the `lime.ko` kernel module on your instances. This path *must* be correct for memory dumping to work.

## Running the Script

To run the script, execute the main Python file:

```bash
python your_script.py