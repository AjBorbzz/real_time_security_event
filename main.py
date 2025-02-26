import boto3
import smtplib
import datetime
import subprocess
import os
import logging
import json
from email.mime.text import MIMEText
from botocore.exceptions import ClientError
from abc import ABC, abstractmethod

# --- Configuration (Environment Variables) ---
# Use a consistent prefix (e.g., IR_) for all related environment variables
AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.environ.get('AWS_REGION', 'us-west-1')
ISOLATION_SECURITY_GROUP_ID = os.environ.get('ISOLATION_SECURITY_GROUP_ID')
EMAIL_FROM = os.environ.get('EMAIL_FROM', "alerts@yourcompany.com")
EMAIL_TO = os.environ.get('EMAIL_TO', "ciso@yourcompany.com")
SMTP_SERVER = os.environ.get('SMTP_SERVER', "smtp.yourcompany.com")
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASS = os.environ.get('SMTP_PASS')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# --- Abstract Base Class for Responders ---

class IncidentResponder(ABC):
    """Abstract base class for incident responders."""

    def __init__(self, instance_id):
        self.instance_id = instance_id
        self.logger = logging.getLogger(self.__class__.__name__)  # Logger per class

    @abstractmethod
    def respond(self):
        """Responds to an incident.  Must be implemented by subclasses."""
        pass

# --- Concrete Responder Classes ---

class InstanceIsolator(IncidentResponder):
    """Isolates an EC2 instance."""

    def __init__(self, instance_id, security_group_id=ISOLATION_SECURITY_GROUP_ID):
        super().__init__(instance_id)
        self.security_group_id = security_group_id
        self.ec2_client = boto3.client('ec2', aws_access_key_id=AWS_ACCESS_KEY,
                                       aws_secret_access_key=AWS_SECRET_KEY, region_name=AWS_REGION)

    def respond(self):
        """Isolates the instance by changing its security group."""
        try:
            response = self.ec2_client.describe_instances(InstanceIds=[self.instance_id])
            current_sg_ids = [sg['GroupId'] for sg in response['Reservations'][0]['Instances'][0]['SecurityGroups']]

            new_sg_ids = [self.security_group_id]
            self.ec2_client.modify_instance_attribute(InstanceId=self.instance_id, Groups=new_sg_ids)
            self.logger.info(f"Instance {self.instance_id} isolated to {self.security_group_id}. Original SGs: {current_sg_ids}")
            return True  # Indicate success
        except ClientError as e:
            self.logger.error(f"Failed to isolate instance {self.instance_id}: {e}", exc_info=True)
            return False
        except IndexError as e:
            self.logger.error(f"Instance {self.instance_id} not found: {e}", exc_info=True)
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during isolation: {e}", exc_info=True)
            return False

class ForensicDataCollector(IncidentResponder):
    """Collects forensic data from an EC2 instance."""

    def __init__(self, instance_id):
        super().__init__(instance_id)
        self.ec2_client = boto3.client('ec2', aws_access_key_id=AWS_ACCESS_KEY,
                                      aws_secret_access_key=AWS_SECRET_KEY, region_name=AWS_REGION)

    def respond(self):
        """Collects logs and memory dump (using LiME)."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        data_directory = f"/tmp/forensics_{self.instance_id}_{timestamp}"
        os.makedirs(data_directory, exist_ok=True)
        self.logger.info(f"Collecting forensic data from {self.instance_id} to {data_directory}")

        try:
            instance_ip = self._get_instance_ip()
            if not instance_ip:
                return # Error already logged in _get_instance_ip
            self._collect_logs(instance_ip, data_directory)
            self._collect_memory_dump(instance_ip, data_directory)
             # --- Add more data collection steps here (e.g., network traffic) ---
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during data collection: {e}", exc_info=True)

    def _get_instance_ip(self):
        """Retrieves the private IP address of the instance."""
        try:
            response = self.ec2_client.describe_instances(InstanceIds=[self.instance_id])
            instance_ip = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
            return instance_ip
        except (ClientError, IndexError) as e:
            self.logger.error(f"Could not retrieve IP for {self.instance_id}: {e}", exc_info=True)
            return None


    def _collect_logs(self, instance_ip, data_directory):
        """Collects system logs using journalctl."""
        log_file_path = os.path.join(data_directory, f"logs_{self.instance_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        try:
            result = subprocess.run(
                ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                 f'ec2-user@{instance_ip}', 'sudo journalctl'],
                capture_output=True, text=True, check=True, timeout=60
            )
            with open(log_file_path, 'w') as log_file:
                log_file.write(result.stdout)
            self.logger.info(f"Logs collected for {self.instance_id} at {log_file_path}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.logger.error(f"Error collecting logs for {self.instance_id}: {e}", exc_info=True)

    def _collect_memory_dump(self, instance_ip, data_directory):
        """Collects a memory dump using LiME (must be pre-installed)."""
        memdump_file_path = os.path.join(data_directory, f"memdump_{self.instance_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.lime")
        try:
            ssh_command = f'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ec2-user@{instance_ip}'
            insmod_command = f'sudo insmod /path/to/lime.ko "path={memdump_file_path} format=lime"' # Use correct LiME path

            result = subprocess.run(f'{ssh_command} {insmod_command}', shell=True, check=True, timeout=300, capture_output=True, text=True)
            self.logger.info(f"Memory dump created: {result.stdout}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.logger.error(f"Error creating memory dump for {self.instance_id}: {e}", exc_info=True)
            if isinstance(e, subprocess.CalledProcessError):
                self.logger.error(f"Error Output: {e.stderr}")


class EmailNotifier(IncidentResponder):
    """Sends email notifications."""

    def __init__(self, instance_id, subject_prefix="Incident Response"):
        super().__init__(instance_id)
        self.subject_prefix = subject_prefix

    def respond(self, subject, body):
        """Sends an email notification."""
        full_subject = f"{self.subject_prefix}: {subject}"
        msg = MIMEText(body)
        msg['Subject'] = full_subject
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO

        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                if SMTP_USER and SMTP_PASS:
                    server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
            self.logger.info(f"Alert email sent to {EMAIL_TO}")
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}", exc_info=True)

# --- Microservice-like Structure (using classes) ---

class IncidentDetectionService:
    """Detects incidents (simulated in this example)."""
    def __init__(self, responder_factory):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.responder_factory = responder_factory # Dependency Injection


    def detect_incident(self):
        """Simulates incident detection.  In a real system, this would
        integrate with GuardDuty, a SIEM, etc.
        """
        compromised_instance_id = 'i-0abcd1234efgh5678'  # Replace with actual detection logic
        self.logger.info(f"Incident detected on instance: {compromised_instance_id}")
        return compromised_instance_id

class IncidentResponseService:
    """Coordinates the incident response process."""

    def __init__(self, isolator, data_collector, notifier):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.isolator = isolator
        self.data_collector = data_collector
        self.notifier = notifier

    def handle_incident(self, instance_id):
        """Handles the incident response workflow."""
        self.logger.info(f"Handling incident for instance: {instance_id}")

        if self.isolator.respond():  # Isolate and check success
            self.data_collector.respond()
            self.notifier.respond(
                subject=f"{instance_id} Isolated",
                body=f"Instance {instance_id} has been isolated, and forensic data collection has started."
            )
        else:
            self.notifier.respond(
                subject=f"FAILED to isolate {instance_id}",
                body=f"Attempt to isolate instance {instance_id} FAILED.  Manual intervention required."
            )

# --- Factory for Responders (Optional) ---

class ResponderFactory:
    """Creates instances of responder classes."""
    @staticmethod
    def create_isolator(instance_id):
        return InstanceIsolator(instance_id)

    @staticmethod
    def create_data_collector(instance_id):
        return ForensicDataCollector(instance_id)
    @staticmethod
    def create_notifier(instance_id):
      return EmailNotifier(instance_id)

# --- Main Execution ---

if __name__ == "__main__":
    # --- Decoupled services ---
    # Using the factory to create responders.  Easier to manage dependencies.
    factory = ResponderFactory()
    isolator = factory.create_isolator("dummy_instance_id") # Pass a dummy ID initially
    data_collector = factory.create_data_collector("dummy_instance_id")
    notifier = factory.create_notifier("dummy_instance_id")
    # The services don't directly depend on each other.
    detection_service = IncidentDetectionService(factory)

    response_service = IncidentResponseService(isolator, data_collector, notifier)

    # --- Simulate the incident detection and response ---
    compromised_instance = detection_service.detect_incident()

    # Now, we create *new* responders with the correct instance ID.
    if compromised_instance: # Check if detection was successful
      isolator = factory.create_isolator(compromised_instance)
      data_collector = factory.create_data_collector(compromised_instance)
      notifier = factory.create_notifier(compromised_instance)

      response_service = IncidentResponseService(isolator, data_collector, notifier)
      response_service.handle_incident(compromised_instance)