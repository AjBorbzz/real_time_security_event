import unittest
from unittest.mock import patch, MagicMock, call
import boto3
import os
import subprocess
from your_script import (  # Replace 'your_script' with the actual filename
    InstanceIsolator,
    ForensicDataCollector,
    EmailNotifier,
    IncidentResponseService,
    IncidentDetectionService,
    ResponderFactory,
)

# --- Setup Mock Environment Variables ---
# Crucial: Use a dictionary to simulate os.environ, and patch os.environ.get
@patch.dict(os.environ, {
    'AWS_ACCESS_KEY_ID': 'test_access_key',
    'AWS_SECRET_ACCESS_KEY': 'test_secret_key',
    'AWS_REGION': 'test-region',
    'ISOLATION_SECURITY_GROUP_ID': 'sg-isolation123',
    'EMAIL_FROM': 'test@example.com',
    'EMAIL_TO': 'test@example.com',
    'SMTP_SERVER': 'localhost',
    'SMTP_PORT': '25',  # Standard non-TLS port for mocking
    # No SMTP_USER or SMTP_PASS: test both authenticated and unauthenticated cases
    'LOG_LEVEL': 'DEBUG'
})
class TestIncidentResponse(unittest.TestCase):

    def setUp(self):
        """Setup method to create common resources."""
        self.instance_id = 'i-1234567890abcdef0'
        self.factory = ResponderFactory()

    @patch('boto3.client')
    def test_instance_isolator_success(self, mock_boto_client):
        """Test successful instance isolation."""
        # Mock the EC2 client and its methods
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        # Mock the describe_instances response
        mock_ec2.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'SecurityGroups': [{'GroupId': 'sg-original1'}, {'GroupId': 'sg-original2'}]
                }]
            }]
        }

        # Mock the modify_instance_attribute call (no return value needed)
        mock_ec2.modify_instance_attribute = MagicMock()

        isolator = InstanceIsolator(self.instance_id)
        result = isolator.respond()

        self.assertTrue(result)  # Check if isolation was successful

        # Assertions for boto3 calls
        mock_ec2.describe_instances.assert_called_once_with(InstanceIds=[self.instance_id])
        mock_ec2.modify_instance_attribute.assert_called_once_with(
            InstanceId=self.instance_id, Groups=['sg-isolation123']
        )


    @patch('boto3.client')
    def test_instance_isolator_failure_clienterror(self, mock_boto_client):
        """Test instance isolation failure due to ClientError."""
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2
        mock_ec2.describe_instances.side_effect = Exception("AWS Error")

        isolator = InstanceIsolator(self.instance_id)
        result = isolator.respond()

        self.assertFalse(result)
        mock_ec2.describe_instances.assert_called_once_with(InstanceIds=[self.instance_id])
        mock_ec2.modify_instance_attribute.assert_not_called()  # Shouldn't be called on error

    @patch('boto3.client')
    def test_instance_isolator_failure_instance_not_found(self, mock_boto_client):
      """Test instance isolation failure when the instance isn't found"""
      mock_ec2 = MagicMock()
      mock_boto_client.return_value = mock_ec2

      # Mock the describe_instances response to indicate the instance is not found
      mock_ec2.describe_instances.return_value = {
          'Reservations': []  # Empty Reservations
      }

      isolator = InstanceIsolator(self.instance_id)
      result = isolator.respond()

      self.assertFalse(result)  # Isolation should fail
      mock_ec2.describe_instances.assert_called_once_with(InstanceIds=[self.instance_id])
      mock_ec2.modify_instance_attribute.assert_not_called()


    @patch('boto3.client')
    @patch('subprocess.run')
    def test_forensic_data_collector_success(self, mock_subprocess_run, mock_boto_client):
        """Test successful forensic data collection."""

        # Mock boto3 client and describe_instances
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{'PrivateIpAddress': '192.168.1.1'}]
            }]
        }

        # Mock subprocess.run for both log collection and memory dump
        mock_subprocess_run.return_value = MagicMock(stdout="Mocked log data", stderr="", returncode=0)

        collector = ForensicDataCollector(self.instance_id)
        collector.respond()

        # Assertions
        mock_boto_client.assert_called()  # Ensure boto3.client was called
        self.assertEqual(mock_subprocess_run.call_count, 2)  # Two calls: logs and memdump

        # More specific checks for the subprocess calls
        expected_log_collection_call = call(
                ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                 'ec2-user@192.168.1.1', 'sudo journalctl'],
                capture_output=True, text=True, check=True, timeout=60
        )
        expected_memory_dump_call =  call('ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ec2-user@192.168.1.1 sudo insmod /path/to/lime.ko "path=/tmp/forensics_i-1234567890abcdef0_20240101_000000/memdump_i-1234567890abcdef0_20240101_000000.lime format=lime"', shell=True, check=True, timeout=300, capture_output=True, text=True)
        mock_subprocess_run.assert_has_calls([expected_log_collection_call, expected_memory_dump_call], any_order = True)

    @patch('boto3.client')
    @patch('subprocess.run')
    def test_forensic_data_collector_log_collection_failure(self, mock_subprocess_run, mock_boto_client):
      """Test log collection failure within ForensicDataCollector"""

      # Mock boto3 client and describe_instances
      mock_ec2 = MagicMock()
      mock_boto_client.return_value = mock_ec2
      mock_ec2.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{'PrivateIpAddress': '192.168.1.1'}]
            }]
        }

      # Mock subprocess.run to simulate a failure in log collection
      mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, "ssh command", stderr="Some SSH error") # Use side_effect to control the behavior
      collector = ForensicDataCollector(self.instance_id)
      collector.respond()

      # Check that _collect_memory_dump was still called, even though _collect_logs failed.
      mock_subprocess_run.assert_called() # Check subprocess.run was called

    @patch('boto3.client')
    @patch('subprocess.run')
    def test_forensic_data_collector_get_ip_failure(self, mock_subprocess_run, mock_boto_client):
        """Test failure to get instance IP."""
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2
        mock_ec2.describe_instances.side_effect = Exception("AWS Error")

        collector = ForensicDataCollector(self.instance_id)
        collector.respond() # Call respond()

        # Neither log collection or memory dump should run if get_ip failed.
        mock_subprocess_run.assert_not_called()

    @patch('smtplib.SMTP')
    def test_email_notifier_success(self, mock_smtp):
        """Test successful email sending."""

        # Mock the SMTP server and its methods
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server  # For context manager

        notifier = EmailNotifier(self.instance_id)
        notifier.respond("Test Subject", "Test Body")

        # Assertions
        mock_smtp.assert_called_once_with('localhost', 25)  # Check SMTP server and port
        mock_server.starttls.assert_called_once()  # Check if starttls was called
        mock_server.sendmail.assert_called_once()  # Check if sendmail was called

        # Since no SMTP_USER/PASS are set, login shouldn't be called.
        mock_server.login.assert_not_called()


    @patch('smtplib.SMTP')
    def test_email_notifier_failure(self, mock_smtp):
        """Test email sending failure."""
        mock_smtp.return_value.__enter__.side_effect = Exception("SMTP Error")

        notifier = EmailNotifier(self.instance_id)
        notifier.respond("Test Subject", "Test Body")  # Call respond

        mock_smtp.assert_called_once_with('localhost', 25)


    @patch('your_script.InstanceIsolator') # Mock the entire class
    @patch('your_script.ForensicDataCollector')
    @patch('your_script.EmailNotifier')
    def test_incident_response_service_handle_incident_success(self, MockNotifier, MockDataCollector, MockIsolator):
      """Test successful incident handling"""
      mock_isolator_instance = MockIsolator.return_value # Get the *instance* of the mocked class
      mock_isolator_instance.respond.return_value = True # Isolation successful

      mock_data_collector_instance = MockDataCollector.return_value
      mock_notifier_instance = MockNotifier.return_value

      response_service = IncidentResponseService(mock_isolator_instance, mock_data_collector_instance, mock_notifier_instance)
      response_service.handle_incident(self.instance_id)

      mock_isolator_instance.respond.assert_called_once()
      mock_data_collector_instance.respond.assert_called_once()
      mock_notifier_instance.respond.assert_called_once()

    @patch('your_script.InstanceIsolator') # Mock the class
    @patch('your_script.ForensicDataCollector')
    @patch('your_script.EmailNotifier')
    def test_incident_response_service_handle_incident_failure(self, MockNotifier, MockDataCollector, MockIsolator):
        """Test incident handling with isolation failure."""
        mock_isolator = MockIsolator.return_value
        mock_isolator.respond.return_value = False  # Simulate isolation failure

        mock_data_collector = MockDataCollector.return_value
        mock_notifier = MockNotifier.return_value

        response_service = IncidentResponseService(mock_isolator, mock_data_collector, mock_notifier)
        response_service.handle_incident(self.instance_id)

        mock_isolator.respond.assert_called_once()
        mock_data_collector.respond.assert_not_called()  # Data collection shouldn't happen
        mock_notifier.respond.assert_called_once() # Notification should happen


    @patch('your_script.ResponderFactory')  # Mock the factory
    def test_incident_detection_service_detect_incident(self, MockResponderFactory):
      """Test incident detection (simulated)."""
      mock_factory = MockResponderFactory.return_value

      detection_service = IncidentDetectionService(mock_factory)
      instance_id = detection_service.detect_incident()

      self.assertIsNotNone(instance_id) # Check an instance_id is returned.

    def test_responder_factory_create_methods(self):
        """Test the responder factory methods"""
        factory = ResponderFactory()

        isolator = factory.create_isolator(self.instance_id)
        self.assertIsInstance(isolator, InstanceIsolator)

        data_collector = factory.create_data_collector(self.instance_id)
        self.assertIsInstance(data_collector, ForensicDataCollector)

        notifier = factory.create_notifier(self.instance_id)
        self.assertIsInstance(notifier, EmailNotifier)

if __name__ == '__main__':
    unittest.main()