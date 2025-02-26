import os
import logging

class Config:
    """Configuration settings for the application, dynamically retrieving values."""

    @classmethod
    def get(cls, key, default=None):
        """Generic method to get a config value."""
        return os.environ.get(key, default)

    @classmethod
    def aws_access_key(cls):
        return cls.get('AWS_ACCESS_KEY_ID')

    @classmethod
    def aws_secret_key(cls):
        return cls.get('AWS_SECRET_ACCESS_KEY')

    @classmethod
    def aws_region(cls):
        return cls.get('AWS_REGION', 'us-west-1')

    @classmethod
    def email_from(cls):
        return cls.get('EMAIL_FROM', "alerts@yourcompany.com")

    @classmethod
    def email_to(cls):
        return cls.get('EMAIL_TO', "ciso@yourcompany.com")

    @classmethod
    def smtp_server(cls):
        return cls.get('SMTP_SERVER', "smtp.yourcompany.com")

    @classmethod
    def smtp_port(cls):
        return int(cls.get('SMTP_PORT', 587))

    @classmethod
    def smtp_user(cls):
        return cls.get('SMTP_USER')

    @classmethod
    def smtp_pass(cls):
        return cls.get('SMTP_PASS')

    @classmethod
    def log_level(cls):
        return cls.get('LOG_LEVEL', 'INFO').upper()

    @classmethod
    def setup_logging(cls):
        """Configures logging settings."""
        logging.basicConfig(level=cls.log_level(),
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Initialize logging
Config.setup_logging()
