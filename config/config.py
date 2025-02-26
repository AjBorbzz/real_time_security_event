import os
import logging

class Config:
    """Configuration settings for the application, using environment variables."""
    
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

    @classmethod
    def setup_logging(cls):
        """Configures logging settings."""
        logging.basicConfig(level=cls.LOG_LEVEL, 
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Initialize logging
Config.setup_logging()
