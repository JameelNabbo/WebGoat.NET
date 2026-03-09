"""Test: Logging Sensitive Data vulnerabilities"""
import logging

logger = logging.getLogger(__name__)

def authenticate(username, password):
    # Logging sensitive data: password
    logger.info(f"Login attempt: {username} with password {password}")
    
    # Logging token
    token = "abc123"
    print(f"Generated auth_token: {token}")
    
    # Logging API key
    api_key = "sk-12345"
    logger.debug(f"Using API key: {api_key}")
    
    return True

def process_payment(credit_card, amount):
    # Logging credit card
    logger.info(f"Processing payment of {amount} for card {credit_card}")
    return True

def handle_error():
    try:
        raise ValueError("something")
    except:
        pass  # Insufficient logging: swallowed exception
    
    try:
        raise RuntimeError("another")
    except Exception:
        pass  # Insufficient logging: another swallowed exception
