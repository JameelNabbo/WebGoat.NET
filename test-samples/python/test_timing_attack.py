"""Test: Timing Attack vulnerabilities"""
import hmac

def verify_token(user_token, expected_token):
    # Timing attack: string comparison with ==
    if user_token == expected_token:
        return True
    return False

def check_password(input_password, stored_hash):
    # Timing attack: comparing password hashes with ==
    computed_hash = hash(input_password)
    if computed_hash == stored_hash:
        return True
    return False

def verify_api_key(api_key, valid_key):
    # Timing attack: direct comparison of secret
    return api_key == valid_key

def verify_signature(signature, expected_signature):
    # Timing attack: comparing signatures
    if signature == expected_signature:
        return True
    return False
