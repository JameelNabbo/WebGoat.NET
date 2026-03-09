"""Test: JWT vulnerabilities"""
import jwt

def create_token(user_id):
    # JWT with weak secret
    token = jwt.encode({"user_id": user_id}, "secret", algorithm="HS256")
    return token

def decode_token_no_algo(token):
    # JWT decode without explicit algorithms
    payload = jwt.decode(token, "secret")
    return payload

def decode_token_none_algo(token):
    # JWT decode allowing 'none' algorithm
    payload = jwt.decode(token, "secret", algorithms=["HS256", "none"])
    return payload

def decode_no_verify(token):
    # JWT decode without verification
    payload = jwt.decode(token, "secret", algorithms=["HS256"],
                        options={"verify_signature": False})
    return payload
