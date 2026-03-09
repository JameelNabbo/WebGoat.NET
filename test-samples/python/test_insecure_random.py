"""Test: Insecure Random vulnerabilities"""
import random

def generate_token():
    # Insecure: using random module for security token
    token = random.randint(100000, 999999)
    return token

def generate_session_id():
    # Insecure: random for session ID
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(32))

def generate_password():
    # Insecure: random for password generation
    return random.getrandbits(128)

def shuffle_cards():
    # Insecure: predictable shuffle
    deck = list(range(52))
    random.shuffle(deck)
    return deck
