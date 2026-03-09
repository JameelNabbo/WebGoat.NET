"""Test: Weak Cryptography vulnerabilities"""
import hashlib
from Crypto.Cipher import DES, ARC4
from Crypto.PublicKey import RSA

def hash_password(password):
    # Weak: MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

def hash_data(data):
    # Weak: SHA1
    return hashlib.sha1(data.encode()).hexdigest()

def hash_dynamic(data, algo):
    # Weak: hashlib.new with weak algo
    return hashlib.new("md5", data.encode()).hexdigest()

def encrypt_data(data, key):
    # Weak: DES cipher
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

def stream_cipher(data, key):
    # Weak: RC4 cipher
    cipher = ARC4.new(key)
    return cipher.encrypt(data)

def generate_key():
    # Weak: Small RSA key
    key = RSA.generate(1024)
    return key
