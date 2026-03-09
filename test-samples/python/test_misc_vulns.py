"""Test: Miscellaneous vulnerabilities (integer overflow, buffer issues, prototype pollution, temp files)"""
import ctypes
import struct
import tempfile
import os
from flask import request

def process_size():
    size = request.args.get("size")
    # Integer overflow in ctypes
    c_size = ctypes.c_int(int(size))
    
    # Buffer with user-controlled size
    buf = ctypes.create_string_buffer(int(size))
    
    # Struct with user-controlled format
    fmt = request.args.get("fmt")
    data = struct.pack(fmt, 42)
    
    return "OK"

def insecure_temp():
    # Insecure temp file creation
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as f:
        f.write("sensitive data")
    return path

class VulnerableClass:
    def __init__(self):
        self.data = {}
    
    def merge(self, user_dict):
        # Prototype pollution via __class__
        for key in user_dict:
            if hasattr(self, key):
                setattr(self, key, user_dict[key])
        # Accessing __class__
        cls = self.__class__
        bases = self.__bases__
