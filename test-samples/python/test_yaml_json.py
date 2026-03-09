"""Test: Unsafe YAML and XML parsing"""
import yaml
import xml.etree.ElementTree as ET

def load_config(data):
    # Unsafe YAML: no SafeLoader
    config = yaml.load(data)
    return config

def load_full(data):
    # Unsafe: yaml.full_load
    return yaml.full_load(data)

def load_unsafe(data):
    # Unsafe: yaml.unsafe_load
    return yaml.unsafe_load(data)

def safe_yaml(data):
    # Safe: yaml.safe_load
    return yaml.safe_load(data)

def parse_xml(data):
    # Unsafe XML parsing
    root = ET.fromstring(data)
    return root
