"""Test: SSL/TLS verification disabled"""
import requests
import httpx

def fetch_data(url):
    # SSL verification disabled
    response = requests.get(url, verify=False)
    return response.json()

def post_data(url, data):
    # SSL verification disabled on POST
    response = requests.post(url, json=data, verify=False)
    return response.status_code

def httpx_fetch(url):
    # httpx with verify=False
    response = httpx.get(url, verify=False)
    return response.text
