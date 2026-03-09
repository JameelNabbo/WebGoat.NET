"""Test: SSRF vulnerabilities"""
import requests
import urllib.request
from flask import Flask, request as flask_request

app = Flask(__name__)

@app.route("/fetch")
def fetch():
    url = flask_request.args.get("url")
    
    # SSRF via requests.get with user URL
    response = requests.get(url)
    
    # SSRF via requests.post
    requests.post(url, json={"data": "test"})
    
    # SSRF via urllib
    urllib.request.urlopen(url)
    
    # SSRF with dynamic URL
    api_url = f"http://internal-api/{url}"
    response2 = requests.get(api_url)
    
    return response.text
