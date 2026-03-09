"""Test: Template Injection (SSTI) vulnerabilities"""
from jinja2 import Template, Environment
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/render")
def render():
    template_str = request.args.get("template")
    
    # SSTI via Jinja2 Template
    t = Template(template_str)
    return t.render()

@app.route("/format")
def format_page():
    name = request.args.get("name")
    
    # SSTI via render_template_string with user input
    return render_template_string(f"Hello {name}!")

def render_email(template_text):
    # SSTI via Environment.from_string
    env = Environment()
    t = env.from_string(template_text)
    return t.render()
