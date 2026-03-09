"""Test: XSS vulnerabilities"""
from flask import Flask, request, render_template_string, Markup
from django.utils.safestring import mark_safe
from django.http import HttpResponse

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name")
    
    # XSS via render_template_string
    return render_template_string("<h1>Hello " + name + "</h1>")
    
@app.route("/profile")
def profile():
    bio = request.args.get("bio")
    
    # XSS via Markup
    safe_bio = Markup(bio)
    
    # XSS via mark_safe
    safe_content = mark_safe(f"<div>{bio}</div>")
    
    return str(safe_bio)

def django_view(request):
    user_input = request.GET.get("data")
    # XSS via HttpResponse with user data
    return HttpResponse(f"<html><body>{user_input}</body></html>")
