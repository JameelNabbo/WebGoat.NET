"""Test: Open Redirect vulnerabilities"""
from flask import Flask, request, redirect
from django.http import HttpResponseRedirect
from fastapi.responses import RedirectResponse

app = Flask(__name__)

@app.route("/login")
def login():
    next_url = request.args.get("next")
    # Open redirect
    return redirect(next_url)

def django_redirect(request):
    url = request.GET.get("redirect_url")
    # Django open redirect
    return HttpResponseRedirect(url)
