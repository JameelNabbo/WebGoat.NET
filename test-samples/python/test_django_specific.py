"""Test: Django-specific vulnerabilities"""
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseRedirect
from django import forms

# Django settings issues
DEBUG = True
ALLOWED_HOSTS = ['*']
SECRET_KEY = 'django-insecure-abc123def456ghi789jkl012'
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
SECURE_SSL_REDIRECT = False

# CSRF exempt
@csrf_exempt
def process_payment(request):
    amount = request.POST.get("amount")
    return HttpResponseRedirect("/success")

# Mass assignment - ModelForm without fields
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = None  # UserProfile
        fields = '__all__'

class UnsafeForm(forms.ModelForm):
    class Meta:
        model = None  # User
        # No fields or exclude specified!

def open_redirect_view(request):
    next_url = request.GET.get("next")
    return HttpResponseRedirect(next_url)
