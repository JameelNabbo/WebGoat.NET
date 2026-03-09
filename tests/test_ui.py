#!/usr/bin/env python3
"""
UI Tests
=========
Tests that the SAST Scanner UI serves correctly and includes
expected elements. Uses requests (no browser required).

Also tests CORS headers on the gateway API.
"""

import pytest
import requests

UI_BASE = "http://localhost:9080"
GATEWAY_BASE = "http://localhost:9000"
TIMEOUT = 10


# ═══════════════════════════════════════════════════════════════════════════
# UI SERVING TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestUIServing:
    """Tests that the UI web server is running and serving content."""

    def test_ui_loads(self):
        """GET :9080 should return 200 with HTML content."""
        resp = requests.get(UI_BASE + "/", timeout=TIMEOUT)
        assert resp.status_code == 200, \
            "UI should return 200, got {}".format(resp.status_code)
        assert "text/html" in resp.headers.get("Content-Type", ""), \
            "UI should serve HTML content"

    def test_ui_returns_html(self):
        """Response body should contain valid HTML structure."""
        resp = requests.get(UI_BASE + "/", timeout=TIMEOUT)
        text = resp.text.lower()
        assert "<html" in text, "Response should contain <html> tag"
        assert "</html>" in text, "Response should contain closing </html> tag"
        assert "<head" in text, "Response should contain <head> tag"
        assert "<body" in text, "Response should contain <body> tag"

    def test_ui_has_title(self):
        """Page should have a title."""
        resp = requests.get(UI_BASE + "/", timeout=TIMEOUT)
        text = resp.text.lower()
        assert "<title>" in text, "Page should have a <title> element"

    def test_ui_has_upload_form(self):
        """HTML should contain a file upload input element."""
        resp = requests.get(UI_BASE + "/", timeout=TIMEOUT)
        text = resp.text.lower()
        # Check for file input or upload-related elements
        has_file_input = 'type="file"' in text or "type='file'" in text
        has_upload_text = "upload" in text or "drop" in text or "browse" in text
        has_input = "<input" in text
        assert has_file_input or has_upload_text or has_input, \
            "UI should have a file upload mechanism"

    def test_ui_has_scanner_status(self):
        """HTML should reference scanner dashboard or status."""
        resp = requests.get(UI_BASE + "/", timeout=TIMEOUT)
        text = resp.text.lower()
        has_scanner_ref = any(kw in text for kw in [
            "scanner", "status", "dashboard", "health",
            "sast", "vulnerability", "scan"
        ])
        assert has_scanner_ref, \
            "UI should reference scanners or scanning functionality"

    def test_ui_has_css(self):
        """Page should include CSS styling."""
        resp = requests.get(UI_BASE + "/", timeout=TIMEOUT)
        text = resp.text.lower()
        has_css = "<style" in text or 'rel="stylesheet"' in text or "style=" in text
        assert has_css, "UI should include CSS styling"

    def test_ui_has_javascript(self):
        """Page should include JavaScript for interactivity."""
        resp = requests.get(UI_BASE + "/", timeout=TIMEOUT)
        text = resp.text.lower()
        has_js = "<script" in text
        assert has_js, "UI should include JavaScript"

    def test_ui_404_handling(self):
        """Requesting a non-existent path should return 404."""
        resp = requests.get(
            UI_BASE + "/this-page-does-not-exist-xyz123",
            timeout=TIMEOUT
        )
        # SimpleHTTPRequestHandler returns 404 for missing files
        assert resp.status_code == 404, \
            "Non-existent page should return 404, got {}".format(resp.status_code)


# ═══════════════════════════════════════════════════════════════════════════
# API CORS TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestAPICors:
    """Tests that the gateway API returns proper CORS headers."""

    def test_api_cors_headers(self):
        """Gateway should return Access-Control-Allow-Origin header."""
        resp = requests.get(
            GATEWAY_BASE + "/health",
            headers={"Origin": "http://localhost:9080"},
            timeout=TIMEOUT,
        )
        assert resp.status_code == 200
        cors_header = resp.headers.get("access-control-allow-origin", "")
        assert cors_header, \
            "Gateway should return Access-Control-Allow-Origin header"

    def test_api_cors_preflight(self):
        """Gateway should handle OPTIONS preflight request."""
        resp = requests.options(
            GATEWAY_BASE + "/scan",
            headers={
                "Origin": "http://localhost:9080",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
            timeout=TIMEOUT,
        )
        # Should not return 405 Method Not Allowed
        assert resp.status_code in (200, 204), \
            "OPTIONS preflight should succeed, got {}".format(resp.status_code)

    def test_api_cors_wildcard(self):
        """Gateway configured with allow_origins=['*'] should accept any origin."""
        resp = requests.get(
            GATEWAY_BASE + "/health",
            headers={"Origin": "https://example.com"},
            timeout=TIMEOUT,
        )
        cors = resp.headers.get("access-control-allow-origin", "")
        assert cors == "*" or cors == "https://example.com", \
            "CORS should allow all origins, got: {}".format(cors)


# ═══════════════════════════════════════════════════════════════════════════
# GATEWAY API ENDPOINT TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestGatewayEndpoints:
    """Tests for gateway API endpoints accessible from the UI."""

    def test_scanners_endpoint(self):
        """GET /scanners should list available scanners."""
        resp = requests.get(GATEWAY_BASE + "/scanners", timeout=TIMEOUT)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict), "Should return a dict of scanners"
        assert len(data) > 0, "Should have at least one scanner"

    def test_health_response_format(self):
        """Health endpoint should return well-formed JSON."""
        resp = requests.get(GATEWAY_BASE + "/health", timeout=TIMEOUT)
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "service" in data or "scanner" in data

    def test_invalid_endpoint(self):
        """Requesting invalid endpoint should return 404 or 405."""
        resp = requests.get(
            GATEWAY_BASE + "/nonexistent-endpoint",
            timeout=TIMEOUT,
        )
        assert resp.status_code in (404, 405, 422), \
            "Invalid endpoint should not return 200"


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
