"""Test: Flask-specific vulnerabilities"""
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)
app.secret_key = "weak"

@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Template injection via render_template_string
    template = f"<h1>Results for: {query}</h1>"
    return render_template_string(template)

@app.route("/redirect")
def do_redirect():
    url = request.args.get("url")
    # Open redirect
    return redirect(url)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if file:
        # Insecure file upload - no extension check
        file.save(f"/uploads/{file.filename}")
    return "OK"

if __name__ == "__main__":
    app.run(debug=True)
