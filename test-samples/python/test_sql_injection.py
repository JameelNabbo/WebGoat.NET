"""Test: SQL Injection vulnerabilities"""
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/users")
def get_users():
    user_id = request.args.get("id")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    
    # SQL Injection via string concatenation
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    
    # SQL Injection via f-string
    cursor.execute(f"SELECT * FROM users WHERE name='{user_id}'")
    
    # SQL Injection via % formatting
    cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)
    
    # SQL Injection via .format()
    cursor.execute("SELECT * FROM users WHERE id={}".format(user_id))
    
    return str(cursor.fetchall())

@app.route("/search")
def search():
    query = request.args.get("q")
    from sqlalchemy import text, create_engine
    engine = create_engine("sqlite:///db.sqlite")
    # SQLAlchemy text() with f-string
    result = engine.execute(text(f"SELECT * FROM items WHERE name LIKE '%{query}%'"))
    return str(result)
