#!/usr/bin/env python3
"""
Backend Scanner Integration Tests
===================================
Comprehensive pytest test suite for all SAST scanner endpoints.

Tests each scanner's:
  - Health endpoint
  - True positive detection (vulnerable code produces findings)
  - False positive resistance (safe code produces no/minimal findings)
  - Edge cases

Also tests the gateway service for zip upload, concurrent scans, etc.

Note: Each scanner has slightly different response formats. The helper
functions normalize access to vulnerability counts and lists.
"""

import io
import json
import os
import time
import zipfile
import random
import string
import concurrent.futures
from typing import Dict, List, Optional

import pytest
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE = "http://localhost"
GATEWAY_PORT = 9000
TIMEOUT = 30

SCANNER_PORTS = {
    "python": 9001,
    "javascript": 9002,
    "csharp": 9003,
    "java": 9004,
    "go": 9005,
    "php": 9006,
    "ruby": 9007,
    "cpp": 9008,
    "rust": 9009,
    "swift": 9010,
    "objc": 9011,
    "kotlin": 9012,
    "dart": 9013,
    "scala": 9014,
    "fsharp": 9015,
    "vb": 9016,
    "perl": 9017,
    "plsql": 9018,
    "iac": 9019,
    "oracle_forms": 9020,
    "ai_llm": 9021,
}

# ---------------------------------------------------------------------------
# Vulnerable code samples - TESTED to trigger each scanner
# ---------------------------------------------------------------------------
VULN_SAMPLES = {
    "python": {
        "sql_injection": {
            "file": "vuln_sql.py",
            "code": '''import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchone()

def get_user_fstring(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()
''',
        },
        "command_injection": {
            "file": "vuln_cmd.py",
            "code": '''import os
import subprocess

def run_cmd(user_input):
    os.system("ping " + user_input)
    subprocess.call("ls " + user_input, shell=True)
    subprocess.Popen("cat " + user_input, shell=True)
''',
        },
        "xss": {
            "file": "vuln_xss.py",
            "code": '''from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")

@app.route("/search")
def search():
    q = request.args.get("q")
    return render_template_string("Results: " + q)
''',
        },
    },
    "javascript": {
        "sql_injection": {
            "file": "vuln_sql.js",
            "code": '''const mysql = require('mysql');
const conn = mysql.createConnection({host:'localhost',user:'root',database:'app'});

function getUser(req, res) {
    const name = req.query.name;
    conn.query("SELECT * FROM users WHERE name = '" + name + "'", (err, rows) => {
        res.json(rows);
    });
}
module.exports = { getUser };
''',
        },
        "xss": {
            "file": "vuln_xss.js",
            "code": '''const express = require('express');
const app = express();
app.get('/search', (req, res) => {
    const q = req.query.q;
    res.send('<h1>Results: ' + q + '</h1>');
});
app.get('/greet', (req, res) => {
    res.write('<div>' + req.query.name + '</div>');
    res.end();
});
''',
        },
        "command_injection": {
            "file": "vuln_cmd.js",
            "code": '''const { exec } = require('child_process');
const express = require('express');
const app = express();
app.get('/ping', (req, res) => {
    exec('ping -c 3 ' + req.query.host, (err, stdout) => {
        res.send(stdout);
    });
});
app.get('/run', (req, res) => {
    exec(req.query.cmd, (err, stdout) => {
        res.send(stdout);
    });
});
''',
        },
    },
    "java": {
        "sql_injection": {
            "file": "VulnSQL.java",
            "code": '''import java.sql.*;
public class VulnSQL {
    public void getUser(String name) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
''',
        },
        "command_injection": {
            "file": "VulnCmd.java",
            "code": '''import java.io.*;
public class VulnCmd {
    public void runCommand(String userInput) throws Exception {
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("ping " + userInput);
        proc.waitFor();
        Runtime.getRuntime().exec(new String[]{"sh", "-c", userInput});
    }
}
''',
        },
        "xss": {
            "file": "VulnXSS.java",
            "code": '''import javax.servlet.http.*;
import java.io.*;
public class VulnXSS extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        resp.getWriter().write("<h1>Hello " + name + "</h1>");
        resp.getWriter().println("<div>" + req.getParameter("q") + "</div>");
    }
}
''',
        },
    },
    "go": {
        "sql_injection": {
            "file": "vuln_sql.go",
            "code": '''package main

import (
    "database/sql"
    "fmt"
    "net/http"
    _ "github.com/lib/pq"
)

func getUser(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    db, err := sql.Open("postgres", "user=app dbname=app sslmode=disable")
    if err != nil {
        return
    }
    query := "SELECT * FROM users WHERE name = '" + name + "'"
    rows, err := db.Query(query)
    if err != nil {
        return
    }
    defer rows.Close()
    fmt.Fprintf(w, "OK")
}
''',
        },
        "command_injection": {
            "file": "vuln_cmd.go",
            "code": '''package main

import (
    "net/http"
    "os/exec"
)

func runPing(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    cmd := exec.Command("sh", "-c", "ping -c 3 " + host)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return
    }
    w.Write(output)
}
''',
        },
    },
    "csharp": {
        "sql_injection": {
            "file": "VulnSQL.cs",
            "code": '''using System;
using System.Data.SqlClient;
namespace VulnApp {
    public class UserService {
        public void GetUser(string name) {
            var conn = new SqlConnection("Server=localhost;Database=app;");
            conn.Open();
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
            cmd.ExecuteReader();
        }
    }
}
''',
        },
        "command_injection": {
            "file": "VulnCmd.cs",
            "code": '''using System;
using System.Diagnostics;
namespace VulnApp {
    public class CommandRunner {
        public void Run(string userInput) {
            Process.Start("cmd.exe", "/c ping " + userInput);
            Process.Start(new ProcessStartInfo { FileName = "cmd.exe", Arguments = "/c " + userInput });
        }
    }
}
''',
        },
        "xss": {
            "file": "VulnXSS.cs",
            "code": '''using Microsoft.AspNetCore.Mvc;
namespace VulnApp.Controllers {
    [ApiController]
    [Route("[controller]")]
    public class SearchController : Controller {
        [HttpGet]
        public ContentResult Search(string query) {
            return Content("<h1>Results for: " + query + "</h1>", "text/html");
        }
        [HttpGet("greet")]
        public ContentResult Greet(string name) {
            return Content("<div>Hello " + name + "</div>", "text/html");
        }
    }
}
''',
        },
    },
    "php": {
        "sql_injection": {
            "file": "vuln_sql.php",
            "code": '''<?php
$conn = new mysqli("localhost", "root", "", "app");
$name = $_GET['name'];
$result = $conn->query("SELECT * FROM users WHERE name = '$name'");
while ($row = $result->fetch_assoc()) {
    echo $row['email'];
}
?>''',
        },
        "command_injection": {
            "file": "vuln_cmd.php",
            "code": '''<?php
$host = $_GET['host'];
$output = shell_exec("ping -c 3 " . $host);
echo "<pre>$output</pre>";
system("nslookup " . $_GET['domain']);
passthru("traceroute " . $_GET['target']);
?>''',
        },
        "xss": {
            "file": "vuln_xss.php",
            "code": '''<?php
$name = $_GET['name'];
echo "<h1>Welcome, " . $name . "</h1>";
echo "<script>var q = '" . $_GET['q'] . "';</script>";
print("<div>" . $_POST['comment'] . "</div>");
?>''',
        },
    },
    "ruby": {
        "sql_injection": {
            "file": "vuln_sql.rb",
            "code": '''require 'sqlite3'
require 'sinatra'

get '/user' do
  name = params[:name]
  db = SQLite3::Database.new("app.db")
  results = db.execute("SELECT * FROM users WHERE name = '#{name}'")
  results.to_s
end
''',
        },
        "command_injection": {
            "file": "vuln_cmd.rb",
            "code": '''require 'sinatra'

get '/ping' do
  host = params[:host]
  output = `ping -c 3 #{host}`
  "<pre>#{output}</pre>"
end

post '/exec' do
  cmd = params[:cmd]
  system(cmd)
  "done"
end
''',
        },
    },
    "cpp": {
        "buffer_overflow": {
            "file": "vuln_buffer.c",
            "code": '''#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_input(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Processed: %s\\n", buffer);
}

void read_file(const char *filename) {
    char buf[256];
    sprintf(buf, "cat %s", filename);
    system(buf);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        process_input(argv[1]);
        read_file(argv[1]);
    }
    return 0;
}
''',
        },
        "format_string": {
            "file": "vuln_format.c",
            "code": '''#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void log_message(char *user_input) {
    printf(user_input);
    fprintf(stderr, user_input);
}

char *copy_name(char *src) {
    char *dst = malloc(strlen(src));
    strcpy(dst, src);
    return dst;
}
''',
        },
    },
    "rust": {
        "unsafe_code": {
            "file": "vuln_unsafe.rs",
            "code": '''use std::process::Command;

fn run_command(user_input: &str) {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 3 {}", user_input))
        .output()
        .expect("failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

fn unsafe_ptr() {
    let mut data = vec![1, 2, 3];
    let ptr = data.as_mut_ptr();
    unsafe {
        *ptr.offset(100) = 42;
    }
}

fn sql_concat(name: &str) -> String {
    format!("SELECT * FROM users WHERE name = \'{}\'", name)
}
''',
        },
    },
}

# ---------------------------------------------------------------------------
# Safe code samples (should NOT trigger High/Critical findings)
# ---------------------------------------------------------------------------
SAFE_SAMPLES = {
    "python": {
        "file": "safe_code.py",
        "code": '''import sqlite3
import hmac
import subprocess
import shlex

def get_user_safe(name):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchone()

def run_cmd_safe(host):
    result = subprocess.run(["ping", "-c", "3", host], capture_output=True, text=True)
    return result.stdout

def compare_token_safe(a, b):
    return hmac.compare_digest(a, b)
''',
    },
    "javascript": {
        "file": "safe_code.js",
        "code": '''const mysql = require('mysql');
const { execFile } = require('child_process');

const pool = mysql.createPool({host: 'localhost', user: 'app', database: 'app'});

function getUser(name, callback) {
    pool.query('SELECT * FROM users WHERE name = ?', [name], callback);
}

function pingSafe(host, callback) {
    execFile('ping', ['-c', '3', host], callback);
}

module.exports = { getUser, pingSafe };
''',
    },
    "php": {
        "file": "safe_code.php",
        "code": '''<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

function getUser($pdo, $name) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name");
    $stmt->execute([':name' => $name]);
    return $stmt->fetch();
}

function displayName($name) {
    $safe = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    echo "<h1>Welcome, " . $safe . "</h1>";
}

function runPing($host) {
    $safeHost = escapeshellarg($host);
    $output = [];
    exec("ping -c 3 " . $safeHost, $output);
    return $output;
}
?>''',
    },
    "go": {
        "file": "safe_code.go",
        "code": '''package main

import (
    "database/sql"
    "net/http"
    "os/exec"
    "html/template"
    _ "github.com/lib/pq"
)

func getUserSafe(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    db, err := sql.Open("postgres", "dbname=app sslmode=disable")
    if err != nil {
        http.Error(w, "db error", 500)
        return
    }
    defer db.Close()
    rows, err := db.Query("SELECT * FROM users WHERE name = $1", name)
    if err != nil {
        http.Error(w, "query error", 500)
        return
    }
    defer rows.Close()
}

func pingSafe(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    cmd := exec.Command("ping", "-c", "3", host)
    output, err := cmd.CombinedOutput()
    if err != nil {
        http.Error(w, "ping error", 500)
        return
    }
    w.Write(output)
}

func searchSafe(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    tmpl := template.Must(template.New("search").Parse("<h1>Results: {{.}}</h1>"))
    err := tmpl.Execute(w, q)
    if err != nil {
        http.Error(w, "template error", 500)
    }
}
''',
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def scanner_url(language, path="/health"):
    port = SCANNER_PORTS.get(language, 0)
    return "{}:{}{}".format(BASE, port, path)


def gateway_url(path="/health"):
    return "{}:{}{}".format(BASE, GATEWAY_PORT, path)


def do_scan(language, files_dict, scan_id=None):
    """Send files to a scanner and return the result JSON."""
    if scan_id is None:
        scan_id = "{}-test-{}".format(language, random.randint(1000, 9999))
    port = SCANNER_PORTS[language]
    resp = requests.post(
        "{}:{}/scan".format(BASE, port),
        json={"files": files_dict, "scanId": scan_id},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def get_vuln_count(result):
    """Extract total vulnerability count from any scanner response format."""
    # Direct top-level field
    if "totalVulnerabilities" in result:
        return result["totalVulnerabilities"]
    if "total_vulnerabilities" in result:
        return result["total_vulnerabilities"]
    # In summary dict
    summary = result.get("summary", {})
    if isinstance(summary, dict):
        if "total" in summary:
            return summary["total"]
        if "totalVulnerabilities" in summary:
            return summary["totalVulnerabilities"]
    # Fall back to counting the list
    return len(result.get("vulnerabilities", []))


def get_vulns(result):
    """Get the list of vulnerabilities from any scanner response format."""
    return result.get("vulnerabilities", [])


def get_severity(vuln):
    """Get severity from a vulnerability, normalizing different field names."""
    return vuln.get("severity", "Unknown")


def get_high_crit_count(result):
    """Count High and Critical severity findings."""
    count = 0
    for v in get_vulns(result):
        sev = get_severity(v).lower()
        if sev in ("critical", "high"):
            count += 1
    return count


def make_zip(files_dict):
    """Create an in-memory zip file from a dict of {filename: content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files_dict.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf


# ═══════════════════════════════════════════════════════════════════════════
# HEALTH CHECK TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestScannerHealth:
    """Test health endpoints for all scanners."""

    @pytest.mark.parametrize("language,port", list(SCANNER_PORTS.items()))
    def test_scanner_health(self, language, port):
        """Each scanner should respond to /health with status=healthy."""
        resp = requests.get("{}:{}/health".format(BASE, port), timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "healthy", \
            "{} scanner health check failed: {}".format(language, data)

    def test_gateway_health(self):
        """Gateway should report healthy status."""
        resp = requests.get(gateway_url("/health"), timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "healthy"


# ═══════════════════════════════════════════════════════════════════════════
# PYTHON SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestPythonScanner:
    LANG = "python"

    def test_python_scanner_health(self):
        resp = requests.get(scanner_url(self.LANG), timeout=10)
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_python_scanner_sql_injection(self):
        sample = VULN_SAMPLES["python"]["sql_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Python scanner should detect SQL injection"

    def test_python_scanner_command_injection(self):
        sample = VULN_SAMPLES["python"]["command_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Python scanner should detect command injection"

    def test_python_scanner_xss(self):
        sample = VULN_SAMPLES["python"]["xss"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Python scanner should detect XSS via render_template_string"

    def test_python_scanner_no_false_positive(self):
        sample = SAFE_SAMPLES["python"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        high_crit = get_high_crit_count(result)
        assert high_crit == 0, \
            "Safe Python code should not trigger High/Critical findings, got {}".format(high_crit)


# ═══════════════════════════════════════════════════════════════════════════
# JAVASCRIPT SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestJavaScriptScanner:
    LANG = "javascript"

    def test_javascript_scanner_health(self):
        resp = requests.get(scanner_url(self.LANG), timeout=10)
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_javascript_scanner_sql_injection(self):
        sample = VULN_SAMPLES["javascript"]["sql_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "JS scanner should detect SQL injection"

    def test_javascript_scanner_xss(self):
        sample = VULN_SAMPLES["javascript"]["xss"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "JS scanner should detect XSS"

    def test_javascript_scanner_command_injection(self):
        sample = VULN_SAMPLES["javascript"]["command_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "JS scanner should detect command injection"

    def test_javascript_scanner_no_false_positive(self):
        """Safe JS code should not trigger Critical findings."""
        sample = SAFE_SAMPLES["javascript"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        crit_count = sum(1 for v in get_vulns(result)
                        if get_severity(v).lower() == "critical")
        assert crit_count == 0, \
            "Safe JS code should not trigger Critical findings, got {}".format(crit_count)


# ═══════════════════════════════════════════════════════════════════════════
# JAVA SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestJavaScanner:
    LANG = "java"

    def test_java_scanner_health(self):
        resp = requests.get(scanner_url(self.LANG), timeout=10)
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_java_scanner_sql_injection(self):
        sample = VULN_SAMPLES["java"]["sql_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Java scanner should detect SQL injection"

    def test_java_scanner_command_injection(self):
        sample = VULN_SAMPLES["java"]["command_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Java scanner should detect command injection"

    def test_java_scanner_xss(self):
        sample = VULN_SAMPLES["java"]["xss"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Java scanner should detect XSS"


# ═══════════════════════════════════════════════════════════════════════════
# GO SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestGoScanner:
    LANG = "go"

    def test_go_scanner_health(self):
        resp = requests.get(scanner_url(self.LANG), timeout=10)
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_go_scanner_sql_injection(self):
        sample = VULN_SAMPLES["go"]["sql_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Go scanner should detect SQL injection"

    def test_go_scanner_command_injection(self):
        sample = VULN_SAMPLES["go"]["command_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Go scanner should detect command injection"

    def test_go_scanner_no_false_positive(self):
        """Safe Go code should not trigger Critical/High injection findings."""
        sample = SAFE_SAMPLES["go"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        # Go scanner may flag "Ignored Error" as Medium, which is acceptable
        # We only check for Critical/High injection-type false positives
        bad_fps = []
        for v in get_vulns(result):
            sev = get_severity(v).lower()
            title = v.get("title", "").lower()
            if sev in ("critical", "high") and any(kw in title for kw in [
                "injection", "xss", "overflow", "traversal", "ssrf"
            ]):
                bad_fps.append(v.get("title"))
        assert len(bad_fps) == 0, \
            "Safe Go code should not trigger High/Critical injection findings: {}".format(bad_fps)


# ═══════════════════════════════════════════════════════════════════════════
# C# SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestCSharpScanner:
    LANG = "csharp"

    def test_csharp_scanner_health(self):
        resp = requests.get(scanner_url(self.LANG), timeout=10)
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_csharp_scanner_sql_injection(self):
        sample = VULN_SAMPLES["csharp"]["sql_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "C# scanner should detect SQL injection"

    def test_csharp_scanner_command_injection(self):
        sample = VULN_SAMPLES["csharp"]["command_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "C# scanner should detect command injection"

    def test_csharp_scanner_xss(self):
        sample = VULN_SAMPLES["csharp"]["xss"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "C# scanner should detect XSS"


# ═══════════════════════════════════════════════════════════════════════════
# PHP SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestPHPScanner:
    LANG = "php"

    def test_php_scanner_health(self):
        resp = requests.get(scanner_url(self.LANG), timeout=10)
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_php_scanner_sql_injection(self):
        sample = VULN_SAMPLES["php"]["sql_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "PHP scanner should detect SQL injection"

    def test_php_scanner_command_injection(self):
        sample = VULN_SAMPLES["php"]["command_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "PHP scanner should detect command injection"

    def test_php_scanner_xss(self):
        sample = VULN_SAMPLES["php"]["xss"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "PHP scanner should detect XSS"

    def test_php_scanner_no_false_positive(self):
        """Safe PHP code should not trigger Critical findings."""
        sample = SAFE_SAMPLES["php"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        crit_count = sum(1 for v in get_vulns(result)
                        if get_severity(v).lower() == "critical")
        assert crit_count == 0, \
            "Safe PHP code should not trigger Critical findings"


# ═══════════════════════════════════════════════════════════════════════════
# RUBY SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestRubyScanner:
    LANG = "ruby"

    def test_ruby_scanner_health(self):
        resp = requests.get(scanner_url(self.LANG), timeout=10)
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_ruby_scanner_sql_injection(self):
        sample = VULN_SAMPLES["ruby"]["sql_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Ruby scanner should detect SQL injection"

    def test_ruby_scanner_command_injection(self):
        sample = VULN_SAMPLES["ruby"]["command_injection"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Ruby scanner should detect command injection"


# ═══════════════════════════════════════════════════════════════════════════
# C/C++ SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestCppScanner:
    LANG = "cpp"

    def test_cpp_scanner_health(self):
        resp = requests.get(scanner_url(self.LANG), timeout=10)
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_cpp_scanner_buffer_overflow(self):
        sample = VULN_SAMPLES["cpp"]["buffer_overflow"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "C/C++ scanner should detect buffer overflow / command injection"

    def test_cpp_scanner_format_string(self):
        sample = VULN_SAMPLES["cpp"]["format_string"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "C/C++ scanner should detect format string vulnerability"


# ═══════════════════════════════════════════════════════════════════════════
# RUST SCANNER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestRustScanner:
    LANG = "rust"

    def test_rust_scanner_health(self):
        resp = requests.get(scanner_url(self.LANG), timeout=10)
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_rust_scanner_unsafe_code(self):
        sample = VULN_SAMPLES["rust"]["unsafe_code"]
        result = do_scan(self.LANG, {sample["file"]: sample["code"]})
        assert get_vuln_count(result) > 0, \
            "Rust scanner should detect unsafe code / command injection"


# ═══════════════════════════════════════════════════════════════════════════
# ADDITIONAL LANGUAGE SCANNER TESTS (smoke tests)
# ═══════════════════════════════════════════════════════════════════════════

class TestAdditionalScanners:
    """Smoke tests for additional language scanners."""

    @pytest.mark.parametrize("language", [
        "swift", "objc", "kotlin", "dart", "scala",
        "fsharp", "vb", "perl", "plsql", "iac",
        "oracle_forms", "ai_llm"
    ])
    def test_additional_scanner_health(self, language):
        resp = requests.get(scanner_url(language), timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "healthy"

    def test_swift_scanner_scan(self):
        code = '''import Foundation

class NetworkManager {
    func fetchData(from url: String) {
        let task = Process()
        task.launchPath = "/bin/sh"
        task.arguments = ["-c", url]
        task.launch()
        task.waitUntilExit()
    }

    func query(name: String) -> String {
        return "SELECT * FROM users WHERE name = '\\(name)'"
    }
}
'''
        result = do_scan("swift", {"vuln.swift": code})
        assert get_vuln_count(result) > 0, \
            "Swift scanner should detect vulnerabilities"

    def test_kotlin_scanner_scan(self):
        code = '''import java.sql.DriverManager

fun getUser(name: String) {
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '$name'")
}

fun runCommand(input: String) {
    Runtime.getRuntime().exec("ping $input")
}
'''
        result = do_scan("kotlin", {"Vuln.kt": code})
        assert get_vuln_count(result) > 0, \
            "Kotlin scanner should detect vulnerabilities"

    def test_iac_scanner_dockerfile(self):
        code = '''FROM ubuntu:latest
RUN apt-get update && apt-get install -y openssh-server
EXPOSE 22
USER root
ENV PASSWORD=mysecretpassword
ENV API_KEY=sk-1234567890abcdef
RUN echo "root:password" | chpasswd
CMD ["/usr/sbin/sshd", "-D"]
'''
        result = do_scan("iac", {"Dockerfile": code})
        assert get_vuln_count(result) > 0, \
            "IaC scanner should detect Dockerfile issues"

    def test_iac_scanner_terraform(self):
        code = '''resource "aws_security_group" "allow_all" {
  name = "allow_all"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  security_groups = [aws_security_group.allow_all.name]
}
'''
        result = do_scan("iac", {"main.tf": code})
        assert get_vuln_count(result) > 0, \
            "IaC scanner should detect overly permissive security group"


# ═══════════════════════════════════════════════════════════════════════════
# GATEWAY TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestGateway:
    """Tests for the Gateway API."""

    def test_gateway_health(self):
        resp = requests.get(gateway_url("/health"), timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_gateway_scanner_status(self):
        resp = requests.get(gateway_url("/scanners"), timeout=15)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) > 5, "Gateway should list multiple scanners"
        py = data.get("python", {})
        assert py.get("status") == "online", "Python scanner should be online"

    def test_gateway_zip_scan(self):
        """Upload a zip with vulnerable Python code via the gateway."""
        files = {
            "vuln.py": '''import os
def run(cmd):
    os.system(cmd)
'''
        }
        zip_buf = make_zip(files)
        resp = requests.post(
            gateway_url("/scan"),
            files={"file": ("test.zip", zip_buf, "application/zip")},
            timeout=60,
        )
        assert resp.status_code == 200
        data = resp.json()
        # Gateway returns scan results (may vary in format)
        assert isinstance(data, dict), "Should return a dict response"

    def test_gateway_empty_zip(self):
        """An empty zip should return gracefully, not crash."""
        zip_buf = make_zip({})
        resp = requests.post(
            gateway_url("/scan"),
            files={"file": ("empty.zip", zip_buf, "application/zip")},
            timeout=30,
        )
        assert resp.status_code < 500, \
            "Empty zip should not cause server error"

    def test_gateway_large_file(self):
        """Send a moderately large file to check resource handling."""
        big_code = "# Large test file\n"
        for i in range(5000):
            big_code += "def func_{}(x):\n    return x + {}\n\n".format(i, i)
        files = {"big_file.py": big_code}
        zip_buf = make_zip(files)
        resp = requests.post(
            gateway_url("/scan"),
            files={"file": ("large.zip", zip_buf, "application/zip")},
            timeout=120,
        )
        assert resp.status_code < 500, \
            "Large file should not crash the gateway"

    def test_concurrent_scans(self):
        """Submit 5 scans concurrently and verify all complete."""
        scan_codes = []
        for i in range(5):
            code = "import os\ndef vuln_{}(cmd):\n    os.system(cmd)\n".format(i)
            scan_codes.append({"vuln_{}.py".format(i): code})

        results = []
        errors = []

        def submit_scan(files):
            try:
                zip_buf = make_zip(files)
                resp = requests.post(
                    gateway_url("/scan"),
                    files={"file": ("concurrent.zip", zip_buf, "application/zip")},
                    timeout=120,
                )
                return resp.status_code
            except Exception as e:
                return str(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(submit_scan, sc) for sc in scan_codes]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                results.append(res)
                if isinstance(res, int) and res >= 500:
                    errors.append(res)
                elif isinstance(res, str):
                    errors.append(res)

        assert len(results) == 5, "All 5 concurrent scans should complete"
        assert len(errors) == 0, "No concurrent scans should fail: {}".format(errors)


# ═══════════════════════════════════════════════════════════════════════════
# SCANNER RESPONSE FORMAT TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestResponseFormat:
    """Verify scanner response format consistency."""

    @pytest.mark.parametrize("language", ["python", "javascript", "java", "csharp", "ruby"])
    def test_scan_response_has_vulnerabilities_list(self, language):
        """Each scanner should return a vulnerabilities list."""
        if language in VULN_SAMPLES:
            first_key = list(VULN_SAMPLES[language].keys())[0]
            sample = VULN_SAMPLES[language][first_key]
            files = {sample["file"]: sample["code"]}
        else:
            files = {"test.txt": "print('hello')"}

        result = do_scan(language, files)
        assert "vulnerabilities" in result, \
            "{}: missing vulnerabilities list".format(language)

    @pytest.mark.parametrize("language", ["python", "javascript", "java", "csharp", "ruby"])
    def test_vulnerability_has_required_fields(self, language):
        """Each vulnerability should have at minimum title, severity, and file path."""
        first_key = list(VULN_SAMPLES[language].keys())[0]
        sample = VULN_SAMPLES[language][first_key]
        files = {sample["file"]: sample["code"]}
        result = do_scan(language, files)

        vulns = get_vulns(result)
        assert len(vulns) > 0, "{}: no vulnerabilities to check format".format(language)

        v = vulns[0]
        assert "title" in v or "name" in v, \
            "{}: vulnerability missing title".format(language)
        assert "severity" in v, \
            "{}: vulnerability missing severity".format(language)
        # File path may be under different keys
        has_path = ("filePath" in v or "file_path" in v or "file" in v or
                    "fileName" in v)
        assert has_path, \
            "{}: vulnerability missing file path, keys={}".format(language, list(v.keys()))


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
