// Vulnerable: Path Traversal + SSRF + Open Redirect samples
const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const app = express();

app.use(express.json());

// Path Traversal: direct user input in file read
app.get('/file', (req, res) => {
  const fileName = req.query.name;
  const content = fs.readFileSync('/uploads/' + fileName);
  res.send(content);
});

// Path Traversal with path.join (partially mitigated but still vulnerable)
app.get('/download', (req, res) => {
  const userPath = req.query.path;
  const filePath = path.join('/var/data', userPath);
  fs.readFile(filePath, (err, data) => {
    res.send(data);
  });
});

// SSRF: user-controlled URL in server-side request
app.get('/fetch', (req, res) => {
  const url = req.query.url;
  axios.get(url).then(response => {
    res.json(response.data);
  });
});

// SSRF via fetch API
app.post('/proxy', async (req, res) => {
  const targetUrl = req.body.url;
  const response = await fetch(targetUrl);
  const data = await response.json();
  res.json(data);
});

// Open Redirect
app.get('/redirect', (req, res) => {
  const returnUrl = req.query.returnUrl;
  res.redirect(returnUrl);
});

// Open Redirect via window.location
function handleLogin(redirectUrl) {
  window.location.href = redirectUrl;
}

app.listen(3003);
