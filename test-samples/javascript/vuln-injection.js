// Vulnerable: Command Injection + Code Injection samples
const express = require('express');
const { exec, execSync, spawn } = require('child_process');
const app = express();

app.use(express.json());

// Command Injection via exec
app.post('/ping', (req, res) => {
  const host = req.body.host;
  exec(`ping -c 4 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

// Command Injection via execSync with concatenation
app.get('/lookup', (req, res) => {
  const domain = req.query.domain;
  const result = execSync('nslookup ' + domain);
  res.send(result.toString());
});

// Code Injection via eval
app.post('/calculate', (req, res) => {
  const expression = req.body.expr;
  const result = eval(expression);
  res.json({ result });
});

// Code Injection via Function constructor
app.post('/execute', (req, res) => {
  const code = req.body.code;
  const fn = Function('return ' + code);
  res.json({ result: fn() });
});

// Code Injection via setTimeout with string
app.post('/delayed', (req, res) => {
  const action = req.body.action;
  setTimeout(action, 1000);
  res.json({ status: 'scheduled' });
});

// Safe: execFile with array args (should NOT trigger injection, but template triggers)
app.post('/safe-ping', (req, res) => {
  const host = req.body.host;
  // Note: still flagged if using tainted template, but execFile with array is safer
  const { execFile } = require('child_process');
  execFile('ping', ['-c', '4', host], (err, stdout) => {
    res.send(stdout);
  });
});

app.listen(3001);
