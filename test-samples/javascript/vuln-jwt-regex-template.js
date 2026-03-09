// Vulnerable: JWT Issues + Regex DoS + Template Injection + Mass Assignment
const express = require('express');
const jwt = require('jsonwebtoken');
const ejs = require('ejs');
const app = express();

app.use(express.json());

// JWT: algorithm none
app.post('/jwt-none', (req, res) => {
  const token = jwt.sign({ user: 'admin' }, 'secret', { algorithm: 'none' });
  res.json({ token });
});

// JWT: verify without algorithm restriction
app.post('/jwt-verify', (req, res) => {
  const token = req.headers.authorization;
  const decoded = jwt.verify(token, 'my-secret');
  res.json(decoded);
});

// JWT: weak HS256
app.post('/jwt-weak', (req, res) => {
  const payload = req.body;
  const token = jwt.sign(payload, 'weak-key', { algorithm: 'HS256' });
  res.json({ token });
});

// Regex DoS: nested quantifiers
app.post('/validate-email', (req, res) => {
  const email = req.body.email;
  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  if (emailRegex.test(email)) {
    res.json({ valid: true });
  }
  res.json({ valid: false });
});

// Regex DoS: evil regex with user input
app.post('/match', (req, res) => {
  const pattern = req.body.pattern;
  const evilRegex = new RegExp('(a+)+$');
  res.json({ matches: evilRegex.test(pattern) });
});

// Template Injection: user input as template
app.post('/render', (req, res) => {
  const template = req.body.template;
  const html = ejs.render(template, { name: 'World' });
  res.send(html);
});

// Mass Assignment: spreading user input into DB
app.post('/api/users', (req, res) => {
  const userData = req.body;
  User.create({ ...userData, createdAt: new Date() }).then(user => {
    res.json(user);
  });
});

// Mass Assignment: direct user object to DB
app.put('/api/users/:id', (req, res) => {
  const updates = req.body;
  User.findOneAndUpdate({ _id: req.params.id }, updates).then(user => {
    res.json(user);
  });
});

// Unsafe deserialization
const serialize = require('node-serialize');
app.post('/data', (req, res) => {
  const input = req.body.payload;
  const obj = serialize.unserialize(input);
  res.json(obj);
});

// SSL/TLS: rejectUnauthorized: false
const https = require('https');
const agent = new https.Agent({
  rejectUnauthorized: false
});

app.listen(3006);
