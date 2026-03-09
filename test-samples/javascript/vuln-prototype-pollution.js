// Vulnerable: Prototype Pollution samples
const express = require('express');
const _ = require('lodash');
const app = express();

app.use(express.json());

// Prototype Pollution via __proto__
app.post('/config', (req, res) => {
  const updates = req.body;
  const config = {};
  for (const key in updates) {
    config[key] = updates[key]; // user controls key, can set __proto__
  }
  res.json(config);
});

// Prototype Pollution via dynamic property with tainted key
app.post('/update', (req, res) => {
  const { key, value } = req.body;
  const obj = {};
  obj[key] = value; // key could be __proto__
  res.json(obj);
});

// Prototype Pollution via Object.assign with user data
app.post('/merge', (req, res) => {
  const userConfig = req.body;
  const defaults = { theme: 'light', lang: 'en' };
  const merged = Object.assign(defaults, userConfig);
  res.json(merged);
});

// Prototype Pollution via lodash merge
app.post('/deep-merge', (req, res) => {
  const data = req.body;
  const target = { admin: false };
  _.merge(target, data);
  res.json(target);
});

// Direct __proto__ assignment
function unsafeClone(src) {
  const dst = {};
  dst.__proto__ = src.__proto__;
  return dst;
}

app.listen(3004);
