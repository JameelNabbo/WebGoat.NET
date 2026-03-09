// Vulnerable: XSS (DOM, React, Reflected) samples
const express = require('express');
const app = express();

app.use(express.json());

// Reflected XSS: echoing user input
app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Hello ' + name + '</h1>');
});

// Reflected XSS via template literal
app.get('/profile', (req, res) => {
  const username = req.query.user;
  res.send(`<div class="profile">${username}</div>`);
});

// DOM XSS: innerHTML assignment
function displayResult(userInput) {
  document.getElementById('output').innerHTML = userInput;
}

// DOM XSS: document.write
function renderPage(content) {
  document.write(content);
}

// Safe: textContent (should NOT trigger)
function safeDisplay(text) {
  document.getElementById('output').textContent = text;
}

app.listen(3002);
