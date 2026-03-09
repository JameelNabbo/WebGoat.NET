// Vulnerable: SQL Injection + NoSQL Injection samples
const express = require('express');
const mysql = require('mysql');
const mongoose = require('mongoose');
const app = express();

app.use(express.json());

// SQL Injection via string concatenation
app.get('/users', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// SQL Injection via template literal
app.post('/search', (req, res) => {
  const term = req.body.searchTerm;
  connection.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`, (err, rows) => {
    res.json(rows);
  });
});

// NoSQL Injection - direct user input as query
app.get('/api/users', (req, res) => {
  const filter = req.query;
  User.find(filter).then(users => res.json(users));
});

// NoSQL Injection via $where
app.post('/api/search', (req, res) => {
  const searchStr = req.body.search;
  User.find({ $where: searchStr }).then(results => {
    res.json(results);
  });
});

// Safe: parameterized query (should NOT trigger)
app.get('/safe-users', (req, res) => {
  const userId = req.query.id;
  db.query('SELECT * FROM users WHERE id = ?', [userId], (err, results) => {
    res.json(results);
  });
});

app.listen(3000);
