// Vulnerable: Express Security Issues (CORS, Cookies, Headers, CSRF, Auth, Upload)
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const multer = require('multer');
const app = express();

app.use(express.json());

// CORS wildcard
app.use(cors({ origin: '*' }));

// Manual wildcard CORS header
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

// Insecure cookie - missing all flags
app.get('/login', (req, res) => {
  res.cookie('sessionId', 'abc123');
  res.json({ loggedIn: true });
});

// Insecure cookie - missing secure and httpOnly
app.get('/set-pref', (req, res) => {
  res.cookie('preferences', JSON.stringify({ theme: 'dark' }), {
    maxAge: 86400000
  });
  res.json({ ok: true });
});

// Missing authentication on admin route
app.get('/admin/users', (req, res) => {
  // No auth middleware!
  res.json({ users: [] });
});

// Missing authentication on API route
app.post('/api/settings', (req, res) => {
  res.json({ updated: true });
});

// Unsafe file upload - no file filter
const upload = multer({
  dest: '/tmp/uploads/',
  limits: { fileSize: 10 * 1024 * 1024 }
});

app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ uploaded: req.file.filename });
});

// Information disclosure: sending stack trace
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack
  });
});

// Trust proxy set to true
app.set('trust proxy', true);

// SSL/TLS disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Session without CSRF
app.use(session({
  secret: 'keyboard-cat-session-secret',
  resave: false,
  saveUninitialized: true
}));

app.listen(3005);
