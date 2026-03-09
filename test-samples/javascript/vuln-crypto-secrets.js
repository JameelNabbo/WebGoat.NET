// Vulnerable: Hardcoded Secrets + Weak Crypto + Insecure Random
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Hardcoded API key
const apiKey = 'AKIAIOSFODNN7EXAMPLE';

// Hardcoded password
const dbPassword = 'SuperSecretP@ssw0rd!';

// Hardcoded JWT secret
const jwtSecret = 'my-jwt-secret-key-2024';

// Hardcoded connection string
const connectionString = 'mongodb://admin:password123@localhost:27017/mydb';

// Hardcoded GitHub token
const githubToken = 'ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_1234';

// Weak hash: MD5
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Weak hash: SHA1
function hashData(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// Deprecated createCipher
function encryptData(data, key) {
  const cipher = crypto.createCipher('aes-256-cbc', key);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Weak cipher: DES
function weakEncrypt(data, key) {
  const cipher = crypto.createCipheriv('des', key, Buffer.alloc(8));
  return cipher.update(data, 'utf8', 'hex');
}

// Insecure random for token generation
function generateToken() {
  const token = Math.random().toString(36).substring(2);
  return token;
}

// Insecure random for session ID
function createSessionId() {
  const sessionId = Math.random().toString(16).slice(2);
  return sessionId;
}

// Config object with secrets
const config = {
  database: {
    password: 'RealDatabasePassword123!',
    host: 'db.example.com'
  },
  auth: {
    client_secret: 'oauth-client-secret-value',
    api_key: 'sk_live_FAKE_TEST_KEY'
  }
};

// Safe: using environment variable (should NOT trigger)
const safeApiKey = process.env.API_KEY;

// Timing attack: string comparison of tokens
function verifyToken(userToken, storedToken) {
  if (userToken === storedToken) {
    return true;
  }
  return false;
}

// Logging sensitive data
function logUserLogin(username, password) {
  console.log('Login attempt:', username, password);
  console.log(`User ${username} password: ${password}`);
}

module.exports = { hashPassword, encryptData, generateToken, config };
