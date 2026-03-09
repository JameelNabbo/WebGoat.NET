"""Test: Hardcoded Secrets vulnerabilities"""

# Hardcoded passwords
DATABASE_PASSWORD = "SuperSecretP@ss123"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
SECRET_KEY = "my-very-secret-key-12345"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
JWT_SECRET = "jwt-weak-secret"
AUTH_TOKEN = "ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_1234"
SLACK_TOKEN = "xoxb-FAKE-TEST-TOKEN"

# Connection strings with embedded credentials
db_url = "postgresql://admin:password123@localhost:5432/mydb"
redis_url = "redis://:s3cret@localhost:6379"

class Config:
    secret_key = "hardcoded-flask-secret"
    db_password = "AnotherHardcodedPassword!"
    private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB..."
    stripe_api_key = "sk_live_FAKE_TEST_KEY"
