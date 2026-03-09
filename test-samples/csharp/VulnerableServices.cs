using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace TestApp.Services
{
    // 10. Hardcoded Secrets
    public class ConfigService
    {
        private string password = "SuperSecretP@ss123!";
        private string apiKey = "sk-api-key-1234567890abcdef1234567890abcdef";
        private string connectionString = "Server=prod-db;Database=app;User=admin;Password=Pr0duction!Pass#2024";
        private string jwtSecret = "my-super-secret-jwt-signing-key-that-should-not-be-here";
        private string secretKey = "AKIAIOSFODNN7EXAMPLE";
        private string privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        public string Token { get; set; } = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded";

        public void Configure()
        {
            var masterKey = "another-secret-key-value-here";
            var encryptionKey = "AES256KeyForEncryption1234567890";
        }
    }

    // 11. Weak Cryptography
    public class CryptoService
    {
        public string HashPassword(string password)
        {
            // Weak: MD5
            var md5 = MD5.Create();
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hash);
        }

        public string HashData(string data)
        {
            // Weak: SHA1
            var sha1 = SHA1.Create();
            var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(data));
            return Convert.ToBase64String(hash);
        }

        public byte[] EncryptData(string plaintext)
        {
            // Weak: DES
            var des = new DESCryptoServiceProvider();
            // ECB mode
            des.Mode = CipherMode.ECB;
            // Hardcoded key
            des.Key = Encoding.UTF8.GetBytes("12345678");
            // Hardcoded IV
            des.IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            
            var encryptor = des.CreateEncryptor();
            return encryptor.TransformFinalBlock(
                Encoding.UTF8.GetBytes(plaintext), 0, plaintext.Length);
        }

        public byte[] WeakEncrypt(string data)
        {
            // Weak: RC2
            var rc2 = new RC2CryptoServiceProvider();
            // Weak: TripleDES
            var tdes = new TripleDESCryptoServiceProvider();
            return null;
        }
    }

    // 12. Insecure Random
    public class TokenService
    {
        public string GenerateToken()
        {
            // Insecure: System.Random for security
            var random = new Random();
            var token = new StringBuilder();
            for (int i = 0; i < 32; i++)
            {
                token.Append((char)random.Next(65, 90));
            }
            return token.ToString();
        }

        public string GenerateOtp()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        public string GenerateSessionId()
        {
            var random = new Random();
            var bytes = new byte[32];
            // Note: This is using Random, not RNGCryptoServiceProvider
            return Convert.ToBase64String(bytes);
        }
    }

    // 14. Entity Framework raw SQL
    public class ProductService
    {
        // Simulated DbContext usage
        public object SearchProducts(string query)
        {
            // These would use a real DbContext
            // context.Products.FromSqlRaw("SELECT * FROM Products WHERE Name = '" + query + "'");
            // context.Database.ExecuteSqlCommand("DELETE FROM Products WHERE Id = " + query);
            return null;
        }
    }

    // 20. Information Disclosure
    public class StartupConfig
    {
        public void Configure(object app)
        {
            // Developer exception page without environment check
            // app.UseDeveloperExceptionPage();
        }
    }

    // 22. File Upload
    public class UploadService
    {
        // File upload without validation
        public async Task<string> Upload(IFormFile file)
        {
            // No extension check, no size check, using original filename
            var filePath = Path.Combine("/uploads", file.FileName);
            using var stream = new FileStream(filePath, FileMode.Create);
            await file.CopyToAsync(stream);
            return filePath;
        }

        // Another upload with original filename
        public async Task<string> UploadDocument(IFormFile document)
        {
            var path = Path.Combine("/documents", document.FileName);
            using var stream = System.IO.File.Create(path);
            await document.CopyToAsync(stream);
            return path;
        }
    }

    // 23. Race Conditions
    public class CacheService
    {
        // Static mutable state without synchronization
        private static Dictionary<string, object> _cache = new Dictionary<string, object>();
        private static List<string> _activeUsers = new List<string>();
        private static int _counter;

        public object GetOrCreate(string key, Func<object> factory)
        {
            // TOCTOU pattern
            if (!_cache.ContainsKey(key))
            {
                _cache[key] = factory();
            }
            return _cache[key];
        }

        // File TOCTOU
        public string ReadFileIfExists(string path)
        {
            if (File.Exists(path))
            {
                return File.ReadAllText(path);
            }
            return null;
        }
    }

    // 25. Logging Sensitive Data
    public class AuthenticationService
    {
        private readonly ILogger<AuthenticationService> _logger;

        public AuthenticationService(ILogger<AuthenticationService> logger)
        {
            _logger = logger;
        }

        public bool Login(string username, string password)
        {
            _logger.LogInformation($"Login attempt: user={username}, password={password}");
            
            var token = GenerateToken();
            _logger.LogDebug($"Generated token: {token}");
            
            _logger.LogWarning($"Failed login with credentials: {username}:{password}");

            var apiKey = GetApiKey();
            _logger.LogInformation($"Using API key: {apiKey}");

            return true;
        }

        public void ProcessPayment(string creditCard, string cvv)
        {
            _logger.LogInformation($"Processing payment with card: {creditCard}, CVV: {cvv}");
        }

        private string GenerateToken() => "token";
        private string GetApiKey() => "key";
    }

    // 26. SSL/TLS Issues
    public class HttpService
    {
        public HttpClient CreateUnsafeClient()
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
            return new HttpClient(handler);
        }

        public void DisableSslValidation()
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;
        }
    }

    // 27. Timing Attacks
    public class ApiKeyValidator
    {
        private const string ValidApiKey = "correct-api-key-12345";
        private const string ValidToken = "valid-jwt-token-here";

        public bool ValidateApiKey(string apiKey)
        {
            // Timing attack: string comparison
            return apiKey == ValidApiKey;
        }

        public bool VerifyToken(string token)
        {
            // Timing attack: Equals
            return ValidToken.Equals(token);
        }

        public bool CheckPassword(string inputHash, string storedHash)
        {
            // Timing attack: string equality for hash
            return inputHash == storedHash;
        }

        public bool VerifySignature(string signature, string expected)
        {
            return signature == expected;
        }

        public bool ValidateHmac(string hmac, string expectedHmac)
        {
            return hmac.Equals(expectedHmac);
        }
    }

    // 30. Regex DoS
    public class ValidationService
    {
        public bool ValidateEmail(string email)
        {
            // ReDoS: nested quantifiers
            var pattern = @"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.([a-zA-Z]+)*$";
            return Regex.IsMatch(email, pattern);
        }

        public bool ValidateUrl(string url)
        {
            // User input as regex
            return Regex.IsMatch("test", url);
        }

        public bool ComplexValidation(string input)
        {
            // Complex regex without timeout
            var regex = new Regex(@"^(https?:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$");
            return regex.IsMatch(input);
        }
    }
}
