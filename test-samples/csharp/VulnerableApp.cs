using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;

// ============================================================
// TEST FILE: Comprehensive vulnerability samples
// This file contains intentional security vulnerabilities
// for testing the C# SAST scanner.
// ============================================================

namespace VulnerableApp.Controllers
{
    // ---- 1. SQL Injection ----
    public class SqlInjectionController : Controller
    {
        [HttpGet]
        public IActionResult Search(string query)
        {
            var userInput = Request.QueryString["search"];

            // VULN: SqlCommand with concatenation
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + userInput + "'");
            cmd.ExecuteReader();

            // VULN: SqlDataAdapter with concatenation
            var adapter = new SqlDataAdapter("SELECT * FROM Products WHERE Category = '" + query + "'", connection);

            // VULN: String interpolation in SQL
            var cmd2 = new SqlCommand($"DELETE FROM Orders WHERE Id = {query}");
            cmd2.ExecuteNonQuery();

            // VULN: Dapper with concatenation
            connection.Query("SELECT * FROM Users WHERE Email = '" + query + "'");

            return View();
        }

        [HttpPost]
        public IActionResult UpdateUser(string userId, string name)
        {
            var input = Request.Form["data"];

            // VULN: EF Core FromSqlRaw with interpolation
            var users = context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {userId}");

            // VULN: ExecuteSqlRaw with concatenation
            context.Database.ExecuteSqlRaw("UPDATE Users SET Name = '" + name + "' WHERE Id = " + userId);

            return Ok();
        }
    }

    // ---- 2. Command Injection ----
    public class CommandController : Controller
    {
        [HttpPost]
        public IActionResult RunDiagnostics(string hostname)
        {
            var userHost = Request.Form["host"];

            // VULN: Process.Start with user input
            Process.Start("ping", "-c 4 " + userHost);

            // VULN: cmd.exe with user input
            Process.Start("cmd.exe", "/c dir " + hostname);

            // VULN: bash with user input
            var psi = new ProcessStartInfo("/bin/bash", "-c \"ls " + userHost + "\"");
            psi.UseShellExecute = true;
            Process.Start(psi);

            return Ok();
        }
    }

    // ---- 3. XSS ----
    public class XssController : Controller
    {
        [HttpGet]
        public void ShowProfile(string name)
        {
            var userInput = Request.QueryString["name"];

            // VULN: Response.Write with user input
            Response.Write("<h1>Welcome " + userInput + "</h1>");

            // VULN: Html.Raw with user input
            Html.Raw(userInput);

            // VULN: HtmlString with dynamic content
            var html = new HtmlString("<script>" + name + "</script>");
        }
    }

    // ---- 4. Path Traversal ----
    public class FileController : Controller
    {
        [HttpGet]
        public IActionResult Download(string filename)
        {
            var userFile = Request.QueryString["file"];

            // VULN: File.ReadAllText with user input
            var content = File.ReadAllText("/uploads/" + userFile);

            // VULN: File.WriteAllText with user-controlled path
            File.WriteAllText(filename, "data");

            // VULN: FileStream with user input
            var stream = new FileStream(userFile, FileMode.Open);

            // VULN: Path.Combine with user input (can be bypassed with absolute paths)
            var path = Path.Combine("/safe/dir", userFile);
            File.ReadAllBytes(path);

            return File(content, "text/plain");
        }
    }

    // ---- 5. Insecure Deserialization ----
    public class DeserializationController : Controller
    {
        [HttpPost]
        public IActionResult Deserialize()
        {
            // VULN: BinaryFormatter
            var formatter = new BinaryFormatter();
            var obj = formatter.Deserialize(Request.Body);

            // VULN: NetDataContractSerializer
            var ncds = new NetDataContractSerializer();

            // VULN: JavaScriptSerializer with SimpleTypeResolver
            var serializer = new JavaScriptSerializer(new SimpleTypeResolver());
            var result = serializer.Deserialize<object>(data);

            // VULN: Json.NET TypeNameHandling.All
            var settings = new JsonSerializerSettings();
            settings.TypeNameHandling = TypeNameHandling.All;
            var obj2 = JsonConvert.DeserializeObject(data, settings);

            return Ok();
        }
    }

    // ---- 6. XXE ----
    public class XxeController : Controller
    {
        [HttpPost]
        public IActionResult ParseXml(string xmlData)
        {
            var userXml = Request.Form["xml"];

            // VULN: XmlDocument without DTD protection
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(userXml);

            // VULN: XmlTextReader without settings
            var reader = new XmlTextReader(new StringReader(userXml));

            // VULN: XmlReader.Create without settings
            var xr = XmlReader.Create(new StringReader(userXml));

            return Ok();
        }
    }

    // ---- 7. SSRF ----
    public class SsrfController : Controller
    {
        private readonly HttpClient _httpClient = new HttpClient();

        [HttpGet]
        public async Task<IActionResult> Fetch(string url)
        {
            var targetUrl = Request.QueryString["url"];

            // VULN: HttpClient with user URL
            var response = await _httpClient.GetAsync(targetUrl);

            // VULN: WebClient with user URL
            var wc = new WebClient();
            var data = wc.DownloadString(url);

            // VULN: HttpClient with concatenated URL
            var response2 = await _httpClient.GetStringAsync("https://api.internal.com/" + url);

            return Ok();
        }
    }

    // ---- 8. LDAP Injection ----
    public class LdapController : Controller
    {
        [HttpPost]
        public IActionResult SearchUser(string username)
        {
            var input = Request.Form["user"];

            // VULN: DirectorySearcher with concatenated filter
            var searcher = new DirectorySearcher();
            searcher.Filter = "(&(objectClass=user)(sAMAccountName=" + input + "))";
            searcher.FindAll();

            return Ok();
        }
    }

    // ---- 9. Hardcoded Secrets ----
    public class SecretsExample
    {
        // VULN: Hardcoded password
        private string password = "SuperSecret123!@#";

        // VULN: Hardcoded API key
        private string apiKey = "sk-1234567890abcdef1234567890abcdef";

        // VULN: Hardcoded connection string
        private string connectionString = "Server=prod-db.internal.com;Database=MainDB;User Id=admin;Password=Pr0d!P@ssw0rd";

        // VULN: Hardcoded JWT token
        private string token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        // VULN: Hardcoded secret key
        private string secretKey = "MyVeryLongAndSecretKeyForEncryption2026!";
    }

    // ---- 10. Weak Cryptography ----
    public class CryptoController : Controller
    {
        public byte[] HashPassword(string password)
        {
            // VULN: MD5
            var md5 = MD5.Create();
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));

            // VULN: SHA1
            var sha1 = SHA1.Create();

            // VULN: DES
            var des = new DESCryptoServiceProvider();

            // VULN: TripleDES
            var tdes = new TripleDESCryptoServiceProvider();

            // VULN: RijndaelManaged
            var rijndael = new RijndaelManaged();

            return hash;
        }
    }

    // ---- 11. Insecure Random ----
    public class TokenGenerator
    {
        public string GenerateToken()
        {
            // VULN: System.Random for security token
            var random = new Random();
            var tokenBytes = new byte[32];
            random.NextBytes(tokenBytes);
            return Convert.ToBase64String(tokenBytes);
        }

        public string GenerateSessionCode()
        {
            // VULN: Random.Next for session code
            var rng = new Random();
            return rng.Next(100000, 999999).ToString();
        }
    }

    // ---- 12. ASP.NET Core Issues ----

    // VULN: CORS allow any origin
    [EnableCors("*")]
    public class InsecureApiController : Controller
    {
        // VULN: Missing authorization on sensitive endpoint
        [HttpDelete]
        public IActionResult DeleteUser(int id)
        {
            // delete user
            return Ok();
        }

        // VULN: Missing authorization on admin endpoint
        [HttpPost]
        public IActionResult UpdateConfig(string key, string value)
        {
            return Ok();
        }
    }

    // VULN: Missing anti-forgery on MVC controller
    public class AccountController : Controller
    {
        // VULN: POST without ValidateAntiForgeryToken
        [HttpPost]
        public IActionResult ChangePassword(string oldPassword, string newPassword)
        {
            // change password logic
            return RedirectToAction("Index");
        }

        [HttpPost]
        public IActionResult DeleteAccount(int userId)
        {
            return Ok();
        }
    }

    // ---- 13. JWT Issues ----
    public class JwtConfig
    {
        public void ConfigureJwt()
        {
            var tokenParams = new TokenValidationParameters();
            // VULN: Disable issuer validation
            tokenParams.ValidateIssuer = false;
            // VULN: Disable audience validation
            tokenParams.ValidateAudience = false;
            // VULN: Disable lifetime validation
            tokenParams.ValidateLifetime = false;
            // VULN: No expiration required
            tokenParams.RequireExpirationTime = false;
            // VULN: Disable signature validation
            tokenParams.RequireSignedTokens = false;
        }
    }

    // ---- 14. Open Redirect ----
    public class RedirectController : Controller
    {
        [HttpGet]
        public IActionResult Login(string returnUrl)
        {
            var target = Request.QueryString["redirect"];
            // VULN: Open redirect with user input
            return Redirect(target);
        }
    }

    // ---- 15. File Upload ----
    public class UploadController : Controller
    {
        [HttpPost]
        public async Task<IActionResult> Upload(IFormFile file)
        {
            // VULN: No validation on file upload
            var filePath = Path.Combine("/uploads", file.FileName);
            using var stream = new FileStream(filePath, FileMode.Create);
            await file.CopyToAsync(stream);
            return Ok();
        }
    }

    // ---- 16. SSL/TLS ----
    public class HttpService
    {
        public HttpClient CreateClient()
        {
            var handler = new HttpClientHandler();
            // VULN: Disable SSL validation
            handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;

            // VULN: Global SSL validation disable
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;

            return new HttpClient(handler);
        }
    }

    // ---- 17. Timing Attack ----
    public class AuthService
    {
        public bool ValidateToken(string providedToken, string storedToken)
        {
            // VULN: String comparison for token validation
            return providedToken.Equals(storedToken);
        }

        public bool ValidateApiKey(string key, string expectedKey)
        {
            // VULN: String comparison for API key
            return key.Equals(expectedKey);
        }
    }

    // ---- 18. Information Disclosure ----
    public class ErrorController : Controller
    {
        [HttpGet]
        public IActionResult HandleError()
        {
            try
            {
                // some operation
            }
            catch (Exception ex)
            {
                // VULN: Exception details to client
                return Json(ex.ToString());
            }
            return Ok();
        }
    }

    // ---- 19. Cookie Security ----
    public class SessionController : Controller
    {
        [HttpPost]
        public IActionResult SetSession()
        {
            // VULN: Cookie without Secure flag
            var options = new CookieOptions();
            Response.Cookies.Append("session", "abc123", options);

            return Ok();
        }

        [HttpPost]
        public IActionResult SetPreference(string value)
        {
            var cookieOpts = new CookieOptions();
            // VULN: HttpOnly disabled
            cookieOpts.HttpOnly = false;
            // VULN: SameSite None
            cookieOpts.SameSite = SameSiteMode.None;
            // VULN: Secure disabled
            cookieOpts.Secure = false;
            Response.Cookies.Append("pref", value, cookieOpts);
            return Ok();
        }
    }

    // ---- 20. Logging Sensitive Data ----
    public class LoginController : Controller
    {
        private readonly ILogger _logger;

        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            // VULN: Logging password
            _logger.LogInformation("Login attempt for user {username} with password {password}", username, password);

            // VULN: Logging credit card
            _logger.LogDebug("Processing payment with creditcard: {card}", cardNumber);

            return Ok();
        }
    }

    // ---- 21. Race Condition ----
    public class FileService
    {
        public void WriteIfNotExists(string path, string content)
        {
            // VULN: TOCTOU race condition
            if (File.Exists(path))
            {
                throw new Exception("File already exists");
            }
            var stream = new FileStream(path, FileMode.CreateNew);
        }
    }

    // ---- 22. AllowAnonymous on sensitive endpoints ----
    [Authorize]
    [ApiController]
    public class AdminController : Controller
    {
        [AllowAnonymous]
        [HttpDelete]
        public IActionResult DeleteUser(int id)
        {
            return Ok();
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult UpdateSettings(object settings)
        {
            return Ok();
        }
    }

    // ---- 23. Input Validation Disabled ----
    public class LegacyController : Controller
    {
        [ValidateInput(false)]
        [HttpPost]
        public IActionResult SubmitForm(string data)
        {
            return View(data);
        }
    }

    // ---- 24. ECB Mode ----
    public class EncryptionService
    {
        public byte[] Encrypt(byte[] data, byte[] key)
        {
            var aes = Aes.Create();
            // VULN: ECB mode
            aes.Mode = CipherMode.ECB;
            aes.Key = key;
            var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }
}
