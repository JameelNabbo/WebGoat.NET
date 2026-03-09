using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace TestApp.Controllers
{
    // 1. SQL Injection - SqlCommand with string concatenation
    // 13. Missing Authorization on controller
    public class UserController : Controller
    {
        private string connectionString = "Server=db;Database=app;User=sa;Password=P@ssw0rd123!";

        // SQL Injection via SqlCommand constructor
        [HttpGet]
        public IActionResult GetUser([FromQuery] string username)
        {
            var conn = new SqlConnection(connectionString);
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Username = '" + username + "'", conn);
            conn.Open();
            var reader = cmd.ExecuteReader();
            return Ok(reader);
        }

        // SQL Injection via CommandText
        [HttpGet]
        public IActionResult SearchUser([FromQuery] string search)
        {
            var conn = new SqlConnection(connectionString);
            var cmd = new SqlCommand();
            cmd.Connection = conn;
            cmd.CommandText = "SELECT * FROM Users WHERE Name LIKE '%" + search + "%'";
            conn.Open();
            return Ok(cmd.ExecuteReader());
        }

        // SQL Injection via string interpolation
        [HttpGet]
        public IActionResult FindUser([FromQuery] string id)
        {
            var conn = new SqlConnection(connectionString);
            var cmd = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", conn);
            conn.Open();
            return Ok(cmd.ExecuteReader());
        }
    }

    // 2. Command Injection
    public class AdminController : Controller
    {
        // Command Injection via Process.Start
        [HttpPost]
        public IActionResult RunDiagnostics([FromBody] string hostname)
        {
            var result = Process.Start("ping", "-c 4 " + hostname);
            return Ok(result);
        }

        // Shell Command Injection
        [HttpPost]
        public IActionResult ExecuteCommand([FromBody] string command)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = "-c " + command,
                UseShellExecute = true,
                RedirectStandardOutput = false
            };
            var process = Process.Start(psi);
            return Ok("executed");
        }

        // Command Injection via ProcessStartInfo constructor
        [HttpPost]
        public IActionResult RunScript([FromQuery] string script)
        {
            var psi = new ProcessStartInfo(script + ".sh");
            Process.Start(psi);
            return Ok();
        }
    }

    // 3. Code Injection
    public class ScriptController : Controller
    {
        [HttpPost]
        public async Task<IActionResult> Evaluate([FromBody] string code)
        {
            // Code injection via Activator.CreateInstance
            var type = Type.GetType(code);
            var instance = Activator.CreateInstance(type);
            return Ok(instance);
        }
    }

    // 4. XSS
    public class PageController : Controller
    {
        // XSS via Response.Write
        [HttpGet]
        public void ShowMessage([FromQuery] string message)
        {
            Response.WriteAsync("<h1>" + message + "</h1>");
        }

        // XSS via Html.Raw
        [HttpGet]
        public IActionResult RenderContent([FromQuery] string content)
        {
            ViewBag.Content = content;
            // In a view: @Html.Raw(ViewBag.Content)
            return View();
        }
    }

    // 5. Path Traversal
    public class FileController : Controller
    {
        // Path Traversal via File.ReadAllText
        [HttpGet]
        public IActionResult DownloadFile([FromQuery] string filename)
        {
            var content = File.ReadAllText("/uploads/" + filename);
            return Content(content);
        }

        // Path Traversal via Path.Combine
        [HttpGet]
        public IActionResult GetDocument([FromQuery] string path)
        {
            var fullPath = Path.Combine("/var/documents", path);
            var stream = new FileStream(fullPath, FileMode.Open);
            return File(stream, "application/octet-stream");
        }

        // Path Traversal via StreamReader
        [HttpGet]
        public IActionResult ReadLog([FromQuery] string logFile)
        {
            var reader = new StreamReader("/var/logs/" + logFile);
            return Content(reader.ReadToEnd());
        }
    }

    // 6. Deserialization
    public class DataController : Controller
    {
        // BinaryFormatter deserialization
        [HttpPost]
        public IActionResult ImportData()
        {
            var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            var obj = formatter.Deserialize(Request.Body);
            return Ok(obj);
        }

        // JavaScriptSerializer with SimpleTypeResolver
        [HttpPost]
        public IActionResult ParseJson([FromBody] string json)
        {
            var serializer = new System.Web.Script.Serialization.JavaScriptSerializer(
                new System.Web.Script.Serialization.SimpleTypeResolver());
            var result = serializer.Deserialize<object>(json);
            return Ok(result);
        }

        // NetDataContractSerializer
        [HttpPost]
        public IActionResult ParseXml()
        {
            var serializer = new System.Runtime.Serialization.NetDataContractSerializer();
            return Ok();
        }
    }

    // 7. XXE
    public class XmlController : Controller
    {
        // XXE via XmlDocument without XmlResolver = null
        [HttpPost]
        public IActionResult ParseXml([FromBody] string xmlContent)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xmlContent);
            return Ok(doc.InnerText);
        }

        // XXE via XmlTextReader
        [HttpPost]
        public IActionResult ProcessXml([FromBody] string xml)
        {
            var reader = new XmlTextReader(new StringReader(xml));
            while (reader.Read()) { }
            return Ok();
        }

        // DtdProcessing.Parse
        [HttpPost]
        public IActionResult TransformXml([FromBody] string xml)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
            settings.ProhibitDtd = false;
            var reader = XmlReader.Create(new StringReader(xml), settings);
            return Ok();
        }
    }

    // 8. SSRF
    public class ProxyController : Controller
    {
        private readonly HttpClient _httpClient = new HttpClient();

        // SSRF via HttpClient
        [HttpGet]
        public async Task<IActionResult> Fetch([FromQuery] string url)
        {
            var response = await _httpClient.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();
            return Content(content);
        }

        // SSRF via HttpClient with concatenation
        [HttpGet]
        public async Task<IActionResult> GetImage([FromQuery] string imageUrl)
        {
            var response = await _httpClient.GetStringAsync("http://internal-service/" + imageUrl);
            return Content(response);
        }

        // SSRF via WebRequest
        [HttpGet]
        public IActionResult FetchUrl([FromQuery] string target)
        {
            var request = System.Net.WebRequest.Create(target);
            return Ok(request.GetResponse());
        }
    }

    // 9. LDAP Injection
    public class AuthController : Controller
    {
        [HttpPost]
        public IActionResult LdapLogin([FromBody] string username, [FromBody] string password)
        {
            var searcher = new System.DirectoryServices.DirectorySearcher(
                "(&(uid=" + username + ")(userPassword=" + password + "))");
            var entry = new System.DirectoryServices.DirectoryEntry(
                "LDAP://dc=company,dc=com/ou=" + username);
            searcher.Filter = "(uid=" + username + ")";
            return Ok(searcher.FindAll());
        }
    }
}
