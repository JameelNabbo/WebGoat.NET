using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://0.0.0.0:9003");
builder.Services.AddSingleton<SastScanner>();

var app = builder.Build();

app.MapGet("/health", () => Results.Ok(new
{
    status = "healthy",
    scanner = "csharp",
    version = "1.0.0",
    engine = "Roslyn AST",
    timestamp = DateTime.UtcNow
}));

app.MapPost("/scan", async (HttpContext ctx, SastScanner scanner) =>
{
    try
    {
        var body = await JsonSerializer.DeserializeAsync<ScanRequest>(ctx.Request.Body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        if (body?.Files == null || body.Files.Count == 0)
            return Results.BadRequest(new { error = "No files provided" });

        var scanId = body.ScanId ?? Guid.NewGuid().ToString();
        var results = scanner.ScanFiles(body.Files, scanId);

        return Results.Ok(new ScanResponse
        {
            ScanId = scanId,
            TotalFiles = body.Files.Count,
            TotalVulnerabilities = results.Count,
            Vulnerabilities = results
        });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Scan error: {ex.Message}");
    }
});

app.Run();

// ---------- Models ----------

public class ScanRequest
{
    public Dictionary<string, string> Files { get; set; } = new();
    public string? ScanId { get; set; }
}

public class ScanResponse
{
    [JsonPropertyName("scanId")]
    public string ScanId { get; set; } = "";
    [JsonPropertyName("totalFiles")]
    public int TotalFiles { get; set; }
    [JsonPropertyName("totalVulnerabilities")]
    public int TotalVulnerabilities { get; set; }
    [JsonPropertyName("vulnerabilities")]
    public List<Vulnerability> Vulnerabilities { get; set; } = new();
}

public class Vulnerability
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";
    [JsonPropertyName("title")]
    public string Title { get; set; } = "";
    [JsonPropertyName("description")]
    public string Description { get; set; } = "";
    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "Medium";
    [JsonPropertyName("confidence")]
    public string Confidence { get; set; } = "Medium";
    [JsonPropertyName("category")]
    public string Category { get; set; } = "";
    [JsonPropertyName("cwe")]
    public string Cwe { get; set; } = "";
    [JsonPropertyName("owasp")]
    public string Owasp { get; set; } = "";
    [JsonPropertyName("file")]
    public string File { get; set; } = "";
    [JsonPropertyName("line")]
    public int Line { get; set; }
    [JsonPropertyName("column")]
    public int Column { get; set; }
    [JsonPropertyName("snippet")]
    public string Snippet { get; set; } = "";
    [JsonPropertyName("recommendation")]
    public string Recommendation { get; set; } = "";
}

// ---------- Scanner Engine ----------

public class SastScanner
{
    private int _vulnCounter;

    public List<Vulnerability> ScanFiles(Dictionary<string, string> files, string scanId)
    {
        _vulnCounter = 0;
        var allVulns = new ConcurrentBag<Vulnerability>();

        Parallel.ForEach(files, kvp =>
        {
            try
            {
                var tree = CSharpSyntaxTree.ParseText(kvp.Value, path: kvp.Key);
                var root = tree.GetCompilationUnitRoot();
                var walker = new VulnerabilityWalker(kvp.Key, kvp.Value);
                walker.Visit(root);
                foreach (var v in walker.Vulnerabilities)
                {
                    v.Id = $"{scanId}-{Interlocked.Increment(ref _vulnCounter)}";
                    allVulns.Add(v);
                }
            }
            catch { /* skip unparseable files */ }
        });

        return allVulns.OrderBy(v => v.File).ThenBy(v => v.Line).ToList();
    }
}

// ---------- AST Walker ----------

public class VulnerabilityWalker : CSharpSyntaxWalker
{
    private readonly string _filePath;
    private readonly string _source;
    private readonly string[] _lines;
    public List<Vulnerability> Vulnerabilities { get; } = new();

    // Basic taint tracking: variable name -> whether it holds user input
    private readonly Dictionary<string, bool> _taintedVars = new(StringComparer.OrdinalIgnoreCase);

    // User input sources
    private static readonly HashSet<string> UserInputSources = new(StringComparer.OrdinalIgnoreCase)
    {
        "Request.QueryString", "Request.Form", "Request.Headers", "Request.Cookies",
        "Request.Path", "Request.Body", "Request.Query", "Request.RouteValues",
        "HttpContext.Request", "context.Request",
        "Console.ReadLine", "ReadLine",
        "Environment.GetEnvironmentVariable",
        "args", "argv"
    };

    // Methods that return user input in ASP.NET Core
    private static readonly HashSet<string> UserInputMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "FromBody", "FromQuery", "FromRoute", "FromHeader", "FromForm",
        "GetQueryNameValuePairs", "ReadAsStringAsync", "ReadAsStreamAsync",
        "ReadFromJsonAsync", "GetString", "GetValue"
    };

    public VulnerabilityWalker(string filePath, string source) : base(SyntaxWalkerDepth.Node)
    {
        _filePath = filePath;
        _source = source;
        _lines = source.Split('\n');
    }

    // ============================================================
    //  VARIABLE ASSIGNMENT TRACKING (basic taint analysis)
    // ============================================================

    public override void VisitVariableDeclaration(VariableDeclarationSyntax node)
    {
        foreach (var declarator in node.Variables)
        {
            if (declarator.Initializer?.Value != null)
            {
                var varName = declarator.Identifier.Text;
                if (IsUserInput(declarator.Initializer.Value))
                    _taintedVars[varName] = true;
            }
        }
        base.VisitVariableDeclaration(node);
    }

    public override void VisitAssignmentExpression(AssignmentExpressionSyntax node)
    {
        if (node.Left is IdentifierNameSyntax id && IsUserInput(node.Right))
            _taintedVars[id.Identifier.Text] = true;

        // Check assignment-based vulnerabilities
        CheckAssignmentVulnerabilities(node);
        base.VisitAssignmentExpression(node);
    }

    // ============================================================
    //  METHOD PARAMETER TRACKING
    // ============================================================

    public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
    {
        // Mark parameters with [FromBody], [FromQuery], etc. as tainted
        foreach (var param in node.ParameterList.Parameters)
        {
            bool hasTaintAttr = param.AttributeLists
                .SelectMany(al => al.Attributes)
                .Any(a =>
                {
                    var name = a.Name.ToString();
                    return name.StartsWith("From") || name == "HttpPost" || name == "HttpGet";
                });

            // In controller methods, all parameters are potentially user input
            if (hasTaintAttr || IsInsideController(node))
                _taintedVars[param.Identifier.Text] = true;
        }

        // Check for missing authorization attributes
        CheckMissingAuthorization(node);
        base.VisitMethodDeclaration(node);
    }

    public override void VisitClassDeclaration(ClassDeclarationSyntax node)
    {
        // Check CORS on controllers
        CheckCorsOnController(node);
        // Check for missing anti-forgery
        CheckMissingAntiForgery(node);
        base.VisitClassDeclaration(node);
    }

    // ============================================================
    //  INVOCATION EXPRESSION (method calls)
    // ============================================================

    public override void VisitInvocationExpression(InvocationExpressionSyntax node)
    {
        var methodName = GetMethodName(node);
        var fullText = node.ToString();

        CheckSqlInjection(node, methodName, fullText);
        CheckCommandInjection(node, methodName, fullText);
        CheckXss(node, methodName, fullText);
        CheckPathTraversal(node, methodName, fullText);
        CheckXxe(node, methodName, fullText);
        CheckSsrf(node, methodName, fullText);
        CheckLdapInjection(node, methodName, fullText);
        CheckWeakCrypto(node, methodName, fullText);
        CheckInsecureRandom(node, methodName, fullText);
        CheckEntityFramework(node, methodName, fullText);
        CheckOpenRedirect(node, methodName, fullText);
        CheckFileUpload(node, methodName, fullText);
        CheckSslValidation(node, methodName, fullText);
        CheckLoggingSensitiveData(node, methodName, fullText);
        CheckTimingAttack(node, methodName, fullText);
        CheckInformationDisclosure(node, methodName, fullText);

        base.VisitInvocationExpression(node);
    }

    // ============================================================
    //  OBJECT CREATION (new X())
    // ============================================================

    public override void VisitObjectCreationExpression(ObjectCreationExpressionSyntax node)
    {
        var typeName = node.Type.ToString();

        CheckDeserializationCreation(node, typeName);
        CheckXxeCreation(node, typeName);
        CheckWeakCryptoCreation(node, typeName);
        CheckInsecureRandomCreation(node, typeName);
        CheckCookieSecurity(node, typeName);
        CheckRaceCondition(node, typeName);
        CheckSqlCommandCreation(node, typeName);

        base.VisitObjectCreationExpression(node);
    }

    // ============================================================
    //  LITERAL EXPRESSIONS (hardcoded secrets)
    // ============================================================

    public override void VisitLiteralExpression(LiteralExpressionSyntax node)
    {
        if (node.IsKind(SyntaxKind.StringLiteralExpression))
            CheckHardcodedSecrets(node);

        base.VisitLiteralExpression(node);
    }

    // ============================================================
    //  ATTRIBUTE CHECKS
    // ============================================================

    public override void VisitAttribute(AttributeSyntax node)
    {
        var attrName = node.Name.ToString();
        CheckJwtAttributes(node, attrName);
        CheckObsoleteSecurityAttributes(node, attrName);
        base.VisitAttribute(node);
    }

    // ============================================================
    //  VULNERABILITY DETECTION METHODS
    // ============================================================

    // --- SQL Injection ---

    private void CheckSqlInjection(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        // SqlCommand.CommandText = "..." + var
        // new SqlCommand("..." + var)
        // ExecuteReader/ExecuteNonQuery/ExecuteScalar with concatenated SQL
        var sqlMethods = new[] { "ExecuteReader", "ExecuteNonQuery", "ExecuteScalar",
            "ExecuteReaderAsync", "ExecuteNonQueryAsync", "ExecuteScalarAsync",
            "Execute", "Query", "QueryFirst", "QueryFirstOrDefault",
            "QuerySingle", "QuerySingleOrDefault", "QueryMultiple" };

        if (sqlMethods.Any(m => methodName.EndsWith(m, StringComparison.OrdinalIgnoreCase)))
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null && args.Value.Count > 0)
            {
                var firstArg = args.Value[0].Expression;
                if (ContainsStringConcatenation(firstArg) || ContainsInterpolation(firstArg) || IsTainted(firstArg))
                {
                    AddVuln(node, "SQL Injection", "High",
                        "SQL query constructed with string concatenation or interpolation using potentially untrusted input.",
                        "CWE-89", "A03:2021",
                        "Use parameterized queries or stored procedures. For Dapper, use @param placeholders with anonymous objects.");
                }
            }
        }

        // FromSqlRaw / FromSql with interpolation
        if (methodName.EndsWith("FromSqlRaw") || methodName.EndsWith("SqlQuery"))
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null && args.Value.Count > 0)
            {
                var firstArg = args.Value[0].Expression;
                if (ContainsStringConcatenation(firstArg) || ContainsInterpolation(firstArg) || IsTainted(firstArg))
                {
                    AddVuln(node, "SQL Injection via Entity Framework", "High",
                        "FromSqlRaw/SqlQuery called with concatenated or interpolated string. Use FromSqlInterpolated instead.",
                        "CWE-89", "A03:2021",
                        "Use FromSqlInterpolated() which safely parameterizes interpolated values, or pass parameters explicitly to FromSqlRaw.");
                }
            }
        }
    }

    private void CheckSqlCommandCreation(ObjectCreationExpressionSyntax node, string typeName)
    {
        if (typeName is "SqlCommand" or "OleDbCommand" or "OdbcCommand" or "NpgsqlCommand" or "MySqlCommand")
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null && args.Value.Count > 0)
            {
                var firstArg = args.Value[0].Expression;
                if (ContainsStringConcatenation(firstArg) || ContainsInterpolation(firstArg) || IsTainted(firstArg))
                {
                    AddVuln(node, "SQL Injection", "High",
                        $"{typeName} created with concatenated SQL query string containing potentially untrusted input.",
                        "CWE-89", "A03:2021",
                        "Use parameterized queries with SqlParameter objects. Never concatenate user input into SQL strings.");
                }
            }
        }

        if (typeName is "SqlDataAdapter" or "OleDbDataAdapter")
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null && args.Value.Count > 0)
            {
                var firstArg = args.Value[0].Expression;
                if (ContainsStringConcatenation(firstArg) || ContainsInterpolation(firstArg) || IsTainted(firstArg))
                {
                    AddVuln(node, "SQL Injection via DataAdapter", "High",
                        $"{typeName} created with concatenated SQL query string.",
                        "CWE-89", "A03:2021",
                        "Use parameterized queries. Pass a SqlCommand with parameters instead of a raw SQL string.");
                }
            }
        }
    }

    // --- Command Injection ---

    private void CheckCommandInjection(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        if (methodName.EndsWith("Process.Start") || methodName.EndsWith("Start"))
        {
            // Check if it looks like Process.Start
            var expr = node.Expression.ToString();
            if (expr.Contains("Process") && expr.Contains("Start"))
            {
                var args = node.ArgumentList?.Arguments;
                if (args != null)
                {
                    foreach (var arg in args)
                    {
                        if (ContainsStringConcatenation(arg.Expression) || ContainsInterpolation(arg.Expression) || IsTainted(arg.Expression))
                        {
                            AddVuln(node, "Command Injection", "Critical",
                                "Process.Start called with user-controlled input. An attacker could execute arbitrary OS commands.",
                                "CWE-78", "A03:2021",
                                "Avoid passing user input to Process.Start. If necessary, use a strict allowlist of permitted commands and validate all arguments.");
                            break;
                        }
                    }
                }
            }
        }

        // ProcessStartInfo with shell execute
        if (fullText.Contains("ProcessStartInfo") && (fullText.Contains("UseShellExecute = true") || fullText.Contains("UseShellExecute=true")))
        {
            if (ContainsStringConcatenation(node) || IsTaintedSubtree(node))
            {
                AddVuln(node, "Command Injection via Shell Execute", "Critical",
                    "ProcessStartInfo with UseShellExecute=true and potentially tainted arguments.",
                    "CWE-78", "A03:2021",
                    "Set UseShellExecute to false and avoid passing user input to process arguments. Validate and sanitize all inputs.");
            }
        }

        // cmd.exe / bash / powershell invocations
        if (fullText.Contains("cmd.exe") || fullText.Contains("/bin/sh") || fullText.Contains("/bin/bash") || fullText.Contains("powershell"))
        {
            if (fullText.Contains("/c ") || fullText.Contains("-c ") || fullText.Contains("-Command"))
            {
                if (ContainsStringConcatenation(node) || ContainsInterpolation(node) || IsTaintedSubtree(node))
                {
                    AddVuln(node, "Command Injection via Shell", "Critical",
                        "Shell command execution (cmd.exe/bash/powershell) with potentially tainted arguments.",
                        "CWE-78", "A03:2021",
                        "Avoid shell command execution with user input. Use direct process execution without shell interpretation.");
                }
            }
        }
    }

    // --- XSS ---

    private void CheckXss(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        // Response.Write
        if (methodName.EndsWith("Response.Write") || methodName.EndsWith("Write") && fullText.Contains("Response"))
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null && args.Value.Count > 0)
            {
                var firstArg = args.Value[0].Expression;
                if (IsTainted(firstArg) || ContainsStringConcatenation(firstArg))
                {
                    AddVuln(node, "Cross-Site Scripting (XSS)", "High",
                        "Response.Write called with potentially untrusted input. Output is not HTML-encoded.",
                        "CWE-79", "A03:2021",
                        "Use HttpUtility.HtmlEncode() or Razor's @ syntax which auto-encodes. Never write raw user input to response.");
                }
            }
        }

        // Html.Raw
        if (methodName.EndsWith("Html.Raw") || methodName.EndsWith("Raw"))
        {
            if (fullText.Contains("Html.Raw") || fullText.Contains("@Html.Raw"))
            {
                var args = node.ArgumentList?.Arguments;
                if (args != null && args.Value.Count > 0)
                {
                    var firstArg = args.Value[0].Expression;
                    if (IsTainted(firstArg) || !IsStaticString(firstArg))
                    {
                        AddVuln(node, "Cross-Site Scripting (XSS) via Html.Raw", "High",
                            "Html.Raw() renders content without HTML encoding. If input is user-controlled, XSS is possible.",
                            "CWE-79", "A03:2021",
                            "Avoid Html.Raw() with user input. Use standard Razor @ output which auto-encodes, or sanitize with a library like HtmlSanitizer.");
                    }
                }
            }
        }

        // HtmlString constructor
        if (fullText.Contains("new HtmlString") || fullText.Contains("new MarkupString"))
        {
            AddVuln(node, "Cross-Site Scripting (XSS) via HtmlString", "Medium",
                "HtmlString/MarkupString bypasses HTML encoding. Ensure content is sanitized.",
                "CWE-79", "A03:2021",
                "Sanitize content before wrapping in HtmlString. Use an HTML sanitizer library.");
        }
    }

    // --- Path Traversal ---

    private void CheckPathTraversal(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        var fileOps = new[] {
            "File.ReadAllText", "File.ReadAllBytes", "File.ReadAllLines",
            "File.WriteAllText", "File.WriteAllBytes", "File.WriteAllLines",
            "File.Open", "File.OpenRead", "File.OpenWrite", "File.Create",
            "File.Delete", "File.Copy", "File.Move", "File.Exists",
            "File.AppendAllText", "File.AppendAllLines",
            "FileStream", "StreamReader", "StreamWriter",
            "Directory.GetFiles", "Directory.GetDirectories", "Directory.Delete",
            "Path.Combine"
        };

        foreach (var op in fileOps)
        {
            if (methodName.EndsWith(op.Split('.').Last()) && fullText.Contains(op.Split('.').First()))
            {
                var args = node.ArgumentList?.Arguments;
                if (args != null && args.Value.Count > 0)
                {
                    var firstArg = args.Value[0].Expression;
                    if (IsTainted(firstArg) || ContainsStringConcatenation(firstArg) || ContainsInterpolation(firstArg))
                    {
                        AddVuln(node, "Path Traversal", "High",
                            $"{op} called with potentially user-controlled path. Attacker could access files outside intended directory using ../ sequences.",
                            "CWE-22", "A01:2021",
                            "Validate and sanitize file paths. Use Path.GetFullPath() and verify the resolved path starts with the expected base directory. Reject paths containing '..'.");
                        break;
                    }
                }
            }
        }
    }

    // --- Deserialization ---

    private void CheckDeserializationCreation(ObjectCreationExpressionSyntax node, string typeName)
    {
        // BinaryFormatter
        if (typeName is "BinaryFormatter" or "SoapFormatter" or "NetDataContractSerializer"
            or "ObjectStateFormatter" or "LosFormatter")
        {
            AddVuln(node, "Insecure Deserialization", "Critical",
                $"{typeName} is inherently unsafe and can lead to remote code execution when deserializing untrusted data.",
                "CWE-502", "A08:2021",
                $"Do not use {typeName}. Use System.Text.Json or JsonSerializer with known types. BinaryFormatter is obsolete and marked dangerous by Microsoft.");
        }

        // JavaScriptSerializer
        if (typeName is "JavaScriptSerializer")
        {
            // Check for SimpleTypeResolver
            var initializerText = node.ToString();
            if (initializerText.Contains("SimpleTypeResolver"))
            {
                AddVuln(node, "Insecure Deserialization via JavaScriptSerializer", "Critical",
                    "JavaScriptSerializer with SimpleTypeResolver allows arbitrary type instantiation during deserialization.",
                    "CWE-502", "A08:2021",
                    "Remove SimpleTypeResolver. Use System.Text.Json with JsonSerializerOptions that restrict type handling.");
            }
        }
    }

    // --- XXE ---

    private void CheckXxe(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        // XmlDocument.LoadXml / Load
        if ((methodName.EndsWith("LoadXml") || methodName.EndsWith("Load")) &&
            (fullText.Contains("XmlDocument") || fullText.Contains("xmlDoc") || fullText.Contains("xmlDocument")))
        {
            // Look for DtdProcessing settings in surrounding context
            if (!HasDtdProtection(node))
            {
                var args = node.ArgumentList?.Arguments;
                if (args != null && args.Value.Count > 0 && (IsTainted(args.Value[0].Expression) || !IsStaticString(args.Value[0].Expression)))
                {
                    AddVuln(node, "XML External Entity (XXE) Injection", "High",
                        "XmlDocument loading XML without DTD processing restrictions. External entities could be used to read local files or perform SSRF.",
                        "CWE-611", "A05:2021",
                        "Set XmlResolver to null and use XmlReaderSettings with DtdProcessing = DtdProcessing.Prohibit before loading XML.");
                }
            }
        }

        // XmlReader.Create without settings
        if (methodName.EndsWith("XmlReader.Create") || (methodName.EndsWith("Create") && fullText.Contains("XmlReader")))
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null)
            {
                bool hasSettings = args.Value.Any(a => a.Expression.ToString().Contains("Settings") ||
                                                        a.Expression.ToString().Contains("XmlReaderSettings"));
                if (!hasSettings)
                {
                    AddVuln(node, "XML External Entity (XXE) - Missing Settings", "Medium",
                        "XmlReader.Create called without explicit XmlReaderSettings. Default settings may allow DTD processing.",
                        "CWE-611", "A05:2021",
                        "Pass XmlReaderSettings with DtdProcessing = DtdProcessing.Prohibit to XmlReader.Create().");
                }
            }
        }
    }

    private void CheckXxeCreation(ObjectCreationExpressionSyntax node, string typeName)
    {
        if (typeName is "XmlDocument" or "XmlTextReader")
        {
            // Check if XmlResolver is set to null in the initializer
            var initializer = node.Initializer;
            bool hasSafeResolver = false;
            if (initializer != null)
            {
                hasSafeResolver = initializer.Expressions.Any(e =>
                    e.ToString().Contains("XmlResolver = null") || e.ToString().Contains("DtdProcessing.Prohibit"));
            }

            if (!hasSafeResolver)
            {
                AddVuln(node, "XML External Entity (XXE) Risk", "Medium",
                    $"{typeName} created without disabling DTD processing or setting XmlResolver to null.",
                    "CWE-611", "A05:2021",
                    $"For {typeName}, set XmlResolver = null and/or DtdProcessing = DtdProcessing.Prohibit immediately after creation.");
            }
        }
    }

    // --- SSRF ---

    private void CheckSsrf(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        var httpMethods = new[] { "GetAsync", "PostAsync", "PutAsync", "DeleteAsync", "SendAsync",
            "GetStringAsync", "GetStreamAsync", "GetByteArrayAsync",
            "DownloadString", "DownloadData", "DownloadFile",
            "OpenRead", "UploadString", "UploadData" };

        if (httpMethods.Any(m => methodName.EndsWith(m)))
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null && args.Value.Count > 0)
            {
                var firstArg = args.Value[0].Expression;
                if (IsTainted(firstArg) || ContainsStringConcatenation(firstArg) || ContainsInterpolation(firstArg))
                {
                    AddVuln(node, "Server-Side Request Forgery (SSRF)", "High",
                        "HTTP request made with user-controlled URL. Attacker could access internal services, cloud metadata endpoints, or scan internal networks.",
                        "CWE-918", "A10:2021",
                        "Validate URLs against an allowlist of permitted hosts/schemes. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.169.254). Use URL parsing to verify the host.");
                }
            }
        }
    }

    // --- LDAP Injection ---

    private void CheckLdapInjection(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        if (methodName.EndsWith("FindAll") || methodName.EndsWith("FindOne"))
        {
            if (fullText.Contains("DirectorySearcher") || fullText.Contains("searcher") || fullText.Contains("Searcher"))
            {
                // Check if filter is constructed with concatenation
                var parent = node.Parent;
                var blockText = GetEnclosingBlockText(node);
                if (blockText.Contains("Filter") && (blockText.Contains("+") || blockText.Contains("$\"")))
                {
                    AddVuln(node, "LDAP Injection", "High",
                        "LDAP search filter constructed with string concatenation. Attacker could modify the query to bypass authentication or access unauthorized data.",
                        "CWE-90", "A03:2021",
                        "Use parameterized LDAP queries or sanitize input by escaping LDAP special characters: *, (, ), \\, NUL. Use a library like Novell.Directory.Ldap with proper escaping.");
                }
            }
        }

        // DirectorySearcher with concatenated filter
        if (fullText.Contains("DirectorySearcher") && fullText.Contains("Filter"))
        {
            if (ContainsStringConcatenation(node) || ContainsInterpolation(node))
            {
                AddVuln(node, "LDAP Injection", "High",
                    "DirectorySearcher filter constructed with string concatenation using potentially untrusted input.",
                    "CWE-90", "A03:2021",
                    "Escape LDAP special characters in user input before constructing filters. Use proper LDAP encoding functions.");
            }
        }
    }

    // --- Hardcoded Secrets ---

    private void CheckHardcodedSecrets(LiteralExpressionSyntax node)
    {
        var value = node.Token.ValueText;
        if (string.IsNullOrWhiteSpace(value) || value.Length < 8) return;

        // Get the assignment context
        var parent = node.Parent;
        string? contextName = null;

        // Check variable name or property name context
        if (parent is EqualsValueClauseSyntax equalsClause)
        {
            var declarator = equalsClause.Parent as VariableDeclaratorSyntax;
            contextName = declarator?.Identifier.Text;
        }
        else if (parent is AssignmentExpressionSyntax assignment)
        {
            contextName = assignment.Left.ToString();
        }
        else if (parent is ArgumentSyntax arg)
        {
            contextName = arg.NameColon?.Name.ToString();
        }

        if (contextName == null) return;

        var lcContext = contextName.ToLowerInvariant();
        var secretPatterns = new[] { "password", "passwd", "pwd", "secret", "apikey", "api_key",
            "connectionstring", "connstring", "token", "accesskey", "secretkey", "private_key",
            "privatekey", "credentials", "auth_token" };

        if (secretPatterns.Any(p => lcContext.Contains(p)))
        {
            // Skip obvious test/example values
            var lcValue = value.ToLowerInvariant();
            if (lcValue == "password" || lcValue == "test" || lcValue == "example" || lcValue == "placeholder"
                || lcValue == "changeme" || lcValue == "todo" || value == "***" || value.All(c => c == '*'))
                return;

            AddVuln(node, "Hardcoded Secret", "High",
                $"Hardcoded credential found in variable/property '{contextName}'. Secrets in source code can be extracted by anyone with access to the repository.",
                "CWE-798", "A07:2021",
                "Store secrets in environment variables, Azure Key Vault, AWS Secrets Manager, or a secure configuration provider. Never commit secrets to source control.");
        }

        // Connection strings with embedded passwords
        if (value.Contains("Password=", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("Pwd=", StringComparison.OrdinalIgnoreCase))
        {
            if (value.Contains("Server=", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("Data Source=", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("Host=", StringComparison.OrdinalIgnoreCase))
            {
                AddVuln(node, "Hardcoded Connection String", "High",
                    "Connection string with embedded credentials found in source code.",
                    "CWE-798", "A07:2021",
                    "Use connection string builders, environment variables, or secure configuration. Consider using Integrated Security/Windows Authentication where possible.");
            }
        }

        // JWT-like tokens
        if (Regex.IsMatch(value, @"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"))
        {
            AddVuln(node, "Hardcoded JWT Token", "High",
                "A JWT token is hardcoded in source code.",
                "CWE-798", "A07:2021",
                "Never hardcode tokens. Use proper token management with secure storage and rotation.");
        }
    }

    // --- Weak Cryptography ---

    private void CheckWeakCrypto(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        // MD5.Create(), SHA1.Create()
        if (methodName.EndsWith("Create"))
        {
            var expr = node.Expression.ToString();
            if (expr.Contains("MD5"))
            {
                AddVuln(node, "Weak Cryptographic Hash (MD5)", "Medium",
                    "MD5 is cryptographically broken. It is vulnerable to collision attacks and should not be used for security purposes.",
                    "CWE-328", "A02:2021",
                    "Use SHA-256 or SHA-512 for integrity checks. For password hashing, use bcrypt, scrypt, or Argon2 via a library like BCrypt.Net.");
            }
            else if (expr.Contains("SHA1"))
            {
                AddVuln(node, "Weak Cryptographic Hash (SHA1)", "Medium",
                    "SHA-1 is deprecated for security use due to practical collision attacks (SHAttered).",
                    "CWE-328", "A02:2021",
                    "Use SHA-256 or SHA-512. For password hashing, use bcrypt, scrypt, or Argon2.");
            }
        }

        // Detect ECB mode
        if (fullText.Contains("CipherMode.ECB"))
        {
            AddVuln(node, "Weak Cipher Mode (ECB)", "High",
                "ECB mode does not provide semantic security - identical plaintext blocks produce identical ciphertext blocks, revealing patterns.",
                "CWE-327", "A02:2021",
                "Use CBC or GCM mode with a random IV. Prefer AES-GCM (AesGcm class) for authenticated encryption.");
        }
    }

    private void CheckWeakCryptoCreation(ObjectCreationExpressionSyntax node, string typeName)
    {
        if (typeName is "DESCryptoServiceProvider" or "DES" or "TripleDESCryptoServiceProvider"
            or "TripleDES" or "RC2CryptoServiceProvider" or "RC2")
        {
            AddVuln(node, $"Weak Encryption Algorithm ({typeName})", "High",
                $"{typeName} uses a weak/deprecated encryption algorithm with insufficient key length.",
                "CWE-327", "A02:2021",
                "Use AES (Aes.Create()) with a 256-bit key. For authenticated encryption, use AES-GCM (AesGcm class).");
        }

        if (typeName is "RijndaelManaged")
        {
            AddVuln(node, "Deprecated Encryption Class", "Low",
                "RijndaelManaged is deprecated. While AES is a subset of Rijndael, use the Aes class directly.",
                "CWE-327", "A02:2021",
                "Replace RijndaelManaged with Aes.Create() for clarity and to ensure AES-compliant block sizes.");
        }
    }

    // --- Insecure Random ---

    private void CheckInsecureRandom(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        // Check for Random.Next() used in security context
        if (methodName.EndsWith("Next") || methodName.EndsWith("NextBytes") || methodName.EndsWith("NextDouble"))
        {
            var expr = node.Expression.ToString();
            // Check if it is on a Random instance (not RandomNumberGenerator)
            if (!expr.Contains("Crypto") && !expr.Contains("RNG") && !expr.Contains("RandomNumberGenerator"))
            {
                var blockText = GetEnclosingBlockText(node);
                var securityContextKeywords = new[] { "token", "password", "secret", "key", "salt", "nonce", "otp", "code", "session", "csrf", "verify" };
                if (securityContextKeywords.Any(k => blockText.Contains(k, StringComparison.OrdinalIgnoreCase)))
                {
                    AddVuln(node, "Insecure Random Number Generator", "High",
                        "System.Random is not cryptographically secure. Using it for security-sensitive values (tokens, keys, etc.) makes them predictable.",
                        "CWE-330", "A02:2021",
                        "Use RandomNumberGenerator.GetBytes() or RandomNumberGenerator.GetInt32() for security-sensitive random values.");
                }
            }
        }
    }

    private void CheckInsecureRandomCreation(ObjectCreationExpressionSyntax node, string typeName)
    {
        if (typeName is "Random")
        {
            var blockText = GetEnclosingBlockText(node);
            var securityContextKeywords = new[] { "token", "password", "secret", "key", "salt", "nonce", "otp", "code", "session", "csrf" };
            if (securityContextKeywords.Any(k => blockText.Contains(k, StringComparison.OrdinalIgnoreCase)))
            {
                AddVuln(node, "Insecure Random for Security Context", "High",
                    "System.Random used in a security-sensitive context. It is predictable and not suitable for generating security tokens or keys.",
                    "CWE-330", "A02:2021",
                    "Use System.Security.Cryptography.RandomNumberGenerator instead of System.Random for any security-sensitive values.");
            }
        }
    }

    // --- Entity Framework ---

    private void CheckEntityFramework(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        // FromSqlRaw with $"..." interpolation
        if (methodName.EndsWith("FromSqlRaw"))
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null && args.Value.Count > 0)
            {
                var firstArg = args.Value[0].Expression;
                if (firstArg is InterpolatedStringExpressionSyntax)
                {
                    AddVuln(node, "SQL Injection via EF Core FromSqlRaw", "Critical",
                        "FromSqlRaw with string interpolation does NOT parameterize values. Unlike FromSqlInterpolated, interpolated values are concatenated directly into the SQL string.",
                        "CWE-89", "A03:2021",
                        "Use FromSqlInterpolated() instead, which properly parameterizes interpolated values. Alternatively, use FromSqlRaw with explicit SqlParameter objects.");
                }
            }
        }

        // ExecuteSqlRaw with interpolation
        if (methodName.EndsWith("ExecuteSqlRaw") || methodName.EndsWith("ExecuteSqlRawAsync"))
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null && args.Value.Count > 0)
            {
                var firstArg = args.Value[0].Expression;
                if (firstArg is InterpolatedStringExpressionSyntax || ContainsStringConcatenation(firstArg))
                {
                    AddVuln(node, "SQL Injection via ExecuteSqlRaw", "Critical",
                        "ExecuteSqlRaw with string interpolation/concatenation. Values are not parameterized.",
                        "CWE-89", "A03:2021",
                        "Use ExecuteSqlInterpolated() or ExecuteSqlInterpolatedAsync() which safely parameterize interpolated values.");
                }
            }
        }
    }

    // --- Open Redirect ---

    private void CheckOpenRedirect(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        if (methodName.EndsWith("Redirect") || methodName.EndsWith("RedirectPermanent"))
        {
            var args = node.ArgumentList?.Arguments;
            if (args != null && args.Value.Count > 0)
            {
                var firstArg = args.Value[0].Expression;
                if (IsTainted(firstArg) || !IsStaticString(firstArg))
                {
                    AddVuln(node, "Open Redirect", "Medium",
                        "Redirect to user-controlled URL. Attacker could redirect users to a malicious site for phishing.",
                        "CWE-601", "A01:2021",
                        "Use Url.IsLocalUrl() to validate redirect targets. Only allow redirects to relative URLs or a whitelist of trusted domains.");
                }
            }
        }

        // LocalRedirect is safe, skip it
        if (methodName.EndsWith("RedirectToAction") || methodName.EndsWith("RedirectToRoute"))
        {
            // These are generally safe as they construct URLs from route data
        }
    }

    // --- File Upload ---

    private void CheckFileUpload(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        if (methodName.EndsWith("CopyToAsync") || methodName.EndsWith("CopyTo"))
        {
            if (fullText.Contains("IFormFile") || fullText.Contains("formFile") || fullText.Contains("uploadedFile") || fullText.Contains("file."))
            {
                var blockText = GetEnclosingBlockText(node);
                if (!blockText.Contains("ContentType") && !blockText.Contains("Extension") && !blockText.Contains("FileType"))
                {
                    AddVuln(node, "Unrestricted File Upload", "High",
                        "File uploaded without validation of content type, extension, or size. Could allow upload of malicious files (web shells, malware).",
                        "CWE-434", "A04:2021",
                        "Validate file extension against an allowlist, check Content-Type, enforce size limits, scan for malware, and store files outside the web root with randomized names.");
                }
            }
        }

        // SaveAs
        if (methodName.EndsWith("SaveAs"))
        {
            if (fullText.Contains("FileName") || fullText.Contains("fileName"))
            {
                if (ContainsStringConcatenation(node) || IsTaintedSubtree(node))
                {
                    AddVuln(node, "Unsafe File Upload Path", "High",
                        "File saved using user-controlled filename. Attacker could use path traversal to overwrite system files.",
                        "CWE-434", "A04:2021",
                        "Generate a new filename server-side. Never use the user-supplied filename directly. Use Path.GetRandomFileName() or a GUID.");
                }
            }
        }
    }

    // --- SSL/TLS Validation ---

    private void CheckSslValidation(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        if (fullText.Contains("ServerCertificateValidationCallback") || fullText.Contains("ServerCertificateCustomValidationCallback"))
        {
            if (fullText.Contains("=> true") || fullText.Contains("return true"))
            {
                AddVuln(node, "SSL/TLS Certificate Validation Disabled", "Critical",
                    "Server certificate validation is disabled (always returns true). This allows man-in-the-middle attacks.",
                    "CWE-295", "A07:2021",
                    "Remove the custom validation callback or implement proper certificate validation. In development, use trusted development certificates instead.");
            }
        }

        // ServicePointManager.ServerCertificateValidationCallback
        if (fullText.Contains("ServicePointManager") && fullText.Contains("CertificateValidation"))
        {
            AddVuln(node, "Global SSL/TLS Validation Override", "Critical",
                "ServicePointManager certificate validation affects ALL HTTP connections in the application.",
                "CWE-295", "A07:2021",
                "Avoid global certificate validation overrides. Use HttpClientHandler.ServerCertificateCustomValidationCallback on specific HttpClient instances if needed.");
        }
    }

    // --- Logging Sensitive Data ---

    private void CheckLoggingSensitiveData(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        var logMethods = new[] { "LogInformation", "LogWarning", "LogError", "LogDebug", "LogTrace",
            "LogCritical", "Information", "Warning", "Error", "Debug", "Write", "WriteLine" };

        if (logMethods.Any(m => methodName.EndsWith(m)))
        {
            var sensitiveKeywords = new[] { "password", "creditcard", "credit_card", "ssn", "social_security",
                "cardnumber", "card_number", "cvv", "pin", "secret", "token", "apikey" };

            var argsText = node.ArgumentList?.ToString().ToLowerInvariant() ?? "";
            if (sensitiveKeywords.Any(k => argsText.Contains(k)))
            {
                AddVuln(node, "Logging Sensitive Data", "Medium",
                    "Potentially sensitive data (passwords, tokens, PII) being written to logs.",
                    "CWE-532", "A09:2021",
                    "Never log sensitive data. Mask or redact sensitive fields before logging. Use structured logging with data classification.");
            }
        }
    }

    // --- Timing Attack ---

    private void CheckTimingAttack(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        // String comparison for secrets/tokens/passwords
        if (methodName.EndsWith("Equals") || methodName.EndsWith("Compare") || methodName.EndsWith("CompareTo"))
        {
            var blockText = GetEnclosingBlockText(node);
            var securityKeywords = new[] { "token", "password", "hash", "secret", "apikey", "signature", "hmac", "digest" };

            if (securityKeywords.Any(k => blockText.Contains(k, StringComparison.OrdinalIgnoreCase)))
            {
                if (!fullText.Contains("FixedTimeEquals") && !fullText.Contains("CryptographicOperations"))
                {
                    AddVuln(node, "Timing Attack Vulnerability", "Medium",
                        "String comparison used for security-sensitive values. Standard string comparison short-circuits on first difference, leaking timing information.",
                        "CWE-208", "A02:2021",
                        "Use CryptographicOperations.FixedTimeEquals() for comparing security-sensitive byte arrays (hashes, tokens, HMACs).");
                }
            }
        }

        // == operator for token/password comparison (checked via binary expression)
    }

    // --- Information Disclosure ---

    private void CheckInformationDisclosure(InvocationExpressionSyntax node, string methodName, string fullText)
    {
        // Exception details in response
        if (methodName.EndsWith("ToString") && fullText.Contains("Exception"))
        {
            var blockText = GetEnclosingBlockText(node);
            if (blockText.Contains("return") || blockText.Contains("Response") || blockText.Contains("Content") || blockText.Contains("Json"))
            {
                AddVuln(node, "Information Disclosure via Exception", "Medium",
                    "Exception details (stack trace, internal paths) may be returned to the client.",
                    "CWE-209", "A04:2021",
                    "Return generic error messages to clients. Log exception details server-side only. Use exception filters or middleware for consistent error handling.");
            }
        }

        // Stack trace in response
        if (fullText.Contains("StackTrace") && (fullText.Contains("return") || fullText.Contains("Response") || fullText.Contains("Write")))
        {
            AddVuln(node, "Stack Trace Disclosure", "Medium",
                "Stack trace information exposed to client. Reveals internal code structure, file paths, and library versions.",
                "CWE-209", "A04:2021",
                "Never return stack traces to end users. Use app.UseExceptionHandler() in production to handle errors generically.");
        }
    }

    // --- Assignment-based checks ---

    private void CheckAssignmentVulnerabilities(AssignmentExpressionSyntax node)
    {
        var left = node.Left.ToString();
        var right = node.Right.ToString();
        var fullText = node.ToString();

        // JsonConvert TypeNameHandling
        if (left.Contains("TypeNameHandling") && !right.Contains("None"))
        {
            if (right.Contains("All") || right.Contains("Auto") || right.Contains("Objects") || right.Contains("Arrays"))
            {
                AddVuln(node, "Insecure Deserialization - TypeNameHandling", "Critical",
                    $"Json.NET TypeNameHandling set to {right}. Allows arbitrary type instantiation during deserialization, enabling remote code execution.",
                    "CWE-502", "A08:2021",
                    "Set TypeNameHandling to None (default). If type handling is required, use a custom ISerializationBinder to restrict allowed types.");
            }
        }

        // XmlResolver assignment (not null = potentially dangerous)
        if (left.Contains("XmlResolver") && !right.Contains("null"))
        {
            AddVuln(node, "XXE Risk - XmlResolver Not Disabled", "Medium",
                "XmlResolver set to a non-null value. External entities and DTDs may be resolved.",
                "CWE-611", "A05:2021",
                "Set XmlResolver = null to prevent external entity resolution.");
        }

        // Cookie security
        if (left.Contains("Secure") && left.Contains("Cookie") && right.Contains("false"))
        {
            AddVuln(node, "Insecure Cookie - Secure Flag Disabled", "Medium",
                "Cookie Secure flag set to false. Cookie will be sent over unencrypted HTTP connections.",
                "CWE-614", "A05:2021",
                "Set the Secure flag to true to ensure cookies are only sent over HTTPS.");
        }

        if (left.Contains("HttpOnly") && right.Contains("false"))
        {
            AddVuln(node, "Insecure Cookie - HttpOnly Disabled", "Medium",
                "Cookie HttpOnly flag set to false. Cookie is accessible to JavaScript, increasing XSS impact.",
                "CWE-1004", "A05:2021",
                "Set HttpOnly = true to prevent JavaScript access to the cookie.");
        }

        if (left.Contains("SameSite") && right.Contains("None"))
        {
            AddVuln(node, "Cookie SameSite None", "Low",
                "Cookie SameSite set to None. Cookie will be sent in cross-site requests, potentially enabling CSRF.",
                "CWE-1275", "A01:2021",
                "Use SameSite=Strict or SameSite=Lax unless cross-site usage is specifically required.");
        }

        // SSL validation
        if (left.Contains("ServerCertificateValidationCallback") || left.Contains("ServerCertificateCustomValidationCallback"))
        {
            if (right.Contains("=> true") || right.Contains("return true") || right.Contains("DangerousAcceptAny"))
            {
                AddVuln(node, "SSL/TLS Certificate Validation Disabled", "Critical",
                    "Certificate validation callback always returns true, disabling all SSL/TLS security.",
                    "CWE-295", "A07:2021",
                    "Implement proper certificate validation or remove the callback. Use trusted certificates in all environments.");
            }
        }

        // CORS
        if (left.Contains("AllowAnyOrigin") || (left.Contains("Origin") && right.Contains("*")))
        {
            // Handled in controller check
        }

        // ValidateIssuer = false (JWT)
        if (left.Contains("ValidateIssuer") && right.Contains("false"))
        {
            AddVuln(node, "JWT Validation Weakness - Issuer Not Validated", "Medium",
                "JWT token issuer validation is disabled. Tokens from any issuer will be accepted.",
                "CWE-287", "A07:2021",
                "Set ValidateIssuer = true and configure ValidIssuer to the expected token issuer.");
        }

        if (left.Contains("ValidateAudience") && right.Contains("false"))
        {
            AddVuln(node, "JWT Validation Weakness - Audience Not Validated", "Medium",
                "JWT token audience validation is disabled. Tokens intended for other services will be accepted.",
                "CWE-287", "A07:2021",
                "Set ValidateAudience = true and configure ValidAudience to the expected audience.");
        }

        if (left.Contains("ValidateLifetime") && right.Contains("false"))
        {
            AddVuln(node, "JWT Validation Weakness - Lifetime Not Validated", "High",
                "JWT token lifetime/expiration validation is disabled. Expired tokens will be accepted.",
                "CWE-613", "A07:2021",
                "Set ValidateLifetime = true to reject expired tokens.");
        }

        if (left.Contains("RequireExpirationTime") && right.Contains("false"))
        {
            AddVuln(node, "JWT Without Expiration", "High",
                "JWT tokens are not required to have an expiration time. Tokens will never expire.",
                "CWE-613", "A07:2021",
                "Set RequireExpirationTime = true and set reasonable token lifetimes.");
        }

        if (left.Contains("RequireSignedTokens") && right.Contains("false"))
        {
            AddVuln(node, "JWT Signature Validation Disabled", "Critical",
                "JWT token signature validation is disabled. Unsigned or tampered tokens will be accepted.",
                "CWE-347", "A07:2021",
                "Set RequireSignedTokens = true. Always validate JWT signatures.");
        }
    }

    // --- JWT Attribute Checks ---

    private void CheckJwtAttributes(AttributeSyntax node, string attrName)
    {
        // AllowAnonymous on sensitive endpoints
        if (attrName == "AllowAnonymous")
        {
            var method = node.FirstAncestorOrSelf<MethodDeclarationSyntax>();
            if (method != null)
            {
                var methodName = method.Identifier.Text.ToLowerInvariant();
                var sensitiveOps = new[] { "delete", "update", "create", "admin", "config", "setting", "user" };
                if (sensitiveOps.Any(op => methodName.Contains(op)))
                {
                    AddVuln(node, "Missing Authorization on Sensitive Endpoint", "High",
                        $"[AllowAnonymous] on potentially sensitive method '{method.Identifier.Text}'. This bypasses all authentication.",
                        "CWE-862", "A01:2021",
                        "Remove [AllowAnonymous] from sensitive endpoints. Use [Authorize] with appropriate policies/roles.");
                }
            }
        }
    }

    private void CheckObsoleteSecurityAttributes(AttributeSyntax node, string attrName)
    {
        if (attrName is "ValidateInput" && node.ArgumentList?.Arguments.FirstOrDefault()?.ToString() == "false")
        {
            AddVuln(node, "Input Validation Disabled", "Medium",
                "[ValidateInput(false)] disables ASP.NET request validation, allowing potentially dangerous input.",
                "CWE-20", "A03:2021",
                "Remove [ValidateInput(false)] and handle input validation explicitly with proper encoding/sanitization.");
        }
    }

    // --- Cookie Security ---

    private void CheckCookieSecurity(ObjectCreationExpressionSyntax node, string typeName)
    {
        if (typeName is "CookieOptions" or "CookieBuilder")
        {
            var initText = node.ToString();
            if (!initText.Contains("Secure = true") && !initText.Contains("Secure=true"))
            {
                AddVuln(node, "Cookie Missing Secure Flag", "Medium",
                    "CookieOptions created without setting Secure = true. Cookie may be sent over HTTP.",
                    "CWE-614", "A05:2021",
                    "Set Secure = true, HttpOnly = true, and SameSite = Strict/Lax on all cookies.");
            }
        }
    }

    // --- Race Condition ---

    private void CheckRaceCondition(ObjectCreationExpressionSyntax node, string typeName)
    {
        // Check-then-act pattern with file operations
        if (typeName is "FileStream")
        {
            var blockText = GetEnclosingBlockText(node);
            if (blockText.Contains("File.Exists") || blockText.Contains("Directory.Exists"))
            {
                AddVuln(node, "TOCTOU Race Condition", "Medium",
                    "Time-of-check-to-time-of-use (TOCTOU) race condition: File existence is checked before opening. Between the check and use, the file could be modified or replaced.",
                    "CWE-367", "A04:2021",
                    "Open the file directly in a try-catch block instead of checking existence first. Use file locking mechanisms for critical operations.");
            }
        }
    }

    // --- CORS ---

    private void CheckCorsOnController(ClassDeclarationSyntax node)
    {
        var attrs = node.AttributeLists.SelectMany(al => al.Attributes);
        foreach (var attr in attrs)
        {
            var attrText = attr.ToString();
            if (attrText.Contains("EnableCors"))
            {
                if (attrText.Contains("\"*\"") || attrText.Contains("AllowAnyOrigin"))
                {
                    AddVuln(attr, "CORS Misconfiguration - Allow Any Origin", "High",
                        "CORS policy allows any origin (*). This permits any website to make cross-origin requests to this API.",
                        "CWE-942", "A05:2021",
                        "Restrict CORS to specific trusted origins. Never use * with credentials. Configure a named CORS policy with specific origins.");
                }
            }
        }

        // Check for AllowAnyOrigin in method calls within the class
        var invocations = node.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var inv in invocations)
        {
            var invText = inv.ToString();
            if (invText.Contains("AllowAnyOrigin") && (invText.Contains("AllowCredentials") || invText.Contains("WithCredentials")))
            {
                AddVuln(inv, "CORS - AllowAnyOrigin with Credentials", "Critical",
                    "CORS configured with AllowAnyOrigin and AllowCredentials. This is forbidden by the CORS spec and creates a security vulnerability.",
                    "CWE-942", "A05:2021",
                    "Never combine AllowAnyOrigin with AllowCredentials. Specify explicit origins when credentials are needed.");
            }
        }
    }

    // --- Anti-Forgery ---

    private void CheckMissingAntiForgery(ClassDeclarationSyntax node)
    {
        var className = node.Identifier.Text;
        bool isController = node.BaseList?.Types.Any(t =>
            t.ToString().Contains("Controller")) == true;

        if (!isController) return;

        var hasGlobalAntiForgery = node.AttributeLists
            .SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString().Contains("AutoValidateAntiforgeryToken") ||
                      a.Name.ToString().Contains("ValidateAntiForgeryToken"));

        if (hasGlobalAntiForgery) return;

        // Check POST methods without anti-forgery
        var methods = node.Members.OfType<MethodDeclarationSyntax>();
        foreach (var method in methods)
        {
            var methodAttrs = method.AttributeLists.SelectMany(al => al.Attributes);
            bool isPost = methodAttrs.Any(a => a.Name.ToString().Contains("HttpPost") ||
                                                a.Name.ToString().Contains("HttpPut") ||
                                                a.Name.ToString().Contains("HttpDelete") ||
                                                a.Name.ToString().Contains("HttpPatch"));
            bool hasAntiForgery = methodAttrs.Any(a => a.Name.ToString().Contains("ValidateAntiForgeryToken"));
            bool isApiController = node.AttributeLists.SelectMany(al => al.Attributes)
                .Any(a => a.Name.ToString().Contains("ApiController"));
            bool hasIgnore = methodAttrs.Any(a => a.Name.ToString().Contains("IgnoreAntiforgeryToken"));

            if (isPost && !hasAntiForgery && !isApiController && !hasIgnore)
            {
                AddVuln(method, "Missing Anti-Forgery Token Validation", "Medium",
                    $"POST/PUT/DELETE method '{method.Identifier.Text}' in MVC controller '{className}' lacks [ValidateAntiForgeryToken]. Vulnerable to CSRF.",
                    "CWE-352", "A01:2021",
                    "Add [ValidateAntiForgeryToken] to POST/PUT/DELETE actions, or [AutoValidateAntiforgeryToken] to the controller class. For APIs, use [ApiController] which uses different CSRF mechanisms.");
            }
        }
    }

    // --- Missing Authorization ---

    private void CheckMissingAuthorization(MethodDeclarationSyntax node)
    {
        // Check if method is in a controller
        var classDecl = node.FirstAncestorOrSelf<ClassDeclarationSyntax>();
        if (classDecl == null) return;

        bool isController = classDecl.BaseList?.Types.Any(t =>
            t.ToString().Contains("Controller")) == true ||
            classDecl.AttributeLists.SelectMany(al => al.Attributes)
                .Any(a => a.Name.ToString().Contains("ApiController"));

        if (!isController) return;

        // Check if class or method has Authorize
        bool classHasAuth = classDecl.AttributeLists.SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString().Contains("Authorize"));

        bool methodHasAuth = node.AttributeLists.SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString().Contains("Authorize"));

        bool methodHasAllowAnon = node.AttributeLists.SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString().Contains("AllowAnonymous"));

        // If neither class nor method has authorization, flag sensitive operations
        if (!classHasAuth && !methodHasAuth && !methodHasAllowAnon)
        {
            var methodName = node.Identifier.Text.ToLowerInvariant();
            var sensitiveKeywords = new[] { "delete", "remove", "update", "edit", "create", "admin",
                "config", "setting", "user", "role", "permission", "grant" };

            if (sensitiveKeywords.Any(k => methodName.Contains(k)))
            {
                var httpAttrs = node.AttributeLists.SelectMany(al => al.Attributes)
                    .Where(a => a.Name.ToString().StartsWith("Http"));
                if (httpAttrs.Any())
                {
                    AddVuln(node, "Missing Authorization", "High",
                        $"Sensitive endpoint '{node.Identifier.Text}' lacks [Authorize] attribute. Any unauthenticated user can access it.",
                        "CWE-862", "A01:2021",
                        "Add [Authorize] with appropriate roles/policies to protect sensitive endpoints. Apply authorization at the controller level for consistent protection.");
                }
            }
        }
    }

    // ============================================================
    //  HELPER METHODS
    // ============================================================

    private bool IsUserInput(ExpressionSyntax expr)
    {
        var text = expr.ToString();
        if (UserInputSources.Any(s => text.Contains(s))) return true;
        if (expr is IdentifierNameSyntax id && _taintedVars.ContainsKey(id.Identifier.Text)) return true;
        // Check for user input method calls
        if (expr is InvocationExpressionSyntax inv)
        {
            var methodName = GetMethodName(inv);
            if (UserInputMethods.Any(m => methodName.Contains(m))) return true;
        }
        return false;
    }

    private bool IsTainted(ExpressionSyntax expr)
    {
        var text = expr.ToString();
        // Direct user input sources
        if (UserInputSources.Any(s => text.Contains(s))) return true;
        // Variable tracking
        if (expr is IdentifierNameSyntax id && _taintedVars.ContainsKey(id.Identifier.Text)) return true;
        // Recursive check on member access
        if (expr is MemberAccessExpressionSyntax ma)
        {
            if (UserInputSources.Any(s => text.Contains(s))) return true;
            return IsTainted(ma.Expression);
        }
        // Check arguments in invocation
        if (expr is InvocationExpressionSyntax inv)
        {
            var methodName = GetMethodName(inv);
            if (UserInputMethods.Any(m => methodName.Contains(m))) return true;
        }
        // Concatenation with tainted
        if (expr is BinaryExpressionSyntax bin && bin.IsKind(SyntaxKind.AddExpression))
            return IsTainted(bin.Left) || IsTainted(bin.Right);
        // Interpolated string with tainted
        if (expr is InterpolatedStringExpressionSyntax interp)
            return interp.Contents.OfType<InterpolationSyntax>().Any(i => IsTainted(i.Expression));
        return false;
    }

    private bool IsTaintedSubtree(SyntaxNode node)
    {
        return node.DescendantNodes().OfType<IdentifierNameSyntax>()
            .Any(id => _taintedVars.ContainsKey(id.Identifier.Text)) ||
            node.DescendantNodes().OfType<ExpressionSyntax>()
            .Any(e => UserInputSources.Any(s => e.ToString().Contains(s)));
    }

    private bool ContainsStringConcatenation(SyntaxNode node)
    {
        // Look for + operator with at least one non-literal operand
        return node.DescendantNodesAndSelf().OfType<BinaryExpressionSyntax>()
            .Any(b => b.IsKind(SyntaxKind.AddExpression) &&
                (b.Left is not LiteralExpressionSyntax || b.Right is not LiteralExpressionSyntax));
    }

    private bool ContainsInterpolation(SyntaxNode node)
    {
        return node.DescendantNodesAndSelf().OfType<InterpolatedStringExpressionSyntax>()
            .Any(i => i.Contents.OfType<InterpolationSyntax>().Any());
    }

    private bool IsStaticString(ExpressionSyntax expr)
    {
        return expr is LiteralExpressionSyntax { RawKind: (int)SyntaxKind.StringLiteralExpression };
    }

    private bool IsInsideController(MethodDeclarationSyntax method)
    {
        var classDecl = method.FirstAncestorOrSelf<ClassDeclarationSyntax>();
        if (classDecl == null) return false;
        var baseTypes = classDecl.BaseList?.Types.Select(t => t.ToString()) ?? Enumerable.Empty<string>();
        return baseTypes.Any(t => t.Contains("Controller")) ||
               classDecl.AttributeLists.SelectMany(al => al.Attributes)
                   .Any(a => a.Name.ToString().Contains("ApiController"));
    }

    private bool HasDtdProtection(SyntaxNode node)
    {
        // Look in the enclosing block for DTD protection
        var block = GetEnclosingBlockText(node);
        return block.Contains("DtdProcessing.Prohibit") || block.Contains("XmlResolver = null") ||
               block.Contains("ProhibitDtd = true") || block.Contains("DtdProcessing = DtdProcessing.Ignore");
    }

    private string GetMethodName(InvocationExpressionSyntax node)
    {
        return node.Expression switch
        {
            MemberAccessExpressionSyntax ma => ma.ToString(),
            IdentifierNameSyntax id => id.Identifier.Text,
            _ => node.Expression.ToString()
        };
    }

    private string GetEnclosingBlockText(SyntaxNode node)
    {
        var method = node.FirstAncestorOrSelf<MethodDeclarationSyntax>();
        if (method != null) return method.ToString();
        var block = node.FirstAncestorOrSelf<BlockSyntax>();
        if (block != null) return block.ToString();
        // Fallback: get surrounding lines
        var span = node.GetLocation().GetLineSpan();
        int startLine = Math.Max(0, span.StartLinePosition.Line - 10);
        int endLine = Math.Min(_lines.Length - 1, span.EndLinePosition.Line + 10);
        return string.Join("\n", _lines.Skip(startLine).Take(endLine - startLine + 1));
    }

    private string GetSnippet(SyntaxNode node)
    {
        var span = node.GetLocation().GetLineSpan();
        int line = span.StartLinePosition.Line;
        int start = Math.Max(0, line - 1);
        int end = Math.Min(_lines.Length - 1, line + 1);
        return string.Join("\n", _lines.Skip(start).Take(end - start + 1)).Trim();
    }

    private void AddVuln(SyntaxNode node, string title, string severity, string description,
        string cwe, string owasp, string recommendation)
    {
        var location = node.GetLocation().GetLineSpan();
        Vulnerabilities.Add(new Vulnerability
        {
            Title = title,
            Description = description,
            Severity = severity,
            Confidence = severity == "Critical" ? "High" : severity == "High" ? "High" : "Medium",
            Category = GetCategory(cwe),
            Cwe = cwe,
            Owasp = owasp,
            File = _filePath,
            Line = location.StartLinePosition.Line + 1,
            Column = location.StartLinePosition.Character + 1,
            Snippet = GetSnippet(node),
            Recommendation = recommendation
        });
    }

    private static string GetCategory(string cwe)
    {
        return cwe switch
        {
            "CWE-89" => "Injection",
            "CWE-78" => "Injection",
            "CWE-90" => "Injection",
            "CWE-79" => "Cross-Site Scripting",
            "CWE-22" => "Path Traversal",
            "CWE-502" => "Insecure Deserialization",
            "CWE-611" => "XML External Entity",
            "CWE-918" => "Server-Side Request Forgery",
            "CWE-798" => "Hardcoded Credentials",
            "CWE-327" or "CWE-328" => "Weak Cryptography",
            "CWE-330" => "Insecure Randomness",
            "CWE-352" => "Cross-Site Request Forgery",
            "CWE-601" => "Open Redirect",
            "CWE-434" => "Unrestricted File Upload",
            "CWE-295" => "Improper Certificate Validation",
            "CWE-532" => "Information Exposure Through Log",
            "CWE-208" => "Timing Attack",
            "CWE-209" => "Information Disclosure",
            "CWE-287" or "CWE-613" or "CWE-347" => "Authentication",
            "CWE-862" => "Missing Authorization",
            "CWE-614" or "CWE-1004" or "CWE-1275" => "Cookie Security",
            "CWE-367" => "Race Condition",
            "CWE-942" => "CORS Misconfiguration",
            "CWE-20" => "Input Validation",
            _ => "Security Misconfiguration"
        };
    }
}
