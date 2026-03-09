// Offensive360 F# SAST Test Sample - Vulnerable Code
// This file contains intentional vulnerabilities for testing the F# scanner

open System
open System.IO
open System.Data.SqlClient
open System.Diagnostics
open System.Security.Cryptography
open System.Net
open System.Xml
open System.Runtime.Serialization.Formatters.Binary
open System.Runtime.InteropServices
open Newtonsoft.Json

// ============================================================
// SQL Injection
// ============================================================
module DatabaseOperations =
    let getUserByName (connStr: string) (userName: string) =
        use conn = new SqlConnection(connStr)
        // VULN: SQL injection via string concatenation
        let query = "SELECT * FROM Users WHERE Name = '" + userName + "'"
        use cmd = new SqlCommand(query, conn)
        conn.Open()
        cmd.ExecuteReader()

    let searchProducts (conn: SqlConnection) (searchTerm: string) =
        // VULN: SQL injection via string format
        let sql = sprintf "SELECT * FROM Products WHERE Name LIKE '%%%s%%'" searchTerm
        use cmd = new SqlCommand(sql, conn)
        cmd.ExecuteReader()

    let deleteUser (conn: SqlConnection) (userId: string) =
        // VULN: SQL injection via interpolated string
        let sql = $"DELETE FROM Users WHERE Id = {userId}"
        use cmd = new SqlCommand(sql, conn)
        cmd.ExecuteNonQuery()

    let dapperQuery (connection: SqlConnection) (email: string) =
        // VULN: Dapper with string concat
        let sql = "SELECT * FROM Users WHERE Email = '" + email + "'"
        connection.Query<obj>(sql)

// ============================================================
// Command Injection
// ============================================================
module CommandExecution =
    let runUserCommand (userInput: string) =
        // VULN: Command injection via Process.Start
        let psi = ProcessStartInfo("cmd", "/c " + userInput)
        Process.Start(psi) |> ignore

    let pingHost (host: string) =
        // VULN: Command injection via ProcessStartInfo with user input
        let info = ProcessStartInfo("bash", $"-c 'ping -c 4 {host}'")
        info.RedirectStandardOutput <- true
        let proc = Process.Start(info)
        proc.StandardOutput.ReadToEnd()

// ============================================================
// Code Injection
// ============================================================
module DynamicExecution =
    let evaluateExpression (expression: string) =
        // VULN: F# Interactive evaluation of user input
        let session = FSharp.Compiler.Interactive.FsiEvaluationSession.Create()
        session.EvalExpression(expression)

    let loadAssembly (path: string) =
        // VULN: Dynamic assembly loading with user input
        let asm = System.Reflection.Assembly.LoadFile(path + ".dll")
        let t = asm.GetType("MyClass")
        Activator.CreateInstance(t)

    let invokeMethod (obj: obj) (methodName: string) (param: string) =
        // VULN: Reflection with user-controlled method name
        let mi = obj.GetType().GetMethod(methodName)
        mi.Invoke(obj, [| param :> obj |])

    let resolveType (typeName: string) =
        // VULN: Dynamic type resolution
        let t = Type.GetType("MyApp.Models." + typeName)
        Activator.CreateInstance(t)

// ============================================================
// XSS (Giraffe/Saturn)
// ============================================================
module WebViews =
    open Giraffe
    open Giraffe.ViewEngine

    let dangerousView (userContent: string) =
        // VULN: rawText with user input
        div [] [
            rawText userContent
            rawText $"<p>{userContent}</p>"
        ]

    let writeResponse (ctx: HttpContext) (input: string) =
        // VULN: Response.Write without encoding
        ctx.Response.Write("Hello " + input)

    let contentResponse (data: string) =
        // VULN: Content with dynamic HTML
        Content($"<div>{data}</div>")

// ============================================================
// Path Traversal
// ============================================================
module FileOperations =
    let readUserFile (fileName: string) =
        // VULN: File read with user input
        let content = File.ReadAllText("/app/data/" + fileName)
        content

    let downloadFile (requestPath: string) =
        // VULN: Path.Combine with user input (can be bypassed with absolute path)
        let fullPath = Path.Combine("/uploads", requestPath)
        File.ReadAllBytes(fullPath)

    let saveFile (userPath: string) (data: byte[]) =
        // VULN: File write with user path
        use stream = new FileStream(userPath, FileMode.Create)
        stream.Write(data, 0, data.Length)

// ============================================================
// Deserialization
// ============================================================
module Serialization =
    let deserializeBinary (data: byte[]) =
        // VULN: BinaryFormatter (critical RCE risk)
        let formatter = BinaryFormatter()
        use ms = new IO.MemoryStream(data)
        formatter.Deserialize(ms)

    let deserializeJson (json: string) =
        // VULN: TypeNameHandling.All enables type injection
        let settings = JsonSerializerSettings()
        settings.TypeNameHandling <- TypeNameHandling.All
        JsonConvert.DeserializeObject(json, settings)

    let deserializeSoap (stream: Stream) =
        // VULN: SoapFormatter deserialization
        let formatter = System.Runtime.Serialization.Formatters.Soap.SoapFormatter()
        formatter.Deserialize(stream)

// ============================================================
// XXE
// ============================================================
module XmlParsing =
    let parseXmlDocument (xmlString: string) =
        // VULN: XmlDocument without safe settings
        let doc = XmlDocument()
        // Missing: doc.XmlResolver <- null
        doc.LoadXml(xmlString)
        doc

    let parseWithDtd (filePath: string) =
        // VULN: DTD processing enabled
        let settings = XmlReaderSettings()
        settings.DtdProcessing <- DtdProcessing.Parse
        let reader = XmlReader.Create(filePath, settings)
        reader

// ============================================================
// SSRF
// ============================================================
module HttpRequests =
    let fetchUrl (url: string) =
        // VULN: SSRF with user-controlled URL
        use client = new System.Net.Http.HttpClient()
        let response = client.GetAsync(url).Result
        response.Content.ReadAsStringAsync().Result

    let proxyRequest (targetUrl: string) =
        // VULN: URI from user input
        let uri = Uri("http://internal-api/" + targetUrl)
        let request = WebRequest.Create(uri)
        request.GetResponse()

// ============================================================
// Hardcoded Secrets
// ============================================================
module Configuration =
    let connectionString = "Server=db.internal;Database=prod;Password=SuperSecret123!;User Id=admin"
    let apiKey = "sk-live-abcdef1234567890abcdef1234567890"
    let jwtSecret = "MyJwtSecretKeyThatShouldBeInConfig2024!"
    let awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
    let privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw"

// ============================================================
// Weak Cryptography
// ============================================================
module Cryptography =
    let hashWithMd5 (data: string) =
        // VULN: MD5 is broken
        use md5 = MD5.Create()
        md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data))

    let hashWithSha1 (data: string) =
        // VULN: SHA1 is deprecated
        use sha1 = SHA1.Create()
        sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data))

    let encryptWithDes (data: byte[]) (key: byte[]) =
        // VULN: DES is weak
        use des = DESCryptoServiceProvider()
        des.Key <- key
        des.CreateEncryptor()

    let encryptEcb (data: byte[]) (key: byte[]) =
        // VULN: ECB mode
        use aes = RijndaelManaged()
        aes.Mode <- CipherMode.ECB
        aes.Key <- key
        aes.CreateEncryptor()

// ============================================================
// Insecure Random
// ============================================================
module RandomGeneration =
    let generateToken () =
        // VULN: System.Random for security token
        let rng = Random()
        let token = Array.init 32 (fun _ -> rng.Next(0, 256) |> byte)
        Convert.ToBase64String(token)

    let generateSessionId () =
        // VULN: Predictable random
        let r = System.Random()
        r.Next(100000, 999999).ToString()

// ============================================================
// Giraffe/Saturn Security
// ============================================================
module WebSecurity =
    open Giraffe
    open Saturn

    let configCors (builder: IApplicationBuilder) =
        // VULN: Overly permissive CORS
        builder.UseCors(fun policy ->
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod() |> ignore)

    let webApp = choose [
        // VULN: Routes without authentication
        route "/api/users" >=> handleGetUsers
        route "/api/admin" >=> handleAdmin
        POST >=> route "/api/delete" >=> handleDelete
    ]

// ============================================================
// Mutable State
// ============================================================
module StateManagement =
    // VULN: Mutable variable
    let mutable globalCounter = 0

    // VULN: Ref cell in async context
    let sharedState = ref []

    let updateState (newValue: string) =
        async {
            // VULN: Ref cell used in async context
            sharedState := newValue :: !sharedState
        }

// ============================================================
// Unsafe Interop
// ============================================================
module NativeInterop =
    // VULN: DllImport P/Invoke
    [<DllImport("kernel32.dll")>]
    extern int GetTickCount()

    // VULN: SuppressUnmanagedCodeSecurity
    [<SuppressUnmanagedCodeSecurity>]
    [<DllImport("user32.dll")>]
    extern bool ShowWindow(nativeint hWnd, int nCmdShow)

    let copyMemory (src: nativeint) (dest: nativeint) (len: int) =
        // VULN: Native pointer operations
        Marshal.Copy(src, Array.zeroCreate<byte> len, 0, len)

// ============================================================
// Type Provider Security
// ============================================================
module DataProviders =
    // VULN: Type provider with remote URL
    type RemoteData = CsvProvider<"http://untrusted-server.com/schema.csv">
    type ApiSchema = JsonProvider<"http://example.com/api/schema.json">

// ============================================================
// Error Handling
// ============================================================
module ErrorHandling =
    let riskyOperation () =
        // VULN: failwith without try/with
        failwith "Something went wrong"

    let silentCatch () =
        try
            someRiskyCall()
        with | _ -> ()  // VULN: Exception swallowed

    let leakyError (ex: Exception) =
        // VULN: Exception message propagation
        raise (Exception("Error: " + ex.Message))

// ============================================================
// Information Disclosure
// ============================================================
module Logging =
    let logSensitive (token: string) =
        // VULN: Logging sensitive data
        printfn "Auth token: %s" token

    let configureApp (app: IApplicationBuilder) =
        // VULN: Developer exception page
        app.UseDeveloperExceptionPage() |> ignore

// ============================================================
// SSL/TLS Issues
// ============================================================
module TlsConfig =
    let disableSslValidation () =
        // VULN: SSL cert validation disabled
        ServicePointManager.ServerCertificateValidationCallback <- fun _ _ _ _ -> true

    let useOldTls () =
        // VULN: Old TLS version
        ServicePointManager.SecurityProtocol <- SecurityProtocolType.Tls

// ============================================================
// LDAP Injection
// ============================================================
module LdapOperations =
    let searchUser (userName: string) =
        // VULN: LDAP with user input
        let entry = new DirectoryServices.DirectoryEntry("LDAP://dc=corp,dc=local")
        let searcher = new DirectoryServices.DirectorySearcher(entry, $"(uid={userName})")
        searcher.FindAll()
