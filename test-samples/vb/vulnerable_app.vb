' Offensive360 VB/VB.NET SAST Test Sample - Vulnerable Code
' This file contains intentional vulnerabilities for testing the VB scanner

Imports System
Imports System.IO
Imports System.Data.SqlClient
Imports System.Diagnostics
Imports System.Security.Cryptography
Imports System.Net
Imports System.Xml
Imports System.Runtime.Serialization.Formatters.Binary
Imports Newtonsoft.Json
Imports System.Web
Imports System.Web.UI

' ============================================================
' SQL Injection
' ============================================================
Module DatabaseOperations
    Sub GetUserByName(connStr As String, userName As String)
        ' VULN: SQL injection via string concatenation with &
        Dim conn As New SqlConnection(connStr)
        Dim query As String = "SELECT * FROM Users WHERE Name = '" & userName & "'"
        Dim cmd As New SqlCommand(query, conn)
        conn.Open()
        cmd.ExecuteReader()
    End Sub

    Sub SearchProducts(conn As SqlConnection, searchTerm As String)
        ' VULN: SQL injection via + operator
        Dim sql As String = "SELECT * FROM Products WHERE Name LIKE '%" + searchTerm + "%'"
        Dim cmd As New SqlCommand(sql, conn)
        cmd.ExecuteReader()
    End Sub

    Sub DeleteUser(conn As SqlConnection, userId As String)
        ' VULN: SQL injection with String.Format
        Dim sql = String.Format("DELETE FROM Users WHERE Id = {0}", userId)
        Dim cmd As New SqlCommand(sql, conn)
        cmd.ExecuteNonQuery()
    End Sub

    Sub LegacyAdoQuery(searchValue As String)
        ' VULN: VB6 ADODB with string concat
        Dim rs As ADODB.Recordset
        Dim conn As New ADODB.Connection
        conn.Open("Provider=SQLOLEDB;Data Source=myServer")
        conn.Execute "SELECT * FROM Orders WHERE Customer = '" & searchValue & "'"
    End Sub

    Sub WebFormsQuery(sender As Object, e As EventArgs)
        ' VULN: SQL with TextBox value
        Dim sql As String = "SELECT * FROM Users WHERE Email = '" & txtEmail.Text & "'"
        Dim cmd As New SqlCommand(sql, conn)
    End Sub
End Module

' ============================================================
' Command Injection
' ============================================================
Module CommandExecution
    Sub RunCommand(userInput As String)
        ' VULN: Process.Start with user input
        Process.Start("cmd.exe", "/c " & userInput)
    End Sub

    Sub ShellCommand(command As String)
        ' VULN: VB Shell function
        Shell "cmd.exe /c " & command
    End Sub

    Sub WScriptShellExec()
        ' VULN: WScript.Shell COM object
        Dim objShell As Object = CreateObject("WScript.Shell")
        objShell.Run("calc.exe")
    End Sub

    Sub ShellApp()
        ' VULN: Shell.Application COM object
        Dim shell As Object = CreateObject("Shell.Application")
        shell.Exec("notepad.exe")
    End Sub
End Module

' ============================================================
' Code Injection
' ============================================================
Module DynamicExecution
    Sub CallDynamic(methodName As String)
        ' VULN: CallByName with user input
        Dim obj As New MyClass()
        CallByName(obj, methodName & "Handler", CallType.Method)
    End Sub

    Sub CreateDynamicObject(progId As String)
        ' VULN: CreateObject with dynamic ProgID
        Dim obj As Object = CreateObject(progId)
        obj.Execute()
    End Sub

    Sub EvalCode(code As String)
        ' VULN: VBScript Execute
        Execute(code)
        ExecuteGlobal(code)
        Eval(code)
    End Sub

    Sub LoadDynamic(path As String)
        ' VULN: Dynamic assembly loading
        Dim asm = System.Reflection.Assembly.LoadFile(path & ".dll")
        Activator.CreateInstance(asm.GetType("Payload"))
    End Sub
End Module

' ============================================================
' XSS (WebForms)
' ============================================================
Module WebFormsXss
    Sub WriteResponse(input As String)
        ' VULN: Response.Write with user input
        Response.Write("<div>" & Request.QueryString("name") & "</div>")
    End Sub

    Sub SetInnerHtml()
        ' VULN: InnerHtml from request
        divContent.InnerHtml = Request.Form("content")
    End Sub

    Sub SetLiteral()
        ' VULN: Literal with unencoded request data
        Literal1.Text = Request.QueryString("msg")
    End Sub

    Sub SetLabelFromInput()
        ' VULN: Label from request
        Label1.Text = "&lt;script&gt;" & Request("input") & "&lt;/script&gt;"
    End Sub
End Module

' ============================================================
' Path Traversal
' ============================================================
Module FileOperations
    Sub ReadFile(fileName As String)
        ' VULN: File read with user input
        Dim content = File.ReadAllText("C:\app\data\" & fileName)
    End Sub

    Sub VB6FileAccess(path As String)
        ' VULN: FileSystemObject with user path
        Dim fso As Object
        Set fso = CreateObject("Scripting.FileSystemObject")
        fso.OpenTextFile path & "\config.ini"
    End Sub

    Sub MappedPath(userPath As String)
        ' VULN: Server.MapPath with user input
        Dim fullPath = Server.MapPath("~/files/" & Request.QueryString("file"))
        File.ReadAllBytes(fullPath)
    End Sub
End Module

' ============================================================
' Deserialization
' ============================================================
Module Serialization
    Sub DeserializeBinary(data As Byte())
        ' VULN: BinaryFormatter RCE
        Dim formatter As New BinaryFormatter()
        Using ms As New MemoryStream(data)
            Dim result = formatter.Deserialize(ms)
        End Using
    End Sub

    Sub DeserializeJson(json As String)
        ' VULN: TypeNameHandling.All
        Dim settings As New JsonSerializerSettings()
        settings.TypeNameHandling := TypeNameHandling.All
        Dim obj = JsonConvert.DeserializeObject(json, settings)
    End Sub

    Sub DeserializeSoap(stream As Stream)
        ' VULN: SoapFormatter
        Dim formatter As New System.Runtime.Serialization.Formatters.Soap.SoapFormatter()
        formatter.Deserialize(stream)
    End Sub
End Module

' ============================================================
' XXE
' ============================================================
Module XmlParsing
    Sub ParseXml(xmlString As String)
        ' VULN: XmlDocument without safe settings
        Dim doc As New XmlDocument()
        doc.LoadXml(xmlString)
    End Sub

    Sub ParseMsxml(xmlData As String)
        ' VULN: MSXML DOM
        Dim doc As Object = CreateObject("MSXML2.DOMDocument")
        doc.async = False
        doc.loadXML(xmlData)
    End Sub

    Sub ParseWithDtd(filePath As String)
        ' VULN: DTD processing enabled
        Dim settings As New XmlReaderSettings()
        settings.DtdProcessing := DtdProcessing.Parse
        Dim reader = XmlReader.Create(filePath, settings)
    End Sub
End Module

' ============================================================
' SSRF
' ============================================================
Module HttpRequests
    Sub FetchUrl(url As String)
        ' VULN: SSRF with user URL
        Dim client As New System.Net.Http.HttpClient()
        Dim response = client.GetAsync(url).Result
    End Sub

    Sub LegacyHttp(targetUrl As String)
        ' VULN: MSXML2.XMLHTTP with user URL
        Dim xmlhttp As Object = CreateObject("MSXML2.XMLHTTP")
        xmlhttp.Open "GET", targetUrl & "/api/data", False
        xmlhttp.Send
    End Sub
End Module

' ============================================================
' Hardcoded Secrets
' ============================================================
Module Configuration
    Dim connectionString As String = "Server=db.internal;Database=prod;Password=SuperSecret123!;User Id=admin"
    Dim apiKey As String = "sk-live-abcdef1234567890abcdef1234567890"
    Dim jwtSecret As String = "MyJwtSecretKeyThatShouldBeInConfig2024!"
    Dim dbPassword As String = "ProductionDbPassword2024!"
End Module

' ============================================================
' Weak Cryptography
' ============================================================
Module Cryptography
    Sub HashWithMd5(data As String)
        ' VULN: MD5 is broken
        Dim md5 As New MD5CryptoServiceProvider()
        md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data))
    End Sub

    Sub HashWithSha1(data As String)
        ' VULN: SHA1 is deprecated
        Dim sha1 = SHA1.Create()
        sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data))
    End Sub

    Sub EncryptWithDes(data As Byte(), key As Byte())
        ' VULN: DES is weak
        Dim des As New DESCryptoServiceProvider()
        des.Key = key
    End Sub
End Module

' ============================================================
' Insecure Random
' ============================================================
Module RandomGeneration
    Sub GenerateToken()
        ' VULN: Rnd for token
        Randomize
        Dim token = Int(Rnd() * 999999)
    End Sub

    Sub GenerateSession()
        ' VULN: System.Random
        Dim r As New Random()
        Dim id = r.Next(100000, 999999)
    End Sub
End Module

' ============================================================
' WebForms Security
' ============================================================
' VULN: ViewState MAC disabled
' <%@ Page EnableViewStateMac="False" %>

' VULN: Event validation disabled
' <%@ Page EnableEventValidation="False" %>

' VULN: Request validation disabled
' <%@ Page ValidateRequest="False" %>

' VULN: ViewState encryption disabled
' ViewStateEncryptionMode = ViewStateEncryptionMode.Never

Module WebFormsConfig
    Sub DisableViewStateMac()
        EnableViewStateMac = False
    End Sub

    Sub DisableEventValidation()
        EnableEventValidation = False
    End Sub

    Sub DisableRequestValidation()
        ValidateRequest = False
    End Sub

    Sub DisableViewStateEncryption()
        ViewStateEncryptionMode = "Never"
    End Sub
End Module

' ============================================================
' VB6/VBA Specific
' ============================================================
Module VB6Operations
    Sub ReadConfigFile(configPath As String)
        ' VULN: VB6 Open with user path
        Open configPath & "\settings.ini" For Input As #1
    End Sub

    Sub CheckEnvironment()
        ' VULN: Environ usage
        Dim dbPath = Environ("DB_PATH")
    End Sub
End Module

' ============================================================
' VBScript Specific
' ============================================================
Module VBScriptOps
    Sub ShellOps()
        ' VULN: WScript.Shell usage
        Dim shell = WScript.Shell
        shell.Run "cmd /c dir"
    End Sub

    Sub WmiQuery()
        ' VULN: WMI provider
        Dim wmi = GetObject("winmgmts:\\.\root\cimv2")
    End Sub
End Module

' ============================================================
' Error Handling
' ============================================================
Module ErrorHandling
    Sub RiskyOperation()
        ' VULN: On Error Resume Next
        On Error Resume Next
        Dim result = SomeRiskyCall()
        ' Error silently swallowed
    End Sub

    Sub EmptyCatch()
        ' VULN: Empty catch
        Try
            SomeOperation()
        Catch ex As Exception
        End Try
    End Sub
End Module

' ============================================================
' Information Disclosure
' ============================================================
Module InfoDisclosure
    ' VULN: Custom errors off
    ' <customErrors mode="Off" />

    Sub LogPassword(password As String)
        ' VULN: Logging sensitive data
        Debug.Print "User password: " & password
    End Sub

    Sub EnableTracing()
        ' VULN: Tracing enabled
        Trace = True
    End Sub

    Sub ShowSecret(secretToken As String)
        ' VULN: MessageBox with sensitive data
        MessageBox.Show("Token: " & secretToken)
    End Sub
End Module

' ============================================================
' Missing Authorization
' ============================================================
Partial Class AdminPage
    Inherits Page

    Sub Page_Load(sender As Object, e As EventArgs)
        ' VULN: No authentication check in Page_Load
        LoadSensitiveData()
    End Sub

    Sub btnSubmit_Click(sender As Object, e As EventArgs)
        ' VULN: No auth check in button handler
        DeleteAllRecords()
    End Sub
End Class

' ============================================================
' SSL/TLS Issues
' ============================================================
Module TlsConfig
    Sub DisableSsl()
        ' VULN: SSL validation disabled
        ServicePointManager.ServerCertificateValidationCallback = Function(s, c, ch, err) Return True End Function
    End Sub

    Sub UseOldTls()
        ' VULN: Old TLS
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls
    End Sub
End Module

' ============================================================
' Open Redirect
' ============================================================
Module Redirects
    Sub HandleRedirect()
        ' VULN: Open redirect with user input
        Response.Redirect(Request.QueryString("returnUrl"))
    End Sub
End Module

' ============================================================
' Cookie Security
' ============================================================
Module CookieOps
    Sub SetCookie()
        ' VULN: Insecure cookie
        Dim cookie As New HttpCookie("auth_token")
        cookie.Value = "secret_value"
        cookie.Secure = False
        cookie.HttpOnly = False
        Response.Cookies.Add(cookie)
    End Sub
End Module
