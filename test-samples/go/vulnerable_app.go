package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"text/template"
	"unsafe"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
	"google.golang.org/grpc"
)

// =============================================================================
// 1. SQL Injection
// =============================================================================

func getUserByName(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	// VULN: SQL injection via string concatenation
	query := "SELECT * FROM users WHERE name = '" + username + "'"
	rows, _ := db.Query(query)
	defer rows.Close()
}

func searchProducts(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("q")
	// VULN: SQL injection via fmt.Sprintf
	query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", search)
	rows, _ := db.Query(query)
	defer rows.Close()
}

// =============================================================================
// 2. Command Injection
// =============================================================================

func pingHost(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	// VULN: Command injection with user input
	cmd := exec.Command("ping", "-c", "4", host)
	output, _ := cmd.CombinedOutput()
	w.Write(output)
}

func runCommand(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	// VULN: Direct command execution with user input
	cmd := exec.Command("sh", "-c", command)
	output, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "%s", output)
}

// =============================================================================
// 3. Path Traversal
// =============================================================================

func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// VULN: Path traversal - no validation
	data, _ := os.ReadFile(filepath.Join("/var/data", filename))
	w.Write(data)
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
	// VULN: Arbitrary file deletion
	os.Remove(path)
}

// =============================================================================
// 4. XSS
// =============================================================================

func renderPage(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	// VULN: XSS - user input directly in response
	fmt.Fprintf(w, "<h1>Hello, %s!</h1>", name)
}

func textTemplateXSS(w http.ResponseWriter, r *http.Request) {
	// VULN: text/template does not escape HTML
	tmpl := template.New("page")
	tmpl.Parse("<html><body>{{.Content}}</body></html>")
}

// =============================================================================
// 5. SSRF
// =============================================================================

func proxyRequest(w http.ResponseWriter, r *http.Request) {
	targetURL := r.FormValue("url")
	// VULN: SSRF - user controls the URL
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

func fetchURL(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("target")
	// VULN: SSRF via string concatenation
	resp, _ := http.Get("http://internal-api/" + url)
	defer resp.Body.Close()
}

// =============================================================================
// 6. Hardcoded Secrets
// =============================================================================

const (
	// VULN: Hardcoded secrets
	dbPassword   = "SuperSecretP@ssw0rd!"
	apiToken     = "ghp_FAKE_TOKEN_TEST_GITHUB_TOKEN_FOR_TESTING_1234"
	jwtSecret    = "my-secret-jwt-key-very-weak"
	awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
)

var dbConnectionString = "postgres://admin:password123@localhost:5432/mydb"

func connectDB() {
	// VULN: Hardcoded password in connection string
	password := "ReallySecretDBPassword2024"
	db, _ := sql.Open("postgres", fmt.Sprintf("host=db password=%s", password))
	_ = db
}

// =============================================================================
// 7. Weak Cryptography
// =============================================================================

func hashPassword(password string) string {
	// VULN: MD5 is cryptographically broken
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

func hashData(data []byte) []byte {
	// VULN: SHA1 is deprecated
	hash := sha1.Sum(data)
	return hash[:]
}

// =============================================================================
// 8. Insecure Random
// =============================================================================

func generateToken() string {
	// VULN: math/rand is not cryptographically secure
	const letters = "abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, 32)
	for i := range result {
		result[i] = letters[rand.Intn(len(letters))]
	}
	return string(result)
}

func generateSessionID() string {
	// VULN: Predictable session ID
	return fmt.Sprintf("%d", rand.Int63())
}

// =============================================================================
// 9. Race Conditions
// =============================================================================

var counter int
var cache = make(map[string]string)

func incrementCounter() {
	// VULN: Race condition - no mutex
	for i := 0; i < 100; i++ {
		go func() {
			counter++
		}()
	}
}

func updateCache(items []string) {
	// VULN: Concurrent map access
	for _, item := range items {
		go func() {
			// VULN: Range variable captured by goroutine
			cache[item] = "processed"
		}()
	}
}

// =============================================================================
// 10. Resource Leaks
// =============================================================================

func fetchData(url string) ([]byte, error) {
	// VULN: Response body not closed
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	// Missing: defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func readConfig(path string) ([]byte, error) {
	// VULN: File handle not closed
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	// Missing: defer f.Close()
	return ioutil.ReadAll(f)
}

// =============================================================================
// 11. Error Handling
// =============================================================================

func processData(data []byte) {
	// VULN: Error ignored
	result, _ := json.Marshal(data)
	_ = result

	f, _ := os.Create("/tmp/output.txt")
	_ = f

	// VULN: Ignored Close error
	_ = f.Close()

	// VULN: panic in non-main function
	panic("something went wrong")
}

// =============================================================================
// 12. Integer Overflow
// =============================================================================

func convertSize(size int64) int32 {
	// VULN: Potential integer overflow
	return int32(size)
}

func truncatePort(port int) uint16 {
	// VULN: Integer truncation
	return uint16(port)
}

// =============================================================================
// 13. Nil Pointer Dereference
// =============================================================================

func processInterface(val interface{}) {
	// VULN: Unchecked type assertion
	str := val.(string)
	fmt.Println(str)
}

func unsafeMapAccess() {
	// VULN: Nil map
	var m map[string]int
	m["key"] = 42
}

// =============================================================================
// 14. Insecure TLS
// =============================================================================

func insecureHTTPClient() *http.Client {
	// VULN: TLS verification disabled
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	return &http.Client{Transport: tr}
}

// =============================================================================
// 15. CORS Misconfiguration
// =============================================================================

func corsHandler(w http.ResponseWriter, r *http.Request) {
	// VULN: Wildcard CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	fmt.Fprintf(w, "OK")
}

// =============================================================================
// 16. Missing Authentication
// =============================================================================

func adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	// VULN: No authentication check on admin endpoint
	userID := r.FormValue("id")
	fmt.Fprintf(w, "Deleted user: %s", userID)
}

func adminUpdateConfig(w http.ResponseWriter, r *http.Request) {
	// VULN: No auth check for config update
	body, _ := ioutil.ReadAll(r.Body)
	os.WriteFile("/etc/app/config.json", body, 0644)
}

// =============================================================================
// 17. Information Disclosure
// =============================================================================

func errorHandler(w http.ResponseWriter, r *http.Request) {
	err := fmt.Errorf("database connection failed: host=db.internal password=secret123")
	// VULN: Internal error details in HTTP response
	http.Error(w, err.Error(), http.StatusInternalServerError)

	// VULN: Stack trace exposure
	stack := debug.Stack()
	w.Write(stack)
}

// =============================================================================
// 18. Template Injection
// =============================================================================

func renderTemplate(w http.ResponseWriter, r *http.Request) {
	userTemplate := r.FormValue("template")
	// VULN: User-controlled template
	tmpl, _ := template.New("user").Parse(userTemplate)
	tmpl.Execute(w, nil)
}

// =============================================================================
// 19. Gin-specific
// =============================================================================

func ginSetup() {
	gin.SetMode(gin.DebugMode)
	r := gin.Default()
	r.SetTrustedProxies(nil)
}

func ginHandler(c *gin.Context) {
	var input map[string]interface{}
	c.BindJSON(&input)
}

// =============================================================================
// 20. Echo-specific
// =============================================================================

func setupEchoRoutes(e *echo.Echo) {
	// VULN: No CSRF middleware
	e.GET("/", func(c echo.Context) error {
		return c.String(200, "Hello")
	})
}

// =============================================================================
// 22. gRPC-specific
// =============================================================================

func grpcClient() {
	// VULN: Insecure gRPC connection
	conn, _ := grpc.Dial("localhost:50051", grpc.WithInsecure())
	_ = conn
}

func grpcServer() {
	// VULN: No interceptors
	s := grpc.NewServer()
	_ = s
}

// =============================================================================
// 23. Unsafe Package
// =============================================================================

func unsafeOperation() {
	var x int = 42
	// VULN: unsafe.Pointer usage
	p := unsafe.Pointer(&x)
	_ = p
}

// =============================================================================
// 24. Goroutine Leaks
// =============================================================================

func leakyGoroutine() {
	ch := make(chan int)
	go func() {
		for {
			// VULN: Infinite loop goroutine without context
			data := <-ch
			_ = data
		}
	}()
}

// =============================================================================
// 25. JWT Issues
// =============================================================================

func createJWT() string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": "admin",
	})
	// VULN: Weak JWT secret
	tokenString, _ := token.SignedString([]byte("weak"))
	return tokenString
}

// =============================================================================
// 26. Open Redirect
// =============================================================================

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("redirect_to")
	// VULN: Open redirect
	http.Redirect(w, r, target, http.StatusFound)
}

// =============================================================================
// 27. File Upload
// =============================================================================

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// VULN: File upload without validation
	file, header, _ := r.FormFile("upload")
	defer file.Close()
	dst, _ := os.Create("/uploads/" + header.Filename)
	defer dst.Close()
}

// =============================================================================
// 28. Logging Sensitive Data
// =============================================================================

func loginHandler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	token := r.FormValue("api_token")
	// VULN: Logging password
	log.Printf("Login attempt with password: %s", password)
	log.Printf("API token: %s", token)
}

// =============================================================================
// 29. Mass Assignment
// =============================================================================

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"isAdmin"`
	Password string `json:"password"`
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	body, _ := ioutil.ReadAll(r.Body)
	// VULN: Mass assignment - user can set IsAdmin
	json.Unmarshal(body, &user)
}

// =============================================================================
// 30. Timing Attack
// =============================================================================

func validateAPIKey(w http.ResponseWriter, r *http.Request) {
	providedKey := r.Header.Get("X-API-Key")
	expectedKey := os.Getenv("API_KEY")
	// VULN: Non-constant-time comparison
	if providedKey == expectedKey {
		w.WriteHeader(200)
	} else {
		w.WriteHeader(401)
	}
}

func verifyToken(userToken, serverToken string) bool {
	// VULN: timing attack via ==
	return userToken == serverToken
}

func verifyPassword(input, stored string) bool {
	// VULN: non-constant time comparison of password hash
	return strings.Compare(input, stored) == 0
}

func main() {
	http.HandleFunc("/user", getUserByName)
	http.HandleFunc("/ping", pingHost)
	http.HandleFunc("/file", serveFile)
	http.HandleFunc("/page", renderPage)
	http.HandleFunc("/proxy", proxyRequest)
	http.HandleFunc("/cors", corsHandler)
	http.HandleFunc("/admin/delete", adminDeleteUser)
	http.HandleFunc("/error", errorHandler)
	http.HandleFunc("/template", renderTemplate)
	http.HandleFunc("/redirect", redirectHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/user/create", createUser)
	http.HandleFunc("/validate", validateAPIKey)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
