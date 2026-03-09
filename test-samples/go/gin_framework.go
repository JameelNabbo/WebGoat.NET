package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

var db *sql.DB

// VULN: Gin - SQL Injection via c.Query
func ginSearchHandler(c *gin.Context) {
	search := c.Query("q")
	query := "SELECT * FROM products WHERE name = '" + search + "'"
	rows, err := db.Query(query)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	c.JSON(200, gin.H{"results": "ok"})
}

// VULN: Gin - Command Injection via c.Param
func ginExecHandler(c *gin.Context) {
	tool := c.Param("tool")
	cmd := exec.Command(tool, "--version")
	output, _ := cmd.Output()
	c.String(200, string(output))
}

// VULN: Gin - XSS via c.DefaultQuery written to response
func ginHelloHandler(c *gin.Context) {
	name := c.DefaultQuery("name", "World")
	c.Writer.WriteString("<h1>Hello " + name + "</h1>")
}

// VULN: Gin - SSRF via c.PostForm
func ginProxyHandler(c *gin.Context) {
	targetURL := c.PostForm("url")
	resp, err := http.Get(targetURL)
	if err != nil {
		c.JSON(500, gin.H{"error": "fetch failed"})
		return
	}
	defer resp.Body.Close()
	c.JSON(200, gin.H{"status": resp.StatusCode})
}

// VULN: Gin - Path Traversal via c.Param
func ginDownloadHandler(c *gin.Context) {
	filename := c.Param("filename")
	c.File("/uploads/" + filename)
}

// VULN: Gin - Debug mode enabled
func setupRouter() *gin.Engine {
	gin.SetMode(gin.DebugMode)
	r := gin.Default()
	return r
}

func main() {
	r := setupRouter()
	r.GET("/search", ginSearchHandler)
	fmt.Println("Server starting")
	r.Run(":8080")
}
