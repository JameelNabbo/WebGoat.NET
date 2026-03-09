package main

import (
	"database/sql"
	"net/http"
	"os"
	"os/exec"

	"github.com/labstack/echo/v4"
)

var echoDb *sql.DB

// VULN: Echo - SQL Injection via c.QueryParam
func echoSearchHandler(c echo.Context) error {
	search := c.QueryParam("q")
	query := "SELECT * FROM items WHERE name LIKE '" + search + "%'"
	rows, err := echoDb.Query(query)
	if err != nil {
		return c.JSON(500, map[string]string{"error": err.Error()})
	}
	defer rows.Close()
	return c.JSON(200, map[string]string{"status": "ok"})
}

// VULN: Echo - Command Injection via c.FormValue
func echoRunHandler(c echo.Context) error {
	command := c.FormValue("cmd")
	cmd := exec.Command("sh", "-c", command)
	output, _ := cmd.Output()
	return c.String(200, string(output))
}

// VULN: Echo - Path Traversal via c.Param
func echoFileHandler(c echo.Context) error {
	filename := c.Param("file")
	data, err := os.ReadFile("/data/" + filename)
	if err != nil {
		return c.JSON(404, map[string]string{"error": "not found"})
	}
	return c.Blob(200, "application/octet-stream", data)
}

// VULN: Echo - SSRF via c.QueryParam
func echoProxyHandler(c echo.Context) error {
	url := c.QueryParam("url")
	resp, err := http.Get(url)
	if err != nil {
		return c.JSON(500, map[string]string{"error": "fetch failed"})
	}
	defer resp.Body.Close()
	return c.JSON(200, map[string]string{"status": "proxied"})
}

func main() {
	e := echo.New()
	e.GET("/search", echoSearchHandler)
	e.POST("/run", echoRunHandler)
	e.GET("/file/:file", echoFileHandler)
	e.GET("/proxy", echoProxyHandler)
	e.Start(":8081")
}
