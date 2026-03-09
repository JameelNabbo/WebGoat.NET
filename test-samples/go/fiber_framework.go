package main

import (
	"database/sql"
	"os/exec"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

var fiberDb *sql.DB

// VULN: Fiber - SQL Injection via c.Query
func fiberSearchHandler(c *fiber.Ctx) error {
	q := c.Query("search")
	query := "SELECT * FROM products WHERE name = '" + q + "'"
	_, err := fiberDb.Exec(query)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"status": "ok"})
}

// VULN: Fiber - Command Injection via c.Params
func fiberExecHandler(c *fiber.Ctx) error {
	tool := c.Params("tool")
	cmd := exec.Command(tool)
	output, _ := cmd.Output()
	return c.Send(output)
}

// VULN: Fiber - SSRF via c.FormValue
func fiberFetchHandler(c *fiber.Ctx) error {
	url := c.FormValue("url")
	resp, err := http.Get(url)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "fetch failed"})
	}
	defer resp.Body.Close()
	return c.JSON(fiber.Map{"status": resp.StatusCode})
}

// VULN: Fiber - Path Traversal via c.Params
func fiberFileHandler(c *fiber.Ctx) error {
	file := c.Params("file")
	return c.SendFile("/uploads/" + file)
}

func main() {
	app := fiber.New()
	app.Get("/search", fiberSearchHandler)
	app.Get("/exec/:tool", fiberExecHandler)
	app.Post("/fetch", fiberFetchHandler)
	app.Get("/file/:file", fiberFileHandler)
	app.Listen(":8082")
}
