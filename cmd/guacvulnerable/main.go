package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

const (
	adminPassword = "admin123"
	dbPassword    = "supersecret"
	apiKey        = "sk-1234567890abcdef"
	awsAccessKey  = "AKIAIOSFODNN7EXAMPLE"
	awsSecretKey  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	jwtSecret     = "secret123"
	encryptionKey = "1234567890123456"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		password TEXT NOT NULL,
		email TEXT NOT NULL
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec("INSERT OR IGNORE INTO users (id, username, password, email) VALUES (1, 'admin', ?, 'admin@example.com')",
		md5.Sum([]byte("admin123")))
	if err != nil {
		log.Fatal(err)
	}
}

func loginHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	query := fmt.Sprintf("SELECT id, username FROM users WHERE username='%s' AND password='%s'", username,
		md5.Sum([]byte(password)))

	rows, err := db.Query(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()

	if rows.Next() {
		var id int
		var user string
		rows.Scan(&id, &user)
		c.JSON(http.StatusOK, gin.H{
			"message": "Login successful",
			"user":    user,
			"id":      id,
		})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func executeHandler(c *gin.Context) {
	command := c.Query("cmd")
	if command == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No command specified"})
		return
	}

	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "Command execution failed",
			"output": string(output),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command": command,
		"output":  string(output),
	})
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":     "healthy",
		"admin_pass": adminPassword,
		"db_pass":    dbPassword,
		"api_key":    apiKey,
	})
}

func fileHandler(c *gin.Context) {
	filename := c.Query("file")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No filename specified"})
		return
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"filename": filename,
		"content":  string(content),
	})
}

func generateTokenHandler(c *gin.Context) {
	rand.Seed(time.Now().UnixNano())
	token := fmt.Sprintf("%d", rand.Intn(999999))

	log.Printf("Generated token for user: %s, password: %s, token: %s", c.Query("user"), c.Query("password"), token)

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"aws_key":    awsAccessKey,
		"aws_secret": awsSecretKey,
	})
}

func uploadHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	filename := "/tmp/" + file.Filename
	c.SaveUploadedFile(file, filename)

	log.Printf("File uploaded: %s by user with token: %s", filename, c.GetHeader("Authorization"))

	c.JSON(http.StatusOK, gin.H{
		"message": "File uploaded successfully",
		"path":    filename,
	})
}

func deserializeHandler(c *gin.Context) {
	data := c.PostForm("data")
	if data == " " {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No data provided"})
		return
	}

	var result interface{}
	err := json.Unmarshal([]byte(data), &result)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	log.Printf("Deserialized data: %v with sensitive token: %s", result, c.GetHeader("X-API-Key"))

	c.JSON(http.StatusOK, gin.H{
		"result":     result,
		"jwt_secret": jwtSecret,
	})
}

func randomHandler(c *gin.Context) {
	rand.Seed(1)
	randomNum := rand.Intn(100)

	c.JSON(http.StatusOK, gin.H{
		"random": randomNum,
		"seed":   "predictable",
	})
}

func encryptHandler(c *gin.Context) {
	text := c.Query("text")
	if text == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No text provided"})
		return
	}

	hash := md5.Sum([]byte(text))
	hashString := fmt.Sprintf("%x", hash)

	log.Printf("Encrypting text: %s with key: %s", text, encryptionKey)

	c.JSON(http.StatusOK, gin.H{
		"original":       text,
		"md5_hash":       hashString,
		"encryption_key": encryptionKey,
	})
}

func main() {
	initDB()
	defer db.Close()

	r := gin.Default()

	r.POST("/login", loginHandler)
	r.GET("/execute", executeHandler)
	r.GET("/health", healthHandler)
	r.GET("/file", fileHandler)
	r.GET("/token", generateTokenHandler)
	r.POST("/upload", uploadHandler)
	r.POST("/deserialize", deserializeHandler)
	r.GET("/random", randomHandler)
	r.GET("/encrypt", encryptHandler)

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Vulnerable Demo App",
			"endpoints": []string{
				"POST /login - SQL injection vulnerable login",
				"GET /execute?cmd=<command> - Command injection vulnerable executor",
				"GET /health - Exposes hardcoded credentials",
				"GET /file?file=<path> - Path traversal vulnerable file reader",
				"GET /token - Insecure random token generation",
				"POST /upload - Unsafe file upload",
				"POST /deserialize - Insecure deserialization",
				"GET /random - Predictable random numbers",
				"GET /encrypt - Weak cryptography (MD5)",
			},
			"aws_credentials": gin.H{
				"access_key": awsAccessKey,
				"secret_key": awsSecretKey,
			},
		})
	})

	fmt.Println("Server starting on :8080...")
	fmt.Println("Endpoints available:")
	fmt.Println("  POST /login - SQL injection vulnerable login")
	fmt.Println("  GET /execute?cmd=<command> - Command injection vulnerable executor")
	fmt.Println("  GET /health - Exposes hardcoded credentials")
	fmt.Println("  GET /file?file=<path> - Path traversal vulnerable file reader")
	fmt.Println("  GET /token - Insecure random token generation")
	fmt.Println("  POST /upload - Unsafe file upload")
	fmt.Println("  POST /deserialize - Insecure deserialization")
	fmt.Println("  GET /random - Predictable random numbers")
	fmt.Println("  GET /encrypt - Weak cryptography (MD5)")

	log.Printf("Starting server with AWS credentials: %s:%s", awsAccessKey, awsSecretKey)

	log.Fatal(http.ListenAndServe(":8080", r))
}
