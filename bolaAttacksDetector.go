package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Request struct {
	URL          string            `json:"url"`
	QueryParams  string            `json:"qs_params"`
	Headers      map[string]string `json:"headers"`
	ReqBodyLen   int               `json:"req_body_len"`
}

type Response struct {
	StatusClass   string `json:"status_class"`
	RspBodyLen    int    `json:"rsp_body_len"`
}

type LogEntry struct {
	Req Request  `json:"req"`
	Rsp Response `json:"rsp"`
}

func detectBolaAttacks(logFile string) {
	// Open the log file
	file, err := os.Open(logFile)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer file.Close()

	// Read and process the log file line by line
	var line string
	for {
		// Read a line from the log file
		_, err := fmt.Fscanln(file, &line)
		if err != nil {
			break // End of file reached
		}

		// Parse the log entry from JSON format
		var logEntry LogEntry
		err = json.Unmarshal([]byte(line), &logEntry)
		if err != nil {
			fmt.Println("Error parsing log entry:", err)
			continue
		}

		// Check for potential BOLA attack
		checkForBolaAttack(logEntry)
	}
}

func checkForBolaAttack(logEntry LogEntry) {
	// Extract the relevant details
	url := logEntry.Req.URL
	username := logEntry.Req.Headers["Username"] // Assuming the username is in the headers

	// Check if user is trying to access another user's resource
	if strings.Contains(url, "user_id") {
		// Extract the user_id from the request URL (/balance?user_id=123)
		urlParts := strings.Split(url, "?")
		if len(urlParts) > 1 {
			queryParams := urlParts[1]
			params := strings.Split(queryParams, "&")

			// Look for user_id parameter in the query string
			for _, param := range params {
				if strings.HasPrefix(param, "user_id=") {
					userID := strings.Split(param, "=")[1]
					// If the username doesn't match the user_id, it could be a BOLA attack
					if username != userID {
						// Log the potential BOLA attack
						fmt.Printf("Potential BOLA Attack detected. User '%s' tried to access user_id='%s'\n", username, userID)
					}
					break
				}
			}
		}
	}
}

func main() {
	// File name to be passed as an argument
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run bolaAttackDetector.go <access_log_file>")
		return
	}
	logFile := os.Args[1]

	// Detect BOLA attacks in the provided log file
	detectBolaAttacks(logFile)
}
