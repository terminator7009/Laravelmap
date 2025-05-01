package vulnerabilities

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// SchedulerVulnerabilitiesScanner is a struct that contains an HTTP client for detecting Laravel scheduler vulnerabilities
type SchedulerVulnerabilitiesScanner struct {
	client *httpclient.Client
}

// NewSchedulerVulnerabilitiesScanner initializes and returns a new SchedulerVulnerabilitiesScanner instance
func NewSchedulerVulnerabilitiesScanner() *SchedulerVulnerabilitiesScanner {
	return &SchedulerVulnerabilitiesScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for Laravel scheduler vulnerabilities
func (svs *SchedulerVulnerabilitiesScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Check for command injection in scheduled tasks
	commandInjectionResults := svs.checkCommandInjectionInScheduledTasks(target)
	results = append(results, commandInjectionResults...)

	// Check for privilege escalation via scheduler
	privilegeEscalationResults := svs.checkPrivilegeEscalationViaScheduler(target)
	results = append(results, privilegeEscalationResults...)

	// Check for scheduler configuration exposure
	configExposureResults := svs.checkSchedulerConfigurationExposure(target)
	results = append(results, configExposureResults...)

	// Check for insecure scheduler endpoints
	insecureEndpointResults := svs.checkInsecureSchedulerEndpoints(target)
	results = append(results, insecureEndpointResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    svs.Name(),
			Category:    "Vulnerabilities",
			Description: "No Laravel scheduler vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "No potential Laravel scheduler vulnerabilities were detected. However, this does not guarantee that the application is not vulnerable to scheduler-related attacks.",
		})
	}

	return results
}

// checkCommandInjectionInScheduledTasks checks for command injection vulnerabilities in scheduled tasks
func (svs *SchedulerVulnerabilitiesScanner) checkCommandInjectionInScheduledTasks(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find potential scheduler endpoints
	schedulerEndpoints := svs.findSchedulerEndpoints(target)

	// Prepare command injection payloads
	injectionPayloads := []struct {
		name  string
		value string
	}{
		{
			name:  "Basic Command Injection",
			value: `{"command":"ls -la"}`,
		},
		{
			name:  "Artisan Command Injection",
			value: `{"command":"env"}`,
		},
		{
			name:  "Shell Command Injection",
			value: `{"command":"system('id')"}`,
		},
		{
			name:  "Pipe Command Injection",
			value: `{"command":"echo hello | grep hello"}`,
		},
		{
			name:  "Semicolon Command Injection",
			value: `{"command":"echo hello; id"}`,
		},
	}

	// Test each endpoint with command injection payloads
	for _, endpoint := range schedulerEndpoints {
		for _, payload := range injectionPayloads {
			// Create the full URL
			fullURL := endpoint
			if !strings.HasPrefix(endpoint, "http") {
				parsedURL, parseErr := url.Parse(target)
				if parseErr != nil {
					continue
				}

				parsedURL.Path = endpoint
				fullURL = parsedURL.String()
			}

			// Send POST request with JSON payload
			headers := map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			}
			resp, err := svs.client.Post(fullURL, headers, strings.NewReader(payload.value))
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a successful command execution
			if svs.isSuccessfulCommandExecution(resp.StatusCode, bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    svs.Name(),
					Category:    "Vulnerabilities",
					Description: fmt.Sprintf("Potential Laravel scheduler command injection vulnerability (%s)", payload.name),
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The scheduler endpoint %s might be vulnerable to command injection. The application accepted a potentially malicious command payload that could lead to arbitrary command execution.", fullURL),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}
		}
	}

	return results
}

// findSchedulerEndpoints finds potential scheduler endpoints in the target application
func (svs *SchedulerVulnerabilitiesScanner) findSchedulerEndpoints(target string) []string {
	var endpoints []string

	// Common scheduler endpoints
	commonEndpoints := []string{
		"/schedule",
		"/scheduler",
		"/cron",
		"/artisan/schedule",
		"/artisan/scheduler",
		"/artisan/cron",
		"/api/schedule",
		"/api/scheduler",
		"/api/cron",
		"/admin/schedule",
		"/admin/scheduler",
		"/admin/cron",
		"/console/schedule",
		"/console/scheduler",
		"/console/cron",
		"/schedule/run",
		"/scheduler/run",
		"/cron/run",
	}

	// Add common endpoints
	endpoints = append(endpoints, commonEndpoints...)

	// Send a GET request to the target
	resp, err := svs.client.Get(target, nil)
	if err != nil {
		return endpoints
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return endpoints
	}
	bodyString := string(bodyBytes)

	// Extract potential scheduler endpoints from HTML
	schedulerPatterns := []string{
		`href=["']([^"']*(?:schedule|scheduler|cron)[^"']*)["']`,
		`action=["']([^"']*(?:schedule|scheduler|cron)[^"']*)["']`,
		`url:\s*["']([^"']*(?:schedule|scheduler|cron)[^"']*)["']`,
	}

	for _, pattern := range schedulerPatterns {
		schedulerRegex := regexp.MustCompile(pattern)
		schedulerMatches := schedulerRegex.FindAllStringSubmatch(bodyString, -1)

		for _, schedulerMatch := range schedulerMatches {
			if len(schedulerMatch) < 2 {
				continue
			}

			endpoint := schedulerMatch[1]
			if !strings.HasPrefix(endpoint, "http") && !strings.HasPrefix(endpoint, "/") {
				endpoint = "/" + endpoint
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	// Extract potential scheduler endpoints from JavaScript files
	jsPattern := `<script[^>]*src=["']([^"']*\.js)["'][^>]*>`
	jsRegex := regexp.MustCompile(jsPattern)
	jsMatches := jsRegex.FindAllStringSubmatch(bodyString, -1)

	for _, jsMatch := range jsMatches {
		if len(jsMatch) < 2 {
			continue
		}

		jsURL := jsMatch[1]
		if !strings.HasPrefix(jsURL, "http") {
			// Convert relative URL to absolute
			parsedURL, parseErr := url.Parse(target)
			if parseErr != nil {
				continue
			}

			if strings.HasPrefix(jsURL, "/") {
				// Absolute path
				parsedURL.Path = jsURL
			} else {
				// Relative path
				if !strings.HasSuffix(parsedURL.Path, "/") {
					parsedURL.Path += "/"
				}
				parsedURL.Path += jsURL
			}

			jsURL = parsedURL.String()
		}

		// Get the JavaScript file
		jsResp, jsErr := svs.client.Get(jsURL, nil)
		if jsErr != nil {
			continue
		}

		jsBodyBytes, jsErr := ioutil.ReadAll(jsResp.Body)
		jsResp.Body.Close()
		if jsErr != nil {
			continue
		}
		jsBodyString := string(jsBodyBytes)

		// Extract potential scheduler endpoints from JavaScript
		for _, pattern := range schedulerPatterns {
			schedulerRegex := regexp.MustCompile(pattern)
			schedulerMatches := schedulerRegex.FindAllStringSubmatch(jsBodyString, -1)

			for _, schedulerMatch := range schedulerMatches {
				if len(schedulerMatch) < 2 {
					continue
				}

				endpoint := schedulerMatch[1]
				if !strings.HasPrefix(endpoint, "http") && !strings.HasPrefix(endpoint, "/") {
					endpoint = "/" + endpoint
				}

				endpoints = append(endpoints, endpoint)
			}
		}
	}

	return endpoints
}

// isSuccessfulCommandExecution checks if the response indicates a successful command execution
func (svs *SchedulerVulnerabilitiesScanner) isSuccessfulCommandExecution(statusCode int, body string) bool {
	// Check for 200 status code
	if statusCode != 200 {
		return false
	}

	// Check for common success patterns
	successPatterns := []string{
		"success",
		"executed",
		"scheduled",
		"command",
		"task",
		"job",
		"output",
		"result",
		"\"status\":\"success\"",
		"\"status\":\"ok\"",
		"\"success\":true",
		"\"executed\":true",
		"\"scheduled\":true",
	}

	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			return true
		}
	}

	// Check if the response is a JSON object with success indicators
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonResponse); err == nil {
		// Check for success status
		if status, ok := jsonResponse["status"]; ok {
			if statusStr, ok := status.(string); ok {
				if statusStr == "success" || statusStr == "ok" {
					return true
				}
			}
		}

		// Check for success boolean
		if success, ok := jsonResponse["success"]; ok {
			if successBool, ok := success.(bool); ok {
				if successBool {
					return true
				}
			}
		}

		// Check for executed boolean
		if executed, ok := jsonResponse["executed"]; ok {
			if executedBool, ok := executed.(bool); ok {
				if executedBool {
					return true
				}
			}
		}

		// Check for scheduled boolean
		if scheduled, ok := jsonResponse["scheduled"]; ok {
			if scheduledBool, ok := scheduled.(bool); ok {
				if scheduledBool {
					return true
				}
			}
		}

		// Check for output field
		if _, ok := jsonResponse["output"]; ok {
			return true
		}

		// Check for result field
		if _, ok := jsonResponse["result"]; ok {
			return true
		}
	}

	return false
}

// checkPrivilegeEscalationViaScheduler checks for privilege escalation vulnerabilities via scheduler
func (svs *SchedulerVulnerabilitiesScanner) checkPrivilegeEscalationViaScheduler(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find potential scheduler task creation endpoints
	taskCreationEndpoints := svs.findTaskCreationEndpoints(target)

	// Prepare privilege escalation payloads
	escalationPayloads := []struct {
		name  string
		value string
	}{
		{
			name:  "User Role Escalation",
			value: `{"task":"App\\Console\\Commands\\UpdateUserRole","parameters":{"user_id":1,"role":"admin"}}`,
		},
		{
			name:  "Create Admin User",
			value: `{"task":"App\\Console\\Commands\\CreateUser","parameters":{"name":"hacker","email":"hacker@example.com","password":"password123","role":"admin"}}`,
		},
		{
			name:  "File Write Access",
			value: `{"task":"Illuminate\\Support\\Facades\\File::put","parameters":["/var/www/html/public/test.php","<?php echo 'Hacked!'; ?>"]}`,
		},
		{
			name:  "Database Modification",
			value: `{"task":"DB::statement","parameters":["UPDATE users SET is_admin = 1 WHERE id = 1"]}`,
		},
	}

	// Test each endpoint with privilege escalation payloads
	for _, endpoint := range taskCreationEndpoints {
		for _, payload := range escalationPayloads {
			// Create the full URL
			fullURL := endpoint
			if !strings.HasPrefix(endpoint, "http") {
				parsedURL, parseErr := url.Parse(target)
				if parseErr != nil {
					continue
				}

				parsedURL.Path = endpoint
				fullURL = parsedURL.String()
			}

			// Send POST request with JSON payload
			headers := map[string]string{
				"Content-Type": "application/json",
				"Accept":       "application/json",
			}
			resp, err := svs.client.Post(fullURL, headers, strings.NewReader(payload.value))
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a successful task creation
			if svs.isSuccessfulTaskCreation(resp.StatusCode, bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    svs.Name(),
					Category:    "Vulnerabilities",
					Description: fmt.Sprintf("Potential Laravel scheduler privilege escalation vulnerability (%s)", payload.name),
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The scheduler endpoint %s might be vulnerable to privilege escalation. The application accepted a potentially malicious task payload that could lead to unauthorized privilege escalation.", fullURL),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}
		}
	}

	return results
}

// findTaskCreationEndpoints finds potential scheduler task creation endpoints in the target application
func (svs *SchedulerVulnerabilitiesScanner) findTaskCreationEndpoints(target string) []string {
	var endpoints []string

	// Common task creation endpoints
	commonEndpoints := []string{
		"/schedule/create",
		"/scheduler/create",
		"/cron/create",
		"/schedule/add",
		"/scheduler/add",
		"/cron/add",
		"/api/schedule/create",
		"/api/scheduler/create",
		"/api/cron/create",
		"/api/schedule/add",
		"/api/scheduler/add",
		"/api/cron/add",
		"/admin/schedule/create",
		"/admin/scheduler/create",
		"/admin/cron/create",
		"/admin/schedule/add",
		"/admin/scheduler/add",
		"/admin/cron/add",
	}

	// Add common endpoints
	endpoints = append(endpoints, commonEndpoints...)

	// Send a GET request to the target
	resp, err := svs.client.Get(target, nil)
	if err != nil {
		return endpoints
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return endpoints
	}
	bodyString := string(bodyBytes)

	// Extract potential task creation endpoints from HTML
	taskCreationPatterns := []string{
		`href=["']([^"']*(?:schedule|scheduler|cron)(?:/|/api/|/admin/)(?:create|add)[^"']*)["']`,
		`action=["']([^"']*(?:schedule|scheduler|cron)(?:/|/api/|/admin/)(?:create|add)[^"']*)["']`,
		`url:\s*["']([^"']*(?:schedule|scheduler|cron)(?:/|/api/|/admin/)(?:create|add)[^"']*)["']`,
	}

	for _, pattern := range taskCreationPatterns {
		taskCreationRegex := regexp.MustCompile(pattern)
		taskCreationMatches := taskCreationRegex.FindAllStringSubmatch(bodyString, -1)

		for _, taskCreationMatch := range taskCreationMatches {
			if len(taskCreationMatch) < 2 {
				continue
			}

			endpoint := taskCreationMatch[1]
			if !strings.HasPrefix(endpoint, "http") && !strings.HasPrefix(endpoint, "/") {
				endpoint = "/" + endpoint
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// isSuccessfulTaskCreation checks if the response indicates a successful task creation
func (svs *SchedulerVulnerabilitiesScanner) isSuccessfulTaskCreation(statusCode int, body string) bool {
	// Check for 200 or 201 status code
	if statusCode != 200 && statusCode != 201 {
		return false
	}

	// Check for common success patterns
	successPatterns := []string{
		"created",
		"added",
		"scheduled",
		"task",
		"job",
		"\"status\":\"success\"",
		"\"status\":\"ok\"",
		"\"success\":true",
		"\"created\":true",
		"\"added\":true",
		"\"scheduled\":true",
	}

	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			return true
		}
	}

	// Check if the response is a JSON object with success indicators
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonResponse); err == nil {
		// Check for success status
		if status, ok := jsonResponse["status"]; ok {
			if statusStr, ok := status.(string); ok {
				if statusStr == "success" || statusStr == "ok" {
					return true
				}
			}
		}

		// Check for success boolean
		if success, ok := jsonResponse["success"]; ok {
			if successBool, ok := success.(bool); ok {
				if successBool {
					return true
				}
			}
		}

		// Check for created boolean
		if created, ok := jsonResponse["created"]; ok {
			if createdBool, ok := created.(bool); ok {
				if createdBool {
					return true
				}
			}
		}

		// Check for added boolean
		if added, ok := jsonResponse["added"]; ok {
			if addedBool, ok := added.(bool); ok {
				if addedBool {
					return true
				}
			}
		}

		// Check for scheduled boolean
		if scheduled, ok := jsonResponse["scheduled"]; ok {
			if scheduledBool, ok := scheduled.(bool); ok {
				if scheduledBool {
					return true
				}
			}
		}

		// Check for task ID
		if _, ok := jsonResponse["task_id"]; ok {
			return true
		}

		// Check for job ID
		if _, ok := jsonResponse["job_id"]; ok {
			return true
		}
	}

	return false
}

// checkSchedulerConfigurationExposure checks for scheduler configuration exposure
func (svs *SchedulerVulnerabilitiesScanner) checkSchedulerConfigurationExposure(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common paths that might expose scheduler configuration
	configPaths := []string{
		"/app/Console/Kernel.php",
		"/storage/logs/laravel.log",
		"/storage/logs/scheduler.log",
		"/storage/logs/cron.log",
		"/.env",
	}

	for _, path := range configPaths {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = path
		fullURL := parsedURL.String()

		// Send GET request
		resp, err := svs.client.Get(fullURL, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response contains scheduler configuration information
		if resp.StatusCode == 200 && svs.containsSchedulerConfig(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    svs.Name(),
				Category:    "Vulnerabilities",
				Description: "Laravel scheduler configuration exposure",
				Path:        fullURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The application exposes scheduler configuration at %s. This could reveal sensitive information about scheduled tasks, commands, and their execution parameters, which could be used to identify potential attack vectors.", fullURL),
			})
		}
	}

	return results
}

// containsSchedulerConfig checks if the response contains scheduler configuration information
func (svs *SchedulerVulnerabilitiesScanner) containsSchedulerConfig(response string) bool {
	schedulerConfigPatterns := []string{
		"$schedule->",
		"->command(",
		"->exec(",
		"->call(",
		"->job(",
		"->cron(",
		"->daily(",
		"->hourly(",
		"->weekly(",
		"->monthly(",
		"->yearly(",
		"->everyMinute(",
		"->everyFiveMinutes(",
		"->everyTenMinutes(",
		"->everyFifteenMinutes(",
		"->everyThirtyMinutes(",
		"->environments(",
		"->withoutOverlapping(",
		"->onOneServer(",
		"->emailOutputTo(",
		"->sendOutputTo(",
		"->appendOutputTo(",
		"protected function schedule(",
		"Running scheduled command:",
	}

	for _, pattern := range schedulerConfigPatterns {
		if strings.Contains(response, pattern) {
			return true
		}
	}

	return false
}

// checkInsecureSchedulerEndpoints checks for insecure scheduler endpoints
func (svs *SchedulerVulnerabilitiesScanner) checkInsecureSchedulerEndpoints(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common scheduler run endpoints
	runEndpoints := []string{
		"/schedule/run",
		"/scheduler/run",
		"/cron/run",
		"/artisan/schedule/run",
		"/artisan/scheduler/run",
		"/artisan/cron/run",
		"/api/schedule/run",
		"/api/scheduler/run",
		"/api/cron/run",
	}

	// Test each run endpoint
	for _, endpoint := range runEndpoints {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = endpoint
		fullURL := parsedURL.String()

		// Send GET request
		resp, err := svs.client.Get(fullURL, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response indicates a successful scheduler run
		if svs.isSuccessfulSchedulerRun(resp.StatusCode, bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    svs.Name(),
				Category:    "Vulnerabilities",
				Description: "Insecure Laravel scheduler run endpoint",
				Path:        fullURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The scheduler run endpoint %s is accessible without proper authentication. This could allow unauthorized users to trigger scheduled tasks, potentially leading to unauthorized actions or denial of service.", fullURL),
			})
		}
	}

	return results
}

// isSuccessfulSchedulerRun checks if the response indicates a successful scheduler run
func (svs *SchedulerVulnerabilitiesScanner) isSuccessfulSchedulerRun(statusCode int, body string) bool {
	// Check for 200 status code
	if statusCode != 200 {
		return false
	}

	// Check for common success patterns
	successPatterns := []string{
		"running",
		"executed",
		"scheduled",
		"task",
		"job",
		"command",
		"Running scheduled command",
		"Schedule run completed",
		"Scheduler run completed",
		"Cron run completed",
		"\"status\":\"success\"",
		"\"status\":\"ok\"",
		"\"success\":true",
		"\"executed\":true",
		"\"scheduled\":true",
	}

	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			return true
		}
	}

	// Check if the response is a JSON object with success indicators
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonResponse); err == nil {
		// Check for success status
		if status, ok := jsonResponse["status"]; ok {
			if statusStr, ok := status.(string); ok {
				if statusStr == "success" || statusStr == "ok" {
					return true
				}
			}
		}

		// Check for success boolean
		if success, ok := jsonResponse["success"]; ok {
			if successBool, ok := success.(bool); ok {
				if successBool {
					return true
				}
			}
		}

		// Check for executed boolean
		if executed, ok := jsonResponse["executed"]; ok {
			if executedBool, ok := executed.(bool); ok {
				if executedBool {
					return true
				}
			}
		}

		// Check for scheduled boolean
		if scheduled, ok := jsonResponse["scheduled"]; ok {
			if scheduledBool, ok := scheduled.(bool); ok {
				if scheduledBool {
					return true
				}
			}
		}

		// Check for tasks array
		if tasks, ok := jsonResponse["tasks"]; ok {
			if tasksArray, ok := tasks.([]interface{}); ok {
				if len(tasksArray) > 0 {
					return true
				}
			}
		}

		// Check for jobs array
		if jobs, ok := jsonResponse["jobs"]; ok {
			if jobsArray, ok := jobs.([]interface{}); ok {
				if len(jobsArray) > 0 {
					return true
				}
			}
		}
	}

	return false
}

// Name returns the name of the scanner
func (svs *SchedulerVulnerabilitiesScanner) Name() string {
	return "Laravel Scheduler Vulnerabilities Scanner"
}
