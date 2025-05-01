package vulnerabilities

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// BroadcastingVulnerabilitiesScanner is a struct that contains an HTTP client for detecting Laravel broadcasting vulnerabilities
type BroadcastingVulnerabilitiesScanner struct {
	client *httpclient.Client
}

// NewBroadcastingVulnerabilitiesScanner initializes and returns a new BroadcastingVulnerabilitiesScanner instance
func NewBroadcastingVulnerabilitiesScanner() *BroadcastingVulnerabilitiesScanner {
	return &BroadcastingVulnerabilitiesScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for Laravel broadcasting vulnerabilities
func (bvs *BroadcastingVulnerabilitiesScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Check for WebSocket security vulnerabilities
	websocketResults := bvs.checkWebSocketSecurity(target)
	results = append(results, websocketResults...)

	// Check for channel authorization bypass vulnerabilities
	channelResults := bvs.checkChannelAuthorizationBypass(target)
	results = append(results, channelResults...)

	// Check for broadcasting configuration exposure
	configResults := bvs.checkBroadcastingConfigExposure(target)
	results = append(results, configResults...)

	// Check for broadcasting event injection vulnerabilities
	injectionResults := bvs.checkBroadcastingEventInjection(target)
	results = append(results, injectionResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    bvs.Name(),
			Category:    "Vulnerabilities",
			Description: "No Laravel broadcasting vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "No potential Laravel broadcasting vulnerabilities were detected. However, this does not guarantee that the application is not vulnerable to broadcasting-related attacks.",
		})
	}

	return results
}

// checkWebSocketSecurity checks for WebSocket security vulnerabilities
func (bvs *BroadcastingVulnerabilitiesScanner) checkWebSocketSecurity(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common WebSocket endpoints
	websocketEndpoints := []string{
		"/socket.io",
		"/laravel-websockets",
		"/ws",
		"/websocket",
		"/echo",
		"/pusher",
		"/broadcasting/socket",
	}

	// Test each WebSocket endpoint
	for _, endpoint := range websocketEndpoints {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = endpoint
		fullURL := parsedURL.String()

		// Send GET request
		resp, err := bvs.client.Get(fullURL, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response indicates a WebSocket server
		if bvs.isWebSocketServer(resp, bodyString) {
			// Check for CORS misconfiguration
			corsHeaders := resp.Header.Get("Access-Control-Allow-Origin")
			if corsHeaders == "*" {
				results = append(results, common.ScanResult{
					ScanName:    bvs.Name(),
					Category:    "Vulnerabilities",
					Description: "Laravel WebSocket CORS misconfiguration",
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The WebSocket endpoint %s has a CORS misconfiguration (Access-Control-Allow-Origin: *). This could allow unauthorized websites to connect to the WebSocket server and potentially access sensitive information or perform actions on behalf of the user.", fullURL),
				})
			}

			// Check for lack of authentication
			if !bvs.requiresAuthentication(resp, bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    bvs.Name(),
					Category:    "Vulnerabilities",
					Description: "Laravel WebSocket missing authentication",
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The WebSocket endpoint %s does not appear to require authentication. This could allow unauthorized users to connect to the WebSocket server and potentially access sensitive information or perform unauthorized actions.", fullURL),
				})
			}

			// Check for information disclosure
			if bvs.containsWebSocketInfo(bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    bvs.Name(),
					Category:    "Vulnerabilities",
					Description: "Laravel WebSocket information disclosure",
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The WebSocket endpoint %s exposes information about the WebSocket server configuration. This could help attackers understand the broadcasting infrastructure and potentially find additional vulnerabilities.", fullURL),
				})
			}
		}
	}

	return results
}

// isWebSocketServer checks if the response indicates a WebSocket server
func (bvs *BroadcastingVulnerabilitiesScanner) isWebSocketServer(resp *http.Response, body string) bool {
	// Check for WebSocket upgrade header
	if resp.Header.Get("Upgrade") == "websocket" {
		return true
	}

	// Check for common WebSocket server response patterns
	websocketPatterns := []string{
		"websocket",
		"socket.io",
		"laravel-websockets",
		"pusher",
		"echo",
		"connection",
		"transport",
		"polling",
		"engine.io",
		"sid",
		"upgrades",
		"pingInterval",
		"pingTimeout",
	}

	for _, pattern := range websocketPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			return true
		}
	}

	// Check for Socket.IO handshake response
	if strings.HasPrefix(body, "97:0") || strings.HasPrefix(body, "0{") {
		return true
	}

	// Check for JSON response with WebSocket information
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonResponse); err == nil {
		// Check for Socket.IO fields
		if _, ok := jsonResponse["sid"]; ok {
			return true
		}
		if _, ok := jsonResponse["upgrades"]; ok {
			return true
		}
		if _, ok := jsonResponse["pingInterval"]; ok {
			return true
		}
		if _, ok := jsonResponse["pingTimeout"]; ok {
			return true
		}

		// Check for Laravel WebSockets fields
		if _, ok := jsonResponse["websocket"]; ok {
			return true
		}
		if _, ok := jsonResponse["socket"]; ok {
			return true
		}
	}

	return false
}

// requiresAuthentication checks if the WebSocket server requires authentication
func (bvs *BroadcastingVulnerabilitiesScanner) requiresAuthentication(resp *http.Response, body string) bool {
	// Check for authentication error messages
	authPatterns := []string{
		"unauthorized",
		"authentication required",
		"not authenticated",
		"invalid token",
		"invalid key",
		"invalid signature",
		"invalid auth",
		"auth_key",
		"auth_signature",
		"auth_timestamp",
		"auth_version",
		"403",
		"forbidden",
	}

	for _, pattern := range authPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			return true
		}
	}

	// Check for 401 or 403 status code
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}

	// Check for JSON response with error information
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonResponse); err == nil {
		// Check for error field
		if errorVal, ok := jsonResponse["error"]; ok {
			if errorStr, ok := errorVal.(string); ok {
				for _, pattern := range authPatterns {
					if strings.Contains(strings.ToLower(errorStr), strings.ToLower(pattern)) {
						return true
					}
				}
			}
		}
	}

	return false
}

// containsWebSocketInfo checks if the response contains WebSocket information
func (bvs *BroadcastingVulnerabilitiesScanner) containsWebSocketInfo(body string) bool {
	infoPatterns := []string{
		"app_key",
		"app_id",
		"key:",
		"cluster:",
		"host:",
		"port:",
		"encrypted:",
		"scheme:",
		"path:",
		"pusher:",
		"socket.io:",
		"laravel-websockets:",
		"broadcasting:",
		"connection:",
		"driver:",
	}

	for _, pattern := range infoPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// checkChannelAuthorizationBypass checks for channel authorization bypass vulnerabilities
func (bvs *BroadcastingVulnerabilitiesScanner) checkChannelAuthorizationBypass(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common broadcasting auth endpoints
	authEndpoints := []string{
		"/broadcasting/auth",
		"/broadcast/auth",
		"/socket.io/auth",
		"/pusher/auth",
		"/laravel-websockets/auth",
		"/api/broadcasting/auth",
	}

	// Prepare channel authorization payloads
	channelPayloads := []struct {
		name     string
		channel  string
		socketId string
	}{
		{
			name:     "Private Admin Channel",
			channel:  "private-admin",
			socketId: "42.1234",
		},
		{
			name:     "Presence Admin Channel",
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
		{
			name:     "Private Dashboard Channel",
			channel:  "private-dashboard",
			socketId: "42.7890",
		},
	}

	// Test each auth endpoint
	for _, endpoint := range authEndpoints {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = endpoint
		fullURL := parsedURL.String()

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
			resp, err := bvs.client.Post(fullURL, headers, strings.NewReader(formData.Encode()))
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
			if bvs.isSuccessfulAuthorization(resp.StatusCode, bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    bvs.Name(),
					Category:    "Vulnerabilities",
					Description: fmt.Sprintf("Potential Laravel broadcasting channel authorization bypass (%s)", payload.name),
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The broadcasting auth endpoint %s might be vulnerable to channel authorization bypass. The application authorized access to the channel '%s' without proper authentication, which could allow unauthorized users to access private or presence channels.", fullURL, payload.channel),
				})

				// Break the loop to avoid duplicate results
				break
			}
		}
	}

	return results
}

// isSuccessfulAuthorization checks if the response indicates a successful channel authorization
func (bvs *BroadcastingVulnerabilitiesScanner) isSuccessfulAuthorization(statusCode int, body string) bool {
	// Check for 200 status code
	if statusCode != 200 {
		return false
	}

	// Check for common success patterns
	successPatterns := []string{
		"auth",
		"channel_data",
		"signature",
		"\"auth\":",
		"\"channel_data\":",
	}

	for _, pattern := range successPatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	// Check if the response is a JSON object with auth data
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonResponse); err == nil {
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

// checkBroadcastingConfigExposure checks for broadcasting configuration exposure
func (bvs *BroadcastingVulnerabilitiesScanner) checkBroadcastingConfigExposure(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common paths that might expose broadcasting configuration
	configPaths := []string{
		"/config/broadcasting.php",
		"/app/config/broadcasting.php",
		"/js/app.js",
		"/js/bootstrap.js",
		"/storage/logs/laravel.log",
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
		resp, err := bvs.client.Get(fullURL, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response contains broadcasting configuration information
		if resp.StatusCode == 200 && bvs.containsBroadcastingConfig(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    bvs.Name(),
				Category:    "Vulnerabilities",
				Description: "Laravel broadcasting configuration exposure",
				Path:        fullURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The application exposes broadcasting configuration at %s. This could reveal sensitive information such as Pusher credentials, Socket.IO configuration, or other broadcasting settings that could be used to gain unauthorized access to real-time communication channels.", fullURL),
			})
		}
	}

	// Also check for broadcasting config in HTML source
	resp, err := bvs.client.Get(target, nil)
	if err == nil {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil {
			bodyString := string(bodyBytes)

			// Check if the HTML source contains broadcasting configuration
			if bvs.containsBroadcastingConfig(bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    bvs.Name(),
					Category:    "Vulnerabilities",
					Description: "Laravel broadcasting configuration in HTML source",
					Path:        target,
					StatusCode:  resp.StatusCode,
					Detail:      "The application exposes broadcasting configuration in its HTML source. This could reveal sensitive information such as Pusher credentials, Socket.IO configuration, or other broadcasting settings that could be used to gain unauthorized access to real-time communication channels.",
				})
			}
		}
	}

	return results
}

// containsBroadcastingConfig checks if the response contains broadcasting configuration information
func (bvs *BroadcastingVulnerabilitiesScanner) containsBroadcastingConfig(response string) bool {
	broadcastingConfigPatterns := []string{
		"PUSHER_APP_ID",
		"PUSHER_APP_KEY",
		"PUSHER_APP_SECRET",
		"PUSHER_APP_CLUSTER",
		"BROADCAST_DRIVER",
		"window.Echo",
		"Echo.channel",
		"Echo.private",
		"Echo.presence",
		"pusher:",
		"key:",
		"cluster:",
		"encrypted:",
		"host:",
		"port:",
		"app_id:",
		"app_key:",
		"app_secret:",
		"connection => pusher",
		"connection => redis",
		"connection => log",
		"driver => pusher",
		"driver => redis",
		"driver => log",
		"'driver' => 'pusher'",
		"'driver' => 'redis'",
		"'driver' => 'log'",
		"Pusher.logToConsole",
		"socketId",
		"socket_id",
		"channel_name",
		"authEndpoint",
		"auth_endpoint",
	}

	for _, pattern := range broadcastingConfigPatterns {
		if strings.Contains(response, pattern) {
			return true
		}
	}

	return false
}

// checkBroadcastingEventInjection checks for broadcasting event injection vulnerabilities
func (bvs *BroadcastingVulnerabilitiesScanner) checkBroadcastingEventInjection(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find potential event dispatch endpoints
	eventEndpoints := bvs.findEventEndpoints(target)

	// Prepare event injection payloads
	injectionPayloads := []struct {
		name  string
		value string
	}{
		{
			name:  "Channel Override",
			value: `{"channel":"private-admin","event":"App\\Events\\AdminNotification","data":{"message":"Test"}}`,
		},
		{
			name:  "Event Name Injection",
			value: `{"channel":"public","event":"App\\Events\\SystemCommand","data":{"command":"id"}}`,
		},
		{
			name:  "Presence Channel Data Injection",
			value: `{"channel":"presence-chat","event":"client-message","data":{"user_id":1,"admin":true,"message":"Test"}}`,
		},
		{
			name:  "Client Event Spoofing",
			value: `{"channel":"private-chat.1","event":"client-message","data":{"from_user_id":999,"message":"Test"}}`,
		},
	}

	// Test each endpoint with event injection payloads
	for _, endpoint := range eventEndpoints {
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
			resp, err := bvs.client.Post(fullURL, headers, strings.NewReader(payload.value))
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a successful event broadcast
			if bvs.isSuccessfulBroadcast(resp.StatusCode, bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    bvs.Name(),
					Category:    "Vulnerabilities",
					Description: fmt.Sprintf("Potential Laravel broadcasting event injection vulnerability (%s)", payload.name),
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The endpoint %s might be vulnerable to broadcasting event injection. The application accepted a potentially malicious event payload that could be broadcast to unauthorized channels or with spoofed data.", fullURL),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}
		}
	}

	return results
}

// findEventEndpoints finds potential event endpoints in the target application
func (bvs *BroadcastingVulnerabilitiesScanner) findEventEndpoints(target string) []string {
	var endpoints []string

	// Common event endpoints
	commonEndpoints := []string{
		"/events/dispatch",
		"/event/dispatch",
		"/api/events/dispatch",
		"/api/event/dispatch",
		"/broadcast",
		"/broadcasting",
		"/api/broadcast",
		"/api/broadcasting",
		"/pusher/events",
		"/socket.io/events",
	}

	// Add common endpoints
	endpoints = append(endpoints, commonEndpoints...)

	// Send a GET request to the target
	resp, err := bvs.client.Get(target, nil)
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
		jsResp, jsErr := bvs.client.Get(jsURL, nil)
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

// isSuccessfulBroadcast checks if the response indicates a successful event broadcast
func (bvs *BroadcastingVulnerabilitiesScanner) isSuccessfulBroadcast(statusCode int, body string) bool {
	// Check for 200 status code
	if statusCode != 200 {
		return false
	}

	// Check for common success patterns
	successPatterns := []string{
		"broadcast",
		"broadcasted",
		"event",
		"dispatched",
		"sent",
		"success",
		"\"status\":\"success\"",
		"\"status\":\"ok\"",
		"\"success\":true",
		"\"event_id\":",
		"\"channel\":",
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

		// Check for event ID
		if _, ok := jsonResponse["event_id"]; ok {
			return true
		}

		// Check for channel
		if _, ok := jsonResponse["channel"]; ok {
			return true
		}
	}

	return false
}

// Name returns the name of the scanner
func (bvs *BroadcastingVulnerabilitiesScanner) Name() string {
	return "Laravel Broadcasting Vulnerabilities Scanner"
}
