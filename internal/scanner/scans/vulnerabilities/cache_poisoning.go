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

// CachePoisoningScanner is a struct that contains an HTTP client for detecting Laravel cache poisoning vulnerabilities
type CachePoisoningScanner struct {
	client *httpclient.Client
}

// NewCachePoisoningScanner initializes and returns a new CachePoisoningScanner instance
func NewCachePoisoningScanner() *CachePoisoningScanner {
	return &CachePoisoningScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for Laravel cache poisoning vulnerabilities
func (cps *CachePoisoningScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Check for cache key manipulation vulnerabilities
	keyManipulationResults := cps.checkCacheKeyManipulation(target)
	results = append(results, keyManipulationResults...)

	// Check for cache data injection vulnerabilities
	dataInjectionResults := cps.checkCacheDataInjection(target)
	results = append(results, dataInjectionResults...)

	// Check for cache configuration exposure
	configExposureResults := cps.checkCacheConfigurationExposure(target)
	results = append(results, configExposureResults...)

	// Check for insecure cache endpoints
	insecureEndpointResults := cps.checkInsecureCacheEndpoints(target)
	results = append(results, insecureEndpointResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    cps.Name(),
			Category:    "Vulnerabilities",
			Description: "No Laravel cache poisoning vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "No potential Laravel cache poisoning vulnerabilities were detected. However, this does not guarantee that the application is not vulnerable to cache-related attacks.",
		})
	}

	return results
}

// checkCacheKeyManipulation checks for cache key manipulation vulnerabilities
func (cps *CachePoisoningScanner) checkCacheKeyManipulation(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find potential cache endpoints
	cacheEndpoints := cps.findCacheEndpoints(target)

	// Prepare cache key manipulation payloads
	keyManipulationPayloads := []struct {
		name  string
		value string
	}{
		{
			name:  "Basic Key Manipulation",
			value: `{"key":"admin_settings","value":{"is_admin":true,"role":"admin"}}`,
		},
		{
			name:  "User Data Manipulation",
			value: `{"key":"user_1_data","value":{"id":1,"name":"Admin","email":"admin@example.com","is_admin":true}}`,
		},
		{
			name:  "Session Data Manipulation",
			value: `{"key":"session_data","value":{"user_id":1,"authenticated":true,"admin":true}}`,
		},
		{
			name:  "Config Manipulation",
			value: `{"key":"app_config","value":{"debug":true,"env":"local","key":"base64:MANIPULATED"}}`,
		},
		{
			name:  "Cache Prefix Bypass",
			value: `{"key":"laravel_cache:admin_settings","value":{"is_admin":true,"role":"admin"}}`,
		},
	}

	// Test each endpoint with cache key manipulation payloads
	for _, endpoint := range cacheEndpoints {
		for _, payload := range keyManipulationPayloads {
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
			resp, err := cps.client.Post(fullURL, headers, strings.NewReader(payload.value))
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a successful cache operation
			if cps.isSuccessfulCacheOperation(resp.StatusCode, bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    cps.Name(),
					Category:    "Vulnerabilities",
					Description: fmt.Sprintf("Potential Laravel cache key manipulation vulnerability (%s)", payload.name),
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The cache endpoint %s might be vulnerable to cache key manipulation. The application accepted a potentially malicious cache key payload that could lead to unauthorized data access or modification.", fullURL),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}
		}
	}

	return results
}

// findCacheEndpoints finds potential cache endpoints in the target application
func (cps *CachePoisoningScanner) findCacheEndpoints(target string) []string {
	var endpoints []string

	// Common cache endpoints
	commonEndpoints := []string{
		"/cache",
		"/api/cache",
		"/admin/cache",
		"/cache/set",
		"/cache/get",
		"/cache/put",
		"/cache/store",
		"/api/cache/set",
		"/api/cache/get",
		"/api/cache/put",
		"/api/cache/store",
		"/admin/cache/set",
		"/admin/cache/get",
		"/admin/cache/put",
		"/admin/cache/store",
	}

	// Add common endpoints
	endpoints = append(endpoints, commonEndpoints...)

	// Send a GET request to the target
	resp, err := cps.client.Get(target, nil)
	if err != nil {
		return endpoints
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return endpoints
	}
	bodyString := string(bodyBytes)

	// Extract potential cache endpoints from HTML
	cachePatterns := []string{
		`href=["']([^"']*(?:cache)[^"']*)["']`,
		`action=["']([^"']*(?:cache)[^"']*)["']`,
		`url:\s*["']([^"']*(?:cache)[^"']*)["']`,
	}

	for _, pattern := range cachePatterns {
		cacheRegex := regexp.MustCompile(pattern)
		cacheMatches := cacheRegex.FindAllStringSubmatch(bodyString, -1)

		for _, cacheMatch := range cacheMatches {
			if len(cacheMatch) < 2 {
				continue
			}

			endpoint := cacheMatch[1]
			if !strings.HasPrefix(endpoint, "http") && !strings.HasPrefix(endpoint, "/") {
				endpoint = "/" + endpoint
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	// Extract potential cache endpoints from JavaScript files
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
		jsResp, jsErr := cps.client.Get(jsURL, nil)
		if jsErr != nil {
			continue
		}

		jsBodyBytes, jsErr := ioutil.ReadAll(jsResp.Body)
		jsResp.Body.Close()
		if jsErr != nil {
			continue
		}
		jsBodyString := string(jsBodyBytes)

		// Extract potential cache endpoints from JavaScript
		for _, pattern := range cachePatterns {
			cacheRegex := regexp.MustCompile(pattern)
			cacheMatches := cacheRegex.FindAllStringSubmatch(jsBodyString, -1)

			for _, cacheMatch := range cacheMatches {
				if len(cacheMatch) < 2 {
					continue
				}

				endpoint := cacheMatch[1]
				if !strings.HasPrefix(endpoint, "http") && !strings.HasPrefix(endpoint, "/") {
					endpoint = "/" + endpoint
				}

				endpoints = append(endpoints, endpoint)
			}
		}

		// Look for cache-related JavaScript functions
		cacheFunctionPatterns := []string{
			`cache\.(?:set|get|put|store|remember)\(["']([^"']*)["']`,
			`Cache\.(?:set|get|put|store|remember)\(["']([^"']*)["']`,
			`\.cache\(["']([^"']*)["']`,
		}

		for _, pattern := range cacheFunctionPatterns {
			cacheFunctionRegex := regexp.MustCompile(pattern)
			cacheFunctionMatches := cacheFunctionRegex.FindAllStringSubmatch(jsBodyString, -1)

			for _, cacheFunctionMatch := range cacheFunctionMatches {
				if len(cacheFunctionMatch) < 2 {
					continue
				}

				// Add the cache key as a potential endpoint parameter
				cacheKey := cacheFunctionMatch[1]
				for _, endpoint := range commonEndpoints {
					endpoints = append(endpoints, fmt.Sprintf("%s?key=%s", endpoint, cacheKey))
				}
			}
		}
	}

	return endpoints
}

// isSuccessfulCacheOperation checks if the response indicates a successful cache operation
func (cps *CachePoisoningScanner) isSuccessfulCacheOperation(statusCode int, body string) bool {
	// Check for 200 status code
	if statusCode != 200 {
		return false
	}

	// Check for common success patterns
	successPatterns := []string{
		"success",
		"cached",
		"stored",
		"saved",
		"\"status\":\"success\"",
		"\"status\":\"ok\"",
		"\"success\":true",
		"\"cached\":true",
		"\"stored\":true",
		"\"saved\":true",
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

		// Check for cached boolean
		if cached, ok := jsonResponse["cached"]; ok {
			if cachedBool, ok := cached.(bool); ok {
				if cachedBool {
					return true
				}
			}
		}

		// Check for stored boolean
		if stored, ok := jsonResponse["stored"]; ok {
			if storedBool, ok := stored.(bool); ok {
				if storedBool {
					return true
				}
			}
		}

		// Check for saved boolean
		if saved, ok := jsonResponse["saved"]; ok {
			if savedBool, ok := saved.(bool); ok {
				if savedBool {
					return true
				}
			}
		}

		// Check for key field
		if _, ok := jsonResponse["key"]; ok {
			return true
		}

		// Check for value field
		if _, ok := jsonResponse["value"]; ok {
			return true
		}
	}

	return false
}

// checkCacheDataInjection checks for cache data injection vulnerabilities
func (cps *CachePoisoningScanner) checkCacheDataInjection(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find forms that might interact with cache
	forms := cps.findCacheForms(target)

	// Prepare cache data injection payloads
	dataInjectionPayloads := []struct {
		name  string
		value string
	}{
		{
			name:  "XSS Injection",
			value: `<script>alert('XSS via Cache')</script>`,
		},
		{
			name:  "HTML Injection",
			value: `<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:red;z-index:9999;">Hacked via Cache</div>`,
		},
		{
			name:  "PHP Object Injection",
			value: `O:8:"stdClass":1:{s:4:"data";s:11:"Injected";}`,
		},
		{
			name:  "JSON Injection",
			value: `{"__proto__":{"isAdmin":true},"data":"Injected"}`,
		},
		{
			name:  "SQL Injection via Cache",
			value: `' OR 1=1--`,
		},
	}

	// Test each form with cache data injection payloads
	for _, form := range forms {
		// Only test POST forms
		if form.method != "POST" {
			continue
		}

		for _, payload := range dataInjectionPayloads {
			// Create a copy of params with the payload in all fields
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
			resp, err := cps.client.Post(form.action, headers, strings.NewReader(formData.Encode()))
			if err != nil {
				continue
			}

			// Store the response to check if the payload was cached
			firstResponseBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			firstResponseString := string(firstResponseBytes)

			// Send a GET request to the same URL to check if the payload was cached
			getResp, err := cps.client.Get(form.action, nil)
			if err != nil {
				continue
			}

			getResponseBytes, err := ioutil.ReadAll(getResp.Body)
			getResp.Body.Close()
			if err != nil {
				continue
			}
			getResponseString := string(getResponseBytes)

			// Check if the payload appears in the GET response, indicating it was cached
			if strings.Contains(getResponseString, payload.value) {
				results = append(results, common.ScanResult{
					ScanName:    cps.Name(),
					Category:    "Vulnerabilities",
					Description: fmt.Sprintf("Potential Laravel cache data injection vulnerability (%s)", payload.name),
					Path:        form.action,
					StatusCode:  getResp.StatusCode,
					Detail:      fmt.Sprintf("The form at %s might be vulnerable to cache data injection. The application appears to cache user input without proper sanitization, which could lead to stored XSS, HTML injection, or other attacks affecting multiple users.", form.action),
				})

				// Break the loop for this form to avoid duplicate results
				break
			}

			// Also check for reflected payloads that might be cacheable
			if strings.Contains(firstResponseString, payload.value) {
				// Send another GET request with a different User-Agent to check if the response is cached
				headers = map[string]string{
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				}
				secondGetResp, err := cps.client.Get(form.action, headers)
				if err != nil {
					continue
				}

				secondGetResponseBytes, err := ioutil.ReadAll(secondGetResp.Body)
				secondGetResp.Body.Close()
				if err != nil {
					continue
				}
				secondGetResponseString := string(secondGetResponseBytes)

				// If the payload appears in the second GET response with a different User-Agent, it might be cached
				if strings.Contains(secondGetResponseString, payload.value) {
					results = append(results, common.ScanResult{
						ScanName:    cps.Name(),
						Category:    "Vulnerabilities",
						Description: fmt.Sprintf("Potential Laravel cache data injection vulnerability (%s)", payload.name),
						Path:        form.action,
						StatusCode:  secondGetResp.StatusCode,
						Detail:      fmt.Sprintf("The form at %s might be vulnerable to cache data injection. The application appears to cache responses containing user input without proper cache control, which could lead to stored XSS, HTML injection, or other attacks affecting multiple users.", form.action),
					})

					// Break the loop for this form to avoid duplicate results
					break
				}
			}
		}
	}

	return results
}

// findCacheForms finds forms that might interact with cache in the target application
func (cps *CachePoisoningScanner) findCacheForms(target string) []form {
	var forms []form

	// Send a GET request to the target
	resp, err := cps.client.Get(target, nil)
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

		// Check if the form might interact with cache
		isCacheForm := false

		// Check if the form action contains cache-related keywords
		if strings.Contains(strings.ToLower(action), "cache") {
			isCacheForm = true
		}

		// Check if the form has cache-related input fields
		for name := range params {
			if strings.Contains(strings.ToLower(name), "cache") {
				isCacheForm = true
				break
			}
		}

		// Check if the form content contains cache-related attributes or comments
		cachePatterns := []string{
			`data-cache`,
			`cache=`,
			`<!-- cache -->`,
			`<!-- cached -->`,
		}

		for _, pattern := range cachePatterns {
			if strings.Contains(strings.ToLower(formContent), strings.ToLower(pattern)) {
				isCacheForm = true
				break
			}
		}

		// If the form might interact with cache, add it to the list
		if isCacheForm {
			forms = append(forms, form{
				action: action,
				method: method,
				params: params,
			})
		} else {
			// Even if the form doesn't have explicit cache indicators, add it if it's a search form
			// as search results are commonly cached
			isSearchForm := false

			// Check if the form action contains search-related keywords
			if strings.Contains(strings.ToLower(action), "search") {
				isSearchForm = true
			}

			// Check if the form has search-related input fields
			for name := range params {
				if strings.Contains(strings.ToLower(name), "search") || strings.Contains(strings.ToLower(name), "query") || strings.Contains(strings.ToLower(name), "q") {
					isSearchForm = true
					break
				}
			}

			if isSearchForm {
				forms = append(forms, form{
					action: action,
					method: method,
					params: params,
				})
			}
		}
	}

	return forms
}

// checkCacheConfigurationExposure checks for cache configuration exposure
func (cps *CachePoisoningScanner) checkCacheConfigurationExposure(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common paths that might expose cache configuration
	configPaths := []string{
		"/config/cache.php",
		"/app/config/cache.php",
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
		resp, err := cps.client.Get(fullURL, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response contains cache configuration information
		if resp.StatusCode == 200 && cps.containsCacheConfig(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    cps.Name(),
				Category:    "Vulnerabilities",
				Description: "Laravel cache configuration exposure",
				Path:        fullURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The application exposes cache configuration at %s. This could reveal sensitive information about cache drivers, connection details, and cache keys, which could be used to perform cache poisoning attacks.", fullURL),
			})
		}
	}

	return results
}

// containsCacheConfig checks if the response contains cache configuration information
func (cps *CachePoisoningScanner) containsCacheConfig(response string) bool {
	cacheConfigPatterns := []string{
		"CACHE_DRIVER",
		"REDIS_HOST",
		"REDIS_PASSWORD",
		"REDIS_PORT",
		"MEMCACHED_HOST",
		"MEMCACHED_PORT",
		"MEMCACHED_USERNAME",
		"MEMCACHED_PASSWORD",
		"driver => file",
		"driver => redis",
		"driver => memcached",
		"driver => database",
		"'driver' => 'file'",
		"'driver' => 'redis'",
		"'driver' => 'memcached'",
		"'driver' => 'database'",
		"connection =>",
		"prefix =>",
		"store =>",
		"path =>",
		"'connection' =>",
		"'prefix' =>",
		"'store' =>",
		"'path' =>",
	}

	for _, pattern := range cacheConfigPatterns {
		if strings.Contains(response, pattern) {
			return true
		}
	}

	return false
}

// checkInsecureCacheEndpoints checks for insecure cache endpoints
func (cps *CachePoisoningScanner) checkInsecureCacheEndpoints(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common cache management endpoints
	cacheManagementEndpoints := []string{
		"/cache/clear",
		"/cache/flush",
		"/cache/reset",
		"/api/cache/clear",
		"/api/cache/flush",
		"/api/cache/reset",
		"/admin/cache/clear",
		"/admin/cache/flush",
		"/admin/cache/reset",
	}

	// Test each cache management endpoint
	for _, endpoint := range cacheManagementEndpoints {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = endpoint
		fullURL := parsedURL.String()

		// Send GET request
		resp, err := cps.client.Get(fullURL, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response indicates a successful cache management operation
		if cps.isSuccessfulCacheManagement(resp.StatusCode, bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    cps.Name(),
				Category:    "Vulnerabilities",
				Description: "Insecure Laravel cache management endpoint",
				Path:        fullURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The cache management endpoint %s is accessible without proper authentication. This could allow unauthorized users to clear or manipulate the application's cache, potentially leading to denial of service or data inconsistency.", fullURL),
			})
		}
	}

	return results
}

// isSuccessfulCacheManagement checks if the response indicates a successful cache management operation
func (cps *CachePoisoningScanner) isSuccessfulCacheManagement(statusCode int, body string) bool {
	// Check for 200 status code
	if statusCode != 200 {
		return false
	}

	// Check for common success patterns
	successPatterns := []string{
		"cleared",
		"flushed",
		"reset",
		"cache cleared",
		"cache flushed",
		"cache reset",
		"successfully cleared",
		"successfully flushed",
		"successfully reset",
		"\"status\":\"success\"",
		"\"status\":\"ok\"",
		"\"success\":true",
		"\"cleared\":true",
		"\"flushed\":true",
		"\"reset\":true",
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

		// Check for cleared boolean
		if cleared, ok := jsonResponse["cleared"]; ok {
			if clearedBool, ok := cleared.(bool); ok {
				if clearedBool {
					return true
				}
			}
		}

		// Check for flushed boolean
		if flushed, ok := jsonResponse["flushed"]; ok {
			if flushedBool, ok := flushed.(bool); ok {
				if flushedBool {
					return true
				}
			}
		}

		// Check for reset boolean
		if reset, ok := jsonResponse["reset"]; ok {
			if resetBool, ok := reset.(bool); ok {
				if resetBool {
					return true
				}
			}
		}
	}

	return false
}

// Name returns the name of the scanner
func (cps *CachePoisoningScanner) Name() string {
	return "Laravel Cache Poisoning Scanner"
}
