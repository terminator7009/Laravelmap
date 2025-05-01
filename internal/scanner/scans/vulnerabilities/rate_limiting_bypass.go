package vulnerabilities

import (
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RateLimitingBypassScanner is a struct that contains an HTTP client for detecting rate limiting bypass vulnerabilities
type RateLimitingBypassScanner struct {
	client *httpclient.Client
}

// NewRateLimitingBypassScanner initializes and returns a new RateLimitingBypassScanner instance
func NewRateLimitingBypassScanner() *RateLimitingBypassScanner {
	return &RateLimitingBypassScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for rate limiting bypass vulnerabilities in Laravel applications
func (rls *RateLimitingBypassScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find login and register endpoints
	loginEndpoints, registerEndpoints := rls.findAuthEndpoints(target)

	// Check for brute force vulnerabilities on login endpoints
	loginResults := rls.checkBruteForceVulnerability(target, loginEndpoints, "login")
	results = append(results, loginResults...)

	// Check for brute force vulnerabilities on register endpoints
	registerResults := rls.checkBruteForceVulnerability(target, registerEndpoints, "register")
	results = append(results, registerResults...)

	// Check for header spoofing bypass
	spoofingResults := rls.checkHeaderSpoofingBypass(target, append(loginEndpoints, registerEndpoints...))
	results = append(results, spoofingResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    rls.Name(),
			Category:    "Vulnerabilities",
			Description: "No rate limiting bypass vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "No potential rate limiting bypass vulnerabilities were detected. However, this does not guarantee that the application is not vulnerable to rate limiting bypass attacks.",
		})
	}

	return results
}

// findAuthEndpoints finds login and register endpoints in the target application
func (rls *RateLimitingBypassScanner) findAuthEndpoints(target string) ([]string, []string) {
	var loginEndpoints []string
	var registerEndpoints []string

	// Common login endpoints
	commonLoginEndpoints := []string{
		"/login",
		"/auth/login",
		"/user/login",
		"/account/login",
		"/signin",
		"/api/login",
		"/api/auth/login",
		"/api/v1/login",
		"/api/v1/auth/login",
	}

	// Common register endpoints
	commonRegisterEndpoints := []string{
		"/register",
		"/signup",
		"/auth/register",
		"/user/register",
		"/account/register",
		"/api/register",
		"/api/auth/register",
		"/api/v1/register",
		"/api/v1/auth/register",
	}

	// Send a GET request to the target
	resp, err := rls.client.Get(target, nil)
	if err != nil {
		return commonLoginEndpoints, commonRegisterEndpoints
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return commonLoginEndpoints, commonRegisterEndpoints
	}
	bodyString := string(bodyBytes)

	// Extract login and register endpoints from HTML
	loginPattern := `(href|action)=["']([^"']*(?:login|signin|auth)[^"']*)["']`
	loginRegex := regexp.MustCompile(loginPattern)
	loginMatches := loginRegex.FindAllStringSubmatch(bodyString, -1)

	for _, match := range loginMatches {
		if len(match) >= 3 {
			endpoint := match[2]
			if !strings.HasPrefix(endpoint, "http") {
				// Convert relative URL to absolute
				if !strings.HasPrefix(endpoint, "/") {
					endpoint = "/" + endpoint
				}
			}
			loginEndpoints = append(loginEndpoints, endpoint)
		}
	}

	registerPattern := `(href|action)=["']([^"']*(?:register|signup)[^"']*)["']`
	registerRegex := regexp.MustCompile(registerPattern)
	registerMatches := registerRegex.FindAllStringSubmatch(bodyString, -1)

	for _, match := range registerMatches {
		if len(match) >= 3 {
			endpoint := match[2]
			if !strings.HasPrefix(endpoint, "http") {
				// Convert relative URL to absolute
				if !strings.HasPrefix(endpoint, "/") {
					endpoint = "/" + endpoint
				}
			}
			registerEndpoints = append(registerEndpoints, endpoint)
		}
	}

	// If no login endpoints were found, use common ones
	if len(loginEndpoints) == 0 {
		loginEndpoints = commonLoginEndpoints
	}

	// If no register endpoints were found, use common ones
	if len(registerEndpoints) == 0 {
		registerEndpoints = commonRegisterEndpoints
	}

	return loginEndpoints, registerEndpoints
}

// checkBruteForceVulnerability checks if the target is vulnerable to brute force attacks
func (rls *RateLimitingBypassScanner) checkBruteForceVulnerability(target string, endpoints []string, endpointType string) []common.ScanResult {
	var results []common.ScanResult
	var wg sync.WaitGroup
	resultChan := make(chan common.ScanResult, len(endpoints))

	// Number of requests to send to test rate limiting
	requestCount := 10

	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()

			// Create the full URL
			fullURL := endpoint
			if !strings.HasPrefix(endpoint, "http") {
				parsedURL, parseErr := url.Parse(target)
				if parseErr != nil {
					return
				}

				parsedURL.Path = endpoint
				fullURL = parsedURL.String()
			}

			// Send multiple requests to test rate limiting
			var successCount int
			var failureCount int
			var lastResponseCode int
			var responseBody string

			for i := 0; i < requestCount; i++ {
				// Create form data based on endpoint type
				formData := url.Values{}
				if endpointType == "login" {
					formData.Set("email", fmt.Sprintf("test%d@example.com", i))
					formData.Set("password", fmt.Sprintf("password%d", i))
				} else { // register
					formData.Set("name", fmt.Sprintf("Test User %d", i))
					formData.Set("email", fmt.Sprintf("test%d@example.com", i))
					formData.Set("password", fmt.Sprintf("password%d", i))
					formData.Set("password_confirmation", fmt.Sprintf("password%d", i))
				}

				// Send POST request
				headers := map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				}
				resp, err := rls.client.Post(fullURL, headers, strings.NewReader(formData.Encode()))
				if err != nil {
					failureCount++
					continue
				}

				bodyBytes, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					failureCount++
					continue
				}
				bodyString := string(bodyBytes)

				// Store the last response for analysis
				lastResponseCode = resp.StatusCode
				responseBody = bodyString

				// Check if the request was successful or failed
				if resp.StatusCode == 429 || // Too Many Requests
					strings.Contains(bodyString, "too many") ||
					strings.Contains(bodyString, "rate limit") ||
					strings.Contains(bodyString, "throttle") {
					failureCount++
				} else {
					successCount++
				}

				// Small delay to avoid overwhelming the server
				time.Sleep(100 * time.Millisecond)
			}

			// If all or most requests were successful, the application might be vulnerable
			if successCount >= requestCount-2 {
				resultChan <- common.ScanResult{
					ScanName:    "Rate Limiting Bypass Scanner",
					Category:    "Vulnerabilities",
					Description: fmt.Sprintf("Potential brute force vulnerability on %s endpoint", endpointType),
					Path:        fullURL,
					StatusCode:  lastResponseCode,
					Detail:      fmt.Sprintf("The %s endpoint %s might be vulnerable to brute force attacks. %d out of %d requests were successful without being rate limited. Last response: %s", endpointType, fullURL, successCount, requestCount, rls.truncateString(responseBody, 100)),
				}
			}
		}(endpoint)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(resultChan)

	// Collect results
	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

// truncateString truncates a string to the specified length and adds "..." if truncated
func (rls *RateLimitingBypassScanner) truncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	return s[:maxLength] + "..."
}

// checkHeaderSpoofingBypass checks if rate limiting can be bypassed using header spoofing
func (rls *RateLimitingBypassScanner) checkHeaderSpoofingBypass(target string, endpoints []string) []common.ScanResult {
	var results []common.ScanResult
	var wg sync.WaitGroup
	resultChan := make(chan common.ScanResult, len(endpoints))

	// Number of requests to send to test rate limiting
	requestCount := 10

	for _, endpoint := range endpoints {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()

			// Create the full URL
			fullURL := endpoint
			if !strings.HasPrefix(endpoint, "http") {
				parsedURL, parseErr := url.Parse(target)
				if parseErr != nil {
					return
				}

				parsedURL.Path = endpoint
				fullURL = parsedURL.String()
			}

			// Send multiple requests with spoofed headers to test rate limiting bypass
			var successCount int
			var lastResponseCode int
			var responseBody string

			for i := 0; i < requestCount; i++ {
				// Create form data
				formData := url.Values{}
				formData.Set("email", "test@example.com")
				formData.Set("password", "password123")

				// Create a new request
				req, reqErr := http.NewRequest("POST", fullURL, strings.NewReader(formData.Encode()))
				if reqErr != nil {
					continue
				}

				// Add headers
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				// Add spoofed headers that might bypass rate limiting
				req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.168.1.%d", i+1))
				req.Header.Set("X-Real-IP", fmt.Sprintf("192.168.1.%d", i+1))
				req.Header.Set("Client-IP", fmt.Sprintf("192.168.1.%d", i+1))
				req.Header.Set("X-Originating-IP", fmt.Sprintf("192.168.1.%d", i+1))
				req.Header.Set("CF-Connecting-IP", fmt.Sprintf("192.168.1.%d", i+1))
				req.Header.Set("True-Client-IP", fmt.Sprintf("192.168.1.%d", i+1))

				// Send request
				resp, err := rls.client.Do(req)
				if err != nil {
					continue
				}

				bodyBytes, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyString := string(bodyBytes)

				// Store the last response for analysis
				lastResponseCode = resp.StatusCode
				responseBody = bodyString

				// Check if the request was successful or failed
				if resp.StatusCode == 429 || // Too Many Requests
					strings.Contains(bodyString, "too many") ||
					strings.Contains(bodyString, "rate limit") ||
					strings.Contains(bodyString, "throttle") {
					// Rate limited, not vulnerable
				} else {
					successCount++
				}

				// Small delay to avoid overwhelming the server
				time.Sleep(100 * time.Millisecond)
			}

			// If all or most requests were successful, the application might be vulnerable
			if successCount >= requestCount-2 {
				resultChan <- common.ScanResult{
					ScanName:    "Rate Limiting Bypass Scanner",
					Category:    "Vulnerabilities",
					Description: "Potential rate limiting bypass vulnerability using header spoofing",
					Path:        fullURL,
					StatusCode:  lastResponseCode,
					Detail:      fmt.Sprintf("The endpoint %s might be vulnerable to rate limiting bypass using header spoofing (X-Forwarded-For, X-Real-IP, etc.). %d out of %d requests were successful without being rate limited. Last response: %s", fullURL, successCount, requestCount, rls.truncateString(responseBody, 100)),
				}
			}
		}(endpoint)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(resultChan)

	// Collect results
	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

// Name returns the name of the scanner
func (rls *RateLimitingBypassScanner) Name() string {
	return "Rate Limiting Bypass Scanner"
}
