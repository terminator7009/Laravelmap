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

// MassAssignmentScanner is a struct that contains an HTTP client for detecting mass assignment vulnerabilities
type MassAssignmentScanner struct {
	client *httpclient.Client
}

// NewMassAssignmentScanner initializes and returns a new MassAssignmentScanner instance
func NewMassAssignmentScanner() *MassAssignmentScanner {
	return &MassAssignmentScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for mass assignment vulnerabilities in Laravel applications
func (mas *MassAssignmentScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// First, detect Laravel routes and forms
	routes, forms := mas.detectRoutesAndForms(target)

	// Check for mass assignment in API endpoints
	apiResults := mas.checkAPIEndpoints(target, routes)
	results = append(results, apiResults...)

	// Check for mass assignment in forms
	formResults := mas.checkForms(target, forms)
	results = append(results, formResults...)

	// Check for mass assignment in common Laravel endpoints
	commonResults := mas.checkCommonEndpoints(target)
	results = append(results, commonResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    mas.Name(),
			Category:    "Vulnerabilities",
			Description: "No mass assignment vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "No potential mass assignment vulnerabilities were detected. However, this does not guarantee that the application is not vulnerable to mass assignment attacks.",
		})
	}

	return results
}

// detectRoutesAndForms detects Laravel routes and forms
func (mas *MassAssignmentScanner) detectRoutesAndForms(target string) ([]string, []form) {
	var routes []string
	var forms []form

	// Send a GET request to the target
	resp, err := mas.client.Get(target, nil)
	if err != nil {
		return routes, forms
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return routes, forms
	}
	bodyString := string(bodyBytes)

	// Extract routes from JavaScript files
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
		jsResp, jsErr := mas.client.Get(jsURL, nil)
		if jsErr != nil {
			continue
		}

		jsBodyBytes, jsErr := ioutil.ReadAll(jsResp.Body)
		jsResp.Body.Close()
		if jsErr != nil {
			continue
		}
		jsBodyString := string(jsBodyBytes)

		// Extract routes from the JavaScript file
		routePatterns := []string{
			`url:\s*['"]([^'"]+)['"]`,
			`href:\s*['"]([^'"]+)['"]`,
			`route\(['"]([^'"]+)`,
			`axios\.(get|post|put|patch|delete)\(['"]([^'"]+)`,
			`\$\.(get|post|put|patch|delete)\(['"]([^'"]+)`,
			`fetch\(['"]([^'"]+)`,
		}

		for _, pattern := range routePatterns {
			routeRegex := regexp.MustCompile(pattern)
			routeMatches := routeRegex.FindAllStringSubmatch(jsBodyString, -1)

			for _, routeMatch := range routeMatches {
				if len(routeMatch) < 2 {
					continue
				}

				route := routeMatch[len(routeMatch)-1]
				if !strings.HasPrefix(route, "http") && !strings.HasPrefix(route, "/") {
					route = "/" + route
				}

				if !strings.HasPrefix(route, "http") {
					// Convert relative URL to absolute
					parsedURL, parseErr := url.Parse(target)
					if parseErr != nil {
						continue
					}

					parsedURL.Path = route
					route = parsedURL.String()
				}

				routes = append(routes, route)
			}
		}
	}

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
		inputPattern := `<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"`
		inputRegex := regexp.MustCompile(inputPattern)
		inputMatches := inputRegex.FindAllStringSubmatch(formContent, -1)

		for _, inputMatch := range inputMatches {
			if len(inputMatch) < 3 {
				continue
			}

			name := inputMatch[1]
			value := inputMatch[2]
			params[name] = value
		}

		forms = append(forms, form{
			action: action,
			method: method,
			params: params,
		})
	}

	return routes, forms
}

// checkAPIEndpoints checks for mass assignment vulnerabilities in API endpoints
func (mas *MassAssignmentScanner) checkAPIEndpoints(target string, routes []string) []common.ScanResult {
	var results []common.ScanResult

	// Common API endpoints to check if no routes were found
	if len(routes) == 0 {
		commonAPIEndpoints := []string{
			"/api/user",
			"/api/users",
			"/api/profile",
			"/api/account",
			"/api/settings",
			"/api/preferences",
			"/api/v1/user",
			"/api/v1/users",
			"/api/v1/profile",
			"/api/v1/account",
		}

		for _, endpoint := range commonAPIEndpoints {
			// Create the full URL
			parsedURL, parseErr := url.Parse(target)
			if parseErr != nil {
				continue
			}

			parsedURL.Path = endpoint
			apiURL := parsedURL.String()

			routes = append(routes, apiURL)
		}
	}

	// Sensitive attributes to test for mass assignment
	sensitiveAttrs := []string{
		"is_admin",
		"admin",
		"role",
		"role_id",
		"permissions",
		"permission_id",
		"is_superuser",
		"superuser",
		"verified",
		"is_verified",
		"email_verified",
		"email_verified_at",
		"active",
		"is_active",
		"status",
		"user_status",
		"balance",
		"credit",
		"points",
	}

	// Test each API endpoint
	for _, route := range routes {
		// Only test POST, PUT, and PATCH endpoints
		for _, method := range []string{"POST", "PUT", "PATCH"} {
			// Test each sensitive attribute
			for _, attr := range sensitiveAttrs {
				// Create the payload
				payload := fmt.Sprintf(`{"%s": true}`, attr)

				// Create a new request
				req, reqErr := http.NewRequest(method, route, strings.NewReader(payload))
				if reqErr != nil {
					continue
				}

				// Add headers
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json")
				req.Header.Set("X-CSRF-TOKEN", "testing")

				// Send request
				resp, err := mas.client.Do(req)
				if err != nil {
					continue
				}

				bodyBytes, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyString := string(bodyBytes)

				// Check if the request was successful (2xx) or if the response indicates a potential vulnerability
				if (resp.StatusCode >= 200 && resp.StatusCode < 300) || mas.checkResponseForSuccess(bodyString, attr) {
					results = append(results, common.ScanResult{
						ScanName:    mas.Name(),
						Category:    "Vulnerabilities",
						Description: "Potential mass assignment vulnerability in API endpoint",
						Path:        route,
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("The API endpoint %s with method %s might be vulnerable to mass assignment attacks. The sensitive attribute '%s' was accepted without proper protection.", route, method, attr),
					})

					// Break the loop for this endpoint and method to avoid duplicate results
					break
				}
			}
		}
	}

	return results
}

// checkForms checks for mass assignment vulnerabilities in forms
func (mas *MassAssignmentScanner) checkForms(target string, forms []form) []common.ScanResult {
	var results []common.ScanResult

	// Sensitive attributes to test for mass assignment
	sensitiveAttrs := []string{
		"is_admin",
		"admin",
		"role",
		"role_id",
		"permissions",
		"permission_id",
		"is_superuser",
		"superuser",
		"verified",
		"is_verified",
		"email_verified",
		"email_verified_at",
		"active",
		"is_active",
		"status",
		"user_status",
		"balance",
		"credit",
		"points",
	}

	// Test each form
	for _, form := range forms {
		// Only test POST forms
		if form.method != "POST" {
			continue
		}

		// Test each sensitive attribute
		for _, attr := range sensitiveAttrs {
			// Create a copy of params with the sensitive attribute
			paramsWithAttr := make(map[string]string)
			for name, value := range form.params {
				paramsWithAttr[name] = value
			}
			paramsWithAttr[attr] = "true"

			// Create form data
			formData := url.Values{}
			for name, value := range paramsWithAttr {
				formData.Set(name, value)
			}

			// Send POST request
			headers := map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}

			// Use the target parameter to construct the full URL if the form action is relative
			formAction := form.action
			if !strings.HasPrefix(formAction, "http") {
				parsedURL, parseErr := url.Parse(target)
				if parseErr != nil {
					continue
				}

				if strings.HasPrefix(formAction, "/") {
					// Absolute path
					parsedURL.Path = formAction
				} else {
					// Relative path
					if !strings.HasSuffix(parsedURL.Path, "/") {
						parsedURL.Path += "/"
					}
					parsedURL.Path += formAction
				}

				formAction = parsedURL.String()
			}

			resp, err := mas.client.Post(formAction, headers, strings.NewReader(formData.Encode()))
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the request was successful (2xx) or if the response indicates a potential vulnerability
			if (resp.StatusCode >= 200 && resp.StatusCode < 300) || mas.checkResponseForSuccess(bodyString, attr) {
				results = append(results, common.ScanResult{
					ScanName:    mas.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential mass assignment vulnerability in form",
					Path:        formAction,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The form at %s might be vulnerable to mass assignment attacks. The sensitive attribute '%s' was accepted without proper protection.", formAction, attr),
				})

				// Break the loop for this form to avoid duplicate results
				break
			}
		}
	}

	return results
}

// checkCommonEndpoints checks for mass assignment vulnerabilities in common Laravel endpoints
func (mas *MassAssignmentScanner) checkCommonEndpoints(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common Laravel endpoints that might be vulnerable to mass assignment
	commonEndpoints := []struct {
		path   string
		method string
	}{
		{"/register", "POST"},
		{"/user/create", "POST"},
		{"/users/create", "POST"},
		{"/profile/update", "POST"},
		{"/profile/edit", "POST"},
		{"/account/update", "POST"},
		{"/settings/update", "POST"},
		{"/password/update", "POST"},
		{"/user/profile", "POST"},
		{"/user/settings", "POST"},
	}

	// Sensitive attributes to test for mass assignment
	sensitiveAttrs := []string{
		"is_admin",
		"admin",
		"role",
		"role_id",
		"permissions",
		"permission_id",
		"is_superuser",
		"superuser",
		"verified",
		"is_verified",
		"email_verified",
		"email_verified_at",
		"active",
		"is_active",
		"status",
		"user_status",
		"balance",
		"credit",
		"points",
	}

	// Test each endpoint
	for _, endpoint := range commonEndpoints {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = endpoint.path
		endpointURL := parsedURL.String()

		// Test each sensitive attribute
		for _, attr := range sensitiveAttrs {
			// Test with JSON payload
			jsonPayload := fmt.Sprintf(`{"%s": true, "email": "test@example.com", "name": "Test User", "password": "password123", "password_confirmation": "password123"}`, attr)

			// Create a new request
			req, reqErr := http.NewRequest(endpoint.method, endpointURL, strings.NewReader(jsonPayload))
			if reqErr != nil {
				continue
			}

			// Add headers
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("X-CSRF-TOKEN", "testing")

			// Send request
			resp, err := mas.client.Do(req)
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the request was successful (2xx) or if the response indicates a potential vulnerability
			if (resp.StatusCode >= 200 && resp.StatusCode < 300) || mas.checkResponseForSuccess(bodyString, attr) {
				results = append(results, common.ScanResult{
					ScanName:    mas.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential mass assignment vulnerability in common endpoint",
					Path:        endpointURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The endpoint %s with method %s might be vulnerable to mass assignment attacks. The sensitive attribute '%s' was accepted without proper protection.", endpointURL, endpoint.method, attr),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}

			// Test with form data
			formData := url.Values{}
			formData.Set(attr, "true")
			formData.Set("email", "test@example.com")
			formData.Set("name", "Test User")
			formData.Set("password", "password123")
			formData.Set("password_confirmation", "password123")

			// Send POST request
			headers := map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}
			resp, err = mas.client.Post(endpointURL, headers, strings.NewReader(formData.Encode()))
			if err != nil {
				continue
			}

			bodyBytes, err = ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString = string(bodyBytes)

			// Check if the request was successful (2xx) or if the response indicates a potential vulnerability
			if (resp.StatusCode >= 200 && resp.StatusCode < 300) || mas.checkResponseForSuccess(bodyString, attr) {
				results = append(results, common.ScanResult{
					ScanName:    mas.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential mass assignment vulnerability in common endpoint",
					Path:        endpointURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The endpoint %s with method %s might be vulnerable to mass assignment attacks. The sensitive attribute '%s' was accepted without proper protection.", endpointURL, endpoint.method, attr),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}
		}
	}

	return results
}

// checkResponseForSuccess checks if the response indicates a successful mass assignment
func (mas *MassAssignmentScanner) checkResponseForSuccess(response string, attr string) bool {
	// Check if the response contains a success message
	successPatterns := []string{
		"success",
		"created",
		"updated",
		"saved",
		"stored",
		"200",
		"201",
	}

	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(response), pattern) {
			return true
		}
	}

	// Check if the response is a JSON object that includes the sensitive attribute
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err == nil {
		// Check if the attribute is in the response
		if _, ok := jsonResponse[attr]; ok {
			return true
		}

		// Check if the attribute is in a nested object
		for _, value := range jsonResponse {
			if nestedObj, ok := value.(map[string]interface{}); ok {
				if _, ok := nestedObj[attr]; ok {
					return true
				}
			}
		}
	}

	return false
}

// Name returns the name of the scanner
func (mas *MassAssignmentScanner) Name() string {
	return "Mass Assignment Scanner"
}
