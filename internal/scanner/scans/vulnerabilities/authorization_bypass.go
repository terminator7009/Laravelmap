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

// AuthorizationBypassScanner is a struct that contains an HTTP client for detecting authorization bypass vulnerabilities
type AuthorizationBypassScanner struct {
	client *httpclient.Client
}

// NewAuthorizationBypassScanner initializes and returns a new AuthorizationBypassScanner instance
func NewAuthorizationBypassScanner() *AuthorizationBypassScanner {
	return &AuthorizationBypassScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for authorization bypass vulnerabilities in Laravel applications
func (abs *AuthorizationBypassScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Detect routes and resources
	routes, resources := abs.detectRoutesAndResources(target)

	// Check for horizontal privilege escalation
	horizontalResults := abs.checkHorizontalPrivilegeEscalation(target, routes, resources)
	results = append(results, horizontalResults...)

	// Check for vertical privilege escalation
	verticalResults := abs.checkVerticalPrivilegeEscalation(target, routes, resources)
	results = append(results, verticalResults...)

	// Check for missing authorization
	missingAuthResults := abs.checkMissingAuthorization(target, routes, resources)
	results = append(results, missingAuthResults...)

	// Check for insecure direct object references (IDOR)
	idorResults := abs.checkIDOR(target, routes, resources)
	results = append(results, idorResults...)

	// Check for policy/gate bypass vulnerabilities
	policyResults := abs.checkPolicyBypass(target, routes, resources)
	results = append(results, policyResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    abs.Name(),
			Category:    "Vulnerabilities",
			Description: "No authorization bypass vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "No potential authorization bypass vulnerabilities were detected. However, this does not guarantee that the application is not vulnerable to authorization bypass attacks.",
		})
	}

	return results
}

// Resource represents a Laravel resource
type Resource struct {
	name      string
	endpoints []string
	idPattern string
}

// detectRoutesAndResources detects Laravel routes and resources
func (abs *AuthorizationBypassScanner) detectRoutesAndResources(target string) ([]string, []Resource) {
	var routes []string
	var resources []Resource

	// Send a GET request to the target
	resp, err := abs.client.Get(target, nil)
	if err != nil {
		return routes, resources
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return routes, resources
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
		jsResp, jsErr := abs.client.Get(jsURL, nil)
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

	// Extract links from the HTML
	linkPattern := `<a[^>]*href="([^"]*)"[^>]*>`
	linkRegex := regexp.MustCompile(linkPattern)
	linkMatches := linkRegex.FindAllStringSubmatch(bodyString, -1)

	for _, linkMatch := range linkMatches {
		if len(linkMatch) < 2 {
			continue
		}

		link := linkMatch[1]
		if strings.HasPrefix(link, "#") || strings.HasPrefix(link, "javascript:") {
			continue
		}

		if !strings.HasPrefix(link, "http") {
			// Convert relative URL to absolute
			parsedURL, parseErr := url.Parse(target)
			if parseErr != nil {
				continue
			}

			if strings.HasPrefix(link, "/") {
				// Absolute path
				parsedURL.Path = link
			} else {
				// Relative path
				if !strings.HasSuffix(parsedURL.Path, "/") {
					parsedURL.Path += "/"
				}
				parsedURL.Path += link
			}

			link = parsedURL.String()
		}

		routes = append(routes, link)
	}

	// Identify resources from routes
	resourcePatterns := []struct {
		pattern    string
		nameIndex  int
		idPattern  string
		endpoints  []string
		resourceFn func(string) Resource
	}{
		{
			pattern:   `/api/([a-zA-Z0-9_-]+)(?:/(\d+))?`,
			nameIndex: 1,
			idPattern: `\d+`,
			endpoints: []string{
				"/api/%s",
				"/api/%s/create",
				"/api/%s/%s",
				"/api/%s/%s/edit",
				"/api/%s/%s/delete",
			},
			resourceFn: func(name string) Resource {
				return Resource{
					name:      name,
					idPattern: `\d+`,
					endpoints: []string{
						fmt.Sprintf("/api/%s", name),
						fmt.Sprintf("/api/%s/create", name),
						fmt.Sprintf("/api/%s/%%s", name),
						fmt.Sprintf("/api/%s/%%s/edit", name),
						fmt.Sprintf("/api/%s/%%s/delete", name),
					},
				}
			},
		},
		{
			pattern:   `/([a-zA-Z0-9_-]+)(?:/(\d+))?`,
			nameIndex: 1,
			idPattern: `\d+`,
			endpoints: []string{
				"/%s",
				"/%s/create",
				"/%s/%s",
				"/%s/%s/edit",
				"/%s/%s/delete",
			},
			resourceFn: func(name string) Resource {
				return Resource{
					name:      name,
					idPattern: `\d+`,
					endpoints: []string{
						fmt.Sprintf("/%s", name),
						fmt.Sprintf("/%s/create", name),
						fmt.Sprintf("/%s/%%s", name),
						fmt.Sprintf("/%s/%%s/edit", name),
						fmt.Sprintf("/%s/%%s/delete", name),
					},
				}
			},
		},
	}

	resourceMap := make(map[string]Resource)
	for _, route := range routes {
		for _, resourcePattern := range resourcePatterns {
			regex := regexp.MustCompile(resourcePattern.pattern)
			matches := regex.FindStringSubmatch(route)
			if len(matches) > resourcePattern.nameIndex {
				resourceName := matches[resourcePattern.nameIndex]
				if resourceName == "login" || resourceName == "register" || resourceName == "logout" || resourceName == "password" {
					continue
				}

				if _, ok := resourceMap[resourceName]; !ok {
					resourceMap[resourceName] = resourcePattern.resourceFn(resourceName)
				}
			}
		}
	}

	// Convert map to slice
	for _, resource := range resourceMap {
		resources = append(resources, resource)
	}

	// Add common Laravel resources if none were detected
	if len(resources) == 0 {
		commonResources := []string{
			"users",
			"posts",
			"articles",
			"comments",
			"products",
			"orders",
			"categories",
			"tags",
			"profiles",
			"settings",
		}

		for _, name := range commonResources {
			resources = append(resources, Resource{
				name:      name,
				idPattern: `\d+`,
				endpoints: []string{
					fmt.Sprintf("/%s", name),
					fmt.Sprintf("/%s/create", name),
					fmt.Sprintf("/%s/%%s", name),
					fmt.Sprintf("/%s/%%s/edit", name),
					fmt.Sprintf("/%s/%%s/delete", name),
					fmt.Sprintf("/api/%s", name),
					fmt.Sprintf("/api/%s/create", name),
					fmt.Sprintf("/api/%s/%%s", name),
					fmt.Sprintf("/api/%s/%%s/edit", name),
					fmt.Sprintf("/api/%s/%%s/delete", name),
				},
			})
		}
	}

	return routes, resources
}

// checkHorizontalPrivilegeEscalation checks for horizontal privilege escalation vulnerabilities
func (abs *AuthorizationBypassScanner) checkHorizontalPrivilegeEscalation(target string, routes []string, resources []Resource) []common.ScanResult {
	var results []common.ScanResult

	// Test IDs for horizontal privilege escalation
	testIDs := []string{"1", "2", "3", "10", "100"}

	// Extract potential user-related endpoints from routes
	userEndpoints := make(map[string]bool)
	for _, route := range routes {
		// Look for routes with user IDs
		userPatterns := []string{
			`/user/\d+`,
			`/users/\d+`,
			`/profile/\d+`,
			`/account/\d+`,
			`/member/\d+`,
			`/members/\d+`,
		}

		for _, pattern := range userPatterns {
			matched, _ := regexp.MatchString(pattern, route)
			if matched {
				userEndpoints[route] = true
				break
			}
		}
	}

	// Test each resource
	for _, resource := range resources {
		for _, endpoint := range resource.endpoints {
			if !strings.Contains(endpoint, "%s") {
				continue
			}

			// Test each ID
			for _, id := range testIDs {
				endpointWithID := fmt.Sprintf(endpoint, id)

				// Create the full URL
				parsedURL, parseErr := url.Parse(target)
				if parseErr != nil {
					continue
				}

				parsedURL.Path = endpointWithID
				fullURL := parsedURL.String()

				// Test GET request
				resp, err := abs.client.Get(fullURL, nil)
				if err != nil {
					continue
				}

				bodyBytes, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyString := string(bodyBytes)

				// Check if the request was successful (2xx) and doesn't contain access denied messages
				if resp.StatusCode >= 200 && resp.StatusCode < 300 && !abs.containsAccessDeniedMessage(bodyString) {
					results = append(results, common.ScanResult{
						ScanName:    abs.Name(),
						Category:    "Vulnerabilities",
						Description: "Potential horizontal privilege escalation vulnerability",
						Path:        fullURL,
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("The endpoint %s might be vulnerable to horizontal privilege escalation. The application returned a successful response for a resource that might belong to another user.", fullURL),
					})

					// Break the loop for this endpoint to avoid duplicate results
					break
				}
			}
		}
	}

	// Test discovered user endpoints
	for endpoint := range userEndpoints {
		// Test GET request
		resp, err := abs.client.Get(endpoint, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the request was successful (2xx) and doesn't contain access denied messages
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && !abs.containsAccessDeniedMessage(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    abs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential horizontal privilege escalation vulnerability (IDOR)",
				Path:        endpoint,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The endpoint %s might be vulnerable to horizontal privilege escalation (IDOR). The application returned a successful response for a resource that might belong to another user.", endpoint),
			})
		}

		// Also test edit endpoints
		if strings.Contains(endpoint, "/view") || strings.Contains(endpoint, "/show") || strings.Contains(endpoint, "/profile") {
			editEndpoint := strings.Replace(endpoint, "/view", "/edit", 1)
			editEndpoint = strings.Replace(editEndpoint, "/show", "/edit", 1)
			editEndpoint = strings.Replace(editEndpoint, "/profile", "/edit", 1)

			// If no replacement was made, add /edit to the endpoint
			if editEndpoint == endpoint {
				// Extract the base path and ID
				parts := strings.Split(endpoint, "/")
				if len(parts) >= 3 {
					// Reconstruct with /edit
					editEndpoint = fmt.Sprintf("/%s/%s/edit", parts[1], parts[2])
				}
			}

			// Create the full URL
			parsedURL, parseErr := url.Parse(target)
			if parseErr != nil {
				continue
			}

			parsedURL.Path = editEndpoint
			editURL := parsedURL.String()

			// Test GET request
			editResp, err := abs.client.Get(editURL, nil)
			if err != nil {
				continue
			}

			editBodyBytes, err := ioutil.ReadAll(editResp.Body)
			editResp.Body.Close()
			if err != nil {
				continue
			}
			editBodyString := string(editBodyBytes)

			// Check if the request was successful (2xx) and doesn't contain access denied messages
			if editResp.StatusCode >= 200 && editResp.StatusCode < 300 && !abs.containsAccessDeniedMessage(editBodyString) {
				results = append(results, common.ScanResult{
					ScanName:    abs.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential horizontal privilege escalation vulnerability (IDOR) on edit endpoint",
					Path:        editURL,
					StatusCode:  editResp.StatusCode,
					Detail:      fmt.Sprintf("The edit endpoint %s might be vulnerable to horizontal privilege escalation (IDOR). The application returned a successful response for editing a resource that might belong to another user.", editURL),
				})
			}
		}
	}

	return results
}

// checkVerticalPrivilegeEscalation checks for vertical privilege escalation vulnerabilities
func (abs *AuthorizationBypassScanner) checkVerticalPrivilegeEscalation(target string, routes []string, resources []Resource) []common.ScanResult {
	var results []common.ScanResult

	// Admin endpoints to check
	adminEndpoints := []string{
		"/admin",
		"/admin/dashboard",
		"/admin/users",
		"/admin/settings",
		"/dashboard",
		"/manage",
		"/manage/users",
		"/manage/settings",
	}

	// Add potential admin endpoints from discovered routes
	for _, route := range routes {
		if strings.Contains(route, "admin") || strings.Contains(route, "dashboard") || strings.Contains(route, "manage") {
			adminEndpoints = append(adminEndpoints, route)
		}
	}

	// Add potential admin endpoints from discovered resources
	for _, resource := range resources {
		if resource.name == "admin" || resource.name == "admins" || resource.name == "dashboard" {
			for _, endpoint := range resource.endpoints {
				if !strings.Contains(endpoint, "%s") {
					adminEndpoints = append(adminEndpoints, endpoint)
				} else {
					// Add with a default ID
					adminEndpoints = append(adminEndpoints, fmt.Sprintf(endpoint, "1"))
				}
			}
		}
	}

	// Test each admin endpoint
	for _, endpoint := range adminEndpoints {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = endpoint
		fullURL := parsedURL.String()

		// Test GET request
		resp, err := abs.client.Get(fullURL, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the request was successful (2xx) and doesn't contain access denied or login messages
		if resp.StatusCode >= 200 && resp.StatusCode < 300 &&
			!abs.containsAccessDeniedMessage(bodyString) &&
			!abs.containsLoginMessage(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    abs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential vertical privilege escalation vulnerability",
				Path:        fullURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The admin endpoint %s might be vulnerable to vertical privilege escalation. The application returned a successful response without proper authentication or authorization.", fullURL),
			})
		}
	}

	return results
}

// checkMissingAuthorization checks for missing authorization vulnerabilities
func (abs *AuthorizationBypassScanner) checkMissingAuthorization(target string, routes []string, resources []Resource) []common.ScanResult {
	var results []common.ScanResult

	// Sensitive operations to check
	sensitiveOperations := []struct {
		path   string
		method string
		data   string
	}{
		{"/users/create", "POST", `{"name":"Test User","email":"test@example.com","password":"password123"}`},
		{"/users/1/delete", "POST", `{}`},
		{"/users/1/update", "POST", `{"name":"Updated User"}`},
		{"/settings/update", "POST", `{"setting":"value"}`},
		{"/api/users", "POST", `{"name":"Test User","email":"test@example.com","password":"password123"}`},
		{"/api/users/1", "DELETE", `{}`},
		{"/api/users/1", "PUT", `{"name":"Updated User"}`},
		{"/api/settings", "PUT", `{"setting":"value"}`},
	}

	// Add endpoints from discovered routes
	for _, route := range routes {
		// Look for routes that might be sensitive operations
		if strings.Contains(route, "create") ||
			strings.Contains(route, "update") ||
			strings.Contains(route, "delete") ||
			strings.Contains(route, "edit") {
			sensitiveOperations = append(sensitiveOperations, struct {
				path   string
				method string
				data   string
			}{
				path:   route,
				method: "POST",
				data:   `{"name":"Test User","email":"test@example.com","password":"password123"}`,
			})
		}
	}

	// Add endpoints from discovered resources
	for _, resource := range resources {
		for _, endpoint := range resource.endpoints {
			if strings.Contains(endpoint, "create") ||
				strings.Contains(endpoint, "edit") ||
				strings.Contains(endpoint, "delete") {
				sensitiveOperations = append(sensitiveOperations, struct {
					path   string
					method string
					data   string
				}{
					path:   endpoint,
					method: "POST",
					data:   fmt.Sprintf(`{"%s_id":1,"name":"Test User"}`, resource.name),
				})
			}
		}
	}

	// Test each sensitive operation
	for _, operation := range sensitiveOperations {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = operation.path
		fullURL := parsedURL.String()

		// Create a new request
		req, reqErr := http.NewRequest(operation.method, fullURL, strings.NewReader(operation.data))
		if reqErr != nil {
			continue
		}

		// Add headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-CSRF-TOKEN", "testing")

		// Send request
		resp, err := abs.client.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the request was successful (2xx) and doesn't contain access denied or login messages
		if (resp.StatusCode >= 200 && resp.StatusCode < 300 || resp.StatusCode == 302) &&
			!abs.containsAccessDeniedMessage(bodyString) &&
			!abs.containsLoginMessage(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    abs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential missing authorization vulnerability",
				Path:        fullURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The endpoint %s with method %s might be vulnerable to unauthorized access. The application returned a successful response for a sensitive operation without proper authentication or authorization.", fullURL, operation.method),
			})
		}
	}

	return results
}

// checkIDOR checks for insecure direct object references (IDOR) vulnerabilities
func (abs *AuthorizationBypassScanner) checkIDOR(target string, routes []string, resources []Resource) []common.ScanResult {
	var results []common.ScanResult

	// Test IDs for IDOR
	testIDs := []string{"1", "2", "3", "10", "100"}

	// Extract potential IDOR endpoints from routes
	idorEndpoints := make(map[string]bool)
	for _, route := range routes {
		// Look for routes with numeric IDs
		idPattern := `(/[a-zA-Z0-9_-]+/\d+)`
		idRegex := regexp.MustCompile(idPattern)
		if idRegex.MatchString(route) {
			idorEndpoints[route] = true
		}
	}

	// Test each resource
	for _, resource := range resources {
		for _, endpoint := range resource.endpoints {
			if !strings.Contains(endpoint, "%s") {
				continue
			}

			// Test each ID
			for _, id := range testIDs {
				endpointWithID := fmt.Sprintf(endpoint, id)

				// Create the full URL
				parsedURL, parseErr := url.Parse(target)
				if parseErr != nil {
					continue
				}

				parsedURL.Path = endpointWithID
				fullURL := parsedURL.String()

				// Test GET request
				resp, err := abs.client.Get(fullURL, nil)
				if err != nil {
					continue
				}

				bodyBytes, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyString := string(bodyBytes)

				// Check if the request was successful (2xx) and contains sensitive data
				if resp.StatusCode >= 200 && resp.StatusCode < 300 && abs.containsSensitiveData(bodyString) {
					results = append(results, common.ScanResult{
						ScanName:    abs.Name(),
						Category:    "Vulnerabilities",
						Description: "Potential IDOR vulnerability",
						Path:        fullURL,
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("The endpoint %s might be vulnerable to Insecure Direct Object Reference (IDOR). The application returned sensitive data for a resource that might belong to another user.", fullURL),
					})

					// Break the loop for this endpoint to avoid duplicate results
					break
				}
			}
		}
	}

	// Test discovered IDOR endpoints
	for endpoint := range idorEndpoints {
		// Test GET request
		resp, err := abs.client.Get(endpoint, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the request was successful (2xx) and contains sensitive data
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && abs.containsSensitiveData(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    abs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential IDOR vulnerability",
				Path:        endpoint,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The endpoint %s might be vulnerable to Insecure Direct Object Reference (IDOR). The application returned sensitive data for a resource that might belong to another user.", endpoint),
			})
		}
	}

	return results
}

// checkPolicyBypass checks for Laravel policy/gate bypass vulnerabilities
func (abs *AuthorizationBypassScanner) checkPolicyBypass(target string, routes []string, resources []Resource) []common.ScanResult {
	var results []common.ScanResult

	// Test parameters for policy bypass
	testParams := []struct {
		name  string
		value string
	}{
		{"_method", "PUT"},
		{"_method", "DELETE"},
		{"_method", "PATCH"},
		{"force", "true"},
		{"admin", "true"},
		{"override", "true"},
		{"bypass", "true"},
		{"debug", "true"},
		{"test", "true"},
	}

	// Extract potential policy bypass endpoints from routes
	policyEndpoints := make(map[string]bool)
	for _, route := range routes {
		// Look for routes that might have policies
		if strings.Contains(route, "edit") ||
			strings.Contains(route, "update") ||
			strings.Contains(route, "delete") ||
			strings.Contains(route, "admin") {
			policyEndpoints[route] = true
		}
	}

	// Test each resource
	for _, resource := range resources {
		for _, endpoint := range resource.endpoints {
			if !strings.Contains(endpoint, "%s") {
				continue
			}

			endpointWithID := fmt.Sprintf(endpoint, "1")

			// Create the full URL
			parsedURL, parseErr := url.Parse(target)
			if parseErr != nil {
				continue
			}

			parsedURL.Path = endpointWithID

			// Test each parameter
			for _, param := range testParams {
				// Create query string
				q := parsedURL.Query()
				q.Set(param.name, param.value)
				parsedURL.RawQuery = q.Encode()
				urlWithParam := parsedURL.String()

				// Test GET request
				resp, err := abs.client.Get(urlWithParam, nil)
				if err != nil {
					continue
				}

				bodyBytes, err := ioutil.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}
				bodyString := string(bodyBytes)

				// Check if the request was successful (2xx) and doesn't contain access denied messages
				if resp.StatusCode >= 200 && resp.StatusCode < 300 && !abs.containsAccessDeniedMessage(bodyString) {
					results = append(results, common.ScanResult{
						ScanName:    abs.Name(),
						Category:    "Vulnerabilities",
						Description: "Potential policy/gate bypass vulnerability",
						Path:        urlWithParam,
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("The endpoint %s with parameter %s=%s might be vulnerable to Laravel policy/gate bypass. The application returned a successful response with a parameter that might bypass authorization checks.", urlWithParam, param.name, param.value),
					})

					// Break the loop for this endpoint to avoid duplicate results
					break
				}
			}
		}
	}

	// Test discovered policy endpoints
	for endpoint := range policyEndpoints {
		for _, param := range testParams {
			// Create the full URL
			parsedURL, parseErr := url.Parse(endpoint)
			if parseErr != nil {
				continue
			}

			// Create query string
			q := parsedURL.Query()
			q.Set(param.name, param.value)
			parsedURL.RawQuery = q.Encode()
			urlWithParam := parsedURL.String()

			// Test GET request
			resp, err := abs.client.Get(urlWithParam, nil)
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the request was successful (2xx) and doesn't contain access denied messages
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && !abs.containsAccessDeniedMessage(bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    abs.Name(),
					Category:    "Vulnerabilities",
					Description: "Potential policy/gate bypass vulnerability",
					Path:        urlWithParam,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The endpoint %s with parameter %s=%s might be vulnerable to Laravel policy/gate bypass. The application returned a successful response with a parameter that might bypass authorization checks.", urlWithParam, param.name, param.value),
				})

				// Break the loop for this endpoint to avoid duplicate results
				break
			}
		}
	}

	return results
}

// containsAccessDeniedMessage checks if the response contains access denied messages
func (abs *AuthorizationBypassScanner) containsAccessDeniedMessage(response string) bool {
	accessDeniedPatterns := []string{
		"access denied",
		"permission denied",
		"unauthorized",
		"forbidden",
		"not authorized",
		"don't have permission",
		"do not have permission",
		"403",
		"not allowed",
	}

	for _, pattern := range accessDeniedPatterns {
		if strings.Contains(strings.ToLower(response), pattern) {
			return true
		}
	}

	return false
}

// containsLoginMessage checks if the response contains login messages
func (abs *AuthorizationBypassScanner) containsLoginMessage(response string) bool {
	loginPatterns := []string{
		"login",
		"sign in",
		"authenticate",
		"credentials",
		"password",
		"username",
		"email",
		"authentication required",
		"please log in",
		"please sign in",
	}

	for _, pattern := range loginPatterns {
		if strings.Contains(strings.ToLower(response), pattern) {
			return true
		}
	}

	return false
}

// containsSensitiveData checks if the response contains sensitive data
func (abs *AuthorizationBypassScanner) containsSensitiveData(response string) bool {
	sensitiveDataPatterns := []string{
		"password",
		"email",
		"address",
		"phone",
		"credit card",
		"ssn",
		"social security",
		"birth date",
		"birthdate",
		"dob",
		"secret",
		"token",
		"api key",
		"apikey",
		"private",
	}

	for _, pattern := range sensitiveDataPatterns {
		if strings.Contains(strings.ToLower(response), pattern) {
			return true
		}
	}

	// Check if the response is a JSON object with user data
	var jsonResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &jsonResponse); err == nil {
		sensitiveKeys := []string{
			"id", "user_id", "name", "email", "password", "address", "phone", "credit_card", "ssn", "dob", "token", "api_key", "private",
		}

		for _, key := range sensitiveKeys {
			if _, ok := jsonResponse[key]; ok {
				return true
			}
		}
	}

	return false
}

// Name returns the name of the scanner
func (abs *AuthorizationBypassScanner) Name() string {
	return "Authorization Bypass Scanner"
}
