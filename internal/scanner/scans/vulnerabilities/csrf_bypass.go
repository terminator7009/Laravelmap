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
	"time"
)

// CSRFBypassScanner is a struct that contains an HTTP client for detecting CSRF protection bypass vulnerabilities
type CSRFBypassScanner struct {
	client *httpclient.Client
}

// NewCSRFBypassScanner initializes and returns a new CSRFBypassScanner instance
func NewCSRFBypassScanner() *CSRFBypassScanner {
	return &CSRFBypassScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for CSRF protection bypass vulnerabilities in Laravel applications
func (cs *CSRFBypassScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// First, check if the application uses Laravel's CSRF protection
	csrfEnabled, csrfToken, cookies := cs.detectCSRFProtection(target)
	if !csrfEnabled {
		results = append(results, common.ScanResult{
			ScanName:    cs.Name(),
			Category:    "Vulnerabilities",
			Description: "CSRF protection might not be enabled",
			Path:        target,
			StatusCode:  0,
			Detail:      "Could not detect Laravel's CSRF protection. This might indicate that CSRF protection is disabled or not properly implemented.",
		})
		return results
	}

	// Check for CSRF bypass vulnerabilities
	bypassResults := cs.checkCSRFBypassVulnerabilities(target, csrfToken, cookies)
	results = append(results, bypassResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    cs.Name(),
			Category:    "Vulnerabilities",
			Description: "No CSRF bypass vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "CSRF protection appears to be properly implemented.",
		})
	}

	return results
}

// detectCSRFProtection checks if the application uses Laravel's CSRF protection
func (cs *CSRFBypassScanner) detectCSRFProtection(target string) (bool, string, []*http.Cookie) {
	// Send a GET request to the target
	resp, err := cs.client.Get(target, nil)
	if err != nil {
		return false, "", nil
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "", nil
	}
	bodyString := string(bodyBytes)

	// Check for CSRF token in meta tag
	csrfTokenPattern := `<meta name="csrf-token" content="([^"]+)"`
	csrfTokenRegex := regexp.MustCompile(csrfTokenPattern)
	matches := csrfTokenRegex.FindStringSubmatch(bodyString)
	if len(matches) > 1 {
		return true, matches[1], resp.Cookies()
	}

	// Check for CSRF token in form
	csrfFormPattern := `<input[^>]*name="_token"[^>]*value="([^"]+)"`
	csrfFormRegex := regexp.MustCompile(csrfFormPattern)
	matches = csrfFormRegex.FindStringSubmatch(bodyString)
	if len(matches) > 1 {
		return true, matches[1], resp.Cookies()
	}

	// Check for XSRF-TOKEN cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "XSRF-TOKEN" {
			return true, cookie.Value, resp.Cookies()
		}
	}

	return false, "", nil
}

// checkCSRFBypassVulnerabilities checks for CSRF bypass vulnerabilities
func (cs *CSRFBypassScanner) checkCSRFBypassVulnerabilities(target string, csrfToken string, cookies []*http.Cookie) []common.ScanResult {
	var results []common.ScanResult

	// Find forms to test
	forms := cs.findForms(target)

	// Test each form for CSRF bypass vulnerabilities
	for _, form := range forms {
		// Test for missing CSRF token
		missingTokenResult := cs.testMissingCSRFToken(form.action, form.method, form.params)
		if missingTokenResult != nil {
			results = append(results, *missingTokenResult)
		}

		// Test for token reuse
		tokenReuseResult := cs.testCSRFTokenReuse(form.action, form.method, form.params, csrfToken, cookies)
		if tokenReuseResult != nil {
			results = append(results, *tokenReuseResult)
		}

		// Test for method switching
		methodSwitchResult := cs.testMethodSwitching(form.action, form.method, form.params, csrfToken)
		if methodSwitchResult != nil {
			results = append(results, *methodSwitchResult)
		}
	}

	// Check for CSRF token in URL
	urlTokenResult := cs.checkCSRFTokenInURL(target)
	if urlTokenResult != nil {
		results = append(results, *urlTokenResult)
	}

	// Check for CSRF token in JSON request
	jsonTokenResult := cs.checkCSRFTokenInJSON(target)
	if jsonTokenResult != nil {
		results = append(results, *jsonTokenResult)
	}

	// Check for CSRF token in API endpoints
	apiTokenResult := cs.checkCSRFTokenInAPI(target, cookies)
	if apiTokenResult != nil {
		results = append(results, *apiTokenResult)
	}

	return results
}

// formData represents an HTML form
type formData struct {
	action string
	method string
	params map[string]string
}

// findForms finds HTML forms in the target page
func (cs *CSRFBypassScanner) findForms(target string) []formData {
	var forms []formData

	// Send a GET request to the target
	resp, err := cs.client.Get(target, nil)
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

		forms = append(forms, formData{
			action: action,
			method: method,
			params: params,
		})
	}

	return forms
}

// testMissingCSRFToken tests if a form can be submitted without a CSRF token
func (cs *CSRFBypassScanner) testMissingCSRFToken(action, method string, params map[string]string) *common.ScanResult {
	// Create a copy of params without the CSRF token
	paramsWithoutToken := make(map[string]string)
	for name, value := range params {
		if name != "_token" && name != "csrf_token" {
			paramsWithoutToken[name] = value
		}
	}

	// Try to submit the form without the CSRF token
	var resp *http.Response
	var err error

	if method == "POST" {
		// Create form data
		formData := url.Values{}
		for name, value := range paramsWithoutToken {
			formData.Set(name, value)
		}

		// Send POST request
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}
		resp, err = cs.client.Post(action, headers, strings.NewReader(formData.Encode()))
	} else {
		// Create query string
		parsedURL, parseErr := url.Parse(action)
		if parseErr != nil {
			return nil
		}

		q := parsedURL.Query()
		for name, value := range paramsWithoutToken {
			q.Set(name, value)
		}
		parsedURL.RawQuery = q.Encode()

		// Send GET request
		resp, err = cs.client.Get(parsedURL.String(), nil)
	}

	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// If the response is a success (2xx) or a redirect (3xx), it might indicate a CSRF vulnerability
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return &common.ScanResult{
			ScanName:    cs.Name(),
			Category:    "Vulnerabilities",
			Description: "Potential CSRF vulnerability: Form submission without CSRF token",
			Path:        action,
			StatusCode:  resp.StatusCode,
			Detail:      fmt.Sprintf("The form at %s with method %s can be submitted without a CSRF token.", action, method),
		}
	}

	return nil
}

// testCSRFTokenReuse tests if a CSRF token can be reused
func (cs *CSRFBypassScanner) testCSRFTokenReuse(action, method string, params map[string]string, csrfToken string, cookies []*http.Cookie) *common.ScanResult {
	// Create a new client to simulate a different session
	newClient := httpclient.NewClient(15 * time.Second)

	// Create a copy of params with the CSRF token
	paramsWithToken := make(map[string]string)
	for name, value := range params {
		paramsWithToken[name] = value
	}

	// Add the CSRF token
	if _, ok := params["_token"]; ok {
		paramsWithToken["_token"] = csrfToken
	} else {
		paramsWithToken["csrf_token"] = csrfToken
	}

	// Try to submit the form with the CSRF token from another session
	var resp *http.Response
	var err error

	if method == "POST" {
		// Create form data
		formData := url.Values{}
		for name, value := range paramsWithToken {
			formData.Set(name, value)
		}

		// Send POST request
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}

		// Create a new request
		req, reqErr := http.NewRequest("POST", action, strings.NewReader(formData.Encode()))
		if reqErr != nil {
			return nil
		}

		// Add headers
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		// Add cookies
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		// Send request
		resp, err = newClient.Do(req)
		if err != nil {
			return nil
		}
	} else {
		// Create query string
		parsedURL, parseErr := url.Parse(action)
		if parseErr != nil {
			return nil
		}

		q := parsedURL.Query()
		for name, value := range paramsWithToken {
			q.Set(name, value)
		}
		parsedURL.RawQuery = q.Encode()

		// Create a new request
		req, reqErr := http.NewRequest("GET", parsedURL.String(), nil)
		if reqErr != nil {
			return nil
		}

		// Add cookies
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		// Send request
		resp, err = newClient.Do(req)
		if err != nil {
			return nil
		}
	}

	defer resp.Body.Close()

	// If the response is a success (2xx) or a redirect (3xx), it might indicate a CSRF vulnerability
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return &common.ScanResult{
			ScanName:    cs.Name(),
			Category:    "Vulnerabilities",
			Description: "Potential CSRF vulnerability: CSRF token reuse",
			Path:        action,
			StatusCode:  resp.StatusCode,
			Detail:      fmt.Sprintf("The form at %s with method %s accepts a reused CSRF token.", action, method),
		}
	}

	return nil
}

// testMethodSwitching tests if a form can be submitted with a different HTTP method
func (cs *CSRFBypassScanner) testMethodSwitching(action, method string, params map[string]string, csrfToken string) *common.ScanResult {
	// Only test POST forms
	if method != "POST" {
		return nil
	}

	// Create a copy of params with the CSRF token
	paramsWithToken := make(map[string]string)
	for name, value := range params {
		paramsWithToken[name] = value
	}

	// Add the CSRF token
	if _, ok := params["_token"]; ok {
		paramsWithToken["_token"] = csrfToken
	} else {
		paramsWithToken["csrf_token"] = csrfToken
	}

	// Create query string
	parsedURL, err := url.Parse(action)
	if err != nil {
		return nil
	}

	q := parsedURL.Query()
	for name, value := range paramsWithToken {
		q.Set(name, value)
	}
	parsedURL.RawQuery = q.Encode()

	// Send GET request instead of POST
	resp, err := cs.client.Get(parsedURL.String(), nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// If the response is a success (2xx) or a redirect (3xx), it might indicate a CSRF vulnerability
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return &common.ScanResult{
			ScanName:    cs.Name(),
			Category:    "Vulnerabilities",
			Description: "Potential CSRF vulnerability: Method switching",
			Path:        action,
			StatusCode:  resp.StatusCode,
			Detail:      fmt.Sprintf("The form at %s can be submitted with GET method instead of POST.", action),
		}
	}

	return nil
}

// checkCSRFTokenInURL checks if CSRF tokens are included in URLs
func (cs *CSRFBypassScanner) checkCSRFTokenInURL(target string) *common.ScanResult {
	// Send a GET request to the target
	resp, err := cs.client.Get(target, nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	bodyString := string(bodyBytes)

	// Check for CSRF token in URLs
	urlPattern := `href="[^"]*(_token|csrf_token)=[^"]*"`
	urlRegex := regexp.MustCompile(urlPattern)
	if urlRegex.MatchString(bodyString) {
		return &common.ScanResult{
			ScanName:    cs.Name(),
			Category:    "Vulnerabilities",
			Description: "CSRF token included in URL",
			Path:        target,
			StatusCode:  resp.StatusCode,
			Detail:      "CSRF tokens should not be included in URLs as they can be leaked through Referer headers, browser history, and logs.",
		}
	}

	return nil
}

// checkCSRFTokenInJSON checks if CSRF protection is properly implemented for JSON requests
func (cs *CSRFBypassScanner) checkCSRFTokenInJSON(target string) *common.ScanResult {
	// Find potential API endpoints
	apiEndpoints := []string{
		"/api/user",
		"/api/profile",
		"/api/settings",
		"/api/data",
		"/api/update",
		"/api/create",
		"/api/delete",
	}

	// Test each API endpoint
	for _, endpoint := range apiEndpoints {
		// Create the full URL
		parsedURL, err := url.Parse(target)
		if err != nil {
			continue
		}

		parsedURL.Path = endpoint
		apiURL := parsedURL.String()

		// Send a POST request without X-CSRF-TOKEN header
		headers := map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		}

		resp, err := cs.client.Post(apiURL, headers, strings.NewReader("{}"))
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// If the response is a success (2xx), it might indicate a CSRF vulnerability
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &common.ScanResult{
				ScanName:    cs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential CSRF vulnerability in JSON API",
				Path:        apiURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The API endpoint %s accepts JSON requests without X-CSRF-TOKEN header.", apiURL),
			}
		}
	}

	return nil
}

// checkCSRFTokenInAPI checks if CSRF protection is properly implemented for API endpoints
func (cs *CSRFBypassScanner) checkCSRFTokenInAPI(target string, cookies []*http.Cookie) *common.ScanResult {
	// Find potential API endpoints
	apiEndpoints := []string{
		"/api/user",
		"/api/profile",
		"/api/settings",
		"/api/data",
		"/api/update",
		"/api/create",
		"/api/delete",
	}

	// Test each API endpoint
	for _, endpoint := range apiEndpoints {
		// Create the full URL
		parsedURL, err := url.Parse(target)
		if err != nil {
			continue
		}

		parsedURL.Path = endpoint
		apiURL := parsedURL.String()

		// Create a new request
		req, err := http.NewRequest("POST", apiURL, strings.NewReader("{}"))
		if err != nil {
			continue
		}

		// Add headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		// Add cookies
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		// Send request with proper error handling
		resp, err := cs.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Read the response body
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response contains a CSRF token error message
		csrfErrorPatterns := []string{
			"csrf",
			"token",
			"mismatch",
			"invalid",
			"missing",
			"419",
		}

		csrfErrorFound := false
		for _, pattern := range csrfErrorPatterns {
			if strings.Contains(strings.ToLower(bodyString), pattern) {
				csrfErrorFound = true
				break
			}
		}

		// If no CSRF error is found and the response is a success (2xx), it might indicate a CSRF vulnerability
		if !csrfErrorFound && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &common.ScanResult{
				ScanName:    cs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential CSRF vulnerability in API endpoint",
				Path:        apiURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The API endpoint %s might not be properly protected against CSRF attacks.", apiURL),
			}
		}
	}

	return nil
}

func (cs *CSRFBypassScanner) Name() string {
	return "CSRF Bypass Scanner"
}
