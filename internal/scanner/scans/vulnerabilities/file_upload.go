package vulnerabilities

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// FileUploadScanner is a struct that contains an HTTP client for detecting file upload vulnerabilities
type FileUploadScanner struct {
	client *httpclient.Client
}

// NewFileUploadScanner initializes and returns a new FileUploadScanner instance
func NewFileUploadScanner() *FileUploadScanner {
	return &FileUploadScanner{
		client: httpclient.NewClient(15 * time.Second),
	}
}

// Run checks for file upload vulnerabilities in Laravel applications
func (fs *FileUploadScanner) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// Find upload forms
	uploadForms := fs.findUploadForms(target)
	if len(uploadForms) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    fs.Name(),
			Category:    "Vulnerabilities",
			Description: "No file upload forms found",
			Path:        target,
			StatusCode:  0,
			Detail:      "No file upload forms were found on the target. This scan requires file upload functionality to test.",
		})
		return results
	}

	// Test each upload form for vulnerabilities
	for _, form := range uploadForms {
		// Test for file extension bypass
		extensionBypassResults := fs.testFileExtensionBypass(form)
		results = append(results, extensionBypassResults...)

		// Test for content type bypass
		contentTypeBypassResults := fs.testContentTypeBypass(form)
		results = append(results, contentTypeBypassResults...)

		// Test for null byte injection
		nullByteResults := fs.testNullByteInjection(form)
		results = append(results, nullByteResults...)

		// Test for double extension
		doubleExtensionResults := fs.testDoubleExtension(form)
		results = append(results, doubleExtensionResults...)

		// Test for large file upload
		largeFileResults := fs.testLargeFileUpload(form)
		results = append(results, largeFileResults...)
	}

	// If no vulnerabilities were detected
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    fs.Name(),
			Category:    "Vulnerabilities",
			Description: "No file upload vulnerabilities detected",
			Path:        target,
			StatusCode:  0,
			Detail:      "File upload functionality appears to be properly implemented and secured.",
		})
	}

	return results
}

// UploadForm represents an HTML form with file upload capability
type uploadForm struct {
	action      string
	method      string
	fileField   string
	otherFields map[string]string
	csrfToken   string
}

// findUploadForms finds HTML forms with file upload fields
func (fs *FileUploadScanner) findUploadForms(target string) []uploadForm {
	var forms []uploadForm

	// Send a GET request to the target
	resp, err := fs.client.Get(target, nil)
	if err != nil {
		return forms
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return forms
	}
	bodyString := string(bodyBytes)

	// Find all forms with enctype="multipart/form-data" or input type="file"
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

		// Check if form has file upload capability
		fileInputPattern := `<input[^>]*type="file"[^>]*name="([^"]*)"[^>]*>`
		fileInputRegex := regexp.MustCompile(fileInputPattern)
		fileInputMatches := fileInputRegex.FindStringSubmatch(formContent)

		if len(fileInputMatches) < 2 {
			continue
		}

		fileField := fileInputMatches[1]

		// If action is relative, make it absolute
		if !strings.HasPrefix(action, "http") {
			parsedURL, err := url.Parse(target)
			if err != nil {
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

		// Find all other input fields
		otherFields := make(map[string]string)
		inputPattern := `<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"`
		inputRegex := regexp.MustCompile(inputPattern)
		inputMatches := inputRegex.FindAllStringSubmatch(formContent, -1)

		var csrfToken string
		for _, inputMatch := range inputMatches {
			if len(inputMatch) < 3 {
				continue
			}

			name := inputMatch[1]
			value := inputMatch[2]

			// Skip file input
			if name == fileField {
				continue
			}

			// Check if this is a CSRF token
			if name == "_token" || name == "csrf_token" {
				csrfToken = value
			}

			otherFields[name] = value
		}

		forms = append(forms, uploadForm{
			action:      action,
			method:      method,
			fileField:   fileField,
			otherFields: otherFields,
			csrfToken:   csrfToken,
		})
	}

	return forms
}

// testFileExtensionBypass tests if dangerous file extensions can be uploaded
func (fs *FileUploadScanner) testFileExtensionBypass(form uploadForm) []common.ScanResult {
	var results []common.ScanResult

	// List of dangerous file types to test
	dangerousFiles := []struct {
		filename    string
		content     string
		contentType string
		description string
	}{
		{
			filename:    "test.php",
			content:     "<?php echo 'LaravelScan File Upload Test'; ?>",
			contentType: "application/x-php",
			description: "PHP file upload",
		},
		{
			filename:    "test.phtml",
			content:     "<?php echo 'LaravelScan File Upload Test'; ?>",
			contentType: "application/x-php",
			description: "PHTML file upload",
		},
		{
			filename:    "test.php5",
			content:     "<?php echo 'LaravelScan File Upload Test'; ?>",
			contentType: "application/x-php",
			description: "PHP5 file upload",
		},
		{
			filename:    "test.php.jpg",
			content:     "<?php echo 'LaravelScan File Upload Test'; ?>",
			contentType: "image/jpeg",
			description: "PHP file disguised as JPG",
		},
		{
			filename:    "test.js",
			content:     "alert('LaravelScan File Upload Test');",
			contentType: "application/javascript",
			description: "JavaScript file upload",
		},
		{
			filename:    "test.html",
			content:     "<script>alert('LaravelScan File Upload Test');</script>",
			contentType: "text/html",
			description: "HTML file upload",
		},
	}

	// Test each dangerous file type
	for _, dangerousFile := range dangerousFiles {
		resp, err := fs.uploadFile(form, dangerousFile.filename, dangerousFile.content, dangerousFile.contentType)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check if the upload was successful
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		bodyString := string(bodyBytes)

		// Check for successful upload indicators
		successPatterns := []string{
			"success",
			"uploaded",
			"complete",
			"file",
			"saved",
			"stored",
		}

		// Check for error indicators
		errorPatterns := []string{
			"invalid",
			"not allowed",
			"forbidden",
			"error",
			"failed",
			"denied",
		}

		successFound := false
		for _, pattern := range successPatterns {
			if strings.Contains(strings.ToLower(bodyString), pattern) {
				successFound = true
				break
			}
		}

		errorFound := false
		for _, pattern := range errorPatterns {
			if strings.Contains(strings.ToLower(bodyString), pattern) {
				errorFound = true
				break
			}
		}

		// If success indicators are found and no error indicators, it might be a vulnerability
		if (successFound && !errorFound) || resp.StatusCode == 200 || resp.StatusCode == 302 {
			results = append(results, common.ScanResult{
				ScanName:    fs.Name(),
				Category:    "Vulnerabilities",
				Description: fmt.Sprintf("Potential file upload vulnerability: %s", dangerousFile.description),
				Path:        form.action,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The application might allow uploading of dangerous file type: %s", dangerousFile.filename),
			})
		}
	}

	return results
}

// testContentTypeBypass tests if content type validation can be bypassed
func (fs *FileUploadScanner) testContentTypeBypass(form uploadForm) []common.ScanResult {
	var results []common.ScanResult

	// PHP file with image content type
	filename := "malicious.php"
	content := "<?php echo 'LaravelScan File Upload Test'; ?>"
	contentType := "image/jpeg" // Mismatched content type

	resp, err := fs.uploadFile(form, filename, content, contentType)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	// Check if the upload was successful
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return results
	}
	bodyString := string(bodyBytes)

	// Check for successful upload indicators
	successPatterns := []string{
		"success",
		"uploaded",
		"complete",
		"file",
		"saved",
		"stored",
	}

	// Check for error indicators
	errorPatterns := []string{
		"invalid",
		"not allowed",
		"forbidden",
		"error",
		"failed",
		"denied",
	}

	successFound := false
	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(bodyString), pattern) {
			successFound = true
			break
		}
	}

	errorFound := false
	for _, pattern := range errorPatterns {
		if strings.Contains(strings.ToLower(bodyString), pattern) {
			errorFound = true
			break
		}
	}

	// If success indicators are found and no error indicators, it might be a vulnerability
	if (successFound && !errorFound) || resp.StatusCode == 200 || resp.StatusCode == 302 {
		results = append(results, common.ScanResult{
			ScanName:    fs.Name(),
			Category:    "Vulnerabilities",
			Description: "Potential content type bypass vulnerability",
			Path:        form.action,
			StatusCode:  resp.StatusCode,
			Detail:      "The application might rely only on Content-Type validation, which can be easily bypassed.",
		})
	}

	return results
}

// testNullByteInjection tests if null byte injection can be used to bypass file extension validation
func (fs *FileUploadScanner) testNullByteInjection(form uploadForm) []common.ScanResult {
	var results []common.ScanResult

	// PHP file with null byte and allowed extension
	filename := "malicious.php\x00.jpg"
	content := "<?php echo 'LaravelScan File Upload Test'; ?>"
	contentType := "image/jpeg"

	resp, err := fs.uploadFile(form, filename, content, contentType)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	// Check if the upload was successful
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return results
	}
	bodyString := string(bodyBytes)

	// Check for successful upload indicators
	successPatterns := []string{
		"success",
		"uploaded",
		"complete",
		"file",
		"saved",
		"stored",
	}

	// Check for error indicators
	errorPatterns := []string{
		"invalid",
		"not allowed",
		"forbidden",
		"error",
		"failed",
		"denied",
	}

	successFound := false
	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(bodyString), pattern) {
			successFound = true
			break
		}
	}

	errorFound := false
	for _, pattern := range errorPatterns {
		if strings.Contains(strings.ToLower(bodyString), pattern) {
			errorFound = true
			break
		}
	}

	// If success indicators are found and no error indicators, it might be a vulnerability
	if (successFound && !errorFound) || resp.StatusCode == 200 || resp.StatusCode == 302 {
		results = append(results, common.ScanResult{
			ScanName:    fs.Name(),
			Category:    "Vulnerabilities",
			Description: "Potential null byte injection vulnerability",
			Path:        form.action,
			StatusCode:  resp.StatusCode,
			Detail:      "The application might be vulnerable to null byte injection in file names.",
		})
	}

	return results
}

// testDoubleExtension tests if double extension can be used to bypass file extension validation
func (fs *FileUploadScanner) testDoubleExtension(form uploadForm) []common.ScanResult {
	var results []common.ScanResult

	// PHP file with double extension
	filename := "malicious.jpg.php"
	content := "<?php echo 'LaravelScan File Upload Test'; ?>"
	contentType := "image/jpeg"

	resp, err := fs.uploadFile(form, filename, content, contentType)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	// Check if the upload was successful
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return results
	}
	bodyString := string(bodyBytes)

	// Check for successful upload indicators
	successPatterns := []string{
		"success",
		"uploaded",
		"complete",
		"file",
		"saved",
		"stored",
	}

	// Check for error indicators
	errorPatterns := []string{
		"invalid",
		"not allowed",
		"forbidden",
		"error",
		"failed",
		"denied",
	}

	successFound := false
	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(bodyString), pattern) {
			successFound = true
			break
		}
	}

	errorFound := false
	for _, pattern := range errorPatterns {
		if strings.Contains(strings.ToLower(bodyString), pattern) {
			errorFound = true
			break
		}
	}

	// If success indicators are found and no error indicators, it might be a vulnerability
	if (successFound && !errorFound) || resp.StatusCode == 200 || resp.StatusCode == 302 {
		results = append(results, common.ScanResult{
			ScanName:    fs.Name(),
			Category:    "Vulnerabilities",
			Description: "Potential double extension vulnerability",
			Path:        form.action,
			StatusCode:  resp.StatusCode,
			Detail:      "The application might be vulnerable to double extension bypass in file names.",
		})
	}

	return results
}

// testLargeFileUpload tests if the application properly validates file size
func (fs *FileUploadScanner) testLargeFileUpload(form uploadForm) []common.ScanResult {
	var results []common.ScanResult

	// Create a large file (5MB)
	content := strings.Repeat("A", 5*1024*1024)
	filename := "large_file.jpg"
	contentType := "image/jpeg"

	resp, err := fs.uploadFile(form, filename, content, contentType)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	// Check if the upload was successful
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return results
	}
	bodyString := string(bodyBytes)

	// Check for successful upload indicators
	successPatterns := []string{
		"success",
		"uploaded",
		"complete",
		"file",
		"saved",
		"stored",
	}

	// Check for error indicators related to file size
	sizeErrorPatterns := []string{
		"size",
		"too large",
		"exceeds",
		"limit",
		"max",
	}

	successFound := false
	for _, pattern := range successPatterns {
		if strings.Contains(strings.ToLower(bodyString), pattern) {
			successFound = true
			break
		}
	}

	sizeErrorFound := false
	for _, pattern := range sizeErrorPatterns {
		if strings.Contains(strings.ToLower(bodyString), pattern) {
			sizeErrorFound = true
			break
		}
	}

	// If success indicators are found and no size error indicators, it might be a vulnerability
	if (successFound && !sizeErrorFound) || resp.StatusCode == 200 || resp.StatusCode == 302 {
		results = append(results, common.ScanResult{
			ScanName:    fs.Name(),
			Category:    "Vulnerabilities",
			Description: "Potential large file upload vulnerability",
			Path:        form.action,
			StatusCode:  resp.StatusCode,
			Detail:      "The application might not properly validate file size, which could lead to denial of service.",
		})
	}

	return results
}

// uploadFile uploads a file to the specified form
func (fs *FileUploadScanner) uploadFile(form uploadForm, filename, content string, contentType string) (*http.Response, error) {
	// Create a buffer to write our multipart form
	var requestBody bytes.Buffer
	multipartWriter := multipart.NewWriter(&requestBody)

	// Add other form fields
	for name, value := range form.otherFields {
		err := multipartWriter.WriteField(name, value)
		if err != nil {
			return nil, err
		}
	}

	// Add CSRF token if available
	if form.csrfToken != "" {
		err := multipartWriter.WriteField("_token", form.csrfToken)
		if err != nil {
			return nil, err
		}
	}

	// Add the file
	fileWriter, err := multipartWriter.CreateFormFile(form.fileField, filename)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(fileWriter, strings.NewReader(content))
	if err != nil {
		return nil, err
	}

	// Close the multipart writer
	err = multipartWriter.Close()
	if err != nil {
		return nil, err
	}

	// Create a new request
	req, err := http.NewRequest(form.method, form.action, &requestBody)
	if err != nil {
		return nil, err
	}

	// Set the content type
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	// Set the MIME type
	req.Header.Set("Content-Type", contentType)

	// Send the request
	return fs.client.Do(req)
}

func (fs *FileUploadScanner) Name() string {
	return "File Upload Vulnerability Scanner"
}
