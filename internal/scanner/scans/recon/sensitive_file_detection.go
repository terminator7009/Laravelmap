package recon

import (
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"strings"
	"time"
)

// SensitiveFileDetectionScan is a struct that contains an HTTP client
type SensitiveFileDetectionScan struct {
	client *httpclient.Client
}

// NewSensitiveFileDetectionScan initializes and returns a new SensitiveFileDetectionScan instance
func NewSensitiveFileDetectionScan() *SensitiveFileDetectionScan {
	return &SensitiveFileDetectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks for sensitive files on the target Laravel application
func (sfds *SensitiveFileDetectionScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// List of sensitive files to check
	sensitiveFiles := []string{
		"/.env",
		"/.env.backup",
		"/.env.old",
		"/.env.save",
		"/.env.example",
		"/storage/logs/laravel.log",
		"/storage/framework/sessions/",
		"/storage/framework/cache/",
		"/composer.json",
		"/composer.lock",
		"/package.json",
		"/package-lock.json",
		"/yarn.lock",
		"/webpack.mix.js",
		"/artisan",
		"/config/app.php",
		"/config/database.php",
		"/config/mail.php",
		"/config/services.php",
		"/vendor/composer/installed.json",
		"/vendor/composer/autoload_classmap.php",
		"/public/phpinfo.php",
		"/public/info.php",
		"/public/test.php",
		"/public/web.config",
		"/public/.htaccess",
		"/storage/.htaccess",
		"/bootstrap/cache/.htaccess",
	}

	for _, file := range sensitiveFiles {
		url := strings.TrimRight(target, "/") + file
		resp, err := sfds.client.Get(url, nil)
		if err != nil {
			continue // Skip if there's an error
		}
		defer resp.Body.Close()

		// Check if the file exists (status code 200)
		if resp.StatusCode == 200 {
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			body := string(bodyBytes)

			// Check if the response is not empty and looks like the expected file
			if len(body) > 0 && sfds.isRelevantContent(file, body) {
				results = append(results, common.ScanResult{
					ScanName:    sfds.Name(),
					Category:    "Recon",
					Description: fmt.Sprintf("Sensitive file found: %s", file),
					Path:        file,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The sensitive file %s is publicly accessible. This could expose configuration details, credentials, or other sensitive information.", file),
				})
			}
		}
	}

	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    sfds.Name(),
			Category:    "Recon",
			Description: "No sensitive files found",
			Path:        target,
			StatusCode:  0,
		})
	}

	return results
}

// isRelevantContent checks if the content appears to be relevant for the given file
func (sfds *SensitiveFileDetectionScan) isRelevantContent(file, content string) bool {
	// Different checks based on file type
	switch {
	case strings.Contains(file, ".env"):
		return strings.Contains(content, "APP_") || strings.Contains(content, "DB_") || strings.Contains(content, "MAIL_")
	case strings.Contains(file, "composer.json"):
		return strings.Contains(content, "require") || strings.Contains(content, "laravel/framework")
	case strings.Contains(file, "package.json"):
		return strings.Contains(content, "dependencies") || strings.Contains(content, "devDependencies")
	case strings.Contains(file, "laravel.log"):
		return strings.Contains(content, "Laravel") || strings.Contains(content, "production.ERROR") || strings.Contains(content, "local.ERROR")
	case strings.Contains(file, "app.php"):
		return strings.Contains(content, "providers") || strings.Contains(content, "aliases")
	case strings.Contains(file, "database.php"):
		return strings.Contains(content, "connections") || strings.Contains(content, "mysql") || strings.Contains(content, "pgsql")
	case strings.Contains(file, "phpinfo.php") || strings.Contains(file, "info.php"):
		return strings.Contains(content, "PHP Version") || strings.Contains(content, "phpinfo()")
	default:
		return true // For other files, assume content is relevant if the file exists
	}
}

// Name returns the name of the scan
func (sfds *SensitiveFileDetectionScan) Name() string {
	return "Sensitive File Detection"
}