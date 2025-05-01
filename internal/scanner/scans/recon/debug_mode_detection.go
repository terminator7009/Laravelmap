package recon

import (
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"strings"
	"time"
)

// DebugModeDetectionScan is a struct that contains an HTTP client
type DebugModeDetectionScan struct {
	client *httpclient.Client
}

// NewDebugModeDetectionScan initializes and returns a new DebugModeDetectionScan instance
func NewDebugModeDetectionScan() *DebugModeDetectionScan {
	return &DebugModeDetectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks if debug mode is enabled on the target Laravel application
func (dmds *DebugModeDetectionScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// List of paths to check for debug mode indicators
	paths := []string{
		"/",
		"/index.php",
		"/api",
		"/debug",
	}

	for _, path := range paths {
		url := strings.TrimRight(target, "/") + path
		resp, err := dmds.client.Get(url, nil)
		if err != nil {
			results = append(results, common.ScanResult{
				ScanName:    dmds.Name(),
				Category:    "Recon",
				Description: fmt.Sprintf("Failed to make request to %s", url),
				Path:        path,
				StatusCode:  0,
				Detail:      err.Error(),
			})
			continue
		}
		defer resp.Body.Close()

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			results = append(results, common.ScanResult{
				ScanName:    dmds.Name(),
				Category:    "Recon",
				Description: fmt.Sprintf("Failed to read response body from %s", url),
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      err.Error(),
			})
			continue
		}
		body := string(bodyBytes)

		// Check for debug mode indicators in the response
		debugIndicators := []string{
			"<title>Laravel - The PHP Framework For Web Artisans</title>",
			"<div class=\"container\">",
			"Whoops, looks like something went wrong.",
			"Stack trace:",
			"ErrorException",
			"vendor/laravel/framework",
			"Illuminate\\",
			"APP_DEBUG",
			"APP_ENV",
			"DB_USERNAME",
			"DB_PASSWORD",
		}

		for _, indicator := range debugIndicators {
			if strings.Contains(body, indicator) {
				results = append(results, common.ScanResult{
					ScanName:    dmds.Name(),
					Category:    "Recon",
					Description: fmt.Sprintf("Debug mode indicator found: %s", indicator),
					Path:        path,
					StatusCode:  resp.StatusCode,
					Detail:      fmt.Sprintf("The application appears to be in debug mode. This can expose sensitive information such as environment variables, database credentials, and stack traces."),
				})
				break
			}
		}
	}

	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    dmds.Name(),
			Category:    "Recon",
			Description: "No debug mode indicators found",
			Path:        target,
			StatusCode:  0,
		})
	}

	return results
}

// Name returns the name of the scan
func (dmds *DebugModeDetectionScan) Name() string {
	return "Debug Mode Detection"
}