package recon

import (
	"fmt"
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"regexp"
	"strings"
	"time"
)

// VersionDetectionScan is a struct that contains an HTTP client
type VersionDetectionScan struct {
	client *httpclient.Client
}

// NewVersionDetectionScan initializes and returns a new VersionDetectionScan instance
func NewVersionDetectionScan() *VersionDetectionScan {
	return &VersionDetectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run detects the Laravel version of the target application
func (vds *VersionDetectionScan) Run(target string) []common.ScanResult {
	var results []common.ScanResult

	// List of paths to check for version information
	paths := []string{
		"/",
		"/login",
		"/register",
		"/home",
		"/api",
	}

	for _, path := range paths {
		url := strings.TrimRight(target, "/") + path
		resp, err := vds.client.Get(url, nil)
		if err != nil {
			continue // Skip if there's an error
		}
		defer resp.Body.Close()

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		body := string(bodyBytes)

		// Check for Laravel version in HTML comments, meta tags, or JavaScript files
		version := vds.extractLaravelVersion(body)
		if version != "" {
			results = append(results, common.ScanResult{
				ScanName:    vds.Name(),
				Category:    "Recon",
				Description: fmt.Sprintf("Laravel version detected: %s", version),
				Path:        path,
				StatusCode:  resp.StatusCode,
				Detail:      fmt.Sprintf("The Laravel version %s was detected. Check for known vulnerabilities in this version.", version),
			})
			break // Found a version, no need to check other paths
		}

		// Check for Laravel-specific CSS or JS files
		jsFiles := vds.extractJavaScriptFiles(body)
		for _, jsFile := range jsFiles {
			jsURL := vds.resolveURL(target, jsFile)
			jsResp, err := vds.client.Get(jsURL, nil)
			if err != nil {
				continue
			}
			defer jsResp.Body.Close()

			jsBodyBytes, err := ioutil.ReadAll(jsResp.Body)
			if err != nil {
				continue
			}
			jsBody := string(jsBodyBytes)

			version := vds.extractLaravelVersion(jsBody)
			if version != "" {
				results = append(results, common.ScanResult{
					ScanName:    vds.Name(),
					Category:    "Recon",
					Description: fmt.Sprintf("Laravel version detected: %s (from JS file)", version),
					Path:        jsFile,
					StatusCode:  jsResp.StatusCode,
					Detail:      fmt.Sprintf("The Laravel version %s was detected in a JavaScript file. Check for known vulnerabilities in this version.", version),
				})
				break // Found a version, no need to check other JS files
			}
		}

		if len(results) > 0 {
			break // Found a version, no need to check other paths
		}
	}

	// If no version was detected, check for Laravel-specific files
	if len(results) == 0 {
		laravelFiles := []string{
			"/vendor/laravel/framework/src/Illuminate/Foundation/Application.php",
			"/vendor/composer/installed.json",
			"/composer.lock",
			"/composer.json",
		}

		for _, file := range laravelFiles {
			url := strings.TrimRight(target, "/") + file
			resp, err := vds.client.Get(url, nil)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					continue
				}
				body := string(bodyBytes)

				version := vds.extractLaravelVersion(body)
				if version != "" {
					results = append(results, common.ScanResult{
						ScanName:    vds.Name(),
						Category:    "Recon",
						Description: fmt.Sprintf("Laravel version detected: %s (from %s)", version, file),
						Path:        file,
						StatusCode:  resp.StatusCode,
						Detail:      fmt.Sprintf("The Laravel version %s was detected in %s. Check for known vulnerabilities in this version.", version, file),
					})
					break
				}
			}
		}
	}

	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    vds.Name(),
			Category:    "Recon",
			Description: "Laravel version could not be determined",
			Path:        target,
			StatusCode:  0,
			Detail:      "The Laravel version could not be determined from the available information.",
		})
	}

	return results
}

// extractLaravelVersion attempts to extract the Laravel version from the content
func (vds *VersionDetectionScan) extractLaravelVersion(content string) string {
	// Regular expressions to match Laravel version patterns
	patterns := []string{
		`Laravel\s+v?(\d+\.\d+\.\d+)`,
		`"laravel/framework"\s*:\s*"v?(\d+\.\d+\.\d+)`,
		`"version"\s*:\s*"v?(\d+\.\d+\.\d+)`,
		`Laravel\s+Framework\s+v?(\d+\.\d+\.\d+)`,
		`Illuminate\\Foundation\\Application::VERSION\s*=\s*['"]v?(\d+\.\d+\.\d+)['"]`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// extractJavaScriptFiles extracts JavaScript file paths from HTML content
func (vds *VersionDetectionScan) extractJavaScriptFiles(content string) []string {
	var jsFiles []string
	re := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["'][^>]*>`)
	matches := re.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			jsFiles = append(jsFiles, match[1])
		}
	}

	return jsFiles
}

// resolveURL resolves a relative URL against a base URL
func (vds *VersionDetectionScan) resolveURL(baseURL, relativeURL string) string {
	if strings.HasPrefix(relativeURL, "http://") || strings.HasPrefix(relativeURL, "https://") {
		return relativeURL
	}

	if strings.HasPrefix(relativeURL, "/") {
		// Absolute path
		baseURL = strings.TrimRight(baseURL, "/")
		return baseURL + relativeURL
	}

	// Relative path
	baseURL = strings.TrimRight(baseURL, "/") + "/"
	return baseURL + relativeURL
}

// Name returns the name of the scan
func (vds *VersionDetectionScan) Name() string {
	return "Laravel Version Detection"
}