package recon

import (
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"strings"
	"time"
)

type PhpVersionScan struct {
	client *httpclient.Client
}

func NewPhpVersionScan() *PhpVersionScan {
	return &PhpVersionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks if the X-Powered-By header is present in the response and returns a slice of ScanResult
func (pvs *PhpVersionScan) Run(target string) []common.ScanResult {
	headers := map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	}

	resp, err := pvs.client.Get(target, headers)
	if err != nil {
		return []common.ScanResult{
			{
				ScanName:    pvs.Name(),
				Category:    "Recon",
				Description: "Failed to make request",
				Path:        target,
				StatusCode:  0,
				Detail:      err.Error(),
			},
		}
	}
	defer resp.Body.Close()

	var results []common.ScanResult

	// Check if the X-Powered-By header is present
	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" && strings.Contains(xPoweredBy, "PHP") {
		results = append(results, common.ScanResult{
			ScanName:    pvs.Name(),
			Category:    "Recon",
			Description: "X-Powered-By header found",
			Path:        target,
			StatusCode:  resp.StatusCode,
			Detail:      xPoweredBy,
		})
	} else {
		results = append(results, common.ScanResult{
			ScanName:    pvs.Name(),
			Category:    "Recon",
			Description: "X-Powered-By header not found",
			Path:        target,
			StatusCode:  resp.StatusCode,
		})
	}

	return results
}

// Name returns the name of the scan
func (pvs *PhpVersionScan) Name() string {
	return "PHP Version Scan"
}
