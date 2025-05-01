package recon

import (
	"io/ioutil"
	"laravelmap/internal/common"
	"laravelmap/pkg/httpclient"
	"regexp"
	"strings"
	"time"
)

// FrameworkDetectionScan is a struct that contains an HTTP client
type FrameworkDetectionScan struct {
	client *httpclient.Client
}

// NewFrameworkDetectionScan initializes and returns a new FrameworkDetectionScan instance
func NewFrameworkDetectionScan() *FrameworkDetectionScan {
	return &FrameworkDetectionScan{
		client: httpclient.NewClient(10 * time.Second),
	}
}

// Run checks for signs of the Laravel framework in the response
func (fds *FrameworkDetectionScan) Run(target string) []common.ScanResult {
	headers := map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	}

	resp, err := fds.client.Get(target, headers)
	if err != nil {
		return []common.ScanResult{
			{
				ScanName:    fds.Name(),
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

	// Read the response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		results = append(results, common.ScanResult{
			ScanName:    fds.Name(),
			Category:    "Recon",
			Description: "Failed to read response body",
			Path:        target,
			StatusCode:  resp.StatusCode,
			Detail:      err.Error(),
		})
		return results
	}
	bodyString := string(bodyBytes)

	// Check for Laravel-specific headers
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" && strings.Contains(poweredBy, "PHP") {
		results = append(results, common.ScanResult{
			ScanName:    fds.Name(),
			Category:    "Recon",
			Description: "Possible Laravel framework detected via X-Powered-By header",
			Path:        target,
			StatusCode:  resp.StatusCode,
			Detail:      poweredBy,
		})
	}

	// Check for Laravel-specific cookies
	for _, cookie := range resp.Cookies() {
		if strings.Contains(strings.ToLower(cookie.Name), "laravel") {
			results = append(results, common.ScanResult{
				ScanName:    fds.Name(),
				Category:    "Recon",
				Description: "Laravel framework detected via cookie name",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      cookie.Name,
			})
		}
		if strings.Contains(strings.ToLower(cookie.Name), "xsrf-token") {
			results = append(results, common.ScanResult{
				ScanName:    fds.Name(),
				Category:    "Recon",
				Description: "Possible Laravel framework detected via XSRF-TOKEN cookie",
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      cookie.Name,
			})
		}
	}

	// Check for Laravel-specific HTML patterns
	laravelPatterns := []struct {
		pattern     string
		description string
	}{
		{`<meta name="csrf-token" content="[^"]+">`, "Laravel CSRF token meta tag"},
		{`laravel[^"']*\.js`, "Laravel JavaScript file reference"},
		{`laravel[^"']*\.css`, "Laravel CSS file reference"},
		{`/vendor/laravel/`, "Laravel vendor path"},
		{`Illuminate\\`, "Laravel Illuminate namespace reference"},
		{`\bstorage/framework\b`, "Laravel storage framework path"},
		{`\bstorage/logs\b`, "Laravel logs path"},
		{`\bbootstrap/cache\b`, "Laravel bootstrap cache path"},
		{`\bapp/Http/Controllers\b`, "Laravel controllers path"},
		{`\bapp/Http/Middleware\b`, "Laravel middleware path"},
		{`\bapp/Providers\b`, "Laravel providers path"},
		{`\bconfig/app.php\b`, "Laravel config file"},
		{`\bdatabase/migrations\b`, "Laravel migrations path"},
		{`\bpublic/index.php\b`, "Laravel public index file"},
		{`\broutes/web.php\b`, "Laravel routes file"},
		{`\bapp/Models\b`, "Laravel models path"},
		{`\bapp/Exceptions\b`, "Laravel exceptions path"},
		{`\bapp/Console\b`, "Laravel console path"},
		{`\bapp/Events\b`, "Laravel events path"},
		{`\bapp/Listeners\b`, "Laravel listeners path"},
		{`\bapp/Jobs\b`, "Laravel jobs path"},
		{`\bapp/Mail\b`, "Laravel mail path"},
		{`\bapp/Notifications\b`, "Laravel notifications path"},
		{`\bapp/Policies\b`, "Laravel policies path"},
		{`\bapp/Rules\b`, "Laravel rules path"},
		{`\bapp/Services\b`, "Laravel services path"},
		{`\bapp/Traits\b`, "Laravel traits path"},
		{`\bapp/View\b`, "Laravel view path"},
		{`\bLaravel\b`, "Laravel keyword"},
		{`\bIlluminate\b`, "Laravel Illuminate keyword"},
		{`\bArtisan\b`, "Laravel Artisan keyword"},
		{`\bEloquent\b`, "Laravel Eloquent keyword"},
		{`\bBlade\b`, "Laravel Blade keyword"},
		{`\bTinker\b`, "Laravel Tinker keyword"},
		{`\bMigration\b`, "Laravel Migration keyword"},
		{`\bSeeder\b`, "Laravel Seeder keyword"},
		{`\bFactory\b`, "Laravel Factory keyword"},
		{`\bMiddleware\b`, "Laravel Middleware keyword"},
		{`\bController\b`, "Laravel Controller keyword"},
		{`\bProvider\b`, "Laravel Provider keyword"},
		{`\bRequest\b`, "Laravel Request keyword"},
		{`\bResponse\b`, "Laravel Response keyword"},
		{`\bRoute\b`, "Laravel Route keyword"},
		{`\bView\b`, "Laravel View keyword"},
		{`\bModel\b`, "Laravel Model keyword"},
		{`\bCollection\b`, "Laravel Collection keyword"},
		{`\bAuth\b`, "Laravel Auth keyword"},
		{`\bSession\b`, "Laravel Session keyword"},
		{`\bCache\b`, "Laravel Cache keyword"},
		{`\bQueue\b`, "Laravel Queue keyword"},
		{`\bEvent\b`, "Laravel Event keyword"},
		{`\bListener\b`, "Laravel Listener keyword"},
		{`\bNotification\b`, "Laravel Notification keyword"},
		{`\bMail\b`, "Laravel Mail keyword"},
		{`\bJob\b`, "Laravel Job keyword"},
		{`\bPolicy\b`, "Laravel Policy keyword"},
		{`\bRule\b`, "Laravel Rule keyword"},
		{`\bService\b`, "Laravel Service keyword"},
		{`\bTrait\b`, "Laravel Trait keyword"},
		{`\bException\b`, "Laravel Exception keyword"},
		{`\bConsole\b`, "Laravel Console keyword"},
		{`\bCommand\b`, "Laravel Command keyword"},
		{`\bSchedule\b`, "Laravel Schedule keyword"},
		{`\bBroadcast\b`, "Laravel Broadcast keyword"},
		{`\bChannel\b`, "Laravel Channel keyword"},
		{`\bPresence\b`, "Laravel Presence keyword"},
		{`\bNotifiable\b`, "Laravel Notifiable keyword"},
		{`\bMailable\b`, "Laravel Mailable keyword"},
		{`\bDispatchable\b`, "Laravel Dispatchable keyword"},
		{`\bQueueable\b`, "Laravel Queueable keyword"},
		{`\bSerializable\b`, "Laravel Serializable keyword"},
		{`\bAuthenticatable\b`, "Laravel Authenticatable keyword"},
		{`\bAuthorizable\b`, "Laravel Authorizable keyword"},
		{`\bCanResetPassword\b`, "Laravel CanResetPassword keyword"},
		{`\bMustVerifyEmail\b`, "Laravel MustVerifyEmail keyword"},
		{`\bNotificationChannels\b`, "Laravel NotificationChannels keyword"},
		{`\bNotifications\b`, "Laravel Notifications keyword"},
		{`\bEvents\b`, "Laravel Events keyword"},
		{`\bJobs\b`, "Laravel Jobs keyword"},
		{`\bListeners\b`, "Laravel Listeners keyword"},
		{`\bPolicies\b`, "Laravel Policies keyword"},
		{`\bRules\b`, "Laravel Rules keyword"},
		{`\bServices\b`, "Laravel Services keyword"},
		{`\bTraits\b`, "Laravel Traits keyword"},
		{`\bExceptions\b`, "Laravel Exceptions keyword"},
		{`\bCommands\b`, "Laravel Commands keyword"},
		{`\bSchedules\b`, "Laravel Schedules keyword"},
		{`\bBroadcasts\b`, "Laravel Broadcasts keyword"},
		{`\bChannels\b`, "Laravel Channels keyword"},
		{`\bPresences\b`, "Laravel Presences keyword"},
		{`\bNotifiables\b`, "Laravel Notifiables keyword"},
		{`\bMailables\b`, "Laravel Mailables keyword"},
		{`\bDispatchables\b`, "Laravel Dispatchables keyword"},
		{`\bQueueables\b`, "Laravel Queueables keyword"},
		{`\bSerializables\b`, "Laravel Serializables keyword"},
		{`\bAuthenticatables\b`, "Laravel Authenticatables keyword"},
		{`\bAuthorizables\b`, "Laravel Authorizables keyword"},
		{`\bCanResetPasswords\b`, "Laravel CanResetPasswords keyword"},
		{`\bMustVerifyEmails\b`, "Laravel MustVerifyEmails keyword"},
		{`\bNotificationChannelss\b`, "Laravel NotificationChannelss keyword"},
	}

	for _, pattern := range laravelPatterns {
		re := regexp.MustCompile(pattern.pattern)
		if re.MatchString(bodyString) {
			results = append(results, common.ScanResult{
				ScanName:    fds.Name(),
				Category:    "Recon",
				Description: "Laravel framework detected via " + pattern.description,
				Path:        target,
				StatusCode:  resp.StatusCode,
				Detail:      "Pattern: " + pattern.pattern,
			})
			break // Found one match, that's enough to confirm Laravel
		}
	}

	// Check for common Laravel paths
	laravelPaths := []string{
		"/robots.txt",
		"/favicon.ico",
		"/public/favicon.ico",
		"/public/robots.txt",
		"/storage",
		"/public/storage",
		"/public/css",
		"/public/js",
		"/public/images",
		"/public/fonts",
		"/public/vendor",
		"/public/mix-manifest.json",
		"/public/index.php",
		"/.env",
		"/.env.example",
		"/.env.backup",
		"/.env.save",
		"/artisan",
		"/server.php",
		"/composer.json",
		"/composer.lock",
		"/package.json",
		"/package-lock.json",
		"/webpack.mix.js",
		"/phpunit.xml",
		"/phpunit.xml.dist",
		"/README.md",
		"/CHANGELOG.md",
		"/LICENSE.md",
		"/CONTRIBUTING.md",
		"/CODE_OF_CONDUCT.md",
		"/SECURITY.md",
		"/UPGRADE.md",
		"/VERSIONING.md",
		"/SUPPORT.md",
		"/SPONSORS.md",
		"/BACKERS.md",
		"/FUNDING.yml",
		"/CODEOWNERS",
		"/.github",
		"/.gitlab",
		"/.gitignore",
		"/.gitattributes",
		"/.editorconfig",
		"/.styleci.yml",
		"/.travis.yml",
		"/.circleci",
		"/.scrutinizer.yml",
		"/.sensiolabs.yml",
		"/.php_cs",
		"/.php_cs.dist",
		"/.phpcs.xml",
		"/.phpcs.xml.dist",
		"/.phpunit.result.cache",
		"/.phpunit.xml",
		"/.phpunit.xml.dist",
		"/.phpstan.neon",
		"/.phpstan.neon.dist",
		"/.psalm",
		"/.psalm.xml",
		"/.psalm.xml.dist",
	}

	// We'll check the first few paths to avoid too many requests
	pathsToCheck := laravelPaths[:5]
	for _, path := range pathsToCheck {
		fullPath := target + path
		resp, err := fds.client.Get(fullPath, headers)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			results = append(results, common.ScanResult{
				ScanName:    fds.Name(),
				Category:    "Recon",
				Description: "Possible Laravel framework detected via common path",
				Path:        fullPath,
				StatusCode:  resp.StatusCode,
				Detail:      "Common Laravel path found: " + path,
			})
			break // Found one path, that's enough to suggest Laravel
		}
	}

	// If no signs of Laravel are detected, return a corresponding result
	if len(results) == 0 {
		results = append(results, common.ScanResult{
			ScanName:    fds.Name(),
			Category:    "Recon",
			Description: "Laravel framework not detected",
			Path:        target,
			StatusCode:  resp.StatusCode,
		})
	}

	return results
}

func (fds *FrameworkDetectionScan) Name() string {
	return "Framework Detection"
}
