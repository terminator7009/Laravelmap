package httpclient

import (
	"io"
	"net/http"
	"time"
)

type Client struct {
	httpClient *http.Client
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) Get(url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return c.httpClient.Do(req)
}

// Post sends an HTTP POST request with the provided headers and body
func (c *Client) Post(url string, headers map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return c.httpClient.Do(req)
}

// Do executes the given HTTP request and returns the HTTP response
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}
