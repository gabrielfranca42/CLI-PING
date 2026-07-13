package model

import "time"

// PingResult holds the result of a single ping to an endpoint.
type PingResult struct {
	URL        string        `json:"url"`
	StatusCode int           `json:"status_code"`
	Status     string        `json:"status"`
	Latency    time.Duration `json:"latency"`
	Alive      bool          `json:"alive"`
	Error      string        `json:"error,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
	TLSValid   bool          `json:"tls_valid"`
	TLSExpiry  time.Time     `json:"tls_expiry,omitempty"`
}

// PingOptions holds the configuration for a ping request.
type PingOptions struct {
	Timeout    time.Duration
	Method     string
	Count      int
	Interval   time.Duration
	FollowRedirects bool
	ShowHeaders     bool
}

// DefaultPingOptions returns reasonable default options.
func DefaultPingOptions() PingOptions {
	return PingOptions{
		Timeout:         10 * time.Second,
		Method:          "GET",
		Count:           1,
		Interval:        1 * time.Second,
		FollowRedirects: true,
		ShowHeaders:     false,
	}
}
