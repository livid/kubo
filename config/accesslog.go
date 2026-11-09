package config

// AccessLog configures local JSON HTTP request logs for a daemon listener.
// A nil configuration or Enabled=false leaves logging disabled.
type AccessLog struct {
	Enabled        bool
	Path           string
	MaxSizeMB      int
	MaxBackups     int
	MaxAgeDays     int
	TrustedProxies []string
}
