// Package accesslog implements the daemon's opt-in, local HTTP request journal.
// It does not inspect request/response bodies or attribute swarm traffic to RPCs.
package accesslog

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/ipfs/kubo/config"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger is shared by all listeners for one daemon service (RPC or gateway).
type Logger struct {
	mu      sync.Mutex
	writer  io.WriteCloser
	closed  bool
	lastErr time.Time
	onError func(error)
	proxies []netip.Prefix
}

// New opens a private, rotating JSONL file. Relative paths are repo-relative.
// Zero rotation limits select bounded defaults, not unlimited retention.
func New(cfg *config.AccessLog, repo, defaultName string, onError func(error)) (*Logger, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	c := *cfg
	if c.MaxSizeMB < 0 || c.MaxBackups < 0 || c.MaxAgeDays < 0 {
		return nil, fmt.Errorf("access log rotation limits must not be negative")
	}
	if c.MaxSizeMB == 0 {
		c.MaxSizeMB = 50
	}
	if c.MaxBackups == 0 {
		c.MaxBackups = 7
	}
	if c.MaxAgeDays == 0 {
		c.MaxAgeDays = 7
	}
	l := &Logger{onError: onError}
	for _, raw := range c.TrustedProxies {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("access log trusted proxy %q: %w", raw, err)
		}
		l.proxies = append(l.proxies, p)
	}
	name := c.Path
	if name == "" {
		name = defaultName
	}
	if !filepath.IsAbs(name) {
		name = filepath.Join(repo, name)
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return nil, fmt.Errorf("create access log directory: %w", err)
	}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open access log: %w", err)
	}
	info, statErr := f.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("access log must be a regular file")
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("secure access log permissions: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close initial access log: %w", err)
	}
	l.writer = &lumberjack.Logger{Filename: name, MaxSize: c.MaxSizeMB, MaxBackups: c.MaxBackups, MaxAge: c.MaxAgeDays, Compress: true}
	return l, nil
}

// Close is safe for disabled loggers and repeated calls.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.writer.Close()
}

func (l *Logger) emit(record any) {
	data, err := json.Marshal(record)
	if err == nil {
		l.mu.Lock()
		if !l.closed {
			var n int
			n, err = l.writer.Write(append(data, '\n'))
			if err == nil && n != len(data)+1 {
				err = io.ErrShortWrite
			}
		}
		l.mu.Unlock()
	}
	if err != nil {
		l.mu.Lock()
		report := time.Since(l.lastErr) >= time.Minute
		if report {
			l.lastErr = time.Now()
		}
		l.mu.Unlock()
		if report && l.onError != nil {
			l.onError(err)
		}
	}
}

type event struct {
	Type          string            `json:"type"`
	Time          time.Time         `json:"time"`
	RequestID     string            `json:"request_id"`
	Service       string            `json:"service"`
	Listener      string            `json:"listener"`
	StartedAt     time.Time         `json:"started_at"`
	Method        string            `json:"method"`
	Scheme        string            `json:"scheme"`
	Host          string            `json:"host"`
	Protocol      string            `json:"protocol"`
	Path          string            `json:"path"`
	Query         url.Values        `json:"query,omitempty"`
	RemoteAddr    string            `json:"remote_addr"`
	ClientIP      string            `json:"client_ip"`
	ClientSource  string            `json:"client_ip_source"`
	UserAgent     string            `json:"user_agent,omitempty"`
	RequestHeader map[string]string `json:"request_headers,omitempty"`
	RequestLength int64             `json:"request_content_length"`
	Result        *result           `json:"result,omitempty"`
}

type result struct {
	Status        int      `json:"status"`
	DurationMS    float64  `json:"duration_ms"`
	FirstByteMS   *float64 `json:"first_byte_ms"`
	RequestBytes  int64    `json:"request_body_bytes_read"`
	ResponseBytes int64    `json:"response_bytes"`
	Outcome       string   `json:"outcome"`
	WriteError    bool     `json:"response_write_error"`
	ContentType   string   `json:"content_type,omitempty"`
	ContentRange  string   `json:"content_range,omitempty"`
	CacheControl  string   `json:"cache_control,omitempty"`
	ETag          string   `json:"etag,omitempty"`
}

type countedBody struct {
	io.ReadCloser
	n atomic.Int64
}

func (b *countedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

// Wrap returns transparent middleware; a nil Logger returns the original handler.
// A start event is written before dispatch and a matching completion event on
// return, cancellation or panic. Bodies and sensitive RPC parameters are omitted.
func (l *Logger) Wrap(service, listener string, next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		client, source := l.client(r)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		e := event{Type: "http_request_start", Time: start.UTC(), RequestID: rand.Text(), Service: service, Listener: listener, StartedAt: start.UTC(), Method: r.Method, Scheme: scheme, Host: clip(r.Host), Protocol: r.Proto, Path: clip(r.URL.Path), Query: safeQuery(r.URL), RemoteAddr: clip(r.RemoteAddr), ClientIP: client, ClientSource: source, UserAgent: clip(r.UserAgent()), RequestLength: r.ContentLength}
		e.RequestHeader = make(map[string]string)
		for _, key := range []string{"Accept", "Content-Type", "Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
			if value := r.Header.Get(key); value != "" {
				e.RequestHeader[key] = clip(value)
			}
		}
		l.emit(e)
		body := &countedBody{ReadCloser: r.Body}
		if r.Body != nil {
			r.Body = body
		}
		var status int
		var first *float64
		var written int64
		var writeError bool
		var hijacked bool
		commit := func(code int) {
			if status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
				status = code
				ms := float64(time.Since(start)) / float64(time.Millisecond)
				first = &ms
			}
		}
		wrapped := httpsnoop.Wrap(w, httpsnoop.Hooks{
			WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(code int) { commit(code); next(code) }
			},
			Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return func(p []byte) (int, error) {
					commit(http.StatusOK)
					n, err := next(p)
					written += int64(n)
					writeError = writeError || err != nil
					return n, err
				}
			},
			ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
				return func(src io.Reader) (int64, error) {
					commit(http.StatusOK)
					n, err := next(src)
					written += n
					writeError = writeError || err != nil
					return n, err
				}
			},
			Hijack: func(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
				return func() (net.Conn, *bufio.ReadWriter, error) {
					conn, rw, err := next()
					hijacked = err == nil
					return conn, rw, err
				}
			},
			FlushError: func(next httpsnoop.FlushErrorFunc) httpsnoop.FlushErrorFunc {
				return func() error {
					commit(http.StatusOK)
					err := next()
					writeError = writeError || err != nil
					return err
				}
			},
			Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
				return func() { commit(http.StatusOK); next() }
			},
		})
		completed := false
		defer func() {
			outcome := "complete"
			switch {
			case !completed:
				outcome = "aborted"
			case r.Context().Err() != nil:
				outcome = "canceled"
			case writeError:
				outcome = "write_error"
			case hijacked:
				outcome = "hijacked"
			}
			if status == 0 && completed && !hijacked && r.Context().Err() == nil {
				status = http.StatusOK
			}
			e.Type, e.Time = "http_request_complete", time.Now().UTC()
			e.Result = &result{Status: status, DurationMS: float64(time.Since(start)) / float64(time.Millisecond), FirstByteMS: first, RequestBytes: body.n.Load(), ResponseBytes: written, Outcome: outcome, WriteError: writeError, ContentType: clip(w.Header().Get("Content-Type")), ContentRange: clip(w.Header().Get("Content-Range")), CacheControl: clip(w.Header().Get("Cache-Control")), ETag: clip(w.Header().Get("ETag"))}
			l.emit(e)
		}()
		next.ServeHTTP(wrapped, r)
		completed = true
	})
}

func clip(s string) string {
	const limit = 1024
	if len(s) > limit {
		return s[:limit] + "[truncated]"
	}
	return s
}

// Only known data-path RPCs may log arg. Config/key/pubsub arguments, arbitrary
// options and malformed or oversized queries are never copied into the log.
func safeQuery(u *url.URL) url.Values {
	if len(u.RawQuery) > 8192 {
		return url.Values{"_query": {"[omitted: too large]"}}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return url.Values{"_query": {"[omitted: malformed]"}}
	}
	argOK := slices.Contains([]string{"/api/v0/pin/add", "/api/v0/pin/rm", "/api/v0/pin/ls", "/api/v0/pin/update", "/api/v0/name/resolve", "/api/v0/resolve", "/api/v0/cat", "/api/v0/get", "/api/v0/ls", "/api/v0/refs", "/api/v0/block/get", "/api/v0/block/stat", "/api/v0/dag/get", "/api/v0/dag/stat", "/api/v0/dag/resolve", "/api/v0/dag/export", "/api/v0/files/stat"}, u.Path)
	for key, values := range q {
		allowed := (key == "arg" && argOK) || slices.Contains([]string{"recursive", "type", "encoding", "offset", "length", "timeout", "nocache", "dht-timeout", "format", "download", "dag-scope", "entity-bytes", "car-version", "car-order", "car-dups"}, key)
		if !allowed {
			q[key] = []string{"[REDACTED]"}
			continue
		}
		for i := range values {
			values[i] = clip(values[i])
		}
	}
	return q
}

func (l *Logger) trusted(ip netip.Addr) bool {
	ip = ip.Unmap()
	return slices.ContainsFunc(l.proxies, func(p netip.Prefix) bool { return p.Contains(ip) })
}

func (l *Logger) client(r *http.Request) (string, string) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !l.trusted(ip) {
		return clip(host), "remote_addr"
	}
	if cf, err := netip.ParseAddr(r.Header.Get("CF-Connecting-IP")); err == nil {
		return cf.Unmap().String(), "cf_connecting_ip"
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(chain) - 1; i >= 0; i-- {
		next, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			break
		}
		ip = next
		if !l.trusted(ip) {
			return ip.Unmap().String(), "x_forwarded_for"
		}
	}
	return clip(host), "remote_addr"
}
