package accesslog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipfs/kubo/config"
	"github.com/stretchr/testify/require"
)

func newTestLog(t *testing.T) (*Logger, string) {
	t.Helper()
	root := t.TempDir()
	l, err := New(&config.AccessLog{Enabled: true}, root, "access.jsonl", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, l.Close()) })
	return l, filepath.Join(root, "access.jsonl")
}

func readEvents(t *testing.T, path string) []event {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var out []event
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var e event
		require.NoError(t, json.Unmarshal(line, &e))
		out = append(out, e)
	}
	return out
}

func TestRequestLifecycleAndPrivacy(t *testing.T) {
	l, path := newTestLog(t)
	release, entered, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := l.Wrap("api", "test-listener", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, err := io.Copy(io.Discard, r.Body)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Range", "bytes 0-2/6")
		w.WriteHeader(http.StatusPartialContent)
		require.NoError(t, http.NewResponseController(w).Flush())
		_, err = io.WriteString(w, "abc")
		require.NoError(t, err)
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/v0/pin/add?arg=/ipns/example&recursive=true&token=QUERY-SECRET", strings.NewReader("BODY-SECRET"))
	r.Header.Set("Authorization", "Bearer AUTH-SECRET")
	r.Header.Set("Cookie", "COOKIE-SECRET")
	r.Header.Set("X-Forwarded-For", "203.0.113.10")
	r.Header.Set("CF-Connecting-IP", "203.0.113.11")
	w := httptest.NewRecorder()
	go func() { defer close(done); h.ServeHTTP(w, r) }()
	<-entered
	start := readEvents(t, path)
	require.Len(t, start, 1, "long-running requests must be visible before they finish")
	require.Equal(t, "http_request_start", start[0].Type)
	require.Nil(t, start[0].Result)
	close(release)
	<-done
	events := readEvents(t, path)
	require.Len(t, events, 2)
	e := events[1]
	require.Equal(t, events[0].RequestID, e.RequestID)
	require.Equal(t, "http_request_complete", e.Type)
	require.Equal(t, "remote_addr", e.ClientSource, "untrusted forwarding headers must not affect attribution")
	require.Equal(t, "/ipns/example", e.Query.Get("arg"))
	require.Equal(t, 206, e.Result.Status)
	require.Equal(t, int64(3), e.Result.ResponseBytes)
	require.Equal(t, int64(len("BODY-SECRET")), e.Result.RequestBytes)
	require.NotNil(t, e.Result.FirstByteMS)
	require.Equal(t, "complete", e.Result.Outcome)
	require.Equal(t, "abc", w.Body.String())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, secret := range []string{"QUERY-SECRET", "BODY-SECRET", "AUTH-SECRET", "COOKIE-SECRET"} {
		require.NotContains(t, string(data), secret)
	}
}

func TestSensitiveRPCAndMalformedQuery(t *testing.T) {
	for _, path := range []string{"/api/v0/config", "/api/v0/config/replace", "/api/v0/key/import", "/api/v0/pubsub/pub"} {
		u, err := url.Parse(path + "?arg=SECRET&key=SECRET&password=SECRET&arbitrary=SECRET")
		require.NoError(t, err)
		data, err := json.Marshal(safeQuery(u))
		require.NoError(t, err)
		require.NotContains(t, string(data), "SECRET")
	}
	for _, raw := range []string{"token=SECRET&bad=%xx", "arg=" + strings.Repeat("x", 9000)} {
		q := safeQuery(&url.URL{Path: "/api/v0/cat", RawQuery: raw})
		require.Contains(t, q.Get("_query"), "omitted")
	}
}

func TestCanceledAndPanickingRequests(t *testing.T) {
	for _, abort := range []bool{false, true} {
		l, path := newTestLog(t)
		ctx, cancel := context.WithCancel(t.Context())
		h := l.Wrap("api", "local", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if abort {
				panic(http.ErrAbortHandler)
			}
			cancel()
		}))
		run := func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx))
		}
		if abort {
			require.PanicsWithValue(t, http.ErrAbortHandler, run)
		} else {
			run()
		}
		cancel()
		e := readEvents(t, path)[1]
		if abort {
			require.Equal(t, "aborted", e.Result.Outcome)
			require.Zero(t, e.Result.Status)
		} else {
			require.Equal(t, "canceled", e.Result.Outcome)
			require.Zero(t, e.Result.Status)
		}
	}
}

func TestProxyAttribution(t *testing.T) {
	root := t.TempDir()
	l, err := New(&config.AccessLog{Enabled: true, TrustedProxies: []string{"127.0.0.0/8", "10.0.0.0/8"}}, root, "proxy.jsonl", nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, l.Close()) }()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "192.0.2.8, 203.0.113.9, 10.1.2.3")
	ip, source := l.client(r)
	require.Equal(t, "203.0.113.9", ip)
	require.Equal(t, "x_forwarded_for", source)
	r.Header.Set("CF-Connecting-IP", "203.0.113.11")
	ip, source = l.client(r)
	require.Equal(t, "203.0.113.11", ip)
	require.Equal(t, "cf_connecting_ip", source)
}

type readerFromWriter struct {
	h http.Header
	b bytes.Buffer
}

func (w *readerFromWriter) Header() http.Header                 { return w.h }
func (w *readerFromWriter) WriteHeader(int)                     {}
func (w *readerFromWriter) Write(b []byte) (int, error)         { return w.b.Write(b) }
func (w *readerFromWriter) ReadFrom(r io.Reader) (int64, error) { return w.b.ReadFrom(r) }

func TestReaderFromAndOptionalInterfaces(t *testing.T) {
	l, path := newTestLog(t)
	w := &readerFromWriter{h: make(http.Header)}
	h := l.Wrap("gateway", "local", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := w.(http.Flusher)
		require.False(t, ok, "do not advertise unsupported optional interfaces")
		_, ok = w.(io.ReaderFrom)
		require.True(t, ok)
		n, err := io.Copy(w, struct{ io.Reader }{strings.NewReader("abcdef")})
		require.NoError(t, err)
		require.Equal(t, int64(6), n)
	}))
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ipfs/test", nil))
	require.Equal(t, int64(6), readEvents(t, path)[1].Result.ResponseBytes)
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("disk unavailable") }
func (failedWriter) Close() error              { return nil }

func TestWriteFailureDoesNotFailRequests(t *testing.T) {
	reports := 0
	l := &Logger{writer: failedWriter{}, onError: func(error) { reports++ }}
	h := l.Wrap("api", "local", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.WriteString(w, "ok")
		require.NoError(t, err)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, "ok", w.Body.String())
	require.Equal(t, 1, reports)
}

func TestConcurrentRecords(t *testing.T) {
	l, path := newTestLog(t)
	h := l.Wrap("api", "local", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	var wg sync.WaitGroup
	for range 40 {
		wg.Go(func() { h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)) })
	}
	wg.Wait()
	events := readEvents(t, path)
	require.Len(t, events, 80)
	counts := make(map[string]int)
	for _, e := range events {
		counts[e.RequestID]++
	}
	require.Len(t, counts, 40)
	for _, n := range counts {
		require.Equal(t, 2, n)
	}
}

func TestRotationAndPrivatePermissions(t *testing.T) {
	root := t.TempDir()
	l, err := New(&config.AccessLog{Enabled: true, MaxSizeMB: 1, MaxBackups: 2}, root, "access.jsonl", nil)
	require.NoError(t, err)
	for range 6 {
		l.emit(map[string]string{"padding": strings.Repeat("x", 700000)})
	}
	require.NoError(t, l.Close())
	require.Eventually(t, func() bool {
		files, err := filepath.Glob(filepath.Join(root, "*.gz"))
		return err == nil && len(files) > 0 && len(files) <= 2
	}, 5*time.Second, 10*time.Millisecond)
	files, err := filepath.Glob(filepath.Join(root, "*"))
	require.NoError(t, err)
	for _, file := range files {
		info, err := os.Stat(file)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestDisabledAndInvalidConfig(t *testing.T) {
	root := t.TempDir()
	l, err := New(nil, root, "unused", nil)
	require.NoError(t, err)
	require.Nil(t, l)
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	require.NotNil(t, l.Wrap("api", "local", h))
	require.NoError(t, l.Close())
	files, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Empty(t, files)
	for _, cfg := range []*config.AccessLog{{Enabled: true, MaxAgeDays: -1}, {Enabled: true, TrustedProxies: []string{"invalid"}}} {
		_, err := New(cfg, root, "invalid", nil)
		require.Error(t, err)
	}
}

type flushErrorWriter struct{ *httptest.ResponseRecorder }

func (w *flushErrorWriter) FlushError() error { return io.ErrClosedPipe }

func TestFlushErrorAccounting(t *testing.T) {
	l, path := newTestLog(t)
	h := l.Wrap("api", "local", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.ErrorIs(t, http.NewResponseController(w).Flush(), io.ErrClosedPipe)
	}))
	h.ServeHTTP(&flushErrorWriter{httptest.NewRecorder()}, httptest.NewRequest(http.MethodGet, "/", nil))
	r := readEvents(t, path)[1].Result
	require.Equal(t, "write_error", r.Outcome)
	require.True(t, r.WriteError)
	require.NotNil(t, r.FirstByteMS)
}

type hijackWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestHijackAndSwitchingProtocols(t *testing.T) {
	l, path := newTestLog(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	h := l.Wrap("gateway", "local", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols)
		_, _, err := w.(http.Hijacker).Hijack()
		require.NoError(t, err)
	}))
	h.ServeHTTP(&hijackWriter{httptest.NewRecorder(), a}, httptest.NewRequest(http.MethodGet, "/", nil))
	r := readEvents(t, path)[1].Result
	require.Equal(t, "hijacked", r.Outcome)
	require.Equal(t, http.StatusSwitchingProtocols, r.Status)
}
