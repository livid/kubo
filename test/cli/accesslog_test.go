package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipfs/kubo/config"
	"github.com/ipfs/kubo/test/cli/harness"
	"github.com/stretchr/testify/require"
)

func TestHTTPAccessLog(t *testing.T) {
	t.Parallel()
	node := harness.NewT(t).NewNode().Init()
	node.UpdateConfig(func(c *config.Config) {
		c.API.AccessLog = &config.AccessLog{Enabled: true}
		c.Gateway.AccessLog = &config.AccessLog{Enabled: true}
	})
	node.StartDaemon("--offline")
	t.Cleanup(func() { node.StopDaemon() })
	cid := node.IPFSAddStr("access log fixture")
	client := node.GatewayClient()
	response := client.Get("/ipfs/"+cid+"?token=QUERY-SECRET", client.WithHeader("Range", "bytes=0-5"), client.WithHeader("Cookie", "COOKIE-SECRET"))
	require.Equal(t, 206, response.StatusCode)
	require.Equal(t, "access", response.Body)
	head := client.Head("/ipfs/" + cid)
	require.Equal(t, 200, head.StatusCode)
	require.Empty(t, head.Body)
	notModified := client.Get("/ipfs/"+cid, client.WithHeader("If-None-Match", head.Headers.Get("ETag")))
	require.Equal(t, 304, notModified.StatusCode)
	node.IPFS("pin", "add", cid)

	for _, service := range []string{"api", "gateway"} {
		path := filepath.Join(node.Dir, service+"-access.jsonl")
		var entries []map[string]any
		require.Eventually(t, func() bool {
			data, err := os.ReadFile(path)
			if err != nil {
				return false
			}
			entries = nil
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var entry map[string]any
				if json.Unmarshal([]byte(line), &entry) != nil {
					return false
				}
				entries = append(entries, entry)
			}
			matched := 0
			for _, entry := range entries {
				if entry["type"] == "http_request_complete" && (entry["path"] == "/api/v0/pin/add" || entry["path"] == "/ipfs/"+cid) {
					matched++
				}
			}
			return (service == "api" && matched >= 1) || (service == "gateway" && matched >= 3)
		}, 5*time.Second, 10*time.Millisecond)
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NotContains(t, string(data), "QUERY-SECRET")
		require.NotContains(t, string(data), "COOKIE-SECRET")
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		seen := make(map[string]bool)
		for _, e := range entries {
			require.Equal(t, service, e["service"])
			if e["type"] != "http_request_complete" {
				continue
			}
			r := e["result"].(map[string]any)
			if service == "api" && e["path"] == "/api/v0/pin/add" {
				require.Equal(t, cid, e["query"].(map[string]any)["arg"].([]any)[0])
				seen["pin"] = true
			}
			if service == "gateway" && e["path"] == "/ipfs/"+cid {
				switch int(r["status"].(float64)) {
				case 206:
					require.Equal(t, float64(6), r["response_bytes"])
					seen["range"] = true
				case 304:
					require.Zero(t, r["response_bytes"])
					seen["304"] = true
				case 200:
					require.Equal(t, "HEAD", e["method"])
					require.Zero(t, r["response_bytes"])
					seen["HEAD"] = true
				}
			}
		}
		if service == "api" {
			require.True(t, seen["pin"])
		} else {
			require.True(t, seen["range"] && seen["HEAD"] && seen["304"])
		}
	}
}

func TestHTTPAccessLogDisabled(t *testing.T) {
	t.Parallel()
	node := harness.NewT(t).NewNode().Init()
	node.UpdateConfig(func(c *config.Config) {
		c.API.AccessLog = &config.AccessLog{Enabled: false}
		c.Gateway.AccessLog = &config.AccessLog{Enabled: false}
	})
	node.StartDaemon("--offline")
	t.Cleanup(func() { node.StopDaemon() })
	cid := node.IPFSAddStr("logging disabled")
	response := node.GatewayClient().Get("/ipfs/" + cid)
	require.Equal(t, 200, response.StatusCode)
	require.Equal(t, "logging disabled", response.Body)
	for _, service := range []string{"api", "gateway"} {
		require.NoFileExists(t, filepath.Join(node.Dir, service+"-access.jsonl"))
	}
}
