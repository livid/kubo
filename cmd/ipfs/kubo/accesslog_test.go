package kubo

import (
	"path/filepath"
	"testing"

	"github.com/ipfs/kubo/config"
	"github.com/stretchr/testify/require"
)

func TestAccessLogServiceFiles(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{}
	cfg.API.AccessLog = &config.AccessLog{Enabled: true}
	cfg.Gateway.AccessLog = &config.AccessLog{Enabled: true, Path: filepath.Join(root, "api-access.jsonl")}
	_, err := openAccessLog(cfg, root, "api")
	require.ErrorContains(t, err, "separate files")
	cfg.Gateway.AccessLog.Path = ""
	for _, service := range []string{"api", "gateway"} {
		l, err := openAccessLog(cfg, root, service)
		require.NoError(t, err)
		require.NotNil(t, l)
		require.NoError(t, l.Close())
	}
}
