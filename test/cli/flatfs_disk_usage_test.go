package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ipfs/kubo/test/cli/harness"
	"github.com/stretchr/testify/require"
)

// GC must not turn an underestimated FlatFS cache into a wrapped RepoSize.
// Both commands run against the same daemon: reopening would hide the bug by
// rejecting the negative cache and calculating usage during startup.
func TestFlatfsDiskUsageRecoversAfterGC(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{"flatfs-levelds", "flatfs-pebbleds"} {
		t.Run(profile, func(t *testing.T) {
			t.Parallel()
			node := harness.NewT(t).NewNode().Init("--empty-repo", "--profile=test,"+profile)
			keep := bytes.Repeat([]byte("p"), 64<<10)
			node.WriteBytes("keep", keep)
			pinned := strings.TrimSpace(node.IPFS("add", "-Q", "--cid-version=1", "--raw-leaves", "keep").Stdout.String())
			node.WriteBytes("garbage", bytes.Repeat([]byte("g"), 1<<20))
			garbage := strings.TrimSpace(node.IPFS("block", "put", "--format=raw", "garbage").Stdout.String())
			node.WriteBytes("blocks/diskUsage.cache", []byte(`{"diskUsage":1,"accuracy":"initial-approximate"}`))

			node.StartDaemon("--offline")
			t.Cleanup(func() { node.StopDaemon() })
			collected := node.IPFS("repo", "gc").Stdout.String()
			require.Contains(t, collected, garbage)
			var stat struct{ RepoSize uint64 }
			require.NoError(t, json.Unmarshal(node.IPFS("repo", "stat", "--enc=json").Stdout.Bytes(), &stat))
			require.GreaterOrEqual(t, stat.RepoSize, uint64(len(keep)))
			require.Less(t, stat.RepoSize, uint64(256<<20), "RepoSize must not wrap")
			var cache struct {
				DiskUsage int64  `json:"diskUsage"`
				Accuracy  string `json:"accuracy"`
			}
			require.NoError(t, json.Unmarshal([]byte(node.ReadFile("blocks/diskUsage.cache")), &cache))
			require.GreaterOrEqual(t, cache.DiskUsage, int64(len(keep)))
			require.Less(t, cache.DiskUsage, int64(2<<20))
			require.Equal(t, "initial-exact", cache.Accuracy)
			require.Equal(t, keep, node.IPFS("block", "get", pinned).Stdout.Bytes())
			require.Contains(t, node.IPFS("pin", "ls", "--type=recursive", pinned).Stdout.String(), pinned)
		})
	}
}
