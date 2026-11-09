# Local HTTP access logs

This fork can record private JSONL request logs for the daemon's RPC API and
HTTP gateway. Use these logs to find expensive commands, large responses and
requests that remain active. Logging is disabled by default, writes only to a
local file, and does not use Kubo's telemetry or subsystem debug-log output.

Enable either service independently, then restart the daemon:

```sh
ipfs config --json API.AccessLog '{"Enabled":true}'
ipfs config --json Gateway.AccessLog '{"Enabled":true}'
```

To disable a log, set its `Enabled` field to `false` and restart. The default
files are `$IPFS_PATH/api-access.jsonl` and `$IPFS_PATH/gateway-access.jsonl`.
An omitted configuration has the same behavior as `Enabled: false`.

## Configuration

Both `API.AccessLog` and `Gateway.AccessLog` accept these fields:

| Field | Default | Meaning |
|---|---|---|
| `Enabled` | `false` | Enable local request logging at daemon startup. |
| `Path` | service-specific name above | Absolute path or path relative to the repository. Use separate files for API and gateway logs. |
| `MaxSizeMB` | `50` | Rotate the active file at this size in MiB. |
| `MaxBackups` | `7` | Keep at most this many compressed backups. |
| `MaxAgeDays` | `7` | Remove older backups during rotation/cleanup. |
| `TrustedProxies` | `[]` | Socket-peer CIDRs allowed to supply client attribution headers. |

Zero rotation limits select the defaults; negative limits and malformed proxy
CIDRs are rejected. Size/count limits may retain less than seven days. The
active file is not deleted solely because of age. Files are opened with mode
`0600`, and new directories use `0700`. An existing log file's permissions are
tightened to `0600`. The daemon fails startup if an enabled log cannot be opened.
Write failures after startup warn at most once per minute and do not fail HTTP
responses; log records can be lost during a storage failure. Writes are
synchronous but are not fsynced per request.

## Events

Each request produces `http_request_start` before dispatch and
`http_request_complete` when its handler finishes. Match them using
`request_id`. A start without a completion can identify a still-running pin or
an interrupted daemon; a long-running request need not finish to become visible.

Both events include UTC time, start time, service (`api` or `gateway`), listener,
method, observed scheme, host, protocol, original path, sanitized query, socket
peer, attributed client IP and its source, User-Agent, selected request headers,
and declared request content length. Completion adds a `result` object with:

- HTTP status, elapsed milliseconds and milliseconds to first final response header,
  body write or flush (`first_byte_ms`, null if none was observed).
- Request-body bytes actually read and response bytes accepted by the HTTP
  writer, including the `io.ReaderFrom` path. Bodies themselves are never logged.
- Outcome (`complete`, `canceled`, `aborted`, `write_error`, or `hijacked`) and a write-error
  flag. Panics retain their original HTTP-server behavior.
- Content-Type, Content-Range, Cache-Control and ETag when set by the handler.

The wrapper preserves optional response-writer interfaces, including flushing,
so streaming RPC responses remain streaming. An aborted or canceled handler that never
wrote a response has status `0`; an ordinary empty response has status `200`.
Completion describes handler lifetime, not the lifetime of a hijacked connection.
These logs cover the daemon's HTTP listeners, not the gateway over libp2p.

## Attribution and redaction

By default, `client_ip` comes only from the socket peer. Behind an explicitly
trusted proxy, a valid `CF-Connecting-IP` takes precedence; otherwise the
`X-Forwarded-For` chain is walked from the right to the first untrusted address.
Only trust proxies that remove or overwrite incoming attribution headers.

Authorization, cookies, signatures, Referer, bodies and arbitrary headers are
not logged. Unknown query values are replaced with `[REDACTED]`. Only known
non-credential options are retained. RPC `arg` is retained only for the data
commands listed in `internal/accesslog/accesslog.go`; config, key and pubsub
arguments are redacted. Malformed and oversized query strings are omitted.
Logged strings are bounded. The logs still contain requested paths, permitted
RPC arguments and client addresses: keep these operator files private.

## What byte counts mean

An RPC `pin/add` can download a large DAG while returning a tiny JSON response.
Its `response_bytes` measures that HTTP response, **not** the downloaded DAG.
Likewise, cached gateway requests can produce large responses without fetching
blocks. Swarm traffic is shared across concurrent operations and background
tasks, so it is not attributed to individual requests here. Use `ipfs stats bw`
and `ipfs diag cmds` alongside these request logs. HTTP counts also exclude
transport framing and do not equal physical-interface or compressed-proxy bytes.
