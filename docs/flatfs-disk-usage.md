# FlatFS disk-usage recovery

This fork pins `github.com/ipfs/go-ds-flatfs` to the immutable remote revision
`github.com/livid/go-ds-flatfs v0.6.2-0.20261109131402-70802b0da410` in all three
Go modules. The upstream module path and datastore format stay compatible.

A positive cached usage estimate can be smaller than the blocks subsequently
deleted by garbage collection. Previously the resulting negative signed counter
was converted to an unsigned value, making `ipfs repo stat` report an enormous
repository size and giving storage decisions an invalid input.

When `DiskUsage` sees a negative counter, the patched datastore recounts the
persisted files before returning a size. Puts, deletes, batch commits and
checkpoint writes wait during recovery; reads remain available. Uncommitted
batch payloads are excluded. A successful recount repairs the counter and
checkpoints it without reopening the datastore. A failed cache write is retried
by the normal checkpoint loop.

Recovery must complete rather than publish a partial estimate. Cancellation,
filesystem errors or the existing five-minute `DiskUsageCalcTimeout` return an
error and leave the counter available for a later retry. Large stores may pause
mutations for the duration of a recovery scan. The normal nonnegative accounting
path remains a fast atomic read. Usage still describes file sizes and metadata,
not physical allocation or an audit of every positive cached estimate.

The CLI regression test `TestFlatfsDiskUsageRecoversAfterGC` starts with an
undersized cache, runs GC and reads statistics from the same offline daemon. It
checks both FlatFS/LevelDB and FlatFS/Pebble layouts and verifies pinned content
survives. The dependency tests additionally cover concurrent mutations, batch
payloads, cancellation, timeout, errors, persisted recovery and batch-lock order.
