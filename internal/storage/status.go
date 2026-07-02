package storage

// Report lifecycle status, encoded in the object-key layout (#10).
//
// Every stored report lives under a status-partitioned key:
//
//	reports/<status>/<id>
//
// where <id> is the stable, unguessable report id minted at ingest
// (see defaultObjectKey) and <status> is one of the values below. Encoding the
// status in the key prefix means:
//
//   - "list the pending reports" is a single prefix List(StatusPrefix(StatusPending)),
//     with no separate index to keep in sync; and
//   - a status transition is a copy of the (already-encrypted) object to the new
//     status's key followed by a delete of the old key. The stored bytes are pure
//     ciphertext and are never decrypted, re-encrypted, or otherwise touched to
//     change status (see internal/lifecycle).
//
// The <id> is stable across transitions: only the status segment of the key
// changes, so a report keeps its identity as it moves pending -> published/removed.
type Status string

const (
	// StatusPending is a freshly accepted report awaiting the weekly publish job.
	// New reports are written here by the ingest Sink.
	StatusPending Status = "pending"
	// StatusRemoved is a report a maintainer pulled before publication (#11); it
	// is excluded from publishing.
	StatusRemoved Status = "removed"
	// StatusPublished is a report already published as a GitHub issue (#15); it is
	// retained but never re-published.
	StatusPublished Status = "published"
)

// ReportsPrefix namespaces every report object within the bucket.
const ReportsPrefix = "reports/"

// StatusPrefix is the key prefix shared by all reports in status s, e.g.
// "reports/pending/". Listing this prefix enumerates exactly the reports in that
// status. The trailing slash is load-bearing: it keeps the statuses disjoint so
// (for example) "reports/pending/" never matches a "reports/published/..." key.
func StatusPrefix(s Status) string {
	return ReportsPrefix + string(s) + "/"
}

// ReportKey is the object key for report id in status s: reports/<status>/<id>.
func ReportKey(s Status, id string) string {
	return StatusPrefix(s) + id
}
