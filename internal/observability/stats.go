package observability

import (
	"database/sql"
	"time"
)

// InstanceUsage aggregates token and request metrics per backend instance.
type InstanceUsage struct {
	InstanceName             string
	TotalRequests            int64
	SuccessCount             int64
	FailureCount             int64
	InputTokens              int64
	OutputTokens             int64
	CacheCreationInputTokens int64
	CacheReadInputTokens     int64
}

// RequestRecord is a flattened view of a single request row used in listings.
type RequestRecord struct {
	RequestID    string
	Timestamp    int64
	APIKeyName   string
	InstanceName string
	Model        string
	Status       string
	InputTokens  int64
	OutputTokens int64
	DurationMs   int64
	SessionID    string
}

// Stats provides read-only query helpers on top of the requests database.
type Stats struct {
	db *sql.DB
}

// NewStats creates a Stats instance backed by db.
func NewStats(db *sql.DB) *Stats {
	return &Stats{db: db}
}

// TokenUsageByInstance returns aggregated metrics grouped by instance_name for
// the last `hours` hours. Pass 0 to query all time.
func (s *Stats) TokenUsageByInstance(hours int) ([]InstanceUsage, error) {
	var (
		rows *sql.Rows
		err  error
	)

	const q = `
		SELECT
			COALESCE(instance_name, '') AS instance_name,
			COUNT(*) AS total_requests,
			SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS success_count,
			SUM(CASE WHEN status != 'success' THEN 1 ELSE 0 END) AS failure_count,
			COALESCE(SUM(input_tokens), 0) AS input_tokens,
			COALESCE(SUM(output_tokens), 0) AS output_tokens,
			COALESCE(SUM(cache_creation_input_tokens), 0) AS cache_creation_input_tokens,
			COALESCE(SUM(cache_read_input_tokens), 0) AS cache_read_input_tokens
		FROM requests
		WHERE (? = 0 OR timestamp > ?)
		GROUP BY instance_name
		ORDER BY total_requests DESC
	`

	cutoff := int64(0)
	if hours > 0 {
		cutoff = time.Now().Unix() - int64(hours)*3600
	}

	rows, err = s.db.Query(q, hours, cutoff)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []InstanceUsage
	for rows.Next() {
		var u InstanceUsage
		if err := rows.Scan(
			&u.InstanceName,
			&u.TotalRequests,
			&u.SuccessCount,
			&u.FailureCount,
			&u.InputTokens,
			&u.OutputTokens,
			&u.CacheCreationInputTokens,
			&u.CacheReadInputTokens,
		); err != nil {
			return nil, err
		}
		results = append(results, u)
	}
	return results, rows.Err()
}

// RecentRequests returns the most recent `limit` request records ordered by
// timestamp descending.
func (s *Stats) RecentRequests(limit int) ([]RequestRecord, error) {
	const q = `
		SELECT
			COALESCE(request_id, ''),
			timestamp,
			COALESCE(api_key_name, ''),
			COALESCE(instance_name, ''),
			COALESCE(model, ''),
			COALESCE(status, ''),
			COALESCE(input_tokens, 0),
			COALESCE(output_tokens, 0),
			COALESCE(duration_ms, 0),
			COALESCE(session_id, '')
		FROM requests
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := s.db.Query(q, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []RequestRecord
	for rows.Next() {
		var r RequestRecord
		if err := rows.Scan(
			&r.RequestID,
			&r.Timestamp,
			&r.APIKeyName,
			&r.InstanceName,
			&r.Model,
			&r.Status,
			&r.InputTokens,
			&r.OutputTokens,
			&r.DurationMs,
			&r.SessionID,
		); err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// Cleanup deletes request records older than retentionDays days and also prunes
// failover_events by the same cutoff. Returns the total number of deleted rows.
func (s *Stats) Cleanup(retentionDays int) (int64, error) {
	cutoff := time.Now().Unix() - int64(retentionDays)*86400

	res, err := s.db.Exec(`DELETE FROM requests WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	// failover_events stores timestamp as TEXT in RFC3339 format; convert cutoff
	// to the same format for comparison via SQLite's datetime functions.
	cutoffStr := time.Unix(cutoff, 0).UTC().Format(time.RFC3339)
	res2, err := s.db.Exec(`DELETE FROM failover_events WHERE timestamp < ?`, cutoffStr)
	if err != nil {
		return deleted, err
	}
	n2, err := res2.RowsAffected()
	if err != nil {
		return deleted, err
	}

	return deleted + n2, nil
}
