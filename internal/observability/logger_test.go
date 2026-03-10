package observability

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// newTestLogger creates a RequestLogger backed by a temp-dir SQLite file.
func newTestLogger(t *testing.T) *RequestLogger {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	l, err := NewRequestLogger(dbPath)
	if err != nil {
		t.Fatalf("NewRequestLogger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// waitForEvents sleeps briefly to allow the async writer goroutine to flush.
func waitForEvents() {
	time.Sleep(100 * time.Millisecond)
}

// TestNewRequestLogger verifies that the database and schema are created.
func TestNewRequestLogger(t *testing.T) {
	l := newTestLogger(t)

	// Verify the requests table exists by querying its schema.
	var name string
	err := l.DB().QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='requests'`,
	).Scan(&name)
	if err != nil {
		t.Fatalf("requests table not found: %v", err)
	}
	if name != "requests" {
		t.Errorf("expected table name 'requests', got %q", name)
	}

	// Verify the failover_events table exists.
	err = l.DB().QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='failover_events'`,
	).Scan(&name)
	if err != nil {
		t.Fatalf("failover_events table not found: %v", err)
	}
}

// TestLogSingleEvent logs one event and reads it back from the database.
func TestLogSingleEvent(t *testing.T) {
	l := newTestLogger(t)

	event := RequestEvent{
		RequestID:                "req-001",
		APIKeyName:               "key-a",
		InstanceName:             "instance-1",
		Model:                    "claude-3-5-sonnet",
		Status:                   "success",
		ErrorType:                "",
		ErrorMessage:             "",
		InputTokens:              100,
		OutputTokens:             200,
		CacheCreationInputTokens: 10,
		CacheReadInputTokens:     20,
		DurationMs:               350,
		SessionID:                "sess-abc",
	}

	l.Log(event)
	waitForEvents()

	var (
		gotRequestID    string
		gotAPIKeyName   string
		gotInstanceName string
		gotModel        string
		gotStatus       string
		gotInputTokens  int64
		gotOutputTokens int64
		gotDurationMs   int64
		gotSessionID    string
		gotCacheCreate  int64
		gotCacheRead    int64
	)

	err := l.DB().QueryRow(
		`SELECT request_id, api_key_name, instance_name, model, status,
		        input_tokens, output_tokens, cache_creation_input_tokens,
		        cache_read_input_tokens, duration_ms, session_id
		 FROM requests WHERE request_id = ?`, "req-001",
	).Scan(
		&gotRequestID, &gotAPIKeyName, &gotInstanceName, &gotModel, &gotStatus,
		&gotInputTokens, &gotOutputTokens, &gotCacheCreate, &gotCacheRead,
		&gotDurationMs, &gotSessionID,
	)
	if err != nil {
		t.Fatalf("query event: %v", err)
	}

	assertEqual(t, "RequestID", "req-001", gotRequestID)
	assertEqual(t, "APIKeyName", "key-a", gotAPIKeyName)
	assertEqual(t, "InstanceName", "instance-1", gotInstanceName)
	assertEqual(t, "Model", "claude-3-5-sonnet", gotModel)
	assertEqual(t, "Status", "success", gotStatus)
	assertEqualInt(t, "InputTokens", 100, gotInputTokens)
	assertEqualInt(t, "OutputTokens", 200, gotOutputTokens)
	assertEqualInt(t, "CacheCreationInputTokens", 10, gotCacheCreate)
	assertEqualInt(t, "CacheReadInputTokens", 20, gotCacheRead)
	assertEqualInt(t, "DurationMs", 350, gotDurationMs)
	assertEqual(t, "SessionID", "sess-abc", gotSessionID)
}

// TestLogMultipleEvents logs N events and verifies the count.
func TestLogMultipleEvents(t *testing.T) {
	l := newTestLogger(t)

	const n = 50
	for i := 0; i < n; i++ {
		l.Log(RequestEvent{
			RequestID: fmt.Sprintf("req-%04d", i),
			Status:    "success",
		})
	}
	waitForEvents()

	var count int64
	if err := l.DB().QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != n {
		t.Errorf("expected %d rows, got %d", n, count)
	}
}

// TestStatsTokenUsageByInstance verifies aggregation per instance.
func TestStatsTokenUsageByInstance(t *testing.T) {
	l := newTestLogger(t)
	stats := NewStats(l.DB())

	events := []RequestEvent{
		{RequestID: "r1", InstanceName: "inst-a", Status: "success", InputTokens: 100, OutputTokens: 50},
		{RequestID: "r2", InstanceName: "inst-a", Status: "success", InputTokens: 200, OutputTokens: 80},
		{RequestID: "r3", InstanceName: "inst-a", Status: "failure", InputTokens: 10, OutputTokens: 0},
		{RequestID: "r4", InstanceName: "inst-b", Status: "success", InputTokens: 400, OutputTokens: 300},
	}
	for _, e := range events {
		l.Log(e)
	}
	waitForEvents()

	usages, err := stats.TokenUsageByInstance(0) // 0 = all time
	if err != nil {
		t.Fatalf("TokenUsageByInstance: %v", err)
	}

	byName := make(map[string]InstanceUsage)
	for _, u := range usages {
		byName[u.InstanceName] = u
	}

	a, ok := byName["inst-a"]
	if !ok {
		t.Fatal("inst-a not found in results")
	}
	assertEqualInt(t, "inst-a TotalRequests", 3, a.TotalRequests)
	assertEqualInt(t, "inst-a SuccessCount", 2, a.SuccessCount)
	assertEqualInt(t, "inst-a FailureCount", 1, a.FailureCount)
	assertEqualInt(t, "inst-a InputTokens", 310, a.InputTokens)
	assertEqualInt(t, "inst-a OutputTokens", 130, a.OutputTokens)

	b, ok := byName["inst-b"]
	if !ok {
		t.Fatal("inst-b not found in results")
	}
	assertEqualInt(t, "inst-b TotalRequests", 1, b.TotalRequests)
	assertEqualInt(t, "inst-b InputTokens", 400, b.InputTokens)
}

// TestStatsRecentRequests verifies ordering and limit.
func TestStatsRecentRequests(t *testing.T) {
	l := newTestLogger(t)
	stats := NewStats(l.DB())

	// Insert events with distinct timestamps directly to control ordering.
	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		_, err := l.DB().Exec(
			`INSERT INTO requests (request_id, timestamp, date, hour, status)
			 VALUES (?, ?, ?, ?, ?)`,
			fmt.Sprintf("req-%d", i),
			now+int64(i), // ascending timestamps
			"2026-01-01",
			10,
			"success",
		)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	records, err := stats.RecentRequests(3)
	if err != nil {
		t.Fatalf("RecentRequests: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}

	// Newest first: req-4, req-3, req-2
	expected := []string{"req-4", "req-3", "req-2"}
	for i, r := range records {
		if r.RequestID != expected[i] {
			t.Errorf("record[%d]: expected request_id %q, got %q", i, expected[i], r.RequestID)
		}
	}
}

// TestStatsCleanup verifies that old records are deleted.
func TestStatsCleanup(t *testing.T) {
	l := newTestLogger(t)
	stats := NewStats(l.DB())

	now := time.Now().Unix()
	oldTimestamp := now - 10*86400 // 10 days ago

	// Insert two old records directly.
	for i := 0; i < 2; i++ {
		_, err := l.DB().Exec(
			`INSERT INTO requests (request_id, timestamp, date, hour, status)
			 VALUES (?, ?, ?, ?, ?)`,
			fmt.Sprintf("old-%d", i),
			oldTimestamp,
			"2026-01-01",
			10,
			"success",
		)
		if err != nil {
			t.Fatalf("insert old: %v", err)
		}
	}

	// Insert one recent record via the logger.
	l.Log(RequestEvent{RequestID: "new-1", Status: "success"})
	waitForEvents()

	// Insert old failover_events.
	oldTime := time.Unix(oldTimestamp, 0).UTC().Format(time.RFC3339)
	_, err := l.DB().Exec(
		`INSERT INTO failover_events (timestamp, instance_name, event_type) VALUES (?, ?, ?)`,
		oldTime, "inst-x", "failover",
	)
	if err != nil {
		t.Fatalf("insert failover_event: %v", err)
	}

	// Run cleanup with 7-day retention; records 10 days old should be removed.
	deleted, err := stats.Cleanup(7)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	// 2 old requests + 1 old failover_event = 3
	if deleted != 3 {
		t.Errorf("expected 3 deleted rows, got %d", deleted)
	}

	// Verify only the recent request remains.
	var count int64
	if err := l.DB().QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 remaining row, got %d", count)
	}

	// Verify the remaining record is the recent one.
	var remainingID string
	if err := l.DB().QueryRow(`SELECT request_id FROM requests`).Scan(&remainingID); err != nil {
		t.Fatalf("select remaining: %v", err)
	}
	if remainingID != "new-1" {
		t.Errorf("expected remaining row 'new-1', got %q", remainingID)
	}

	// Verify failover_events are also cleaned up.
	var fCount int64
	if err := l.DB().QueryRow(`SELECT COUNT(*) FROM failover_events`).Scan(&fCount); err != nil {
		t.Fatalf("count failover: %v", err)
	}
	if fCount != 0 {
		t.Errorf("expected 0 failover_events, got %d", fCount)
	}
}

// assertEqual is a typed string equality helper.
func assertEqual(t *testing.T, field, want, got string) {
	t.Helper()
	if want != got {
		t.Errorf("%s: want %q, got %q", field, want, got)
	}
}

// assertEqualInt is a typed int64 equality helper that accepts any integer type.
func assertEqualInt[T ~int | ~int64 | ~int32](t *testing.T, field string, want T, got T) {
	t.Helper()
	if want != got {
		t.Errorf("%s: want %d, got %d", field, want, got)
	}
}

// Compile-time check: DB() method signature must exist on RequestLogger.
var _ func(*RequestLogger) *sql.DB = (*RequestLogger).DB
