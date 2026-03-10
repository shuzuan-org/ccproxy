package observability

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// initSQL contains the database schema initialization SQL.
const initSQL = `
CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    date TEXT NOT NULL,
    hour INTEGER NOT NULL,
    api_key_name TEXT,
    instance_name TEXT,
    model TEXT,
    status TEXT,
    error_type TEXT,
    error_message TEXT,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    cache_creation_input_tokens INTEGER DEFAULT 0,
    cache_read_input_tokens INTEGER DEFAULT 0,
    duration_ms INTEGER,
    session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_requests_api_key_name ON requests(api_key_name);
CREATE INDEX IF NOT EXISTS idx_requests_instance_name ON requests(instance_name);
CREATE INDEX IF NOT EXISTS idx_requests_session_id ON requests(session_id);
CREATE INDEX IF NOT EXISTS idx_requests_date ON requests(date);

CREATE TABLE IF NOT EXISTS failover_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    instance_name TEXT,
    event_type TEXT,
    failure_type TEXT,
    error_message TEXT,
    switch_count INTEGER
);

CREATE INDEX IF NOT EXISTS idx_failover_timestamp ON failover_events(timestamp);
`

// RequestEvent holds all fields for a single proxy request log entry.
type RequestEvent struct {
	RequestID                string
	APIKeyName               string
	InstanceName             string
	Model                    string
	Status                   string // success|failure|business_error|timeout
	ErrorType                string
	ErrorMessage             string
	InputTokens              int64
	OutputTokens             int64
	CacheCreationInputTokens int64
	CacheReadInputTokens     int64
	DurationMs               int64
	SessionID                string
}

// RequestLogger asynchronously writes request events to a SQLite database.
type RequestLogger struct {
	db     *sql.DB
	events chan RequestEvent
	done   chan struct{}
	wg     sync.WaitGroup
}

// NewRequestLogger opens (or creates) a SQLite database at dbPath, runs schema
// migrations, and starts the background event processor.
func NewRequestLogger(dbPath string) (*RequestLogger, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Enable WAL mode for better concurrent read/write performance
	db.Exec("PRAGMA journal_mode=WAL")
	db.Exec("PRAGMA synchronous=NORMAL")

	// Run schema migrations
	if _, err := db.Exec(initSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	l := &RequestLogger{
		db:     db,
		events: make(chan RequestEvent, 10000),
		done:   make(chan struct{}),
	}

	l.wg.Add(1)
	go l.processEvents()

	return l, nil
}

// Log enqueues a RequestEvent for async persistence. Drops the event and logs
// a warning if the internal channel is full.
func (l *RequestLogger) Log(event RequestEvent) {
	select {
	case l.events <- event:
	default:
		slog.Warn("request logger channel full, dropping event", "request_id", event.RequestID)
	}
}

// Close drains the event channel, waits for the background goroutine to finish,
// and closes the database connection.
func (l *RequestLogger) Close() {
	close(l.events)
	l.wg.Wait()
	l.db.Close()
}

// DB returns the underlying *sql.DB for direct queries (e.g., stats).
func (l *RequestLogger) DB() *sql.DB {
	return l.db
}

// processEvents reads from the events channel and writes each record to SQLite.
func (l *RequestLogger) processEvents() {
	defer l.wg.Done()
	for event := range l.events {
		now := time.Now()
		_, err := l.db.Exec(
			`INSERT INTO requests (
				request_id, timestamp, date, hour,
				api_key_name, instance_name, model, status,
				error_type, error_message,
				input_tokens, output_tokens,
				cache_creation_input_tokens, cache_read_input_tokens,
				duration_ms, session_id
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			event.RequestID,
			now.Unix(),
			now.Format("2006-01-02"),
			now.Hour(),
			event.APIKeyName,
			event.InstanceName,
			event.Model,
			event.Status,
			event.ErrorType,
			event.ErrorMessage,
			event.InputTokens,
			event.OutputTokens,
			event.CacheCreationInputTokens,
			event.CacheReadInputTokens,
			event.DurationMs,
			event.SessionID,
		)
		if err != nil {
			slog.Error("failed to log request", "error", err, "request_id", event.RequestID)
		}
	}
}
