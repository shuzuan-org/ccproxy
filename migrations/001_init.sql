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
