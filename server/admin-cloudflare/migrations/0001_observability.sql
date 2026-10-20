CREATE TABLE snapshots (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  source_revision TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE INDEX snapshots_latest ON snapshots(node_id, observed_at DESC, received_at DESC);
-- Retain IDs independently of snapshots for the entire signature validity window.
CREATE TABLE receipts (id TEXT PRIMARY KEY, received_at INTEGER NOT NULL);
CREATE TABLE audit (
  id TEXT PRIMARY KEY,
  occurred_at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL
);
CREATE INDEX audit_latest ON audit(occurred_at DESC);
