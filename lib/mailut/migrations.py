"""Schema definition and migrations.

Migrations are an ordered list of ``(version, description, statements)``.  Each
migration runs exactly once, inside a transaction, and its version is recorded
in ``schema_migrations``.  Even with a single schema today, the mechanism is
explicit so that a future release has one obvious place to extend.

Rules for adding a migration:
  * append, never edit a released entry;
  * bump ``release.SCHEMA_VERSION`` to the new highest version;
  * every statement must be idempotent-safe under a fresh database too.
"""

from __future__ import annotations

MIGRATIONS: list[tuple[int, str, tuple[str, ...]]] = [
    (
        1,
        "initial schema",
        (
            # -- collection scopes ------------------------------------------
            """
            CREATE TABLE audit_scopes (
                id                     INTEGER PRIMARY KEY,
                scope_type             TEXT    NOT NULL
                                       CHECK (scope_type IN ('all', 'domain', 'email')),
                scope_value            TEXT    NOT NULL,
                mode                   TEXT    NOT NULL
                                       CHECK (mode IN ('include', 'exclude')),
                level                  TEXT    NOT NULL
                                       CHECK (level IN ('metadata', 'headers', 'message')),
                retention_days         INTEGER NOT NULL CHECK (retention_days >= 1),
                message_retention_days INTEGER CHECK (message_retention_days IS NULL
                                                      OR message_retention_days >= 1),
                created_at             TEXT    NOT NULL,
                updated_at             TEXT    NOT NULL,
                UNIQUE (scope_type, scope_value)
            )
            """,
            # -- one observed SMTP/Rspamd decision --------------------------
            """
            CREATE TABLE audit_events (
                id                   INTEGER PRIMARY KEY,
                fingerprint          TEXT    NOT NULL UNIQUE,
                occurred_at          TEXT    NOT NULL,
                received_at          TEXT    NOT NULL,
                source               TEXT    NOT NULL,
                stage                TEXT    NOT NULL,
                action               TEXT    NOT NULL,
                envelope_from        TEXT,
                envelope_from_domain TEXT,
                envelope_to          TEXT,
                envelope_to_domain   TEXT,
                header_from          TEXT,
                header_to            TEXT,
                subject              TEXT,
                message_id           TEXT,
                queue_id             TEXT,
                session_id           TEXT,
                remote_ip            TEXT,
                helo                 TEXT,
                smtp_code            TEXT,
                smtp_enhanced_code   TEXT,
                reason               TEXT,
                rspamd_score         REAL,
                rspamd_required      REAL,
                rspamd_action        TEXT,
                spf                  TEXT,
                dkim                 TEXT,
                dmarc                TEXT,
                message_size         INTEGER,
                level                TEXT    NOT NULL,
                scope_id             INTEGER REFERENCES audit_scopes (id) ON DELETE SET NULL,
                expires_at           TEXT    NOT NULL
            )
            """,
            # Deliberate indexes only: these back the documented query filters.
            "CREATE INDEX idx_events_occurred   ON audit_events (occurred_at)",
            "CREATE INDEX idx_events_expires    ON audit_events (expires_at)",
            "CREATE INDEX idx_events_rcpt       ON audit_events (envelope_to, occurred_at)",
            "CREATE INDEX idx_events_rcpt_dom   ON audit_events (envelope_to_domain, occurred_at)",
            "CREATE INDEX idx_events_sender     ON audit_events (envelope_from, occurred_at)",
            "CREATE INDEX idx_events_action     ON audit_events (action, occurred_at)",
            "CREATE INDEX idx_events_queue_id   ON audit_events (queue_id)",
            "CREATE INDEX idx_events_message_id ON audit_events (message_id)",
            "CREATE INDEX idx_events_remote_ip  ON audit_events (remote_ip, occurred_at)",
            # -- Rspamd symbols, normalised so they can be queried ----------
            """
            CREATE TABLE audit_symbols (
                id       INTEGER PRIMARY KEY,
                event_id INTEGER NOT NULL REFERENCES audit_events (id) ON DELETE CASCADE,
                symbol   TEXT    NOT NULL,
                score    REAL,
                options  TEXT
            )
            """,
            "CREATE INDEX idx_symbols_event  ON audit_symbols (event_id)",
            "CREATE INDEX idx_symbols_symbol ON audit_symbols (symbol)",
            # -- stored headers / raw messages ------------------------------
            # 'headers' payloads are small and kept inline; 'message' payloads
            # are gzipped files under the message directory and only
            # referenced from here.
            """
            CREATE TABLE audit_payloads (
                id             INTEGER PRIMARY KEY,
                event_id       INTEGER NOT NULL REFERENCES audit_events (id) ON DELETE CASCADE,
                kind           TEXT    NOT NULL CHECK (kind IN ('headers', 'message')),
                path           TEXT,
                content        TEXT,
                stored_bytes   INTEGER,
                original_bytes INTEGER,
                sha256         TEXT,
                created_at     TEXT    NOT NULL,
                expires_at     TEXT    NOT NULL
            )
            """,
            "CREATE INDEX idx_payloads_event   ON audit_payloads (event_id)",
            "CREATE INDEX idx_payloads_expires ON audit_payloads (expires_at)",
            # -- collector cursors / bookkeeping ----------------------------
            """
            CREATE TABLE collector_state (
                key        TEXT PRIMARY KEY,
                value      TEXT,
                updated_at TEXT NOT NULL
            )
            """,
            # -- queue/rate samples written by `mailut watch` ---------------
            """
            CREATE TABLE watch_samples (
                id                      INTEGER PRIMARY KEY,
                occurred_at             TEXT    NOT NULL,
                severity                TEXT    NOT NULL,
                reasons                 TEXT,
                window                  TEXT,
                queue_total             INTEGER NOT NULL DEFAULT 0,
                deferred_queue          INTEGER NOT NULL DEFAULT 0,
                sent                    INTEGER NOT NULL DEFAULT 0,
                bounced                 INTEGER NOT NULL DEFAULT 0,
                deferred                INTEGER NOT NULL DEFAULT 0,
                bounce_defer_rate       INTEGER NOT NULL DEFAULT 0,
                rate_limits             INTEGER NOT NULL DEFAULT 0,
                spam_blocks             INTEGER NOT NULL DEFAULT 0,
                top_sasl_user           TEXT,
                top_sasl_count          INTEGER NOT NULL DEFAULT 0,
                bulk_senders            INTEGER NOT NULL DEFAULT 0,
                queue_top_sender        TEXT,
                queue_top_sender_count  INTEGER NOT NULL DEFAULT 0,
                queue_top_domain_sender TEXT,
                queue_top_domain_count  INTEGER NOT NULL DEFAULT 0,
                queue_unique_domains    INTEGER NOT NULL DEFAULT 0,
                expires_at              TEXT    NOT NULL
            )
            """,
            "CREATE INDEX idx_watch_occurred ON watch_samples (occurred_at)",
            "CREATE INDEX idx_watch_expires  ON watch_samples (expires_at)",
            # -- purge audit trail ------------------------------------------
            """
            CREATE TABLE purge_runs (
                id          INTEGER PRIMARY KEY,
                started_at  TEXT    NOT NULL,
                finished_at TEXT,
                selector    TEXT    NOT NULL,
                events      INTEGER NOT NULL DEFAULT 0,
                payloads    INTEGER NOT NULL DEFAULT 0,
                files       INTEGER NOT NULL DEFAULT 0,
                errors      INTEGER NOT NULL DEFAULT 0
            )
            """,
        ),
    ),
]

LATEST = max(version for version, _desc, _sql in MIGRATIONS)
