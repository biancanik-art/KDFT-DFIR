PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    examiner_name TEXT,
    case_number TEXT,
    case_type TEXT,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS case_options (
    case_id INTEGER PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
    default_export_folder TEXT,
    temporary_folder TEXT,
    index_folder TEXT,
    timezone TEXT NOT NULL DEFAULT 'UTC',
    date_format TEXT NOT NULL DEFAULT 'ISO',
    time_format TEXT NOT NULL DEFAULT '24h'
);

CREATE TABLE IF NOT EXISTS global_options (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    config_root TEXT,
    evidence_library_root TEXT,
    default_storage_root TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS installed_resources (
    id INTEGER PRIMARY KEY,
    resource_key TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    config_file_name TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    storage_scope TEXT NOT NULL DEFAULT 'global',
    version TEXT NOT NULL DEFAULT '1',
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS evidence_sources (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL,
    source_path TEXT NOT NULL,
    display_name TEXT NOT NULL,
    size_bytes INTEGER,
    read_file_system_requested INTEGER NOT NULL DEFAULT 1,
    attach_status TEXT NOT NULL DEFAULT 'attached',
    encryption_status TEXT NOT NULL DEFAULT 'unknown',
    attached_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    indexed_at TEXT,
    notes TEXT,
    sha256_hex TEXT,
    hashed_at TEXT,
    UNIQUE(case_id, source_path)
);

CREATE TABLE IF NOT EXISTS evidence_jobs (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence_sources(id) ON DELETE CASCADE,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    parameters_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT,
    finished_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS filesystem_entries (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER NOT NULL REFERENCES evidence_sources(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES filesystem_entries(id) ON DELETE SET NULL,
    logical_path TEXT NOT NULL,
    name TEXT NOT NULL,
    entry_kind TEXT NOT NULL,
    size_bytes INTEGER,
    is_deleted INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    content_head BLOB,
    discovered_by_job_id INTEGER REFERENCES evidence_jobs(id) ON DELETE SET NULL,
    UNIQUE(evidence_id, logical_path)
);

CREATE INDEX IF NOT EXISTS ix_filesystem_entries_case_evidence
ON filesystem_entries(case_id, evidence_id);

CREATE INDEX IF NOT EXISTS ix_filesystem_entries_parent
ON filesystem_entries(parent_id);

CREATE INDEX IF NOT EXISTS ix_filesystem_entries_job
ON filesystem_entries(discovered_by_job_id);

-- Parser-derived text is stored separately from the bounded raw-byte preview.
-- Segment rows preserve source-entry provenance and allow complete parsed text
-- to be searched without changing the canonical filesystem name or path.
CREATE TABLE IF NOT EXISTS filesystem_entry_text_segments (
    entry_id INTEGER NOT NULL REFERENCES filesystem_entries(id) ON DELETE CASCADE,
    parser_name TEXT NOT NULL,
    segment_index INTEGER NOT NULL,
    part_name TEXT NOT NULL,
    content BLOB NOT NULL,
    content_encoding TEXT NOT NULL,
    segment_kind TEXT NOT NULL DEFAULT 'visible_text',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(entry_id, parser_name, segment_index)
);

CREATE INDEX IF NOT EXISTS ix_filesystem_entry_text_segments_entry
ON filesystem_entry_text_segments(entry_id);

-- Parser-extracted binary payloads (for example PST attachments) remain
-- portable with the case and are linked to a derived filesystem entry.
CREATE TABLE IF NOT EXISTS filesystem_entry_binary_blobs (
    entry_id INTEGER PRIMARY KEY REFERENCES filesystem_entries(id) ON DELETE CASCADE,
    parser_name TEXT NOT NULL,
    blob_kind TEXT NOT NULL,
    content BLOB NOT NULL,
    sha256_hex TEXT NOT NULL,
    size_bytes INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bookmark_folders (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES bookmark_folders(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    folder_comment TEXT,
    show_in_report INTEGER NOT NULL DEFAULT 1,
    report_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_bookmark_folders_root_name
ON bookmark_folders(case_id, name)
WHERE parent_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_bookmark_folders_child_name
ON bookmark_folders(case_id, parent_id, name)
WHERE parent_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY,
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    folder_id INTEGER NOT NULL REFERENCES bookmark_folders(id) ON DELETE CASCADE,
    bookmark_type TEXT NOT NULL,
    data_type TEXT,
    title TEXT,
    examiner_comment TEXT,
    in_report INTEGER NOT NULL DEFAULT 1,
    source_ref_json TEXT NOT NULL DEFAULT '{}',
    content_ref_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS bookmark_items (
    id INTEGER PRIMARY KEY,
    bookmark_id INTEGER NOT NULL REFERENCES bookmarks(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence_sources(id) ON DELETE SET NULL,
    entry_id INTEGER REFERENCES filesystem_entries(id) ON DELETE SET NULL,
    item_order INTEGER NOT NULL,
    display_name TEXT,
    logical_path TEXT,
    selection_offset INTEGER,
    selection_length INTEGER,
    data_preview TEXT,
    item_ref_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(bookmark_id, item_order)
);

CREATE INDEX IF NOT EXISTS ix_bookmark_items_entry
ON bookmark_items(entry_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    object_type TEXT,
    object_id INTEGER,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);
INSERT OR IGNORE INTO global_options(id) VALUES (1);
INSERT OR IGNORE INTO installed_resources(
    resource_key, display_name, config_file_name, resource_kind, storage_scope, version, notes
) VALUES
    ('file_signatures', 'File Signatures', 'FileSignatures.ini', 'file_signature_catalog', 'global', 'kdft-v1-baseline', 'Built-in KDFT configuration resource.'),
    ('file_types', 'File Types', 'FileTypes.ini', 'file_type_catalog', 'global', 'kdft-v1-baseline', 'Built-in KDFT configuration resource.'),
    ('filters', 'Filters', 'Filters.ini', 'filter_catalog', 'global', 'kdft-v1-baseline', 'Built-in KDFT configuration resource.'),
    ('keywords', 'Keywords', 'Keywords.ini', 'keyword_catalog', 'global', 'kdft-v1-baseline', 'Built-in KDFT configuration resource.'),
    ('profiles', 'Profiles', 'Profiles.ini', 'profile_catalog', 'global', 'kdft-v1-baseline', 'Built-in KDFT configuration resource.'),
    ('text_styles', 'Text Styles', 'TextStyles.ini', 'text_style_catalog', 'global', 'kdft-v1-baseline', 'Built-in KDFT configuration resource.'),
    ('case_report_template', 'Case Report Template', 'CaseReport.ini', 'report_template', 'global', 'kdft-v1-baseline', 'Built-in KDFT report template.');
