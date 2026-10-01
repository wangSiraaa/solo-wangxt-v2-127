-- 企业邮件档案：信头、结构、关系、附件元数据、解析失败
-- PostgreSQL 13+ （immutable 生成列需要 PG12+）
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS emails (
    id                  UUID PRIMARY KEY,
    raw_sha256          TEXT NOT NULL UNIQUE,
    raw_size            BIGINT NOT NULL,
    raw_path            TEXT NOT NULL,
    raw_reused          BOOLEAN NOT NULL DEFAULT FALSE,
    message_id          TEXT,
    message_id_raw      TEXT,
    date_iso            TIMESTAMPTZ,
    subject             TEXT,
    subject_raw         TEXT,
    from_addr           JSONB NOT NULL DEFAULT '[]'::jsonb,
    to_addr             JSONB NOT NULL DEFAULT '[]'::jsonb,
    cc_addr             JSONB NOT NULL DEFAULT '[]'::jsonb,
    bcc_addr            JSONB NOT NULL DEFAULT '[]'::jsonb,
    sender_addr         JSONB NOT NULL DEFAULT '[]'::jsonb,
    reply_to            JSONB NOT NULL DEFAULT '[]'::jsonb,
    body_text           TEXT NOT NULL DEFAULT '',
    body_html_sanitized TEXT NOT NULL DEFAULT '',
    body_html_escaped   TEXT NOT NULL DEFAULT '',
    body_part_path_text TEXT,
    body_part_path_html TEXT,
    part_tree           JSONB NOT NULL DEFAULT '{}'::jsonb,
    headers             JSONB NOT NULL DEFAULT '[]'::jsonb,
    header_summary      JSONB NOT NULL DEFAULT '[]'::jsonb,
    defects             JSONB NOT NULL DEFAULT '[]'::jsonb,
    has_errors          BOOLEAN NOT NULL DEFAULT FALSE,
    duplicate_of        UUID REFERENCES emails(id),
    thread_id           TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Message-ID 故意不加 UNIQUE：重复标识是“冲突”，必须保留多条记录
CREATE INDEX IF NOT EXISTS idx_emails_message_id ON emails(message_id);
CREATE INDEX IF NOT EXISTS idx_emails_date ON emails(date_iso DESC);
CREATE INDEX IF NOT EXISTS idx_emails_duplicate_of ON emails(duplicate_of);
CREATE INDEX IF NOT EXISTS idx_emails_thread ON emails(thread_id);

-- 参与人规范化（信头与关系查询）
CREATE TABLE IF NOT EXISTS participants (
    id      BIGSERIAL PRIMARY KEY,
    email   CITEXT UNIQUE,
    name    TEXT
);

CREATE TABLE IF NOT EXISTS email_participants (
    email_id       UUID NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    participant_id BIGINT NOT NULL REFERENCES participants(id) ON DELETE CASCADE,
    field_name     TEXT NOT NULL CHECK (field_name IN ('from','to','cc','bcc','sender','reply-to')),
    ordinal        INT NOT NULL DEFAULT 0,
    PRIMARY KEY (email_id, participant_id, field_name, ordinal)
);
CREATE INDEX IF NOT EXISTS idx_ep_participant ON email_participants(participant_id);

-- 附件/内嵌资源元数据（字节本身在受控目录，按 sha256 去重）
CREATE TABLE IF NOT EXISTS attachments (
    id               UUID PRIMARY KEY,
    email_id         UUID NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    sha256           TEXT NOT NULL,
    relative_path    TEXT NOT NULL,
    original_filename TEXT,
    safe_filename    TEXT NOT NULL,
    content_type     TEXT NOT NULL,
    content_id       TEXT,
    content_location TEXT,
    disposition      TEXT,
    kind             TEXT NOT NULL CHECK (kind IN ('attachment','inline')),
    size             BIGINT NOT NULL,
    part_path        TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_attach_email ON attachments(email_id);
CREATE INDEX IF NOT EXISTS idx_attach_sha ON attachments(sha256);
CREATE INDEX IF NOT EXISTS idx_attach_cid ON attachments(email_id, content_id);

-- 会话边：References / In-Reply-To 全量保留（重复、循环、悬挂都不清理）
CREATE TABLE IF NOT EXISTS email_edges (
    id               BIGSERIAL PRIMARY KEY,
    email_id         UUID NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    kind             TEXT NOT NULL CHECK (kind IN ('in-reply-to','references')),
    target_message_id TEXT NOT NULL,
    ordinal          INT NOT NULL DEFAULT 0,
    raw              TEXT,
    target_email_id  UUID REFERENCES emails(id)
);
CREATE INDEX IF NOT EXISTS idx_edges_email ON email_edges(email_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON email_edges(target_message_id);

-- 会话聚类结果（由重建任务整体替换）
CREATE TABLE IF NOT EXISTS threads (
    thread_id        TEXT PRIMARY KEY,
    cycle            BOOLEAN NOT NULL DEFAULT FALSE,
    member_count     INT NOT NULL DEFAULT 0,
    rebuilt_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS thread_cycles (
    id          BIGSERIAL PRIMARY KEY,
    cycle_path  JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS dangling_refs (
    id      BIGSERIAL PRIMARY KEY,
    src     TEXT,
    target  TEXT NOT NULL,
    kind    TEXT NOT NULL
);
-- 主题弱候选：仅提示，绝不参与自动合并
CREATE TABLE IF NOT EXISTS subject_candidates (
    id          BIGSERIAL PRIMARY KEY,
    subject_key TEXT NOT NULL,
    email_ids   JSONB NOT NULL
);

-- 解析失败：原 EML 已隔离，记录可定位
CREATE TABLE IF NOT EXISTS parse_failures (
    id              UUID PRIMARY KEY,
    raw_sha256      TEXT NOT NULL,
    raw_size        BIGINT NOT NULL,
    stage           TEXT NOT NULL,
    error_type      TEXT NOT NULL,
    message         TEXT NOT NULL,
    quarantine_path TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_failures_created ON parse_failures(created_at DESC);

-- 多语言检索：subject/body 使用 simple 配置（不做英文词干，避免误伤中文与 ID）
CREATE OR REPLACE FUNCTION mail_fts_document(p emails)
RETURNS tsvector
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT
        setweight(to_tsvector('simple', coalesce(p.subject, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(p.body_text, '')), 'B');
$$;

CREATE INDEX IF NOT EXISTS idx_emails_fts ON emails USING GIN (mail_fts_document(emails));
