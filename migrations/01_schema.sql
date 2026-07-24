-- 01: initial schema.
-- One row in `reports` per aggregate report received; one row in `records`
-- per <record> element inside it (a sending IP + its auth results).

CREATE TABLE IF NOT EXISTS reports (
    id            INT UNSIGNED     NOT NULL AUTO_INCREMENT PRIMARY KEY,
    org_name      VARCHAR(255)     NOT NULL,             -- who sent the report (google.com, Mimecast...)
    org_email     VARCHAR(255)     NULL,
    report_id     VARCHAR(255)     NOT NULL,             -- the reporter's own id for this report
    domain        VARCHAR(255)     NOT NULL,             -- policy_published/domain (your domain)
    date_begin    DATETIME         NOT NULL,             -- report window, converted from Unix ts
    date_end      DATETIME         NOT NULL,
    policy_p      VARCHAR(12)      NULL,                 -- none | quarantine | reject
    policy_sp     VARCHAR(12)      NULL,                 -- subdomain policy
    policy_pct    TINYINT UNSIGNED NULL,                 -- % of mail the policy applies to
    policy_adkim  CHAR(1)          NULL,                 -- r(elaxed) | s(trict) DKIM alignment
    policy_aspf   CHAR(1)          NULL,                 -- r | s SPF alignment
    source_file   VARCHAR(255)     NULL,                 -- original uploaded filename
    created_at    TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Duplicate prevention. report_id alone is NOT globally unique: each
    -- reporting org generates its own ids, so we scope it by org_name.
    UNIQUE KEY uq_org_report (org_name, report_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS records (
    id             INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    report_id      INT UNSIGNED NOT NULL,                -- FK to reports.id
    source_ip      VARCHAR(45)  NOT NULL,                -- fits IPv6
    ptr_hostname   VARCHAR(255) NULL,                    -- reverse DNS of source_ip at insert time
    msg_count      INT UNSIGNED NOT NULL DEFAULT 1,      -- messages this row aggregates
    disposition    VARCHAR(12)  NULL,                    -- what the receiver did: none | quarantine | reject
    eval_dkim      VARCHAR(12)  NULL,                    -- DMARC-evaluated (aligned) DKIM: pass | fail
    eval_spf       VARCHAR(12)  NULL,                    -- DMARC-evaluated (aligned) SPF: pass | fail
    header_from    VARCHAR(255) NULL,                    -- the From: domain the user sees
    envelope_from  VARCHAR(255) NULL,
    envelope_to    VARCHAR(255) NULL,
    -- Raw auth_results detail. A record can carry several DKIM signatures;
    -- we keep the most relevant one (a passing one if any, else the first).
    dkim_domain    VARCHAR(255) NULL,
    dkim_selector  VARCHAR(63)  NULL,
    dkim_result    VARCHAR(20)  NULL,                    -- pass | fail | neutral | temperror | permerror
    spf_domain     VARCHAR(255) NULL,
    spf_result     VARCHAR(20)  NULL,
    reason_type    VARCHAR(30)  NULL,                    -- policy override (forwarded, mailing_list...)
    reason_comment VARCHAR(255) NULL,

    CONSTRAINT fk_records_report
        FOREIGN KEY (report_id) REFERENCES reports (id) ON DELETE CASCADE,
    KEY idx_source_ip (source_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
