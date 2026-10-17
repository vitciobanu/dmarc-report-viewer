# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A self-hosted DMARC aggregate-report viewer: upload (or IMAP-fetch) the
`.xml.gz`/`.zip` reports that mailbox providers email you, parse them into
MySQL, and browse dashboards. See README.md for features and setup.

**Stack:** plain PHP ≥ 8.1 (`pdo_mysql`, `zip`, `zlib`, `simplexml`,
`mbstring`; `openssl` for IMAP) + MySQL 8. No frameworks, no Composer, no Node, no
build step, no test suite — verification is manual via the running app.
The target audience includes PHP beginners, so code stays simple and
well-commented.

## Commands

```sh
php scripts/init_db.php        # apply pending migrations/NN_*.sql (idempotent)
php -S 127.0.0.1:8082 -t public   # throwaway dev server
php bin/imap-fetch.php         # pull report emails via IMAP (needs config.php imap block)
php -l public/index.php        # syntax-check a file (no linter/tests exist)
```

First-time setup: copy `scripts/create_db.sql` to
`scripts/create_db.local.sql` (gitignored), set the password there, run it
as MySQL admin → copy `config.sample.php` to `config.php` → `php
scripts/init_db.php`. `create_db.sql` creates the user for both
`'localhost'` and `'127.0.0.1'` grant hosts (MySQL treats them as
distinct); keep both in sync if the user changes.

## Architecture

- `public/` — one self-contained controller+view file per page
  (`index.php` dashboard, `upload.php`, `report.php`, `ips.php`,
  `dns.php` live DNS status).
  POST handlers follow Post/Redirect/Get with flash messages
  (`flash_set()`/`flash_get()` in `src/helpers.php`). `public/assets/`
  holds `style.css` and `app.js` (upload drag-drop + date-filter
  auto-submit; no AJAX, no libs —
  the dashboard chart is inline PHP-generated SVG, and its interactivity
  — `?hide=` series toggles, `?cat=&day=` segment drill-down — is plain
  links re-rendered server-side, not JS).
- `src/db.php` — `Database::pdo()` is the **single PDO entry point**
  (lazy, memoized, exceptions on, real prepares). Never instantiate PDO
  elsewhere. `Database::config()` loads `config.php` (gitignored;
  template in `config.sample.php`).
- `src/parser.php` — the pipeline: `dmarc_extract_xmls()` (magic-byte
  detection, gzip/zip with decompression-size limits) →
  `dmarc_parse_xml()` (DOCTYPE rejected, `LIBXML_NONET`, structural
  validation; `LIBXML_NOENT` is deliberately absent — entities must never
  be substituted, don't "fix" that) → `dmarc_store()` (transactional
  insert, duplicate check on `(org_name, report_id)`).
  `dmarc_process_file()` wraps the three for both the upload page and the
  IMAP fetcher.
- `src/helpers.php` — `e()` (escape ALL dynamic output with this),
  date/percent formatting, `date_filter()` (shared `?from=&to=` handling),
  `domain_filter()` / `domain_sql()` / `known_domains()` (shared
  `?domain=` handling), `health_state()` (green/amber/red from the pass
  rate, thresholds in `config.php` `health`), `rdns_lookup()` (memoized
  PTR lookup, stored on records at insert time).
- `src/domains.php` — the dashboard's domain model. Card rows are keyed
  on the **sender** (`LOWER(COALESCE(NULLIF(rec.header_from,''),
  rep.domain))`), grouped by `domain_group()` (topmost domain listed in
  `config.php` `domains`, else the last two labels). `domain_type()`:
  own configured type, else nearest configured parent's, else
  `sending`. `sender_state()` colors a row (parked: no mail / all
  blocked = ok, delivered spoofing = warn, any DMARC pass = bad);
  `policy_advice()` gives the next step from weekly buckets over
  `advisor.weeks` (levels ok / ready / wait / fix / none). The current
  policy comes from live DNS (`dmarc_lookup()`), falling back to the
  newest report: effective policy is `p` of the sender's own record,
  else the parent's `sp` (or `p`).
- `src/dnscheck.php` — live DNS via `dns_get_record()` (memoized):
  `dns_txt()`, `dns_mx()`, `dns_has_key()` (follows CNAMEs by hand
  FIRST — asking the TXT of a CNAME name took ~7 s on Windows),
  `dmarc_lookup()` (own `_dmarc` record, else the main domain's with
  `sp`; 2+ own records = none applies), `dns_check()` (findings with
  levels ok / info / warn / bad).
- `src/views/header.php` + `footer.php` — shared layout; pages set
  `$title`/`$active` before requiring the header.
- `bin/imap-fetch.php` — CLI-only. Contains a minimal IMAP-over-TLS
  client (LOGIN/LIST/SELECT/UID FETCH/UID STORE via raw socket — PHP 8.4
  has no core imap extension) and a recursive MIME attachment extractor.
  Accounts: the `imap` block itself (one mailbox) or `imap.accounts` (a
  list, which then replaces it; `imap.enabled` stays the master switch).
  Accounts run one after another; one failing is logged, the others
  continue, and the run exits 1. Scans every folder except
  Trash/Drafts/Sent (or the account's explicit `folders` list).
  Progress lives in `uploads/imap/state.json` as
  `{"user@host": {folder: {uidvalidity, last_uid}}}` (highest examined
  UID; reset when the folder's UIDVALIDITY changes; `--all` rescans
  everything); the old flat single-account layout is migrated to the
  first configured account. New
  messages are pre-filtered by BODYSTRUCTURE so only report-shaped ones
  are downloaded in full (`BODY.PEEK[]`), and only messages that yielded
  a report attachment are flagged `\Seen` — it never moves or deletes
  mail, and non-report mail keeps its unread status. Size safety:
  messages over ~1.5× `max_upload_bytes` are refused before download
  (RFC822.SIZE), the client hard-rejects oversized literals as defense
  in depth, and attachments over `max_upload_bytes` are skipped before
  import. A folder that fails to scan is logged and skipped without
  aborting the run (its state is not advanced). Attachments land in
  `uploads/imap/`.
- `migrations/NN_*.sql` — numbered schema migrations, applied in order by
  `scripts/init_db.php` and recorded in `schema_migrations` (that
  bookkeeping table is created by `init_db.php` itself, not by any
  migration). Never edit an applied migration; add a new numbered file.
  Keep statements simple (split on `;`, no stored routines/DELIMITER).
  Schema: `reports` (unique `(org_name, report_id)`) 1—N `records`
  (FK ON DELETE CASCADE).

## Conventions

- Repo is 100% English: code, comments, commits, issues, PRs, docs.
- Escape every dynamic output with `e()`; PDO prepared statements for
  every query; validate user input (`filter_input`, `FILTER_VALIDATE_IP`).
- Minimize hardcoded values — tunables live in `config.php`.
- DMARC-result semantics used everywhere: **aligned** = evaluated DKIM
  pass AND SPF pass; **partial** = exactly one passes (DMARC still
  passes); **fail** = neither (highlighted red as possible spoofing).
  Auth results are colored with `result_class()` (pass green, fail red);
  dispositions with `disposition_class()` (quarantine/reject amber — the
  receiver acting on policy is attention-worthy, not an auth failure).
  A missing (NULL) evaluated result counts as a fail everywhere:
  `COALESCE(..., '') <> 'pass'` in SQL, `!== 'pass'` in PHP — keep both
  in sync.
- Timestamps in reports are Unix epoch; they are converted to the
  configured timezone at insert time and stored as DATETIME.
- Date filtering: `date_filter()` matches on the report's `date_begin`
  (window start), remembers the last explicit range in the session so it
  follows the user across pages, and defaults to the last 90 days. The
  shared filter UI (domain selector when >1 domain, From/To inputs +
  progressive quick presets, applied on change via `app.js`) lives in
  `src/views/date_filter.php`. The domain cards and the policy advisor
  do NOT follow it (fixed windows, see below).
- Domain filtering: `domain_filter()` reads `?domain=` (empty = all
  domains), accepts only domains present in `reports.domain`, and is
  remembered in the session like the date range. Every query scoped by
  the filters appends `domain_sql()` (`AND rep.domain = :domain`, so the
  reports table must be aliased `rep`). The dashboard's domain cards
  ignore both filters on purpose (fixed `health.days` window, default
  30; advice over `advisor.weeks`, default 4), and the policy advisor
  panel shows the selected domain's card-row advice (same function, so
  they never disagree).
- The app ships with NO authentication (documented in README) — intended
  for localhost/LAN use only.
- Update README.md/this file in the same commit as any behavior change.
- Secrets: `config.php` and `uploads/` are gitignored; never put
  credentials in code, commits, issue text, or CLI arguments.
