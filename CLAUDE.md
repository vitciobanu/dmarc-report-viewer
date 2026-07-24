# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A self-hosted DMARC aggregate-report viewer: upload (or IMAP-fetch) the
`.xml.gz`/`.zip` reports that mailbox providers email you, parse them into
MySQL, and browse dashboards. See README.md for features and setup.

**Stack:** plain PHP ≥ 8.1 (`pdo_mysql`, `zip`, `zlib`, `simplexml`;
`openssl` for IMAP) + MySQL 8. No frameworks, no Composer, no Node, no
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
  (`index.php` dashboard, `upload.php`, `report.php`, `ips.php`).
  POST handlers follow Post/Redirect/Get with flash messages
  (`flash_set()`/`flash_get()` in `src/helpers.php`). `public/assets/`
  holds `style.css` and `app.js` (upload drag-drop; no AJAX, no libs —
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
  `rdns_lookup()` (memoized PTR lookup, stored on records at insert time).
- `src/views/header.php` + `footer.php` — shared layout; pages set
  `$title`/`$active` before requiring the header.
- `bin/imap-fetch.php` — CLI-only. Contains a minimal IMAP-over-TLS
  client (LOGIN/LIST/SELECT/UID FETCH/UID STORE via raw socket — PHP 8.4
  has no core imap extension) and a recursive MIME attachment extractor.
  Scans every folder except Trash/Drafts/Sent (or the explicit
  `imap.folders` list). Per-folder progress lives in
  `uploads/imap/state.json` (highest examined UID; reset when the
  folder's UIDVALIDITY changes; `--all` rescans everything). New
  messages are pre-filtered by BODYSTRUCTURE so only report-shaped ones
  are downloaded in full (`BODY.PEEK[]`), and only messages that yielded
  a report attachment are flagged `\Seen` — it never moves or deletes
  mail, and non-report mail keeps its unread status. Attachments land in
  `uploads/imap/`; oversized ones are skipped per `max_upload_bytes`,
  same as the upload page.
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
- Timestamps in reports are Unix epoch; they are converted to the
  configured timezone at insert time and stored as DATETIME.
- Date filtering: `date_filter()` defaults to the last 90 days and
  matches on the report's `date_begin` (window start). Exception: the
  dashboard's policy advisor uses its own fixed 60-day window and reads
  "current policy" from the newest report — independent of the filter.
- The app ships with NO authentication (documented in README) — intended
  for localhost/LAN use only.
- Update README.md/this file in the same commit as any behavior change.
- Secrets: `config.php` and `uploads/` are gitignored; never put
  credentials in code, commits, issue text, or CLI arguments.
