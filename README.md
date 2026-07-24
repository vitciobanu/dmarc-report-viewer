# DMARC Report Viewer

A small, self-hosted web app to collect and visualize **DMARC aggregate
reports** — the `.xml.gz` / `.zip` attachments that Google, Mimecast,
Yahoo & co. email you when you publish a DMARC record.

Plain **PHP 8 + MySQL**. No frameworks, no Composer, no Node, no build
step: clone it, point any PHP-enabled web server at `public/`, done. A
lightweight alternative to hosted DMARC dashboards (Postmark DMARC,
EasyDMARC...) and to heavier self-hosted stacks (parsedmarc + Elasticsearch,
dmarc-visualizer + Grafana).

## Features

- **Upload page** with drag & drop and multi-file support — accepts
  `.xml`, `.xml.gz` and `.zip` (including zips that batch several reports).
  Files are detected by magic bytes, so misnamed attachments still work.
- **Duplicate-safe**: reports are deduplicated by `(organization,
  report_id)`; re-uploading the same file is always a no-op.
- **Dashboard**: totals, SPF / DKIM / full-alignment pass rates, DMARC
  failure count, a daily stacked-bar timeline (inline SVG, no JS chart
  libs), report list, and top source IPs — all filtered by date range.
- **Policy advisor**: tells you when your alignment rate over the last 60
  days makes it safe to move from `p=none` to `p=quarantine` to `p=reject`.
- **Source-IP explorer**: every IP that sent mail as your domain, with
  volume, pass rates, reverse-DNS hostname (resolved and stored at import
  time), first/last seen, and drill-down to every record. Rows with DMARC
  failures are highlighted in red.
- **Report detail**: full metadata + every record, with all identifiers
  (header from, envelope from/to) and the raw auth results (DKIM
  selector/domain, SPF domain, policy-override reasons).
- **IMAP fetcher** (`bin/imap-fetch.php`): optionally pull report emails
  straight from a mailbox over TLS — no PHP imap extension needed (it was
  dropped from core in PHP 8.4; this speaks the protocol over a raw
  socket). Scans all folders, remembers what it has already examined,
  and never disturbs non-report mail. Run it by hand or from a
  scheduled task.
- **Safety**: PDO prepared statements everywhere, all output escaped,
  XXE-hardened XML parsing (DOCTYPEs rejected, `LIBXML_NONET`),
  decompression size limits against zip bombs, structural validation that
  the XML really is a DMARC aggregate report.

## Requirements

- PHP ≥ 8.1 with `pdo_mysql`, `zip`, `zlib`, `simplexml` (and `openssl`
  for the IMAP fetcher) — all bundled in normal PHP builds.
- MySQL 8 (or MariaDB).
- Any web server that runs PHP (Apache, nginx+FPM, or just `php -S`).

## Setup

```sh
git clone <this repo>
cd dmarc-report-viewer

# 1. Database + dedicated user: copy scripts/create_db.sql to
#    scripts/create_db.local.sql (gitignored), set a password in the copy,
#    then run it as an admin user (MySQL Workbench or the mysql CLI).

# 2. App config: copy the template and fill in the same password.
cp config.sample.php config.php

# 3. Create the tables (idempotent migration runner).
php scripts/init_db.php

# 4. Serve public/ — quick start:
php -S 127.0.0.1:8082 -t public
# ...or add an Apache vhost with DocumentRoot pointing at public/.
```

Open <http://127.0.0.1:8082>, go to **Upload**, and drop your report
files in.

### IMAP fetching (optional)

Fill the `imap` block in `config.php` — use a dedicated **app password**
(most providers offer them in their security settings, ideally with
IMAP-only scope), never your main password. Then:

```sh
php bin/imap-fetch.php        # process messages new since the last run
php bin/imap-fetch.php --all  # rescan every folder from scratch
```

It scans **every folder** of the account (except Trash, Drafts and
Sent), so reports are found even when they land in the inbox or get
filed into the wrong folder; set `imap.folders` to an explicit list to
restrict it. It is designed to leave your mailbox alone:

- Progress is remembered per folder (`uploads/imap/state.json`), so each
  message is examined at most once across runs — `--all` starts over.
- Only the cheap MIME structure of new messages is fetched; a full
  message body is downloaded only when that structure looks like it
  carries a report file.
- Only messages that really contained a report are marked as read —
  everything else keeps its read/unread status. Nothing is ever moved
  or deleted.

Attachments over `max_upload_bytes` are skipped, same as on the upload
page. Schedule it (Windows Task Scheduler, cron) for a zero-touch
pipeline.

## Database schema

Two tables (created by `migrations/01_schema.sql`):

- **`reports`** — one row per aggregate report: reporting org, report id,
  date range, published policy (`p`, `sp`, `pct`, `adkim`, `aspf`).
  Unique on `(org_name, report_id)`.
- **`records`** — one row per `<record>`: source IP (+ stored rDNS
  hostname), message count, DMARC-evaluated SPF/DKIM results,
  disposition, identifiers, raw auth results, override reasons.

Schema changes are numbered `migrations/NN_*.sql` files; `php
scripts/init_db.php` applies pending ones and records them in
`schema_migrations` (safe to re-run).

## Security notes

This app ships **without authentication** — it is meant for a local
machine or a trusted LAN. If you expose it to the internet, put it
behind your web server's auth (HTTP Basic, SSO proxy...) — and consider
that the reports reveal your mail flow metadata.

## License

MIT
