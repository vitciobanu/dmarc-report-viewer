<?php
/**
 * Small presentation helpers shared by every page.
 */

/**
 * Escape a value for safe HTML output. ALWAYS wrap dynamic output in e().
 * This is the single defense against XSS (script injection) in the app.
 */
function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

/**
 * Format a stored DATETIME string ("2026-07-20 02:00:00") for display,
 * e.g. "20 Jul 2026". Returns '—' for null/empty.
 */
function fmt_date(?string $datetime): string
{
    if (!$datetime) {
        return '—';
    }
    return date('d M Y', strtotime($datetime));
}

/**
 * Same as fmt_date() but includes the time: "20 Jul 2026 02:00".
 */
function fmt_datetime(?string $datetime): string
{
    if (!$datetime) {
        return '—';
    }
    return date('d M Y H:i', strtotime($datetime));
}

/**
 * Format a ratio as a percentage with one decimal: pct(45, 60) => "75.0%".
 * Returns '—' when the denominator is zero (no data).
 */
function pct(int|float $part, int|float $total): string
{
    if ($total == 0) {
        return '—';
    }
    return number_format($part / $total * 100, 1) . '%';
}

/**
 * Convert a Unix timestamp (as found in DMARC reports) to a DATETIME
 * string in the configured timezone, ready to INSERT into MySQL.
 */
function ts_to_datetime(int $timestamp): string
{
    return date('Y-m-d H:i:s', $timestamp);
}

/* ----------------------------------------------------------------------
 * Flash messages (Post/Redirect/Get pattern)
 *
 * A POST handler stores its outcome in the session, redirects, and the
 * next GET request shows the message once. This prevents the "resubmit
 * form?" browser warning on refresh.
 * ------------------------------------------------------------------- */

/** Queue a flash message. $type is 'success', 'error' or 'info'. */
function flash_set(string $type, string $message): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
}

/** Pop and return all queued flash messages (empties the queue). */
function flash_get(): array
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    $messages = $_SESSION['flash'] ?? [];
    unset($_SESSION['flash']);
    return $messages;
}

/* ----------------------------------------------------------------------
 * Date-range filter shared by dashboard pages
 * ------------------------------------------------------------------- */

/**
 * Read the ?from= / ?to= query-string filter. An explicitly chosen range
 * is remembered in the session, so it follows the user from page to page;
 * without one the default is the last 90 days.
 * Returns ['from' => 'YYYY-MM-DD', 'to' => 'YYYY-MM-DD'].
 */
function date_filter(): array
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }

    // Only accept well-formed dates; anything else falls back to the
    // remembered range, then to the defaults.
    $valid = fn(string $d): bool => (bool)preg_match('/^\d{4}-\d{2}-\d{2}$/', $d);

    $from = $_GET['from'] ?? '';
    $to   = $_GET['to'] ?? '';

    if ($valid($from)) {
        $_SESSION['filter_from'] = $from;
    } else {
        $from = $_SESSION['filter_from'] ?? date('Y-m-d', strtotime('-90 days'));
    }
    if ($valid($to)) {
        $_SESSION['filter_to'] = $to;
    } else {
        $to = $_SESSION['filter_to'] ?? date('Y-m-d');
    }
    return ['from' => $from, 'to' => $to];
}

/* ----------------------------------------------------------------------
 * Domain filter (for monitoring several domains in one app)
 * ------------------------------------------------------------------- */

/**
 * Every domain that has at least one report, alphabetically. Memoized:
 * several parts of a page ask for it.
 */
function known_domains(): array
{
    static $domains = null;
    if ($domains === null) {
        $domains = Database::pdo()
            ->query('SELECT DISTINCT domain FROM reports ORDER BY domain')
            ->fetchAll(PDO::FETCH_COLUMN);
    }
    return $domains;
}

/**
 * Read the ?domain= query-string filter. Returns the selected domain, or
 * null for "all domains".
 *   ?domain=example.com  select that domain (remembered in the session,
 *                        so it follows the user across pages)
 *   ?domain=             (present but empty) back to all domains
 *   no parameter         keep whatever was chosen before
 * Only domains that actually appear in reports are accepted.
 */
function domain_filter(): ?string
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }

    if (array_key_exists('domain', $_GET)) {
        $asked = (string)$_GET['domain'];
        $_SESSION['filter_domain'] = in_array($asked, known_domains(), true) ? $asked : null;
    }

    $domain = $_SESSION['filter_domain'] ?? null;
    // A remembered domain whose reports were all deleted is dropped.
    return in_array($domain, known_domains(), true) ? $domain : null;
}

/**
 * SQL fragment restricting a query to the selected domain, for queries
 * that alias the reports table as "rep". Adds the :domain parameter to
 * $params when needed; returns '' (no restriction) for all domains.
 */
function domain_sql(?string $domain, array &$params): string
{
    if ($domain === null) {
        return '';
    }
    $params[':domain'] = $domain;
    return ' AND rep.domain = :domain';
}

/**
 * Health color of a domain from its DMARC pass rate (messages where at
 * least one aligned mechanism passed): 'ok' (green), 'warn' (amber),
 * 'bad' (red), or 'neutral' when there is no data. Thresholds come from
 * the health block of config.php.
 */
function health_state(int $total, int $fails): string
{
    if ($total === 0) {
        return 'neutral';
    }
    $cfg     = Database::config()['health'] ?? [];
    $passPct = ($total - $fails) / $total * 100;
    return match (true) {
        $passPct >= (float)($cfg['ok_pct'] ?? 99)   => 'ok',
        $passPct >= (float)($cfg['warn_pct'] ?? 90) => 'warn',
        default                                     => 'bad',
    };
}

/**
 * Reverse-DNS lookup with an in-request cache, so the same IP is only
 * resolved once per upload batch. Returns null when there is no PTR
 * record or lookups are disabled in config.
 */
function rdns_lookup(string $ip): ?string
{
    static $cache = [];

    if (!(Database::config()['rdns_lookup'] ?? true)) {
        return null;
    }
    if (array_key_exists($ip, $cache)) {
        return $cache[$ip];
    }

    $host = gethostbyaddr($ip);
    // gethostbyaddr() returns the IP itself (or false) when there is no PTR.
    $cache[$ip] = ($host !== false && $host !== $ip) ? $host : null;
    return $cache[$ip];
}

/**
 * CSS class for coloring an SPF/DKIM authentication result in tables:
 * green for pass, red for fail, neutral otherwise.
 */
function result_class(?string $result): string
{
    return match (strtolower($result ?? '')) {
        'pass' => 'ok',
        'fail', 'permerror' => 'bad',
        default => 'neutral',
    };
}

/**
 * CSS class for coloring a DMARC disposition (what the receiver DID with
 * the mail). Unlike an auth failure, quarantine/reject is not inherently
 * "bad" — it may be your policy working as intended against spoofing —
 * so it gets an attention-drawing amber, not red.
 */
function disposition_class(?string $disposition): string
{
    return match (strtolower($disposition ?? '')) {
        'quarantine', 'reject' => 'warn',
        default => 'neutral',
    };
}
