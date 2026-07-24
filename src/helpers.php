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
 * Read the ?from= / ?to= query-string filter, defaulting to the last 90
 * days. Returns ['from' => 'YYYY-MM-DD', 'to' => 'YYYY-MM-DD'].
 */
function date_filter(): array
{
    $from = $_GET['from'] ?? '';
    $to   = $_GET['to'] ?? '';

    // Only accept well-formed dates; anything else falls back to defaults.
    $valid = fn(string $d): bool => (bool)preg_match('/^\d{4}-\d{2}-\d{2}$/', $d);

    if (!$valid($from)) {
        $from = date('Y-m-d', strtotime('-90 days'));
    }
    if (!$valid($to)) {
        $to = date('Y-m-d');
    }
    return ['from' => $from, 'to' => $to];
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
