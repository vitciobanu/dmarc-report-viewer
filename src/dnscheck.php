<?php
/**
 * Live DNS checks: SPF, DMARC, MX and DKIM records of a domain, plus
 * plain-language findings (used by the DNS page and by the dashboard to
 * know each domain's CURRENT policy).
 *
 * Lookups go through this server's normal DNS resolver (PHP's
 * dns_get_record), so a value can be up to one TTL old after a change —
 * exactly what mail receivers see too.
 *
 * Requires src/domains.php (domain_type, domain_ancestors).
 */

/**
 * TXT strings published at exactly $name (long records split into
 * several strings are joined back). Memoized per request.
 */
function dns_txt(string $name): array
{
    static $cache = [];
    $name = strtolower(rtrim($name, '.'));
    if (!isset($cache[$name])) {
        // "@" hides PHP's warning for names that do not exist — an
        // empty result is a normal answer here, not an error.
        $records = @dns_get_record($name, DNS_TXT) ?: [];
        $cache[$name] = [];
        foreach ($records as $r) {
            if (strtolower($r['host'] ?? '') === $name) {
                $cache[$name][] = isset($r['entries']) ? implode('', $r['entries']) : ($r['txt'] ?? '');
            }
        }
    }
    return $cache[$name];
}

/** MX targets of $name, lowest preference first. */
function dns_mx(string $name): array
{
    $records = @dns_get_record($name, DNS_MX) ?: [];
    usort($records, fn($a, $b) => ($a['pri'] ?? 0) <=> ($b['pri'] ?? 0));
    return array_map(fn($r) => $r['target'] === '' ? '. (null MX)' : $r['target'], $records);
}

/**
 * True when a DKIM key is published at $name — directly as TXT, or
 * through a CNAME (common with mail providers) whose target holds it.
 *
 * The CNAME is looked up FIRST on purpose: asking for the TXT of a name
 * that is a CNAME can take several seconds on some resolvers, while
 * following the CNAME by hand is instant.
 */
function dns_has_key(string $name): bool
{
    for ($hop = 0; $hop < 3; $hop++) {           // follow at most 3 CNAMEs
        $cname = @dns_get_record($name, DNS_CNAME) ?: [];
        if (!$cname) {
            break;
        }
        $name = $cname[0]['target'];
    }
    return (bool)(@dns_get_record($name, DNS_TXT) ?: []);
}

/** Split "v=DMARC1; p=none; rua=..." into ['v' => 'DMARC1', 'p' => 'none', ...]. */
function dmarc_tags(string $record): array
{
    $tags = [];
    foreach (explode(';', $record) as $part) {
        if (str_contains($part, '=')) {
            [$k, $v] = explode('=', $part, 2);
            $tags[strtolower(trim($k))] = trim($v);
        }
    }
    return $tags;
}

/**
 * The DMARC record that applies to $domain, the way receivers find it:
 * its own _dmarc record, or else the one of its organizational domain
 * (the main domain, see domain_group()), whose sp= then applies.
 *
 * Returns [
 *   'own'     => DMARC records at _dmarc.$domain (more than 1 = broken),
 *   'source'  => domain whose record applies (null if none),
 *   'record'  => that record's text, 'tags' => parsed tags,
 *   'policy'  => effective policy (p, or sp/p when inherited),
 *   'tag'     => 'p' or 'sp', 'pct' => int,
 * ]
 */
function dmarc_lookup(string $domain): array
{
    static $cache = [];
    $domain = strtolower($domain);
    if (isset($cache[$domain])) {
        return $cache[$domain];
    }

    $isDmarc = fn($t) => stripos(ltrim($t), 'v=DMARC1') === 0;
    $own = array_values(array_filter(dns_txt("_dmarc.$domain"), $isDmarc));
    $result = ['own' => $own, 'source' => null, 'record' => null, 'tags' => [],
               'policy' => null, 'tag' => 'p', 'pct' => 100];

    if (count($own) === 1) {
        $result['source'] = $domain;
        $result['record'] = $own[0];
    } elseif (count($own) === 0) {
        $org = domain_group($domain);
        if ($org !== $domain) {
            $parent = array_values(array_filter(dns_txt("_dmarc.$org"), $isDmarc));
            if (count($parent) === 1) {
                $result['source'] = $org;
                $result['record'] = $parent[0];
                $result['tag']    = 'sp';
            }
        }
    }
    // (2+ own records: receivers ignore them all → no applicable record.)

    if ($result['record'] !== null) {
        $tags = dmarc_tags($result['record']);
        $result['tags']   = $tags;
        $result['policy'] = $result['tag'] === 'sp' ? ($tags['sp'] ?? $tags['p'] ?? null) : ($tags['p'] ?? null);
        $result['pct']    = isset($tags['pct']) ? (int)$tags['pct'] : 100;
    }
    return $cache[$domain] = $result;
}

/**
 * Full check of one domain for the DNS page.
 * $selectors: DKIM selectors seen for this domain in the reports.
 * Returns the raw values plus 'findings' => [['level' => ok|info|warn|bad, 'text' => ...]].
 */
function dns_check(string $domain, array $selectors = []): array
{
    $type  = domain_type($domain);
    $dmarc = dmarc_lookup($domain);
    $spf   = array_values(array_filter(dns_txt($domain), fn($t) => stripos(ltrim($t), 'v=spf1') === 0));
    $mx    = dns_mx($domain);
    $dkim  = [];
    foreach ($selectors as $sel) {
        $dkim[$sel] = dns_has_key("$sel._domainkey.$domain");
    }

    $f = [];
    $add = function (string $level, string $text) use (&$f) { $f[] = ['level' => $level, 'text' => $text]; };

    // ---- DMARC
    $nOwn = count($dmarc['own']);
    if ($nOwn > 1) {
        $add('bad', "$nOwn DMARC records at _dmarc.$domain: receivers ignore all of them. Keep exactly one.");
    } elseif ($dmarc['record'] === null) {
        $add('bad', "No DMARC record (none at _dmarc.$domain, nor inherited from its main domain).");
    } else {
        if ($dmarc['tag'] === 'sp') {
            $add('info', "No record of its own: inherits sp=" . ($dmarc['policy'] ?? '?') . " from _dmarc.{$dmarc['source']}.");
        }
        if (!in_array($dmarc['policy'], ['none', 'quarantine', 'reject'], true)) {
            $add('bad', "Policy is missing or invalid (\"" . ($dmarc['policy'] ?? '') . "\").");
        }
        if (empty($dmarc['tags']['rua'])) {
            $add('warn', "No rua= tag: nobody receives aggregate reports for this domain.");
        }
        if ($type === 'parked' && ($dmarc['policy'] !== 'reject' || $dmarc['pct'] < 100)) {
            $add('warn', "Parked domain: publish p=reject (now {$dmarc['tag']}={$dmarc['policy']}" . ($dmarc['pct'] < 100 ? ", pct={$dmarc['pct']}" : '') . ").");
        }
        if ($type === 'sending' && $dmarc['policy'] === 'none') {
            $add('info', 'Monitoring only (p=none): the dashboard tells you when it is safe to tighten.');
        }
    }

    // ---- SPF
    if (count($spf) > 1) {
        $add('bad', count($spf) . ' SPF records: receivers treat this as an error (permerror). Merge them into one.');
    } elseif (!$spf) {
        $add('warn', $type === 'parked'
            ? 'No SPF record: publish "v=spf1 -all" (nobody may send for this domain).'
            : 'No SPF record: receivers cannot check which servers may send for this domain.');
    } else {
        $value = trim($spf[0]);
        if (preg_match('/(^|\s)\+?all\b/i', $value)) {
            $add('bad', 'SPF ends in "+all": it authorizes ANY server in the world to send as this domain.');
        }
        if ($type === 'parked' && strtolower(preg_replace('/\s+/', ' ', $value)) !== 'v=spf1 -all') {
            $add('warn', 'Parked domain: SPF should be exactly "v=spf1 -all" — the current one still authorizes senders.');
        }
    }

    // ---- DKIM
    foreach ($dkim as $sel => $ok) {
        if (!$ok) {
            $add('warn', "DKIM selector \"$sel\" appears in reports but $sel._domainkey.$domain is not published.");
        }
    }
    if ($type === 'sending' && !$selectors) {
        $add('info', 'No DKIM signature seen in the reports yet.');
    }

    if (!$f) {
        $add('ok', 'Everything looks right.');
    }

    $worst = 'ok';
    foreach ($f as $x) {
        if (state_rank($x['level'] === 'info' ? 'ok' : $x['level']) > state_rank($worst)) {
            $worst = $x['level'];
        }
    }

    return ['domain' => $domain, 'type' => $type, 'dmarc' => $dmarc, 'spf' => $spf,
            'mx' => $mx, 'dkim' => $dkim, 'findings' => $f, 'state' => $worst];
}
