<?php
/**
 * Live DNS checks: SPF, DMARC, MX and DKIM records of a domain, plus
 * plain-language findings (used by the DNS page and by the dashboard to
 * know each domain's CURRENT policy).
 *
 * Two ways to look records up (dns.resolver in config.php):
 *   'system' (default) — this server's normal resolver (dns_get_record).
 *                        A value can be up to one TTL old after a change.
 *   'doh'              — DNS-over-HTTPS to a public resolver (Cloudflare
 *                        by default): the same answers mail receivers
 *                        get, even when the local resolver (some NAT or
 *                        virtual-switch DNS proxies) serves stale data.
 *                        If a DoH request fails, that one lookup falls
 *                        back to the system resolver.
 *
 * Requires src/domains.php (domain_type, domain_group, state_rank).
 */

/** Which resolver is in use: 'doh' or 'system'. */
function dns_resolver(): string
{
    return (Database::config()['dns']['resolver'] ?? 'system') === 'doh' ? 'doh' : 'system';
}

/**
 * The per-request lookup cache, shared by dns_lookup() and
 * dns_prefetch(): ["TXT example.com" => [records...]]. Returned by
 * reference ("&") so callers can add to it.
 */
function &dns_cache(): array
{
    static $cache = [];
    return $cache;
}

/**
 * Look up the $type records ('TXT', 'MX' or 'CNAME') published at
 * exactly $name. Memoized per request. Each record is
 * ['value' => text / target, 'pri' => MX preference or 0].
 * TXT values split into several strings are joined back into one.
 */
function dns_lookup(string $name, string $type): array
{
    $cache = &dns_cache();
    $name  = strtolower(rtrim($name, '.'));
    $key   = "$type $name";
    if (!isset($cache[$key])) {
        $records = null;
        if (dns_resolver() === 'doh') {
            $records = doh_parse(http_get_json(doh_url($name, $type)), $name, $type);
        }
        // null = DoH not used or failed → ask the system resolver.
        $cache[$key] = $records ?? system_query($name, $type);
    }
    return $cache[$key];
}

/**
 * Run many DoH lookups IN PARALLEL and keep the answers in the cache, so
 * the dns_lookup() calls that follow are instant. Each DoH request takes
 * ~100 ms; a page needing 50 of them would take 5 s one by one, but well
 * under a second this way. Does nothing for the system resolver or
 * without the curl extension (dns_lookup() then works one by one).
 *
 * $queries: [[name, type], ...]
 */
function dns_prefetch(array $queries): void
{
    if (dns_resolver() !== 'doh' || !function_exists('curl_multi_init')) {
        return;
    }
    $cache   = &dns_cache();
    $multi   = curl_multi_init();
    $handles = [];
    foreach ($queries as [$name, $type]) {
        $name = strtolower(rtrim($name, '.'));
        $key  = "$type $name";
        if (isset($cache[$key]) || isset($handles[$key])) {
            continue;
        }
        $h = curl_init();
        curl_setopt_array($h, doh_curl_options(doh_url($name, $type)));
        curl_multi_add_handle($multi, $h);
        $handles[$key] = [$h, $name, $type];
    }

    // Let curl run all transfers until every one has finished.
    do {
        $status = curl_multi_exec($multi, $running);
        if ($running) {
            curl_multi_select($multi, 1.0);
        }
    } while ($running && $status === CURLM_OK);

    foreach ($handles as $key => [$h, $name, $type]) {
        $ok   = curl_getinfo($h, CURLINFO_RESPONSE_CODE) === 200;
        $body = $ok ? curl_multi_getcontent($h) : null;
        // A failed request is simply not cached: dns_lookup() will try
        // again later (and fall back to the system resolver if needed).
        $records = doh_parse($body, $name, $type);
        if ($records !== null) {
            $cache[$key] = $records;
        }
        curl_multi_remove_handle($multi, $h);
        curl_close($h);
    }
    curl_multi_close($multi);
}

/** dns_lookup() through PHP's dns_get_record (the system resolver). */
function system_query(string $name, string $type): array
{
    $name = strtolower(rtrim($name, '.'));
    $flag = ['TXT' => DNS_TXT, 'MX' => DNS_MX, 'CNAME' => DNS_CNAME][$type];
    // "@" hides PHP's warning for names that do not exist — an empty
    // result is a normal answer here, not an error.
    $out = [];
    foreach (@dns_get_record($name, $flag) ?: [] as $r) {
        if (strtolower($r['host'] ?? '') !== $name) {
            continue; // e.g. the TXT of a CNAME target, not of $name itself
        }
        $out[] = match ($type) {
            'TXT'   => ['value' => isset($r['entries']) ? implode('', $r['entries']) : ($r['txt'] ?? ''), 'pri' => 0],
            'MX'    => ['value' => $r['target'] ?? '', 'pri' => (int)($r['pri'] ?? 0)],
            'CNAME' => ['value' => $r['target'] ?? '', 'pri' => 0],
        };
    }
    return $out;
}

/**
 * URL of a DoH JSON query. Both Cloudflare (https://cloudflare-dns.com/
 * dns-query) and Google (https://dns.google/resolve) speak this format.
 */
function doh_url(string $name, string $type): string
{
    $base = Database::config()['dns']['doh_url'] ?? 'https://cloudflare-dns.com/dns-query';
    return $base . '?' . http_build_query(['name' => $name, 'type' => $type]);
}

/**
 * Turn a DoH JSON answer into dns_lookup() records. Returns null when the
 * body is missing or the server reported an error (so the caller can
 * fall back); an empty array is a valid "no such record" answer.
 */
function doh_parse(?string $body, string $name, string $type): ?array
{
    $json = $body === null ? null : json_decode($body, true);
    // Status 0 = NOERROR, 3 = NXDOMAIN (name does not exist: a valid,
    // empty answer). Anything else (SERVFAIL...) counts as a failure.
    if (!is_array($json) || !in_array($json['Status'] ?? -1, [0, 3], true)) {
        return null;
    }

    $name     = strtolower(rtrim($name, '.'));
    $typeCode = ['TXT' => 16, 'MX' => 15, 'CNAME' => 5][$type];
    $out = [];
    foreach ($json['Answer'] ?? [] as $a) {
        if (($a['type'] ?? 0) !== $typeCode || strtolower(rtrim($a['name'] ?? '', '.')) !== $name) {
            continue; // other types/names in the answer (CNAME chain...)
        }
        $data = trim($a['data'] ?? '');
        if ($type === 'TXT') {
            // Cloudflare quotes each string ("part1" "part2"); Google
            // returns plain text. Join quoted parts back into one value.
            if (str_starts_with($data, '"') && preg_match_all('/"((?:[^"\\\\]|\\\\.)*)"/', $data, $m)) {
                $data = stripcslashes(implode('', $m[1]));
            }
            $out[] = ['value' => $data, 'pri' => 0];
        } elseif ($type === 'MX') {
            // "10 mx1.example.com." — preference, then target.
            [$pri, $target] = array_pad(preg_split('/\s+/', $data, 2), 2, '');
            $out[] = ['value' => rtrim($target, '.'), 'pri' => (int)$pri];
        } else {
            $out[] = ['value' => rtrim($data, '.'), 'pri' => 0];
        }
    }
    return $out;
}

/** curl options for one DoH request (certificates are verified). */
function doh_curl_options(string $url): array
{
    $timeout = max(1, (int)(Database::config()['dns']['timeout'] ?? 5));
    return [
        CURLOPT_URL            => $url,
        CURLOPT_HTTPHEADER     => ['Accept: application/dns-json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
    ];
}

/**
 * GET one DoH URL; returns the body or null on any error. Uses curl when
 * available (reusing ONE connection for the whole request, much faster
 * than a new TLS handshake each time), else file_get_contents.
 */
function http_get_json(string $url): ?string
{
    static $curl = null;
    if (function_exists('curl_init')) {
        $curl ??= curl_init();
        curl_setopt_array($curl, doh_curl_options($url));
        $body = curl_exec($curl);
        $code = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        return ($body !== false && $code === 200) ? $body : null;
    }
    $ctx = stream_context_create(['http' => [
        'header'  => "Accept: application/dns-json\r\n",
        'timeout' => max(1, (int)(Database::config()['dns']['timeout'] ?? 5)),
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    return $body === false ? null : $body;
}

/** TXT strings published at exactly $name. */
function dns_txt(string $name): array
{
    return array_column(dns_lookup($name, 'TXT'), 'value');
}

/** MX targets of $name, lowest preference first. */
function dns_mx(string $name): array
{
    $records = dns_lookup($name, 'MX');
    usort($records, fn($a, $b) => $a['pri'] <=> $b['pri']);
    return array_map(fn($r) => $r['value'] === '' ? '. (null MX)' : $r['value'], $records);
}

/**
 * True when a DKIM key is published at $name — directly as TXT, or
 * through a CNAME (common with mail providers) whose target holds it.
 *
 * The CNAME is looked up FIRST on purpose: with the system resolver,
 * asking for the TXT of a name that is a CNAME can take several seconds,
 * while following the CNAME by hand is instant.
 */
function dns_has_key(string $name): bool
{
    for ($hop = 0; $hop < 3; $hop++) {           // follow at most 3 CNAMEs
        $cname = dns_lookup($name, 'CNAME');
        if (!$cname) {
            break;
        }
        $name = $cname[0]['value'];
    }
    return (bool)dns_lookup($name, 'TXT');
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
