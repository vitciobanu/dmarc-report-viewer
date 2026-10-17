<?php
/**
 * Domain model for the dashboard cards and the policy advisor.
 *
 * Vocabulary used in this file:
 *   sender         the domain in the From: header of the mail (records.
 *                  header_from) — "who sent it". One card row per sender.
 *   policy domain  the domain whose DMARC record was applied (reports.
 *                  domain). For a subdomain WITHOUT its own record this is
 *                  the parent, and the parent's sp= tag is what applies.
 *   group          the main domain a sender belongs to: one card each.
 *   type           'sending' (the domain sends mail) or 'parked' (it never
 *                  does), from the domains map in config.php.
 *
 * The CURRENT policy of each domain comes from a live DNS lookup
 * (dmarc_lookup() in src/dnscheck.php) — reports arrive a day late and
 * would still show a policy you have just changed. The newest report is
 * the fallback when DNS gives no answer.
 *
 * Requires src/db.php, src/helpers.php and src/dnscheck.php.
 */

/* ----------------------------------------------------------------------
 * Configuration: monitored domains, types, grouping
 * ------------------------------------------------------------------- */

/** The domains map from config.php, lowercased: [name => 'sending'|'parked']. */
function configured_domains(): array
{
    static $map = null;
    if ($map === null) {
        $map = [];
        foreach (Database::config()['domains'] ?? [] as $name => $type) {
            $map[strtolower(trim($name))] = ($type === 'parked') ? 'parked' : 'sending';
        }
    }
    return $map;
}

/**
 * Every "ancestor" of a domain name, itself first:
 * a.b.example.com → [a.b.example.com, b.example.com, example.com, com]
 */
function domain_ancestors(string $name): array
{
    $labels = explode('.', strtolower($name));
    $list = [];
    while ($labels) {
        $list[] = implode('.', $labels);
        array_shift($labels);
    }
    return $list;
}

/**
 * Type of a domain: its own configured type, else the type of its nearest
 * configured parent (so a spoofed random subdomain of a parked domain is
 * parked too), else 'sending'.
 */
function domain_type(string $name): string
{
    foreach (domain_ancestors($name) as $candidate) {
        if (isset(configured_domains()[$candidate])) {
            return configured_domains()[$candidate];
        }
    }
    return 'sending';
}

/**
 * The main domain a name is grouped under (one dashboard card each): the
 * TOPMOST configured ancestor, or — for domains not in the config — the
 * last two labels (example.com). That fallback is right for .es/.eu/.com
 * style TLDs; list such domains in config.php for anything like .co.uk.
 */
function domain_group(string $name): string
{
    $top = null;
    foreach (domain_ancestors($name) as $candidate) {
        if (isset(configured_domains()[$candidate])) {
            $top = $candidate;
        }
    }
    if ($top !== null) {
        return $top;
    }
    $labels = explode('.', strtolower($name));
    return implode('.', array_slice($labels, -2));
}

/* ----------------------------------------------------------------------
 * Per-sender statistics + state + advice
 * ------------------------------------------------------------------- */

/** Severity order used to pick a card's color from its rows. */
function state_rank(string $state): int
{
    return ['neutral' => 0, 'ok' => 1, 'warn' => 2, 'bad' => 3][$state] ?? 0;
}

/**
 * Build the data behind the dashboard's domain cards.
 *
 * Rows = configured domains + every sender seen in the health or advisor
 * window. Returns [group => ['state' => ..., 'rows' => [sender => row]]],
 * groups and rows sorted by name (the group's own domain first).
 */
function domain_overview(): array
{
    $pdo  = Database::pdo();
    $cfg  = Database::config();
    $days = max(1, (int)($cfg['health']['days'] ?? 30));
    $weeks = max(1, (int)($cfg['advisor']['weeks'] ?? 4));

    // The sender of a record: its header_from, or the report's domain
    // when the reporter left header_from empty. Lowercased so case
    // differences between reporters do not split a domain in two.
    $senderSql = "LOWER(COALESCE(NULLIF(rec.header_from, ''), rep.domain))";
    $failSql   = "COALESCE(rec.eval_dkim, '') <> 'pass' AND COALESCE(rec.eval_spf, '') <> 'pass'";

    // ---- 1. Health window: volumes per sender (last N days).
    $stmt = $pdo->prepare("
        SELECT $senderSql AS sender,
               SUM(rec.msg_count) AS total,
               SUM(CASE WHEN rec.eval_dkim = 'pass' AND rec.eval_spf = 'pass' THEN rec.msg_count ELSE 0 END) AS aligned,
               SUM(CASE WHEN (COALESCE(rec.eval_dkim, '') = 'pass') XOR (COALESCE(rec.eval_spf, '') = 'pass') THEN rec.msg_count ELSE 0 END) AS partial,
               SUM(CASE WHEN $failSql THEN rec.msg_count ELSE 0 END) AS fails,
               -- failed mail the receiver still delivered (no quarantine/reject)
               SUM(CASE WHEN $failSql AND COALESCE(rec.disposition, 'none') NOT IN ('quarantine', 'reject')
                        THEN rec.msg_count ELSE 0 END) AS unblocked
        FROM records rec
        JOIN reports rep ON rep.id = rec.report_id
        WHERE rep.date_begin >= :since
        GROUP BY sender
    ");
    $stmt->execute([':since' => date('Y-m-d 00:00:00', strtotime("-$days days"))]);
    $health = [];
    foreach ($stmt->fetchAll() as $r) {
        $health[$r['sender']] = $r;
    }

    // ---- 2. Advisor window: messages and failures per sender per ISO week.
    $stmt = $pdo->prepare("
        SELECT $senderSql AS sender,
               YEARWEEK(rep.date_begin, 3) AS wk,
               SUM(rec.msg_count) AS total,
               SUM(CASE WHEN $failSql THEN rec.msg_count ELSE 0 END) AS fails
        FROM records rec
        JOIN reports rep ON rep.id = rec.report_id
        WHERE rep.date_begin >= :since
        GROUP BY sender, wk
    ");
    $stmt->execute([':since' => date('Y-m-d 00:00:00', strtotime('-' . ($weeks * 7) . ' days'))]);
    $weekly = [];
    foreach ($stmt->fetchAll() as $r) {
        $weekly[$r['sender']][$r['wk']] = ['total' => (int)$r['total'], 'fails' => (int)$r['fails']];
    }

    // ---- 3. Current policy per sender, from the newest report that
    // mentions it (any age). A subdomain without its own record is
    // covered by its parent's sp= (or p= when sp is not published).
    $latest = [];
    foreach ($pdo->query("
        SELECT $senderSql AS sender, rep.domain, rep.policy_p, rep.policy_sp, rep.policy_pct, rep.date_end
        FROM records rec
        JOIN reports rep ON rep.id = rec.report_id
        ORDER BY rep.date_end
    ") as $r) {
        $latest[$r['sender']] = $r; // later rows overwrite: newest wins
    }

    // ---- 4. Which senders get a row.
    $names = array_unique(array_merge(
        array_keys(configured_domains()), array_keys($health), array_keys($weekly)
    ));

    $groups = [];
    foreach ($names as $name) {
        $h   = $health[$name] ?? null;
        $pol = $latest[$name] ?? null;
        $ownRecord = $pol && strtolower($pol['domain']) === $name;

        // Current policy: live DNS first, newest report as fallback.
        $live = dmarc_lookup($name);
        if ($live['policy'] !== null) {
            $policy = ['policy' => $live['policy'], 'pct' => $live['pct'], 'domain' => $live['source'],
                       'tag' => $live['tag'], 'from' => 'DNS'];
        } elseif ($pol) {
            $policy = ['policy' => $ownRecord ? $pol['policy_p'] : ($pol['policy_sp'] ?? $pol['policy_p']),
                       'pct' => (int)($pol['policy_pct'] ?? 100), 'domain' => strtolower($pol['domain']),
                       'tag' => $ownRecord ? 'p' : 'sp', 'from' => 'newest report'];
        } else {
            $policy = ['policy' => null, 'pct' => 100, 'domain' => null, 'tag' => 'p', 'from' => null];
        }

        $row = [
            'name'    => $name,
            'type'    => domain_type($name),
            'total'   => (int)($h['total'] ?? 0),
            'aligned' => (int)($h['aligned'] ?? 0),
            'partial' => (int)($h['partial'] ?? 0),
            'fails'   => (int)($h['fails'] ?? 0),
            'unblocked' => (int)($h['unblocked'] ?? 0),
            // Effective policy and where it comes from.
            'policy'        => $policy['policy'],
            'pct'           => $policy['pct'],
            'policy_domain' => $policy['domain'],
            'policy_tag'    => $policy['tag'],
            'policy_from'   => $policy['from'],
            'last'          => $pol['date_end'] ?? null,
            'days'          => $days,
        ];
        [$row['state'], $row['value'], $row['detail']] = sender_state($row);
        $row['advice'] = policy_advice($row, $weekly[$name] ?? []);

        $groups[domain_group($name)]['rows'][$name] = $row;
    }

    // Sort groups by name; inside a group, the main domain first.
    ksort($groups);
    foreach ($groups as $g => &$group) {
        uksort($group['rows'], fn($a, $b) => [$a !== $g, $a] <=> [$b !== $g, $b]);
        $group['state'] = 'neutral';
        foreach ($group['rows'] as $row) {
            if (state_rank($row['state']) > state_rank($group['state'])) {
                $group['state'] = $row['state'];
            }
        }
    }
    unset($group);
    return $groups;
}

/**
 * Split the overview into what the dashboard shows and the "quiet"
 * parked domains it hides: parked, no mail at all in the health window
 * and p=reject in place — the normal state of a domain that never sends
 * mail, so a card for it would only be noise. Such a row comes back by
 * itself as soon as something needs attention (spoofed mail in reports,
 * mail passing DMARC, or a policy weaker than reject).
 * Set health.show_quiet_parked = true in config.php to always show them.
 *
 * Returns [overview without the quiet rows, list of hidden names]. A card
 * left without rows is dropped; card colors are recomputed.
 */
function hide_quiet_parked(array $overview): array
{
    if (Database::config()['health']['show_quiet_parked'] ?? false) {
        return [$overview, []];
    }

    $hidden = [];
    foreach ($overview as $g => $group) {
        foreach ($group['rows'] as $name => $row) {
            $quiet = $row['type'] === 'parked' && $row['total'] === 0 && $row['advice']['level'] === 'ok';
            if ($quiet) {
                $hidden[] = $name;
                unset($overview[$g]['rows'][$name]);
            }
        }
        if (!$overview[$g]['rows']) {
            unset($overview[$g]);
            continue;
        }
        $overview[$g]['state'] = 'neutral';
        foreach ($overview[$g]['rows'] as $row) {
            if (state_rank($row['state']) > state_rank($overview[$g]['state'])) {
                $overview[$g]['state'] = $row['state'];
            }
        }
    }
    sort($hidden);
    return [$overview, $hidden];
}

/**
 * Color + headline value + one-line detail of a sender over the health
 * window. Returns [state, value, detail].
 *
 * Sending domains: colored by DMARC pass rate (health thresholds).
 * Parked domains never send, so ANY mail claiming to be them is spoofing:
 *   - none at all, or all of it blocked by receivers  → ok
 *   - spoofed mail that was still delivered            → warn
 *   - mail that PASSED DMARC (someone is sending authenticated mail
 *     from a domain marked as not sending)             → bad
 */
function sender_state(array $r): array
{
    $msgs = plural($r['total'], 'message');
    if ($r['type'] === 'parked') {
        $passed = $r['total'] - $r['fails'];
        if ($r['total'] === 0) {
            return ['ok', 'No mail', "nothing sent or spoofed in {$r['days']} days"];
        }
        if ($passed > 0) {
            return ['bad', 'Sending!', number_format($passed) . " of $msgs passed DMARC — this domain is marked as not sending"];
        }
        if ($r['unblocked'] > 0) {
            return ['warn', 'Spoofed', number_format($r['unblocked']) . " of " . plural($r['total'], 'spoofed message') . " delivered anyway"];
        }
        return ['ok', 'Blocked', plural($r['total'], 'spoofed message') . ", all blocked by receivers"];
    }

    if ($r['total'] === 0) {
        return ['neutral', 'No data', "no reports in the last {$r['days']} days"];
    }
    $fails = $r['fails'] > 0 ? number_format($r['fails']) . ' failed' : 'no failures';
    return [health_state($r['total'], $r['fails']), pct($r['total'] - $r['fails'], $r['total']), "$msgs · $fails"];
}

/**
 * The next DMARC policy step for a sender — "if it stays like this for a
 * few weeks, tighten the policy".
 *
 * Sending domains move none → quarantine → reject once, over the last
 * advisor.weeks weeks, ALL of these hold:
 *   - pass rate >= advisor.pass_pct
 *   - reports in at least advisor.min_weeks different weeks
 *   - at least advisor.min_messages messages
 * Parked domains should be at p=reject right away (nothing legitimate can
 * break).
 *
 * $weeks: [yearweek => ['total' => n, 'fails' => n]] for this sender.
 * Returns ['level' => ok|ready|wait|fix|none, 'text' => ...].
 */
function policy_advice(array $r, array $weeks): array
{
    $cfg       = Database::config()['advisor'] ?? [];
    $nWeeks    = max(1, (int)($cfg['weeks'] ?? 4));
    $minWeeks  = min($nWeeks, max(1, (int)($cfg['min_weeks'] ?? 3)));
    $minMsgs   = max(1, (int)($cfg['min_messages'] ?? 10));
    $passPct   = (float)($cfg['pass_pct'] ?? 99);

    $atReject = $r['policy'] === 'reject' && $r['pct'] >= 100;

    if ($r['policy'] === null) {
        return ['level' => 'fix', 'text' => 'No DMARC policy found (DNS or reports) — see the DNS page.'];
    }
    if ($atReject) {
        return ['level' => 'ok', 'text' => 'p=reject in place — final policy.'];
    }

    // Where to make the change. A subdomain that inherits its parent's
    // sp= is best given its own record, so the parent stays untouched.
    $where = $r['policy_tag'] === 'p'
        ? "_dmarc.{$r['name']}"
        : "its own record _dmarc.{$r['name']} (it now inherits sp={$r['policy']} from {$r['policy_domain']})";

    if ($r['type'] === 'parked') {
        return ['level' => 'ready', 'text' => "Publish p=reject in $where: this domain sends no mail."];
    }

    $total = array_sum(array_column($weeks, 'total'));
    $fails = array_sum(array_column($weeks, 'fails'));
    if ($total === 0) {
        return ['level' => 'none', 'text' => "No reports in the last $nWeeks weeks — nothing to judge yet."];
    }
    $pass = ($total - $fails) / $total * 100;
    $passStr = number_format($pass, 1) . '%';
    if ($pass < $passPct) {
        return ['level' => 'fix', 'text' => "$passStr pass over $nWeeks weeks — fix the failing sources before tightening."];
    }

    // Next step on the none → quarantine → reject ladder.
    $next = match (true) {
        $r['policy'] === 'none'                     => 'p=quarantine',
        $r['policy'] === 'quarantine' && $r['pct'] < 100 => 'pct=100 (still p=quarantine)',
        default                                     => 'p=reject',
    };

    $weeksWithData = count(array_filter($weeks, fn($w) => $w['total'] > 0));
    if ($weeksWithData < $minWeeks || $total < $minMsgs) {
        return ['level' => 'wait', 'text' => "$passStr pass so far. If it stays like this, $next is next — "
            . "keep monitoring ($weeksWithData of $minWeeks weeks, $total of $minMsgs messages needed)."];
    }
    return ['level' => 'ready', 'text' => "$passStr pass in $weeksWithData of the last $nWeeks weeks ("
        . plural($total, 'message') . "): ready for $next in $where."];
}
