<?php
/**
 * Dashboard: per-domain health cards, summary cards, policy advisor,
 * daily timeline chart, reports list and top source IPs.
 *
 * Everything except the health cards is scoped to the shared filters,
 * both remembered in the session across pages:
 *   ?from=YYYY-MM-DD&to=YYYY-MM-DD   date range (default: last 90 days)
 *   ?domain=example.com               one domain (default: all of them)
 * The health cards always cover a fixed recent window (health.days in
 * config.php, default 30) so they read as "how is each domain doing
 * right now", whatever range is being browsed.
 *
 * The filter matches reports whose window START (date_begin) falls in
 * the range. Classification per record:
 *   aligned  — DKIM pass AND SPF pass (fully aligned)
 *   partial  — exactly one of them passes (DMARC still passes)
 *   fail     — neither passes (DMARC fail → possible spoofing)
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/helpers.php';

$pdo    = Database::pdo();
$range  = date_filter();
$domain = domain_filter();   // null = all domains
$params = [':from' => $range['from'] . ' 00:00:00', ':to' => $range['to'] . ' 23:59:59'];
// " AND rep.domain = :domain" (and the parameter) when a domain is
// selected, '' otherwise — appended to every date-range WHERE below.
$dSql   = domain_sql($domain, $params);

// ---------------------------------------------------------------------
// Per-domain health cards: DMARC results of each domain over the last
// N days (fixed window, independent of the filters above).
// ---------------------------------------------------------------------
$healthDays = max(1, (int)(Database::config()['health']['days'] ?? 30));
$stmt = $pdo->prepare("
    SELECT
        rep.domain,
        COALESCE(SUM(rec.msg_count), 0) AS total,
        COALESCE(SUM(CASE WHEN rec.eval_dkim = 'pass' AND rec.eval_spf = 'pass' THEN rec.msg_count ELSE 0 END), 0) AS aligned,
        COALESCE(SUM(CASE WHEN (COALESCE(rec.eval_dkim, '') = 'pass') XOR (COALESCE(rec.eval_spf, '') = 'pass') THEN rec.msg_count ELSE 0 END), 0) AS partial,
        COALESCE(SUM(CASE WHEN COALESCE(rec.eval_dkim, '') <> 'pass' AND COALESCE(rec.eval_spf, '') <> 'pass' THEN rec.msg_count ELSE 0 END), 0) AS fails
    FROM reports rep
    LEFT JOIN records rec ON rec.report_id = rep.id
    WHERE rep.date_begin >= :since
    GROUP BY rep.domain
");
$stmt->execute([':since' => date('Y-m-d 00:00:00', strtotime("-$healthDays days"))]);
$recent = [];
foreach ($stmt->fetchAll() as $row) {
    $recent[$row['domain']] = $row;
}

// Policy currently published by each domain (from its newest report,
// whatever its age) and when that newest report was.
$latest = [];
foreach ($pdo->query("
    SELECT rep.domain, rep.policy_p, rep.date_end
    FROM reports rep
    JOIN (SELECT domain, MAX(date_end) AS last_end FROM reports GROUP BY domain) newest
      ON newest.domain = rep.domain AND newest.last_end = rep.date_end
") as $row) {
    $latest[$row['domain']] = $row;
}

// One card per known domain, including domains with no recent reports
// (shown grey, so a mailbox that stopped delivering reports stands out).
$healthCards = [];
foreach (known_domains() as $d) {
    $r = $recent[$d] ?? ['total' => 0, 'aligned' => 0, 'partial' => 0, 'fails' => 0];
    $healthCards[$d] = [
        'total'   => (int)$r['total'],
        'aligned' => (int)$r['aligned'],
        'partial' => (int)$r['partial'],
        'fails'   => (int)$r['fails'],
        'state'   => health_state((int)$r['total'], (int)$r['fails']),
        'policy'  => $latest[$d]['policy_p'] ?? null,
        'last'    => $latest[$d]['date_end'] ?? null,
    ];
}

// ---------------------------------------------------------------------
// Summary totals over the selected range.
// ---------------------------------------------------------------------
$stmt = $pdo->prepare("
    SELECT
        COALESCE(SUM(rec.msg_count), 0) AS total,
        COALESCE(SUM(CASE WHEN rec.eval_spf  = 'pass' THEN rec.msg_count ELSE 0 END), 0) AS spf_pass,
        COALESCE(SUM(CASE WHEN rec.eval_dkim = 'pass' THEN rec.msg_count ELSE 0 END), 0) AS dkim_pass,
        COALESCE(SUM(CASE WHEN rec.eval_dkim = 'pass' AND rec.eval_spf = 'pass' THEN rec.msg_count ELSE 0 END), 0) AS aligned,
        COALESCE(SUM(CASE WHEN COALESCE(rec.eval_dkim, '') <> 'pass' AND COALESCE(rec.eval_spf, '') <> 'pass' THEN rec.msg_count ELSE 0 END), 0) AS fails
    FROM records rec
    JOIN reports rep ON rep.id = rec.report_id
    WHERE rep.date_begin BETWEEN :from AND :to$dSql
");
$stmt->execute($params);
$sum = $stmt->fetch();

// ---------------------------------------------------------------------
// Policy advisor: alignment health over the selected range + the
// currently published policy from the newest report (the policy is
// whatever is live NOW, so that part ignores the date range on purpose).
// A policy belongs to ONE domain, so the advisor only runs when a
// single domain is in scope: the selected one, or the only one there is.
// ---------------------------------------------------------------------
$advisorDomain = $domain ?? (count(known_domains()) === 1 ? known_domains()[0] : null);
$stmt = $pdo->prepare("
    SELECT
        COALESCE(SUM(rec.msg_count), 0) AS total,
        COALESCE(SUM(CASE WHEN COALESCE(rec.eval_dkim, '') <> 'pass' AND COALESCE(rec.eval_spf, '') <> 'pass' THEN rec.msg_count ELSE 0 END), 0) AS fails
    FROM records rec
    JOIN reports rep ON rep.id = rec.report_id
    WHERE rep.date_begin BETWEEN :from AND :to$dSql
");
$stmt->execute($params);
$adv = $stmt->fetch();

$currentPolicy = $advisorDomain !== null ? ($latest[$advisorDomain]['policy_p'] ?? null) : null;

$advisor = null; // ['state' => ok|warn|bad|neutral, 'headline' => ..., 'body' => ...]
if ($advisorDomain !== null && $adv['total'] > 0) {
    $passPct = ($adv['total'] - $adv['fails']) / $adv['total'] * 100;
    $passStr = number_format($passPct, 1) . '%';
    $period = 'between ' . fmt_date($range['from']) . ' and ' . fmt_date($range['to']);
    if ($adv['fails'] > 0 && $passPct < 90) {
        $advisor = ['state' => 'bad',
            'headline' => "Only $passStr of mail passed DMARC $period.",
            'body' => "Investigate the failing IPs below before tightening the policy — either a legitimate sender is misconfigured or someone is spoofing the domain."];
    } elseif ($currentPolicy === 'none' && $passPct >= 99 && $adv['total'] >= 100) {
        $advisor = ['state' => 'ok',
            'headline' => "$passStr of mail passed DMARC $period — you can move from p=none to p=quarantine.",
            'body' => "Alignment is consistently healthy. Consider publishing p=quarantine (optionally with pct=25 to start), then aim for p=reject once quarantine shows no problems."];
    } elseif ($currentPolicy === 'quarantine' && $passPct >= 99.5) {
        $advisor = ['state' => 'ok',
            'headline' => "$passStr DMARC pass under p=quarantine $period — p=reject looks safe.",
            'body' => "Quarantine has not affected legitimate mail. Publishing p=reject completes the rollout."];
    } else {
        $advisor = ['state' => 'warn',
            'headline' => "$passStr of mail passed DMARC $period.",
            'body' => "Keep monitoring; tighten the policy once the pass rate stays above 99% (current policy: p=" . ($currentPolicy ?? '?') . ")."];
    }
}

// ---------------------------------------------------------------------
// Daily timeline: stacked aligned / partial / fail volumes per day.
// ---------------------------------------------------------------------
$stmt = $pdo->prepare("
    SELECT
        DATE(rep.date_begin) AS day,
        SUM(CASE WHEN rec.eval_dkim = 'pass' AND rec.eval_spf = 'pass' THEN rec.msg_count ELSE 0 END) AS aligned,
        SUM(CASE WHEN (COALESCE(rec.eval_dkim, '') = 'pass') XOR (COALESCE(rec.eval_spf, '') = 'pass') THEN rec.msg_count ELSE 0 END) AS partial,
        SUM(CASE WHEN COALESCE(rec.eval_dkim, '') <> 'pass' AND COALESCE(rec.eval_spf, '') <> 'pass' THEN rec.msg_count ELSE 0 END) AS fails
    FROM records rec
    JOIN reports rep ON rep.id = rec.report_id
    WHERE rep.date_begin BETWEEN :from AND :to$dSql
    GROUP BY day
    ORDER BY day
");
$stmt->execute($params);
$days = $stmt->fetchAll();

// ---------------------------------------------------------------------
// Chart interactivity — no JavaScript: every click is a plain link that
// reloads the page with extra query parameters (URLs stay shareable).
//   ?hide=aligned,partial   series toggled off via the legend
//   ?cat=fail&day=YYYY-MM-DD  bar segment clicked → day-records panel
// ---------------------------------------------------------------------
$allSeries = [
    // url key => [SQL column alias, bar CSS class, legend label]
    'aligned' => ['aligned', 'bar-ok',   'Fully aligned'],
    'partial' => ['partial', 'bar-warn', 'Partial (one of SPF/DKIM)'],
    'fail'    => ['fails',   'bar-bad',  'DMARC fail'],
];

$hidden = array_values(array_intersect(
    explode(',', $_GET['hide'] ?? ''), array_keys($allSeries)
));
if (count($hidden) === count($allSeries)) {
    $hidden = []; // hiding every series would leave an empty chart
}
$visible = array_diff_key($allSeries, array_flip($hidden));

$cat    = in_array($_GET['cat'] ?? '', array_keys($allSeries), true) ? $_GET['cat'] : null;
$selDay = preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['day'] ?? '') ? $_GET['day'] : null;

/**
 * Build a dashboard URL that keeps the current state (date range, hidden
 * series, selected segment) except for the given overrides. Pass null as
 * an override value to drop that parameter.
 */
function dash_url(array $overrides = []): string
{
    global $range, $domain, $hidden, $cat, $selDay;
    $q = array_merge([
        'domain' => $domain,
        'from'   => $range['from'],
        'to'     => $range['to'],
        'hide' => implode(',', $hidden),
        'cat'  => $cat,
        'day'  => $selDay,
    ], $overrides);
    $q = array_filter($q, fn($v) => $v !== null && $v !== '');
    return 'index.php?' . http_build_query($q);
}

// Records behind the clicked bar segment (one day, one result category).
$dayRecords = [];
if ($cat && $selDay) {
    // $catCond comes from this fixed match, never from user input.
    $catCond = match ($cat) {
        'aligned' => "rec.eval_dkim = 'pass' AND rec.eval_spf = 'pass'",
        'partial' => "(COALESCE(rec.eval_dkim, '') = 'pass') XOR (COALESCE(rec.eval_spf, '') = 'pass')",
        'fail'    => "COALESCE(rec.eval_dkim, '') <> 'pass' AND COALESCE(rec.eval_spf, '') <> 'pass'",
    };
    $dayParams = [':day' => $selDay];
    $dayDSql   = domain_sql($domain, $dayParams);
    $stmt = $pdo->prepare("
        SELECT rec.*, rep.org_name, rep.id AS rep_id
        FROM records rec
        JOIN reports rep ON rep.id = rec.report_id
        WHERE DATE(rep.date_begin) = :day AND $catCond$dayDSql
        ORDER BY rec.msg_count DESC, rec.source_ip
    ");
    $stmt->execute($dayParams);
    $dayRecords = $stmt->fetchAll();
}

// ---------------------------------------------------------------------
// Reports in range (newest first).
// ---------------------------------------------------------------------
$stmt = $pdo->prepare("
    SELECT rep.*,
           COUNT(rec.id)                AS n_records,
           COALESCE(SUM(rec.msg_count), 0) AS n_msgs,
           COALESCE(SUM(CASE WHEN COALESCE(rec.eval_dkim, '') <> 'pass' AND COALESCE(rec.eval_spf, '') <> 'pass' THEN rec.msg_count ELSE 0 END), 0) AS n_fails
    FROM reports rep
    LEFT JOIN records rec ON rec.report_id = rep.id
    WHERE rep.date_begin BETWEEN :from AND :to$dSql
    GROUP BY rep.id
    ORDER BY rep.date_begin DESC
");
$stmt->execute($params);
$reports = $stmt->fetchAll();

// ---------------------------------------------------------------------
// Top source IPs in range (by volume, worst first among equals).
// ---------------------------------------------------------------------
$stmt = $pdo->prepare("
    SELECT rec.source_ip,
           MAX(rec.ptr_hostname) AS ptr_hostname,
           SUM(rec.msg_count)    AS n_msgs,
           SUM(CASE WHEN rec.eval_spf  = 'pass' THEN rec.msg_count ELSE 0 END) AS spf_pass,
           SUM(CASE WHEN rec.eval_dkim = 'pass' THEN rec.msg_count ELSE 0 END) AS dkim_pass,
           SUM(CASE WHEN COALESCE(rec.eval_dkim, '') <> 'pass' AND COALESCE(rec.eval_spf, '') <> 'pass' THEN rec.msg_count ELSE 0 END) AS n_fails
    FROM records rec
    JOIN reports rep ON rep.id = rec.report_id
    WHERE rep.date_begin BETWEEN :from AND :to$dSql
    GROUP BY rec.source_ip
    ORDER BY n_fails DESC, n_msgs DESC
    LIMIT 15
");
$stmt->execute($params);
$topIps = $stmt->fetchAll();

$title  = 'Dashboard';
$active = 'dashboard';
require __DIR__ . '/../src/views/header.php';
?>

<div class="page-head">
    <h1>Dashboard<?php if ($domain): ?> <span class="muted mono" style="font-size:17px">· <?= e($domain) ?></span><?php endif; ?></h1>
    <!-- Shared filter form (domain, date inputs, quick presets). -->
    <?php require __DIR__ . '/../src/views/date_filter.php'; ?>
</div>

<?php if ($healthCards): ?>
<!-- Per-domain health over the last N days. Each card is a link that
     filters the whole dashboard to its domain; clicking the selected
     card again goes back to all domains. -->
<div class="section-label">Domains · last <?= $healthDays ?> days</div>
<div class="domain-cards">
    <?php foreach ($healthCards as $d => $h):
        $isSel = ($domain === $d); ?>
        <a class="domain-card <?= e($h['state']) ?><?= $isSel ? ' selected' : '' ?>"
           href="index.php?domain=<?= $isSel ? '' : e(urlencode($d)) ?>"
           title="<?= $isSel ? 'Show all domains' : 'Show only this domain' ?>">
            <div class="dc-head">
                <span class="dc-domain"><?= e($d) ?></span>
                <span class="badge neutral">p=<?= e($h['policy'] ?? '?') ?></span>
            </div>
            <?php if ($h['total'] > 0): ?>
                <div class="value <?= e($h['state']) ?>"><?= pct($h['total'] - $h['fails'], $h['total']) ?></div>
                <div class="sub">DMARC pass</div>
                <?php // Proportional bar: aligned / partial / fail (same colors as the chart). ?>
                <div class="mix" aria-hidden="true">
                    <span class="ok"   style="width:<?= round($h['aligned'] / $h['total'] * 100, 2) ?>%"></span>
                    <span class="warn" style="width:<?= round($h['partial'] / $h['total'] * 100, 2) ?>%"></span>
                    <span class="bad"  style="width:<?= round($h['fails'] / $h['total'] * 100, 2) ?>%"></span>
                </div>
                <div class="sub">
                    <?= number_format($h['total']) ?> messages ·
                    <?= $h['fails'] > 0 ? '<strong class="bad">' . number_format($h['fails']) . ' failed</strong>' : 'no failures' ?>
                </div>
            <?php else: ?>
                <div class="value neutral">No data</div>
                <div class="sub">no reports in the last <?= $healthDays ?> days</div>
            <?php endif; ?>
            <div class="sub">Last report: <?= e(fmt_date($h['last'])) ?></div>
        </a>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<?php if ($advisor): ?>
    <div class="panel advisor <?= e($advisor['state']) ?>">
        <div class="headline"><?= e($advisor['headline']) ?></div>
        <p><?= e($advisor['body']) ?></p>
    </div>
<?php endif; ?>

<div class="cards">
    <div class="card">
        <div class="label">Total messages</div>
        <div class="value"><?= number_format((int)$sum['total']) ?></div>
        <div class="sub"><?= e($range['from']) ?> → <?= e($range['to']) ?></div>
    </div>
    <div class="card">
        <div class="label">SPF pass</div>
        <div class="value ok"><?= pct((int)$sum['spf_pass'], (int)$sum['total']) ?></div>
        <div class="sub"><?= number_format((int)$sum['spf_pass']) ?> messages</div>
    </div>
    <div class="card">
        <div class="label">DKIM pass</div>
        <div class="value ok"><?= pct((int)$sum['dkim_pass'], (int)$sum['total']) ?></div>
        <div class="sub"><?= number_format((int)$sum['dkim_pass']) ?> messages</div>
    </div>
    <div class="card">
        <div class="label">Fully aligned</div>
        <div class="value ok"><?= pct((int)$sum['aligned'], (int)$sum['total']) ?></div>
        <div class="sub">SPF and DKIM both pass</div>
    </div>
    <div class="card">
        <div class="label">DMARC fail</div>
        <div class="value <?= $sum['fails'] > 0 ? 'bad' : 'ok' ?>"><?= number_format((int)$sum['fails']) ?></div>
        <div class="sub">possible spoofing</div>
    </div>
</div>

<?php if ($days): ?>
<div class="panel chart">
    <h2>Daily volume</h2>
    <?php
    // ---- Inline SVG stacked-bar chart, generated in PHP (no JS libs). ---
    // Every bar segment is a link (?cat=&day=) opening the records panel
    // below; the legend links toggle series on/off (?hide=).
    $W = 1000; $H = 220;                 // viewBox size
    $padL = 46; $padR = 8; $padT = 10; $padB = 28;
    $plotW = $W - $padL - $padR;
    $plotH = $H - $padT - $padB;

    // Scale to the tallest stack of the VISIBLE series only, so hiding
    // a dominant series re-zooms the chart onto what is left.
    $maxTotal = max(array_map(
        fn($d) => array_sum(array_map(fn($s) => (int)$d[$s[0]], $visible)),
        $days
    ));
    $maxTotal = max($maxTotal, 1);
    $n        = count($days);
    $slot     = $plotW / $n;             // horizontal space per day
    $barW     = max(2, min(30, $slot * 0.7));
    $labelEvery = max(1, (int)ceil($n / 12)); // ~12 x-axis labels max
    ?>
    <svg viewBox="0 0 <?= $W ?> <?= $H ?>" role="img" aria-label="Daily message volume, stacked by DMARC result">
        <?php // Y-axis gridlines + labels (0, half, max).
        foreach ([0, 0.5, 1] as $f):
            $y = $padT + $plotH - $f * $plotH; ?>
            <line class="axis" x1="<?= $padL ?>" y1="<?= $y ?>" x2="<?= $W - $padR ?>" y2="<?= $y ?>"/>
            <text x="<?= $padL - 6 ?>" y="<?= $y + 4 ?>" text-anchor="end"><?= number_format($maxTotal * $f) ?></text>
        <?php endforeach; ?>

        <?php foreach ($days as $i => $d):
            $x = $padL + $i * $slot + ($slot - $barW) / 2;
            $y = $padT + $plotH; // stack upwards from the baseline
            // Draw segments in fixed order: aligned (green), partial
            // (amber), fail (red) — each shrinks the remaining baseline.
            foreach ($visible as $key => [$col, $class]):
                $h = $d[$col] / $maxTotal * $plotH;
                if ($h <= 0) continue;
                $y -= $h;
                // Highlight the segment whose records panel is open.
                $isSel = ($cat === $key && $selDay === $d['day']); ?>
                <a href="<?= e(dash_url(['cat' => $key, 'day' => $d['day']])) ?>">
                    <rect class="<?= $class ?><?= $isSel ? ' selected' : '' ?>" x="<?= round($x, 1) ?>" y="<?= round($y, 1) ?>"
                          width="<?= round($barW, 1) ?>" height="<?= round($h, 1) ?>">
                        <title><?= e($d['day']) ?> — <?= number_format((int)$d[$col]) ?> <?= e($key) ?> (click for records)</title>
                    </rect>
                </a>
            <?php endforeach;
            if ($i % $labelEvery === 0): ?>
                <text x="<?= round($x + $barW / 2, 1) ?>" y="<?= $H - 8 ?>" text-anchor="middle"><?= e(date('d M', strtotime($d['day']))) ?></text>
            <?php endif;
        endforeach; ?>
    </svg>
    <div class="legend">
        <?php foreach ($allSeries as $key => [$col, $class, $label]):
            $isHidden  = in_array($key, $hidden, true);
            // Clicking a legend entry adds/removes its series from ?hide=.
            $newHidden = $isHidden
                ? array_values(array_diff($hidden, [$key]))
                : array_merge($hidden, [$key]); ?>
            <a class="<?= $isHidden ? 'off' : '' ?>"
               href="<?= e(dash_url(['hide' => implode(',', $newHidden)])) ?>"
               title="Show/hide this series"><span class="dot <?= e(substr($class, 4)) ?>"></span><?= e($label) ?></a>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<?php if ($cat && $selDay): ?>
<h2 id="day-records"><?= e($allSeries[$cat][2]) ?> records on <?= e(fmt_date($selDay)) ?> (<?= count($dayRecords) ?>)
    <a class="muted" style="font-weight:400;font-size:14px" href="<?= e(dash_url(['cat' => null, 'day' => null])) ?>">— clear ×</a>
</h2>
<div class="table-wrap">
<table>
    <thead>
    <tr>
        <th>Source IP</th><th>Hostname (rDNS)</th><th class="num">Msgs</th>
        <th>Disposition</th><th>SPF</th><th>DKIM</th>
        <th>Header From</th><th>Report</th>
    </tr>
    </thead>
    <tbody>
    <?php if (!$dayRecords): ?>
        <tr><td colspan="8" class="muted">No records match this day and result.</td></tr>
    <?php endif; ?>
    <?php foreach ($dayRecords as $rec):
        $isFail = $rec['eval_dkim'] !== 'pass' && $rec['eval_spf'] !== 'pass'; ?>
        <tr class="<?= $isFail ? 'row-bad' : '' ?>">
            <td class="mono"><a href="ips.php?ip=<?= e(urlencode($rec['source_ip'])) ?>"><?= e($rec['source_ip']) ?></a></td>
            <td class="mono"><?= e($rec['ptr_hostname'] ?? '') ?: '<span class="muted">no PTR</span>' ?></td>
            <td class="num"><?= number_format((int)$rec['msg_count']) ?></td>
            <td><span class="badge <?= disposition_class($rec['disposition']) ?>"><?= e($rec['disposition'] ?? '—') ?></span></td>
            <td><span class="badge <?= result_class($rec['eval_spf']) ?>"><?= e($rec['eval_spf'] ?? '—') ?></span></td>
            <td><span class="badge <?= result_class($rec['eval_dkim']) ?>"><?= e($rec['eval_dkim'] ?? '—') ?></span></td>
            <td class="mono"><?= e($rec['header_from'] ?? '—') ?></td>
            <td><a href="report.php?id=<?= (int)$rec['rep_id'] ?>"><?= e($rec['org_name']) ?> →</a></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
</div>
<?php endif; ?>

<h2>Reports (<?= count($reports) ?>)</h2>
<div class="table-wrap">
<table>
    <thead>
    <tr>
        <th>Period</th><th>Reporter</th><th>Domain</th><th>Policy</th>
        <th class="num">Records</th><th class="num">Messages</th><th class="num">Fails</th><th></th>
    </tr>
    </thead>
    <tbody>
    <?php if (!$reports): ?>
        <tr><td colspan="8" class="muted">No reports in this date range — upload some first.</td></tr>
    <?php endif; ?>
    <?php foreach ($reports as $r): ?>
        <tr class="<?= $r['n_fails'] > 0 ? 'row-bad' : '' ?>">
            <td><?= e(fmt_date($r['date_begin'])) ?> → <?= e(fmt_date($r['date_end'])) ?></td>
            <td><?= e($r['org_name']) ?></td>
            <td class="mono"><?= e($r['domain']) ?></td>
            <td><span class="badge neutral">p=<?= e($r['policy_p'] ?? '?') ?></span></td>
            <td class="num"><?= (int)$r['n_records'] ?></td>
            <td class="num"><?= number_format((int)$r['n_msgs']) ?></td>
            <td class="num"><?= $r['n_fails'] > 0 ? '<span class="badge bad">' . number_format((int)$r['n_fails']) . '</span>' : '0' ?></td>
            <td><a href="report.php?id=<?= (int)$r['id'] ?>">detail →</a></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
</div>

<h2>Top source IPs <a class="muted" style="font-weight:400;font-size:14px" href="ips.php?from=<?= e($range['from']) ?>&amp;to=<?= e($range['to']) ?>">— see all</a></h2>
<div class="table-wrap">
<table>
    <thead>
    <tr>
        <th>Source IP</th><th>Hostname (rDNS)</th><th class="num">Messages</th>
        <th class="num">SPF pass</th><th class="num">DKIM pass</th><th class="num">DMARC fail</th>
    </tr>
    </thead>
    <tbody>
    <?php if (!$topIps): ?>
        <tr><td colspan="6" class="muted">No data yet.</td></tr>
    <?php endif; ?>
    <?php foreach ($topIps as $ip): ?>
        <tr class="<?= $ip['n_fails'] > 0 ? 'row-bad' : '' ?>">
            <td class="mono"><a href="ips.php?ip=<?= e(urlencode($ip['source_ip'])) ?>"><?= e($ip['source_ip']) ?></a></td>
            <td class="mono"><?= e($ip['ptr_hostname'] ?? '') ?: '<span class="muted">no PTR</span>' ?></td>
            <td class="num"><?= number_format((int)$ip['n_msgs']) ?></td>
            <td class="num"><?= pct((int)$ip['spf_pass'], (int)$ip['n_msgs']) ?></td>
            <td class="num"><?= pct((int)$ip['dkim_pass'], (int)$ip['n_msgs']) ?></td>
            <td class="num"><?= $ip['n_fails'] > 0 ? '<span class="badge bad">' . number_format((int)$ip['n_fails']) . '</span>' : '0' ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
</div>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
