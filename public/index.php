<?php
/**
 * Dashboard: domain cards (one per main domain, one row per sending
 * domain, with the next policy step), policy advisor, summary cards,
 * daily timeline chart, reports list and top source IPs.
 *
 * Everything except the domain cards and the advisor is scoped to the
 * shared filters, both remembered in the session across pages:
 *   ?from=YYYY-MM-DD&to=YYYY-MM-DD   date range (default: last 90 days)
 *   ?domain=example.com               one domain (default: all of them)
 * The cards always cover a fixed recent window (health.days in
 * config.php, default 30) and the advice the last advisor.weeks weeks, so
 * they read as "how is each domain doing right now", whatever range is
 * being browsed. Their logic lives in src/domains.php.
 *
 * The filter matches reports whose window START (date_begin) falls in
 * the range. Classification per record:
 *   aligned  — DKIM pass AND SPF pass (fully aligned)
 *   partial  — exactly one of them passes (DMARC still passes)
 *   fail     — neither passes (DMARC fail → possible spoofing)
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/helpers.php';
require __DIR__ . '/../src/domains.php';
require __DIR__ . '/../src/dnscheck.php';

$pdo    = Database::pdo();
$range  = date_filter();
$domain = domain_filter();   // null = all domains
$params = [':from' => $range['from'] . ' 00:00:00', ':to' => $range['to'] . ' 23:59:59'];
// " AND rep.domain = :domain" (and the parameter) when a domain is
// selected, '' otherwise — appended to every date-range WHERE below.
$dSql   = domain_sql($domain, $params);

// ---------------------------------------------------------------------
// Domain cards: one per main domain, one row per sending domain, with
// state + next policy step (see src/domains.php). Fixed recent window,
// independent of the filters above.
// ---------------------------------------------------------------------
$healthDays = max(1, (int)(Database::config()['health']['days'] ?? 30));
$overview   = domain_overview();

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
// Policy advisor: the next policy step for ONE domain — the selected
// one, or the only one there is. Same logic (and window) as the card
// rows, so the two never disagree.
// ---------------------------------------------------------------------
$allRows = []; // every row of every card, keyed by domain name
foreach ($overview as $group) {
    $allRows += $group['rows'];
}
$advisorRow = null;
if ($domain !== null) {
    $advisorRow = $allRows[strtolower($domain)] ?? null;
} elseif (count($allRows) === 1) {
    $advisorRow = reset($allRows);
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
           -- the From: domains seen in this report (a parent's report can
           -- also carry mail of subdomains without their own record)
           GROUP_CONCAT(DISTINCT LOWER(rec.header_from) ORDER BY LOWER(rec.header_from) SEPARATOR ', ') AS header_froms,
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

<?php if ($overview): ?>
<!-- Domain cards over the last N days: one per main domain, one row per
     sending domain (subdomains under their parent). A row's name filters
     the dashboard to it (when it has reports of its own); clicking the
     selected one again goes back to all domains. -->
<div class="section-label">Domains · last <?= $healthDays ?> days</div>
<div class="domain-cards">
    <?php foreach ($overview as $g => $group): ?>
        <div class="domain-card <?= e($group['state']) ?>">
            <?php foreach ($group['rows'] as $name => $row):
                $isSel   = ($domain !== null && strtolower($domain) === $name);
                // Only names that are a report domain can be filtered on.
                $canLink = in_array($name, array_map('strtolower', known_domains()), true); ?>
                <div class="dc-row<?= $name === $g ? ' main' : '' ?><?= $isSel ? ' selected' : '' ?>">
                    <div class="dc-head">
                        <?php if ($canLink): ?>
                            <a class="dc-domain" href="index.php?domain=<?= $isSel ? '' : e(urlencode($name)) ?>"
                               title="<?= $isSel ? 'Show all domains' : 'Show only this domain' ?>"><?= e($name) ?></a>
                        <?php else: ?>
                            <span class="dc-domain"><?= e($name) ?></span>
                        <?php endif; ?>
                        <span>
                            <?php if ($row['type'] === 'parked'): ?><span class="badge neutral" title="Configured as a domain that sends no mail">parked</span><?php endif; ?>
                            <span class="badge neutral" title="<?= $row['policy'] === null ? 'No DMARC policy found' : e("{$row['policy_tag']}= of _dmarc.{$row['policy_domain']} (from {$row['policy_from']})") ?>">p=<?= e($row['policy'] ?? '?') ?></span>
                        </span>
                    </div>
                    <div class="dc-value <?= e($row['state']) ?>"><?= e($row['value']) ?></div>
                    <?php if ($row['total'] > 0 && $row['type'] === 'sending'): ?>
                        <?php // Proportional bar: aligned / partial / fail (same colors as the chart). ?>
                        <div class="mix" aria-hidden="true">
                            <span class="ok"   style="width:<?= round($row['aligned'] / $row['total'] * 100, 2) ?>%"></span>
                            <span class="warn" style="width:<?= round($row['partial'] / $row['total'] * 100, 2) ?>%"></span>
                            <span class="bad"  style="width:<?= round($row['fails'] / $row['total'] * 100, 2) ?>%"></span>
                        </div>
                    <?php endif; ?>
                    <div class="sub"><?= e($row['detail']) ?></div>
                    <div class="advice <?= e($row['advice']['level']) ?>"><?= e($row['advice']['text']) ?></div>
                    <div class="sub">Last report: <?= e(fmt_date($row['last'])) ?></div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<?php if ($advisorRow):
    // Panel color: the row's state, except that a "ready" step is good news.
    $advState = match ($advisorRow['advice']['level']) {
        'ready', 'ok' => 'ok',
        'fix'         => 'bad',
        'wait'        => 'warn',
        default       => 'neutral',
    }; ?>
    <div class="panel advisor <?= e($advState) ?>">
        <div class="headline">Policy advisor · <?= e($advisorRow['name']) ?> (p=<?= e($advisorRow['policy'] ?? '?') ?>)</div>
        <p><?= e($advisorRow['advice']['text']) ?></p>
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
        <th>Period</th><th>Reporter</th><th>Domain</th><th>Header From</th><th>Policy</th>
        <th class="num">Records</th><th class="num">Messages</th><th class="num">Fails</th><th></th>
    </tr>
    </thead>
    <tbody>
    <?php if (!$reports): ?>
        <tr><td colspan="9" class="muted">No reports in this date range — upload some first.</td></tr>
    <?php endif; ?>
    <?php foreach ($reports as $r): ?>
        <tr class="<?= $r['n_fails'] > 0 ? 'row-bad' : '' ?>">
            <td><?= e(fmt_date($r['date_begin'])) ?> → <?= e(fmt_date($r['date_end'])) ?></td>
            <td><?= e($r['org_name']) ?></td>
            <td class="mono"><?= e($r['domain']) ?></td>
            <td class="mono"><?= e($r['header_froms'] ?? '—') ?></td>
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
