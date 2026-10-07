<?php
/**
 * Source IPs, two modes:
 *   ips.php            — every IP aggregated across all reports in the
 *                        date range and selected domain (volume, pass
 *                        rates, first/last seen)
 *   ips.php?ip=1.2.3.4 — drill-down: every record for that one IP
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/helpers.php';

$pdo   = Database::pdo();
$range  = date_filter();
$domain = domain_filter();   // null = all domains
$ip    = trim($_GET['ip'] ?? '');

$title  = 'Source IPs';
$active = 'ips';

// =====================================================================
// Drill-down mode: one IP, all its records (no date filter — full history).
// =====================================================================
if ($ip !== '') {
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        http_response_code(400);
        exit('Invalid IP address.');
    }

    $stmt = $pdo->prepare("
        SELECT rec.*, rep.org_name, rep.date_begin, rep.date_end, rep.id AS rep_id
        FROM records rec
        JOIN reports rep ON rep.id = rec.report_id
        WHERE rec.source_ip = ?
        ORDER BY rep.date_begin DESC
    ");
    $stmt->execute([$ip]);
    $records = $stmt->fetchAll();

    $title = "IP $ip";
    require __DIR__ . '/../src/views/header.php';
    ?>
    <p><a href="ips.php">← All source IPs</a></p>
    <h1><span class="mono"><?= e($ip) ?></span>
        <?php if ($records && $records[0]['ptr_hostname']): ?>
            <span class="muted" style="font-size:17px">— <?= e($records[0]['ptr_hostname']) ?></span>
        <?php endif; ?>
    </h1>

    <div class="table-wrap">
    <table>
        <thead>
        <tr>
            <th>Report period</th><th>Reporter</th><th class="num">Msgs</th>
            <th>Disposition</th><th>SPF</th><th>DKIM</th>
            <th>Header From</th><th>DKIM selector</th>
        </tr>
        </thead>
        <tbody>
        <?php if (!$records): ?>
            <tr><td colspan="8" class="muted">This IP does not appear in any report.</td></tr>
        <?php endif; ?>
        <?php foreach ($records as $rec):
            $isFail = $rec['eval_dkim'] !== 'pass' && $rec['eval_spf'] !== 'pass'; ?>
            <tr class="<?= $isFail ? 'row-bad' : '' ?>">
                <td><a href="report.php?id=<?= (int)$rec['rep_id'] ?>"><?= e(fmt_date($rec['date_begin'])) ?> → <?= e(fmt_date($rec['date_end'])) ?></a></td>
                <td><?= e($rec['org_name']) ?></td>
                <td class="num"><?= number_format((int)$rec['msg_count']) ?></td>
                <td><span class="badge <?= disposition_class($rec['disposition']) ?>"><?= e($rec['disposition'] ?? '—') ?></span></td>
                <td><span class="badge <?= result_class($rec['eval_spf']) ?>"><?= e($rec['eval_spf'] ?? '—') ?></span></td>
                <td><span class="badge <?= result_class($rec['eval_dkim']) ?>"><?= e($rec['eval_dkim'] ?? '—') ?></span></td>
                <td class="mono"><?= e($rec['header_from'] ?? '—') ?></td>
                <td class="mono"><?= e($rec['dkim_selector'] ?? '—') ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </div>
    <?php
    require __DIR__ . '/../src/views/footer.php';
    exit;
}

// =====================================================================
// Aggregated mode: every IP in the date range (and selected domain).
// =====================================================================
$params = [':from' => $range['from'] . ' 00:00:00', ':to' => $range['to'] . ' 23:59:59'];
$dSql   = domain_sql($domain, $params);
$stmt = $pdo->prepare("
    SELECT rec.source_ip,
           MAX(rec.ptr_hostname)  AS ptr_hostname,
           COUNT(DISTINCT rep.id) AS n_reports,
           SUM(rec.msg_count)     AS n_msgs,
           MIN(rep.date_begin)    AS first_seen,
           MAX(rep.date_end)      AS last_seen,
           SUM(CASE WHEN rec.eval_spf  = 'pass' THEN rec.msg_count ELSE 0 END) AS spf_pass,
           SUM(CASE WHEN rec.eval_dkim = 'pass' THEN rec.msg_count ELSE 0 END) AS dkim_pass,
           SUM(CASE WHEN COALESCE(rec.eval_dkim, '') <> 'pass' AND COALESCE(rec.eval_spf, '') <> 'pass' THEN rec.msg_count ELSE 0 END) AS n_fails
    FROM records rec
    JOIN reports rep ON rep.id = rec.report_id
    WHERE rep.date_begin BETWEEN :from AND :to$dSql
    GROUP BY rec.source_ip
    ORDER BY n_fails DESC, n_msgs DESC
");
$stmt->execute($params);
$ips = $stmt->fetchAll();

require __DIR__ . '/../src/views/header.php';
?>

<div class="page-head">
    <h1>Source IPs<?php if ($domain): ?> <span class="muted mono" style="font-size:17px">· <?= e($domain) ?></span><?php endif; ?></h1>
    <?php require __DIR__ . '/../src/views/date_filter.php'; ?>
</div>

<p class="muted">
    Every IP that sent mail claiming to be your domain, aggregated across
    all reports in the range. Rows in red contain DMARC failures —
    legitimate-but-misconfigured senders or spoofing attempts. Click an IP
    for its full history.
</p>

<div class="table-wrap">
<table>
    <thead>
    <tr>
        <th>Source IP</th><th>Hostname (rDNS)</th>
        <th class="num">Messages</th><th class="num">Reports</th>
        <th class="num">SPF pass</th><th class="num">DKIM pass</th><th class="num">DMARC fail</th>
        <th>First seen</th><th>Last seen</th>
    </tr>
    </thead>
    <tbody>
    <?php if (!$ips): ?>
        <tr><td colspan="9" class="muted">No data in this date range.</td></tr>
    <?php endif; ?>
    <?php foreach ($ips as $row): ?>
        <tr class="<?= $row['n_fails'] > 0 ? 'row-bad' : '' ?>">
            <td class="mono"><a href="ips.php?ip=<?= e(urlencode($row['source_ip'])) ?>"><?= e($row['source_ip']) ?></a></td>
            <td class="mono"><?= e($row['ptr_hostname'] ?? '') ?: '<span class="muted">no PTR</span>' ?></td>
            <td class="num"><?= number_format((int)$row['n_msgs']) ?></td>
            <td class="num"><?= (int)$row['n_reports'] ?></td>
            <td class="num"><?= pct((int)$row['spf_pass'], (int)$row['n_msgs']) ?></td>
            <td class="num"><?= pct((int)$row['dkim_pass'], (int)$row['n_msgs']) ?></td>
            <td class="num"><?= $row['n_fails'] > 0 ? '<span class="badge bad">' . number_format((int)$row['n_fails']) . '</span>' : '0' ?></td>
            <td><?= e(fmt_date($row['first_seen'])) ?></td>
            <td><?= e(fmt_date($row['last_seen'])) ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
</div>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
