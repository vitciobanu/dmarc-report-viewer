<?php
/**
 * DNS status: live SPF / DMARC / MX / DKIM records of every monitored
 * domain, with plain-language findings (see src/dnscheck.php).
 *
 * Domains checked:
 *   - every domain in the domains map of config.php,
 *   - every domain that appears as a report's policy domain,
 *   - every From: domain whose mail PASSED DMARC in the last 90 days
 *     (real senders — spoofed random subdomains are left out).
 * DKIM selectors to check are the ones seen in the reports.
 *
 * Lookups use this server's DNS resolver, so right after a change a
 * value can be up to one TTL old (the same delay mail receivers have).
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/helpers.php';
require __DIR__ . '/../src/domains.php';
require __DIR__ . '/../src/dnscheck.php';

$pdo = Database::pdo();

// ---- Which domains to check.
$names = array_keys(configured_domains());
foreach (known_domains() as $d) {
    $names[] = strtolower($d);
}
$stmt = $pdo->prepare("
    SELECT DISTINCT LOWER(rec.header_from)
    FROM records rec
    JOIN reports rep ON rep.id = rec.report_id
    WHERE rep.date_begin >= :since
      AND rec.header_from IS NOT NULL
      AND (rec.eval_dkim = 'pass' OR rec.eval_spf = 'pass')
");
$stmt->execute([':since' => date('Y-m-d', strtotime('-90 days'))]);
foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $d) {
    $names[] = $d;
}
$names = array_values(array_unique(array_filter($names)));

// ---- DKIM selectors seen in the reports, per signing domain.
$selectors = [];
foreach ($pdo->query("
    SELECT DISTINCT LOWER(dkim_domain) AS d, dkim_selector AS sel
    FROM records
    WHERE dkim_domain IS NOT NULL AND dkim_selector IS NOT NULL AND dkim_selector <> ''
") as $r) {
    $selectors[$r['d']][] = $r['sel'];
}

// ---- Run the checks, grouped by main domain (same grouping as the dashboard).
$groups = [];
foreach ($names as $name) {
    $groups[domain_group($name)][$name] = dns_check($name, $selectors[$name] ?? []);
}
ksort($groups);
foreach ($groups as $g => &$rows) {
    uksort($rows, fn($a, $b) => [$a !== $g, $a] <=> [$b !== $g, $b]);
}
unset($rows);

$title  = 'DNS';
$active = 'dns';
require __DIR__ . '/../src/views/header.php';
?>

<h1>DNS status</h1>
<p class="muted">
    Live SPF, DMARC, MX and DKIM records of your domains, checked through
    this server's DNS resolver — right after a change, a value can be up
    to one TTL old. Domain types (sending / parked) come from the
    <span class="mono">domains</span> map in config.php.
</p>

<?php if (!$groups): ?>
    <p class="muted">No domains yet: list them in config.php or import some reports.</p>
<?php endif; ?>

<?php foreach ($groups as $g => $rows): ?>
<h2 class="mono"><?= e($g) ?></h2>
<div class="table-wrap">
<table class="dns-table">
    <thead>
    <tr>
        <th>Domain</th><th>DMARC (applies)</th><th>SPF</th><th>MX</th><th>DKIM</th><th>Findings</th>
    </tr>
    </thead>
    <tbody>
    <?php foreach ($rows as $name => $c): ?>
        <tr class="<?= $c['state'] === 'bad' ? 'row-bad' : '' ?>">
            <td>
                <span class="mono"><?= e($name) ?></span><br>
                <span class="badge neutral"><?= e($c['type']) ?></span>
            </td>
            <td class="mono wrap">
                <?php if ($c['dmarc']['record'] !== null): ?>
                    <span class="badge <?= $c['dmarc']['policy'] === 'reject' ? 'ok' : ($c['dmarc']['policy'] === 'quarantine' ? 'warn' : 'neutral') ?>"><?= e($c['dmarc']['tag'] . '=' . ($c['dmarc']['policy'] ?? '?')) ?></span>
                    <?php if ($c['dmarc']['tag'] === 'sp'): ?><span class="muted">from <?= e($c['dmarc']['source']) ?></span><?php endif; ?>
                    <div class="muted small"><?= e($c['dmarc']['record']) ?></div>
                <?php else: ?>
                    <span class="badge bad"><?= count($c['dmarc']['own']) > 1 ? count($c['dmarc']['own']) . ' records' : 'none' ?></span>
                <?php endif; ?>
            </td>
            <td class="mono wrap small"><?= $c['spf'] ? e(implode(' | ', $c['spf'])) : '<span class="muted">none</span>' ?></td>
            <td class="mono wrap small"><?= $c['mx'] ? e(implode(', ', $c['mx'])) : '<span class="muted">none</span>' ?></td>
            <td class="mono small">
                <?php foreach ($c['dkim'] as $sel => $ok): ?>
                    <span class="badge <?= $ok ? 'ok' : 'bad' ?>"><?= e($sel) ?></span>
                <?php endforeach; ?>
                <?php if (!$c['dkim']): ?><span class="muted">—</span><?php endif; ?>
            </td>
            <td class="wrap">
                <ul class="findings">
                    <?php foreach ($c['findings'] as $f): ?>
                        <li class="<?= e($f['level']) ?>"><?= e($f['text']) ?></li>
                    <?php endforeach; ?>
                </ul>
            </td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
</div>
<?php endforeach; ?>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
