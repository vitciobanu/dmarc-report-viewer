<?php
/**
 * Report detail: metadata of one aggregate report + every record in it.
 * Reached from the dashboard via report.php?id=N.
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/helpers.php';

$pdo = Database::pdo();

$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$id) {
    http_response_code(400);
    exit('Missing or invalid report id.');
}

$stmt = $pdo->prepare('SELECT * FROM reports WHERE id = ?');
$stmt->execute([$id]);
$report = $stmt->fetch();

if (!$report) {
    http_response_code(404);
    exit('Report not found.');
}

$stmt = $pdo->prepare('SELECT * FROM records WHERE report_id = ? ORDER BY msg_count DESC, source_ip');
$stmt->execute([$id]);
$records = $stmt->fetchAll();

$title  = 'Report ' . $report['report_id'];
$active = 'dashboard';
require __DIR__ . '/../src/views/header.php';
?>

<p><a href="index.php">← Back to dashboard</a></p>

<h1>Report from <?= e($report['org_name']) ?></h1>

<div class="panel">
    <dl class="meta-grid">
        <div><dt>Report ID</dt><dd class="mono"><?= e($report['report_id']) ?></dd></div>
        <div><dt>Period</dt><dd><?= e(fmt_datetime($report['date_begin'])) ?> → <?= e(fmt_datetime($report['date_end'])) ?></dd></div>
        <div><dt>Domain</dt><dd class="mono"><?= e($report['domain']) ?></dd></div>
        <div><dt>Reporter contact</dt><dd><?= e($report['org_email'] ?? '—') ?></dd></div>
        <div><dt>Policy</dt><dd>
            p=<?= e($report['policy_p'] ?? '?') ?><?= $report['policy_sp'] ? ', sp=' . e($report['policy_sp']) : '' ?><?= $report['policy_pct'] !== null ? ', pct=' . (int)$report['policy_pct'] : '' ?>
        </dd></div>
        <div><dt>Alignment mode</dt><dd>
            adkim=<?= e($report['policy_adkim'] ?? '?') ?>, aspf=<?= e($report['policy_aspf'] ?? '?') ?>
            <span class="muted">(r = relaxed, s = strict)</span>
        </dd></div>
        <div><dt>Imported</dt><dd><?= e(fmt_datetime($report['created_at'])) ?> <span class="muted">from <?= e($report['source_file'] ?? '?') ?></span></dd></div>
    </dl>
</div>

<h2>Records (<?= count($records) ?>)</h2>
<div class="table-wrap">
<table>
    <thead>
    <tr>
        <th>Source IP</th><th>Hostname (rDNS)</th><th class="num">Msgs</th>
        <th>Disposition</th><th>SPF</th><th>DKIM</th>
        <th>Header From</th><th>Envelope from → to</th>
        <th>DKIM domain / selector</th><th>SPF domain</th><th>Override</th>
    </tr>
    </thead>
    <tbody>
    <?php foreach ($records as $rec):
        // A row is highlighted when DMARC failed outright (neither
        // aligned mechanism passed) — the possible-spoofing case.
        $isFail = $rec['eval_dkim'] !== 'pass' && $rec['eval_spf'] !== 'pass'; ?>
        <tr class="<?= $isFail ? 'row-bad' : '' ?>">
            <td class="mono"><a href="ips.php?ip=<?= e(urlencode($rec['source_ip'])) ?>"><?= e($rec['source_ip']) ?></a></td>
            <td class="mono"><?= e($rec['ptr_hostname'] ?? '') ?: '<span class="muted">no PTR</span>' ?></td>
            <td class="num"><?= number_format((int)$rec['msg_count']) ?></td>
            <td><span class="badge <?= disposition_class($rec['disposition']) ?>"><?= e($rec['disposition'] ?? '—') ?></span></td>
            <td><span class="badge <?= result_class($rec['eval_spf']) ?>"><?= e($rec['eval_spf'] ?? '—') ?></span></td>
            <td><span class="badge <?= result_class($rec['eval_dkim']) ?>"><?= e($rec['eval_dkim'] ?? '—') ?></span></td>
            <td class="mono"><?= e($rec['header_from'] ?? '—') ?></td>
            <td class="mono muted">
                <?= e($rec['envelope_from'] ?? '—') ?><?= $rec['envelope_to'] ? ' → ' . e($rec['envelope_to']) : '' ?>
            </td>
            <td class="mono">
                <?= e($rec['dkim_domain'] ?? '—') ?><?= $rec['dkim_selector'] ? ' / ' . e($rec['dkim_selector']) : '' ?>
                <?php if ($rec['dkim_result'] && $rec['dkim_result'] !== $rec['eval_dkim']): ?>
                    <span class="badge <?= result_class($rec['dkim_result']) ?>"><?= e($rec['dkim_result']) ?></span>
                <?php endif; ?>
            </td>
            <td class="mono">
                <?= e($rec['spf_domain'] ?? '—') ?>
                <?php if ($rec['spf_result'] && $rec['spf_result'] !== $rec['eval_spf']): ?>
                    <span class="badge <?= result_class($rec['spf_result']) ?>"><?= e($rec['spf_result']) ?></span>
                <?php endif; ?>
            </td>
            <td class="muted"><?= e($rec['reason_type'] ?? '') ?><?= $rec['reason_comment'] ? ' (' . e($rec['reason_comment']) . ')' : '' ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
</div>

<p class="muted">
    SPF / DKIM columns show the <em>DMARC-evaluated</em> (alignment-aware)
    result. When the raw authentication result differs (e.g. DKIM signature
    valid but for another domain), it appears as an extra badge next to the
    domain.
</p>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
