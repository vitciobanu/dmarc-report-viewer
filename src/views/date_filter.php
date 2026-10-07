<?php
/**
 * Shared filter form: domain selector (when several domains have
 * reports), From/To date inputs and quick-range presets.
 * Pages set $range (from date_filter()) and $domain (from
 * domain_filter()) before including this partial.
 *
 * Presets appear progressively as the dataset grows: each one is only
 * shown once there is data older than the previous (smaller) preset
 * would cover, so the row starts small and gains entries over time.
 */

$oldest  = Database::pdo()->query('SELECT MIN(DATE(date_begin)) FROM reports')->fetchColumn();
$today   = date('Y-m-d');
$presets = [];

if ($oldest) {
    $daysBack = (int)((strtotime($today) - strtotime($oldest)) / 86400);
    $ytdDays  = (int)((strtotime($today) - strtotime(date('Y-01-01'))) / 86400);

    // label => [window start, only shown when data is older than N days]
    $candidates = [
        'Week'    => [date('Y-m-d', strtotime('-7 days')), 0],
        'Month'   => [date('Y-m-d', strtotime('-30 days')), 7],
        'YTD'     => [date('Y-01-01'), 30],
        '1 year'  => [date('Y-m-d', strtotime('-1 year')), $ytdDays],
        '5 years' => [date('Y-m-d', strtotime('-5 years')), 365],
    ];
    foreach ($candidates as $label => [$start, $minDays]) {
        if ($daysBack > $minDays) {
            $presets[$label] = $start;
        }
    }
}
?>
<form method="get" class="filter">
    <?php
    // Domain selector, only worth showing once reports exist for more
    // than one domain. Pages set $domain (from domain_filter()); the
    // empty option sends ?domain= which means "all domains".
    if (count(known_domains()) > 1): ?>
    <div>
        <label for="domain">Domain</label>
        <select id="domain" name="domain">
            <option value="">All domains</option>
            <?php foreach (known_domains() as $d): ?>
                <option value="<?= e($d) ?>"<?= ($domain ?? null) === $d ? ' selected' : '' ?>><?= e($d) ?></option>
            <?php endforeach; ?>
        </select>
    </div>
    <?php endif; ?>
    <div>
        <label for="from">From</label>
        <input type="date" id="from" name="from" value="<?= e($range['from']) ?>">
    </div>
    <div>
        <label for="to">To</label>
        <input type="date" id="to" name="to" value="<?= e($range['to']) ?>">
    </div>
    <button type="submit" class="btn secondary">Apply</button>
    <?php if ($presets): ?>
        <div class="presets">
            <?php foreach ($presets as $label => $start): ?>
                <a class="<?= ($range['from'] === $start && $range['to'] === $today) ? 'active' : '' ?>"
                   href="?from=<?= e($start) ?>&amp;to=<?= e($today) ?>"><?= e($label) ?></a>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</form>
