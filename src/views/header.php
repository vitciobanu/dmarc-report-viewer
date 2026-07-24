<?php
/**
 * Shared page header + navigation.
 *
 * Each page sets $title (browser tab / heading) and $active (nav key)
 * before requiring this file, then emits its content, then requires
 * footer.php.
 */

$nav = [
    'dashboard' => ['index.php',  'Dashboard'],
    'upload'    => ['upload.php', 'Upload'],
    'ips'       => ['ips.php',    'Source IPs'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($title ?? 'DMARC Report Viewer') ?> · DMARC Report Viewer</title>
<link rel="stylesheet" href="assets/style.css">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📊</text></svg>">
</head>
<body>
<header class="topbar">
    <div class="topbar-inner">
        <span class="brand">📊 DMARC Report Viewer</span>
        <nav>
            <?php foreach ($nav as $key => [$href, $label]): ?>
                <a href="<?= e($href) ?>" class="<?= ($active ?? '') === $key ? 'active' : '' ?>"><?= e($label) ?></a>
            <?php endforeach; ?>
        </nav>
    </div>
</header>
<main class="container">
<?php
// Flash messages queued by a previous POST (Post/Redirect/Get pattern).
foreach (flash_get() as $flash): ?>
    <div class="flash flash-<?= e($flash['type']) ?>"><?= e($flash['message']) ?></div>
<?php endforeach; ?>
