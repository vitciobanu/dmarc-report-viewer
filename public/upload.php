<?php
/**
 * Upload page: accepts one or several .xml / .xml.gz / .zip report files,
 * stores a copy under uploads/, parses each and inserts into MySQL.
 *
 * Follows Post/Redirect/Get: the POST branch processes the files, queues
 * one flash message per result, and redirects back to this page.
 */

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/helpers.php';
require __DIR__ . '/../src/parser.php';

$cfg = Database::config();

// ---------------------------------------------------------------------
// POST: process the uploaded files, then redirect (PRG).
// ---------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $files = $_FILES['files'] ?? null;
    if (!$files || !is_array($files['name']) || $files['name'][0] === '') {
        flash_set('error', 'No files were selected.');
        header('Location: upload.php');
        exit;
    }

    // uploads/ is gitignored, so it may not exist on a fresh clone.
    $uploadDir = dirname(__DIR__) . '/uploads';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    // PHP gives us parallel arrays (name[0], tmp_name[0], ...) — walk them.
    foreach ($files['name'] as $i => $originalName) {

        if ($files['error'][$i] !== UPLOAD_ERR_OK) {
            flash_set('error', "$originalName: upload failed (PHP error code {$files['error'][$i]}).");
            continue;
        }
        if ($files['size'][$i] > $cfg['max_upload_bytes']) {
            flash_set('error', "$originalName: file exceeds the upload size limit.");
            continue;
        }
        // Cheap extension pre-check; the parser re-validates content by
        // magic bytes anyway, this just gives a clearer message.
        if (!preg_match('/\.(xml|xml\.gz|gz|zip)$/i', $originalName)) {
            flash_set('error', "$originalName: unsupported file type (expected .xml, .xml.gz or .zip).");
            continue;
        }

        // Keep a copy in uploads/ (timestamped to avoid name collisions).
        $safeName = date('Ymd_His_') . preg_replace('/[^A-Za-z0-9._!-]/', '_', basename($originalName));
        $dest     = "$uploadDir/$safeName";

        if (!move_uploaded_file($files['tmp_name'][$i], $dest)) {
            flash_set('error', "$originalName: could not move the uploaded file.");
            continue;
        }

        // Parse + insert. One uploaded file may contain several XMLs (zip).
        foreach (dmarc_process_file($dest, $originalName) as $result) {
            $msg = "{$result['name']}: {$result['detail']}";
            match ($result['status']) {
                'inserted'  => flash_set('success', "✓ $msg"),
                'duplicate' => flash_set('info', "↷ Skipped duplicate — $msg"),
                default     => flash_set('error', "✗ {$result['name']}: {$result['detail']}"),
            };
        }
    }

    header('Location: upload.php');
    exit;
}

// ---------------------------------------------------------------------
// GET: render the form.
// ---------------------------------------------------------------------
$title  = 'Upload reports';
$active = 'upload';
require __DIR__ . '/../src/views/header.php';
?>

<h1>Upload reports</h1>

<form method="post" enctype="multipart/form-data">
    <div id="dropzone" class="dropzone">
        <span class="big">📥</span>
        <strong>Drag report files here</strong><br>
        or click to browse — .xml, .xml.gz and .zip, multiple files allowed
    </div>

    <!-- The real input; hidden because the dropzone drives it. -->
    <input type="file" name="files[]" id="file-input" multiple
           accept=".xml,.gz,.zip,application/gzip,application/zip,text/xml"
           style="display:none">

    <ul id="file-list" class="file-list"></ul>

    <button type="submit" id="upload-btn" class="btn" disabled>Upload &amp; parse</button>
</form>

<div class="panel">
    <h2>What happens on upload</h2>
    <p class="muted">
        Each file is decompressed if needed, validated as a DMARC aggregate
        report (malformed or non-DMARC XML is rejected), and inserted into
        the database. Reports already imported are detected by their
        <span class="mono">(organization, report_id)</span> pair and skipped,
        so re-uploading the same file is always safe. A copy of every file
        is kept in the <span class="mono">uploads/</span> folder.
    </p>
</div>

<?php require __DIR__ . '/../src/views/footer.php'; ?>
