<?php
/**
 * Idempotent migration runner. Run from the project root:
 *
 *     php scripts/init_db.php
 *
 * Applies every migrations/NN_*.sql not yet applied, in filename order,
 * and records each one in the `schema_migrations` table — so running it
 * twice is safe (already-applied files are skipped). Never edit an
 * already-applied migration; add a new numbered file instead.
 */

require __DIR__ . '/../src/db.php';

$pdo = Database::pdo();

// Bookkeeping table for applied migrations (created on first run).
$pdo->exec("
    CREATE TABLE IF NOT EXISTS schema_migrations (
        filename   VARCHAR(255) NOT NULL PRIMARY KEY,
        applied_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
");

$applied = $pdo->query('SELECT filename FROM schema_migrations')->fetchAll(PDO::FETCH_COLUMN);

$files = glob(__DIR__ . '/../migrations/*.sql');
sort($files); // apply in NN_ filename order

$ran = 0;
foreach ($files as $file) {
    $name = basename($file);
    if (in_array($name, $applied, true)) {
        echo "skip  $name (already applied)\n";
        continue;
    }

    $sql = file_get_contents($file);

    // Strip full-line comments, then split the file into statements on ';'.
    // Keep each migration statement simple (no stored routines/DELIMITER).
    $lines = array_filter(
        explode("\n", $sql),
        fn($l) => !str_starts_with(ltrim($l), '--')
    );
    $statements = array_filter(
        array_map('trim', explode(';', implode("\n", $lines)))
    );

    foreach ($statements as $statement) {
        $pdo->exec($statement);
    }

    $stmt = $pdo->prepare('INSERT INTO schema_migrations (filename) VALUES (?)');
    $stmt->execute([$name]);
    echo "apply $name (" . count($statements) . " statements)\n";
    $ran++;
}

echo $ran === 0 ? "Nothing to do — schema is up to date.\n" : "Done: $ran migration(s) applied.\n";
