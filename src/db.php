<?php
/**
 * Single PDO entry point.
 *
 * Every part of the app gets its database connection by calling
 * Database::pdo(). The connection is created once (lazily, on first use)
 * and memoized — never instantiate PDO anywhere else.
 */

class Database
{
    /** @var PDO|null The memoized connection (created on first call). */
    private static ?PDO $pdo = null;

    /** @var array|null The loaded config.php contents. */
    private static ?array $config = null;

    /**
     * Load config.php once and return it as an array.
     * Dies with a helpful message if the file is missing.
     */
    public static function config(): array
    {
        if (self::$config === null) {
            $path = dirname(__DIR__) . '/config.php';
            if (!is_file($path)) {
                http_response_code(500);
                exit("Missing config.php — copy config.sample.php to config.php and fill in your values.\n");
            }
            self::$config = require $path;

            // Make PHP date functions use the configured timezone everywhere.
            date_default_timezone_set(self::$config['timezone'] ?? 'UTC');
        }
        return self::$config;
    }

    /**
     * Return the shared PDO connection, creating it on first use.
     */
    public static function pdo(): PDO
    {
        if (self::$pdo === null) {
            $db = self::config()['db'];

            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                $db['host'], $db['port'], $db['name'], $db['charset']
            );

            self::$pdo = new PDO($dsn, $db['user'], $db['pass'], [
                // Throw exceptions on SQL errors instead of failing silently.
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                // fetch() returns ['column' => value] arrays (no numeric keys).
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                // Use real server-side prepared statements (safer).
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        }
        return self::$pdo;
    }
}
