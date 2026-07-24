<?php
/**
 * Configuration template.
 *
 * Copy this file to config.php and fill in your values.
 * config.php is gitignored — it holds credentials and must NEVER be committed.
 */

return [

    // ---- MySQL ----------------------------------------------------------
    'db' => [
        'host'    => '127.0.0.1',
        'port'    => 3306,
        'name'    => 'dmarc',
        'user'    => 'dmarc',
        'pass'    => 'CHANGE_ME',
        'charset' => 'utf8mb4',
    ],

    // ---- Display --------------------------------------------------------
    // Timezone used to convert the Unix timestamps found in the reports
    // into human-readable dates (both when storing and when displaying).
    // Any PHP timezone identifier works: https://www.php.net/timezones
    'timezone' => 'UTC',

    // ---- Upload limits --------------------------------------------------
    // Reports are tiny (a few KB). These caps protect against oversized
    // uploads and decompression ("zip bomb") attacks.
    'max_upload_bytes'       => 5 * 1024 * 1024,   // 5 MB per uploaded file
    'max_decompressed_bytes' => 20 * 1024 * 1024,  // 20 MB after decompression

    // ---- rDNS -----------------------------------------------------------
    // Reverse-DNS (PTR) lookup of each source IP at insert time. Set to
    // false if your machine has no DNS access or lookups are slow.
    'rdns_lookup' => true,

    // ---- IMAP fetcher (bin/imap-fetch.php) ------------------------------
    // Optional: pull report emails straight from your mailbox.
    // Use a dedicated app password (most providers offer them in their
    // security settings, ideally IMAP-only), never your main password.
    'imap' => [
        'enabled'  => false,
        'host'     => 'imap.example.com',
        'port'     => 993,               // IMAPS (TLS)
        'user'     => 'you@example.com',
        'pass'     => 'CHANGE_ME',
        // Folders to scan. '*' (default) = every folder except Trash,
        // Drafts and Sent, so reports filed into the wrong folder are
        // still found. Or list specific ones: ['INBOX', 'Reports/DMARC'].
        'folders'  => '*',
    ],
];
