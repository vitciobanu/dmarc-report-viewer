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

    // ---- Domain health cards (dashboard) --------------------------------
    // One card per domain at the top of the dashboard, colored by its
    // DMARC pass rate over the last `days` days:
    //   >= ok_pct  green · >= warn_pct  amber · below that  red
    'health' => [
        'days'     => 30,
        'ok_pct'   => 99,
        'warn_pct' => 90,
    ],

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

        // Several mailboxes (e.g. one per domain you monitor)? Uncomment
        // 'accounts': when present it REPLACES the single account above
        // (only 'enabled' above still applies, as the master switch).
        // Each entry takes the same keys; 'port' and 'folders' are
        // optional, and 'enabled' => false skips one account.
        // Keep the mailbox you used before FIRST in the list: it inherits
        // the progress already saved in uploads/imap/state.json.
        //
        // 'accounts' => [
        //     [
        //         'host' => 'imap.example.com',
        //         'user' => 'you@example.com',
        //         'pass' => 'CHANGE_ME',
        //     ],
        //     [
        //         'host'    => 'mail.example.org',
        //         'port'    => 993,
        //         'user'    => 'reports@example.org',
        //         'pass'    => 'CHANGE_ME',
        //         'folders' => ['INBOX'],
        //     ],
        // ],
    ],
];
