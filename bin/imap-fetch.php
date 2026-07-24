<?php
/**
 * IMAP fetcher: pulls DMARC report emails straight from your mailbox and
 * feeds their attachments to the same parser the upload page uses.
 *
 *     php bin/imap-fetch.php            # process messages new since last run
 *     php bin/imap-fetch.php --all      # rescan every folder from scratch
 *
 * It scans EVERY folder of the account (except Trash, Drafts and Sent),
 * so a report that lands in the inbox — or gets filed into the wrong
 * folder — is still found. Set imap.folders in config.php to an explicit
 * list to restrict it.
 *
 * Because personal folders are scanned too, the fetcher is careful not
 * to disturb them:
 *   - Per-folder progress (the highest examined UID) is remembered in
 *     uploads/imap/state.json, so each message is examined at most once
 *     across runs.
 *   - Only the cheap MIME skeleton (BODYSTRUCTURE) of new messages is
 *     fetched; the full body is downloaded only when that skeleton
 *     mentions a zip/gzip/xml part or a report-looking filename.
 *   - Only messages that actually yielded a report attachment are marked
 *     \Seen — everything else keeps its read/unread status untouched.
 *
 * PHP 8.4 removed the imap extension from core, so this speaks the IMAP
 * protocol directly over a TLS socket — only the commands we need:
 * LOGIN, LIST, SELECT, UID FETCH, UID STORE, LOGOUT.
 */

if (PHP_SAPI !== 'cli') {
    exit("This script must be run from the command line.\n");
}

require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/helpers.php';
require __DIR__ . '/../src/parser.php';

$cfg  = Database::config();
$imap = $cfg['imap'] ?? [];

if (empty($imap['enabled'])) {
    exit("IMAP fetching is disabled — set imap.enabled = true in config.php.\n");
}

$fetchAll = in_array('--all', $argv, true);

// =====================================================================
// Minimal IMAP client
// =====================================================================
class ImapClient
{
    /** @var resource */
    private $sock;
    private int $tagCounter = 0;

    /**
     * @param int $maxLiteral Hard ceiling (bytes) on any single literal
     *        the server may send us; 0 = unlimited. Defense in depth: the
     *        caller already skips oversized messages via RFC822.SIZE, but
     *        a lying/hostile server must not be able to make us buffer
     *        gigabytes either.
     */
    public function __construct(string $host, int $port, private int $maxLiteral = 0)
    {
        // ssl:// gives us implicit TLS (IMAPS, port 993). Certificate
        // verification is ON by default — that is what we want.
        $this->sock = stream_socket_client(
            "ssl://$host:$port", $errno, $errstr, 30
        );
        if ($this->sock === false) {
            throw new RuntimeException("connection failed: $errstr ($errno)");
        }
        stream_set_timeout($this->sock, 60);
        $this->readLine(); // server greeting: "* OK ..."
    }

    /** Read one CRLF-terminated line from the server. */
    private function readLine(): string
    {
        $line = fgets($this->sock);
        if ($line === false) {
            throw new RuntimeException('connection lost while reading');
        }
        return $line;
    }

    /** Read exactly $n bytes (used for IMAP literals like {12345}). */
    private function readBytes(int $n): string
    {
        $data = '';
        while (strlen($data) < $n) {
            $chunk = fread($this->sock, min(65536, $n - strlen($data)));
            if ($chunk === false || $chunk === '') {
                throw new RuntimeException('connection lost while reading literal');
            }
            $data .= $chunk;
        }
        return $data;
    }

    /**
     * Send a tagged command and collect every response line until the
     * tagged completion ("A3 OK ..."). Literals ({n} + raw bytes) inside
     * the response are read in full and appended to their line.
     *
     * @return array{status: string, lines: string[]}
     */
    public function command(string $cmd): array
    {
        $tag = 'A' . (++$this->tagCounter);
        fwrite($this->sock, "$tag $cmd\r\n");
        return $this->collect($tag);
    }

    private function collect(string $tag): array
    {
        $lines = [];
        $oversized = null;
        while (true) {
            $line = $this->readLine();

            // A line ending in {n} announces a literal: n raw bytes follow.
            if (preg_match('/\{(\d+)\}\r?\n$/', $line, $m)) {
                $n = (int)$m[1];
                if ($this->maxLiteral > 0 && $n > $this->maxLiteral) {
                    // Read and DISCARD the oversized literal in small
                    // chunks (never buffering it) so the connection stays
                    // in sync, and fail the command once the server has
                    // finished its response.
                    $this->discardBytes($n);
                    $oversized = $n;
                } else {
                    $line .= $this->readBytes($n);
                }
            }
            if (str_starts_with($line, "$tag ")) {
                // "A3 OK ..." / "A3 NO ..." / "A3 BAD ..."
                $status = strtoupper(explode(' ', trim($line))[1] ?? 'BAD');
                if ($status !== 'OK') {
                    throw new RuntimeException('server said: ' . trim($line));
                }
                if ($oversized !== null) {
                    throw new RuntimeException(
                        "server sent a $oversized-byte literal, over the {$this->maxLiteral}-byte safety limit"
                    );
                }
                return ['status' => $status, 'lines' => $lines];
            }
            $lines[] = $line;
        }
    }

    /** Read and throw away exactly $n bytes without buffering them. */
    private function discardBytes(int $n): void
    {
        while ($n > 0) {
            $chunk = fread($this->sock, min(65536, $n));
            if ($chunk === false || $chunk === '') {
                throw new RuntimeException('connection lost while discarding literal');
            }
            $n -= strlen($chunk);
        }
    }

    /**
     * LOGIN with the password sent as an IMAP literal, so any special
     * character (quotes, backslashes, spaces) works unmodified.
     */
    public function login(string $user, string $pass): void
    {
        $tag = 'A' . (++$this->tagCounter);
        fwrite($this->sock, sprintf("%s LOGIN \"%s\" {%d}\r\n",
            $tag, addcslashes($user, '"\\'), strlen($pass)));

        // The server must answer "+ ..." (continue) before we send the literal.
        $line = $this->readLine();
        if (!str_starts_with($line, '+')) {
            throw new RuntimeException('login rejected: ' . trim($line));
        }
        fwrite($this->sock, "$pass\r\n");
        $this->collect($tag);
    }

    /** @return array{name: string, flags: string[]}[] every folder on the account */
    public function listFolders(): array
    {
        $result  = $this->command('LIST "" "*"');
        $folders = [];
        foreach ($result['lines'] as $line) {
            // * LIST (\Flags ...) "/" "Folder name"   — the name is quoted
            // when it contains spaces, bare otherwise.
            if (preg_match('/^\* LIST \(([^)]*)\) "[^"]*" (?:"(.*)"|(\S+))\s*$/', trim($line), $m)) {
                $folders[] = [
                    'name'  => ($m[2] ?? '') !== '' ? stripslashes($m[2]) : $m[3],
                    'flags' => preg_split('/\s+/', trim($m[1]), -1, PREG_SPLIT_NO_EMPTY),
                ];
            }
        }
        return $folders;
    }

    /** SELECT a folder; returns its message count and UIDVALIDITY. */
    public function select(string $folder): array
    {
        $result = $this->command('SELECT "' . addcslashes($folder, '"\\') . '"');
        $info = ['exists' => 0, 'uidvalidity' => 0];
        foreach ($result['lines'] as $line) {
            if (preg_match('/^\* (\d+) EXISTS/', $line, $m)) {
                $info['exists'] = (int)$m[1];
            }
            if (preg_match('/UIDVALIDITY (\d+)/', $line, $m)) {
                $info['uidvalidity'] = (int)$m[1];
            }
        }
        return $info;
    }

    /**
     * Fetch the BODYSTRUCTURE (the MIME skeleton: part types and
     * filenames, no content) plus total message size of every message in
     * a UID range — the cheap way to decide which messages are worth
     * downloading in full, and to refuse oversized ones before download.
     *
     * @return array<int, array{struct: string, size: int}> keyed by UID
     */
    public function uidFetchStructures(string $range): array
    {
        $result  = $this->command("UID FETCH $range (BODYSTRUCTURE RFC822.SIZE)");
        $structs = [];
        foreach ($result['lines'] as $line) {
            if (str_contains($line, 'BODYSTRUCTURE') && preg_match('/\bUID (\d+)/', $line, $m)) {
                $size = preg_match('/RFC822\.SIZE (\d+)/', $line, $s) ? (int)$s[1] : 0;
                $structs[(int)$m[1]] = ['struct' => $line, 'size' => $size];
            }
        }
        return $structs;
    }

    /**
     * Fetch the full raw source (headers + body) of one message by UID.
     * BODY.PEEK[] instead of BODY[] so the message is NOT marked \Seen —
     * only messages with an actual report attachment get flagged.
     */
    public function uidFetchMessage(int $uid): string
    {
        $result = $this->command("UID FETCH $uid (BODY.PEEK[])");
        // The message arrives as a literal appended to the "* n FETCH" line;
        // strip the protocol framing around it.
        foreach ($result['lines'] as $line) {
            $pos = strpos($line, "}\r\n");
            if ($pos === false) {
                $pos = strpos($line, "}\n");
            }
            if (str_contains($line, 'FETCH') && $pos !== false) {
                return substr($line, $pos + ($line[$pos + 1] === "\r" ? 3 : 2));
            }
        }
        throw new RuntimeException("no body returned for UID $uid");
    }

    /** Flag one message as \Seen (only done after importing a report). */
    public function markSeen(int $uid): void
    {
        $this->command("UID STORE $uid +FLAGS (\\Seen)");
    }

    public function close(): void
    {
        try {
            $this->command('LOGOUT');
        } catch (Throwable) {
            // Ignore errors during logout — we are leaving anyway.
        }
        fclose($this->sock);
    }
}

// =====================================================================
// MIME: extract report attachments from a raw email
// =====================================================================

/**
 * Return every attachment that looks like a DMARC report file:
 * [['filename' => ..., 'content' => raw bytes], ...]
 */
function mime_extract_attachments(string $raw): array
{
    [$headers, $body] = mime_split($raw);
    return mime_walk($headers, $body);
}

/** Split a message/part into [header-string, body-string]. */
function mime_split(string $raw): array
{
    $sep = strpos($raw, "\r\n\r\n");
    $len = 4;
    if ($sep === false) {
        $sep = strpos($raw, "\n\n");
        $len = 2;
    }
    if ($sep === false) {
        return [$raw, ''];
    }
    return [substr($raw, 0, $sep), substr($raw, $sep + $len)];
}

/** Get a header value (first line only is enough here), unfolded. */
function mime_header(string $headers, string $name): ?string
{
    if (preg_match('/^' . preg_quote($name, '/') . ':[ \t]*(.*(?:\r?\n[ \t].*)*)/mi', $headers, $m)) {
        return preg_replace('/\r?\n[ \t]+/', ' ', trim($m[1]));
    }
    return null;
}

/** Recursively walk a MIME part tree collecting report attachments. */
function mime_walk(string $headers, string $body): array
{
    $type = strtolower(mime_header($headers, 'Content-Type') ?? 'text/plain');

    // Multipart: split on the boundary and recurse into each sub-part.
    if (str_starts_with($type, 'multipart/')
        && preg_match('/boundary="?([^";]+)"?/i', $type, $m)) {
        $found = [];
        // Parts live between "--boundary" markers; the last one ends "--".
        $chunks = preg_split('/\r?\n--' . preg_quote(trim($m[1]), '/') . '(?:--)?[ \t]*\r?\n?/', "\r\n" . $body);
        foreach ($chunks as $chunk) {
            if (trim($chunk) === '') {
                continue;
            }
            [$h, $b] = mime_split($chunk);
            $found = array_merge($found, mime_walk($h, $b));
        }
        return $found;
    }

    // Leaf part: is it a report file? Match by declared type or filename.
    $disposition = mime_header($headers, 'Content-Disposition') ?? '';
    $filename    = null;
    foreach ([$disposition, $type] as $source) {
        if (preg_match('/(?:file)?name="?([^";]+)"?/i', $source, $m)) {
            $filename = trim($m[1]);
            break;
        }
    }

    $looksLikeReport =
        preg_match('#application/(zip|gzip|x-gzip|xml)|text/xml#', $type)
        || ($filename && preg_match('/\.(xml|xml\.gz|gz|zip)$/i', $filename));

    if (!$looksLikeReport) {
        return [];
    }

    // Decode the body according to its transfer encoding.
    $encoding = strtolower(mime_header($headers, 'Content-Transfer-Encoding') ?? '7bit');
    $content  = match ($encoding) {
        'base64'           => base64_decode(preg_replace('/\s+/', '', $body), true) ?: '',
        'quoted-printable' => quoted_printable_decode($body),
        default            => $body,
    };

    if ($content === '') {
        return [];
    }
    return [['filename' => $filename ?? 'report.xml', 'content' => $content]];
}

// =====================================================================
// Main
// =====================================================================
try {
    // Same per-file cap as the upload page; enforced here too so a huge
    // (or malicious) attachment cannot fill memory or disk before the
    // parser's own decompression limit even gets a chance to run.
    $maxBytes = (int)($cfg['max_upload_bytes'] ?? 5 * 1024 * 1024);

    // A whole MESSAGE may legitimately be larger than its attachment
    // (base64 inflates ~4/3, plus MIME headers) — allow that overhead
    // when judging RFC822.SIZE before download.
    $maxMsgBytes = (int)($maxBytes * 1.5) + 512 * 1024;

    echo "Connecting to {$imap['host']}:{$imap['port']}...\n";
    $client = new ImapClient($imap['host'], (int)$imap['port'], $maxMsgBytes + 65536);
    $client->login($imap['user'], $imap['pass']);

    // Folders to scan: an explicit list in config, or '*' (the default)
    // meaning every folder except Trash, Drafts and Sent — so reports
    // filed into the wrong folder are still picked up.
    $folderCfg = $imap['folders'] ?? '*';
    if (is_array($folderCfg)) {
        $folders = $folderCfg;
    } else {
        $folders = [];
        foreach ($client->listFolders() as $f) {
            $flags = array_map('strtolower', $f['flags']);
            if (array_intersect($flags, ['\noselect', '\trash', '\drafts', '\sent'])) {
                continue;
            }
            $folders[] = $f['name'];
        }
    }

    $saveDir = dirname(__DIR__) . '/uploads/imap';
    if (!is_dir($saveDir)) {
        mkdir($saveDir, 0755, true);
    }

    // Per-folder progress: the highest UID already examined, so every
    // message is inspected at most once across runs. UIDs are only
    // meaningful for a given UIDVALIDITY — if the server changes it,
    // the folder is rescanned from the start.
    $stateFile = "$saveDir/state.json";
    $state = is_file($stateFile)
        ? (json_decode((string)file_get_contents($stateFile), true) ?: [])
        : [];

    // A message is worth downloading when its MIME skeleton mentions a
    // zip/gzip/xml part or a filename with a report extension.
    $candidate = '/"(zip|gzip|x-gzip|xml)"|\.(xml|gz|zip)"/i';

    $inserted = $duplicates = $errors = 0;

    foreach ($folders as $folder) {
      // One broken folder (un-selectable, transient server error) must
      // not abort the whole run — log it and move on to the next one.
      try {
        $info   = $client->select($folder);
        $fState = $state[$folder] ?? null;
        if (!$fState || $fState['uidvalidity'] !== $info['uidvalidity']) {
            $fState = ['uidvalidity' => $info['uidvalidity'], 'last_uid' => 0];
        }
        if ($fetchAll) {
            $fState['last_uid'] = 0;
        }

        if ($info['exists'] === 0) {
            $state[$folder] = $fState;
            continue;
        }

        $structs = $client->uidFetchStructures(($fState['last_uid'] + 1) . ':*');
        ksort($structs);

        // An "N:*" range always returns at least the newest message, even
        // when N is past it — keep only what we have not examined yet.
        $structs = array_filter($structs, fn($uid) => $uid > $fState['last_uid'], ARRAY_FILTER_USE_KEY);
        echo "Scanning '$folder': " . count($structs) . " new of {$info['exists']} message(s).\n";

        foreach ($structs as $uid => ['struct' => $struct, 'size' => $size]) {
            $fState['last_uid'] = $uid;

            if (!preg_match($candidate, $struct)) {
                continue; // no report-shaped part — not worth downloading
            }

            // Refuse oversized messages BEFORE downloading them, so a
            // huge attachment mailed to us can never exhaust memory.
            if ($size > $maxMsgBytes) {
                echo "  [$folder] UID $uid: skipped — message is $size bytes, over the size limit.\n";
                $errors++;
                continue;
            }

            $raw = $client->uidFetchMessage($uid);
            $attachments = mime_extract_attachments($raw);
            if (!$attachments) {
                echo "  [$folder] UID $uid: no report attachment after all, skipping.\n";
                continue;
            }

            foreach ($attachments as $att) {
                if (strlen($att['content']) > $maxBytes) {
                    echo "  [$folder] UID $uid {$att['filename']}: skipped — larger than max_upload_bytes.\n";
                    $errors++;
                    continue;
                }

                $safeName = date('Ymd_His_') . "uid{$uid}_"
                          . preg_replace('/[^A-Za-z0-9._!-]/', '_', $att['filename']);
                $path = "$saveDir/$safeName";
                file_put_contents($path, $att['content']);

                foreach (dmarc_process_file($path, $att['filename']) as $result) {
                    echo "  [$folder] UID $uid {$result['name']}: {$result['status']} — {$result['detail']}\n";
                    match ($result['status']) {
                        'inserted'  => $inserted++,
                        'duplicate' => $duplicates++,
                        default     => $errors++,
                    };
                }
            }

            // Mark only actual report messages as read — everything else
            // in the folder keeps its unread status untouched.
            $client->markSeen($uid);
        }

        $state[$folder] = $fState;
        file_put_contents($stateFile, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
      } catch (RuntimeException $e) {
        // Progress for this folder is intentionally NOT saved, so the
        // next run retries it from the same point.
        echo "  [$folder] folder skipped: {$e->getMessage()}\n";
        $errors++;
      }
    }

    $client->close();
    echo "Done: $inserted inserted, $duplicates duplicate(s) skipped, $errors error(s).\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'IMAP fetch failed: ' . $e->getMessage() . "\n");
    exit(1);
}
