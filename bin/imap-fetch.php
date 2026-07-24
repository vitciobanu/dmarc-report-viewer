<?php
/**
 * IMAP fetcher: pulls DMARC report emails straight from your mailbox and
 * feeds their attachments to the same parser the upload page uses.
 *
 *     php bin/imap-fetch.php            # fetch new (unseen) messages
 *     php bin/imap-fetch.php --all      # rescan the whole folder
 *
 * Configure the [imap] block in config.php first (host, credentials,
 * folder). Designed for a scheduled task (Windows Task Scheduler / cron).
 *
 * PHP 8.4 removed the imap extension from core, so this speaks the IMAP
 * protocol directly over a TLS socket — only the five commands we need:
 * LOGIN, SELECT, SEARCH, FETCH, STORE. Messages are fetched with
 * BODY.PEEK[] (which does NOT set \Seen) and explicitly flagged \Seen
 * only after their attachments are saved and imported — so a run that
 * dies halfway leaves the unprocessed messages unseen for the next run.
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

    public function __construct(string $host, int $port)
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
        while (true) {
            $line = $this->readLine();

            // A line ending in {n} announces a literal: n raw bytes follow.
            if (preg_match('/\{(\d+)\}\r?\n$/', $line, $m)) {
                $line .= $this->readBytes((int)$m[1]);
            }
            if (str_starts_with($line, "$tag ")) {
                // "A3 OK ..." / "A3 NO ..." / "A3 BAD ..."
                $status = strtoupper(explode(' ', trim($line))[1] ?? 'BAD');
                if ($status !== 'OK') {
                    throw new RuntimeException('server said: ' . trim($line));
                }
                return ['status' => $status, 'lines' => $lines];
            }
            $lines[] = $line;
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

    /** @return int[] message sequence numbers matching the criteria */
    public function search(string $criteria): array
    {
        $result = $this->command("SEARCH $criteria");
        foreach ($result['lines'] as $line) {
            if (preg_match('/^\* SEARCH ?(.*)$/i', trim($line), $m)) {
                return $m[1] === '' ? [] : array_map('intval', explode(' ', trim($m[1])));
            }
        }
        return [];
    }

    /**
     * Fetch the full raw source (headers + body) of one message.
     * BODY.PEEK[] instead of BODY[] so the message is NOT marked \Seen
     * yet — we only flag it after successful processing (markSeen()).
     */
    public function fetchMessage(int $seq): string
    {
        $result = $this->command("FETCH $seq (BODY.PEEK[])");
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
        throw new RuntimeException("no body returned for message $seq");
    }

    /** Flag one message as \Seen so the default UNSEEN search skips it. */
    public function markSeen(int $seq): void
    {
        $this->command("STORE $seq +FLAGS (\\Seen)");
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
    echo "Connecting to {$imap['host']}:{$imap['port']}...\n";
    $client = new ImapClient($imap['host'], (int)$imap['port']);
    $client->login($imap['user'], $imap['pass']);
    $client->command('SELECT "' . addcslashes($imap['folder'], '"\\') . '"');

    $criteria = (!$fetchAll && ($imap['unseen_only'] ?? true)) ? 'UNSEEN' : 'ALL';
    $ids = $client->search($criteria);
    echo 'Found ' . count($ids) . " message(s) matching $criteria in '{$imap['folder']}'.\n";

    $saveDir  = dirname(__DIR__) . '/uploads/imap';
    if (!is_dir($saveDir)) {
        mkdir($saveDir, 0777, true);
    }
    $inserted = $duplicates = $errors = 0;

    // Same per-file cap as the upload page; enforced here too so a huge
    // (or malicious) attachment cannot fill the disk before the parser's
    // own decompression limit even gets a chance to run.
    $maxBytes = (int)($cfg['max_upload_bytes'] ?? 5 * 1024 * 1024);

    foreach ($ids as $seq) {
        $raw = $client->fetchMessage($seq);
        $attachments = mime_extract_attachments($raw);

        if (!$attachments) {
            echo "  msg #$seq: no report attachment found, skipping.\n";
            $client->markSeen($seq);
            continue;
        }

        foreach ($attachments as $att) {
            if (strlen($att['content']) > $maxBytes) {
                echo "  msg #$seq {$att['filename']}: skipped — larger than max_upload_bytes.\n";
                $errors++;
                continue;
            }

            $safeName = date('Ymd_His_') . "msg{$seq}_"
                      . preg_replace('/[^A-Za-z0-9._!-]/', '_', $att['filename']);
            $path = "$saveDir/$safeName";
            file_put_contents($path, $att['content']);

            foreach (dmarc_process_file($path, $att['filename']) as $result) {
                echo "  msg #$seq {$result['name']}: {$result['status']} — {$result['detail']}\n";
                match ($result['status']) {
                    'inserted'  => $inserted++,
                    'duplicate' => $duplicates++,
                    default     => $errors++,
                };
            }
        }

        // Only now, with every attachment saved and processed, is the
        // message flagged as read (the files stay in uploads/imap either
        // way, and --all can always re-scan the whole folder).
        $client->markSeen($seq);
    }

    $client->close();
    echo "Done: $inserted inserted, $duplicates duplicate(s) skipped, $errors error(s).\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'IMAP fetch failed: ' . $e->getMessage() . "\n");
    exit(1);
}
