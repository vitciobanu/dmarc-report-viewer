<?php
/**
 * DMARC aggregate report parser.
 *
 * Pipeline: file on disk → dmarc_extract_xmls() (decompress .gz/.zip)
 *           → dmarc_parse_xml() (validate + turn XML into an array)
 *           → dmarc_store() (INSERT into MySQL, skipping duplicates).
 *
 * Every function throws RuntimeException with a human-readable message on
 * bad input; callers catch it and show the message next to the filename.
 */

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';

/**
 * Take an uploaded/fetched file and return the XML document(s) inside it.
 *
 * Accepts plain .xml, gzip (.xml.gz) and .zip (which may contain several
 * XML files — some reporters batch them). Detection is done by magic
 * bytes, not by file extension, so misnamed files still work.
 *
 * @return array<int, array{name: string, xml: string}>
 */
function dmarc_extract_xmls(string $path, string $originalName): array
{
    $cfg = Database::config();
    $maxBytes = $cfg['max_decompressed_bytes'];

    $head = (string)file_get_contents($path, false, null, 0, 4);

    // gzip magic bytes: 1f 8b
    if (str_starts_with($head, "\x1f\x8b")) {
        return [[
            'name' => preg_replace('/\.gz$/i', '', $originalName),
            'xml'  => gz_read_limited($path, $maxBytes),
        ]];
    }

    // zip magic bytes: "PK"
    if (str_starts_with($head, 'PK')) {
        return zip_read_limited($path, $maxBytes);
    }

    // Otherwise expect plain XML. Reject anything huge outright.
    if (filesize($path) > $maxBytes) {
        throw new RuntimeException('file too large');
    }
    $xml = (string)file_get_contents($path);
    if (!str_contains(substr($xml, 0, 256), '<?xml') && !str_contains(substr($xml, 0, 256), '<feedback')) {
        throw new RuntimeException('not an XML, gzip or zip file');
    }
    return [['name' => $originalName, 'xml' => $xml]];
}

/**
 * Decompress a gzip file, refusing to inflate past $maxBytes
 * (protection against decompression bombs).
 */
function gz_read_limited(string $path, int $maxBytes): string
{
    $gz = gzopen($path, 'rb');
    if ($gz === false) {
        throw new RuntimeException('could not open gzip file');
    }
    $out = '';
    while (!gzeof($gz)) {
        $out .= gzread($gz, 65536);
        if (strlen($out) > $maxBytes) {
            gzclose($gz);
            throw new RuntimeException('decompressed content exceeds the size limit');
        }
    }
    gzclose($gz);
    return $out;
}

/**
 * Extract every .xml inside a zip, checking each entry's declared
 * uncompressed size against the limit BEFORE extracting it.
 *
 * @return array<int, array{name: string, xml: string}>
 */
function zip_read_limited(string $path, int $maxBytes): array
{
    $zip = new ZipArchive();
    if ($zip->open($path) !== true) {
        throw new RuntimeException('could not open zip file');
    }

    $results = [];
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $stat = $zip->statIndex($i);
        if ($stat === false) {
            continue;
        }
        // Skip directories and non-XML entries (some zips ship a readme).
        if (str_ends_with($stat['name'], '/') || !preg_match('/\.xml$/i', $stat['name'])) {
            continue;
        }
        if ($stat['size'] > $maxBytes) {
            $zip->close();
            throw new RuntimeException("zip entry '{$stat['name']}' exceeds the size limit");
        }
        $xml = $zip->getFromIndex($i);
        if ($xml !== false) {
            $results[] = ['name' => basename($stat['name']), 'xml' => $xml];
        }
    }
    $zip->close();

    if (!$results) {
        throw new RuntimeException('zip contains no XML files');
    }
    return $results;
}

/**
 * Validate an XML string as a DMARC aggregate report and convert it to a
 * plain PHP array ready for dmarc_store().
 */
function dmarc_parse_xml(string $xml): array
{
    // --- Security: refuse documents that declare a DOCTYPE. DMARC reports
    // never need one, and DOCTYPEs are the vehicle for XXE (external
    // entity) attacks. LIBXML_NONET additionally blocks any network access
    // during parsing, and we deliberately do NOT pass LIBXML_NOENT (so
    // entities are never substituted).
    if (preg_match('/<!DOCTYPE/i', $xml)) {
        throw new RuntimeException('XML contains a DOCTYPE declaration (rejected for security)');
    }

    $prev = libxml_use_internal_errors(true);
    $doc  = simplexml_load_string($xml, SimpleXMLElement::class, LIBXML_NONET | LIBXML_COMPACT);
    libxml_clear_errors();
    libxml_use_internal_errors($prev);

    if ($doc === false) {
        throw new RuntimeException('not well-formed XML');
    }

    // --- Structural validation: it must look like a DMARC aggregate report.
    if ($doc->getName() !== 'feedback' || !isset($doc->report_metadata, $doc->policy_published)) {
        throw new RuntimeException('not a DMARC aggregate report (missing feedback/report_metadata/policy_published)');
    }
    if (!isset($doc->record)) {
        throw new RuntimeException('report contains no <record> elements');
    }

    $meta   = $doc->report_metadata;
    $policy = $doc->policy_published;

    $begin = (int)$meta->date_range->begin;
    $end   = (int)$meta->date_range->end;
    if ($begin <= 0 || $end <= 0) {
        throw new RuntimeException('invalid date_range timestamps');
    }

    $report = [
        'org_name'     => trim((string)$meta->org_name),
        'org_email'    => trim((string)$meta->email) ?: null,
        'report_id'    => trim((string)$meta->report_id),
        'domain'       => trim((string)$policy->domain),
        'date_begin'   => ts_to_datetime($begin),
        'date_end'     => ts_to_datetime($end),
        'policy_p'     => (string)$policy->p ?: null,
        'policy_sp'    => (string)$policy->sp ?: null,
        'policy_pct'   => isset($policy->pct) ? (int)$policy->pct : null,
        'policy_adkim' => (string)$policy->adkim ?: null,
        'policy_aspf'  => (string)$policy->aspf ?: null,
        'records'      => [],
    ];

    if ($report['org_name'] === '' || $report['report_id'] === '' || $report['domain'] === '') {
        throw new RuntimeException('missing org_name, report_id or domain');
    }

    foreach ($doc->record as $rec) {
        $row  = $rec->row;
        $pol  = $row->policy_evaluated;
        $auth = $rec->auth_results;

        $ip = trim((string)$row->source_ip);
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new RuntimeException("invalid source_ip '$ip'");
        }

        // A record may carry several DKIM signature results (e.g. the
        // sender's own domain + a forwarder's). Keep the most relevant:
        // a passing one if any exists, otherwise the first one listed.
        $dkim = null;
        if (isset($auth->dkim)) {
            foreach ($auth->dkim as $d) {
                if ($dkim === null || (string)$d->result === 'pass') {
                    $dkim = $d;
                }
                if ((string)$d->result === 'pass') {
                    break;
                }
            }
        }
        $spf = isset($auth->spf) ? $auth->spf[0] : null;

        // Optional policy-override reason (why the receiver did not apply
        // the published policy: forwarded mail, mailing list...).
        $reason = isset($pol->reason) ? $pol->reason[0] : null;

        $report['records'][] = [
            'source_ip'      => $ip,
            'msg_count'      => max(1, (int)$row->count),
            'disposition'    => (string)$pol->disposition ?: null,
            'eval_dkim'      => (string)$pol->dkim ?: null,
            'eval_spf'       => (string)$pol->spf ?: null,
            'header_from'    => trim((string)$rec->identifiers->header_from) ?: null,
            'envelope_from'  => trim((string)$rec->identifiers->envelope_from) ?: null,
            'envelope_to'    => trim((string)$rec->identifiers->envelope_to) ?: null,
            'dkim_domain'    => $dkim ? (trim((string)$dkim->domain) ?: null) : null,
            'dkim_selector'  => $dkim ? (trim((string)$dkim->selector) ?: null) : null,
            'dkim_result'    => $dkim ? ((string)$dkim->result ?: null) : null,
            'spf_domain'     => $spf ? (trim((string)$spf->domain) ?: null) : null,
            'spf_result'     => $spf ? ((string)$spf->result ?: null) : null,
            'reason_type'    => $reason ? ((string)$reason->type ?: null) : null,
            'reason_comment' => $reason ? (trim((string)$reason->comment) ?: null) : null,
        ];
    }

    return $report;
}

/**
 * Insert a parsed report (and all its records) into MySQL inside one
 * transaction. Returns 'inserted' or 'duplicate'.
 */
function dmarc_store(array $report, string $sourceFile): string
{
    $pdo = Database::pdo();

    // Duplicate check first (cheap SELECT against the unique key).
    $stmt = $pdo->prepare('SELECT id FROM reports WHERE org_name = ? AND report_id = ?');
    $stmt->execute([$report['org_name'], $report['report_id']]);
    if ($stmt->fetch()) {
        return 'duplicate';
    }

    // Transaction: either the report AND all its records go in, or nothing.
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('
            INSERT INTO reports
                (org_name, org_email, report_id, domain, date_begin, date_end,
                 policy_p, policy_sp, policy_pct, policy_adkim, policy_aspf, source_file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        $stmt->execute([
            $report['org_name'], $report['org_email'], $report['report_id'],
            $report['domain'], $report['date_begin'], $report['date_end'],
            $report['policy_p'], $report['policy_sp'], $report['policy_pct'],
            $report['policy_adkim'], $report['policy_aspf'],
            mb_substr($sourceFile, 0, 255),
        ]);
        $reportId = (int)$pdo->lastInsertId();

        $stmt = $pdo->prepare('
            INSERT INTO records
                (report_id, source_ip, ptr_hostname, msg_count, disposition,
                 eval_dkim, eval_spf, header_from, envelope_from, envelope_to,
                 dkim_domain, dkim_selector, dkim_result, spf_domain, spf_result,
                 reason_type, reason_comment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ');
        foreach ($report['records'] as $r) {
            $stmt->execute([
                $reportId, $r['source_ip'], rdns_lookup($r['source_ip']),
                $r['msg_count'], $r['disposition'], $r['eval_dkim'], $r['eval_spf'],
                $r['header_from'], $r['envelope_from'], $r['envelope_to'],
                $r['dkim_domain'], $r['dkim_selector'], $r['dkim_result'],
                $r['spf_domain'], $r['spf_result'],
                $r['reason_type'], $r['reason_comment'],
            ]);
        }

        $pdo->commit();
        return 'inserted';
    } catch (Throwable $e) {
        $pdo->rollBack();
        throw $e;
    }
}

/**
 * Convenience wrapper used by both the upload page and the IMAP fetcher:
 * process one file on disk and return one status line per XML found.
 *
 * @return array<int, array{name: string, status: string, detail: string}>
 */
function dmarc_process_file(string $path, string $originalName): array
{
    $results = [];
    try {
        $xmls = dmarc_extract_xmls($path, $originalName);
    } catch (RuntimeException $e) {
        return [['name' => $originalName, 'status' => 'error', 'detail' => $e->getMessage()]];
    }

    foreach ($xmls as $entry) {
        try {
            $report = dmarc_parse_xml($entry['xml']);
            $status = dmarc_store($report, $originalName);
            $detail = sprintf(
                '%s, %d record(s), %s → %s',
                $report['org_name'],
                count($report['records']),
                fmt_date($report['date_begin']),
                fmt_date($report['date_end'])
            );
            $results[] = ['name' => $entry['name'], 'status' => $status, 'detail' => $detail];
        } catch (RuntimeException $e) {
            $results[] = ['name' => $entry['name'], 'status' => 'error', 'detail' => $e->getMessage()];
        }
    }
    return $results;
}
