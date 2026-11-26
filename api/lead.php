<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function respond(int $status, array $body): void {
    http_response_code($status);
    echo json_encode($body);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    respond(405, ['ok' => false]);
}

$data = json_decode(file_get_contents('php://input', false, null, 0, 8193), true);
if (!is_array($data)) {
    respond(400, ['ok' => false]);
}

// Honeypot: silently reject bot fills without revealing the trap
if (!empty($data['website'])) {
    respond(200, ['ok' => false]);
}

$fields = [];
foreach ([
    'name' => 120,
    'company' => 160,
    'email' => 254,
    'phone' => 40,
    'source_url' => 2048,
    'submission_key' => 128,
] as $field => $limit) {
    $raw = $data[$field] ?? null;
    if (!is_string($raw) || trim($raw) === '' || strlen($raw) > $limit || preg_match('/[[:cntrl:]]/', $raw)) {
        respond(400, ['ok' => false]);
    }
    $fields[$field] = trim($raw);
}
extract($fields, EXTR_SKIP);

$digits = preg_replace('/\D/', '', $phone);
if (
    !filter_var($email, FILTER_VALIDATE_EMAIL)
    || !preg_match('/^[+0-9 ().-]+$/D', $phone)
    || strlen($digits) < 7
    || strlen($digits) > 15
    || !filter_var($source_url, FILTER_VALIDATE_URL)
    || !preg_match('~^https?://~i', $source_url)
    || !preg_match('/^[A-Za-z0-9_-]{8,128}$/D', $submission_key)
) {
    respond(400, ['ok' => false]);
}

try {
    // Only keys, receipts and timestamps are persisted outside the document root.
    $dir = sys_get_temp_dir() . '/gnc-plumbing-map-' . substr(hash('sha256', __DIR__), 0, 20);
    if (is_link($dir) || (!is_dir($dir) && !@mkdir($dir, 0700) && !is_dir($dir))) {
        throw new RuntimeException('Receipt storage unavailable');
    }

    $db = new PDO('sqlite:' . $dir . '/receipts.sqlite', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 10,
    ]);
    $db->exec('CREATE TABLE IF NOT EXISTS receipts (key TEXT PRIMARY KEY, receipt TEXT, created INTEGER)');
    $db->exec('BEGIN IMMEDIATE');
    $db->prepare('DELETE FROM receipts WHERE created <= ?')->execute([time() - 600]);

    $lookup = $db->prepare('SELECT receipt FROM receipts WHERE key = ?');
    $lookup->execute([$submission_key]);
    $receipt = $lookup->fetchColumn();
    $lookup->closeCursor();
    if ($receipt !== false) {
        $db->exec('COMMIT');
        respond(200, ['ok' => true, 'receiptId' => $receipt, 'duplicate' => true]);
    }

    $receipt = bin2hex(random_bytes(12));
    $db->prepare('INSERT INTO receipts VALUES (?, ?, ?)')->execute([$submission_key, $receipt, time()]);

    $payload = [
        'campaign' => 'GNC Plumbing — Harrisburg 30-Mile Pilot',
        'name' => $name,
        'company' => $company,
        'email' => $email,
        'phone' => $phone,
        'message' => "Campaign: GNC Plumbing Estimate Follow-Up Map\nReceipt: $receipt\nUTC: " . gmdate('Y-m-d\TH:i:s\Z') . "\nSource: $source_url\nSubmission key: $submission_key",
        '_subject' => "[Get New Customers — Plumbing Map Request] $name ($company)",
        '_replyto' => $email,
    ];

    $ch = curl_init('https://formspree.io/f/xyewvbwy');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Accept: application/json',
            'Origin: https://limitless-lime-goshawk-85.hostingersite.com',
            'Referer: https://limitless-lime-goshawk-85.hostingersite.com/sites/plumbing-landing/',
        ],
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
    ]);
    $response = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    $result = is_string($response) ? json_decode($response, true) : null;
    if ($status !== 200 || !is_array($result) || ($result['ok'] ?? false) !== true) {
        $db->exec('ROLLBACK');
        respond(502, ['ok' => false]);
    }

    $db->exec('COMMIT');
    respond(200, ['ok' => true, 'receiptId' => $receipt]);
} catch (Throwable $e) {
    respond(502, ['ok' => false]);
}
