<?php
/**
 * VetPet Care - Contact / Bulk Inquiry handler  (SMTP / guaranteed delivery)
 * ---------------------------------------------------------------------------
 * Sends form submissions through Gmail's SMTP server so mail reliably lands
 * in the inbox (not spam). No external library required - pure PHP sockets.
 *
 * SETUP (one time):
 *  1. The Gmail account below must have 2-Step Verification ON.
 *  2. Create an "App Password":  Google Account > Security > 2-Step
 *     Verification > App passwords > (App: Mail, Device: Other "Website").
 *     Google gives you a 16-character password like "abcd efgh ijkl mnop".
 *  3. Paste it into $SMTP_PASS below (spaces can stay or be removed).
 *  4. Upload this file next to index.html.
 *
 * SECURITY: this file holds a password. Keep it on the server only, never in
 * public Git. Most hosts also let you move the 4 SMTP_* values into a file
 * ABOVE the public_html folder and include() it - recommended if available.
 * ---------------------------------------------------------------------------
 */

// ---- SMTP settings --------------------------------------------------
$SMTP_HOST = 'smtp.hostinger.com';
$SMTP_PORT = 465;                       // 465 = SSL (recommended). 587 = STARTTLS.
$SMTP_USER = 'care@vetpetcare.in';   // the Gmail account that sends
$SMTP_PASS = 'Bni@2026#';    // <-- paste Gmail App Password here

// ---- Message settings -----------------------------------------------
$TO        = 'care@vetpetcare.in';   // where inquiries are delivered
$FROM      = 'care@vetpetcare.in';   // must equal $SMTP_USER for Gmail
$FROM_NAME = 'VetPet Care Website';
$SUBJECT_PREFIX = 'New Website Inquiry';
// ---------------------------------------------------------------------

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Method not allowed.']);
    exit;
}

// Spam honeypot: bots fill the hidden "website" field; humans leave it blank.
if (!empty($_POST['website'])) { echo json_encode(['ok' => true]); exit; }

function clean($v) {
    $v = isset($v) ? trim($v) : '';
    return str_replace(["\r", "\n", "%0a", "%0d"], ' ', $v);
}

$name    = clean($_POST['name']    ?? '');
$phone   = clean($_POST['phone']   ?? '');
$email   = clean($_POST['email']   ?? '');
$country = clean($_POST['country'] ?? '');
$type    = clean($_POST['type']    ?? 'General Enquiry');
$message = trim($_POST['message']  ?? '');
$message = str_replace(["\r\n", "\r"], "\n", $message);

$errors = [];
if ($name === '')    $errors[] = 'name';
if ($phone === '')   $errors[] = 'phone';
if ($message === '') $errors[] = 'message';
if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'email';
if ($errors) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'Please check the highlighted fields.', 'fields' => $errors]);
    exit;
}

// Build the email
$subject = $SUBJECT_PREFIX . ' - ' . $type . ' (' . $name . ')';
$body  = "New inquiry from the VetPet Care website\n";
$body .= "----------------------------------------\n\n";
$body .= "Name:          $name\n";
$body .= "Phone:         $phone\n";
$body .= "Email:         " . ($email !== '' ? $email : '-') . "\n";
$body .= "Country:       " . ($country !== '' ? $country : '-') . "\n";
$body .= "Inquiry Type:  $type\n\n";
$body .= "Message:\n$message\n\n";
$body .= "----------------------------------------\n";
$body .= "Sent: " . date('d M Y, H:i') . "\n";
if (!empty($_SERVER['REMOTE_ADDR'])) $body .= "IP:   " . $_SERVER['REMOTE_ADDR'] . "\n";

// Headers for the DATA section
$headers = [];
$headers[] = 'From: ' . mb_encode_mimeheader($FROM_NAME) . ' <' . $FROM . '>';
$headers[] = 'To: <' . $TO . '>';
$headers[] = ($email !== '')
    ? 'Reply-To: ' . mb_encode_mimeheader($name) . ' <' . $email . '>'
    : 'Reply-To: <' . $FROM . '>';
$headers[] = 'Subject: ' . mb_encode_mimeheader($subject);
$headers[] = 'Date: ' . date('r');
$headers[] = 'MIME-Version: 1.0';
$headers[] = 'Content-Type: text/plain; charset=UTF-8';
$headers[] = 'Content-Transfer-Encoding: 8bit';

list($sent, $err) = smtp_send($SMTP_HOST, $SMTP_PORT, $SMTP_USER, $SMTP_PASS, $FROM, $TO, $headers, $body);

if ($sent) {
    echo json_encode(['ok' => true]);
} else {
    http_response_code(500);
    // Log the real SMTP error for you; show a friendly message to the visitor.
    error_log('VetPet SMTP error: ' . $err);
    echo json_encode(['ok' => false, 'error' => 'Sorry, the message could not be sent. Please WhatsApp or call us instead.']);
}

/**
 * Minimal SMTP client over SSL/TLS (AUTH LOGIN). Returns [bool ok, string error].
 */
function smtp_send($host, $port, $user, $pass, $from, $to, array $headers, $body) {
    $transport = ($port == 465) ? "ssl://$host:$port" : "tcp://$host:$port";
    $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
    $fp = @stream_socket_client($transport, $errno, $errstr, 20, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) return [false, "Connect failed: $errstr ($errno)"];
    stream_set_timeout($fp, 20);

    // Read a (possibly multi-line) reply and check the expected code.
    $read = function () use ($fp) {
        $data = '';
        while (($line = fgets($fp, 515)) !== false) {
            $data .= $line;
            if (isset($line[3]) && $line[3] === ' ') break; // last line
        }
        return $data;
    };
    $cmd = function ($c) use ($fp) { fwrite($fp, $c . "\r\n"); };
    $expect = function ($resp, $code) { return substr($resp, 0, 3) === (string)$code; };

    $greet = $read();
    if (!$expect($greet, 220)) { fclose($fp); return [false, "Greeting: $greet"]; }

    $host_name = !empty($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost';
    $cmd("EHLO $host_name"); $r = $read();
    if (!$expect($r, 250)) { fclose($fp); return [false, "EHLO: $r"]; }

    // STARTTLS path for port 587
    if ($port == 587) {
        $cmd("STARTTLS"); $r = $read();
        if (!$expect($r, 220)) { fclose($fp); return [false, "STARTTLS: $r"]; }
        if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            fclose($fp); return [false, "TLS negotiation failed"];
        }
        $cmd("EHLO $host_name"); $r = $read();
        if (!$expect($r, 250)) { fclose($fp); return [false, "EHLO(TLS): $r"]; }
    }

    $cmd("AUTH LOGIN"); $r = $read();
    if (!$expect($r, 334)) { fclose($fp); return [false, "AUTH: $r"]; }
    $cmd(base64_encode($user)); $r = $read();
    if (!$expect($r, 334)) { fclose($fp); return [false, "User: $r"]; }
    $cmd(base64_encode($pass)); $r = $read();
    if (!$expect($r, 235)) { fclose($fp); return [false, "Auth rejected (check App Password): $r"]; }

    $cmd("MAIL FROM:<$from>"); $r = $read();
    if (!$expect($r, 250)) { fclose($fp); return [false, "MAIL FROM: $r"]; }
    $cmd("RCPT TO:<$to>"); $r = $read();
    if (!$expect($r, 250) && !$expect($r, 251)) { fclose($fp); return [false, "RCPT TO: $r"]; }
    $cmd("DATA"); $r = $read();
    if (!$expect($r, 354)) { fclose($fp); return [false, "DATA: $r"]; }

    // Body: join headers, blank line, then body. Dot-stuff lines starting with '.'
    $data = implode("\r\n", $headers) . "\r\n\r\n";
    $body = str_replace("\n", "\r\n", str_replace("\r\n", "\n", $body));
    $lines = explode("\r\n", $body);
    foreach ($lines as $line) {
        if (isset($line[0]) && $line[0] === '.') $line = '.' . $line;
        $data .= $line . "\r\n";
    }
    $data .= ".";                       // end-of-data terminator
    $cmd($data); $r = $read();
    if (!$expect($r, 250)) { fclose($fp); return [false, "Send: $r"]; }

    $cmd("QUIT"); fclose($fp);
    return [true, ''];
}
