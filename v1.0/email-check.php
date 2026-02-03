<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$domain = isset($_POST['domain']) ? trim($_POST['domain']) : '';
$dkimSelector = isset($_POST['dkimSelector']) ? trim($_POST['dkimSelector']) : 'default';

if (empty($domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing domain']);
    exit;
}

$url = 'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/refs/heads/main/disposable_email_blocklist.conf';
$domains = file_get_contents($url);
$disposableDomains = explode("\n", $domains);
$disposableDomains = array_filter($disposableDomains, function($domain) {
    return !empty(trim($domain));
});

function isDisposableEmail($domain) {
    global $disposableDomains;
    return in_array(strtolower($domain), $disposableDomains);
}

function hasMXRecord($domain) {
    $records = @dns_get_record($domain, DNS_MX);
    return $records && count($records) > 0;
}

function validateSPF($domain) {
    $records = @dns_get_record($domain, DNS_TXT);
    if ($records) {
        foreach ($records as $record) {
            if (stripos($record['txt'], 'v=spf1') === 0) {
                return $record['txt'];
            }
        }
    }
    return 'SPF record missing';
}

function validateDMARC($domain) {
    $records = @dns_get_record('_dmarc.' . $domain, DNS_TXT);
    if ($records) {
        foreach ($records as $record) {
            if (stripos($record['txt'], 'v=DMARC1') === 0) {
                return $record['txt'];
            }
        }
    }
    return 'DMARC record missing';
}

function validateDKIM($domain, $selector) {
    if (empty($selector)) {
        return 'DKIM Selector is missing';
    }

    $dkimDomain = $selector . '._domainkey.' . $domain;
    $records = @dns_get_record($dkimDomain, DNS_TXT);
    
    if ($records && count($records) > 0) {
        return 'Valid DKIM record found for selector ' . $selector . ': ' . $records[0]['txt'];
    }
    
    return 'No valid DKIM record found for selector ' . $selector;
}

function validateMX($domain) {
    $records = @dns_get_record($domain, DNS_MX);
    
    if (!$records || count($records) === 0) {
        return 'No MX records found';
    }
    
    $results = [];
    foreach ($records as $record) {
        $results[] = $record['target'] . ' (priority ' . $record['pri'] . ')';
    }
    
    return implode(', ', $results);
}

function validatePTR($domain) {
    $ip = @gethostbyname($domain);
    
    if ($ip === $domain) {
        return 'No valid IP address found for domain';
    }
    
    $hostname = @gethostbyaddr($ip);
    
    if ($hostname && $hostname !== $ip) {
        return $hostname;
    }
    
    return 'No PTR record found';
}

function validateBIMI($domain) {
    $records = @dns_get_record('default._bimi.' . $domain, DNS_TXT);
    
    if ($records) {
        foreach ($records as $record) {
            if (stripos($record['txt'], 'v=BIMI1') === 0) {
                return $record['txt'];
            }
        }
    }
    
    return 'BIMI record missing or invalid';
}

function validateGoogleVerification($domain) {
    $records = @dns_get_record($domain, DNS_TXT);
    
    if ($records) {
        foreach ($records as $record) {
            if (stripos($record['txt'], 'google-site-verification=') === 0) {
                return 'Domain is verified by Google';
            }
        }
    }
    
    return 'Domain is not verified by Google';
}

$disposable = isDisposableEmail($domain);
$mxValid = hasMXRecord($domain);
$deliverable = $mxValid && !$disposable;

$spf = validateSPF($domain);
$dmarc = validateDMARC($domain);
$dkim = validateDKIM($domain, $dkimSelector);
$mx = validateMX($domain);
$ptr = validatePTR($domain);
$bimi = validateBIMI($domain);
$googleVerify = validateGoogleVerification($domain);

echo json_encode([
    'success' => true,
    'mxValid' => $mxValid,
    'disposable' => $disposable,
    'deliverable' => $deliverable,
    'spf' => $spf,
    'dmarc' => $dmarc,
    'dkim' => $dkim,
    'mx' => $mx,
    'ptr' => $ptr,
    'bimi' => $bimi,
    'google_verification' => $googleVerify
], JSON_PRETTY_PRINT);
?>