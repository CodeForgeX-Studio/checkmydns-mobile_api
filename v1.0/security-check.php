<?php
ini_set('display_errors', 0);
error_reporting(E_ALL);

header('Content-Type: application/json');
header('Access-Control-Allow-Origin', '*');
header('Access-Control-Allow-Methods', 'POST');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$domain = isset($_POST['domain']) ? trim($_POST['domain']) : '';
$dkimSelectorInput = isset($_POST['dkim_selector']) ? trim($_POST['dkim_selector']) : '';

if (empty($domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing domain']);
    exit;
}

$domain = preg_replace('#^https?://#i', '', $domain);
$domain = explode('/', $domain)[0];

if (!preg_match('/^([a-z0-9-]+\.)+[a-z]{2,}$/i', $domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid domain format']);
    exit;
}

include '../config/dnsServers.php';

function queryDnssecWithDig($domain, $type, $dnsServers, $maxServers = 5) {
    $results = [];
    if (!function_exists('shell_exec')) {
        return $results;
    }
    $count = 0;
    foreach ($dnsServers as $location => $info) {
        if ($count >= $maxServers) break;
        $serverIp = $info['ip'];
        $cmd = sprintf(
            'dig +short %s %s @%s +time=2 +tries=1',
            escapeshellarg($type),
            escapeshellarg($domain),
            escapeshellarg($serverIp)
        );
        $output = shell_exec($cmd);
        if (!empty($output)) {
            $lines = explode("\n", trim($output));
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '') continue;
                $results[] = [
                    'server'   => $location,
                    'ip'       => $serverIp,
                    'provider' => $info['provider'],
                    'line'     => $line
                ];
            }
        }
        $count++;
    }
    return $results;
}

function getParentDomain($domain) {
    $parts = explode('.', $domain);
    if (count($parts) > 2) {
        return implode('.', array_slice($parts, -2));
    }
    return $domain;
}

function domainSecurityCheck($domain, $dkimSelectorInput, $dnsServers) {
    $score = 0;
    $total = 0;
    $issues = [];
    $warnings = [];
    $improvements = [];
    $details = [];
    $parentDomain = getParentDomain($domain);

    $details['input_domain'] = $domain;
    $details['parent_domain'] = $parentDomain;
    $details['using_parent_fallback'] = false;

    $total += 30;

    $mxSub = @dns_get_record($domain, DNS_MX);
    $mxParent = ($parentDomain !== $domain) ? @dns_get_record($parentDomain, DNS_MX) : [];
    $mx = $mxSub;
    $mxFoundOn = $domain;
    $mxFallback = false;
    if (empty($mxSub) && !empty($mxParent)) {
        $mx = $mxParent;
        $mxFoundOn = $parentDomain;
        $mxFallback = true;
        $details['using_parent_fallback'] = true;
    }
    $details['MX'] = [
        'records' => $mx,
        'found_on' => !empty($mx) ? $mxFoundOn : null,
        'fallback_used' => $mxFallback
    ];
    if (!empty($mx)) {
        $score += 3;
    } else {
        $issues[] = 'No MX records found (email may be undeliverable).';
        $improvements[] = 'Add at least one MX record pointing to a valid mail server.';
    }

    $txtSub = @dns_get_record($domain, DNS_TXT);
    $txtParent = ($parentDomain !== $domain) ? @dns_get_record($parentDomain, DNS_TXT) : [];
    $spf = null;
    $spfFoundOn = null;
    $spfFallback = false;

    if (!empty($txtSub)) {
        foreach ($txtSub as $r) {
            $txtValue = $r['txt'] ?? '';
            if (stripos($txtValue, 'v=spf1') === 0) {
                $spf = $txtValue;
                $spfFoundOn = $domain;
                break;
            }
        }
    }
    if (!$spf && !empty($txtParent)) {
        foreach ($txtParent as $r) {
            $txtValue = $r['txt'] ?? '';
            if (stripos($txtValue, 'v=spf1') === 0) {
                $spf = $txtValue;
                $spfFoundOn = $parentDomain;
                $spfFallback = true;
                $details['using_parent_fallback'] = true;
                break;
            }
        }
    }

    if ($spf) {
        $score += 5;
        $spfMode = null;
        if (strpos($spf, '-all') !== false) {
            $spfMode = 'hardfail (-all)';
        } elseif (strpos($spf, '~all') !== false) {
            $spfMode = 'softfail (~all)';
        } elseif (strpos($spf, '?all') !== false) {
            $spfMode = 'neutral (?all)';
        } else {
            $spfMode = 'unknown';
        }
        $details['SPF'] = [
            'value' => $spf,
            'mode' => $spfMode,
            'found_on' => $spfFoundOn,
            'fallback_used' => $spfFallback
        ];
        if ($spfMode === 'softfail (~all)' || $spfMode === 'neutral (?all)' || $spfMode === 'unknown') {
            $improvements[] = 'Tighten SPF policy to use "-all" after confirming all legitimate senders are included.';
        }
    } else {
        $details['SPF'] = null;
        $issues[] = 'No SPF record detected (higher email spoofing risk).';
        $improvements[] = 'Add an SPF record (v=spf1 ...) that includes all legitimate mail servers and ends with "-all".';
    }

    $dmarcVal = '';
    $dmarcFoundOn = null;
    $dmarcFallback = false;
    $dmarcSub = @dns_get_record('_dmarc.' . $domain, DNS_TXT);
    if (!empty($dmarcSub)) {
        $dmarcVal = $dmarcSub[0]['txt'] ?? '';
        $dmarcFoundOn = $domain;
    } elseif ($parentDomain !== $domain) {
        $dmarcParent = @dns_get_record('_dmarc.' . $parentDomain, DNS_TXT);
        if (!empty($dmarcParent)) {
            $dmarcVal = $dmarcParent[0]['txt'] ?? '';
            $dmarcFoundOn = $parentDomain;
            $dmarcFallback = true;
            $details['using_parent_fallback'] = true;
        }
    }

    if ($dmarcVal && stripos($dmarcVal, 'v=DMARC1') === 0) {
        $score += 10;
        $parsed = [
            'value' => $dmarcVal,
            'found_on' => $dmarcFoundOn,
            'fallback_used' => $dmarcFallback
        ];
        $tags = explode(';', $dmarcVal);
        foreach ($tags as $tag) {
            $tag = trim($tag);
            if ($tag === '') continue;
            $parts = explode('=', $tag, 2);
            if (count($parts) !== 2) continue;
            $k = trim($parts[0]);
            $v = trim($parts[1]);
            if ($k === 'p') $parsed['policy'] = $v;
            if ($k === 'sp') $parsed['subdomain_policy'] = $v;
            if ($k === 'rua') $parsed['rua'] = $v;
            if ($k === 'ruf') $parsed['ruf'] = $v;
        }
        $details['DMARC'] = $parsed;
        if (empty($parsed['policy']) || $parsed['policy'] === 'none') {
            $improvements[] = 'Change DMARC policy from "none" to "quarantine" or "reject" once you are comfortable with the reports.';
        }
        if (empty($parsed['rua'])) {
            $improvements[] = 'Add a "rua" tag to DMARC so you receive aggregate reports (e.g. rua=mailto:dmarc@yourdomain.com).';
        }
    } else {
        $details['DMARC'] = null;
        $issues[] = 'No DMARC record found (enable DMARC with p=quarantine or p=reject).';
        $improvements[] = 'Add a DMARC record like: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com;';
    }

    $autoSelectors = ['default', 'google', 'selector1', 'mail', 's1', 's2', 'x', 'spacemail'];
    if ($dkimSelectorInput !== '') {
        array_unshift($autoSelectors, $dkimSelectorInput);
        $autoSelectors = array_values(array_unique($autoSelectors));
    }

    $dkim = false;
    $dkimSelectorUsed = null;
    $dkimFoundOn = null;
    $dkimFallback = false;

    foreach ($autoSelectors as $sel) {
        $dkim_rec_sub = @dns_get_record("{$sel}._domainkey.{$domain}", DNS_TXT);
        if (!empty($dkim_rec_sub)) {
            $dkim = true;
            $dkimSelectorUsed = $sel;
            $dkimFoundOn = $domain;
            break;
        }
    }

    if (!$dkim && $parentDomain !== $domain) {
        foreach ($autoSelectors as $sel) {
            $dkim_rec_parent = @dns_get_record("{$sel}._domainkey.{$parentDomain}", DNS_TXT);
            if (!empty($dkim_rec_parent)) {
                $dkim = true;
                $dkimSelectorUsed = $sel;
                $dkimFoundOn = $parentDomain;
                $dkimFallback = true;
                $details['using_parent_fallback'] = true;
                break;
            }
        }
    }

    if ($dkim) {
        $score += 7;
        $details['DKIM'] = [
            'selector_used' => $dkimSelectorUsed,
            'found_on' => $dkimFoundOn,
            'fallback_used' => $dkimFallback,
            'status' => 'found'
        ];
    } else {
        $details['DKIM'] = null;
        $issues[] = 'No DKIM record detected for tested selectors.';
        $improvements[] = 'Check your mail provider documentation for the correct DKIM selector and add the corresponding TXT record under selector._domainkey.' . $domain . '.';
    }

    $bimiVal = null;
    $bimiFoundOn = null;
    $bimiFallback = false;
    $bimiSub = @dns_get_record("default._bimi.{$domain}", DNS_TXT);
    if (!empty($bimiSub)) {
        $bimiVal = $bimiSub[0]['txt'] ?? '';
        $bimiFoundOn = $domain;
    } elseif ($parentDomain !== $domain) {
        $bimiParent = @dns_get_record("default._bimi.{$parentDomain}", DNS_TXT);
        if (!empty($bimiParent)) {
            $bimiVal = $bimiParent[0]['txt'] ?? '';
            $bimiFoundOn = $parentDomain;
            $bimiFallback = true;
            $details['using_parent_fallback'] = true;
        }
    }
    if ($bimiVal) {
        $score += 5;
        $details['BIMI'] = [
            'value' => $bimiVal,
            'found_on' => $bimiFoundOn,
            'fallback_used' => $bimiFallback
        ];
    } else {
        $details['BIMI'] = null;
        $warnings[] = 'BIMI is not configured.';
        $improvements[] = 'Configure BIMI (default._bimi.' . $parentDomain . ') with an SVG logo and ensure a strong DMARC policy (p=quarantine or reject).';
    }

    $total += 30;
    $cert = getSSLCert($domain);
    if ($cert) {
        $expiry_days = ($cert['validTo_time_t'] - time()) / (24*3600);
        $cert['expiry_days'] = $expiry_days;
        if (isset($cert['extensions']['subjectAltName'])) {
            $sanStr = $cert['extensions']['subjectAltName'];
            $parts = explode(',', $sanStr);
            $altnames = [];
            foreach ($parts as $p) {
                $p = trim($p);
                if (stripos($p, 'DNS:') === 0) {
                    $altnames[] = trim(substr($p, 4));
                }
            }
            $cert['altnames'] = $altnames;
        }
        $details['SSL'] = $cert;
        if ($expiry_days > 30) {
            $score += 15;
        } else {
            $issues[] = 'SSL certificate is expiring within 30 days. Renew as soon as possible.';
            $improvements[] = 'Renew your SSL certificate before it expires to avoid browser warnings.';
        }
        $score += 10;
    } else {
        $details['SSL'] = null;
        $issues[] = 'No valid SSL certificate detected (risk of man-in-the-middle attacks).';
        $improvements[] = 'Install a valid SSL certificate (e.g. via Let\'s Encrypt) on your web server.';
    }

    $headers = getHeaders("https://{$domain}");
    if ($headers && stripos($headers, 'Strict-Transport-Security') !== false) {
        if (stripos($headers, 'preload') !== false) {
            $score += 5;
            $details['HSTS'] = 'Preload-ready';
        } else {
            $warnings[] = 'HSTS enabled but not using preload.';
            $improvements[] = 'Update HSTS header to include "preload" and submit your domain to the browser preload lists.';
            $details['HSTS'] = 'Enabled (no preload)';
        }
    } else {
        $details['HSTS'] = null;
        $warnings[] = 'HSTS is not enabled.';
        $improvements[] = 'Enable HSTS with: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload';
    }

    $total += 25;

    $dsResults     = queryDnssecWithDig($domain, 'DS', $dnsServers);
    $dnskeyResults = queryDnssecWithDig($domain, 'DNSKEY', $dnsServers);

    $dnssecStatus = null;
    $dnssecFor = null;
    $dnssecFallback = false;

    if (!empty($dsResults) || !empty($dnskeyResults)) {
        $dnssecStatus = 'Enabled';
        $dnssecFor = $domain;
    } elseif ($parentDomain !== $domain) {
        $dsParent     = queryDnssecWithDig($parentDomain, 'DS', $dnsServers);
        $dnskeyParent = queryDnssecWithDig($parentDomain, 'DNSKEY', $dnsServers);
        if (!empty($dsParent) || !empty($dnskeyParent)) {
            $dnssecStatus = 'Enabled (parent domain)';
            $dnssecFor = $parentDomain;
            $dsResults = $dsParent;
            $dnskeyResults = $dnskeyParent;
            $dnssecFallback = true;
            $details['using_parent_fallback'] = true;
        }
    }

    if ($dnssecStatus) {
        $score += 20;
        $details['DNSSEC'] = [
            'status' => $dnssecStatus,
            'applies_to' => $dnssecFor,
            'fallback_used' => $dnssecFallback,
            'ds'     => $dsResults,
            'dnskey' => $dnskeyResults
        ];
    } else {
        $details['DNSSEC'] = null;
        $issues[] = 'DNSSEC could not be detected from the tested resolvers.';
        $improvements[] = 'If DNSSEC is enabled, allow some time for DS records to propagate or verify using your registrar\'s control panel.';
    }

    $caa = [];
    $caaFoundOn = null;
    $caaFallback = false;
    if (defined('DNS_CAA')) {
        $caaSub = @dns_get_record($domain, DNS_CAA);
        if (!empty($caaSub)) {
            $caa = $caaSub;
            $caaFoundOn = $domain;
        } elseif ($parentDomain !== $domain) {
            $caaParent = @dns_get_record($parentDomain, DNS_CAA);
            if (!empty($caaParent)) {
                $caa = $caaParent;
                $caaFoundOn = $parentDomain;
                $caaFallback = true;
                $details['using_parent_fallback'] = true;
            }
        }
    }
    if (!empty($caa)) {
        $score += 5;
        $details['CAA'] = [
            'value' => 'Present (restricts certificate authorities).',
            'found_on' => $caaFoundOn,
            'fallback_used' => $caaFallback
        ];
    } else {
        $details['CAA'] = null;
        $warnings[] = 'No CAA records found.';
        $improvements[] = 'Add CAA records to restrict which certificate authorities may issue certificates for your domain.';
    }

    $total += 15;

    $mta_sts = [];
    $mtaStsFoundOn = null;
    $mtaStsFallback = false;
    $mtaSub = @dns_get_record('_mta-sts.' . $domain, DNS_TXT);
    if (!empty($mtaSub)) {
        $mta_sts = $mtaSub;
        $mtaStsFoundOn = $domain;
    } elseif ($parentDomain !== $domain) {
        $mtaParent = @dns_get_record('_mta-sts.' . $parentDomain, DNS_TXT);
        if (!empty($mtaParent)) {
            $mta_sts = $mtaParent;
            $mtaStsFoundOn = $parentDomain;
            $mtaStsFallback = true;
            $details['using_parent_fallback'] = true;
        }
    }
    if (!empty($mta_sts)) {
        $score += 7;
        $details['MTA_STS'] = [
            'value' => 'Present',
            'found_on' => $mtaStsFoundOn,
            'fallback_used' => $mtaStsFallback
        ];
    } else {
        $details['MTA_STS'] = null;
        $warnings[] = 'MTA-STS is not configured.';
        $improvements[] = 'Publish an _mta-sts.' . $parentDomain . ' TXT record and host an MTA-STS policy file over HTTPS.';
    }

    $tls_rpt = [];
    $tlsRptFoundOn = null;
    $tlsRptFallback = false;
    $tlsSub = @dns_get_record('_smtp._tls.' . $domain, DNS_TXT);
    if (!empty($tlsSub)) {
        $tls_rpt = $tlsSub;
        $tlsRptFoundOn = $domain;
    } elseif ($parentDomain !== $domain) {
        $tlsParent = @dns_get_record('_smtp._tls.' . $parentDomain, DNS_TXT);
        if (!empty($tlsParent)) {
            $tls_rpt = $tlsParent;
            $tlsRptFoundOn = $parentDomain;
            $tlsRptFallback = true;
            $details['using_parent_fallback'] = true;
        }
    }
    if (!empty($tls_rpt)) {
        $score += 8;
        $details['TLS_RPT'] = [
            'value' => 'Present',
            'found_on' => $tlsRptFoundOn,
            'fallback_used' => $tlsRptFallback
        ];
    } else {
        $details['TLS_RPT'] = null;
        $warnings[] = 'TLS-RPT is not configured.';
        $improvements[] = 'Add a _smtp._tls.' . $parentDomain . ' TXT record to receive reports about TLS issues for your mail.';
    }

    $percentage = $total > 0 ? round(($score / $total) * 100) : 0;
    $level = $percentage >= 85 ? 'High' : ($percentage >= 60 ? 'Medium' : 'Low');

    return [
        'percentage'   => $percentage,
        'level'        => $level,
        'issues'       => $issues,
        'warnings'     => $warnings,
        'improvements' => $improvements,
        'details'      => $details
    ];
}

function getSSLCert($domain) {
    if (!function_exists('stream_socket_client') || !function_exists('openssl_x509_parse')) {
        return false;
    }

    $context = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'verify_peer' => false,
            'verify_peer_name' => false
        ]
    ]);

    $stream = @stream_socket_client(
        "ssl://{$domain}:443",
        $errno,
        $errstr,
        15,
        STREAM_CLIENT_CONNECT,
        $context
    );

    if (!$stream) {
        return false;
    }

    $params = stream_context_get_params($stream);
    fclose($stream);

    if (!isset($params['options']['ssl']['peer_certificate'])) {
        return false;
    }

    $cert = @openssl_x509_parse($params['options']['ssl']['peer_certificate']);
    if (!$cert) {
        return false;
    }

    $cert['issuer'] = $cert['issuer']['CN'] ?? 'Unknown';

    return $cert;
}

function getHeaders($url) {
    if (!function_exists('curl_init')) {
        return '';
    }

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $response = curl_exec($ch);
    curl_close($ch);

    return $response ?: '';
}

$result = domainSecurityCheck($domain, $dkimSelectorInput, $dnsServers);
echo json_encode($result, JSON_PRETTY_PRINT);