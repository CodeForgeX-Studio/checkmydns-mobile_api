<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$target = isset($_POST['target']) ? trim($_POST['target']) : '';
$mode   = isset($_POST['mode']) ? trim($_POST['mode']) : 'auto';

if (empty($target)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing IP address or domain']);
    exit;
}

function is_ip($value) {
    return filter_var($value, FILTER_VALIDATE_IP) !== false;
}

function is_domain($value) {
    return (bool)preg_match('/^([a-z0-9-]+\.)+[a-z]{2,}$/i', $value);
}

$type = 'domain';

if ($mode === 'ip') {
    if (!is_ip($target)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid IP address']);
        exit;
    }
    $type = 'ip';
} elseif ($mode === 'domain') {
    if (!is_domain($target)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid domain']);
        exit;
    }
    $type = 'domain';
} else {
    if (is_ip($target)) {
        $type = 'ip';
    } elseif (is_domain($target)) {
        $type = 'domain';
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Input is neither a valid IP nor a valid domain']);
        exit;
    }
}

$ipToCheck = null;
$domainToCheck = null;

if ($type === 'ip') {
    $ipToCheck = $target;
    $domainToCheck = $target;
} else {
    $domainToCheck = $target;
    $resolvedIp = gethostbyname($target);
    if ($resolvedIp && $resolvedIp !== $target && is_ip($resolvedIp)) {
        $ipToCheck = $resolvedIp;
    }
}

include '../config/dnsbls.php';

function reverse_ip_for_dnsbl($ip) {
    $parts = explode('.', $ip);
    return implode('.', array_reverse($parts));
}

$results = [];
$listedCount = 0;
$totalLists = count($dnsbls);

foreach ($dnsbls as $dnsbl) {
    $queryHost = null;
    if ($ipToCheck) {
        $rev = reverse_ip_for_dnsbl($ipToCheck);
        $queryHost = $rev . '.' . $dnsbl['host'];
    } else {
        $queryHost = $domainToCheck . '.' . $dnsbl['host'];
    }

    $listed = false;
    $response = null;
    $reason = null;

    try {
        $records = @dns_get_record($queryHost, DNS_A + DNS_TXT);
        if (!empty($records)) {
            foreach ($records as $rec) {
                if (isset($rec['type']) && $rec['type'] === 'A' && isset($rec['ip'])) {
                    $listed = true;
                    $response = $rec['ip'];
                }
                if (isset($rec['type']) && $rec['type'] === 'TXT' && isset($rec['txt'])) {
                    $reason = $rec['txt'];
                }
            }
        }
    } catch (Exception $e) {
    }

    if ($listed) {
        $listedCount++;
    }

    $results[] = [
        'name'     => $dnsbl['name'],
        'host'     => $dnsbl['host'],
        'listed'   => $listed,
        'response' => $response,
        'reason'   => $reason,
        'list_url' => $dnsbl['info']
    ];
}

$output = [
    'checked_value' => $type === 'ip' ? $ipToCheck : $domainToCheck,
    'type'          => $type,
    'ip'            => $ipToCheck,
    'domain'        => $domainToCheck,
    'total_lists'   => $totalLists,
    'listed_count'  => $listedCount,
    'results'       => $results
];

echo json_encode($output, JSON_PRETTY_PRINT);