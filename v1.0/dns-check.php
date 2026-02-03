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
$recordType = isset($_POST['recordType']) ? strtoupper(trim($_POST['recordType'])) : '';

if (empty($domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing domain']);
    exit;
}

if (empty($recordType)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing record type']);
    exit;
}

$validRecordTypes = ['A', 'AAAA', 'MX', 'NS', 'PTR', 'CNAME', 'SOA', 'TXT', 'SRV', 'NAPTR', 'CAA', 'DS', 'DNSKEY'];
if (!in_array($recordType, $validRecordTypes)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid record type']);
    exit;
}

include '../config/dnsServers.php';

function checkDNS($domain, $recordType, $serverIp) {
    $result = [
        'dns_results' => [],
        'resolved' => false
    ];

    try {
        switch ($recordType) {
            case 'A':
                $records = @dns_get_record($domain, DNS_A);
                if ($records) {
                    foreach ($records as $record) {
                        $result['dns_results'][] = [
                            'type' => 'A',
                            'host' => $domain,
                            'ip' => $record['ip']
                        ];
                    }
                    $result['resolved'] = true;
                }
                break;

            case 'AAAA':
                $records = @dns_get_record($domain, DNS_AAAA);
                if ($records) {
                    foreach ($records as $record) {
                        $result['dns_results'][] = [
                            'type' => 'AAAA',
                            'host' => $domain,
                            'ipv6' => $record['ipv6']
                        ];
                    }
                    $result['resolved'] = true;
                }
                break;

            case 'MX':
                $records = @dns_get_record($domain, DNS_MX);
                if ($records) {
                    foreach ($records as $record) {
                        $result['dns_results'][] = [
                            'type' => 'MX',
                            'host' => $domain,
                            'target' => $record['target'],
                            'priority' => $record['pri']
                        ];
                    }
                    $result['resolved'] = true;
                }
                break;

            case 'NS':
                $records = @dns_get_record($domain, DNS_NS);
                if ($records) {
                    foreach ($records as $record) {
                        $result['dns_results'][] = [
                            'type' => 'NS',
                            'host' => $domain,
                            'ns_server' => $record['target']
                        ];
                    }
                    $result['resolved'] = true;
                }
                break;

            case 'TXT':
                $records = @dns_get_record($domain, DNS_TXT);
                if ($records) {
                    foreach ($records as $record) {
                        $result['dns_results'][] = [
                            'type' => 'TXT',
                            'host' => $domain,
                            'txt' => $record['txt']
                        ];
                    }
                    $result['resolved'] = true;
                }
                break;

            case 'CNAME':
                $records = @dns_get_record($domain, DNS_CNAME);
                if ($records) {
                    foreach ($records as $record) {
                        $result['dns_results'][] = [
                            'type' => 'CNAME',
                            'host' => $domain,
                            'cname' => $record['target']
                        ];
                    }
                    $result['resolved'] = true;
                }
                break;

            case 'SOA':
                $records = @dns_get_record($domain, DNS_SOA);
                if ($records && count($records) > 0) {
                    $result['dns_results'][] = [
                        'type' => 'SOA',
                        'host' => $domain,
                        'primary_name_server' => $records[0]['mname'],
                        'hostmaster' => $records[0]['rname']
                    ];
                    $result['resolved'] = true;
                }
                break;

            case 'PTR':
                $ip = @gethostbyname($domain);
                if ($ip !== $domain) {
                    $hostname = @gethostbyaddr($ip);
                    $result['dns_results'][] = [
                        'type' => 'PTR',
                        'host' => $domain,
                        'ptr' => $hostname !== $ip ? $hostname : 'No PTR record found'
                    ];
                    $result['resolved'] = $hostname !== $ip;
                } else {
                    $result['dns_results'][] = [
                        'error' => 'Unable to resolve domain to IP address'
                    ];
                }
                break;

            case 'SRV':
                $records = @dns_get_record($domain, DNS_SRV);
                if ($records) {
                    foreach ($records as $record) {
                        $result['dns_results'][] = [
                            'type' => 'SRV',
                            'host' => $domain,
                            'target' => $record['target'],
                            'port' => $record['port']
                        ];
                    }
                    $result['resolved'] = true;
                }
                break;

            case 'CAA':
                $records = @dns_get_record($domain, DNS_CAA);
                if ($records) {
                    foreach ($records as $record) {
                        $result['dns_results'][] = [
                            'type' => 'CAA',
                            'host' => $domain,
                            'flags' => $record['flags'],
                            'tag' => $record['tag'],
                            'value' => $record['value']
                        ];
                    }
                    $result['resolved'] = true;
                } else {
                    $result['dns_results'][] = [
                        'type' => 'CAA',
                        'host' => $domain,
                        'message' => 'No CAA records found'
                    ];
                }
                break;

            case 'NAPTR':
                $records = @dns_get_record($domain, DNS_NAPTR);
                if ($records) {
                    foreach ($records as $record) {
                        $result['dns_results'][] = [
                            'type' => 'NAPTR',
                            'host' => $domain,
                            'order' => $record['order'],
                            'preference' => $record['pref'],
                            'flags' => $record['flags'],
                            'service' => $record['services'],
                            'regexp' => $record['regex'],
                            'replacement' => $record['replacement']
                        ];
                    }
                    $result['resolved'] = true;
                }
                break;

            case 'DS':
            case 'DNSKEY':
                $cmd = escapeshellcmd("dig +short $recordType " . escapeshellarg($domain) . " @$serverIp +time=1 +tries=1");
                $output = shell_exec($cmd);
                if (!empty(trim($output))) {
                    $lines = explode("\n", trim($output));
                    foreach ($lines as $line) {
                        if (!empty($line)) {
                            $parts = explode(' ', $line);
                            if ($recordType === 'DS' && count($parts) >= 4) {
                                $result['dns_results'][] = [
                                    'type' => 'DS',
                                    'host' => $domain,
                                    'key_tag' => $parts[0],
                                    'algorithm' => $parts[1],
                                    'digest_type' => $parts[2],
                                    'digest' => $parts[3]
                                ];
                            } elseif ($recordType === 'DNSKEY' && count($parts) >= 4) {
                                $result['dns_results'][] = [
                                    'type' => 'DNSKEY',
                                    'host' => $domain,
                                    'flags' => $parts[0],
                                    'protocol' => $parts[1],
                                    'algorithm' => $parts[2],
                                    'public_key' => $parts[3]
                                ];
                            }
                        }
                    }
                    $result['resolved'] = count($result['dns_results']) > 0;
                } else {
                    $result['dns_results'][] = [
                        'type' => $recordType,
                        'host' => $domain,
                        'message' => "No $recordType records found"
                    ];
                }
                break;

            default:
                $result['dns_results'][] = ['error' => 'Unsupported record type'];
        }
    } catch (Exception $e) {
        $result['dns_results'][] = ['error' => 'DNS resolution failed'];
    }

    return $result;
}

$results = [];
$batchSize = 10;
$serverEntries = array_keys($dnsServers);

for ($i = 0; $i < count($serverEntries); $i += $batchSize) {
    $batch = array_slice($serverEntries, $i, $batchSize);
    
    foreach ($batch as $location) {
        $info = $dnsServers[$location];
        $dnsResult = checkDNS($domain, $recordType, $info['ip']);
        
        $results[] = [
            'location' => $location,
            'ip' => $info['ip'],
            'provider' => $info['provider'],
            'dns_results' => $dnsResult['dns_results'],
            'resolved' => $dnsResult['resolved']
        ];
    }
}

echo json_encode($results, JSON_PRETTY_PRINT);
?>