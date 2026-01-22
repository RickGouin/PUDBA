#!/usr/bin/env php
<?php
if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be run from the command line\n");
    exit(1);
}
require __DIR__ . '/helpers.php';

$cfg = pudba_load_config();

try {
    pudba_ensure_dirs($cfg);
} catch (Throwable $e) {
    fwrite(STDERR, "PUDBA cron error: " . $e->getMessage() . "\n");
    exit(1);
}

$options = getopt('', ['conn:', 'conn-ref:', 'job::', 'db::']);
$args = $GLOBALS['argv'] ?? [];

function pudba_cli_get_option_value(array $args, string $name): ?string {
    $count = count($args);
    for ($i = 0; $i < $count; $i++) {
        $arg = (string)$args[$i];
        if ($arg === $name) {
            $next = $args[$i + 1] ?? null;
            if ($next === null || str_starts_with((string)$next, '-')) {
                return null;
            }
            return (string)$next;
        }
        if (str_starts_with($arg, $name . '=')) {
            return substr($arg, strlen($name) + 1);
        }
    }
    return null;
}

$connKey = (string)($options['conn'] ?? '');
$connRef = (string)($options['conn-ref'] ?? '');
$jobValue = $options['job'] ?? null;
$jobName = trim((string)($jobValue ?? ''));
if ($jobName === '') {
    $jobOverride = pudba_cli_get_option_value($args, '--job');
    if ($jobOverride !== null) {
        $jobName = trim($jobOverride);
    }
}

$dbValue = $options['db'] ?? null;
$dbOverride = trim((string)($dbValue ?? ''));
if ($dbOverride === '') {
    $dbOverride = trim((string)(pudba_cli_get_option_value($args, '--db') ?? ''));
}

[$resolvedKey, $resolvedConn, $resolvedErr] = (function () use ($cfg, $connKey, $dbOverride): array {
    $resolved = pudba_resolve_connection($cfg, $connKey, $dbOverride);
    return [
        (string)($resolved['key'] ?? ''),
        $resolved['connection'] ?? null,
        $resolved['error'] ?? null,
    ];
})();

if ($connRef === '') {
    $connRef = (string)(pudba_cli_get_option_value($args, '--conn-ref') ?? '');
}

if ($connRef !== '') {
    $refResolved = pudba_resolve_connection_ref($cfg, $connRef);
    if (!empty($refResolved['connection'])) {
        $resolvedKey = (string)($refResolved['key'] ?? '');
        $resolvedConn = $refResolved['connection'];
        $resolvedErr = null;
    } elseif (!$resolvedConn) {
        $resolvedErr = $refResolved['error'] ?? 'invalid connection reference';
        $resolvedConn = null;
        $resolvedKey = '';
    }
}

if (!$resolvedConn) {
    fwrite(STDERR, "PUDBA cron error: invalid or missing connection reference/key.\n");
    exit(1);
}

$connKey = $resolvedKey;
$conn = $resolvedConn;

if ($dbOverride !== '') {
    try {
        $available = pudba_list_databases($conn);
    } catch (Throwable $e) {
        fwrite(STDERR, "PUDBA cron error: failed listing databases ({$e->getMessage()}).\n");
        exit(1);
    }
    if (!in_array($dbOverride, $available, true)) {
        fwrite(STDERR, "PUDBA cron error: invalid database selection.\n");
        exit(1);
    }
    $conn['db'] = $dbOverride;
}

if (empty($conn['db'])) {
    fwrite(STDERR, "PUDBA cron error: database selection is required.\n");
    exit(1);
}

try {
    $backup = pudba_execute_backup($cfg, $conn, $connKey, [], 'cron_backup');
    $result = $backup['result'];
    $filename = $backup['filename'];
    $outFile = $backup['out_file'];

    if ($result['ok'] && is_file($outFile) && filesize($outFile) > 0) {
        $label = $jobName !== '' ? "{$jobName}: " : '';
        fwrite(STDOUT, $label . "Backup created: {$filename}\n");
        exit(0);
    }

    $stderr = trim((string)($result['stderr'] ?? ''));
    fwrite(STDERR, "PUDBA cron backup failed (exit {$result['exit']}). {$stderr}\n");
    exit(1);
} catch (Throwable $e) {
    fwrite(STDERR, "PUDBA cron error: " . $e->getMessage() . "\n");
    exit(1);
}
