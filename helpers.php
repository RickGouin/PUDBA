<?php

function pudba_config_path(): string {
    return __DIR__ . '/config.php';
}

function pudba_load_config(): array {
    $cfg = require pudba_config_path();
    if (!is_array($cfg)) {
        throw new RuntimeException("config.php did not return an array.");
    }
    return $cfg;
}

function pudba_save_config(array $cfg): void {
    $path = pudba_config_path();
    $export = var_export($cfg, true);
    $php = "<?php\n/**\n * PUDBA config (auto-written)\n */\n\n\$CONFIG = {$export};\n\nreturn \$CONFIG;\n";
    $tmp = $path . '.tmp';
    if (file_put_contents($tmp, $php, LOCK_EX) === false) {
        throw new RuntimeException("Failed writing temporary config file: {$tmp}");
    }
    if (!@rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException("Failed replacing config.php. Check file permissions.");
    }
    if (function_exists('opcache_invalidate')) {
        @opcache_invalidate($path, true);
    }
}

function pudba_h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function pudba_start_session(): void {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        // Reasonable defaults for a simple internal tool
        ini_set('session.use_strict_mode', '1');
        session_name('PUDBA');
        $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        session_set_cookie_params([
            'httponly' => true,
            'secure' => $https,
            'samesite' => 'Lax',
        ]);
        session_start();
    }
}

function pudba_logout(): void {
    pudba_start_session();
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();
    session_start();
    session_regenerate_id(true);
    $_SESSION = [];
}

function pudba_set_flash(string $type, string $message, array $details = []): void {
    pudba_start_session();
    $_SESSION['flash'] = [
        'type' => $type,
        'message' => $message,
        'details' => $details,
    ];
}

function pudba_get_flash(): ?array {
    pudba_start_session();
    if (!isset($_SESSION['flash'])) return null;
    $f = $_SESSION['flash'];
    unset($_SESSION['flash']);
    return $f;
}

function pudba_ensure_dirs(array $cfg): void {
    $dirs = [
        $cfg['data_dir'] ?? (__DIR__ . '/data'),
        $cfg['backup_dir'] ?? (__DIR__ . '/data/backups'),
        $cfg['log_dir'] ?? (__DIR__ . '/data/logs'),
    ];
    foreach ($dirs as $d) {
        if (!is_dir($d)) {
            if (!@mkdir($d, 0775, true)) {
                throw new RuntimeException("Failed to create directory: {$d}");
            }
        }
        if (!is_writable($d)) {
            throw new RuntimeException("Directory not writable: {$d}");
        }
    }
}

/**
 * Returns full path for DB backup folder: backup_dir/DBNAME/
 */
function pudba_db_backup_dir(array $cfg, string $dbName): string {
    $base = rtrim($cfg['backup_dir'], '/');
    $safeDb = preg_replace('/[^A-Za-z0-9_\-]/', '_', $dbName);
    return $base . '/' . $safeDb;
}

function pudba_ensure_db_backup_dir(array $cfg, string $dbName): string {
    $dir = pudba_db_backup_dir($cfg, $dbName);
    if (!is_dir($dir)) {
        if (!@mkdir($dir, 0775, true)) {
            throw new RuntimeException("Failed to create DB backup directory: {$dir}");
        }
    }
    if (!is_writable($dir)) {
        throw new RuntimeException("DB backup directory not writable: {$dir}");
    }
    return $dir;
}

function pudba_prune_backups(array $cfg): int {
    $days = (int)($cfg['retention_days'] ?? 0);
    if ($days <= 0) {
        return 0;
    }

    $base = rtrim((string)($cfg['backup_dir'] ?? ''), '/');
    if ($base === '' || !is_dir($base)) {
        return 0;
    }

    $cutoff = time() - ($days * 86400);
    $deleted = 0;
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($it as $finfo) {
        /** @var SplFileInfo $finfo */
        if (!$finfo->isFile()) continue;
        $name = $finfo->getFilename();
        if (!preg_match('/\.sql(\.gz)?$/', $name)) continue;
        if ($finfo->getMTime() >= $cutoff) continue;
        $path = $finfo->getRealPath();
        if ($path && @unlink($path)) {
            $deleted++;
        }
    }

    return $deleted;
}

/**
 * Finds first existing binary from candidates using `command -v`.
 */
function pudba_find_binary(array $candidates): ?string {
    foreach ($candidates as $bin) {
        $bin = trim($bin);
        if ($bin === '') continue;
        // Use "command -v" (POSIX). Works on typical LAMP.
        $out = @shell_exec('command -v ' . escapeshellarg($bin) . ' 2>/dev/null');
        if (is_string($out)) {
            $path = trim($out);
            if ($path !== '') return $bin; // return name; rely on PATH
        }
    }
    return null;
}

/**
 * Finds the newest PHP CLI binary on PATH.
 */
function pudba_find_php_cli(): array {
    $errors = [];
    $candidates = pudba_collect_php_cli_candidates();
    if (!$candidates) {
        $path = getenv('PATH') ?: '';
        return [
            'bin' => null,
            'version' => null,
            'errors' => ["No PHP binaries found on PATH ({$path}). Install php-cli and ensure PATH is set."],
        ];
    }

    $best = null;
    $bestVersion = null;
    foreach ($candidates as $bin) {
        $probe = pudba_probe_php_cli($bin);
        if (!$probe['ok']) {
            $errors[] = $probe['error'];
            continue;
        }
        $version = $probe['version'];
        if ($best === null || version_compare($version, $bestVersion, '>')) {
            $best = $bin;
            $bestVersion = $version;
        }
    }

    if ($best === null) {
        $errors[] = 'No PHP CLI binaries were usable. Ensure php-cli is installed and that the CLI binary is on PATH.';
    }

    return [
        'bin' => $best,
        'version' => $bestVersion,
        'errors' => $errors,
    ];
}

function pudba_collect_php_cli_candidates(): array {
    $bins = [];
    $path = getenv('PATH') ?: '';
    foreach (explode(PATH_SEPARATOR, $path) as $dir) {
        $dir = trim($dir);
        if ($dir === '' || !is_dir($dir)) {
            continue;
        }
        foreach (glob($dir . '/php*') ?: [] as $file) {
            $base = basename($file);
            if (!preg_match('/^php(?:[0-9]+(?:\\.[0-9]+)*)?$/', $base)) {
                continue;
            }
            if (!is_file($file) || !is_executable($file)) {
                continue;
            }
            $real = realpath($file) ?: $file;
            $bins[$real] = $real;
        }
    }

    $phpBinary = defined('PHP_BINARY') ? PHP_BINARY : '';
    if ($phpBinary && is_file($phpBinary) && is_executable($phpBinary)) {
        $real = realpath($phpBinary) ?: $phpBinary;
        $bins[$real] = $real;
    }

    return array_values($bins);
}

function pudba_probe_php_cli(string $bin): array {
    $sapiResult = pudba_proc_open_argv([$bin, '-r', 'echo PHP_SAPI;']);
    if ($sapiResult['exit_code'] !== 0) {
        return [
            'ok' => false,
            'error' => "PHP binary {$bin} failed to run CLI check.",
        ];
    }
    $sapi = trim($sapiResult['stdout']);
    if ($sapi !== 'cli') {
        return [
            'ok' => false,
            'error' => "PHP binary {$bin} is not CLI (reported {$sapi}).",
        ];
    }

    $versionResult = pudba_proc_open_argv([$bin, '-r', 'echo PHP_VERSION;']);
    if ($versionResult['exit_code'] !== 0) {
        return [
            'ok' => false,
            'error' => "PHP CLI {$bin} failed to report its version.",
        ];
    }
    $version = trim($versionResult['stdout']);
    if ($version === '') {
        return [
            'ok' => false,
            'error' => "PHP CLI {$bin} reported an empty version string.",
        ];
    }

    return [
        'ok' => true,
        'version' => $version,
    ];
}

function pudba_has_gzip(): bool {
    return pudba_find_binary(['gzip']) !== null;
}

function pudba_has_gunzip(): bool {
    // gunzip is usually provided by gzip package; also allow "gzip -dc"
    return pudba_find_binary(['gunzip', 'gzip']) !== null;
}

/**
 * Masks the password in a command string for display.
 * We intentionally pass password via env var MYSQL_PWD (preferred) to avoid showing in args.
 * Still mask just in case.
 */
function pudba_mask_command(string $cmd): string {
    // Mask MYSQL_PWD=...
    $cmd = preg_replace('/MYSQL_PWD=([^\s]+)/', 'MYSQL_PWD=********', $cmd);
    // Mask --password=... or -p...
    $cmd = preg_replace('/--password=([^\s]+)/', '--password=********', $cmd);
    $cmd = preg_replace('/\s-p([^\s]+)/', ' -p********', $cmd);
    return $cmd;
}

/**
 * Basic safe key/identifier checks (for config connection keys and table names).
 */
function pudba_is_safe_key(string $s): bool {
    return (bool)preg_match('/^[A-Za-z0-9_\-]+$/', $s);
}

function pudba_is_safe_table(string $s): bool {
    // allow db.table? but we mostly use table names from information_schema, so keep tight
    return (bool)preg_match('/^[A-Za-z0-9_\$]+$/', $s);
}

function pudba_cron_job_suffix(): string {
    return '_PUDBA';
}

function pudba_strip_cron_job_suffix(string $name): string {
    $suffix = pudba_cron_job_suffix();
    if ($suffix !== '' && str_ends_with($name, $suffix)) {
        return substr($name, 0, -strlen($suffix));
    }
    return $name;
}

function pudba_normalize_cron_job_name(string $name): string {
    $name = trim($name);
    if ($name === '') return '';
    $suffix = pudba_cron_job_suffix();
    if (!str_ends_with($name, $suffix)) {
        $name .= $suffix;
    }
    return $name;
}

/**
 * Connect via mysqli.
 */
function pudba_mysqli(array $conn): mysqli {
    $host = (string)($conn['host'] ?? '127.0.0.1');
    $port = (int)($conn['port'] ?? 3306);
    $user = (string)($conn['user'] ?? '');
    $pass = (string)($conn['pass'] ?? '');
    $db   = (string)($conn['db'] ?? '');

    mysqli_report(MYSQLI_REPORT_OFF);
    $mysqli = @new mysqli($host, $user, $pass, $db, $port);
    if ($mysqli->connect_errno) {
        throw new RuntimeException("MySQL connect failed: " . $mysqli->connect_error);
    }
    $charset = (string)($conn['charset'] ?? 'utf8mb4');
    @$mysqli->set_charset($charset);
    return $mysqli;
}

function pudba_detect_server_flavor(array $conn): string {
    try {
        $mysqli = pudba_mysqli($conn);
        $res = $mysqli->query("SELECT VERSION() AS version, @@version_comment AS version_comment");
        $row = $res ? $res->fetch_assoc() : null;
        $mysqli->close();
    } catch (Throwable $e) {
        return 'unknown';
    }

    $version = (string)($row['version'] ?? '');
    $comment = (string)($row['version_comment'] ?? '');
    $haystack = $version . ' ' . $comment;

    if (stripos($haystack, 'mariadb') !== false) {
        return 'mariadb';
    }

    if ($haystack !== '') {
        return 'mysql';
    }

    return 'unknown';
}

function pudba_test_connection(array $conn): array {
    try {
        $mysqli = pudba_mysqli($conn);
        $res = $mysqli->query("SELECT NOW() AS now_time");
        $row = $res ? $res->fetch_assoc() : null;
        $mysqli->close();
        return ['ok' => true, 'message' => 'Connection OK', 'now' => $row['now_time'] ?? null];
    } catch (Throwable $e) {
        return ['ok' => false, 'message' => $e->getMessage()];
    }
}

function pudba_list_tables(array $conn): array {
    $mysqli = pudba_mysqli($conn);
    $db = $mysqli->real_escape_string((string)$conn['db']);
    $sql = "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='{$db}' ORDER BY TABLE_NAME";
    $res = $mysqli->query($sql);
    if (!$res) {
        $err = $mysqli->error;
        $mysqli->close();
        throw new RuntimeException("Failed listing tables: {$err}");
    }
    $tables = [];
    while ($row = $res->fetch_assoc()) {
        $tables[] = $row['TABLE_NAME'];
    }
    $mysqli->close();
    return $tables;
}

function pudba_is_system_database(string $dbName): bool {
    $dbName = strtolower($dbName);
    $system = [
        'information_schema',
        'performance_schema',
        'mysql',
        'sys',
        'mariadb',
    ];
    return in_array($dbName, $system, true);
}

function pudba_list_databases(array $conn): array {
    $mysqli = pudba_mysqli($conn);
    $res = $mysqli->query("SHOW DATABASES");
    if (!$res) {
        $err = $mysqli->error;
        $mysqli->close();
        throw new RuntimeException("Failed listing databases: {$err}");
    }
    $dbs = [];
    while ($row = $res->fetch_assoc()) {
        $name = (string)($row['Database'] ?? '');
        if ($name === '' || pudba_is_system_database($name)) {
            continue;
        }
        $dbs[] = $name;
    }
    $mysqli->close();
    sort($dbs, SORT_NATURAL | SORT_FLAG_CASE);
    return $dbs;
}

function pudba_now_utc_stamp(): string {
    // Example: 20260108T153012Z
    return gmdate('Ymd\THis\Z');
}

function pudba_generate_connection_id(): string {
    return bin2hex(random_bytes(4));
}

function pudba_connection_key(string $host, string $db, string $id): string {
    $keyDb = $db !== '' ? $db : 'server';
    return $host . '-' . $keyDb . '-' . $id;
}

function pudba_connection_ref(string $host, int $port, string $db): string {
    $host = strtolower(trim($host));
    $db = trim($db);
    $port = $port > 0 ? $port : 3306;
    $payload = json_encode(
        ['host' => $host, 'port' => $port, 'db' => $db],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
    $encoded = rtrim(strtr(base64_encode((string)$payload), '+/', '-_'), '=');
    return 'r1_' . $encoded;
}

function pudba_parse_connection_ref(string $ref): ?array {
    $ref = trim($ref);
    if ($ref === '' || !str_starts_with($ref, 'r1_')) {
        return null;
    }
    $encoded = substr($ref, 3);
    $padded = strtr($encoded, '-_', '+/');
    $padLen = strlen($padded) % 4;
    if ($padLen !== 0) {
        $padded .= str_repeat('=', 4 - $padLen);
    }
    $decoded = base64_decode($padded, true);
    if ($decoded === false) {
        return null;
    }
    $data = json_decode($decoded, true);
    if (!is_array($data)) {
        return null;
    }
    $host = trim((string)($data['host'] ?? ''));
    $db = trim((string)($data['db'] ?? ''));
    $port = (int)($data['port'] ?? 0);
    if ($host === '' && $db === '' && $port === 0) {
        return null;
    }
    if ($port <= 0) {
        $port = 3306;
    }
    return ['host' => $host, 'port' => $port, 'db' => $db];
}

function pudba_resolve_connection_ref(array $cfg, string $connRef): array {
    $connections = (array)($cfg['connections'] ?? []);
    if ($connRef === '') {
        return [
            'key' => '',
            'connection' => null,
            'error' => 'missing connection reference',
        ];
    }
    foreach ($connections as $key => $conn) {
        $ref = pudba_connection_ref(
            (string)($conn['host'] ?? ''),
            (int)($conn['port'] ?? 3306),
            (string)($conn['db'] ?? '')
        );
        if ($ref === $connRef) {
            return [
                'key' => (string)$key,
                'connection' => $conn,
            ];
        }
    }

    $parsed = pudba_parse_connection_ref($connRef);
    if ($parsed) {
        $refHost = strtolower(trim((string)($parsed['host'] ?? '')));
        $refPort = (int)($parsed['port'] ?? 3306);
        $refDb = trim((string)($parsed['db'] ?? ''));

        $hostMatches = [];
        foreach ($connections as $key => $conn) {
            $host = strtolower(trim((string)($conn['host'] ?? '')));
            $port = (int)($conn['port'] ?? 3306);
            if ($host === $refHost && $port === $refPort) {
                $hostMatches[$key] = $conn;
            }
        }

        if ($refDb !== '') {
            foreach ($hostMatches as $key => $conn) {
                $connDb = trim((string)($conn['db'] ?? ''));
                if ($connDb === $refDb) {
                    return [
                        'key' => (string)$key,
                        'connection' => $conn,
                    ];
                }
            }
        }

        if (count($hostMatches) === 1) {
            $key = array_key_first($hostMatches);
            $conn = $hostMatches[$key];
            if ($refDb !== '') {
                $conn['db'] = $refDb;
            }
            return [
                'key' => (string)$key,
                'connection' => $conn,
            ];
        }

        if (count($hostMatches) > 1) {
            return [
                'key' => '',
                'connection' => null,
                'error' => 'ambiguous connection reference',
            ];
        }
    }

    return [
        'key' => '',
        'connection' => null,
        'error' => 'invalid connection reference',
    ];
}

function pudba_resolve_connection(array $cfg, string $connKey, string $dbOverride = ''): array {
    $connections = (array)($cfg['connections'] ?? []);
    if ($connKey !== '' && isset($connections[$connKey])) {
        return [
            'key' => $connKey,
            'connection' => $connections[$connKey],
        ];
    }

    if ($connKey === '') {
        return [
            'key' => '',
            'connection' => null,
            'error' => 'missing connection key',
        ];
    }

    return [
        'key' => '',
        'connection' => null,
        'error' => 'invalid connection key',
    ];
}

/**
 * Deterministic filename format:
 * 20260108T153012Z__r1_abcd123__ALL.sql
 * 20260108T153012Z__r1_abcd123__tables__users,orders.sql
 *
 * If gz enabled, ends with .sql.gz
 */
function pudba_build_backup_filename(string $ts, string $connRef, ?array $tables, bool $compressed): string {
    $safeConn = preg_replace('/[^A-Za-z0-9_\-]/', '_', $connRef);

    if (!$tables || count($tables) === 0) {
        $name = "{$ts}__{$safeConn}__ALL.sql";
    } else {
        $clean = [];
        foreach ($tables as $t) {
            $t = trim($t);
            if ($t === '') continue;
            $clean[] = preg_replace('/[^A-Za-z0-9_\$]/', '_', $t);
        }
        $list = implode(',', $clean);
        $name = "{$ts}__{$safeConn}__tables__{$list}.sql";
    }
    if ($compressed) $name .= '.gz';
    return $name;
}

function pudba_parse_backup_filename(string $filename): array {
    // returns metadata from filename; best-effort
    $base = basename($filename);
    $meta = [
        'filename' => $base,
        'timestamp' => null,
        'connection' => null,
        'db' => null,
        'tables' => null,
        'scope' => null, // ALL or tables
        'compressed' => (str_ends_with($base, '.gz')),
    ];

    $noext = $base;
    if (str_ends_with($noext, '.sql.gz')) $noext = substr($noext, 0, -7);
    elseif (str_ends_with($noext, '.sql')) $noext = substr($noext, 0, -4);

    $parts = explode('__', $noext);
    if (count($parts) >= 3) {
        $meta['timestamp'] = $parts[0];
        $meta['connection'] = $parts[1];

        if ($parts[2] === 'ALL') {
            $meta['scope'] = 'ALL';
            $meta['tables'] = [];
        } elseif ($parts[2] === 'tables' && isset($parts[3])) {
            $meta['scope'] = 'tables';
            $meta['tables'] = $parts[3] === '' ? [] : explode(',', $parts[3]);
        }
    }

    if (!empty($meta['connection'])) {
        $parsed = pudba_parse_connection_ref((string)$meta['connection']);
        if ($parsed) {
            $meta['parsed_host'] = $parsed['host'];
            $meta['parsed_port'] = $parsed['port'];
            $meta['parsed_db'] = $parsed['db'];
        }
    }
    return $meta;
}

/**
 * Returns array of backups (recent-first) across all DB folders, limited.
 */
function pudba_list_recent_backups(array $cfg): array {
    $base = rtrim($cfg['backup_dir'], '/');
    if (!is_dir($base)) return [];

    $files = [];
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($it as $finfo) {
        /** @var SplFileInfo $finfo */
        if (!$finfo->isFile()) continue;
        $name = $finfo->getFilename();
        if (!preg_match('/\.sql(\.gz)?$/', $name)) continue;

        $full = $finfo->getRealPath();
        if (!$full) continue;

        $meta = pudba_parse_backup_filename($name);
        $meta['path'] = $full;
        $meta['size'] = $finfo->getSize();
        $meta['mtime'] = $finfo->getMTime();

        // attempt to infer DB from folder if not parsed
        if (!$meta['db']) {
            $meta['db'] = basename(dirname($full));
        }

        $files[] = $meta;
    }

    usort($files, fn($a, $b) => ($b['mtime'] <=> $a['mtime']));
    $max = (int)($cfg['recent_backups_max'] ?? 25);
    return array_slice($files, 0, max(1, $max));
}

function pudba_bytes_human(int $bytes): string {
    $units = ['B','KB','MB','GB','TB'];
    $i = 0;
    $v = (float)$bytes;
    while ($v >= 1024 && $i < count($units)-1) {
        $v /= 1024;
        $i++;
    }
    return ($i === 0) ? "{$bytes} {$units[$i]}" : (number_format($v, 2) . " {$units[$i]}");
}

/**
 * Helpers for safe argv-based process execution.
 */
function pudba_format_argv(array $argv): string {
    $parts = [];
    foreach ($argv as $arg) {
        $parts[] = escapeshellarg((string)$arg);
    }
    return implode(' ', $parts);
}

function pudba_format_command(array $argv, array $env = []): string {
    $prefix = '';
    foreach ($env as $key => $value) {
        $prefix .= $key . '=' . escapeshellarg((string)$value) . ' ';
    }
    return $prefix . pudba_format_argv($argv);
}

function pudba_split_args(string $s): array {
    $s = trim($s);
    if ($s === '') return [];

    $tokens = [];
    $pattern = '/"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)"|\'([^\'\\\\]*(?:\\\\.[^\'\\\\]*)*)\'|(\\S+)/';
    if (preg_match_all($pattern, $s, $matches, PREG_SET_ORDER)) {
        foreach ($matches as $m) {
            if ($m[1] !== '') {
                $tokens[] = stripcslashes($m[1]);
            } elseif ($m[2] !== '') {
                $tokens[] = $m[2];
            } else {
                $tokens[] = $m[3];
            }
        }
    }
    return $tokens;
}

/**
 * Runs a command with argv array, capturing output and exit code.
 */
function pudba_proc_open_argv(array $argv, array $env = [], $stdin = null, $stdout = null, $stderr = null): array {
    $descriptor = [];
    $pipes = [];

    $descriptor[0] = $stdin ?? ['pipe', 'r'];
    $descriptor[1] = $stdout ?? ['pipe', 'w'];
    $descriptor[2] = $stderr ?? ['pipe', 'w'];

    $useEnv = $env ? array_merge($_ENV, $env) : null;
    $proc = @proc_open($argv, $descriptor, $pipes, null, $useEnv);
    if (!is_resource($proc)) {
        throw new RuntimeException("Failed to start process.");
    }

    if ($stdin === null && isset($pipes[0])) {
        fclose($pipes[0]);
    }

    $stdoutText = '';
    if ($stdout === null && isset($pipes[1])) {
        $stdoutText = stream_get_contents($pipes[1]) ?: '';
        fclose($pipes[1]);
    }

    $stderrText = '';
    if ($stderr === null && isset($pipes[2])) {
        $stderrText = stream_get_contents($pipes[2]) ?: '';
        fclose($pipes[2]);
    }

    $exit = proc_close($proc);

    return [
        'exit_code' => $exit,
        'stdout' => $stdoutText,
        'stderr' => $stderrText,
    ];
}

/**
 * Runs a two-stage pipeline by streaming stdout of A into stdin of B.
 */
function pudba_run_pipeline(array $procs): array {
    $count = count($procs);
    if ($count === 1) {
        $p = $procs[0];
        return pudba_proc_open_argv(
            $p['argv'],
            $p['env'] ?? [],
            $p['stdin'] ?? null,
            $p['stdout'] ?? null,
            $p['stderr'] ?? null
        );
    }
    if ($count !== 2) {
        throw new RuntimeException("Only two-stage pipelines are supported.");
    }

    $stderrStreams = [];
    $stderrOwned = [];
    $procsHandles = [];
    $pipesList = [];

    foreach ($procs as $i => $p) {
        $stderrStream = $p['stderr'] ?? fopen('php://temp', 'w+');
        if (!$stderrStream) {
            throw new RuntimeException("Failed to allocate stderr buffer.");
        }
        $stderrStreams[$i] = $stderrStream;
        $stderrOwned[$i] = !isset($p['stderr']);

        $descriptor = [
            0 => $p['stdin'] ?? ['pipe', 'r'],
            1 => $p['stdout'] ?? ['pipe', 'w'],
            2 => $stderrStream,
        ];

        $useEnv = !empty($p['env']) ? array_merge($_ENV, $p['env']) : null;
        $proc = @proc_open($p['argv'], $descriptor, $pipes, null, $useEnv);
        if (!is_resource($proc)) {
            throw new RuntimeException("Failed to start pipeline process.");
        }
        $procsHandles[$i] = $proc;
        $pipesList[$i] = $pipes;

        if (!isset($p['stdin']) && isset($pipes[0])) {
            // We'll write only when piping. Close stdin for safety if not used.
            if ($i === 0) {
                fclose($pipes[0]);
            }
        }
    }

    $upstreamOut = $pipesList[0][1] ?? null;
    $downstreamIn = $pipesList[1][0] ?? null;
    if (!is_resource($upstreamOut) || !is_resource($downstreamIn)) {
        throw new RuntimeException("Pipeline could not be connected.");
    }

    stream_copy_to_stream($upstreamOut, $downstreamIn);
    fclose($upstreamOut);
    fclose($downstreamIn);

    $stdoutText = '';
    if (!isset($procs[1]['stdout']) && isset($pipesList[1][1])) {
        $stdoutText = stream_get_contents($pipesList[1][1]) ?: '';
        fclose($pipesList[1][1]);
    }

    $stderrText = '';
    $exitCode = 0;
    foreach ($procsHandles as $i => $proc) {
        $exit = proc_close($proc);
        if ($exitCode === 0 && $exit !== 0) {
            $exitCode = $exit;
        }
        $stream = $stderrStreams[$i];
        if ($stream && $stderrOwned[$i]) {
            rewind($stream);
            $stderrText .= stream_get_contents($stream) ?: '';
            fclose($stream);
        }
    }

    return [
        'exit_code' => $exitCode,
        'stdout' => $stdoutText,
        'stderr' => $stderrText,
    ];
}

/**
 * Runs a command spec, capturing output and exit code. Also logs to file.
 */
function pudba_run_command(array $cfg, array $command, string $logPrefix = 'cmd'): array {
    $ts = date('Ymd_His');
    $logDir = rtrim($cfg['log_dir'], '/');
    $logFile = "{$logDir}/{$logPrefix}_{$ts}_" . bin2hex(random_bytes(3)) . ".log";

    $stdout = '';
    $stderr = '';
    $exit = 0;

    if (($command['type'] ?? '') === 'pipeline') {
        $result = pudba_run_pipeline($command['procs']);
        $stdout = $result['stdout'];
        $stderr = $result['stderr'];
        $exit = $result['exit_code'];
    } else {
        $result = pudba_proc_open_argv(
            $command['argv'],
            $command['env'] ?? [],
            $command['stdin'] ?? null,
            $command['stdout'] ?? null,
            $command['stderr'] ?? null
        );
        $stdout = $result['stdout'];
        $stderr = $result['stderr'];
        $exit = $result['exit_code'];
    }

    $cmd = $command['log_cmd'] ?? '';
    $cmdMasked = pudba_mask_command($cmd);

    $logBody = "=== COMMAND ===\n" . $cmdMasked . "\n\n=== STDOUT ===\n{$stdout}\n\n=== STDERR ===\n{$stderr}\n\n=== EXIT ===\n{$exit}\n";
    @file_put_contents($logFile, $logBody, LOCK_EX);

    return [
        'ok' => ($exit === 0),
        'exit' => $exit,
        'stdout' => $stdout,
        'stderr' => $stderr,
        'log_file' => $logFile,
        'cmd' => $cmd,
        'cmd_masked' => $cmdMasked,
    ];
}

/**
 * Builds mysqldump/mariadb-dump argv with MYSQL_PWD env var (avoids exposing password in args).
 */
function pudba_build_dump_command(array $cfg, array $conn, string $connKey, ?array $tables, string $outFile): array {
    $dumpBin = pudba_find_binary(['mysqldump', 'mariadb-dump']) ?? 'mysqldump';
    $flavor = pudba_detect_server_flavor($conn);

    $host = (string)$conn['host'];
    $port = (int)$conn['port'];
    $user = (string)$conn['user'];
    $pass = (string)$conn['pass'];
    $db   = (string)$conn['db'];

    $argv = [
        $dumpBin,
        "--host={$host}",
        "--port={$port}",
        "--user={$user}",
    ];

    $opts = $cfg['dump_options'] ?? [];
    $skipPrefixes = [];
    if ($flavor === 'mariadb') {
        $skipPrefixes[] = '--set-gtid-purged';
    }
    foreach ($opts as $o) {
        $o = trim((string)$o);
        foreach (pudba_split_args($o) as $token) {
            if ($token !== '') {
                foreach ($skipPrefixes as $prefix) {
                    if (str_starts_with($token, $prefix)) {
                        continue 2;
                    }
                }
                $argv[] = $token;
            }
        }
    }

    $argv[] = $db;

    if ($tables && count($tables) > 0) {
        foreach ($tables as $t) {
            $argv[] = $t;
        }
    }

    $compressed = (bool)($cfg['enable_compression'] ?? true) && pudba_has_gzip() && str_ends_with($outFile, '.gz');
    $env = ['MYSQL_PWD' => $pass];

    $baseCmd = pudba_format_command($argv, $env);
    if ($compressed) {
        $gzipBin = pudba_find_binary(['gzip']) ?? 'gzip';
        $logCmd = $baseCmd . ' | ' . pudba_format_argv([$gzipBin, '-c']) . ' > ' . escapeshellarg($outFile);
        return [
            'argv' => $argv,
            'env' => $env,
            'compressed' => true,
            'gzip_argv' => [$gzipBin, '-c'],
            'log_cmd' => $logCmd,
        ];
    }

    $logCmd = $baseCmd . ' > ' . escapeshellarg($outFile);
    return [
        'argv' => $argv,
        'env' => $env,
        'compressed' => false,
        'log_cmd' => $logCmd,
    ];
}

/**
 * Executes a backup using the same command flow as the UI.
 */
function pudba_execute_backup(array $cfg, array $conn, string $connKey, ?array $tables, string $logPrefix = 'backup'): array {
    $db = (string)$conn['db'];
    try {
        pudba_prune_backups($cfg);
    } catch (Throwable $e) {
        // Ignore pruning failures; do not block backups.
    }
    $dir = pudba_ensure_db_backup_dir($cfg, $db);

    $ts = pudba_now_utc_stamp();
    $wantGz = (bool)($cfg['enable_compression'] ?? true) && pudba_has_gzip();
    $connRef = pudba_connection_ref((string)$conn['host'], (int)($conn['port'] ?? 3306), (string)$conn['db']);
    $filename = pudba_build_backup_filename($ts, $connRef, $tables, $wantGz);
    $outFile = $dir . '/' . $filename;

    $plan = pudba_build_dump_command($cfg, $conn, $connKey, $tables, $outFile);
    $outHandle = @fopen($outFile, 'wb');
    if (!$outHandle) {
        throw new RuntimeException("Failed to open backup output file for writing.");
    }

    if (!empty($plan['compressed'])) {
        $command = [
            'type' => 'pipeline',
            'log_cmd' => $plan['log_cmd'],
            'procs' => [
                [
                    'argv' => $plan['argv'],
                    'env' => $plan['env'],
                ],
                [
                    'argv' => $plan['gzip_argv'],
                    'stdout' => $outHandle,
                ],
            ],
        ];
    } else {
        $command = [
            'type' => 'single',
            'log_cmd' => $plan['log_cmd'],
            'argv' => $plan['argv'],
            'env' => $plan['env'],
            'stdout' => $outHandle,
        ];
    }

    $result = pudba_run_command($cfg, $command, $logPrefix);
    fclose($outHandle);

    return [
        'result' => $result,
        'filename' => $filename,
        'out_file' => $outFile,
    ];
}

function pudba_parse_pudba_cron_jobs(string $crontab): array {
    $jobs = [];
    $suffix = pudba_cron_job_suffix();
    $lines = preg_split('/\r?\n/', $crontab) ?: [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        $match = null;
        if (preg_match('/^(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+?)\s+#\s*PUDBA JOB:\s*(.+)$/', $line, $match)) {
            $schedule = $match[1];
            $command = $match[2];
            $name = trim($match[3]);
        } elseif (preg_match('/^(@\S+)\s+(.+?)\s+#\s*PUDBA JOB:\s*(.+)$/', $line, $match)) {
            $schedule = $match[1];
            $command = $match[2];
            $name = trim($match[3]);
        } else {
            continue;
        }
        if (!str_ends_with($name, $suffix)) {
            continue;
        }
        $jobs[] = [
            'name' => $name,
            'schedule' => $schedule,
            'command' => trim($command),
            'line' => $line,
        ];
    }
    return $jobs;
}

function pudba_human_cron_schedule(string $schedule): string {
    $schedule = trim($schedule);
    $labels = [
        '@hourly' => 'Hourly',
        '@daily' => 'Daily',
        '@midnight' => 'Daily',
        '@weekly' => 'Weekly',
        '@monthly' => 'Monthly',
        '0 * * * *' => 'Hourly',
        '0 0 * * *' => 'Daily',
        '0 0 * * 0' => 'Weekly',
        '0 0 1 * *' => 'Monthly',
    ];

    return $labels[$schedule] ?? 'Custom';
}

function pudba_find_pudba_cron_job(array $jobs, string $name): ?array {
    foreach ($jobs as $job) {
        if (($job['name'] ?? '') === $name) {
            return $job;
        }
    }
    return null;
}

function pudba_remove_pudba_cron_job(string $crontab, string $name): string {
    $pattern = '/^.*#\s*PUDBA JOB:\s*' . preg_quote($name, '/') . '\s*$/m';
    $new = preg_replace($pattern, '', $crontab) ?? $crontab;
    $new = preg_replace("/\n{3,}/", "\n\n", $new) ?? $new;
    $new = trim($new);
    if ($new !== '') {
        $new .= "\n";
    }
    return $new;
}

function pudba_read_crontab(string $crontabBin): string {
    $result = pudba_proc_open_argv([$crontabBin, '-l']);
    if ($result['exit_code'] !== 0) {
        $stderr = strtolower(trim((string)($result['stderr'] ?? '')));
        if (str_contains($stderr, 'no crontab')) {
            return '';
        }
        throw new RuntimeException('Failed to read crontab: ' . trim((string)($result['stderr'] ?? '')));
    }
    return (string)($result['stdout'] ?? '');
}

function pudba_write_crontab(string $crontabBin, string $content): void {
    $tmp = tempnam(sys_get_temp_dir(), 'pudba_cron_');
    if ($tmp === false) {
        throw new RuntimeException('Failed to create temporary crontab file.');
    }
    if (file_put_contents($tmp, $content) === false) {
        @unlink($tmp);
        throw new RuntimeException('Failed to write temporary crontab file.');
    }
    $result = pudba_proc_open_argv([$crontabBin, $tmp]);
    @unlink($tmp);
    if ($result['exit_code'] !== 0) {
        throw new RuntimeException('Failed to install crontab: ' . trim((string)($result['stderr'] ?? '')));
    }
}

function pudba_write_crontab_logged(array $cfg, string $crontabBin, string $content, string $logCmd, string $logPrefix = 'cron'): array {
    $tmp = tempnam(sys_get_temp_dir(), 'pudba_cron_');
    if ($tmp === false) {
        throw new RuntimeException('Failed to create temporary crontab file.');
    }
    if (file_put_contents($tmp, $content) === false) {
        @unlink($tmp);
        throw new RuntimeException('Failed to write temporary crontab file.');
    }

    $command = [
        'type' => 'single',
        'argv' => [$crontabBin, $tmp],
        'log_cmd' => $logCmd !== '' ? $logCmd : pudba_format_argv([$crontabBin, $tmp]),
    ];

    $result = pudba_run_command($cfg, $command, $logPrefix);
    @unlink($tmp);
    if (!$result['ok']) {
        throw new RuntimeException('Failed to install crontab: ' . trim((string)($result['stderr'] ?? '')));
    }
    return $result;
}

/**
 * Builds restore argv using mysql/mariadb; supports .sql and .sql.gz
 */
function pudba_build_restore_command(array $cfg, array $conn, string $inFile): array {
    $mysqlBin = pudba_find_binary(['mysql', 'mariadb']) ?? 'mysql';

    $host = (string)$conn['host'];
    $port = (int)$conn['port'];
    $user = (string)$conn['user'];
    $pass = (string)$conn['pass'];
    $db   = (string)$conn['db'];

    $argv = [
        $mysqlBin,
        "--host={$host}",
        "--port={$port}",
        "--user={$user}",
        $db,
    ];
    $env = ['MYSQL_PWD' => $pass];

    $baseCmd = pudba_format_command($argv, $env);
    $isGz = str_ends_with($inFile, '.gz');

    if ($isGz) {
        $gunzip = pudba_find_binary(['gunzip']);
        if ($gunzip) {
            $logCmd = pudba_format_argv([$gunzip, '-c']) . ' < ' . escapeshellarg($inFile) . ' | ' . $baseCmd;
            return [
                'argv' => $argv,
                'env' => $env,
                'compressed' => true,
                'decompress_argv' => [$gunzip, '-c'],
                'log_cmd' => $logCmd,
            ];
        }
        $gzip = pudba_find_binary(['gzip']);
        if ($gzip) {
            $logCmd = pudba_format_argv([$gzip, '-dc']) . ' < ' . escapeshellarg($inFile) . ' | ' . $baseCmd;
            return [
                'argv' => $argv,
                'env' => $env,
                'compressed' => true,
                'decompress_argv' => [$gzip, '-dc'],
                'log_cmd' => $logCmd,
            ];
        }
        return [
            'error' => 'Restore failed: no gzip/gunzip available to decompress .gz backups.',
        ];
    }

    $logCmd = $baseCmd . ' < ' . escapeshellarg($inFile);
    return [
        'argv' => $argv,
        'env' => $env,
        'compressed' => false,
        'log_cmd' => $logCmd,
    ];
}

/**
 * Path traversal protection for downloads:
 * - accepts filename only (basename)
 * - resolves within backup_dir
 */
function pudba_resolve_download_path(array $cfg, string $requested): ?string {
    $requested = trim($requested);
    if ($requested === '') return null;

    // Only allow a plain filename, no slashes
    if ($requested !== basename($requested)) return null;

    $base = realpath($cfg['backup_dir']);
    if (!$base) return null;

    // search for filename under backup_dir (DB subfolders)
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($it as $finfo) {
        if (!$finfo->isFile()) continue;
        if ($finfo->getFilename() === $requested) {
            $full = $finfo->getRealPath();
            if (!$full) return null;
            // ensure still inside base
            if (str_starts_with($full, $base . DIRECTORY_SEPARATOR)) {
                return $full;
            }
        }
    }
    return null;
}

/**
 * Auth: setup if missing; verify otherwise.
 */
function pudba_auth_is_configured(array $cfg): bool {
    return !empty($cfg['auth_user_hash']) && !empty($cfg['auth_pass_hash']);
}

function pudba_auth_verify(array $cfg, string $user, string $pass): bool {
    if (!pudba_auth_is_configured($cfg)) return false;
    return password_verify($user, (string)$cfg['auth_user_hash'])
        && password_verify($pass, (string)$cfg['auth_pass_hash']);
}

function pudba_auth_require(array $cfg): void {
    pudba_start_session();
    if (!empty($_SESSION['authed'])) return;

    // allow login POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
        if (!pudba_csrf_check((string)($_POST['csrf'] ?? ''))) {
            pudba_set_flash('error', 'Invalid CSRF token.');
            header('Location: index.php');
            exit;
        }
        $attempts = (int)($_SESSION['login_failures'] ?? 0);
        if ($attempts >= 5) {
            $delay = min(2.0, 0.25 * ($attempts - 4));
            usleep((int)($delay * 1000000));
        }
        $user = (string)($_POST['username'] ?? '');
        $pass = (string)($_POST['password'] ?? '');
        if (pudba_auth_verify($cfg, $user, $pass)) {
            session_regenerate_id(true);
            $_SESSION['authed'] = true;
            $_SESSION['login_failures'] = 0;
            pudba_set_flash('success', 'Logged in.');
            header('Location: index.php');
            exit;
        }
        $_SESSION['login_failures'] = $attempts + 1;
        pudba_set_flash('error', 'Invalid username or password.');
        header('Location: index.php');
        exit;
    }

    // render login gate by throwing a special exception handled in index.php
    throw new RuntimeException('__PUDBA_AUTH_REQUIRED__');
}

function pudba_csrf_token(): string {
    pudba_start_session();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return (string)$_SESSION['csrf'];
}

function pudba_csrf_check(string $token): bool {
    pudba_start_session();
    return isset($_SESSION['csrf']) && hash_equals((string)$_SESSION['csrf'], $token);
}
?>
