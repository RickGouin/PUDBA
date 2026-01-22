<?php
require __DIR__ . '/helpers.php';

pudba_start_session();

$cfg = pudba_load_config();

function pudba_build_connection_from_post(array $post, array $existing = []): array {
    $label = trim((string)($post['label'] ?? ''));
    $host = trim((string)($post['host'] ?? ''));
    $port = (int)($post['port'] ?? 3306);
    $user = trim((string)($post['user'] ?? ''));
    $pass = (string)($post['pass'] ?? '');
    $db = trim((string)($post['db'] ?? ''));
    $charset = trim((string)($post['charset'] ?? ''));
    $clearPass = !empty($post['clear_pass']);

    $errors = [];
    if ($host === '') $errors[] = 'Host is required.';
    if ($user === '') $errors[] = 'User is required.';
    if ($port <= 0) $errors[] = 'Port must be a positive number.';

    if ($charset === '') {
        $charset = (string)($existing['charset'] ?? 'utf8mb4');
    }

    $finalPass = (string)($existing['pass'] ?? '');
    if ($clearPass) {
        $finalPass = '';
    } elseif ($pass !== '' || !$existing) {
        $finalPass = $pass;
    }

    return [
        'errors' => $errors,
        'connection' => [
            'label' => $label,
            'host' => $host,
            'port' => $port,
            'user' => $user,
            'pass' => $finalPass,
            'db' => $db,
            'charset' => $charset,
        ],
    ];
}

// Ensure folders exist early
try {
    pudba_ensure_dirs($cfg);
} catch (Throwable $e) {
    http_response_code(500);
    echo "<h1>PUDBA - Setup Error</h1>";
    echo "<p>" . pudba_h($e->getMessage()) . "</p>";
    echo "<p>Fix permissions, then reload.</p>";
    exit;
}

// Initial auth setup if missing hashes
if (!pudba_auth_is_configured($cfg)) {
    $flash = pudba_get_flash();

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'setup_auth') {
        if (!pudba_csrf_check((string)($_POST['csrf'] ?? ''))) {
            pudba_set_flash('error', 'Invalid CSRF token.');
            header('Location: index.php');
            exit;
        }

        $user = trim((string)($_POST['username'] ?? ''));
        $pass = (string)($_POST['password'] ?? '');
        $pass2 = (string)($_POST['password2'] ?? '');

        if ($user === '' || $pass === '') {
            pudba_set_flash('error', 'Username and password are required.');
            header('Location: index.php');
            exit;
        }
        if ($pass !== $pass2) {
            pudba_set_flash('error', 'Passwords do not match.');
            header('Location: index.php');
            exit;
        }

        $cfg['auth_user_hash'] = password_hash($user, PASSWORD_DEFAULT);
        $cfg['auth_pass_hash'] = password_hash($pass, PASSWORD_DEFAULT);

        try {
            pudba_save_config($cfg);
            session_regenerate_id(true);
            $_SESSION['authed'] = true;
            pudba_set_flash('success', 'Authentication initialized. You are now logged in.');
            $connections = (array)($cfg['connections'] ?? []);
            $firstKey = $connections ? array_key_first($connections) : '';
            $target = $firstKey !== '' ? ('index.php?conn=' . urlencode($firstKey)) : 'index.php';
            header('Location: ' . $target);
            exit;
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Failed to write config.php: ' . $e->getMessage());
        }

        header('Location: index.php');
        exit;
    }

    ?>
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>PUDBA - Initial Setup</title>
        <link rel="stylesheet" href="style.css">
    </head>
    <body>
    <div class="wrap">
        <header class="topbar">
            <div class="brand">PolarForge Universal Database Backup Assistant</div>
            <div class="tag">Initial authentication setup</div>
        </header>

        <?php if ($flash): ?>
            <div class="msg <?= pudba_h($flash['type']) ?>">
                <strong><?= pudba_h(strtoupper($flash['type'])) ?>:</strong> <?= pudba_h($flash['message']) ?>
            </div>
        <?php endif; ?>

        <div class="card">
            <h2>Set Username & Password</h2>
            <p class="muted">
                PUDBA will store a single hashed username + password in <code>config.php</code>.
            </p>

            <form method="post" class="form">
                <input type="hidden" name="action" value="setup_auth">
                <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">

                <label>Username</label>
                <input name="username" autocomplete="username" required>

                <label>Password</label>
                <input name="password" type="password" autocomplete="new-password" required>

                <label>Confirm Password</label>
                <input name="password2" type="password" autocomplete="new-password" required>

                <button class="btn primary" type="submit">Initialize</button>
            </form>
        </div>

        <div class="footer muted">
            After setup, you can change auth by editing/removing <code>auth_user_hash</code> and <code>auth_pass_hash</code> in <code>config.php</code>.
        </div>
    </div>
    </body>
    </html>
    <?php
    exit;
}

// Require auth (login gate)
try {
    pudba_auth_require($cfg);
} catch (RuntimeException $e) {
    if ($e->getMessage() === '__PUDBA_AUTH_REQUIRED__') {
        $flash = pudba_get_flash();
        ?>
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>PUDBA - Login</title>
            <link rel="stylesheet" href="style.css">
        </head>
        <body>
        <div class="wrap">
            <header class="topbar">
                <div class="brand">PolarForge Universal Database Backup Assistant</div>
                <div class="tag">Login</div>
            </header>

            <?php if ($flash): ?>
                <div class="msg <?= pudba_h($flash['type']) ?>">
                    <strong><?= pudba_h(strtoupper($flash['type'])) ?>:</strong> <?= pudba_h($flash['message']) ?>
                </div>
            <?php endif; ?>

            <div class="card">
                <h2>Sign in</h2>
                <form method="post" class="form">
                    <input type="hidden" name="action" value="login">
                    <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                    <label>Username</label>
                    <input name="username" autocomplete="username" required>
                    <label>Password</label>
                    <input name="password" type="password" autocomplete="current-password" required>
                    <button class="btn primary" type="submit">Login</button>
                </form>
            </div>

            <div class="footer muted">
                Tip: if you forgot credentials, remove the auth hash keys from <code>config.php</code> to re-init.
            </div>
        </div>
        </body>
        </html>
        <?php
        exit;
    }
    throw $e;
}

// Handle download endpoint: index.php?download=FILENAME
if (isset($_GET['download'])) {
    $path = pudba_resolve_download_path($cfg, (string)$_GET['download']);
    if (!$path || !is_file($path)) {
        http_response_code(404);
        echo "Not found.";
        exit;
    }
    $name = basename($path);
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Content-Length: ' . filesize($path));
    readfile($path);
    exit;
}

// Logout
if (isset($_GET['logout'])) {
    pudba_logout();
    header('Location: index.php');
    exit;
}

// Defaults
$connections = (array)($cfg['connections'] ?? []);
if (!$connections) {
    pudba_set_flash('error', 'No connections configured in config.php.');
}

$selectedKey = (string)($_GET['conn'] ?? ($_SESSION['conn'] ?? ''));
if ($selectedKey === '' || !isset($connections[$selectedKey])) {
    $keys = array_keys($connections);
    $selectedKey = $keys[0] ?? '';
}
if ($selectedKey !== '') {
    $_SESSION['conn'] = $selectedKey;
}

$selectedConn = $selectedKey !== '' && isset($connections[$selectedKey]) ? $connections[$selectedKey] : null;
$dbList = [];
$dbErr = null;
$activeDb = null;
$activeConn = $selectedConn ? $selectedConn : null;
if ($selectedConn) {
    try {
        $dbList = pudba_list_databases($selectedConn);
    } catch (Throwable $e) {
        $dbErr = $e->getMessage();
    }

    $configuredDb = trim((string)($selectedConn['db'] ?? ''));
    if ($configuredDb !== '') {
        $activeDb = $configuredDb;
    } else {
        $sessionDb = '';
        if (!empty($_SESSION['active_db']) && is_array($_SESSION['active_db'])) {
            $sessionDb = (string)($_SESSION['active_db'][$selectedKey] ?? '');
        }
        if ($sessionDb !== '' && in_array($sessionDb, $dbList, true)) {
            $activeDb = $sessionDb;
        } elseif ($dbList) {
            $activeDb = $dbList[0];
            $_SESSION['active_db'][$selectedKey] = $activeDb;
        }
    }

    if ($activeDb !== '') {
        $activeConn = $selectedConn;
        $activeConn['db'] = $activeDb;
    }
}

// Handle POST actions (PRG)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string)($_POST['action'] ?? '');

    if (!pudba_csrf_check((string)($_POST['csrf'] ?? ''))) {
        pudba_set_flash('error', 'Invalid CSRF token.');
        header('Location: index.php' . ($selectedKey ? '?conn=' . urlencode($selectedKey) : ''));
        exit;
    }

    // Switch connection
    if ($action === 'select_connection') {
        $k = (string)($_POST['conn_key'] ?? '');
        if ($k !== '' && isset($connections[$k])) {
            $_SESSION['conn'] = $k;
            pudba_set_flash('success', 'Connection selected: ' . $k);
            header('Location: index.php?conn=' . urlencode($k));
            exit;
        }
        pudba_set_flash('error', 'Invalid connection selection.');
        header('Location: index.php');
        exit;
    }

    if ($action === 'select_database') {
        if (!$selectedConn) {
            pudba_set_flash('error', 'Select a connection first.');
            header('Location: index.php');
            exit;
        }
        if (!empty($selectedConn['db'])) {
            pudba_set_flash('error', 'This connection is locked to a specific database.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }
        $dbSelect = trim((string)($_POST['db_select'] ?? ''));
        try {
            $available = pudba_list_databases($selectedConn);
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Failed listing databases: ' . $e->getMessage());
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }
        if ($dbSelect === '' || !in_array($dbSelect, $available, true)) {
            pudba_set_flash('error', 'Select a valid database.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }
        $_SESSION['active_db'][$selectedKey] = $dbSelect;
        pudba_set_flash('success', 'Database selected: ' . $dbSelect);
        header('Location: index.php?conn=' . urlencode($selectedKey));
        exit;
    }

    if ($action === 'test_connection_draft') {
        $built = pudba_build_connection_from_post($_POST);
        if (!empty($built['errors'])) {
            pudba_set_flash('error', implode(' ', $built['errors']));
        } else {
            $res = pudba_test_connection($built['connection']);
            if ($res['ok']) {
                pudba_set_flash('success', 'Connection OK. Server time: ' . ($res['now'] ?? 'unknown'));
            } else {
                pudba_set_flash('error', 'Connection failed: ' . $res['message']);
            }
        }
        $target = 'index.php';
        $tab = trim((string)($_POST['return_tab'] ?? ''));
        if ($selectedKey !== '') {
            $target .= '?conn=' . urlencode($selectedKey);
        }
        if ($tab !== '') {
            $target .= ($selectedKey !== '' ? '&' : '?') . 'tab=' . urlencode($tab);
        }
        header('Location: ' . $target);
        exit;
    }

    if ($action === 'add_connection') {
        $built = pudba_build_connection_from_post($_POST);
        if (!empty($built['errors'])) {
            pudba_set_flash('error', implode(' ', $built['errors']));
            header('Location: index.php');
            exit;
        }

        $key = '';
        $id = '';
        for ($i = 0; $i < 5; $i++) {
            $id = pudba_generate_connection_id();
            $key = pudba_connection_key($built['connection']['host'], $built['connection']['db'], $id);
            if (!isset($connections[$key])) {
                break;
            }
        }
        if ($key === '' || isset($connections[$key])) {
            pudba_set_flash('error', 'Connection key could not be generated. Please try again.');
            header('Location: index.php');
            exit;
        }

        $built['connection']['id'] = $id;

        $cfg['connections'][$key] = $built['connection'];
        try {
            pudba_save_config($cfg);
            $_SESSION['conn'] = $key;
            pudba_set_flash('success', 'Connection added.');
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Failed to save config: ' . $e->getMessage());
        }
        header('Location: index.php?conn=' . urlencode($key));
        exit;
    }

    if ($action === 'update_connection') {
        $key = (string)($_POST['conn_key'] ?? '');
        if ($key === '' || !isset($connections[$key])) {
            pudba_set_flash('error', 'Select a valid connection to update.');
            header('Location: index.php');
            exit;
        }

        $existing = (array)$connections[$key];
        $built = pudba_build_connection_from_post($_POST, $existing);
        if (!empty($built['errors'])) {
            pudba_set_flash('error', implode(' ', $built['errors']));
            header('Location: index.php?conn=' . urlencode($key));
            exit;
        }

        $id = (string)($existing['id'] ?? '');
        if ($id === '') {
            $id = pudba_generate_connection_id();
        }
        $built['connection']['id'] = $id;

        $newKey = pudba_connection_key($built['connection']['host'], $built['connection']['db'], $id);
        if ($newKey === '' || ($newKey !== $key && isset($connections[$newKey]))) {
            pudba_set_flash('error', 'Connection key could not be generated. Please try again.');
            header('Location: index.php?conn=' . urlencode($key));
            exit;
        }

        if ($newKey !== $key) {
            unset($cfg['connections'][$key]);
        }
        $cfg['connections'][$newKey] = $built['connection'];
        try {
            pudba_save_config($cfg);
            $_SESSION['conn'] = $newKey;
            pudba_set_flash('success', 'Connection updated.');
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Failed to save config: ' . $e->getMessage());
        }
        header('Location: index.php?conn=' . urlencode($newKey));
        exit;
    }

    if ($action === 'delete_connection') {
        $key = (string)($_POST['conn_key'] ?? '');
        if ($key === '' || !isset($connections[$key])) {
            pudba_set_flash('error', 'Select a valid connection to remove.');
            header('Location: index.php');
            exit;
        }

        unset($cfg['connections'][$key]);
        try {
            pudba_save_config($cfg);
            $remaining = array_keys((array)($cfg['connections'] ?? []));
            $nextKey = $remaining[0] ?? '';
            if (!empty($_SESSION['conn']) && $_SESSION['conn'] === $key) {
                $_SESSION['conn'] = $nextKey;
            }
            pudba_set_flash('success', 'Connection removed.');
            if ($nextKey !== '') {
                header('Location: index.php?conn=' . urlencode($nextKey));
            } else {
                header('Location: index.php');
            }
            exit;
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Failed to save config: ' . $e->getMessage());
            header('Location: index.php');
            exit;
        }
    }

    if ($action === 'run_cron_job' || $action === 'delete_cron_job') {
        $jobName = trim((string)($_POST['job_name'] ?? ''));
        $jobName = preg_replace('/\s+/', ' ', $jobName);
        $jobName = preg_replace('/[^A-Za-z0-9 _\\-\\.]/', '', $jobName);
        $jobName = pudba_normalize_cron_job_name($jobName);

        if ($jobName === '') {
            pudba_set_flash('error', 'Cron job name is required.');
            header('Location: index.php' . ($selectedKey ? '?conn=' . urlencode($selectedKey) : ''));
            exit;
        }

        try {
            $crontabBin = pudba_find_binary(['crontab']);
            if (!$crontabBin) {
                throw new RuntimeException('crontab is not available on this server.');
            }
            $existing = pudba_read_crontab($crontabBin);
            $jobs = pudba_parse_pudba_cron_jobs($existing);
            $job = pudba_find_pudba_cron_job($jobs, $jobName);

            if ($action === 'run_cron_job') {
                if (!$job) {
                    throw new RuntimeException('Cron job not found.');
                }
                $argv = pudba_split_args((string)($job['command'] ?? ''));
                if (!$argv) {
                    throw new RuntimeException('Cron command is empty.');
                }
                $run = pudba_run_command($cfg, [
                    'type' => 'single',
                    'argv' => $argv,
                    'log_cmd' => (string)$job['command'],
                ], 'cron_run');
                if ($run['ok']) {
                    pudba_set_flash('success', 'Cron job started: ' . $jobName, [
                        'cmd' => $run['cmd_masked'],
                        'log' => $run['log_file'],
                        'stdout' => $run['stdout'],
                        'stderr' => $run['stderr'],
                    ]);
                } else {
                    pudba_set_flash('error', 'Cron job failed (exit ' . $run['exit'] . '): ' . $jobName, [
                        'cmd' => $run['cmd_masked'],
                        'log' => $run['log_file'],
                        'stdout' => $run['stdout'],
                        'stderr' => $run['stderr'],
                    ]);
                }
            } else {
                if (!$job) {
                    throw new RuntimeException('Cron job not found.');
                }
                $newCron = pudba_remove_pudba_cron_job($existing, $jobName);
                $install = pudba_write_crontab_logged($cfg, $crontabBin, $newCron, $job['command'], 'cron_remove');
                pudba_set_flash('success', 'Cron job deleted: ' . $jobName, [
                    'log' => $install['log_file'],
                    'stdout' => $install['stdout'],
                    'stderr' => $install['stderr'],
                ]);
            }
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Cron job action failed: ' . $e->getMessage());
        }

        header('Location: index.php' . ($selectedKey ? '?conn=' . urlencode($selectedKey) : ''));
        exit;
    }

    if ($action === 'update_retention') {
        $daysRaw = trim((string)($_POST['retention_days'] ?? ''));
        $days = filter_var($daysRaw, FILTER_VALIDATE_INT);
        if ($days === false || $days < 0) {
            pudba_set_flash('error', 'Retention must be a non-negative number of days.');
            header('Location: index.php' . ($selectedKey ? '?conn=' . urlencode($selectedKey) : ''));
            exit;
        }
        $cfg['retention_days'] = (int)$days;
        try {
            pudba_save_config($cfg);
            pudba_set_flash('success', 'Retention period updated.');
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Failed to save config: ' . $e->getMessage());
        }
        header('Location: index.php' . ($selectedKey ? '?conn=' . urlencode($selectedKey) : ''));
        exit;
    }

    if (!$selectedConn) {
        pudba_set_flash('error', 'No connection selected.');
        header('Location: index.php');
        exit;
    }

    // Test connection
    if ($action === 'test_connection') {
        $res = pudba_test_connection($selectedConn);
        if ($res['ok']) {
            pudba_set_flash('success', 'Connection OK. Server time: ' . ($res['now'] ?? 'unknown'));
        } else {
            pudba_set_flash('error', 'Connection failed: ' . $res['message']);
        }
        header('Location: index.php?conn=' . urlencode($selectedKey));
        exit;
    }

    // Backup
    if ($action === 'backup') {
        if (!$activeConn || empty($activeConn['db'])) {
            pudba_set_flash('error', 'Select a database before running a backup.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }
        $scope = (string)($_POST['scope'] ?? 'ALL');
        $tables = [];

        if ($scope === 'TABLES') {
            $tables = (array)($_POST['tables'] ?? []);
            $tables = array_values(array_filter(array_map('trim', $tables), fn($t) => $t !== ''));
        } else {
            $tables = [];
        }

        // Validate table names (basic)
        foreach ($tables as $t) {
            if (!pudba_is_safe_table($t)) {
                pudba_set_flash('error', "Unsafe table name rejected: {$t}");
                header('Location: index.php?conn=' . urlencode($selectedKey));
                exit;
            }
        }

        try {
            $backup = pudba_execute_backup($cfg, $activeConn, $selectedKey, $tables, 'backup');
            $result = $backup['result'];
            $filename = $backup['filename'];
            $outFile = $backup['out_file'];

            if ($result['ok'] && is_file($outFile) && filesize($outFile) > 0) {
                pudba_set_flash('success', 'Backup created: ' . $filename, [
                    'cmd' => $result['cmd_masked'],
                    'log' => $result['log_file'],
                    'file' => $filename,
                ]);
            } else {
                $extra = trim($result['stderr'] ?? '');
                pudba_set_flash('error', 'Backup failed (exit ' . $result['exit'] . '). ' . ($extra ? 'See details.' : ''), [
                    'cmd' => $result['cmd_masked'],
                    'stderr' => $result['stderr'],
                    'stdout' => $result['stdout'],
                    'log' => $result['log_file'],
                ]);
            }
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Backup error: ' . $e->getMessage());
        }

        header('Location: index.php?conn=' . urlencode($selectedKey));
        exit;
    }

    if ($action === 'create_job') {
        if (!$activeConn || empty($activeConn['db'])) {
            pudba_set_flash('error', 'Select a database before creating a backup job.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }
        $jobName = trim((string)($_POST['job_name'] ?? ''));
        $jobName = preg_replace('/\s+/', ' ', $jobName);
        $jobName = preg_replace('/[^A-Za-z0-9 _\\-\\.]/', '', $jobName);
        $jobName = pudba_normalize_cron_job_name($jobName);
        $scheduleKey = (string)($_POST['schedule'] ?? '');

        $schedules = [
            'hourly' => '0 * * * *',
            'daily' => '0 0 * * *',
            'weekly' => '0 0 * * 0',
            'monthly' => '0 0 1 * *',
        ];

        if ($jobName === '') {
            pudba_set_flash('error', 'Job name is required.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }
        if (!isset($schedules[$scheduleKey])) {
            pudba_set_flash('error', 'Select a valid schedule.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }

        try {
            $crontabBin = pudba_find_binary(['crontab']);
            if (!$crontabBin) {
                throw new RuntimeException('crontab is not available on this server.');
            }
            $phpResult = pudba_find_php_cli();
            $phpBin = $phpResult['bin'];
            if (!$phpBin) {
                $details = '';
                if (!empty($phpResult['errors'])) {
                    $details = ' Details: ' . implode(' ', array_unique($phpResult['errors']));
                }
                throw new RuntimeException('PHP CLI binary could not be found for cron execution.' . $details);
            }

            $scriptPath = __DIR__ . '/cron_backup.php';
            if (!is_file($scriptPath)) {
                throw new RuntimeException('Cron backup script not found.');
            }

            $existing = pudba_read_crontab($crontabBin);
            if ($existing !== '' && preg_match('/^# PUDBA JOB: ' . preg_quote($jobName, '/') . '\\b/m', $existing)) {
                throw new RuntimeException('A cron job with that name already exists.');
            }

            $argv = [
                $phpBin,
                $scriptPath,
                '--conn-ref',
                pudba_connection_ref(
                    (string)$activeConn['host'],
                    (int)($activeConn['port'] ?? 3306),
                    (string)$activeConn['db']
                ),
                '--conn',
                $selectedKey,
                '--job',
                $jobName,
            ];
            if (empty($selectedConn['db'])) {
                $argv[] = '--db';
                $argv[] = (string)$activeConn['db'];
            }
            $command = pudba_format_argv($argv);
            $line = $schedules[$scheduleKey] . ' ' . $command . ' # PUDBA JOB: ' . $jobName;

            $newCron = rtrim($existing);
            if ($newCron !== '') {
                $newCron .= "\n";
            }
            $newCron .= $line . "\n";

            $install = pudba_write_crontab_logged($cfg, $crontabBin, $newCron, $command);
            pudba_set_flash('success', 'Cron job created: ' . $jobName, [
                'cmd' => $command,
                'log' => $install['log_file'],
                'stdout' => $install['stdout'],
                'stderr' => $install['stderr'],
            ]);
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Failed to create cron job: ' . $e->getMessage());
        }

        header('Location: index.php?conn=' . urlencode($selectedKey));
        exit;
    }

    // Restore (confirmed)
    if ($action === 'restore_confirmed') {
        if (!$activeConn || empty($activeConn['db'])) {
            pudba_set_flash('error', 'Select a database before restoring a backup.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }
        $filename = (string)($_POST['filename'] ?? '');
        $resolved = pudba_resolve_download_path($cfg, $filename);

        if (!$resolved || !is_file($resolved)) {
            pudba_set_flash('error', 'Restore file not found or not allowed.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }

        // Extra safety: only allow restore into the selected connection's DB folder (optional but nice)
        $dbFolder = pudba_db_backup_dir($cfg, (string)$activeConn['db']);
        $dbFolderReal = realpath($dbFolder);
        $resolvedReal = realpath($resolved);
        if ($dbFolderReal && $resolvedReal && !str_starts_with($resolvedReal, $dbFolderReal . DIRECTORY_SEPARATOR)) {
            pudba_set_flash('error', 'Refusing restore: backup file is not in the selected DB folder.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }

        // Build restore command
        try {
            $plan = pudba_build_restore_command($cfg, $activeConn, $resolved);
            if (!empty($plan['error'])) {
                pudba_set_flash('error', $plan['error']);
                header('Location: index.php?conn=' . urlencode($selectedKey));
                exit;
            }

            $inHandle = @fopen($resolved, 'rb');
            if (!$inHandle) {
                throw new RuntimeException("Failed to open restore file for reading.");
            }
            if (!empty($plan['compressed'])) {
                $command = [
                    'type' => 'pipeline',
                    'log_cmd' => $plan['log_cmd'],
                    'procs' => [
                        [
                            'argv' => $plan['decompress_argv'],
                            'stdin' => $inHandle,
                        ],
                        [
                            'argv' => $plan['argv'],
                            'env' => $plan['env'],
                        ],
                    ],
                ];
            } else {
                $command = [
                    'type' => 'single',
                    'log_cmd' => $plan['log_cmd'],
                    'argv' => $plan['argv'],
                    'env' => $plan['env'],
                    'stdin' => $inHandle,
                ];
            }

            $result = pudba_run_command($cfg, $command, 'restore');
            fclose($inHandle);

            if ($result['ok']) {
                pudba_set_flash('success', 'Restore completed: ' . basename($resolved), [
                    'cmd' => $result['cmd_masked'],
                    'log' => $result['log_file'],
                ]);
            } else {
                pudba_set_flash('error', 'Restore failed (exit ' . $result['exit'] . '). See details.', [
                    'cmd' => $result['cmd_masked'],
                    'stderr' => $result['stderr'],
                    'stdout' => $result['stdout'],
                    'log' => $result['log_file'],
                ]);
            }
        } catch (Throwable $e) {
            pudba_set_flash('error', 'Restore error: ' . $e->getMessage());
        }

        header('Location: index.php?conn=' . urlencode($selectedKey));
        exit;
    }

    // Delete backup (confirmed)
    if ($action === 'delete_backup') {
        $filename = (string)($_POST['filename'] ?? '');
        $resolved = pudba_resolve_download_path($cfg, $filename);

        if (!$activeConn || empty($activeConn['db'])) {
            pudba_set_flash('error', 'Select a database before deleting backups.');
            header('Location: index.php');
            exit;
        }

        if (!$resolved || !is_file($resolved)) {
            pudba_set_flash('error', 'Delete failed: backup file not found or not allowed.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }

        $dbFolder = pudba_db_backup_dir($cfg, (string)$activeConn['db']);
        $dbFolderReal = realpath($dbFolder);
        $resolvedReal = realpath($resolved);
        if ($dbFolderReal && $resolvedReal && !str_starts_with($resolvedReal, $dbFolderReal . DIRECTORY_SEPARATOR)) {
            pudba_set_flash('error', 'Refusing delete: backup file is not in the selected DB folder.');
            header('Location: index.php?conn=' . urlencode($selectedKey));
            exit;
        }

        if (@unlink($resolved)) {
            pudba_set_flash('success', 'Backup deleted: ' . basename($resolved));
        } else {
            pudba_set_flash('error', 'Failed to delete backup file. Check file permissions.');
        }

        header('Location: index.php?conn=' . urlencode($selectedKey));
        exit;
    }

    pudba_set_flash('error', 'Unknown action.');
    header('Location: index.php?conn=' . urlencode($selectedKey));
    exit;
}

// Render page
$flash = pudba_get_flash();

$tables = [];
$tableErr = null;
$tableNotice = null;
if ($activeConn && !empty($activeConn['db'])) {
    try {
        $tables = pudba_list_tables($activeConn);
    } catch (Throwable $e) {
        $tableErr = $e->getMessage();
    }
} elseif ($selectedConn) {
    $tableNotice = 'Select a database to list tables.';
}

$canRunBackup = (bool)($activeConn && !empty($activeConn['db']));

$recent = pudba_list_recent_backups($cfg);
$retentionDays = (int)($cfg['retention_days'] ?? 0);
$recentPerPage = 6;
$recentPage = max(1, (int)($_GET['recent_page'] ?? 1));
$recentTotal = count($recent);
$recentPages = max(1, (int)ceil($recentTotal / $recentPerPage));
if ($recentPage > $recentPages) {
    $recentPage = $recentPages;
}
$recentOffset = ($recentPage - 1) * $recentPerPage;
$recentPageItems = array_slice($recent, $recentOffset, $recentPerPage);

$recentQueryBase = $_GET;
unset($recentQueryBase['recent_page']);

$connectionsByRef = [];
foreach ($connections as $conn) {
    $connRef = pudba_connection_ref(
        (string)($conn['host'] ?? ''),
        (int)($conn['port'] ?? 3306),
        (string)($conn['db'] ?? '')
    );
    if ($connRef !== '') {
        $connectionsByRef[$connRef] = $conn;
    }
}

$cronJobs = [];
$cronErr = null;
try {
    $crontabBin = pudba_find_binary(['crontab']);
    if ($crontabBin) {
        $cronJobs = pudba_parse_pudba_cron_jobs(pudba_read_crontab($crontabBin));
    } else {
        $cronErr = 'crontab is not available on this server.';
    }
} catch (Throwable $e) {
    $cronErr = $e->getMessage();
}

$dumpBin = pudba_find_binary(['mysqldump', 'mariadb-dump']) ?? '(not found)';
$mysqlBin = pudba_find_binary(['mysql', 'mariadb']) ?? '(not found)';
$gzipOk = ((bool)($cfg['enable_compression'] ?? true) && pudba_has_gzip()) ? 'yes' : 'no';

?>
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>PUDBA</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="wrap">
    <header class="topbar">
        <div class="brand">PolarForge Universal Database Backup Assistant</div>
        <div class="tag">
            Native MySQL/MariaDB backup manager
            <a class="link" href="?logout=1" title="Logout">Logout</a>
        </div>
    </header>

    <?php if ($flash): ?>
        <div class="msg <?= pudba_h($flash['type']) ?>">
            <div class="msg-row">
                <div>
                    <strong><?= pudba_h(strtoupper($flash['type'])) ?>:</strong>
                    <?= pudba_h($flash['message']) ?>
                </div>
                <?php if (!empty($flash['details'])): ?>
                    <button class="btn small" type="button" data-toggle="details">Details</button>
                <?php endif; ?>
            </div>
            <?php if (!empty($flash['details'])): ?>
                <div class="details" data-details hidden>
                    <pre><?php
                        $d = $flash['details'];
                        if (isset($d['cmd'])) echo "Command:\n" . $d['cmd'] . "\n\n";
                        if (isset($d['log'])) echo "Log:\n" . $d['log'] . "\n\n";
                        if (isset($d['stderr'])) echo "STDERR:\n" . $d['stderr'] . "\n\n";
                        if (isset($d['stdout'])) echo "STDOUT:\n" . $d['stdout'] . "\n\n";
                    ?></pre>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <div class="grid">
        <div class="card card-connection">
            <div class="card-head">
                <div>
                    <h2>Database</h2>
                    <div class="muted mini">Connect, test, and manage saved profiles.</div>
                </div>
                <button class="icon-btn" type="button" id="openAddConnection" aria-label="Add connection">
                    <span class="icon-plus" aria-hidden="true">+</span>
                </button>
            </div>

            <div class="card-section">
                <div class="section-head">
                    <h3>Connections</h3>
                </div>

                <?php if ($connections): ?>
                    <div class="connection-list">
                        <?php foreach ($connections as $k => $c): ?>
                            <div class="connection-item">
                                <div>
                                    <div class="connection-title">
                                        <?php
                                        $title = trim((string)($c['label'] ?? ''));
                                        if ($title === '') {
                                            $hostTitle = trim((string)($c['host'] ?? ''));
                                            $portTitle = trim((string)($c['port'] ?? ''));
                                            $title = $hostTitle;
                                            if ($hostTitle !== '' && $portTitle !== '') {
                                                $title .= ':' . $portTitle;
                                            }
                                            if ($title === '') {
                                                $title = 'Connection';
                                            }
                                        }
                                        ?>
                                        <span class="mono"><?= pudba_h($title) ?></span>
                                        <?php if ($k === $selectedKey): ?>
                                            <span class="active-badge">Active</span>
                                        <?php endif; ?>
                                    </div>
                                    <div class="muted mini">
                                        <?= pudba_h($c['host'] ?? '') ?>:<?= pudba_h((string)($c['port'] ?? '')) ?>
                                        · DB: <?= pudba_h(!empty($c['db']) ? (string)$c['db'] : 'All databases') ?>
                                    </div>
                                </div>
                                <div class="row">
                                    <?php if ($k !== $selectedKey): ?>
                                        <form method="post">
                                            <input type="hidden" name="action" value="select_connection">
                                            <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                                            <input type="hidden" name="conn_key" value="<?= pudba_h($k) ?>">
                                            <button class="btn small primary" type="submit">Use</button>
                                        </form>
                                    <?php endif; ?>
                                    <button class="btn small" type="button" data-edit-connection="<?= pudba_h($k) ?>">Edit</button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="muted">No connections yet. Use the plus button to add one.</div>
                <?php endif; ?>
            </div>

            <div class="divider"></div>

            <div class="card-section">
                <?php if ($selectedConn): ?>
                    <h3>Active connection</h3>
                    <div class="kv compact">
                        <div><span class="k">Host</span><span class="v"><?= pudba_h($selectedConn['host'] ?? '') ?>:<?= pudba_h((string)($selectedConn['port'] ?? '')) ?></span></div>
                        <div>
                            <span class="k">DB</span>
                            <span class="v">
                                <?php
                                $displayDbList = $dbList;
                                if (!$displayDbList && !empty($selectedConn['db'])) {
                                    $displayDbList = [(string)$selectedConn['db']];
                                }
                                ?>
                                <form method="post" class="inline-actions db-inline-actions">
                                    <input type="hidden" name="action" value="select_database">
                                    <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                                    <select name="db_select" class="select" <?= !empty($selectedConn['db']) ? 'disabled' : '' ?>>
                                        <?php if (!$displayDbList): ?>
                                            <option value="">No databases found</option>
                                        <?php endif; ?>
                                        <?php foreach ($displayDbList as $dbName): ?>
                                            <option value="<?= pudba_h($dbName) ?>" <?= $activeDb === $dbName ? 'selected' : '' ?>>
                                                <?= pudba_h($dbName) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                    <button class="btn small" type="submit" <?= (!empty($selectedConn['db']) || !$dbList) ? 'disabled' : '' ?>>Set</button>
                                </form>
                            </span>
                        </div>
                        <div><span class="k">User</span><span class="v"><?= pudba_h($selectedConn['user'] ?? '') ?></span></div>
                    </div>
                    <?php if ($dbErr): ?>
                        <div class="msg error">
                            <strong>ERROR:</strong> <?= pudba_h($dbErr) ?>
                        </div>
                    <?php endif; ?>

                    <div class="row">
                        <form method="post">
                            <input type="hidden" name="action" value="test_connection">
                            <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                            <button class="btn" type="submit">Test connection</button>
                        </form>
                        <div class="mini muted tool-line">
                            Dump: <code><?= pudba_h($dumpBin) ?></code> · Restore: <code><?= pudba_h($mysqlBin) ?></code> · gzip: <code><?= pudba_h($gzipOk) ?></code>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="card card-backup">
            <h2>Backup</h2>

            <?php if ($tableErr): ?>
                <div class="msg error">
                    <strong>ERROR:</strong> Failed listing tables: <?= pudba_h($tableErr) ?>
                </div>
            <?php elseif ($tableNotice): ?>
                <div class="msg">
                    <strong>NOTE:</strong> <?= pudba_h($tableNotice) ?>
                </div>
            <?php endif; ?>

            <form method="post" id="backupForm" class="form">
                <input type="hidden" name="action" value="backup">
                <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">

                <label>Scope</label>
                <div class="scope">
                    <label class="radio">
                        <input type="radio" name="scope" value="ALL" checked>
                        Entire database
                    </label>
                    <label class="radio">
                        <input type="radio" name="scope" value="TABLES">
                        Select Tables
                    </label>
                </div>

                <div id="tablesMulti" class="hidden">
                    <label>Select Tables</label>
                    <select name="tables[]" multiple size="8" class="select mono">
                        <?php foreach ($tables as $t): ?>
                            <option value="<?= pudba_h($t) ?>"><?= pudba_h($t) ?></option>
                        <?php endforeach; ?>
                    </select>
                    <div class="muted mini">Tip: Select one table, or Ctrl/Cmd-click to select multiple.</div>
                </div>

                <div class="row">
                    <button class="btn primary" type="submit" <?= $canRunBackup ? '' : 'disabled' ?>>Create backup</button>
                    <button class="btn" type="button" id="openCreateJob" <?= $canRunBackup ? '' : 'disabled' ?>>Create job</button>
                </div>
            </form>

            <h3 class="section-spacer">Scheduled jobs</h3>

            <?php if ($cronErr): ?>
                <div class="msg error">
                    <strong>ERROR:</strong> <?= pudba_h($cronErr) ?>
                </div>
            <?php elseif (!$cronJobs): ?>
                <div class="muted">No scheduled cron jobs found.</div>
            <?php else: ?>
                <div class="table">
                    <div class="thead">
                        <div>Name</div>
                        <div>Schedule</div>
                        <div>Actions</div>
                    </div>

                    <?php foreach ($cronJobs as $job): ?>
                        <div class="trow">
                            <div class="mono"><?= pudba_h(pudba_strip_cron_job_suffix($job['name'])) ?></div>
                            <div><?= pudba_h(pudba_human_cron_schedule($job['schedule'])) ?></div>
                            <div class="actions inline-actions">
                                <form method="post">
                                    <input type="hidden" name="action" value="run_cron_job">
                                    <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                                    <input type="hidden" name="job_name" value="<?= pudba_h($job['name']) ?>">
                                    <button class="btn small primary" type="submit">Run&nbsp;now</button>
                                </form>
                                <form method="post">
                                    <input type="hidden" name="action" value="delete_cron_job">
                                    <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                                    <input type="hidden" name="job_name" value="<?= pudba_h($job['name']) ?>">
                                    <button class="btn small danger" type="submit" data-cron-delete>Delete</button>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <div class="card">
        <div class="card-head">
            <h2>Recent backups</h2>
            <button class="icon-btn" type="button" id="openRetention" aria-label="Configure retention">
                <span class="icon-gear" aria-hidden="true">⚙</span>
            </button>
        </div>

        <?php if (!$recent): ?>
            <div class="muted">No backups found yet.</div>
        <?php else: ?>
            <div class="table">
                <div class="thead">
                    <div>Host</div>
                    <div>Database</div>
                    <div>Size</div>
                    <div>Date</div>
                    <div>Actions</div>
                </div>

                <?php foreach ($recentPageItems as $b): ?>
                    <?php
                    $fname = $b['filename'];
                    $created = date('Y-m-d H:i:s', (int)$b['mtime']);
                    $size = pudba_bytes_human((int)$b['size']);
                    $db = (string)($b['db'] ?? '');
                    $connKey = (string)($b['connection'] ?? '');
                    $parsedHost = (string)($b['parsed_host'] ?? '');
                    $parsedPort = (string)($b['parsed_port'] ?? '');
                    $parsedDb = (string)($b['parsed_db'] ?? '');
                    $host = '';
                    if ($connKey !== '' && isset($connectionsByRef[$connKey])) {
                        $host = (string)($connectionsByRef[$connKey]['host'] ?? '');
                        $port = (string)($connectionsByRef[$connKey]['port'] ?? '');
                        if ($host !== '' && $port !== '') {
                            $host .= ':' . $port;
                        }
                    } elseif ($parsedHost !== '') {
                        $host = $parsedHost;
                        if ($parsedPort !== '') {
                            $host .= ':' . $parsedPort;
                        }
                    }
                    if ($host === '') {
                        $host = '—';
                    }
                    $displayDb = $db;
                    if (($connKey === '' || !isset($connectionsByRef[$connKey])) && $parsedDb !== '') {
                        $displayDb = $parsedDb;
                    }
                    $inSelectedDb = $activeDb && ($db === (string)$activeDb);
                    $scopeLabel = null;
                    if (!empty($b['scope'])) {
                        $scopeLabel = $b['scope'] === 'ALL' ? 'All Tables' : 'Select Tables';
                    }
                    ?>
                    <div class="trow">
                        <div class="mono">
                            <?= pudba_h($host) ?>
                            <?php if ($scopeLabel): ?>
                                <div class="mini muted">
                                    <?= pudba_h($scopeLabel) ?>
                                    <?= !empty($b['compressed']) ? ' · gz' : '' ?>
                                </div>
                            <?php endif; ?>
                        </div>
                        <div><?= pudba_h($displayDb) ?></div>
                        <div><?= pudba_h($size) ?></div>
                        <div><?= pudba_h($created) ?></div>
                        <div class="actions">
                            <a class="btn small" href="?download=<?= urlencode($fname) ?>">Download</a>

                            <?php if ($selectedConn && $inSelectedDb): ?>
                                <button
                                    class="btn small primary"
                                    type="button"
                                    data-restore-btn
                                    data-filename="<?= pudba_h($fname) ?>"
                                >Restore</button>
                                <button
                                    class="btn small danger"
                                    type="button"
                                    data-delete-btn
                                    data-filename="<?= pudba_h($fname) ?>"
                                >Delete</button>
                            <?php else: ?>
                                <span class="muted mini">Select DB <code><?= pudba_h($db) ?></code> to restore</span>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
            <?php if ($recentPages > 1): ?>
                <div class="pagination">
                    <div class="muted mini">
                        Page <?= pudba_h((string)$recentPage) ?> of <?= pudba_h((string)$recentPages) ?>
                    </div>
                    <div class="pagination-links">
                        <?php
                        $recentPrev = $recentPage - 1;
                        $recentNext = $recentPage + 1;
                        $recentBase = 'index.php';
                        $recentPrevQuery = $recentQueryBase;
                        $recentPrevQuery['recent_page'] = $recentPrev;
                        $recentNextQuery = $recentQueryBase;
                        $recentNextQuery['recent_page'] = $recentNext;
                        $recentPrevHref = $recentPrev >= 1 ? $recentBase . '?' . http_build_query($recentPrevQuery) : '';
                        $recentNextHref = $recentNext <= $recentPages ? $recentBase . '?' . http_build_query($recentNextQuery) : '';
                        ?>
                        <a class="btn small <?= $recentPrevHref ? '' : 'ghost disabled' ?>"
                           href="<?= pudba_h($recentPrevHref ?: '#') ?>"
                           <?= $recentPrevHref ? '' : 'aria-disabled="true"' ?>>Prev</a>
                        <a class="btn small <?= $recentNextHref ? '' : 'ghost disabled' ?>"
                           href="<?= pudba_h($recentNextHref ?: '#') ?>"
                           <?= $recentNextHref ? '' : 'aria-disabled="true"' ?>>Next</a>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>

    </div>

    <div class="modal hidden" id="retentionModal" hidden>
        <div class="modal-card">
            <div class="modal-head">
                <h3>Configure retention</h3>
                <button class="btn small ghost" type="button" data-modal-close>Close</button>
            </div>
            <p class="muted">
                Set how many days of backups to keep. Use <strong>0</strong> to disable pruning.
            </p>
            <form method="post" class="form compact">
                <input type="hidden" name="action" value="update_retention">
                <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">

                <label for="retentionDays">Retention period (days)</label>
                <input id="retentionDays" name="retention_days" type="number" min="0" value="<?= pudba_h((string)$retentionDays) ?>" required>

                <div class="row">
                    <button class="btn primary" type="submit">Save retention</button>
                    <span class="muted mini">Pruning runs whenever a backup is created.</span>
                </div>
            </form>
        </div>
    </div>

    <!-- Restore confirm modal -->
    <div class="modal hidden" id="restoreModal" hidden>
                <div class="modal-card">
            <h3>Confirm restore</h3>
            <p>
                This will restore the selected backup into:
                <strong><?= pudba_h($activeDb ?? '') ?></strong>
                <?php if (!empty($selectedConn['host'])): ?>
                    (<?= pudba_h($selectedConn['host']) ?><?= !empty($selectedConn['port']) ? ':' . pudba_h((string)$selectedConn['port']) : '' ?>)
                <?php endif; ?>
            </p>
            <p class="muted">
                Make sure you understand this will overwrite existing data depending on the SQL contents.
            </p>

            <form method="post" class="row" id="restoreForm">
                <input type="hidden" name="action" value="restore_confirmed">
                <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                <input type="hidden" name="filename" id="restoreFilename" value="">
                <button class="btn primary" type="submit">Yes, restore</button>
                <button class="btn" type="button" id="restoreCancel">Cancel</button>
            </form>

            <div class="muted mini mono" id="restoreFileLabel"></div>
        </div>
    </div>

    <!-- Delete confirm modal -->
    <div class="modal hidden" id="deleteModal" hidden>
        <div class="modal-card">
            <h3>Confirm delete</h3>
            <p>
                This will permanently delete the selected backup file from disk.
            </p>
            <p class="muted">
                This cannot be undone.
            </p>

            <form method="post" class="row" id="deleteForm">
                <input type="hidden" name="action" value="delete_backup">
                <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                <input type="hidden" name="filename" id="deleteFilename" value="">
                <button class="btn danger" type="submit">Yes, delete</button>
                <button class="btn" type="button" id="deleteCancel">Cancel</button>
            </form>

            <div class="muted mini mono" id="deleteFileLabel"></div>
        </div>
    </div>

    <!-- Create job modal -->
    <div class="modal hidden" id="createJobModal" hidden>
        <div class="modal-card">
            <div class="modal-head">
                <h3>Create backup job</h3>
                <button class="btn small ghost" type="button" data-modal-close>Close</button>
            </div>
            <p class="muted">
                This job will back up <strong><?= pudba_h($activeDb ?? '') ?></strong>
                <?php if (!empty($selectedConn['host'])): ?>
                    (<?= pudba_h($selectedConn['host']) ?><?= !empty($selectedConn['port']) ? ':' . pudba_h((string)$selectedConn['port']) : '' ?>)
                <?php endif; ?>
                on the selected schedule.
            </p>
            <form method="post" class="form compact">
                <input type="hidden" name="action" value="create_job">
                <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">

                <label for="jobName">Job name</label>
                <input id="jobName" name="job_name" required maxlength="64" placeholder="Nightly backup">

                <label for="jobSchedule">Schedule</label>
                <select id="jobSchedule" name="schedule" required>
                    <option value="hourly">Hourly</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                </select>

                <div class="row">
                    <button class="btn primary" type="submit" <?= $canRunBackup ? '' : 'disabled' ?>>Create job</button>
                    <span class="muted mini">Uses the active connection and current backup settings.</span>
                </div>
            </form>
        </div>
    </div>

    <div class="modal hidden" id="addConnectionModal" hidden>
        <div class="modal-card">
            <div class="modal-head">
                <h3>Add connection</h3>
                <button class="btn small ghost" type="button" data-modal-close>Close</button>
            </div>
            <form method="post" class="form compact">
                <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">

                <div class="form-grid">
                    <div class="field">
                        <label for="addLabel">Label</label>
                        <input name="label" id="addLabel" placeholder="Friendly name (optional)">
                    </div>

                    <div class="field">
                        <div class="label-row">
                            <label for="addHost">Host</label>
                        </div>
                        <input name="host" id="addHost" required placeholder="127.0.0.1">
                    </div>

                    <div class="field">
                        <label for="addUser">User</label>
                        <input name="user" id="addUser" required>
                    </div>

                    <div class="field">
                        <div class="label-row">
                            <label for="addPass">Password</label>
                        </div>
                        <input name="pass" id="addPass" type="password">
                    </div>

                    <div class="field">
                        <div class="label-row">
                            <label for="addDb">Database (optional)</label>
                        </div>
                        <input name="db" id="addDb" placeholder="Leave blank to choose per run">
                    </div>
                </div>

                <div class="row">
                    <button class="btn primary" type="submit" name="action" value="add_connection">Add connection</button>
                    <button class="btn small ghost advanced-toggle" type="button" aria-expanded="false" aria-controls="addAdvanced">
                        Advanced <span class="chevron" aria-hidden="true">▾</span>
                    </button>
                </div>

                <div class="advanced" id="addAdvanced" hidden>
                    <div class="form-grid">
                        <div class="field">
                            <label for="addPort">Port</label>
                            <input name="port" id="addPort" type="number" min="1" value="3306" required>
                        </div>

                        <div class="field">
                            <label for="addCharset">Charset</label>
                            <input name="charset" id="addCharset" value="utf8mb4">
                        </div>

                        <div class="field field-full">
                            <div class="label-row">
                                <span class="muted mini">Connection key</span>
                            </div>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <div class="modal hidden" id="editConnectionModal" hidden>
        <div class="modal-card">
            <div class="modal-head">
                <h3>Edit connection</h3>
                <button class="btn small ghost" type="button" data-modal-close>Close</button>
            </div>
            <form method="post" class="form compact" id="editConnectionForm">
                <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                <input type="hidden" name="conn_key" id="editConnKey">

                <div class="form-grid">
                    <div class="field">
                        <label for="editLabel">Label</label>
                        <input name="label" id="editLabel" placeholder="Friendly name (optional)">
                    </div>

                    <div class="field">
                        <div class="label-row">
                            <label for="editHost">Host</label>
                        </div>
                        <input name="host" id="editHost" required>
                    </div>

                    <div class="field">
                        <label for="editUser">User</label>
                        <input name="user" id="editUser" required>
                    </div>

                    <div class="field">
                        <div class="label-row">
                            <label for="editPass">New password</label>
                        </div>
                        <input name="pass" id="editPass" type="password" placeholder="Leave blank to keep current">
                    </div>

                    <div class="field field-full">
                        <label class="radio" for="editClearPass">
                            <input type="checkbox" name="clear_pass" id="editClearPass">
                            Clear stored password
                        </label>
                    </div>

                    <div class="field">
                        <div class="label-row">
                            <label for="editDb">Database (optional)</label>
                        </div>
                        <input name="db" id="editDb" placeholder="Leave blank to choose per run">
                    </div>
                </div>

                <div class="row">
                    <button class="btn primary" type="submit" name="action" value="update_connection" <?= $connections ? '' : 'disabled' ?>>Save changes</button>
                    <button class="btn small ghost advanced-toggle" type="button" aria-expanded="false" aria-controls="editAdvanced" <?= $connections ? '' : 'disabled' ?>>
                        Advanced <span class="chevron" aria-hidden="true">▾</span>
                    </button>
                </div>

                <div class="advanced" id="editAdvanced" hidden>
                    <div class="form-grid">
                        <div class="field">
                            <label for="editPort">Port</label>
                            <input name="port" id="editPort" type="number" min="1" required>
                        </div>

                        <div class="field">
                            <label for="editCharset">Charset</label>
                            <input name="charset" id="editCharset">
                        </div>

                        <div class="field field-full">
                            <div class="label-row">
                                <span class="muted mini">Connection key</span>
                            </div>
                        </div>
                    </div>
                </div>
            </form>

            <form method="post" class="row" id="deleteConnectionForm">
                <input type="hidden" name="action" value="delete_connection">
                <input type="hidden" name="csrf" value="<?= pudba_h(pudba_csrf_token()) ?>">
                <input type="hidden" name="conn_key" id="deleteConnKey" value="">
                <button class="btn danger" type="submit" <?= $connections ? '' : 'disabled' ?>>Remove connection</button>
                <span class="muted mini">Removing a connection does not delete existing backups.</span>
            </form>
        </div>
    </div>

    <div class="footer muted">
        PUDBA by <a class="footer-link" href="https://www.rickgouin.com" target="_blank" rel="noopener noreferrer">Rick Gouin</a>
    </div>
</div>

<script>
(function () {
    // flash details toggle
    document.querySelectorAll('[data-toggle="details"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const details = btn.closest('.msg').querySelector('[data-details]');
            if (!details) return;
            details.hidden = !details.hidden;
            btn.textContent = details.hidden ? 'Details' : 'Hide details';
        });
    });

    // Backup scope toggles
    const form = document.getElementById('backupForm');
    const multi = document.getElementById('tablesMulti');
    function updateScope() {
        const scope = form.querySelector('input[name="scope"]:checked')?.value || 'ALL';
        multi.classList.toggle('hidden', scope !== 'TABLES');
    }

    form.querySelectorAll('input[name="scope"]').forEach(r => r.addEventListener('change', updateScope));
    updateScope();

    document.querySelectorAll('.advanced-toggle').forEach(btn => {
        const targetId = btn.getAttribute('aria-controls');
        const target = targetId ? document.getElementById(targetId) : null;
        if (!target) return;
        btn.addEventListener('click', () => {
            const expanded = btn.getAttribute('aria-expanded') === 'true';
            btn.setAttribute('aria-expanded', expanded ? 'false' : 'true');
            target.hidden = expanded;
        });
    });

    // Restore confirmation modal
    const modal = document.getElementById('restoreModal');
    const cancel = document.getElementById('restoreCancel');
    const fnameInput = document.getElementById('restoreFilename');
    const label = document.getElementById('restoreFileLabel');
    const deleteModal = document.getElementById('deleteModal');
    const deleteCancel = document.getElementById('deleteCancel');
    const deleteInput = document.getElementById('deleteFilename');
    const deleteLabel = document.getElementById('deleteFileLabel');

    const connectionData = <?= json_encode($connections, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    const deleteKey = document.getElementById('deleteConnKey');
    const editLabel = document.getElementById('editLabel');
    const editHost = document.getElementById('editHost');
    const editPort = document.getElementById('editPort');
    const editUser = document.getElementById('editUser');
    const editPass = document.getElementById('editPass');
    const editDb = document.getElementById('editDb');
    const editCharset = document.getElementById('editCharset');
    const editClearPass = document.getElementById('editClearPass');

    function populateEditForm(key) {
        const data = connectionData[key];
        if (!data) return;
        editLabel.value = data.label || '';
        editHost.value = data.host || '';
        editPort.value = data.port || 3306;
        editUser.value = data.user || '';
        editPass.value = '';
        editDb.value = data.db || '';
        editCharset.value = data.charset || 'utf8mb4';
        editClearPass.checked = false;
        deleteKey.value = key || '';
    }

    function connectionSummary(key) {
        const data = connectionData[key] || {};
        const labelText = (data.label || '').trim();
        if (labelText) {
            return labelText;
        }
        const host = (data.host || '').trim();
        const port = data.port || '';
        const db = (data.db || '').trim();
        let summary = host ? host + (port ? ':' + port : '') : '';
        if (db) {
            summary = summary ? summary + ' · ' + db : db;
        } else {
            summary = summary ? summary + ' · All databases' : 'All databases';
        }
        return summary || 'this connection';
    }

    const deleteForm = document.getElementById('deleteConnectionForm');
    if (deleteForm) {
        deleteForm.addEventListener('submit', (e) => {
            if (!deleteKey.value) return;
            const ok = confirm('Remove connection "' + connectionSummary(deleteKey.value) + '"? This cannot be undone.');
            if (!ok) {
                e.preventDefault();
            }
        });
    }

    document.querySelectorAll('[data-cron-delete]').forEach(btn => {
        const form = btn.closest('form');
        if (!form) return;
        form.addEventListener('submit', (e) => {
            const name = form.querySelector('input[name="job_name"]')?.value || 'this cron job';
            const ok = confirm('Delete cron job "' + name + '"?');
            if (!ok) {
                e.preventDefault();
            }
        });
    });

    function openRestoreModal(filename) {
        fnameInput.value = filename || '';
        label.textContent = 'Backup file: ' + (filename || '');
        modal.hidden = false;
        modal.classList.remove('hidden');
    }

    function closeRestoreModal() {
        modal.hidden = true;
        modal.classList.add('hidden');
        fnameInput.value = '';
    }

    function openDeleteModal(filename) {
        deleteInput.value = filename || '';
        deleteLabel.textContent = 'Backup file: ' + (filename || '');
        deleteModal.hidden = false;
        deleteModal.classList.remove('hidden');
    }

    function closeDeleteModal() {
        deleteModal.hidden = true;
        deleteModal.classList.add('hidden');
        deleteInput.value = '';
    }

    const addModal = document.getElementById('addConnectionModal');
    const editModal = document.getElementById('editConnectionModal');
    const jobModal = document.getElementById('createJobModal');
    const retentionModal = document.getElementById('retentionModal');
    const openAddBtn = document.getElementById('openAddConnection');
    const openJobBtn = document.getElementById('openCreateJob');
    const openRetentionBtn = document.getElementById('openRetention');
    const editKeyInput = document.getElementById('editConnKey');

    function openModal(target) {
        if (!target) return;
        target.hidden = false;
        target.classList.remove('hidden');
    }

    function closeModal(target) {
        if (!target) return;
        target.hidden = true;
        target.classList.add('hidden');
    }

    if (openAddBtn) {
        openAddBtn.addEventListener('click', () => openModal(addModal));
    }
    if (openJobBtn) {
        openJobBtn.addEventListener('click', () => openModal(jobModal));
    }
    if (openRetentionBtn) {
        openRetentionBtn.addEventListener('click', () => openModal(retentionModal));
    }

    document.querySelectorAll('[data-modal-close]').forEach(btn => {
        btn.addEventListener('click', () => {
            closeModal(addModal);
            closeModal(editModal);
            closeModal(jobModal);
            closeModal(retentionModal);
        });
    });

    document.querySelectorAll('[data-edit-connection]').forEach(btn => {
        btn.addEventListener('click', () => {
            const key = btn.getAttribute('data-edit-connection') || '';
            if (!key) return;
            populateEditForm(key);
            if (editKeyInput) {
                editKeyInput.value = key;
            }
            openModal(editModal);
        });
    });

    [addModal, editModal, jobModal, retentionModal].forEach(target => {
        if (!target) return;
        target.addEventListener('click', (e) => {
            if (e.target === target) {
                closeModal(target);
            }
        });
    });

    document.querySelectorAll('[data-restore-btn]').forEach(btn => {
        btn.addEventListener('click', () => {
            const fn = btn.getAttribute('data-filename');
            openRestoreModal(fn || '');
        });
    });

    document.querySelectorAll('[data-delete-btn]').forEach(btn => {
        btn.addEventListener('click', () => {
            const fn = btn.getAttribute('data-filename');
            openDeleteModal(fn || '');
        });
    });

    cancel.addEventListener('click', () => {
        closeRestoreModal();
    });

    deleteCancel.addEventListener('click', () => {
        closeDeleteModal();
    });

    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeRestoreModal();
        }
    });

    deleteModal.addEventListener('click', (e) => {
        if (e.target === deleteModal) {
            closeDeleteModal();
        }
    });

    closeRestoreModal();
    closeDeleteModal();
    closeModal(addModal);
    closeModal(editModal);
    closeModal(jobModal);
    closeModal(retentionModal);
})();
</script>
</body>
</html>
