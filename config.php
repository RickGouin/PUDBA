<?php
/**
 * PUDBA config
 * - No external dependencies
 * - This file is written by PUDBA during initial auth setup
 */

$CONFIG = [
    // Where PUDBA will store files
    'data_dir' => __DIR__ . '/data',
    'backup_dir' => __DIR__ . '/data/backups',
    'log_dir' => __DIR__ . '/data/logs',

    // Recent backups list limit
    'recent_backups_max' => 25,

    // Retention window in days (0 disables pruning)
    'retention_days' => 30,

    // Prefer compression when possible (gzip)
    'enable_compression' => true,

    // Optional: extra mysqldump options
    'dump_options' => [
        '--single-transaction',
        '--routines',
        '--triggers',
        '--events',
        '--add-drop-table',
        '--set-gtid-purged=OFF',
    ],

    // Connections: add as many as you like
    // NOTE: PUDBA will NOT store DB data; this is just connection config.
    'connections' => [
        '127.0.0.1-mydb' => [
            'label' => 'Local MySQL',
            'host' => '127.0.0.1',
            'port' => 3306,
            'user' => 'root',
            'pass' => '',
            'db'   => 'mydb',
            'charset' => 'utf8mb4',
        ],
        // 'prod' => [
        //     'label' => 'Production',
        //     'host' => 'db.example.com',
        //     'port' => 3306,
        //     'user' => 'backup_user',
        //     'pass' => 'secret',
        //     'db'   => 'prod_db',
        //     'charset' => 'utf8mb4',
        // ],
    ],

    // Auth hashes (auto-created on first run)
    // 'auth_user_hash' => '...',
    // 'auth_pass_hash' => '...',
];

return $CONFIG;
