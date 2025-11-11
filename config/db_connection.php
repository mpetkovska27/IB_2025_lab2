<?php
function connectDatabase(): SQLite3 {
    $dbDir = __DIR__ . '/../database';
    if (!is_dir($dbDir)) {
        mkdir($dbDir, 0755, true);
    }
    $db = new SQLite3($dbDir . '/db.sqlite');
    initializeDatabase($db);
    return $db;
}

function initializeDatabase($db) {
    $createTableQuery = <<<SQL
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    email_verified INTEGER DEFAULT 0,
    email_verification_code TEXT,
    email_verification_expires DATETIME,
    two_factor_code TEXT,
    two_factor_code_expires DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
SQL;
    if (!$db->exec($createTableQuery)) {
        echo "Error creating table: " . $db->lastErrorMsg();
    }
}
