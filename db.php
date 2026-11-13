<?php
// Configuration Settings for XAMPP
$host     = '127.0.0.1';
$db       = 'siargao_lost_found_db';
$user     = 'root';      // Default XAMPP username
$pass     = '';          // Default XAMPP password (blank)
$charset  = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";

$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    error_log($e->getMessage());
    exit(json_encode(['success' => false, 'message' => 'Database connection failed.']));
}
?>