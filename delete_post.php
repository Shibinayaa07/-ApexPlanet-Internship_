<?php
session_start();
require_once 'db.php';

// Role check: only editors/admins can delete
if (!isset($_SESSION['username'], $_SESSION['role']) || !in_array($_SESSION['role'], ['admin', 'editor'])) {
    header("Location: login.php");
    exit;
}

// Validate ID
if (!isset($_GET['id']) || !ctype_digit($_GET['id'])) {
    die('Invalid post ID.');
}

$id = (int) $_GET['id'];

// Optional: check ownership or post existence
$stmt = $pdo->prepare("DELETE FROM posts WHERE id = ?");
$stmt->execute([$id]);

header("Location: view_posts.php");
exit;
