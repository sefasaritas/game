<?php
require_once 'config/database.php';
session_start();

// Zaten giriş yapmış kullanıcıyı oyuna yönlendir
if (isset($_SESSION['user_token'])) {
    header("Location: game.php");
    exit;
}

$error = $_GET['error'] ?? '';
$success = $_GET['success'] ?? '';

// POST isteği kontrolü
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $database = new Database();
        $db = $database->getConnection();
        $sessionManager = new SessionManager($db);
        
        // Form verilerini al ve temizle
        $username = Security::sanitizeInput($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $rememberMe = isset($_POST['remember_me']);
        
        // Doğrulama
        if (empty($username) || empty($password)) {
            $error = "Kullanıcı adı ve şifre gereklidir.";
        } else {
            // Kullanıcıyı bul
            $query = "SELECT id, username, email, password_hash, is_active, is_verified 
                      FROM users 
                      WHERE (username = :username OR email = :username) AND is_active = 1";
            
            $stmt = $db->prepare($query);
            $stmt->bindParam(':username', $username);
            $stmt->execute();
            
            $user = $stmt->fetch();
            
            if ($user && Security::verifyPassword($password, $user['password_hash'])) {
                // Başarılı giriş
                $sessionToken = $sessionManager->createSession($user['id']);
                
                // Oturum verilerini ayarla
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['user_token'] = $sessionToken;
                
                // Remember me için cookie ayarla
                if ($rememberMe) {
                    $cookieExpiry = time() + (30 * 24 * 60 * 60); // 30 gün
                    setcookie('user_token', $sessionToken, $cookieExpiry, '/', '', true, true);
                }
                
                // Son giriş zamanını güncelle
                $updateQuery = "UPDATE users SET last_login = NOW() WHERE id = :user_id";
                $updateStmt = $db->prepare($updateQuery);
                $updateStmt->bindParam(':user_id', $user['id']);
                $updateStmt->execute();
                
                // Oyuna yönlendir
                header("Location: game.php");
                exit;
            } else {
                $error = "Kullanıcı adı veya şifre hatalı.";
            }
        }