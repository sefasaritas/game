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
        
        // Form verilerini al ve temizle
        $username = Security::sanitizeInput($_POST['username'] ?? '');
        $email = Security::sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        // Doğrulama
        $errors = [];
        
        if (empty($username) || strlen($username) < 3) {
            $errors[] = "Kullanıcı adı en az 3 karakter olmalıdır.";
        }
        
        if (strlen($username) > 50) {
            $errors[] = "Kullanıcı adı 50 karakterden uzun olamaz.";
        }
        
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            $errors[] = "Kullanıcı adı sadece harf, rakam ve alt çizgi içerebilir.";
        }
        
        if (empty($email) || !Security::validateEmail($email)) {
            $errors[] = "Geçerli bir e-posta adresi giriniz.";
        }
        
        if (empty($password) || !Security::isStrongPassword($password)) {
            $errors[] = "Şifre en az 8 karakter olmalı ve büyük harf, küçük harf, rakam içermelidir.";
        }
        
        if ($password !== $confirmPassword) {
            $errors[] = "Şifreler eşleşmiyor.";
        }
        
        // Kullanıcı adı ve e-posta kontrolü
        if (empty($errors)) {
            $checkQuery = "SELECT id FROM users WHERE username = :username OR email = :email";
            $checkStmt = $db->prepare($checkQuery);
            $checkStmt->bindParam(':username', $username);
            $checkStmt->bindParam(':email', $email);
            $checkStmt->execute();
            
            if ($checkStmt->fetch()) {
                $errors[] = "Bu kullanıcı adı veya e-posta adresi zaten kullanılıyor.";
            }
        }
        
        if (!empty($errors)) {
            $error = implode('<br>', $errors);
        } else {
            // Kullanıcıyı kaydet
            $passwordHash = Security::hashPassword($password);
            $verificationToken = Security::generateToken();
            
            $insertQuery = "INSERT INTO users (username, email, password_hash, verification_token) 
                           VALUES (:username, :email, :password_hash, :verification_token)";
            
            $insertStmt = $db->prepare($insertQuery);
            $insertStmt->bindParam(':username', $username);
            $insertStmt->bindParam(':email', $email);
            $insertStmt->bindParam(':password_hash', $passwordHash);
            $insertStmt->bindParam(':verification_token', $verificationToken);
            
            if ($insertStmt->execute()) {
                $success = "Kayıt başarılı! Şimdi giriş yapabilirsiniz.";
                // Başarılı kayıt sonrası login sayfasına yönlendir
                header("Location: login.php?success=" . urlencode($success));
                exit;
            } else {
                $error = "Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.";
            }
        }
        
    } catch (Exception $e) {
        error_log("Kayıt hatası: " . $e->getMessage());
        $error = "Bir hata oluştu. Lütfen tekrar deneyin.";
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kayıt Ol - Ticaret Hanı</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #2c1810 0%, #4a2c17 100%);
            color: #f4e4c1;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .auth-container {
            background: rgba(0,0,0,0.4);
            border-radius: 15px;
            padding: 40px;
            border: 2px solid #d4af37;
            max-width: 400px;
            width: 100%;
            margin: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        
        .auth-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .auth-header h1 {
            color: #d4af37;
            font-size: 2.2em;
            margin: 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }
        
        .auth-header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #d4af37;
            font-weight: bold;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #8b6914;
            border-radius: 8px;
            background: rgba(244, 228, 193, 0.1);
            color: #f4e4c1;
            font-size: 16px;
            transition: border-color 0.3s ease;
            box-sizing: border-box;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #d4af37;
            background: rgba(244, 228, 193, 0.2);
        }
        
        .form-group input::placeholder {
            color: rgba(244, 228, 193, 0.6);
        }
        
        .submit-button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(45deg, #d4af37, #f4e4c1);
            border: 2px solid #8b6914;
            border-radius: 8px;
            color: #2c1810;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 20px;
        }
        
        .submit-button:hover {
            background: linear-gradient(45deg, #f4e4c1, #d4af37);
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(212, 175, 55, 0.3);
        }
        
        .submit-button:active {
            transform: translateY(0);
        }
        
        .auth-links {
            text-align: center;
            margin-top: 20px;
        }
        
        .auth-links a {
            color: #d4af37;
            text-decoration: none;
            font-weight: bold;
            transition: color 0.3s ease;
        }
        
        .auth-links a:hover {
            color: #f4e4c1;
        }
        
        .alert {
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-weight: bold;
        }
        
        .alert-error {
            background: rgba(231, 76, 60, 0.2);
            border: 1px solid #e74c3c;
            color: #e74c3c;
        }
        
        .alert-success {
            background: rgba(39, 174, 96, 0.2);
            border: 1px solid #27ae60;
            color: #27ae60;
        }
        
        .password-requirements {
            font-size: 12px;
            color: rgba(244, 228, 193, 0.7);
            margin-top: 5px;
        }
        
        .game-title {
            text-align: center;
            margin-bottom: 20px;
            font-size: 3em;
        }
        
        @media (max-width: 480px) {
            .auth-container {
                padding: 20px;
                margin: 10px;
            }
            
            .auth-header h1 {
                font-size: 1.8em;
            }
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="game-title">🏛️</div>
        <div class="auth-header">
            <h1>Kayıt Ol</h1>
            <p>Ticaret Hanı'na hoş geldiniz!</p>
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-error"><?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo $success; ?></div>
        <?php endif; ?>
        
        <form method="POST" action="register.php">
            <div class="form-group">
                <label for="username">Kullanıcı Adı</label>
                <input type="text" id="username" name="username" required
                       placeholder="Kullanıcı adınızı giriniz"
                       value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                       minlength="3" maxlength="50" pattern="[a-zA-Z0-9_]+">
            </div>
            
            <div class="form-group">
                <label for="email">E-posta Adresi</label>
                <input type="email" id="email" name="email" required
                       placeholder="E-posta adresinizi giriniz"
                       value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
            </div>
            
            <div class="form-group">
                <label for="password">Şifre</label>
                <input type="password" id="password" name="password" required
                       placeholder="Şifrenizi giriniz" minlength="8">
                <div class="password-requirements">
                    En az 8 karakter, büyük harf, küçük harf ve rakam içermelidir.
                </div>
            </div>
            
            <div class="form-group">
                <label for="confirm_password">Şifre Tekrar</label>
                <input type="password" id="confirm_password" name="confirm_password" required
                       placeholder="Şifrenizi tekrar giriniz" minlength="8">
            </div>
            
            <button type="submit" class="submit-button">
                🎯 Kayıt Ol ve Ticarete Başla!
            </button>
        </form>
        
        <div class="auth-links">
            Zaten hesabınız var mı? 
            <a href="login.php">Giriş Yap</a>
        </div>
    </div>
    
    <script>
        // Şifre eşleşme kontrolü
        document.getElementById('confirm_password').addEventListener('input', function() {
            const password = document.getElementById('password').value;
            const confirmPassword = this.value;
            
            if (password !== confirmPassword) {
                this.setCustomValidity('Şifreler eşleşmiyor');
            } else {
                this.setCustomValidity('');
            }
        });
        
        // Şifre güçlülük kontrolü
        document.getElementById('password').addEventListener('input', function() {
            const password = this.value;
            const isStrong = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/.test(password);
            
            if (password.length > 0 && !isStrong) {
                this.setCustomValidity('Şifre en az 8 karakter olmalı ve büyük harf, küçük harf, rakam içermelidir');
            } else {
                this.setCustomValidity('');
            }
        });
    </script>
</body>
</html>