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
        
    } catch (Exception $e) {
        error_log("Giriş hatası: " . $e->getMessage());
        $error = "Bir hata oluştu. Lütfen tekrar deneyin.";
    }
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Giriş Yap - Ticaret Hanı</title>
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
        
        .checkbox-group {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
            margin-right: 10px;
            transform: scale(1.2);
            accent-color: #d4af37;
        }
        
        .checkbox-group label {
            margin: 0;
            cursor: pointer;
            user-select: none;
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
        
        .game-title {
            text-align: center;
            margin-bottom: 20px;
            font-size: 3em;
        }
        
        .forgot-password {
            text-align: center;
            margin-top: 15px;
        }
        
        .forgot-password a {
            color: rgba(244, 228, 193, 0.8);
            text-decoration: none;
            font-size: 14px;
        }
        
        .forgot-password a:hover {
            color: #d4af37;
        }
        
        .demo-login {
            background: rgba(52, 152, 219, 0.2);
            border: 1px solid #3498db;
            border-radius: 6px;
            padding: 10px;
            margin-bottom: 20px;
            font-size: 14px;
            text-align: center;
            color: #3498db;
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
            <h1>Giriş Yap</h1>
            <p>Ticaret Hanı'na hoş geldiniz!</p>
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-error"><?php echo $error; ?></div>
        <?php endif; ?>
        
        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo $success; ?></div>
        <?php endif; ?>
        
        <div class="demo-login">
            <strong>💡 Demo Kullanıcısı:</strong><br>
            Kullanıcı adı: <code>demo</code> | Şifre: <code>demo123</code>
        </div>
        
        <form method="POST" action="login.php">
            <div class="form-group">
                <label for="username">Kullanıcı Adı veya E-posta</label>
                <input type="text" id="username" name="username" required
                       placeholder="Kullanıcı adı veya e-posta adresinizi giriniz"
                       value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>">
            </div>
            
            <div class="form-group">
                <label for="password">Şifre</label>
                <input type="password" id="password" name="password" required
                       placeholder="Şifrenizi giriniz">
            </div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="remember_me" name="remember_me">
                <label for="remember_me">Beni hatırla (30 gün)</label>
            </div>
            
            <button type="submit" class="submit-button">
                🚪 Giriş Yap ve Ticarete Devam Et!
            </button>
        </form>
        
        <div class="forgot-password">
            <a href="forgot-password.php">Şifremi unuttum</a>
        </div>
        
        <div class="auth-links">
            Henüz hesabınız yok mu? 
            <a href="register.php">Kayıt Ol</a>
        </div>
        
        <div class="auth-links" style="margin-top: 30px;">
            <a href="index.html">🎮 Misafir olarak oyna</a>
        </div>
    </div>
    
    <script>
        // Form otomatik tamamlama için demo verileri
        document.addEventListener('DOMContentLoaded', function() {
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.get('demo') === '1') {
                document.getElementById('username').value = 'demo';
                document.getElementById('password').value = 'demo123';
            }
        });
        
        // Enter tuşu ile form gönderimi
        document.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                document.querySelector('form').submit();
            }
        });
        
        // Kullanıcı adı alanında boşluk temizleme
        document.getElementById('username').addEventListener('input', function() {
            this.value = this.value.trim();
        });
    </script>
</body>
</html>