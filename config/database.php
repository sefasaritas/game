<?php
// Veritabanı konfigürasyonu
class Database {
    private $host = 'localhost';
    private $db_name = 'sql_game';
    private $username = 'sql_game'; // Veritabanı kullanıcı adınızı buraya yazın
    private $password = 'pLKYWdStt2dJzF2D'; // Veritabanı şifrenizi buraya yazın
    private $charset = 'utf8mb4';
    private $conn;
    
    public function getConnection() {
        $this->conn = null;
        
        try {
            $dsn = "mysql:host=" . $this->host . ";dbname=" . $this->db_name . ";charset=" . $this->charset;
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
            ];
            
            $this->conn = new PDO($dsn, $this->username, $this->password, $options);
        } catch(PDOException $exception) {
            error_log("Veritabanı bağlantı hatası: " . $exception->getMessage());
            throw new Exception("Veritabanı bağlantısı kurulamadı.");
        }
        
        return $this->conn;
    }
}

// Güvenlik ayarları
class Security {
    public static function generateToken($length = 32) {
        return bin2hex(random_bytes($length));
    }
    
    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64 MB
            'time_cost' => 4,       // 4 iterations
            'threads' => 3,         // 3 threads
        ]);
    }
    
    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    public static function sanitizeInput($input) {
        return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
    }
    
    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }
    
    public static function isStrongPassword($password) {
        // En az 8 karakter, büyük harf, küçük harf, rakam
        return preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/', $password);
    }
}

// Oturum yönetimi
class SessionManager {
    private $db;
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    public function createSession($userId) {
        $token = Security::generateToken();
        $expiresAt = date('Y-m-d H:i:s', strtotime('+30 days'));
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        
        $query = "INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent) 
                  VALUES (:user_id, :token, :expires_at, :ip_address, :user_agent)";
        
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(':user_id', $userId);
        $stmt->bindParam(':token', $token);
        $stmt->bindParam(':expires_at', $expiresAt);
        $stmt->bindParam(':ip_address', $ipAddress);
        $stmt->bindParam(':user_agent', $userAgent);
        $stmt->execute();
        
        return $token;
    }
    
    public function validateSession($token) {
        $query = "SELECT u.*, s.expires_at 
                  FROM users u 
                  INNER JOIN user_sessions s ON u.id = s.user_id 
                  WHERE s.session_token = :token AND s.expires_at > NOW() AND u.is_active = 1";
        
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
        
        return $stmt->fetch();
    }
    
    public function destroySession($token) {
        $query = "DELETE FROM user_sessions WHERE session_token = :token";
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(':token', $token);
        $stmt->execute();
    }
    
    public function cleanExpiredSessions() {
        $query = "CALL CleanExpiredSessions()";
        $stmt = $this->db->prepare($query);
        $stmt->execute();
    }
}

// Hata işleme
function handleError($message, $redirectUrl = null) {
    error_log($message);
    if ($redirectUrl) {
        header("Location: $redirectUrl?error=" . urlencode("Bir hata oluştu. Lütfen tekrar deneyin."));
    } else {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Bir hata oluştu. Lütfen tekrar deneyin.']);
    }
}

// JSON yanıt gönderme
function sendJsonResponse($success, $message, $data = null) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'success' => $success,
        'message' => $message,
        'data' => $data
    ], JSON_UNESCAPED_UNICODE);
    exit;
}
?>