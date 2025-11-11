<?php

require_once __DIR__ . '/../config/db_connection.php';
require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../config/two_factor_verification.php';
function validatePassword($password) {
    if (strlen($password) <= 8) {
        return ['valid' => false, 'message' => 'Password must be longer than 8 characters.'];
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        return ['valid' => false, 'message' => 'Password must contain at least one uppercase letter.'];
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        return ['valid' => false, 'message' => 'Password must contain at least one lowercase letter.'];
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        return ['valid' => false, 'message' => 'Password must contain at least one number.'];
    }
    
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        return ['valid' => false, 'message' => 'Password must contain at least one special character.'];
    }
    
    return ['valid' => true, 'message' => ''];
}
//password za testiranje: Testiram@1

/**
 * registracija na nov korisnik
 * @param string $username
 * @param string $email
 * @param string $password
 * @return array ['success' => bool, 'message' => string]
 */
function registerUser($username, $email, $password) {
    // validacija tuka
    if (empty($username) || empty($email) || empty($password)) {
        return ['success' => false, 'message' => 'All fields are required.'];
    }
    
    // validacija za email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['success' => false, 'message' => 'Invalid email format.'];
    }
    
    // validacija na lozinka
    $passwordValidation = validatePassword($password);
    if (!$passwordValidation['valid']) {
        return ['success' => false, 'message' => $passwordValidation['message']];
    }
        
    try {
        $db = connectDatabase();
        
        // dali postoi userot
        $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bindValue(1, $username, SQLITE3_TEXT);
        $result = $stmt->execute();
        if ($result->fetchArray()) {
            $db->close();
            return ['success' => false, 'message' => 'Username is already taken.'];
        }
        
        // dali postoi emailot
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bindValue(1, $email, SQLITE3_TEXT);
        $result = $stmt->execute();
        if ($result->fetchArray()) {
            $db->close();
            return ['success' => false, 'message' => 'Email address is already registered.'];
        }
        
        // heshiranje na pasword tuka
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        //verifikaciski kod generira tuka
        $verificationCode = generateVerificationCode(8);
        $expiresAt = date('Y-m-d H:i:s', time() + (15 * 60)); //istekuva za 15 min

        // vnesuvanje nov korisnik
        $stmt = $db->prepare("INSERT INTO users (username, email, password_hash, email_verified, email_verification_code, email_verification_expires) VALUES (?, ?, ?, 0, ?, ?)");
        $stmt->bindValue(1, $username, SQLITE3_TEXT);
        $stmt->bindValue(2, $email, SQLITE3_TEXT);
        $stmt->bindValue(3, $passwordHash, SQLITE3_TEXT);
        $stmt->bindValue(4, $verificationCode, SQLITE3_TEXT);
        $stmt->bindValue(5, $expiresAt, SQLITE3_TEXT);
        $stmt->execute();

        $userId = $db->lastInsertRowID();
        sendVerificationCode($email, $verificationCode, 'registration');
        
        $db->close();
return [
    'success' => true,
    'message' => 'Registration successful! Please check your email for verification code.',
    'user_id' => $userId,
];
    } catch (Exception $e) {
        if (isset($db)) $db->close();
        return ['success' => false, 'message' => 'Registration error: ' . $e->getMessage()];
    }
}

//verifikacija na email so kod
function verifyEmailWithCode($userId, $code){
    if (empty($userId) || empty($code)) {
        return ['success' => false, 'message' => 'User ID and verification code are required.'];
    }

    try {
        $db = connectDatabase();
        //go proveruvame kodot
        $stmt = $db->prepare("SELECT id, email_verified FROM users WHERE id = ? AND email_verification_code = ? AND email_verification_expires > datetime('now')");
        $stmt->bindValue(1, $userId, SQLITE3_INTEGER);
        $stmt->bindValue(2, $code, SQLITE3_TEXT);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        if (!$user) {
            $db->close();
            return ['success' => false, 'message' => 'Invalid or expired verification code.'];
        }
        if ($user['email_verified']) {
            $db->close();
            return ['success' => false, 'message' => 'Email is already verified.'];
        }
        // ako e sve ok kje go oznacime korisnikot kako verificiram i kje go izbrisheme kodot
        $stmt = $db->prepare("UPDATE users SET email_verified = 1, email_verification_code = NULL, email_verification_expires = NULL WHERE id = ?");
        $stmt->bindValue(1, $userId, SQLITE3_INTEGER);
        $stmt->execute();

        $db->close();
        return ['success' => true, 'message' => 'Email verified successfully! You can now log in.'];

    } catch (Exception $e) {
        if (isset($db)) $db->close();
        return ['success' => false, 'message' => 'Verification error: ' . $e->getMessage()];
    }
    }

/**
 * najava na korisnik
 * @param string $username
 * @param string $password
 * @return array ['success' => bool, 'message' => string, 'user' => array|null]
 */
function loginUser($username, $password) {
    // validacija
    if (empty($username) || empty($password)) {
        return ['success' => false, 'message' => 'Please enter username and password.'];
    }
    
    try {
        $db = connectDatabase();

        $stmt = $db->prepare("SELECT id, username, email, password_hash, email_verified FROM users WHERE username = ? OR email = ?");
        $stmt->bindValue(1, $username, SQLITE3_TEXT);
        $stmt->bindValue(2, $username, SQLITE3_TEXT);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        $db->close();

        if (!$user) {
            return ['success' => false, 'message' => 'Invalid username or password.', 'step' => 'credentials'];
        }

        if (!$user['email_verified']) {
            return ['success' => false, 'message' => 'Please verify your email before logging in.', 'step' => 'credentials', 'user_id' => $user['id']];
        }

        if (!password_verify($password, $user['password_hash'])) {
            return ['success' => false, 'message' => 'Invalid username or password.'];
        }
        //generirame 2FA kod za najava na korisnik
        $twoFactorCode = generateVerificationCode(8);
        $expiresAt = date('Y-m-d H:i:s', time() + (10 * 60)); // 10 minuti
        //go zacuvuva kodot vo db
        $db = connectDatabase();

        $stmt = $db->prepare("UPDATE users SET two_factor_code = ?, two_factor_code_expires = ? WHERE id = ?");
        $stmt->bindValue(1, $twoFactorCode, SQLITE3_TEXT);
        $stmt->bindValue(2, $expiresAt, SQLITE3_TEXT);
        $stmt->bindValue(3, $user['id'], SQLITE3_INTEGER);
        $stmt->execute();

        sendVerificationCode($user['email'], $twoFactorCode, '2fa');
        $db->close();

        // go zacuvuva user_id vo sesion
        $_SESSION['pending_login_user_id'] = $user['id'];
        $_SESSION['pending_login_username'] = $user['username'];

        return [
            'success' => true,
            'message' => 'Please check your email for the 2FA code.',
            'step' => '2fa',
            'user_id' => $user['id'],
        ];
    } catch (Exception $e) {
        if (isset($db)) $db->close();
        return ['success' => false, 'message' => 'Login error: ' . $e->getMessage(), 'step' => 'credentials'];
    }
}

function verify2FACode($userId, $code) {
    if (empty($userId) || empty($code)) {
        return ['success' => false, 'message' => 'User ID and 2FA code are required.'];
    }

    try {
        $db = connectDatabase();

        $stmt = $db->prepare("SELECT id, username, email FROM users WHERE id = ? AND two_factor_code = ? AND two_factor_code_expires > datetime('now')");
        $stmt->bindValue(1, $userId, SQLITE3_INTEGER);
        $stmt->bindValue(2, $code, SQLITE3_TEXT);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        if (!$user) {
            $db->close();
            return ['success' => false, 'message' => 'Invalid or expired 2FA code.'];
        }

        //ako e ok da se izbrishe kodot
        $stmt = $db->prepare("UPDATE users SET two_factor_code = NULL, two_factor_code_expires = NULL WHERE id = ?");
        $stmt->bindValue(1, $userId, SQLITE3_INTEGER);
        $stmt->execute();

        $sessionToken = generateSessionToken();

        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['session_token'] = $sessionToken;
        //kje gi otstrani pending od sesijata
        unset($_SESSION['pending_login_user_id']);
        unset($_SESSION['pending_login_username']);

        setSessionTokenCookie($sessionToken);

        $db->close();

        return [
            'success' => true,
            'message' => 'Login successful!',
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email']
            ]
        ];
    } catch (Exception $e) {
        if (isset($db)) $db->close();
        return ['success' => false, 'message' => '2FA verification error: ' . $e->getMessage()];
    }
}
function getCurrentUser() {
    if (!isLoggedIn()) {
        return null;
    }
    
    try {
        $db = connectDatabase();
        $stmt = $db->prepare("SELECT id, username, email, first_name, last_name, created_at FROM users WHERE id = ?");
        $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);
        $db->close();
        return $user ?: null;
    } catch (Exception $e) {
        if (isset($db)) $db->close();
        return null;
    }
}

function getAllUsers() {
    try {
        $db = connectDatabase();
        $result = $db->query("SELECT id, username, email, created_at FROM users ORDER BY created_at DESC");
        $users = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $users[] = $row;
        }
        $db->close();
        return $users;
    } catch (Exception $e) {
        if (isset($db)) $db->close();
        return [];
    }
}

function updateUserInfo($userId, $username, $email, $firstName = '', $lastName = '') {

    if (empty($username) || empty($email)) {
        return ['success' => false, 'message' => 'Username and email are required.'];
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['success' => false, 'message' => 'Invalid email format.'];
    }

    if (strlen($username) < 3 || strlen($username) > 50) {
        return ['success' => false, 'message' => 'Username must be between 3 and 50 characters.'];
    }

    // moze da editira samo svoj profil
    if (!isLoggedIn() || $_SESSION['user_id'] != $userId) {
        return ['success' => false, 'message' => 'You can only edit your own profile.'];
    }
    
    try {
        $db = connectDatabase();

        $stmt = $db->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
        $stmt->bindValue(1, $username, SQLITE3_TEXT);
        $stmt->bindValue(2, $userId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        if ($result->fetchArray()) {
            $db->close();
            return ['success' => false, 'message' => 'Username is already taken.'];
        }

        $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
        $stmt->bindValue(1, $email, SQLITE3_TEXT);
        $stmt->bindValue(2, $userId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        if ($result->fetchArray()) {
            $db->close();
            return ['success' => false, 'message' => 'Email address is already registered.'];
        }

        $stmt = $db->prepare("UPDATE users SET username = ?, email = ?, first_name = ?, last_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->bindValue(1, $username, SQLITE3_TEXT);
        $stmt->bindValue(2, $email, SQLITE3_TEXT);
        $stmt->bindValue(3, $firstName ?: null, SQLITE3_TEXT);
        $stmt->bindValue(4, $lastName ?: null, SQLITE3_TEXT);
        $stmt->bindValue(5, $userId, SQLITE3_INTEGER);
        $stmt->execute();

        $_SESSION['username'] = $username;
        $_SESSION['email'] = $email;
        
        $db->close();
        return ['success' => true, 'message' => 'Profile updated successfully!'];
        
    } catch (Exception $e) {
        if (isset($db)) $db->close();
        return ['success' => false, 'message' => 'Update error: ' . $e->getMessage()];
    }
}

function updatePassword($userId, $currentPassword, $newPassword, $confirmPassword) {
    // validacija
    if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
        return ['success' => false, 'message' => 'All password fields are required.'];
    }
    // samo svojot pasvord da moze da go smeni
    if (!isLoggedIn() || $_SESSION['user_id'] != $userId) {
        return ['success' => false, 'message' => 'You can only change your own password.'];
    }

    // dali se isti
    if ($newPassword !== $confirmPassword) {
        return ['success' => false, 'message' => 'New passwords do not match.'];
    }
    // validacija na novata lozinka
    $passwordValidation = validatePassword($newPassword);
    if (!$passwordValidation['valid']) {
        return ['success' => false, 'message' => $passwordValidation['message']];
    }
    
    try {
        $db = connectDatabase();

        $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
        $stmt->bindValue(1, $userId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);
        
        if (!$user) {
            $db->close();
            return ['success' => false, 'message' => 'User not found.'];
        }

        if (!password_verify($currentPassword, $user['password_hash'])) {
            $db->close();
            return ['success' => false, 'message' => 'Current password is incorrect.'];
        }
        //dali tekovnata lozinka e razlicna od starata
        if (password_verify($newPassword, $user['password_hash'])) {
            $db->close();
            return ['success' => false, 'message' => 'New password must be different from current password.'];
        }
        //heshiranje na novata lzoinka
        $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        
        // azuriranje na lozinkata
        $stmt = $db->prepare("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->bindValue(1, $newPasswordHash, SQLITE3_TEXT);
        $stmt->bindValue(2, $userId, SQLITE3_INTEGER);
        $stmt->execute();
        
        $db->close();
        return ['success' => true, 'message' => 'Password changed successfully!'];
        
    } catch (Exception $e) {
        if (isset($db)) $db->close();
        return ['success' => false, 'message' => 'Password update error: ' . $e->getMessage()];
    }
}
//brishenje na profil
function deleteUser($userId, $password) {
    if (!isLoggedIn()) {
        return ['success' => false, 'message' => 'You must be logged in to delete your account.'];
    }

    if ($_SESSION['user_id'] != $userId) {
        return ['success' => false, 'message' => 'You can only delete your own account.'];
    }

    if (empty($password)) {
        return ['success' => false, 'message' => 'Password is required to confirm account deletion.'];
    }
    
    try {
        $db = connectDatabase();

        $stmt = $db->prepare("SELECT id, password_hash FROM users WHERE id = ?");
        $stmt->bindValue(1, $userId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);
        
        if (!$user) {
            $db->close();
            return ['success' => false, 'message' => 'User not found.'];
        }

        if (!password_verify($password, $user['password_hash'])) {
            $db->close();
            return ['success' => false, 'message' => 'Incorrect password. Account deletion cancelled.'];
        }
        //izbrishi go korisnikot od db
        $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
        $stmt->bindValue(1, $userId, SQLITE3_INTEGER);
        $stmt->execute();
        
        $db->close();
        return ['success' => true, 'message' => 'Account deleted successfully.'];
        
    } catch (Exception $e) {
        if (isset($db)) $db->close();
        return ['success' => false, 'message' => 'Error deleting account: ' . $e->getMessage()];
    }
}
