<?php
require_once 'config/session.php';
require_once 'includes/auth.php';

requireGuest();

$error = '';
$success = '';
$show2FA = false;
$userId = null;

if (isset($_POST['two_factor_code']) && isset($_POST['user_id'])) {
    $userId = $_POST['user_id'] ?? null;
    $code = trim($_POST['two_factor_code'] ?? '');

    if ($userId && $code) {
        $result = verify2FACode($userId, $code);
        if ($result['success']) {
            header('Location: index.php');
            exit();
        } else {
            $error = $result['message'];
            $show2FA = true;
        }
    } else {
        $error = 'Please enter the 2FA code.';
        $show2FA = true;
    }
} else {
    
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    $result = loginUser($username, $password);
    if ($result['success'] && isset($result['step']) && $result['step'] === '2fa') {
        $show2FA = true;
        $userId = $result['user_id'];
    } else {
        $error = $result['message'];
        // ako ne e verificiran email-ot
        if (isset($result['user_id']) && isset($result['step']) && $result['step'] === 'credentials') {
            $error .= ' <a href="register.php">Click here to verify your email</a>.';
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $show2FA ? 'Two-Factor Authentication' : 'Login'; ?> - User Authentication</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <div class="auth-box">
            <?php if ($show2FA): ?>
                <h1>Two-Factor Authentication</h1>
                
                <?php if ($error): ?>
                    <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>
                
                <p>Please enter the 2FA code sent to your email address.</p>
                <p><small>Check your terminal for the 2FA code (if running in test mode).</small></p>
                
                <form method="POST" action="login.php">
                    <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($userId); ?>">
                    <div class="form-group">
                        <label for="two_factor_code">2FA Code:</label>
                        <input type="text" id="two_factor_code" name="two_factor_code" required
                               pattern="[0-9]{8}" maxlength="8" 
                               placeholder="00000000" autocomplete="off">
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Verify & Login</button>
                </form>
                
                <p class="auth-link">
                    <a href="login.php">Back to Login</a>
                </p>
            <?php else: ?>
                <h1>Login</h1>
                
                <?php if ($error): ?>
                    <div class="alert alert-error"><?php echo $error; ?></div>
                <?php endif; ?>
                
                
                <form method="POST" action="login.php">
                    <div class="form-group">
                        <label for="username">Username or Email:</label>
                        <input type="text" id="username" name="username" required 
                               value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>">
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">Log In</button>
                </form>
                
                <p class="auth-link">
                    Don't have an account? <a href="register.php">Register</a>
                </p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
