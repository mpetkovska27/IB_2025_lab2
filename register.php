<?php
require_once 'config/session.php';
require_once 'includes/auth.php';

requireGuest();

//dokolku ne mi go pecati kodot vo terminal, go pecatam tuka

$error = '';
$success = '';
$showVerification = false;
$userId = null;
//$verificationCode = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    //ova e za verification kod
    if (isset($_POST['verification_code']) && isset($_POST['user_id'])) {
        $userId = $_POST['user_id'] ?? null;
        $code = trim($_POST['verification_code'] ?? '');

        if ($userId && $code) {
            $result = verifyEmailWithCode($userId, $code);
            if ($result['success']) {
                header('Location: login.php');
                exit();
            } else {
                $error = $result['message'];
                $showVerification = true;
//                $userId = $userId;
            }
        } else {
            $error = 'Please enter the verification code.';
            $showVerification = true;
        }
    } else {
        //ova e za registracija
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        if ($password !== $confirm_password) {
            $error = 'Passwords do not match.';
        } else {
            $result = registerUser($username, $email, $password);
            if ($result['success']) {
                $showVerification = true;
                $userId = $result['user_id'];
//                $verificationCode = $result['verification_code'];
//                $success = $result['message'];
            } else {
                $error = $result['message'];
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $showVerification ? 'Verify Email' : 'Register'; ?> - User Authentication</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<div class="container">
    <div class="auth-box">
        <?php if ($showVerification): ?>
            <h1>Verify Your Email</h1>

            <?php if ($error): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>

<!--            --><?php //if ($verificationCode): ?>
<!--                <div style='background: #ffffcc; padding: 15px; margin: 10px; border: 2px solid #ffcc00; border-radius: 5px;'>-->
<!--                    <strong>TEST MODE - Verification Code:</strong><br>-->
<!--                    <strong style='font-size: 24px; color: red;'>--><?php //echo htmlspecialchars($verificationCode); ?><!--</strong><br>-->
<!--                </div>-->
<!--            --><?php //endif; ?>

            <p>Please enter the verification code sent to your email address.</p>

            <form method="POST" action="register.php">
                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($userId); ?>">
                <div class="form-group">
                    <label for="verification_code">Verification Code:</label>
                    <input type="text" id="verification_code" name="verification_code" required
                           pattern="^\d{8}$" maxlength="8"
                           placeholder="00000000" autocomplete="off">
                </div>

                <button type="submit" class="btn btn-primary">Verify Email</button>
            </form>

            <p class="auth-link">
                <a href="register.php">Back to Registration</a>
            </p>
        <?php else: ?>
            <h1>Register</h1>

            <?php if ($error): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>

            <form method="POST" action="register.php">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required
                           value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                           minlength="3" maxlength="50">
                </div>

                <div class="form-group">
                    <label for="email">Email Address:</label>
                    <input type="email" id="email" name="email" required
                           value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
                </div>

                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required
                           minlength="9">
                    <small class="password-hint">Password must be longer than 8 characters and contain at least one uppercase letter, one lowercase letter, one number, and one special character.</small>
                </div>

                <div class="form-group">
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" id="confirm_password" name="confirm_password" required
                           minlength="9">
                </div>

                <button type="submit" class="btn btn-primary">Register</button>
            </form>

            <p class="auth-link">
                Already have an account? <a href="login.php">Log in</a>
            </p>
        <?php endif; ?>
    </div>
</div>
</body>
</html>