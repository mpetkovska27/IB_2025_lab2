<?php

function generateVerificationCode($length = 8) {
    return str_pad(rand(0, pow(10, $length) - 1), $length, '0', STR_PAD_LEFT);
}

function sendVerificationCode($email, $code, $type = 'registration')
{
    $subject = $type === 'registration'
        ? 'Email Verification Code'
        : 'Two-Factor Authentication Code';

    $message = $type === 'registration'
        ? "Your verification code is: $code\n\nThis code will expire in 15 minutes."
        : "Your 2FA code is: $code\n\nThis code will expire in 10 minutes.";

    // ova kje go koristime za lokalno testiranje samo, kje go prikaze kodot vo error log
    // error_log("=== EMAIL ===");
    // error_log("To: $email");
    // error_log("Subject: $subject");
    // error_log("Code: $code");
    // error_log("=============");
    $output = "\n" . str_repeat("=", 50) . "\n";
    $output .= "=== EMAIL VERIFICATION ===\n";
    $output .= "To: $email\n";
    $output .= "Subject: $subject\n";
    $output .= "Code: $code\n";
    $output .= "Type: $type\n";
    $output .= "Message: " . trim($message) . "\n";
    $output .= str_repeat("=", 50) . "\n\n";

    file_put_contents('php://stderr', $output);

    return true;
}

