<?php

namespace SuperTokens\Laravel\Helpers;

use Ramsey\Uuid\Uuid;

class Utils {

    public static function encrypt(string $plaintext, string $masterkey) {
        $iv = random_bytes(16);
        $salt = random_bytes(64);

        $key = openssl_pbkdf2($masterkey, $salt, 100, 32, "sha512");
        $cipher = "aes-256-gcm";

        $tag = ""; // will be filled by openssl_encrypt
        $encrypted = openssl_encrypt($plaintext, $cipher, $key, $options=0, $iv, $tag);

        $ciphertext = base64_encode($salt.$iv.$tag.$encrypted);
        return $ciphertext;
    }

    public static function decrypt(string $encdata, string $masterkey) {
        $bData = base64_decode($encdata);

        $salt = substr($bData, 0, 64); 
        $iv = substr($bData, 64, 16);
        $tag = substr($bData, 80, 16);
        $text = substr($bData, 96);

        $key = openssl_pbkdf2($masterkey, $salt, 100, 32, "sha512");
        $cipher = "aes-256-gcm";

        $decipher = openssl_decrypt($text, $cipher, $key, $options=0, $iv, $tag);

        $decrypted = utf8_encode($decipher);
        return $decrypted;
    }

    public static function hashString(string $toHash) {
        return hash("sha256", $toHash);
    }

    public static function generateUUID() {
        return Uuid::uuid1();
    }

    public static function generateNewSigningKey() {
        $key = openssl_pbkdf2(random_bytes(64), random_bytes(64), 100, 32, "sha512");
        return base64_encode($key);
    }

    public static function hmac(string $text, string $key) {
        return hash_hmac("sha256", $text, $key);
    }

    public static function generateSessionHandle() {
        return Utils::generateUUID();
    }

    public static function sanitizeStringInput($field) {
        if ($field === "") {
            return "";
        }

        if (gettype($field) !== "string") {
            return;
        }

        return trim($field);
    }

    public static function sanitizeNumberInput($field) {
        $type = gettype($field);
        if ($type === "integer" || $type === "double") {
            return $field;
        }

        if ($type !== "string") {
            return;
        }

        return number_format(trim($field));
    }

    public static function sanitizeBooleanInput($field) {
        if ($field === true || $field === false) {
            return $field;
        }
        if ($field === "false") {
            return false;
        }
        if ($field === "true") {
            return true;
        }
        return;
    }
}