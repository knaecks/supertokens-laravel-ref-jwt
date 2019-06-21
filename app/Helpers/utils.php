<?php

namespace SuperTokens\Laravel\Helpers;

class Utils {

    public static function encrypt (string $plaintext, string $masterkey) {
        $iv = random_bytes(16);
        $salt = random_bytes(64);

        $key = openssl_pbkdf2($masterkey, $salt, 100, 32, "sha512");
        $cipher = "aes-256-gcm";

        $tag = ""; // will be filled by openssl_encrypt
        $encrypted = openssl_encrypt($plaintext, $cipher, $key, $options=0, $iv, $tag);

        $ciphertext = base64_encode($salt.$iv.$tag.$encrypted);
        return $ciphertext;
    }

    public static function decrypt (string $encdata, string $masterkey) {
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
}