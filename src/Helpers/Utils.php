<?php

namespace SuperTokens\Session\Helpers;

use DateTime;
use Exception;
use Ramsey\Uuid\Uuid;

class Utils {

    /**
     * @param $plaintext
     * @param $masterkey
     * @return string
     * @throws Exception
     */
    public static function encrypt($plaintext, $masterkey) {
        $iv = random_bytes(16);
        $salt = random_bytes(64);

        $key = openssl_pbkdf2($masterkey, $salt, 100, 32, "sha512");
        $cipher = "aes-256-gcm";

        $tag = ""; // will be filled by openssl_encrypt
        $encrypted = openssl_encrypt($plaintext, $cipher, $key, $options=0, $iv, $tag);

        $ciphertext = base64_encode($salt.$iv.$tag.$encrypted);
        return $ciphertext;
    }

    /**
     * @param $encdata
     * @param $masterkey
     * @return string
     */
    public static function decrypt($encdata, $masterkey) {
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

    /**
     * @param $toHash
     * @return string
     */
    public static function hashString($toHash) {
        return hash("sha256", $toHash);
    }

    /**
     * @return string
     * @throws Exception
     */
    public static function generateUUID() {
        return Uuid::uuid1()->toString();
    }

    /**
     * @return string
     * @throws Exception
     */
    public static function generateNewSigningKey() {
        $key = openssl_pbkdf2(random_bytes(64), random_bytes(64), 100, 32, "sha512");
        return base64_encode($key);
    }

    /**
     * @param $text
     * @param $key
     * @return string
     */
    public static function hmac($text, $key) {
        return hash_hmac("sha256", $text, $key);
    }

    /**
     * @return string
     * @throws Exception
     */
    public static function generateSessionHandle() {
        return Utils::generateUUID();
    }

    /**
     * @param $field
     * @return string|void
     */
    public static function sanitizeStringInput($field) {
        if ($field === "") {
            return "";
        }

        if (gettype($field) !== "string") {
            return;
        }

        return trim($field);
    }

    /**
     * @param $field
     * @return string|void
     */
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

    /**
     * @param $field
     * @return bool|void
     */
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

    /**
     * @param $data
     * @return false|string
     */
    public static function serializeData($data) {
        if (!isset($data)) {
            return "";
        }
        return json_encode($data);
    }

    /**
     * @param $data
     * @return mixed|void
     */
    public static function unserializeData($data) {
        if ($data === "") {
            return;
        }
        return json_decode($data, true);
    }

    /**
     * @return int
     * @throws Exception
     */
    public static function getDateTimeStamp() {
        return (new DateTime())->getTimestamp();
    }
}