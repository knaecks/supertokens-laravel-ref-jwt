<?php

namespace SuperTokens\Session\Helpers;

use DateTime;
use Exception;
use Ramsey\Uuid\Uuid;
use SuperTokens\Session\Exceptions\SuperTokensException;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;

class Utils
{

    /**
     * @param $plaintext
     * @param $masterkey
     * @return string
     * @throws Exception
     */
    public static function encrypt($plaintext, $masterkey)
    {
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
    public static function decrypt($encdata, $masterkey)
    {
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
    public static function hashString($toHash)
    {
        return hash("sha256", $toHash);
    }

    /**
     * @return string
     * @throws SuperTokensGeneralException
     */
    public static function generateUUID()
    {
        try {
            return Uuid::uuid1()->toString();
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @return string
     * @throws Exception
     */
    public static function generateNewSigningKey()
    {
        $key = openssl_pbkdf2(random_bytes(64), random_bytes(64), 100, 32, "sha512");
        return base64_encode($key);
    }

    /**
     * @param $text
     * @param $key
     * @return string
     */
    public static function hmac($text, $key)
    {
        return hash_hmac("sha256", $text, $key);
    }

    /**
     * @return string
     * @throws SuperTokensGeneralException
     */
    public static function generateSessionHandle()
    {
        return Utils::generateUUID();
    }

    /**
     * @param $field
     * @return string|null
     */
    public static function sanitizeStringInput($field)
    {
        if ($field === "") {
            return "";
        }

        if (gettype($field) !== "string") {
            return null;
        }

        return trim($field);
    }

    /**
     * @param $field
     * @return string|null
     */
    public static function sanitizeNumberInput($field)
    {
        $type = gettype($field);
        if ($type === "integer" || $type === "double") {
            return $field;
        }

        if ($type !== "string") {
            return null;
        }

        return number_format(trim($field));
    }

    /**
     * @param $field
     * @return bool|null
     */
    public static function sanitizeBooleanInput($field)
    {
        if ($field === true || $field === false) {
            return $field;
        }
        if ($field === "false") {
            return false;
        }
        if ($field === "true") {
            return true;
        }
        return null;
    }

    /**
     * @param $data
     * @return false|string
     */
    public static function serializeData($data)
    {
        if (!isset($data)) {
            return "";
        }
        return json_encode($data);
    }

    /**
     * @param $data
     * @return mixed|null
     */
    public static function unserializeData($data)
    {
        if ($data === "") {
            return null;
        }
        return json_decode($data, true);
    }

    /**
     * @return int
     * @throws SuperTokensGeneralException
     */
    public static function getDateTimeStamp()
    {
        try {
            return (new DateTime())->getTimestamp();
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $userId
     * @throws SuperTokensGeneralException
     */
    public static function checkUserIdIsStringOrNumber($userId)
    {
        if (!is_string($userId) && !is_numeric($userId)) {
            throw SuperTokensException::generateGeneralException("userId must be a string or a number");
        }
    }

    /**
     * @param $userId
     * @return string
     * @throws SuperTokensGeneralException
     */
    public static function stringifyUserId($userId)
    {
        Utils::checkUserIdIsStringOrNumber($userId);
        if (is_string($userId)) {
            $jsonFromUserId = json_decode($userId, true);
            if ($jsonFromUserId === null || is_numeric($jsonFromUserId)) {
                //  $userId is not a JSON.
                return $userId;
            }
            if (count($jsonFromUserId) === 1 && array_key_exists("i", $jsonFromUserId)) {
                throw SuperTokensException::generateGeneralException("passed userId cannot be stringified version of object type {i: string}");
            }
            return $userId;
        }
        return json_encode([
            "i" => $userId
        ]);
    }

    public static function parseUserIdToCorrectFormat($userId)
    {
        $id = json_decode($userId, true);
        if ($id === null || !is_array($id)) {
            return $userId;
        }
        if (count($id) !== 1 || $id["i"] === null) {
            return $userId;
        }
        return $id["i"];
    }
}
