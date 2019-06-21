<?php

namespace SuperTokens\Laravel\Helpers;

use SuperTokens\Laravel\Models\RefreshTokenModel;
use SuperTokens\Laravel\Helpers\Utils;

class RefreshToken {

    private static $key;

    /**
     * @todo
     */
    public static function getInfoFromRefreshToken(string $token) {

        $key = RefreshToken::getKey();
        $splittedToken = explode(".", $token);

        if (count($splittedToken) > 2) {
            // throw error
        }
        $nonce = $splittedToken[1];

        // decrpyt and json parse to get following variable
        $payload = json_decode(Utils::decrypt($splittedToken[0], $key));
        $sessionHandle = Utils::sanitizeStringInput($payload['sessionHandle']);
        $userId = Utils::sanitizeStringInput($payload['userId']);
        $parentRefreshTokenHash1 = Utils::sanitizeStringInput($payload['prt']);
        $nonceFromEnc = Utils::sanitizeStringInput($payload['nonce']);

        if (!isset($sessionHandle) || !isset($userId) || $nonceFromEnc !== $nonce) {
            // throw error
        }

        return [
            'sessionHandle' => $sessionHandle,
            'userId' => $userId,
            'parentRefreshTokenHash1' => $parentRefreshTokenHash1,
        ];
    }

    /**
     * @todo
     */
    public static function createNewRefreshToken(string $sessionHandle, string $userId, $parentRefreshTokenHash1) {

        $key = RefreshToken::getKey();
        $nonce = Utils::hashString(Utils::generateUUID()); // hash of randomly generated UUID
        $payloadSerialised = json_encode([
            'sessionHandle' => $sessionHandle,
            'userId' => $sessionHandle,
            'prt' => $parentRefreshTokenHash1,
            'nonce' => $nonce
        ]);
        $encryptedPart = Utils::encrypt($payloadSerialised, $key); //encrypt $payloadSerialised with $key
        $token = $encryptedPart.'.'.$nonce;
        $validity = config('superTokens.tokens.refreshToken.validity');
        $date = new DateTime();
        $currentTimestamp = $date->getTimestamp();
        $expiry = $currentTimestamp + $validity;
        return [
            'token' => $token,
            'expiry' => $expiry
        ];
    }

    public static function getKey() {
        return "some key";
    }
}