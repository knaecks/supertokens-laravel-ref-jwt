<?php

namespace SuperTokens\Laravel\Helpers;

use SuperTokens\Laravel\Models\RefreshTokenModel;

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
        $sessionHandle = '';
        $userId = '';
        $parentRefreshTokenHash1 = '';
        $nonceFromEnc = '';

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
    public static function createNewRefreshToken($sessionHandle, $userId, $parentRefreshTokenHash1) {

        $key = RefreshToken::getKey();
        $nonce = ''; // hash of randomly generated UUID
        $payloadSerialised = ''; // stringified json payload. will contain sessionHandle, userId, prt, nonce
        $encryptedPart = ''; //encrypt $payloadSerialised with $key
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