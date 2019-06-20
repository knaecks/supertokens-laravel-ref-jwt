<?php

namespace SuperTokens\Laravel\Helpers;

class AccessToken {

    /**
     * @todo
     */
    public static function getInfoFromAccessToken(string $token, $retry = true) {

        $sessionHandle = '';
        $userId = '';
        $refreshTokenHash1 = '';
        $expiryTime = '';
        $parentRefreshTokenHash1 = '';
        $userPayload = '';

        return [
            'sessionHandle' => $sessionHandle,
            'userId' => $userId,
            'refreshTokenHash1' => $refreshTokenHash1,
            'expiryTime' => $expiryTime,
            'parentRefreshTokenHash1' => $parentRefreshTokenHash1,
            'userPayload' => $userPayload,
        ];   
    }

    /**
     * @todo
     */
    public static function createNewAccessToken($sessionHandle, $userId, $refreshTokenHash1, $parentRefreshTokenHash1, $userPayload) {

        return [
            'token' => $token,
            'expiry' => $expiry
        ];
    }
}