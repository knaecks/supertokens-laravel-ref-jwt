<?php

namespace SuperTokens\Laravel\Helpers;

use SuperTokens\Laravel\Helpers\Jwt;
use SuperTokens\Laravel\Helpers\Utils;

class AccessToken {

    /**
     * @todo
     */
    public static function getInfoFromAccessToken(string $token, $retry = true) {

        $key = AccessToken::getKey();
        try {
            $payload = Jwt::verifyJWTAndGetPayload($token, $key);
        } catch (Exception $e) {
            if ($retry) {
                /**
                 * @todo: unset signing key
                 */
                return AccessToken::getInfoFromAccessToken($token, false);
            } else {
                throw $e;
            }
        }
        $sessionHandle = Utils::sanitizeStringInput($payload['sessionHandle']);
        $userId = Utils::sanitizeStringInput($payload['userId']);
        $refreshTokenHash1 = Utils::sanitizeStringInput($payload['rt']);
        $expiryTime = Utils::sanitizeNumberInput($payload['expiryTime']);
        $parentRefreshTokenHash1 = Utils::sanitizeStringInput($payload['prt']);
        $userPayload = $payload['userPayload'];

        if (!isset($sessionHandle) || !isset($userId) || !isset($refreshTokenHash1) || !isset($expiryTime)) {
            // it would come here if we change the structure of the JWT.
            // throw error
        }
        $date = new DateTime();
        $currentTimestamp = $date->getTimestamp();
        if ($expiryTime < $currentTimestamp) {
            // throw Error("expired access token");
        }

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

        $key = AccessToken::getKey();
        $validity = config('superTokens.tokens.accessToken.validity');
        $date = new DateTime();
        $currentTimestamp = $date->getTimestamp();
        $expiry = $currentTimestamp + $validity;

        $token = Jwt::createJWT([
            'sessionHandle' => $sessionHandle,
            'userId' => $userId,
            'rt' => $refreshTokenHash1,
            'prt' => $parentRefreshTokenHash1,
            'expiryTime' => $expiry,
            'userPayload' => $userPayload
        ], $key);

        return [
            'token' => $token,
            'expiry' => $expiry
        ];
    }

    public static function getKey() {
        return "some key";
    }
}