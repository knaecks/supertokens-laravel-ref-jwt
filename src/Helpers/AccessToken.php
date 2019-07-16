<?php

namespace SuperTokens\Session\Helpers;

use DateTime;
use Error;
use Exception;
use Illuminate\Support\Facades\Config;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensException;
use SuperTokens\Session\Exceptions\SuperTokensTryRefreshTokenException;
use SuperTokens\Session\Helpers\Utils;
use SuperTokens\Session\Helpers\Jwt;
use SuperTokens\Session\Helpers\AccessTokenSigningKey;

class AccessToken {

    /**
     * @param $token
     * @param bool $retry
     * @return array
     * @throws SuperTokensTryRefreshTokenException | SuperTokensGeneralException
     */
    public static function getInfoFromAccessToken($token, $retry = true) {

        $key = AccessTokenSigningKey::getKey();
        try {
            try {
                $payload = Jwt::verifyJWTAndGetPayload($token, $key);
            } catch (Exception $e) {
                if ($retry) {
                    AccessTokenSigningKey::removeKeyFromMemory();
                    return AccessToken::getInfoFromAccessToken($token, false);
                } else {
                    throw $e;
                }
            }
            $sessionHandle = Utils::sanitizeStringInput($payload['sessionHandle']);
            $userId = $payload['userId'];
            $refreshTokenHash1 = Utils::sanitizeStringInput($payload['rt']);
            $expiryTime = Utils::sanitizeNumberInput($payload['expiryTime']);
            $parentRefreshTokenHash1 = Utils::sanitizeStringInput($payload['prt']);
            $antiCsrfToken = Utils::sanitizeStringInput($payload['antiCsrfToken']);
            $userPayload = $payload['userPayload'];

            if (!isset($sessionHandle) || !isset($userId) || !isset($refreshTokenHash1) || !isset($expiryTime) ||
                (!isset($antiCsrfToken) && Config::get("supertokens.tokens.enableAntiCsrf"))) {
                // it would come here if we change the structure of the JWT.
                // throw error
                throw new Exception("invalid access token payload");
            }
            $date = new DateTime();
            $currentTimestamp = $date->getTimestamp();
            if ($expiryTime < $currentTimestamp) {
                throw new Exception("expired access token");
            }

            return [
                'sessionHandle' => $sessionHandle,
                'userId' => $userId,
                'refreshTokenHash1' => $refreshTokenHash1,
                'expiryTime' => $expiryTime,
                'parentRefreshTokenHash1' => $parentRefreshTokenHash1,
                'userPayload' => $userPayload,
                'antiCsrfToken' => $antiCsrfToken
            ];
        } catch (Exception $e) {
            throw SuperTokensException::generateTryRefreshTokenException($e);
        }
    }

    /**
     * @param $sessionHandle
     * @param $userId
     * @param $refreshTokenHash1
     * @param $antiCsrfToken
     * @param $parentRefreshTokenHash1
     * @param $userPayload
     * @return array
     * @throws SuperTokensGeneralException
     */
    public static function createNewAccessToken($sessionHandle, $userId, $refreshTokenHash1, $antiCsrfToken, $parentRefreshTokenHash1, $userPayload) {

        try {
            $key = AccessTokenSigningKey::getKey();
            $validity = Config::get('supertokens.tokens.accessToken.validity');
            $date = new DateTime();
            $currentTimestamp = $date->getTimestamp();
            $expiry = $currentTimestamp + $validity;
            $token = Jwt::createJWT([
                'sessionHandle' => $sessionHandle,
                'userId' => $userId,
                'rt' => $refreshTokenHash1,
                'antiCsrfToken' => $antiCsrfToken,
                'prt' => $parentRefreshTokenHash1,
                'expiryTime' => $expiry,
                'userPayload' => $userPayload
            ], $key);

            return [
                'token' => $token,
                'expiry' => $expiry
            ];
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }
}
