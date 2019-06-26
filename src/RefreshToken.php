<?php

namespace SuperTokens\Laravel;

use Error;
use Exception;
use DateTime;
use Illuminate\Support\Facades\Config;
use SuperTokens\Laravel\Exceptions\GeneralException;
use SuperTokens\Laravel\Exceptions\SuperTokensAuthException;
use SuperTokens\Laravel\Exceptions\UnauthorizedException;
use SuperTokens\Laravel\Helpers\Utils;
use SuperTokens\Laravel\Helpers\RefreshTokenSigningKey;

class RefreshToken {

    /**
     * @param $token
     * @return array
     * @throws SuperTokensAuthException
     */
    public static function getInfoFromRefreshToken($token) {

        $key = RefreshTokenSigningKey::getKey();
        try {
            $splittedToken = explode(".", $token);

            if (count($splittedToken) > 2) {
                throw new Exception("invalid refresh token");
            }
            $nonce = $splittedToken[1];

            // decrpyt and json parse to get following variable
            $payload = json_decode(Utils::decrypt($splittedToken[0], $key));
            $sessionHandle = Utils::sanitizeStringInput($payload['sessionHandle']);
            $userId = Utils::sanitizeStringInput($payload['userId']);
            $parentRefreshTokenHash1 = Utils::sanitizeStringInput($payload['prt']);
            $nonceFromEnc = Utils::sanitizeStringInput($payload['nonce']);

            if (!isset($sessionHandle) || !isset($userId) || $nonceFromEnc !== $nonce) {
                throw new Exception("invalid refresh token");
            }

            return [
                'sessionHandle' => $sessionHandle,
                'userId' => $userId,
                'parentRefreshTokenHash1' => $parentRefreshTokenHash1,
            ];
        } catch (Exception $e) {
            throw new UnauthorizedException($e->getMessage());
        }
    }

    /**
     * @param $sessionHandle
     * @param $userId
     * @param $parentRefreshTokenHash1
     * @return array
     * @throws SuperTokensAuthException
     */
    public static function createNewRefreshToken($sessionHandle, $userId, $parentRefreshTokenHash1) {

        try {
            $key = RefreshTokenSigningKey::getKey();
            $nonce = Utils::hashString(Utils::generateUUID()); // hash of randomly generated UUID
            $payloadSerialised = json_encode([
                'sessionHandle' => $sessionHandle,
                'userId' => $userId,
                'prt' => $parentRefreshTokenHash1,
                'nonce' => $nonce
            ]);
            $encryptedPart = Utils::encrypt($payloadSerialised, $key); //encrypt $payloadSerialised with $key
            $token = $encryptedPart.'.'.$nonce;
            $validity = Config::get('supertokens.tokens.refreshToken.validity');
            $date = new DateTime();
            $currentTimestamp = $date->getTimestamp();
            $expiry = $currentTimestamp + $validity;
            return [
                'token' => $token,
                'expiry' => $expiry
            ];
        } catch (Exception $e) {
            throw new GeneralException($e->getMessage());
        }
    }

}