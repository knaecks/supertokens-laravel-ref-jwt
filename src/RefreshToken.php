<?php

namespace SuperTokens\Laravel;

use Error;
use Exception;
use DateTime;
use Illuminate\Support\Facades\Config;
use SuperTokens\Laravel\Helpers\Utils;
use SuperTokens\Laravel\Helpers\RefreshTokenSigningKey;

class RefreshToken {

    /**
     * @param $token
     * @return array
     * @throws Exception
     */
    public static function getInfoFromRefreshToken($token) {

        $key = RefreshTokenSigningKey::getKey();
        $splittedToken = explode(".", $token);

        if (count($splittedToken) > 2) {
            throw new Error();
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
            throw new Error();
            // throw error
        }

        return [
            'sessionHandle' => $sessionHandle,
            'userId' => $userId,
            'parentRefreshTokenHash1' => $parentRefreshTokenHash1,
        ];
    }

    /**
     * @param $sessionHandle
     * @param $userId
     * @param $parentRefreshTokenHash1
     * @return array
     * @throws Exception
     */
    public static function createNewRefreshToken($sessionHandle, $userId, $parentRefreshTokenHash1) {

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
        return array(
            'token' => $token,
            'expiry' => $expiry
        );
    }

}