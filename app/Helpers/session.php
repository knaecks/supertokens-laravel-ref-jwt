<?php

namespace SuperTokens\Laravel\Helpers;

use Illuminate\Support\Facades\DB;
use SuperTokens\Laravel\Helpers\Utils;
use SuperTokens\Laravel\Helpers\AccessToken;
use SuperTokens\Laravel\Helpers\RefreshToken;
use SuperTokens\Laravel\Models\RefreshTokenModel;
use SuperTokens\Laravel\Db\RefreshTokenDb;

class Session {
    /**
     * @todo
     */
    public static function createNewSession(string $userId, $jwtPayload, $sessionData) {
        $sessionHandle = Utils::generateSessionHandle();
        $refreshToken = RefreshToken::createNewRefreshToken($sessionHandle, $userId, null);
        $accessToken = AccessToken::createNewAccessToken($sessionHandle, $userId, Utils::hashString($refreshToken['token']), null, $jwtPayload);

        RefreshTokenDb::createNewSessionInDB(
            $sessionHandle,
            $userId,
            Utils::hashString(Utils::hashString($refreshToken['token'])),
            $sessionData,
            $refreshToken['expiry'],
            $jwtPayload
        );

       return [
            'session' => [
                'handle' => $sessionHandle,
                'userid' => $userId,
                'jwtPayload' => $jwtPayload,
            ],
            'accessToken' => [
                'value' => $accessToken['token'],
                'expires' => $accessToken['expiry'],
            ],
            'refreshToken' => [
                'value' => $refreshToken['token'],
                'expires' => $refreshToken['expiry'],
            ],
            'idRefreshToken' => [
                'value' => Utils::generateUUID(),
                'expires' => $refreshToken['expiry'],
            ]
        ];
    }

    /**
     * @todo
     */
    public static function getSession(string $accessToken) {
        $accessTokenInfo = AccessToken::getInfoFromAccessToken($accessToken);
        $sessionHandle = $accessTokenInfo['sessionHandle'];

        $blacklisting = config('superTokens.tokens.accessToken.blacklisting');

        if (isset($blacklisting) && $blacklisting) {
            $isBlacklisted = RefreshTokenDb::isSessionBlacklisted($sessionHandle);
            if ($isBlacklisted) {
                // throw error: session is over or has been blacklisted
            }
        }

        if (!isset($accessTokenInfo['parentRefreshTokenHash1'])) {
            return [
                'session' => [
                    'handle' => $accessTokenInfo['sessionHandle'],
                    'userid' => $accessTokenInfo['userId'],
                    'jwtPayload' => $accessTokenInfo['userPayload'],
                ],
                'newAccessToken' => null
            ];
        }

        DB::beginTransaction();
        try {

            $sessionInfo = RefreshTokenDb::getSessionInfo($sessionHandle);
            if (!isset($sessionInfo)) {
                DB::commit();
                // throw error: missing session in db
            }

            $promote = $sessionInfo['refreshTokenHash2'] === Utils::hashString($accessTokenInfo['parentRefreshTokenHash1']);
            if ($promote || $sessionInfo['refreshTokenHash2'] === Utils::hashString($accessTokenInfo['refreshTokenHash1'])) {

                if ($promote) {
                    $validity = config('superTokens.tokens.refreshToken.validity');
                    $date = new DateTime();
                    $currentTimestamp = $date->getTimestamp();
                    $expiresAt = $currentTimestamp + $validity;
                    RefreshTokenDb::updateSessionInfo(
                        $sessionHandle,
                        Utils::hashString(accessTokenInfo['refreshTokenHash1']),
                        $sessionInfo['sessionData'],
                        $expiresAt
                    );
                }
                DB::commit();
            }

            $newAccessToken = AccessToken::createNewAccessToken(
                $sessionHandle,
                $accessTokenInfo['userId'],
                $accessTokenInfo['refreshTokenHash1'],
                null,
                $accessTokenInfo['userPayload']
            );
            return [
                'session' => [
                    'handle' => $sessionHandle,
                    'userid' => $accessTokenInfo['userId'],
                    'jwtPayload' => $accessTokenInfo['userPayload'],
                ],
                'newAccessToken' => [
                    'value' => $newAccessToken['token'],
                    'expires' => $newAccessToken['expiry'],
                ],
            ];
            DB::commit();
            // throw error: using access token whose refresh token is no more.
        } catch(Exception $e) {
            DB::rollBack();
            throw $e;
        }
    }

    /**
     * @todo
     */
    public static function refreshSession(string $refreshToken) {
        $refreshToken = '';
        $refreshTokenInfo = '';
        return Session::refreshSessionHelper($refreshToken, $refreshTokenInfo);    
    }

    /**
     * @todo
     */
    public static function refreshSessionHelper(string $refreshToken, $refreshTokenInfo) {
        return [
            'session' => [
                'handle' => $handle,
                'userid' => $userId,
                'jwtPayload' => $jwtPayload,
            ],
            'newAccessToken' => [
                'value' => $accessToken,
                'expires' => $accessTokenExipres,
            ],
            'newRefreshToken' => [
                'value' => $refreshToken,
                'expires' => $refreshTokenExipres,
            ],
            'newIdRefreshToken' => [
                'value' => $idRefreshToken,
                'expires' => $idRefreshTokenExipres,
            ]
        ];
    }

    /**
     * @todo
     */
    public static function revokeAllSessionsForUser(string $userId) {

    }

    /**
     * @todo
     */
    public static function getAllSessionHandlesForUser(string $userId) {
        return [];
    }

    /**
     * @todo
     */
    public static function revokeSessionUsingSessionHandle(string $sessionHandle) {
        return true;
    }

    /**
     * @todo
     */
    public static function getSessionData(string $sessionHandle) {

    }

    /**
     * @todo
     */
    public static function updateSessionData(string $sessionHandle, $newSessionData)
    {

    }
}