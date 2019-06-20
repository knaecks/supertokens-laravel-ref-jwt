<?php

namespace SuperTokens\Laravel\Helpers;

use Illuminate\Support\Facades\DB;

class Session {
    /**
     * @todo
     */
    public static function createNewSession(string $userId, $jwtPayload, $sessionData) {
        $handle = '';
        $accessToken = '';
        $accessTokenExipres = '';
        $refreshToken = '';
        $refreshTokenExipres = '';
        $idRefreshToken = '';
        $idRefreshTokenExipres = '';

        return [
            'session' => [
                'handle' => $handle,
                'userid' => $userId,
                'jwtPayload' => $jwtPayload,
            ],
            'accessToken' => [
                'value' => $accessToken,
                'expires' => $accessTokenExipres,
            ],
            'refreshToken' => [
                'value' => $refreshToken,
                'expires' => $refreshTokenExipres,
            ],
            'idRefreshToken' => [
                'value' => $idRefreshToken,
                'expires' => $idRefreshTokenExipres,
            ]
        ];
    }

    /**
     * @todo
     */
    public static function getSession(string $accessToken) {
        DB::beginTransaction();
        try {
            return [
                'session' => [
                    'handle' => $handle,
                    'userid' => $userId,
                    'jwtPayload' => $jwtPayload,
                ],
            ];
    
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
            ];
        } catch(Exception $e) { DB::rollBack();
            throw $e;
        }
        DB::commit();
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