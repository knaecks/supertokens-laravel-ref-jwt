<?php

namespace SuperTokens\Laravel\Db;

use SuperTokens\Laravel\Helpers\Utils;
use SuperTokens\Laravel\Models\RefreshTokenModel;

class RefreshTokenDb {

    public static function isSessionBlacklisted($sessionHandle): boolean {
        $result = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->get();
        $noOfRows = $result->count();
        return $noOfRows === 0;
    }

    public static function createNewSessionInDB(string $sessionHandle, string $userId, string $refreshTokenHash2, $sessionData, $expiresAt, $jwtPayload) {
        $sessionForDb = new RefreshTokenModel;
        $sessionForDb->session_handle = $sessionHandle;
        $sessionForDb->user_id = $userId;
        $sessionForDb->refresh_token_hash_2 = $refreshTokenHash2;
        $sessionForDb->session_info = Utils::serializeData($sessionData);
        $sessionForDb->expires_at = $expiresAt;
        $sessionForDb->jwt_user_payload = Utils::serializeData($jwtPayload);
        $sessionForDb->save();
    }

    public static function getSessionInfo(string $sessionHandle) {
        $result = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->lockForUpdate()->first();
        if ($result === null) {
            return null;
        }
        return [
            'userId' => $result->user_id,
            'refreshTokenHash2' => $result->refresh_token_hash_2,
            'sessionData' => Utils::unserializeData($result->session_info),
            'expiresAt' => $result->expires_at,
            'jwtPayload' => Utils::unserializeData($result->jwt_user_payload),
        ];
    }

    public static function updateSessionInfo(string $sessionHandle, string $refreshTokenHash2, $sessionData, $expiresAt) {
        $session = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->first();
        $session->refresh_token_hash_2 = $refreshTokenHash2;
        $session->session_info = Utils::serializeData($sessionData);
        $session->expires_at = $expiresAt;
        $session->save();
    }
}