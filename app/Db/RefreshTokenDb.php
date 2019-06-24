<?php

namespace SuperTokens\Laravel\Db;

use SuperTokens\Laravel\Helpers\Utils;
use SuperTokens\Laravel\Models\RefreshTokenModel;

class RefreshTokenDb {

    public static function isSessionBlacklisted($sessionHandle): boolean {
        $noOfRows = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->count();
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

    public static function getAllSessionHandlesForUser(string $userId) {
        $sessions = RefreshTokenModel::where('user_id', '=', $userId)->get();
        $sessionHandles = [];
        foreach ($sessions as $session) {
            array_push($sessionHandles, strval($session->session_handle));
        }
    }

    public static function deleteSession(string $sessionHandle) {
        RefreshTokenModel::where('session_handle', '=', $sessionHandle)->delete();
    }

    public static function getSessionData(string $sessionHandle) {
        $session = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->first();
        if ($session === null) {
            return [
                'found' => false
            ];
        }
        return [
            'found' => true,
            'data' => Utils::unserializeData($session->session_info)
        ];
    }

    public static function updateSessionData(string $sessionHandle, $sessionData) {
        $session = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->first();
        $session->session_info = Utils::serializeData($sessionData);
        $session->save();
    }
}