<?php

namespace SuperTokens\Laravel\Db;

use SuperTokens\Laravel\Helpers\Utils;
use SuperTokens\Laravel\Models\RefreshTokenModel;

/**
 * Class RefreshTokenDb
 * @package SuperTokens\Laravel\Db
 */
class RefreshTokenDb {

    /**
     * @param $sessionHandle
     * @return bool
     */
    public static function isSessionBlacklisted($sessionHandle) {
        $noOfRows = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->count();
        return $noOfRows === 0;
    }

    /**
     * @param $sessionHandle
     * @param $userId
     * @param $refreshTokenHash2
     * @param $sessionData
     * @param $expiresAt
     * @param $jwtPayload
     */
    public static function createNewSessionInDB($sessionHandle, $userId, $refreshTokenHash2, $sessionData, $expiresAt, $jwtPayload) {
        $sessionForDb = new RefreshTokenModel;
        $sessionForDb->session_handle = $sessionHandle;
        $sessionForDb->user_id = $userId;
        $sessionForDb->refresh_token_hash_2 = $refreshTokenHash2;
        $sessionForDb->session_info = Utils::serializeData($sessionData);
        $sessionForDb->expires_at = $expiresAt;
        $sessionForDb->jwt_user_payload = Utils::serializeData($jwtPayload);
        $sessionForDb->save();
    }

    /**
     * @param $sessionHandle
     * @return array|null
     */
    public static function getSessionInfo($sessionHandle) {
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

    /**
     * @param $sessionHandle
     * @param $refreshTokenHash2
     * @param $sessionData
     * @param $expiresAt
     */
    public static function updateSessionInfo($sessionHandle, $refreshTokenHash2, $sessionData, $expiresAt) {
        $session = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->first();
        $session->refresh_token_hash_2 = $refreshTokenHash2;
        $session->session_info = Utils::serializeData($sessionData);
        $session->expires_at = $expiresAt;
        $session->save();
    }

    /**
     * @param $userId
     * @return array
     */
    public static function getAllSessionHandlesForUser($userId) {
        $sessions = RefreshTokenModel::where('user_id', '=', $userId)->get();
        $sessionHandles = [];
        foreach ($sessions as $session) {
            array_push($sessionHandles, strval($session->session_handle));
        }
        return $sessionHandles;
    }

    /**
     * @param $sessionHandle
     */
    public static function deleteSession($sessionHandle) {
        RefreshTokenModel::where('session_handle', '=', $sessionHandle)->delete();
    }

    /**
     * @param $sessionHandle
     * @return array
     */
    public static function getSessionData($sessionHandle) {
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

    /**
     * @param $sessionHandle
     * @param $sessionData
     */
    public static function updateSessionData($sessionHandle, $sessionData) {
        $session = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->first();
        $session->session_info = Utils::serializeData($sessionData);
        $session->save();
    }
}