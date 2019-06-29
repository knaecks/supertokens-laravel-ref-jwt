<?php

namespace SuperTokens\Session\Db;

use Exception;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Helpers\Utils;
use SuperTokens\Session\Models\RefreshTokenModel;

/**
 * Class RefreshTokenDb
 * @package SuperTokens\Session\Db
 */
class RefreshTokenDb {

    /**
     * @param $sessionHandle
     * @return bool
     * @throws Exception
     */
    public static function isSessionBlacklisted($sessionHandle) {
        try {
            $noOfRows = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->count();
            return $noOfRows === 0;
        } catch (Exception $e) {
            throw $e;
        }
    }

    /**
     * @param $sessionHandle
     * @param $userId
     * @param $refreshTokenHash2
     * @param $sessionData
     * @param $expiresAt
     * @param $jwtPayload
     * @throws Exception
     */
    public static function createNewSessionInDB($sessionHandle, $userId, $refreshTokenHash2, $sessionData, $expiresAt, $jwtPayload) {
        try {
            $sessionForDb = new RefreshTokenModel;
            $sessionForDb->session_handle = $sessionHandle;
            $sessionForDb->user_id = $userId;
            $sessionForDb->refresh_token_hash_2 = $refreshTokenHash2;
            $sessionForDb->session_info = Utils::serializeData($sessionData);
            $sessionForDb->expires_at = $expiresAt;
            $sessionForDb->jwt_user_payload = Utils::serializeData($jwtPayload);
            $sessionForDb->save();
        } catch (Exception $e) {
            throw $e;
        }
    }

    /**
     * @param $sessionHandle
     * @return array|null
     * @throws Exception
     */
    public static function getSessionInfo($sessionHandle) {
        try {
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
        } catch (Exception $e) {
            throw $e;
        }
    }

    /**
     * @param $sessionHandle
     * @param $refreshTokenHash2
     * @param $sessionData
     * @param $expiresAt
     * @throws Exception
     */
    public static function updateSessionInfo($sessionHandle, $refreshTokenHash2, $sessionData, $expiresAt) {
        try {
            RefreshTokenModel::where('session_handle', '=', $sessionHandle)
                ->update([
                    'refresh_token_hash_2' => $refreshTokenHash2,
                    'session_info' => Utils::serializeData($sessionData),
                    'expires_at' => $expiresAt
                ]);
        } catch (Exception $e) {
            throw $e;
        }
    }

    /**
     * @param $userId
     * @return array
     * @throws Exception
     */
    public static function getAllSessionHandlesForUser($userId) {
        try {
            $sessions = RefreshTokenModel::where('user_id', '=', $userId)->get();
            $sessionHandles = [];
            foreach ($sessions as $session) {
                array_push($sessionHandles, strval($session->session_handle));
            }
            return $sessionHandles;
        } catch (Exception $e) {
            throw $e;
        }
    }

    /**
     * @param $sessionHandle
     * @throws Exception
     */
    public static function deleteSession($sessionHandle) {
        try {
            RefreshTokenModel::where('session_handle', '=', $sessionHandle)->delete();
        } catch (Exception $e) {
            throw $e;
        }
    }

    /**
     * @param $sessionHandle
     * @return array
     * @throws Exception
     */
    public static function getSessionData($sessionHandle) {
        try {
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
        } catch (Exception $e) {
            throw $e;
        }
    }

    /**
     * @param $sessionHandle
     * @param $sessionData
     * @return bool
     * @throws Exception
     */
    public static function updateSessionData($sessionHandle, $sessionData){
        try {
            $session = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->first();
            if ($session === null) {
                return false;
            }
            RefreshTokenModel::where('session_handle', '=', $sessionHandle)
                ->update([
                    'session_info' => Utils::serializeData($sessionData)
                ]);
            return true;
        } catch (Exception $e) {
            throw $e;
        }
    }
}