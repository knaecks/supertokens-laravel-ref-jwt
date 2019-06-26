<?php

namespace SuperTokens\Laravel\Db;

use Exception;
use SuperTokens\Laravel\Exceptions\GeneralException;
use SuperTokens\Laravel\Exceptions\SuperTokensAuthException;
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
     * @throws SuperTokensAuthException
     */
    public static function isSessionBlacklisted($sessionHandle) {
        try {
            $noOfRows = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->count();
            return $noOfRows === 0;
        } catch (Exception $e) {
            throw new GeneralException($e->getMessage());
        }
    }

    /**
     * @param $sessionHandle
     * @param $userId
     * @param $refreshTokenHash2
     * @param $sessionData
     * @param $expiresAt
     * @param $jwtPayload
     * @throws SuperTokensAuthException
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
            throw new GeneralException($e->getMessage());
        }
    }

    /**
     * @param $sessionHandle
     * @return array|null
     * @throws SuperTokensAuthException
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
            throw new GeneralException($e->getMessage());
        }
    }

    /**
     * @param $sessionHandle
     * @param $refreshTokenHash2
     * @param $sessionData
     * @param $expiresAt
     * @throws SuperTokensAuthException
     */
    public static function updateSessionInfo($sessionHandle, $refreshTokenHash2, $sessionData, $expiresAt) {
        try {
            $session = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->first();
            $session->refresh_token_hash_2 = $refreshTokenHash2;
            $session->session_info = Utils::serializeData($sessionData);
            $session->expires_at = $expiresAt;
            $session->save();
        } catch (Exception $e) {
            throw new GeneralException($e->getMessage());
        }
    }

    /**
     * @param $userId
     * @return array
     * @throws SuperTokensAuthException
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
            throw new GeneralException($e->getMessage());
        }
    }

    /**
     * @param $sessionHandle
     * @throws SuperTokensAuthException
     */
    public static function deleteSession($sessionHandle) {
        try {
            RefreshTokenModel::where('session_handle', '=', $sessionHandle)->delete();
        } catch (Exception $e) {
            throw new GeneralException($e->getMessage());
        }
    }

    /**
     * @param $sessionHandle
     * @return array
     * @throws SuperTokensAuthException
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
            throw new GeneralException($e->getMessage());
        }
    }

    /**
     * @param $sessionHandle
     * @param $sessionData
     * @return bool
     * @throws SuperTokensAuthException
     */
    public static function updateSessionData($sessionHandle, $sessionData){
        try {
            $session = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->first();
            if ($session === null) {
                return false;
            }
            $session->session_info = Utils::serializeData($sessionData);
            $session->save();
            return true;
        } catch (Exception $e) {
            throw new GeneralException($e->getMessage());
        }
    }
}