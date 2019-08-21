<?php

namespace SuperTokens\Session\Db;

use Exception;
use SuperTokens\Session\Exceptions\SuperTokensException;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Helpers\Utils;
use SuperTokens\Session\Models\RefreshTokenModel;

/**
 * Class RefreshTokenDb
 * @package SuperTokens\SessionHandlingFunctions\Db
 */
class RefreshTokenDb
{

    /**
     * @param $sessionHandle
     * @return bool
     * @throws SuperTokensGeneralException
     */
    public static function isSessionBlacklisted($sessionHandle)
    {
        try {
            $noOfRows = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->count();
            return $noOfRows === 0;
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $sessionHandle
     * @param $userId
     * @param $refreshTokenHash2
     * @param $sessionInfo
     * @param $expiresAt
     * @param $jwtPayload
     * @throws SuperTokensGeneralException
     */
    public static function createNewSessionInDB($sessionHandle, $userId, $refreshTokenHash2, $sessionInfo, $expiresAt, $jwtPayload)
    {
        try {
            $userId = Utils::stringifyUserId($userId);
            $serialisedSessionObject = Utils::serializeData($sessionInfo);
            $serialisedJWTPayload = Utils::serializeData($jwtPayload);
            if ($serialisedSessionObject === false || $serialisedJWTPayload === false) {
                throw new Exception("unable to serialised user provided payload");
            }
            $sessionForDb = new RefreshTokenModel;
            $sessionForDb->session_handle = $sessionHandle;
            $sessionForDb->user_id = $userId;
            $sessionForDb->refresh_token_hash_2 = $refreshTokenHash2;
            $sessionForDb->session_info = $serialisedSessionObject;
            $sessionForDb->expires_at = $expiresAt;
            $sessionForDb->jwt_user_payload = $serialisedJWTPayload;
            $sessionForDb->save();
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $sessionHandle
     * @return array|null
     * @throws SuperTokensGeneralException
     */
    public static function getSessionObjectForUpdate($sessionHandle)
    {
        try {
            $result = RefreshTokenModel::where('session_handle', '=', $sessionHandle)->lockForUpdate()->first();
            if ($result === null) {
                return null;
            }
            return [
                'userId' => Utils::parseUserIdToCorrectFormat($result->user_id),
                'refreshTokenHash2' => $result->refresh_token_hash_2,
                'sessionInfo' => Utils::unserializeData($result->session_info),
                'expiresAt' => $result->expires_at,
                'jwtPayload' => Utils::unserializeData($result->jwt_user_payload),
            ];
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $sessionHandle
     * @param $refreshTokenHash2
     * @param $sessionInfo
     * @param $expiresAt
     * @return int
     * @throws SuperTokensGeneralException
     */
    public static function updateSessionObject_Transaction($sessionHandle, $refreshTokenHash2, $sessionInfo, $expiresAt)
    {
        try {
            $serialisedSessionObject = Utils::serializeData($sessionInfo);
            if ($serialisedSessionObject === false) {
                throw new Exception("unable to serialised user provided payload");
            }
            return RefreshTokenModel::where('session_handle', '=', $sessionHandle)
                ->update([
                    'refresh_token_hash_2' => $refreshTokenHash2,
                    'session_info' => $serialisedSessionObject,
                    'expires_at' => $expiresAt
                ]);
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $userId
     * @return array
     * @throws SuperTokensGeneralException
     */
    public static function getAllSessionHandlesForUser($userId)
    {
        try {
            $userId = Utils::stringifyUserId($userId);
            $sessions = RefreshTokenModel::where('user_id', '=', $userId)->get();
            $sessionHandles = [];
            foreach ($sessions as $session) {
                array_push($sessionHandles, strval($session->session_handle));
            }
            return $sessionHandles;
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $sessionHandle
     * @throws SuperTokensGeneralException
     * @return number
     */
    public static function deleteSession($sessionHandle)
    {
        try {
            return RefreshTokenModel::where('session_handle', '=', $sessionHandle)->delete();
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $sessionHandle
     * @return array
     * @throws SuperTokensGeneralException
     */
    public static function getSessionInfo($sessionHandle)
    {
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
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $sessionHandle
     * @param $sessionInfo
     * @return int
     * @throws SuperTokensGeneralException
     */
    public static function updateSessionInfo($sessionHandle, $sessionInfo)
    {
        try {
            $serialisedSessionObject = Utils::serializeData($sessionInfo);
            if ($serialisedSessionObject === false) {
                throw new Exception("unable to serialised user provided payload");
            }
            return RefreshTokenModel::where('session_handle', '=', $sessionHandle)
                ->update([
                    'session_info' => $serialisedSessionObject
                ]);
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     *
     */
    public static function removeOldSessions()
    {
        try {
            $currentTimestamp = Utils::getDateTimeStamp();
            return RefreshTokenModel::where('expires_at', '<=', $currentTimestamp)->delete();
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }
}
