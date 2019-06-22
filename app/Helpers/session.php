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
            }

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
        $refreshTokenInfo = RefreshToken::getInfoFromRefreshToken($refreshToken);
        return Session::refreshSessionHelper($refreshToken, $refreshTokenInfo);
    }

    /**
     * @todo
     */
    public static function refreshSessionHelper(string $refreshToken, $refreshTokenInfo) {
        $sessionHandle = $refreshTokenInfo['sessionHandle'];
        DB::beginTransaction();
        try {

            $sessionInfo = RefreshTokenDb::getSessionInfo($sessionHandle);
            $date = new DateTime();
            $currentTimestamp = $date->getTimestamp();
            if (!isset($sessionInfo) || $sessionInfo['expiresAt'] < $currentTimestamp) {
                DB::commit();
                // throw error: session does not exist or has expired
            }

            if ($sessionInfo['userId'] !== $refreshTokenInfo['userId']) {
                DB::commit();
                // throw error: userId for session does not match the userId in the refresh token
            }

            if ($sessionInfo['refreshTokenHash2'] === Utils::hashString(Utils::hashString($refreshToken))) {
                DB::commit();
                $newRefreshToken = RefreshToken::createNewRefreshToken($sessionHandle, $refreshTokenInfo['userId'], Utils::hashString($refreshToken));
                $accessToken = AccessToken::createNewAccessToken(
                    $sessionHandle,
                    $refreshTokenInfo['userId'],
                    Utils::hashString($newRefreshToken['token']),
                    Utils::hashString($refreshToken),
                    $sessionInfo['jwtPayload']
                );
                return [
                    'session' => [
                        'handle' => $sessionHandle,
                        'userid' => $refreshTokenInfo['userId'],
                        'jwtPayload' => $sessionInfo['jwtPayload'],
                    ],
                    'newAccessToken' => [
                        'value' => $newAccessToken['token'],
                        'expires' => $newAccessToken['expiry'],
                    ],
                    'newRefreshToken' => [
                        'value' => $newRefreshToken['token'],
                        'expires' => $newRefreshToken['expiry'],
                    ],
                    'newIdRefreshToken' => [
                        'value' => Utils::generateUUID(),
                        'expires' => $newRefreshToken['expiry'],
                    ]
                ];
            }

            if (
                isset($refreshTokenInfo['parentRefreshTokenHash1']) &&
                Utils::hashString($refreshTokenInfo['parentRefreshTokenHash1']) === $sessionInfo['refreshTokenHash2']
            ) {
                // At this point, the input refresh token is a child and its parent is in the database. Normally, this part of the code
                // will be reached only when the client uses a refresh token to request a new refresh token before
                // using its access token. This would happen in case client recieves a new set of tokens and right before the next
                // API call, the app is killed. and when the app opens again, the client's access token is expired.

                // Since this is used by the client, we know that the client has this set of tokens, so we can make them the parent.
                // Here we set the expiry based on the current time and not the time this refresh token was created. This may
                // result in refresh tokens living on for a longer period of time than what is expected. But that is OK, since they keep changing
                // based on access token's expiry anyways.
                // This can be solved fairly easily by keeping the expiry time in the refresh token payload as well.
                $validity = config('superTokens.tokens.refreshToken.validity');
                $date = new DateTime();
                $currentTimestamp = $date->getTimestamp();
                $expiresAt = $currentTimestamp + $validity;
                RefreshTokenDb::updateSessionInfo(
                    $sessionHandle,
                    Utils::hashString(Utils::hashString($refreshToken)),
                    $sessionInfo['sessionData'],
                    $expiresAt
                );
                DB::commit();

                // now we can generate children tokens for the current input token.
                return Session::refreshSessionHelper($refreshToken, $refreshTokenInfo);
            }

            DB::commit();
            /**
             * @todo: token theft
             */
            // throw error: token theft detected!
        } catch (Exception $e) {
            DB::rollBack();
            throw $e;
        }
    }

    /**
     * @todo
     */
    public static function revokeAllSessionsForUser(string $userId) {
        $sessionHandles = RefreshTokenDb::getAllSessionHandlesForUser($userId);
        for ($i = 0; $i < count($sessionHandles); $i++) {
            Session::revokeSessionUsingSessionHandle($sessionHandles[i]);
        }
    }

    /**
     * @todo
     */
    public static function getAllSessionHandlesForUser(string $userId) {
        $sessionHandles = RefreshTokenDb::getAllSessionHandlesForUser($userId);
        return $sessionHandles;
    }

    /**
     * @todo
     */
    public static function revokeSessionUsingSessionHandle(string $sessionHandle) {
        RefreshTokenDb::deleteSession($sessionHandle);
    }

    /**
     * @todo
     */
    public static function getSessionData(string $sessionHandle) {
        $result = RefreshTokenDb::getSessionData($sessionHandle);
        if (!$result['found']) {
            // throw error: session does not exist anymore
        }
        return $result['data'];
    }

    /**
     * @todo
     */
    public static function updateSessionData(string $sessionHandle, $newSessionData) {
        RefreshTokenDb::updateSessionData($sessionHandle, $newSessionData);
    }
}