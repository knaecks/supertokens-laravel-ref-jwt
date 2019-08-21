<?php

namespace SuperTokens\Session;

use DateTime;
use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use SuperTokens\Session\Exceptions\SuperTokensException;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensTokenTheftException;
use SuperTokens\Session\Exceptions\SuperTokensTryRefreshTokenException;
use SuperTokens\Session\Exceptions\SuperTokensUnauthorizedException;
use SuperTokens\Session\Helpers\Utils;
use SuperTokens\Session\Db\RefreshTokenDb;
use SuperTokens\Session\Helpers\AccessTokenSigningKey;
use SuperTokens\Session\Helpers\RefreshTokenSigningKey;
use SuperTokens\Session\Helpers\AccessToken;
use SuperTokens\Session\Helpers\RefreshToken;

/**
 * Class SessionHandlingFunctions
 * @package SuperTokens\SessionHandlingFunctions
 */
class SessionHandlingFunctions
{

    /**
     * SessionHandlingFunctions constructor.
     * @throws Exception
     */
    public function __construct()
    {
        AccessTokenSigningKey::init();
        RefreshTokenSigningKey::init();
    }

    /**
     * @param $userId
     * @param $jwtPayload
     * @param $sessionData
     * @return array
     * @throws SuperTokensGeneralException
     */
    public static function createNewSession($userId, $jwtPayload, $sessionData)
    {
        Utils::checkUserIdIsStringOrNumber($userId);
        $sessionHandle = Utils::generateSessionHandle();
        $refreshToken = RefreshToken::createNewRefreshToken($sessionHandle, $userId, null);
        $antiCsrfToken = Config::get("supertokens.tokens.enableAntiCsrf") ? Utils::generateUUID() : null;
        $accessToken = AccessToken::createNewAccessToken($sessionHandle, $userId, Utils::hashString($refreshToken['token']), $antiCsrfToken, null, $jwtPayload);

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
                'userId' => $userId,
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
            ],
           'antiCsrfToken' => $antiCsrfToken
        ];
    }

    /**
     * @param $accessToken
     * @param $antiCsrfToken
     * @return array
     * @throws SuperTokensGeneralException | SuperTokensUnauthorizedException | SuperTokensTryRefreshTokenException
     */
    public static function getSession($accessToken, $antiCsrfToken = null)
    {
        $accessTokenInfo = AccessToken::getInfoFromAccessToken($accessToken);
        $sessionHandle = $accessTokenInfo['sessionHandle'];

        $antiCsrfToken = Config::get("supertokens.tokens.enableAntiCsrf") ? $antiCsrfToken : null;
        if ($antiCsrfToken !== null) {
            if ($antiCsrfToken !== $accessTokenInfo['antiCsrfToken']) {
                throw SuperTokensException::generateTryRefreshTokenException("anti-csrf check failed");
            }
        }

        $blacklisting = Config::get('supertokens.tokens.accessToken.blacklisting');

        if (isset($blacklisting) && $blacklisting === true) {
            $isBlacklisted = RefreshTokenDb::isSessionBlacklisted($sessionHandle);
            if ($isBlacklisted) {
                throw SuperTokensException::generateUnauthorisedException("session is over or has been blacklisted");
            }
        }

        if (!isset($accessTokenInfo['parentRefreshTokenHash1'])) {
            return [
                'session' => [
                    'handle' => $accessTokenInfo['sessionHandle'],
                    'userId' => $accessTokenInfo['userId'],
                    'jwtPayload' => $accessTokenInfo['userPayload'],
                ]
            ];
        }

        $rollback = false;
        try {
            DB::beginTransaction();
            $rollback = true;
            $sessionInfo = RefreshTokenDb::getSessionInfoForUpdate($sessionHandle);
            if (!isset($sessionInfo)) {
                DB::commit();
                $rollback = false;
                throw SuperTokensException::generateUnauthorisedException("missing session in db");
            }

            $promote = $sessionInfo['refreshTokenHash2'] === Utils::hashString($accessTokenInfo['parentRefreshTokenHash1']);
            if ($promote || $sessionInfo['refreshTokenHash2'] === Utils::hashString($accessTokenInfo['refreshTokenHash1'])) {
                if ($promote) {
                    $validity = RefreshToken::getValidity();
                    $date = new DateTime();
                    $currentTimestamp = $date->getTimestamp();
                    $expiresAt = $currentTimestamp + $validity;
                    RefreshTokenDb::updateSessionInfo_Transaction(
                        $sessionHandle,
                        Utils::hashString($accessTokenInfo['refreshTokenHash1']),
                        $sessionInfo['sessionData'],
                        $expiresAt
                    );
                }
                DB::commit();
                $rollback = false;
                $newAccessToken = AccessToken::createNewAccessToken(
                    $sessionHandle,
                    $accessTokenInfo['userId'],
                    $accessTokenInfo['refreshTokenHash1'],
                    $accessTokenInfo['antiCsrfToken'],
                    null,
                    $accessTokenInfo['userPayload']
                );
                return [
                    'session' => [
                        'handle' => $sessionHandle,
                        'userId' => $accessTokenInfo['userId'],
                        'jwtPayload' => $accessTokenInfo['userPayload'],
                    ],
                    'newAccessToken' => [
                        'value' => $newAccessToken['token'],
                        'expires' => $newAccessToken['expiry'],
                    ],
                ];
            }

            $rollback = false;
            DB::commit();
            throw SuperTokensException::generateUnauthorisedException("using access token whose refresh token is no more.");
        } catch (Exception $e) {
            if ($rollback) {
                DB::rollBack();
            }
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $refreshToken
     * @return array
     * @throws SuperTokensException
     * @throws SuperTokensUnauthorizedException
     * @throws SuperTokensTokenTheftException
     */
    public static function refreshSession($refreshToken)
    {
        $refreshTokenInfo = RefreshToken::getInfoFromRefreshToken($refreshToken);
        return SessionHandlingFunctions::refreshSessionHelper($refreshToken, $refreshTokenInfo);
    }

    /**
     * @param $refreshToken
     * @param $refreshTokenInfo
     * @return array
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     * @throws SuperTokensTokenTheftException
     */
    public static function refreshSessionHelper($refreshToken, $refreshTokenInfo)
    {
        $sessionHandle = $refreshTokenInfo['sessionHandle'];
        $rollback = false;
        try {
            DB::beginTransaction();
            $rollback = true;

            $sessionInfo = RefreshTokenDb::getSessionInfoForUpdate($sessionHandle);
            $date = new DateTime();
            $currentTimestamp = $date->getTimestamp();
            if (!isset($sessionInfo) || $sessionInfo['expiresAt'] < $currentTimestamp) {
                DB::commit();
                $rollback = false;
                throw SuperTokensException::generateUnauthorisedException("session does not exist or has expired");
            }

            if ($sessionInfo['userId'] !== $refreshTokenInfo['userId']) {
                DB::commit();
                $rollback = false;
                throw SuperTokensException::generateUnauthorisedException("userId for session does not match the userId in the refresh token");
            }

            if ($sessionInfo['refreshTokenHash2'] === Utils::hashString(Utils::hashString($refreshToken))) {
                DB::commit();
                $rollback = false;
                $newRefreshToken = RefreshToken::createNewRefreshToken($sessionHandle, $refreshTokenInfo['userId'], Utils::hashString($refreshToken));
                $newAntiCsrfToken = Config::get("supertokens.tokens.enableAntiCsrf") ? Utils::generateUUID() : null;
                $newAccessToken = AccessToken::createNewAccessToken(
                    $sessionHandle,
                    $refreshTokenInfo['userId'],
                    Utils::hashString($newRefreshToken['token']),
                    $newAntiCsrfToken,
                    Utils::hashString($refreshToken),
                    $sessionInfo['jwtPayload']
                );
                return [
                    'session' => [
                        'handle' => $sessionHandle,
                        'userId' => $refreshTokenInfo['userId'],
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
                    ],
                    'newAntiCsrfToken' => $newAntiCsrfToken
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
                $validity = RefreshToken::getValidity();
                $date = new DateTime();
                $currentTimestamp = $date->getTimestamp();
                $expiresAt = $currentTimestamp + $validity;
                RefreshTokenDb::updateSessionInfo_Transaction(
                    $sessionHandle,
                    Utils::hashString(Utils::hashString($refreshToken)),
                    $sessionInfo['sessionData'],
                    $expiresAt
                );
                DB::commit();
                $rollback = false;
                // now we can generate children tokens for the current input token.
                return SessionHandlingFunctions::refreshSessionHelper($refreshToken, $refreshTokenInfo);
            }

            DB::commit();
            $rollback = false;
            throw SuperTokensException::generateTokenTheftException($sessionInfo['userId'], $sessionHandle);
        } catch (Exception $e) {
            if ($rollback) {
                DB::rollBack();
            }
            if ($e instanceof SuperTokensTokenTheftException) {
                throw $e;
            }
            if ($e instanceof SuperTokensUnauthorizedException) {
                throw $e;
            }
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $userId
     * @throws SuperTokensGeneralException
     */
    public static function revokeAllSessionsForUser($userId)
    {
        $sessionHandles = RefreshTokenDb::getAllSessionHandlesForUser($userId);
        for ($i = 0; $i < count($sessionHandles); $i++) {
            SessionHandlingFunctions::revokeSessionUsingSessionHandle($sessionHandles[$i]);
        }
    }

    /**
     * @param $userId
     * @return array
     * @throws SuperTokensGeneralException
     */
    public static function getAllSessionHandlesForUser($userId)
    {
        return RefreshTokenDb::getAllSessionHandlesForUser($userId);
    }

    /**
     * @param $sessionHandle
     * @return bool
     * @throws SuperTokensGeneralException
     */
    public static function revokeSessionUsingSessionHandle($sessionHandle)
    {
        return RefreshTokenDb::deleteSession($sessionHandle) === 1;
    }

    /**
     * @param $sessionHandle
     * @return mixed
     * @throws Exception
     * @throws SuperTokensUnauthorizedException | SuperTokensGeneralException
     */
    public static function getSessionData($sessionHandle)
    {
        $result = RefreshTokenDb::getSessionData($sessionHandle);
        if (!$result['found']) {
            throw SuperTokensException::generateUnauthorisedException("session does not exist anymore");
        }
        return $result['data'];
    }

    /**
     * @param $sessionHandle
     * @param $newSessionData
     * @throws SuperTokensUnauthorizedException | SuperTokensGeneralException
     */
    public static function updateSessionData($sessionHandle, $newSessionData)
    {
        $affected = RefreshTokenDb::updateSessionData($sessionHandle, $newSessionData);
        if ($affected !== 1) {
            throw SuperTokensException::generateUnauthorisedException("session does not exist anymore");
        }
    }
}
