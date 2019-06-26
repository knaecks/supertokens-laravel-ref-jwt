<?php

namespace SuperTokens\Session;

use DateTime;
use Closure;
use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use SuperTokens\Session\Exceptions\SuperTokensAuthException;
use SuperTokens\Session\Exceptions\UnauthorizedException;
use SuperTokens\Session\Helpers\Utils;
use SuperTokens\Session\Db\RefreshTokenDb;
use SuperTokens\Session\Helpers\AccessTokenSigningKey;
use SuperTokens\Session\Helpers\RefreshTokenSigningKey;

/**
 * Class Session
 * @package SuperTokens\Session
 */
class Session {

    /**
     * @var bool
     */
    private static $isInitiated = false;

    /**
     * Session constructor.
     * @throws Exception
     */
    public function __construct(Closure $getSigningKey = null) {
        if (!Session::$isInitiated) {
            AccessTokenSigningKey::init($getSigningKey);
            RefreshTokenSigningKey::init();
            Session::$isInitiated = true;
        }
    }

    /**
     * @param $userId
     * @param $jwtPayload
     * @param $sessionData
     * @return array
     * @throws SuperTokensAuthException | Exception
     */
    public function createNewSession($userId, $jwtPayload, $sessionData) {
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
            ]
        ];
    }

    /**
     * @param $accessToken
     * @return array
     * @throws SuperTokensAuthException | Exception
     */
    public function getSession($accessToken) {
        $accessTokenInfo = AccessToken::getInfoFromAccessToken($accessToken);
        $sessionHandle = $accessTokenInfo['sessionHandle'];

        $blacklisting = Config::get('supertokens.tokens.accessToken.blacklisting');

        if (isset($blacklisting) && $blacklisting) {
            $isBlacklisted = RefreshTokenDb::isSessionBlacklisted($sessionHandle);
            if ($isBlacklisted) {
                throw new UnauthorizedException("session is over or has been blacklisted");
            }
        }

        if (!isset($accessTokenInfo['parentRefreshTokenHash1'])) {
            return [
                'session' => [
                    'handle' => $accessTokenInfo['sessionHandle'],
                    'userId' => $accessTokenInfo['userId'],
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
                throw new UnauthorizedException("missing session in db");
            }

            $promote = $sessionInfo['refreshTokenHash2'] === Utils::hashString($accessTokenInfo['parentRefreshTokenHash1']);
            if ($promote || $sessionInfo['refreshTokenHash2'] === Utils::hashString($accessTokenInfo['refreshTokenHash1'])) {

                if ($promote) {
                    $validity = Config::get('supertokens.tokens.refreshToken.validity');
                    $date = new DateTime();
                    $currentTimestamp = $date->getTimestamp();
                    $expiresAt = $currentTimestamp + $validity;
                    RefreshTokenDb::updateSessionInfo(
                        $sessionHandle,
                        Utils::hashString($accessTokenInfo['refreshTokenHash1']),
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
                        'userId' => $accessTokenInfo['userId'],
                        'jwtPayload' => $accessTokenInfo['userPayload'],
                    ],
                    'newAccessToken' => [
                        'value' => $newAccessToken['token'],
                        'expires' => $newAccessToken['expiry'],
                    ],
                ];
            }

            DB::commit();
            throw new UnauthorizedException("using access token whose refresh token is no more.");
        } catch(Exception $e) {
            DB::rollBack();
            throw $e;
        }
    }

    /**
     * @param $refreshToken
     * @return array
     * @throws SuperTokensAuthException | Exception
     */
    public function refreshSession($refreshToken) {
        $refreshTokenInfo = RefreshToken::getInfoFromRefreshToken($refreshToken);
        return Session::refreshSessionHelper($refreshToken, $refreshTokenInfo);
    }

    /**
     * @param $refreshToken
     * @param $refreshTokenInfo
     * @return array
     * @throws SuperTokensAuthException | Exception
     */
    public function refreshSessionHelper($refreshToken, $refreshTokenInfo) {
        $sessionHandle = $refreshTokenInfo['sessionHandle'];
        DB::beginTransaction();
        try {

            $sessionInfo = RefreshTokenDb::getSessionInfo($sessionHandle);
            $date = new DateTime();
            $currentTimestamp = $date->getTimestamp();
            if (!isset($sessionInfo) || $sessionInfo['expiresAt'] < $currentTimestamp) {
                DB::commit();
                throw new UnauthorizedException("session does not exist or has expired");
            }

            if ($sessionInfo['userId'] !== $refreshTokenInfo['userId']) {
                DB::commit();
                throw new UnauthorizedException("userId for session does not match the userId in the refresh token");
            }

            if ($sessionInfo['refreshTokenHash2'] === Utils::hashString(Utils::hashString($refreshToken))) {
                DB::commit();
                $newRefreshToken = RefreshToken::createNewRefreshToken($sessionHandle, $refreshTokenInfo['userId'], Utils::hashString($refreshToken));
                $newAccessToken = AccessToken::createNewAccessToken(
                    $sessionHandle,
                    $refreshTokenInfo['userId'],
                    Utils::hashString($newRefreshToken['token']),
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
                $validity = Config::get('supertokens.tokens.refreshToken.validity');
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
            throw new UnauthorizedException("token theft detected!");
        } catch (Exception $e) {
            DB::rollBack();
            throw $e;
        }
    }

    /**
     * @param $userId
     */
    public function revokeAllSessionsForUser($userId) {
        $sessionHandles = RefreshTokenDb::getAllSessionHandlesForUser($userId);
        for ($i = 0; $i < count($sessionHandles); $i++) {
            Session::revokeSessionUsingSessionHandle($sessionHandles[$i]);
        }
    }

    /**
     * @param $userId
     * @return array
     */
    public function getAllSessionHandlesForUser($userId) {
        $sessionHandles = RefreshTokenDb::getAllSessionHandlesForUser($userId);
        return $sessionHandles;
    }

    /**
     * @param $sessionHandle
     */
    public function revokeSessionUsingSessionHandle($sessionHandle) {
        RefreshTokenDb::deleteSession($sessionHandle);
    }

    /**
     * @param $sessionHandle
     * @return mixed
     * @throws UnauthorizedException
     */
    public function getSessionData($sessionHandle) {
        $result = RefreshTokenDb::getSessionData($sessionHandle);
        if (!$result['found']) {
            throw new UnauthorizedException("session does not exist anymore");
        }
        return $result['data'];
    }

    /**
     * @param $sessionHandle
     * @param $newSessionData
     */
    public function updateSessionData($sessionHandle, $newSessionData) {
        RefreshTokenDb::updateSessionData($sessionHandle, $newSessionData);
    }
}