<?php

namespace SuperTokens\Session;


use Exception;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use SuperTokens\Session\Exceptions\SuperTokensTokenTheftException;
use SuperTokens\Session\Helpers\Cookie;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensUnauthorizedException;
use SuperTokens\Session\Exceptions\SuperTokensTryRefreshTokenException;

class SuperToken {

    /**
     * Session constructor.
     * @throws Exception
     */
    public function __construct() {
        new Session();
    }

    /**
     * @param Response $response
     * @param $userId
     * @param null $jwtPayload
     * @param null $sessionData
     * @return SuperTokenSession
     * @throws SuperTokensGeneralException
     */
    public static function createNewSession(Response $response, $userId, $jwtPayload = null, $sessionData = null) {
        $newSession = Session::createNewSession($userId, $jwtPayload, $sessionData);

        Cookie::attachAccessTokenToCookie($response, $newSession['accessToken']['value'], $newSession['accessToken']['expires']);
        Cookie::attachRefreshTokenToCookie($response, $newSession['refreshToken']['value'], $newSession['refreshToken']['expires']);
        Cookie::attachIdRefreshTokenToCookie($response, $newSession['idRefreshToken']['value'], $newSession['idRefreshToken']['expires']);

        return new SuperTokenSession($newSession['session']['handle'], $newSession['session']['userId'], $newSession['session']['jwtPayload'], $response);
    }

    /**
     * @param Request $request
     * @param Response $response
     * @return SuperTokenSession
     * @throws SuperTokensGeneralException
     * @throws SuperTokensTryRefreshTokenException
     * @throws SuperTokensUnauthorizedException
     */
    public static function getSession(Request $request, Response $response) {
        $idRefreshToken = Cookie::getIdRefreshTokenFromCookie($request);

        if (!isset($idRefreshToken) || $idRefreshToken === null) {
            Cookie::clearSessionFromCookie($response);
            throw new SuperTokensUnauthorizedException("missing auth tokens in cookies");
        }

        $accessToken = Cookie::getAccessTokenFromCookie($request);
        if (!isset($accessToken)) {
            throw new SuperTokensTryRefreshTokenException("access token missing in cookies");
        }

        try {
            $newSession = Session::getSession($accessToken);
            if (isset($newSession['newAccessToken'])) {
                Cookie::attachAccessTokenToCookie($response, $newSession['newAccessToken']['value'], $newSession['newAccessToken']['expires']);
            }
            return new SuperTokenSession($newSession['session']['handle'], $newSession['session']['userId'], $newSession['session']['jwtPayload'], $response);
        } catch (SuperTokensUnauthorizedException $e) {
            Cookie::clearSessionFromCookie($response);
            throw $e;
        }
    }

    /**
     * @param Request $request
     * @param Response $response
     * @return SuperTokenSession
     * @throws Exceptions\SuperTokensException
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     * @throws SuperTokensTokenTheftException

     */
    public static function refreshSession(Request $request, Response $response) {
        $refreshToken = Cookie::getRefreshTokenFromCookie($request);
        $idRefreshToken = Cookie::getIdRefreshTokenFromCookie($request);
        if (!isset($refreshToken) || !isset($idRefreshToken)) {
            Cookie::clearSessionFromCookie($response);
            throw new SuperTokensUnauthorizedException("missing auth tokens in cookies");
        }

        try {
            $newSession = Session::refreshSession($refreshToken);

            Cookie::attachAccessTokenToCookie($response, $newSession['newAccessToken']['value'], $newSession['newAccessToken']['expires']);
            Cookie::attachRefreshTokenToCookie($response, $newSession['newRefreshToken']['value'], $newSession['newRefreshToken']['expires']);
            Cookie::attachIdRefreshTokenToCookie($response, $newSession['newIdRefreshToken']['value'], $newSession['newIdRefreshToken']['expires']);

            return new SuperTokenSession($newSession['session']['handle'], $newSession['session']['userId'], $newSession['session']['jwtPayload'], $response);
        } catch (SuperTokensUnauthorizedException $e) {
            Cookie::clearSessionFromCookie($response);
            throw $e;
        } catch (SuperTokensTokenTheftException $e) {
            Cookie::clearSessionFromCookie($response);
            throw $e;
        }
    }

    /**
     * @param $userId
     * @throws SuperTokensGeneralException
     */
    public static function revokeAllSessionsForUser($userId) {
        Session::revokeAllSessionsForUser($userId);
    }

    /**
     * @param $userId
     * @throws SuperTokensGeneralException
     */
    public static function getAllSessionHandlesForUser($userId) {
        Session::getAllSessionHandlesForUser($userId);
    }

    /**
     * @param $sessionHandle
     * @throws SuperTokensGeneralException
     */
    public static function revokeSessionUsingSessionHandle($sessionHandle) {
        Session::revokeSessionUsingSessionHandle($sessionHandle);
    }

    /**
     * @param $sessionHandle
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     */
    public static function getSessionDataForSessionHandle($sessionHandle) {
        Session::getSessionData($sessionHandle);
    }

    /**
     * @param $sessionHandle
     * @param null $newSessionData
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     */
    public static function updateSessionDataForSessionHandle($sessionHandle, $newSessionData = null) {
        Session::updateSessionData($sessionHandle, $newSessionData);
    }
}