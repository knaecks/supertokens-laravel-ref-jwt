<?php

namespace SuperTokens\Session;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Config;
use SuperTokens\Session\Exceptions\SuperTokensException;
use SuperTokens\Session\Exceptions\SuperTokensTokenTheftException;
use SuperTokens\Session\Helpers\CookieAndHeader;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensUnauthorizedException;
use SuperTokens\Session\Exceptions\SuperTokensTryRefreshTokenException;

class SuperToken
{

    /**
     * SessionHandlingFunctions constructor.
     * @throws Exception
     */
    public function __construct()
    {
        new SessionHandlingFunctions();
    }

    /**
     * @param Response $response
     * @param $userId
     * @param null $jwtPayload
     * @param null $sessionInfo
     * @return Session
     * @throws SuperTokensGeneralException
     */
    public static function createNewSession(Response $response, $userId, $jwtPayload = null, $sessionInfo = null)
    {
        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionInfo);

        CookieAndHeader::attachAccessTokenToCookie($response, $newSession['accessToken']['value'], $newSession['accessToken']['expires']);
        CookieAndHeader::attachRefreshTokenToCookie($response, $newSession['refreshToken']['value'], $newSession['refreshToken']['expires']);
        CookieAndHeader::attachIdRefreshTokenToCookie($response, $newSession['idRefreshToken']['value'], $newSession['idRefreshToken']['expires']);
        CookieAndHeader::attachAntiCsrfHeaderIfRequired($response, $newSession['antiCsrfToken']);

        return new Session($newSession['session']['handle'], $newSession['session']['userId'], $newSession['session']['jwtPayload'], $response);
    }

    /**
     * @param Request $request
     * @param Response $response
     * @return Session
     * @throws SuperTokensGeneralException
     * @throws SuperTokensTryRefreshTokenException
     * @throws SuperTokensUnauthorizedException
     */
    public static function getSession(Request $request, Response $response, $enableCsrfProtection)
    {
        $idRefreshToken = CookieAndHeader::getIdRefreshTokenFromCookie($request);

        if (!isset($idRefreshToken) || $idRefreshToken === null) {
            CookieAndHeader::clearSessionFromCookie($response);
            throw SuperTokensException::generateUnauthorisedException("missing auth tokens in cookies");
        }

        $accessToken = CookieAndHeader::getAccessTokenFromCookie($request);
        if (!isset($accessToken)) {
            throw SuperTokensException::generateTryRefreshTokenException("access token missing in cookies");
        }

        try {
            $enableCsrfProtection = $enableCsrfProtection && Config::get("supertokens.tokens.enableAntiCsrf");
            $antiCsrfToken = $enableCsrfProtection ? CookieAndHeader::getAntiCsrfHeader($request) : null;
            if ($antiCsrfToken === null && $enableCsrfProtection) {
                throw SuperTokensException::generateTryRefreshTokenException("anti csrf token is missing");
            }
            $antiCsrfToken = $antiCsrfToken === null? false : $antiCsrfToken;
            $newSession = SessionHandlingFunctions::getSession($accessToken, $antiCsrfToken);
            if (isset($newSession['newAccessToken'])) {
                CookieAndHeader::attachAccessTokenToCookie($response, $newSession['newAccessToken']['value'], $newSession['newAccessToken']['expires']);
            }
            return new Session($newSession['session']['handle'], $newSession['session']['userId'], $newSession['session']['jwtPayload'], $response);
        } catch (SuperTokensUnauthorizedException $e) {
            CookieAndHeader::clearSessionFromCookie($response);
            throw $e;
        }
    }

    /**
     * @param Request $request
     * @param Response $response
     * @return Session
     * @throws Exceptions\SuperTokensException
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     * @throws SuperTokensTokenTheftException
 */
    public static function refreshSession(Request $request, Response $response)
    {
        $refreshToken = CookieAndHeader::getRefreshTokenFromCookie($request);
        $idRefreshToken = CookieAndHeader::getIdRefreshTokenFromCookie($request);
        if (!isset($refreshToken) || !isset($idRefreshToken)) {
            CookieAndHeader::clearSessionFromCookie($response);
            throw SuperTokensException::generateUnauthorisedException("missing auth tokens in cookies");
        }

        try {
            $newSession = SessionHandlingFunctions::refreshSession($refreshToken);

            CookieAndHeader::attachAccessTokenToCookie($response, $newSession['newAccessToken']['value'], $newSession['newAccessToken']['expires']);
            CookieAndHeader::attachRefreshTokenToCookie($response, $newSession['newRefreshToken']['value'], $newSession['newRefreshToken']['expires']);
            CookieAndHeader::attachIdRefreshTokenToCookie($response, $newSession['newIdRefreshToken']['value'], $newSession['newIdRefreshToken']['expires']);
            CookieAndHeader::attachAntiCsrfHeaderIfRequired($response, $newSession['newAntiCsrfToken']);

            return new Session($newSession['session']['handle'], $newSession['session']['userId'], $newSession['session']['jwtPayload'], $response);
        } catch (SuperTokensUnauthorizedException $e) {
            CookieAndHeader::clearSessionFromCookie($response);
            throw $e;
        } catch (SuperTokensTokenTheftException $e) {
            CookieAndHeader::clearSessionFromCookie($response);
            throw $e;
        }
    }

    /**
     * @param $userId
     * @throws SuperTokensGeneralException
     */
    public static function revokeAllSessionsForUser($userId)
    {
        SessionHandlingFunctions::revokeAllSessionsForUser($userId);
    }

    /**
     * @param $userId
     * @throws SuperTokensGeneralException
     */
    public static function getAllSessionHandlesForUser($userId)
    {
        SessionHandlingFunctions::getAllSessionHandlesForUser($userId);
    }

    /**
     * @param $sessionHandle
     * @throws SuperTokensGeneralException
     */
    public static function revokeSessionUsingSessionHandle($sessionHandle)
    {
        SessionHandlingFunctions::revokeSessionUsingSessionHandle($sessionHandle);
    }

    /**
     * @param $sessionHandle
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     */
    public static function getSessionInfoForSessionHandle($sessionHandle)
    {
        SessionHandlingFunctions::getSessionInfo($sessionHandle);
    }

    /**
     * @param $sessionHandle
     * @param null $newSessionInfo
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     */
    public static function updateSessionInfoForSessionHandle($sessionHandle, $newSessionInfo = null)
    {
        SessionHandlingFunctions::updateSessionInfo($sessionHandle, $newSessionInfo);
    }

    /**
     * @param Response $response
     */
    public static function setRelevantHeadersForOptionAPI(Response $response)
    {
        CookieAndHeader::setOptionsAPIHeader($response);
    }
}
