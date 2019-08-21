<?php

namespace SuperTokens\Session\Helpers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Config;
use mysql_xdevapi\Exception;
use SuperTokens\Session\Exceptions\SuperTokensException;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;

define("ACCESS_TOKEN_COOKIE_KEY", "sAccessToken");
define("REFRESH_TOKEN_COOKIE_KEY", "sRefreshToken");
define("ID_REFRESH_TOKEN_COOKIE_KEY", "sIdRefreshToken");
define("ANTI_CSRF_HEADER_KEY", "anti-csrf");

class CookieAndHeader
{
    public static function setOptionsAPIHeader(Response $response)
    {
        CookieAndHeader::setHeader($response, "Access-Control-Allow-Headers", ANTI_CSRF_HEADER_KEY);
        CookieAndHeader::setHeader($response, "Access-Control-Allow-Credentials", "true");
    }

    public static function setHeader(Response $response, $key, $value)
    {
        $response->header($key, $value);
    }

    private static function getHeader(Request $request, $key)
    {
        $value = $request->header($key);
        return $value;
    }

    public static function attachAntiCsrfHeaderIfRequired(Response $response, $value)
    {
        if (Config::get("supertokens.tokens.enableAntiCsrf")) {
            if ($value === null) {
                throw SuperTokensException::generateGeneralException("BUG: anti-csrf token is null. if you are getting this error, please report it as bug.");
            }
            CookieAndHeader::setHeader($response, ANTI_CSRF_HEADER_KEY, $value);
            CookieAndHeader::setHeader($response, "Access-Control-Expose-Headers", ANTI_CSRF_HEADER_KEY);
        }
    }

    public static function getAntiCsrfHeader(Request $request)
    {
        return CookieAndHeader::getHeader($request, ANTI_CSRF_HEADER_KEY);
    }

    /**
     * @param Response $response
     * @param $key
     * @param $value
     * @param $minutes
     * @param $path
     * @param $domain
     * @param $secure
     * @param $httpOnly
     */
    public static function setCookie(Response $response, $key, $value, $minutes, $path, $domain, $secure, $httpOnly)
    {
        $response->withCookie(cookie($key, $value, $minutes, $path, $domain, $secure, $httpOnly));
    }

    /**
     * @param Request $request
     * @param $key
     * @return string|null
     */
    public static function getCookie(Request $request, $key)
    {
        $value = $request->cookie($key);

        return $value;
    }

    /**
     * @param Response $response
     */
    public static function clearSessionFromCookie(Response $response)
    {
        CookieAndHeader::setCookie($response, ACCESS_TOKEN_COOKIE_KEY, "", 0, Config::get("supertokens.tokens.accessToken.accessTokenPath"), CookieAndHeader::getDomain(), CookieAndHeader::getSecure(), true);
        CookieAndHeader::setCookie($response, ID_REFRESH_TOKEN_COOKIE_KEY, "", 0, Config::get("supertokens.tokens.accessToken.accessTokenPath"), CookieAndHeader::getDomain(), false, false);
        CookieAndHeader::setCookie($response, REFRESH_TOKEN_COOKIE_KEY, "", 0, CookieAndHeader::getRefreshTokenPath(), CookieAndHeader::getDomain(), CookieAndHeader::getSecure(), true);
    }

    /**
     * @param Response $response
     * @param $token
     * @param $expiresAt
     * @throws SuperTokensGeneralException
     */
    public static function attachAccessTokenToCookie(Response $response, $token, $expiresAt)
    {
        CookieAndHeader::setCookie($response, ACCESS_TOKEN_COOKIE_KEY, $token, CookieAndHeader::getMinutes($expiresAt), Config::get("supertokens.tokens.accessToken.accessTokenPath"), CookieAndHeader::getDomain(), CookieAndHeader::getSecure(), true);
    }

    /**
     * @param Response $response
     * @param $token
     * @param $expiresAt
     * @throws SuperTokensGeneralException
     */
    public static function attachRefreshTokenToCookie(Response $response, $token, $expiresAt)
    {
        CookieAndHeader::setCookie($response, REFRESH_TOKEN_COOKIE_KEY, $token, CookieAndHeader::getMinutes($expiresAt), CookieAndHeader::getRefreshTokenPath(), CookieAndHeader::getDomain(), CookieAndHeader::getSecure(), true);
    }

    /**
     * @param Response $response
     * @param $token
     * @param $expiresAt
     * @throws SuperTokensGeneralException
     */
    public static function attachIdRefreshTokenToCookie(Response $response, $token, $expiresAt)
    {
        CookieAndHeader::setCookie($response, ID_REFRESH_TOKEN_COOKIE_KEY, $token, CookieAndHeader::getMinutes($expiresAt), Config::get("supertokens.tokens.accessToken.accessTokenPath"), CookieAndHeader::getDomain(), false, false);
    }

    /**
     * @param Request $request
     * @return string|null
     */
    public static function getAccessTokenFromCookie(Request $request)
    {
        return self::getCookie($request, ACCESS_TOKEN_COOKIE_KEY);
    }

    /**
     * @param Request $request
     * @return string|null
     */
    public static function getRefreshTokenFromCookie(Request $request)
    {
        return self::getCookie($request, REFRESH_TOKEN_COOKIE_KEY);
    }

    /**
     * @param Request $request
     * @return string|null
     */
    public static function getIdRefreshTokenFromCookie(Request $request)
    {
        return self::getCookie($request, ID_REFRESH_TOKEN_COOKIE_KEY);
    }

    /**
     * @return mixed
     */
    private static function getDomain()
    {
        return Config::get("supertokens.cookie.domain");
    }

    /**
     * @return mixed
     */
    private static function getSecure()
    {
        return Config::get("supertokens.cookie.secure");
    }

    /**
     * @return mixed
     */
    private static function getRefreshTokenPath()
    {
        return Config::get("supertokens.tokens.refreshToken.renewTokenPath");
    }

    /**
     * @param $expiresAt
     * @return int
     * @throws SuperTokensGeneralException
     */
    private static function getMinutes($expiresAt)
    {
        $currentTimestamp = Utils::getDateTimeStamp();
        $minutes = floor(($expiresAt - $currentTimestamp) / 60);
        $minutes = max(0, $minutes);
        return (int)$minutes;
    }
}
