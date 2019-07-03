<?php

namespace SuperTokens\Session\Helpers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Config;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;

define("ACCESS_TOKEN_COOKIE_KEY", "sAccessToken");
define("REFRESH_TOKEN_COOKIE_KEY", "sRefreshToken");
define("ID_REFRESH_TOKEN_COOKIE_KEY", "sIdRefreshToken");

class Cookie {

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
    public static function setCookie(Response $response, $key, $value, $minutes, $path, $domain, $secure, $httpOnly) {
        $response->withCookie(cookie($key, $value, $minutes, $path, $domain, $secure, $httpOnly));
        return;
    }

    /**
     * @param Request $request
     * @param $key
     * @return string|null
     */
    public static function getCookie(Request $request, $key) {
        $value = $request->cookie($key);

        return $value;
    }

    /**
     * @param Response $response
     */
    public static function clearSessionFromCookie(Response $response) {
        Cookie::setCookie($response, ACCESS_TOKEN_COOKIE_KEY, "", 0, "/", Cookie::getDomain(), Cookie::getSecure(), true);
        Cookie::setCookie($response, ID_REFRESH_TOKEN_COOKIE_KEY, "", 0, "/", Cookie::getDomain(), false, false);
        Cookie::setCookie($response, REFRESH_TOKEN_COOKIE_KEY, "", 0, Cookie::getRefreshTokenPath(), Cookie::getDomain(), Cookie::getSecure(), true);
    }

    /**
     * @param Response $response
     * @param $token
     * @param $expiresAt
     * @throws SuperTokensGeneralException
     */
    public static function attachAccessTokenToCookie(Response $response, $token, $expiresAt) {
        Cookie::setCookie($response, ACCESS_TOKEN_COOKIE_KEY, $token, Cookie::getMinutes($expiresAt), "/", Cookie::getDomain(), Cookie::getSecure(), true);
    }

    /**
     * @param Response $response
     * @param $token
     * @param $expiresAt
     * @throws SuperTokensGeneralException
     */
    public static function attachRefreshTokenToCookie(Response $response, $token, $expiresAt) {
        Cookie::setCookie($response, REFRESH_TOKEN_COOKIE_KEY, $token, Cookie::getMinutes($expiresAt), Cookie::getRefreshTokenPath(), Cookie::getDomain(), Cookie::getSecure(), true);
    }

    /**
     * @param Response $response
     * @param $token
     * @param $expiresAt
     * @throws SuperTokensGeneralException
     */
    public static function attachIdRefreshTokenToCookie(Response $response, $token, $expiresAt) {
        Cookie::setCookie($response, ID_REFRESH_TOKEN_COOKIE_KEY, $token, Cookie::getMinutes($expiresAt), "/", Cookie::getDomain(), false, false);
    }

    /**
     * @param Request $request
     * @return string|null
     */
    public static function getAccessTokenFromCookie(Request $request) {
        return self::getCookie($request, ACCESS_TOKEN_COOKIE_KEY);
    }

    /**
     * @param Request $request
     * @return string|null
     */
    public static function getRefreshTokenFromCookie(Request $request) {
        return self::getCookie($request, REFRESH_TOKEN_COOKIE_KEY);
    }

    /**
     * @param Request $request
     * @return string|null
     */
    public static function getIdRefreshTokenFromCookie(Request $request) {
        return self::getCookie($request, ID_REFRESH_TOKEN_COOKIE_KEY);
    }

    /**
     * @return mixed
     */
    private static function getDomain() {
        return Config::get("supertokens.cookie.domain");
    }

    /**
     * @return mixed
     */
    private static function getSecure() {
        return Config::get("supertokens.cookie.secure");
    }

    /**
     * @return mixed
     */
    private static function getRefreshTokenPath() {
        return Config::get("supertokens.tokens.refreshToken.renewTokenPath");
    }

    /**
     * @param $expiresAt
     * @return int
     * @throws SuperTokensGeneralException
     */
    private static function getMinutes($expiresAt) {
        $currentTimestamp = Utils::getDateTimeStamp();
        $minutes = floor(($expiresAt - $currentTimestamp) / 60);
        $minutes = max(0, $minutes);
        return (int)$minutes;
    }
}