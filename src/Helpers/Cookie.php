<?php

namespace SuperTokens\Session\Helpers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

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
        $response->withCookie($key, $value, $minutes, $path, $domain, $secure, $httpOnly);
        return;
    }

    /**
     * @param Request $request
     * @param $key
     * @return array|string|null
     */
    public static function getCookie(Request $request, $key) {
        $value = $request->cookie($key);
        return $value;
    }
}