<?php

namespace SuperTokens\Laravel\Helpers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;

class Cookie {

    /**
     *
     */
    public static function setCookie(Response $response, string $key, string $value, $minutes, $path, $domain, $secure, $httpOnly) {
        $response->withCookie(cookie($key, $value, $minutes, $path, $domain, $secure, $httpOnly));
        return;
    }

    /**
     *
     */
    public static function getCookie(Request $request, string $key) {
        $value = $request->cookie($key);
        return $value;
    }
}