<?php


return [
    'tokens' => [
        'accessToken' => [
            'signingKey' => [
                'dynamic' => env('SUPER_TOKEN_AT_SK_DYNAMIC', true),
                'updateInterval' => env('SUPER_TOKEN_AT_SK_UPDATE_INTERVAL', 24),
                'get' => null,
            ],
            'validity' => env('SUPER_TOKEN_AT_VALIDITY', 3600),
            'blacklisting' => env('SUPER_TOKEN_AT_BLACKLISTING', false),
            'accessTokenPath' => env('SUPER_TOKEN_AT_PATH', "/"),
        ],
        'enableAntiCsrf' => env('SUPER_TOKEN_ENABLE_ANTI_CSRF', true),
        'refreshToken' => [
            'validity' => env('SUPER_TOKEN_RT_VALIDITY', 2400),
            'removalCronjobInterval' => env('SUPER_TOKEN_RT_AUTO_REMOVE_INTERVAL', '0 0 1-31/7 * *'),
            'renewTokenPath' => env('SUPER_TOKEN_RT_RENEW_PATH'),
        ],
    ],
    'cookie' => [
        'domain' => env('SUPER_TOKEN_COOKIE_DOMAIN', 'localhost'),
        'secure' => env('SUPER_TOKEN_COOKIE_SECURE', true)
    ]
];