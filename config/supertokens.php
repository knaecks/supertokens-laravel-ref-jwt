<?php


return [
    'tokens' => [
        'accessToken' => [
            'signingKey' => [
                'dynamic' => env('AA', true),
                'updateInterval' => env('BB', 24),
                'get' => null,
            ],
            'validity' => env('DD', 3600),
            'blacklisting' => env('EE', false),
        ],
        'refreshToken' => [
            'validity' => env('FF', 2400),
            'removalCronjobInterval' => env('GG'),
            'renewTokenPath' => env('HH'),
        ],
    ]
];