<?php

namespace SuperTokens\Laravel\Helpers;

use SuperTokens\Laravel\Helpers\Utils;

class Jwt {
    
    protected static function getHeader() {
        return base64_encode(json_encode([
            'alg' => 'HS256',
            'typ' => 'JWT'
        ]));
    }

    public static function createJWT($plainTextPayload, string $signingKey) {
        $header = Jwt::getHeader();
        $payload = base64_encode(json_encode($plainTextPayload));
        $signature = Utils::hmac($header.".".$payload, $signingKey);
        return "$header.$payload.$signature";
    }

    public static function verifyJWTAndGetPayload(string $jwt, string $signingKey) {
        $splittedInput = explode(".", $jwt);
        $header = Jwt::getHeader();

        if (count($splittedInput) !== 3) {
            // error
        }

        if ($splittedInput[0] !== $header) {
            // error
        }

        $payload = $splittedInput[1];
        $signatureFromHeaderAndPayload = Utils::hmac($header.".".$payload, $signingKey);

        if ($signatureFromHeaderAndPayload !== $splittedInput[2]) {
            // error
        }

        $payload = base64_decode($payload);
        return json_decode($payload);
    }
}