<?php

namespace SuperTokens\Laravel\Helpers;
use Exception;

class Jwt {

    /**
     * @return string
     */
    protected static function getHeader() {
        return base64_encode(json_encode([
            'alg' => 'HS256',
            'typ' => 'JWT'
        ]));
    }

    /**
     * @param $plainTextPayload
     * @param $signingKey
     * @return string
     */
    public static function createJWT($plainTextPayload, $signingKey) {
        $header = Jwt::getHeader();
        $payload = base64_encode(json_encode($plainTextPayload));
        $signature = Utils::hmac($header.".".$payload, $signingKey);
        return "$header.$payload.$signature";
    }

    /**
     * @param $jwt
     * @param $signingKey
     * @return mixed
     * @throws Exception
     */
    public static function verifyJWTAndGetPayload($jwt, $signingKey) {
        $splittedInput = explode(".", $jwt);
        $header = Jwt::getHeader();

        if (count($splittedInput) !== 3) {
            throw new Exception("invalid jwt");
        }

        if ($splittedInput[0] !== $header) {
            throw new Exception("jwt header mismatch");
        }

        $payload = $splittedInput[1];
        $signatureFromHeaderAndPayload = Utils::hmac($header.".".$payload, $signingKey);

        if ($signatureFromHeaderAndPayload !== $splittedInput[2]) {
            throw new Exception("jwt verification failed");
        }

        $payload = base64_decode($payload);
        return json_decode($payload);
    }
}