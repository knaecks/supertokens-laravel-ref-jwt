<?php

namespace SuperTokens\Session\Tests;

use Exception;
use SuperTokens\Session\Helpers\Jwt;

class JwtTest extends TestCase
{

    /**
     * @throws Exception
     */
    public function testCreateAndVerifyJWT_SameSigningKey()
    {
        $payload = [
            'userId' => 'testing'
        ];
        $signature = 'supertokens';

        $jwt = Jwt::createJWT($payload, $signature);

        $payloadFromJwt = Jwt::verifyJWTAndGetPayload($jwt, $signature);
        $this->assertEquals($payload, $payloadFromJwt);
    }

    /**
     * @throws Exception
     */
    public function testCreateAndVerifyJWT_DifferentSigningKey()
    {
        $payload = [
            'userId' => 'testing'
        ];
        $signature = 'supertokens';

        $jwt = Jwt::createJWT($payload, $signature);

        $signature = 'supertokens2';
        $error = false;
        try {
            Jwt::verifyJWTAndGetPayload($jwt, $signature);
            $error = true;
        } catch (Exception $e) {
            $this->assertTrue(true);
        }

        if ($error) {
            throw new Exception("jwt verified with wrong signing key");
        }
    }
}
