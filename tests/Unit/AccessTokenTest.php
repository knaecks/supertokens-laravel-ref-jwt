<?php

namespace SuperTokens\Session\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\Concerns\CreatesApplication;
use SuperTokens\Session\AccessToken;
use SuperTokens\Session\Helpers\AccessTokenSigningKey;
use SuperTokens\Session\Session;
use SuperTokens\Session\Exceptions\SuperTokensAuthException;

class AccessTokenTest extends TestCase {
    use RefreshDatabase;

    /**
     * @throws SuperTokensAuthException
     */
    public function testCreateAndGetInfo() {
        new Session();

        $sessionHandle = "sessionHandle";
        $userId = "userId";
        $refreshTokenHash1 = "refreshTokenHash1";
        $parentRefreshTokenHash1 = "parentRefreshTokenHash1";
        $userPayload = [
            "a" => "a"
        ];

        $token = AccessToken::createNewAccessToken($sessionHandle, $userId, $refreshTokenHash1, $parentRefreshTokenHash1, $userPayload);
        $infoFromToken = AccessToken::getInfoFromAccessToken(($token['token']));
        $this->assertEquals($infoFromToken, [
            "sessionHandle" => "sessionHandle",
            "userId" => "userId",
            "refreshTokenHash1" => "refreshTokenHash1",
            "expiryTime" => $token['expiry'],
            "parentRefreshTokenHash1" => "parentRefreshTokenHash1",
            "userPayload" => [
                "a" => "a"
            ]
        ]);
    }

    /**
     * @throws SuperTokensAuthException
     */
    public function testUserDefinedSingingKeyFunction() {
        Config::set('supertokens.tokens.accessToken.signingKey.get', function () { return "supertokens_testing"; });
        new Session();

        $key = AccessTokenSigningKey::getKey();

        $this->assertEquals($key, "supertokens_testing");
    }
}