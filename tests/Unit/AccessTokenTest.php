<?php

namespace SuperTokens\Session\Tests;

use function FinalAnnotations\finalFoo;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Exception;
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
        AccessTokenSigningKey::resetInstance();
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
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.get', function () { return "supertokens_testing"; });
        new Session();

        $key = AccessTokenSigningKey::getKey();

        $this->assertEquals($key, "supertokens_testing");
    }

    /**
     * @throws SuperTokensAuthException
     */
    public function testVeryShortUpdateIntervalForSingingKey() {
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.updateInterval', 0.0005);
        new Session();

        $key1 = AccessTokenSigningKey::getKey();
        sleep(2);
        $key2 = AccessTokenSigningKey::getKey();

        $this->assertNotEquals($key1, $key2);
    }

    /**
     * @throws Exception
     */
    public function testCreateAndGetInfoForAccessTokenWithShortValidity() {
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.validity', 1);
        new Session();

        $sessionHandle = "sessionHandle";
        $userId = "userId";
        $refreshTokenHash1 = "refreshTokenHash1";
        $parentRefreshTokenHash1 = "parentRefreshTokenHash1";
        $userPayload = [
            "a" => "a"
        ];
        $token = AccessToken::createNewAccessToken($sessionHandle, $userId, $refreshTokenHash1, $parentRefreshTokenHash1, $userPayload);
        sleep(2);

        try {
            AccessToken::getInfoFromAccessToken(($token['token']));
            throw new Exception("test failed");
        } catch (SuperTokensAuthException $e) {
            $this->assertEquals($e->getCode(), SuperTokensAuthException::$TryRefreshTokenException);
        }
    }

    /**
     * @throws Exception
     */
    public function testCreateAndGetInfoForAccessTokenWithShortUpdateIntervalSigningKey() {
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.updateInterval', 0.0005);
        new Session();

        $sessionHandle = "sessionHandle";
        $userId = "userId";
        $refreshTokenHash1 = "refreshTokenHash1";
        $parentRefreshTokenHash1 = "parentRefreshTokenHash1";
        $userPayload = [
            "a" => "a"
        ];
        $token = AccessToken::createNewAccessToken($sessionHandle, $userId, $refreshTokenHash1, $parentRefreshTokenHash1, $userPayload);
        sleep(2);

        try {
            AccessToken::getInfoFromAccessToken(($token['token']));
            throw new Exception("test failed");
        } catch (SuperTokensAuthException $e) {
            $this->assertEquals($e->getCode(), SuperTokensAuthException::$TryRefreshTokenException);
        }
    }
}