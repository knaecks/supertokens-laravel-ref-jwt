<?php

namespace SuperTokens\Session\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Exception;
use SuperTokens\Session\Helpers\AccessToken;
use SuperTokens\Session\Exceptions\SuperTokensTryRefreshTokenException;
use SuperTokens\Session\Helpers\AccessTokenSigningKey;
use SuperTokens\Session\SessionHandlingFunctions;
use SuperTokens\Session\Exceptions\SuperTokensException;

class AccessTokenTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @throws SuperTokensException
     */
    public function testCreateAndGetInfo()
    {
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $sessionHandle = "sessionHandle";
        $userId = "userId";
        $refreshTokenHash1 = "refreshTokenHash1";
        $parentRefreshTokenHash1 = "parentRefreshTokenHash1";
        $userPayload = [
            "a" => "a"
        ];
        $antiCsrfToken = "";

        $token = AccessToken::createNewAccessToken($sessionHandle, $userId, $refreshTokenHash1, $antiCsrfToken, $parentRefreshTokenHash1, $userPayload);
        $infoFromToken = AccessToken::getInfoFromAccessToken(($token['token']));
        $this->assertEquals($infoFromToken, [
            "sessionHandle" => "sessionHandle",
            "userId" => "userId",
            "refreshTokenHash1" => "refreshTokenHash1",
            "antiCsrfToken" => "",
            "expiryTime" => $token['expiry'],
            "parentRefreshTokenHash1" => "parentRefreshTokenHash1",
            "userPayload" => [
                "a" => "a"
            ]
        ]);
    }

    /**
     * @throws SuperTokensException
     */
    public function testUserDefinedSingingKeyFunction()
    {
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.get', function () {
            return "supertokens_testing";
        });
        new SessionHandlingFunctions();

        $key = AccessTokenSigningKey::getKey();

        $this->assertEquals($key, "supertokens_testing");
    }

    /**
     * @throws SuperTokensException
     */
    public function testVeryShortUpdateIntervalForSingingKey()
    {
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.updateInterval', 0.0005);
        new SessionHandlingFunctions();

        $key1 = AccessTokenSigningKey::getKey();
        sleep(2);
        $key2 = AccessTokenSigningKey::getKey();

        $this->assertNotEquals($key1, $key2);
    }

    /**
     * @throws Exception
     */
    public function testCreateAndGetInfoForAccessTokenWithShortValidity()
    {
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.validity', 1);
        new SessionHandlingFunctions();

        $sessionHandle = "sessionHandle";
        $userId = "userId";
        $refreshTokenHash1 = "refreshTokenHash1";
        $parentRefreshTokenHash1 = "parentRefreshTokenHash1";
        $userPayload = [
            "a" => "a"
        ];
        $antiCsrfToken = "csrf";
        $token = AccessToken::createNewAccessToken($sessionHandle, $userId, $refreshTokenHash1, $antiCsrfToken, $parentRefreshTokenHash1, $userPayload);
        sleep(2);

        try {
            AccessToken::getInfoFromAccessToken(($token['token']));
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        } catch (Exception $e) {
            throw new Exception("test failed");
        }
    }

    /**
     * @throws Exception
     */
    public function testCreateAndGetInfoForAccessTokenWithShortUpdateIntervalSigningKey()
    {
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.updateInterval', 0.0005);
        new SessionHandlingFunctions();

        $sessionHandle = "sessionHandle";
        $userId = "userId";
        $refreshTokenHash1 = "refreshTokenHash1";
        $parentRefreshTokenHash1 = "parentRefreshTokenHash1";
        $userPayload = [
            "a" => "a"
        ];
        $antiCsrfToken = "csrf";
        $token = AccessToken::createNewAccessToken($sessionHandle, $userId, $refreshTokenHash1, $antiCsrfToken, $parentRefreshTokenHash1, $userPayload);
        sleep(2);

        try {
            AccessToken::getInfoFromAccessToken(($token['token']));
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        } catch (Exception $e) {
            throw new Exception("test failed");
        }
    }
}
