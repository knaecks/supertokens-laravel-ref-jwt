<?php

namespace SuperTokens\Session\Tests;

use Exception;
use SuperTokens\Session\Helpers\RefreshTokenSigningKey;
use SuperTokens\Session\Session;
use SuperTokens\Session\AccessToken;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use SuperTokens\Session\Helpers\AccessTokenSigningKey;
use SuperTokens\Session\Exceptions\SuperTokensAuthException;
use SuperTokens\Session\Models\RefreshTokenModel;

class SessionTest extends TestCase {
    use RefreshDatabase;

    /**
     * @throws SuperTokensAuthException | Exception
     */
    public function testCreateAndGetSession() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new Session();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = Session::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("accessToken", $newSession);
        $this->assertArrayHasKey("idRefreshToken", $newSession);
        $this->assertArrayHasKey("refreshToken", $newSession);
        $this->assertArrayHasKey("session", $newSession);
        $this->assertIsArray($newSession['accessToken']);
        $this->assertIsArray($newSession['idRefreshToken']);
        $this->assertIsArray($newSession['refreshToken']);
        $this->assertIsArray($newSession['session']);
        $this->assertArrayHasKey("value", $newSession['accessToken']);
        $this->assertArrayHasKey("expires", $newSession['accessToken']);
        $this->assertIsString($newSession['accessToken']['value']);
        $this->assertIsInt($newSession['accessToken']['expires']);
        $this->assertArrayHasKey("value", $newSession['idRefreshToken']);
        $this->assertArrayHasKey("expires", $newSession['idRefreshToken']);
        $this->assertIsString($newSession['idRefreshToken']['value']);
        $this->assertIsInt($newSession['idRefreshToken']['expires']);
        $this->assertArrayHasKey("value", $newSession['refreshToken']);
        $this->assertArrayHasKey("expires", $newSession['refreshToken']);
        $this->assertIsString($newSession['refreshToken']['value']);
        $this->assertIsInt($newSession['refreshToken']['expires']);
        $this->assertArrayHasKey("handle", $newSession['session']);
        $this->assertArrayHasKey("userId", $newSession['session']);
        $this->assertArrayHasKey("jwtPayload", $newSession['session']);
        $this->assertIsString($newSession['session']['handle']);
        $this->assertEquals($newSession['session']['userId'], $userId);
        $this->assertEquals($newSession['session']['jwtPayload'], $jwtPayload);
        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 1);

        $sessionInfo = Session::getSession($newSession['accessToken']['value']);
        $this->assertIsArray($sessionInfo);
        $this->assertArrayNotHasKey("newAccessToken", $sessionInfo);
        $this->assertArrayHasKey("session", $sessionInfo);
        $this->assertArrayHasKey("handle", $sessionInfo['session']);
        $this->assertArrayHasKey("userId", $sessionInfo['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo['session']);
        $this->assertIsString($sessionInfo['session']['handle']);
        $this->assertEquals($sessionInfo['session']['userId'], $userId);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
    }

    /**
     * @throws SuperTokensAuthException | Exception
     */
    public function testCreateAndGetSessionWhereAccessTokenExpiresAfterOneSec() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.validity', 1);
        new Session();
        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = Session::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("accessToken", $newSession);
        $this->assertIsArray($newSession['accessToken']);
        $this->assertArrayHasKey("value", $newSession['accessToken']);
        $this->assertArrayHasKey("expires", $newSession['accessToken']);
        $this->assertIsString($newSession['accessToken']['value']);
        $this->assertIsInt($newSession['accessToken']['expires']);

        sleep(2);
        try {
            Session::getSession($newSession['accessToken']['value']);
        } catch (SuperTokensAuthException $e) {
            $this->assertEquals($e->getCode(), SuperTokensAuthException::$TryRefreshTokenException);
        }
    }

    /**
     * @throws SuperTokensAuthException | Exception
     */
    public function testCreateAndGetSessionWhereAccessTokenSigningKeyGetsUpdatedEveryTwoSec() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.updateInterval', 0.0005);
        new Session();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = Session::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("accessToken", $newSession);
        $this->assertIsArray($newSession['accessToken']);
        $this->assertArrayHasKey("value", $newSession['accessToken']);
        $this->assertIsString($newSession['accessToken']['value']);

        sleep(2);
        try {
            Session::getSession($newSession['accessToken']['value']);
        } catch (SuperTokensAuthException $e) {
            $this->assertEquals($e->getCode(), SuperTokensAuthException::$TryRefreshTokenException);
        }

        $newRefreshedSession = Session::refreshSession($newSession['refreshToken']['value']);
        $this->assertIsArray($newRefreshedSession);
        $this->assertIsArray($newRefreshedSession['newAccessToken']);
        $this->assertArrayHasKey("value", $newRefreshedSession['newAccessToken']);
        $this->assertIsString($newRefreshedSession['newAccessToken']['value']);
        $this->assertNotEquals($newRefreshedSession['newAccessToken']['value'], $newSession['accessToken']['value']);

        $sessionInfo = Session::getSession($newRefreshedSession['newAccessToken']['value']);
        $this->assertIsArray($sessionInfo);
        $this->assertArrayHasKey("session", $sessionInfo);
        $this->assertArrayHasKey("userId", $sessionInfo['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo['session']);
        $this->assertEquals($sessionInfo['session']['userId'], $userId);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
    }

    /**
     * @throws SuperTokensAuthException | Exception
     */
    public function testAlteringOfPayload() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new Session();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];
        $newSession = Session::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("accessToken", $newSession);
        $this->assertIsArray($newSession['accessToken']);
        $this->assertArrayHasKey("value", $newSession['accessToken']);
        $this->assertIsString($newSession['accessToken']['value']);

        Session::getSession($newSession['accessToken']['value']);

        $alteredPayload = base64_encode(json_encode(array_merge($jwtPayload, [ 'b' => "new field" ])));
        $alteredToken = explode(".", $newSession['accessToken']['value'])[0].$alteredPayload.explode(".", $newSession['accessToken']['value'])[2];

        try {
            Session::getSession($alteredToken);
        } catch (SuperTokensAuthException $e) {
            $this->assertEquals($e->getCode(), SuperTokensAuthException::$TryRefreshTokenException);
        }
    }

    /**
     * @throws SuperTokensAuthException | Exception
     */
    public function testRefreshSession()
    {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.validity', 1);
        new Session();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = Session::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("accessToken", $newSession);
        $this->assertArrayHasKey("idRefreshToken", $newSession);
        $this->assertArrayHasKey("refreshToken", $newSession);
        $this->assertArrayHasKey("session", $newSession);
        $this->assertIsArray($newSession['accessToken']);
        $this->assertIsArray($newSession['idRefreshToken']);
        $this->assertIsArray($newSession['refreshToken']);
        $this->assertIsArray($newSession['session']);
        $this->assertArrayHasKey("value", $newSession['accessToken']);
        $this->assertArrayHasKey("value", $newSession['idRefreshToken']);
        $this->assertArrayHasKey("value", $newSession['refreshToken']);
        $this->assertIsString($newSession['accessToken']['value']);
        $this->assertIsString($newSession['idRefreshToken']['value']);
        $this->assertIsString($newSession['refreshToken']['value']);

        sleep(2);
        try {
            Session::getSession($newSession['accessToken']['value']);
        } catch (SuperTokensAuthException $e) {
            $this->assertEquals($e->getCode(), SuperTokensAuthException::$TryRefreshTokenException);
        }

        $newRefreshedSession = Session::refreshSession($newSession['refreshToken']['value']);
        $this->assertIsArray($newRefreshedSession);
        $this->assertArrayHasKey("newAccessToken", $newRefreshedSession);
        $this->assertArrayHasKey("newIdRefreshToken", $newRefreshedSession);
        $this->assertArrayHasKey("newRefreshToken", $newRefreshedSession);
        $this->assertArrayHasKey("session", $newRefreshedSession);
        $this->assertIsArray($newRefreshedSession['newAccessToken']);
        $this->assertIsArray($newRefreshedSession['newIdRefreshToken']);
        $this->assertIsArray($newRefreshedSession['newRefreshToken']);
        $this->assertIsArray($newRefreshedSession['session']);
        $this->assertArrayHasKey("value", $newRefreshedSession['newAccessToken']);
        $this->assertArrayHasKey("expires", $newRefreshedSession['newAccessToken']);
        $this->assertIsString($newRefreshedSession['newAccessToken']['value']);
        $this->assertIsInt($newRefreshedSession['newAccessToken']['expires']);
        $this->assertArrayHasKey("value", $newRefreshedSession['newIdRefreshToken']);
        $this->assertArrayHasKey("expires", $newRefreshedSession['newIdRefreshToken']);
        $this->assertIsString($newRefreshedSession['newIdRefreshToken']['value']);
        $this->assertIsInt($newRefreshedSession['newIdRefreshToken']['expires']);
        $this->assertArrayHasKey("value", $newRefreshedSession['newRefreshToken']);
        $this->assertArrayHasKey("expires", $newRefreshedSession['newRefreshToken']);
        $this->assertIsString($newRefreshedSession['newRefreshToken']['value']);
        $this->assertIsInt($newRefreshedSession['newRefreshToken']['expires']);
        $this->assertNotEquals($newRefreshedSession['newRefreshToken']['value'], $newSession['refreshToken']['value']);
        $this->assertNotEquals($newRefreshedSession['newAccessToken']['value'], $newSession['accessToken']['value']);
        $this->assertNotEquals($newRefreshedSession['newIdRefreshToken']['value'], $newSession['idRefreshToken']['value']);
        $this->assertArrayHasKey("handle", $newRefreshedSession['session']);
        $this->assertArrayHasKey("userId", $newRefreshedSession['session']);
        $this->assertArrayHasKey("jwtPayload", $newRefreshedSession['session']);
        $this->assertIsString($newRefreshedSession['session']['handle']);
        $this->assertEquals($newRefreshedSession['session']['userId'], $userId);
        $this->assertEquals($newRefreshedSession['session']['jwtPayload'], $jwtPayload);

        $sessionInfo = Session::getSession($newRefreshedSession['newAccessToken']['value']);
        $this->assertIsArray($sessionInfo);
        $this->assertArrayHasKey("newAccessToken", $sessionInfo);
        $this->assertArrayHasKey("value", $sessionInfo['newAccessToken']);
        $this->assertArrayHasKey("expires", $sessionInfo['newAccessToken']);
        $this->assertIsString($sessionInfo['newAccessToken']['value']);
        $this->assertIsInt($sessionInfo['newAccessToken']['expires']);
        $this->assertNotEquals($newRefreshedSession['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);
        $this->assertArrayHasKey("session", $sessionInfo);
        $this->assertIsArray($sessionInfo['session']);
        $this->assertIsArray($sessionInfo['newAccessToken']);
        $this->assertArrayHasKey("handle", $sessionInfo['session']);
        $this->assertArrayHasKey("userId", $sessionInfo['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo['session']);
        $this->assertIsString($sessionInfo['session']['handle']);
        $this->assertEquals($sessionInfo['session']['userId'], $userId);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);

        $newSessionInfo = Session::getSession($sessionInfo['newAccessToken']['value']);
        $this->assertIsArray($newSessionInfo);
        $this->assertArrayNotHasKey("newAccessToken", $newSessionInfo);
        $this->assertArrayHasKey("session", $newSessionInfo);
        $this->assertArrayHasKey("handle", $newSessionInfo['session']);
        $this->assertArrayHasKey("userId", $newSessionInfo['session']);
        $this->assertArrayHasKey("jwtPayload", $newSessionInfo['session']);
        $this->assertIsString($newSessionInfo['session']['handle']);
        $this->assertEquals($newSessionInfo['session']['userId'], $userId);
        $this->assertEquals($newSessionInfo['session']['jwtPayload'], $jwtPayload);

        sleep(2);
        try {
            Session::getSession($newSession['accessToken']['value']);
        } catch (SuperTokensAuthException $e) {
            $this->assertEquals($e->getCode(), SuperTokensAuthException::$TryRefreshTokenException);
        }

        $newRefreshedSession2 = Session::refreshSession($newRefreshedSession['newRefreshToken']['value']);
        $this->assertIsArray($newRefreshedSession2);
        $this->assertIsArray($newRefreshedSession2['newAccessToken']);
        $this->assertArrayHasKey("value", $newRefreshedSession2['newAccessToken']);
        $this->assertIsString($newRefreshedSession2['newAccessToken']['value']);
        $this->assertNotEquals($newRefreshedSession2['newAccessToken']['value'], $newSession['accessToken']['value']);
        $this->assertNotEquals($newRefreshedSession2['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);

        $sessionInfo2 = Session::getSession($newRefreshedSession2['newAccessToken']['value']);
        $this->assertIsArray($sessionInfo2);
        $this->assertArrayHasKey("session", $sessionInfo2);
        $this->assertArrayHasKey("newAccessToken", $sessionInfo2);
        $this->assertNotEquals($sessionInfo2['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);
    }

    /**
     * @throws SuperTokensAuthException | Exception
     */
    public function testRefreshSessionWithRefreshTokenValidityLessThanThreeSec() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.refreshToken.validity', 0.0008);
        new Session();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        // Part 1
        {
            $newSession = Session::createNewSession($userId, $jwtPayload, $sessionData);
            $this->assertIsArray($newSession);
            $this->assertArrayHasKey("refreshToken", $newSession);
            $this->assertIsArray($newSession['refreshToken']);
            $this->assertArrayHasKey("value", $newSession['refreshToken']);
            $this->assertIsString($newSession['refreshToken']['value']);

            $newRefreshedSession = Session::refreshSession($newSession['refreshToken']['value']);
            $this->assertIsArray($newRefreshedSession);
            $this->assertArrayHasKey("newAccessToken", $newRefreshedSession);
            $this->assertIsArray($newRefreshedSession['newAccessToken']);
            $this->assertArrayHasKey("value", $newRefreshedSession['newAccessToken']);

            $sessionInfo = Session::getSession($newRefreshedSession['newAccessToken']['value']);
            $this->assertIsArray($sessionInfo);
            $this->assertArrayHasKey("newAccessToken", $sessionInfo);
            $this->assertArrayHasKey("value", $sessionInfo['newAccessToken']);
            $this->assertIsString($sessionInfo['newAccessToken']['value']);
            $this->assertNotEquals($newRefreshedSession['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);

            sleep(3);
            try {
                Session::refreshSession($newRefreshedSession['newRefreshToken']['value']);
            } catch (SuperTokensAuthException $e) {
                $this->assertEquals($e->getCode(), SuperTokensAuthException::$UnauthorizedException);
            }
        }

        // Part 2
        {
            $newSession = Session::createNewSession($userId, $jwtPayload, $sessionData);
            $this->assertIsArray($newSession);
            $this->assertArrayHasKey("refreshToken", $newSession);
            $this->assertIsArray($newSession['refreshToken']);
            $this->assertArrayHasKey("value", $newSession['refreshToken']);
            $this->assertIsString($newSession['refreshToken']['value']);

            $newRefreshedSession = Session::refreshSession($newSession['refreshToken']['value']);
            $this->assertIsArray($newRefreshedSession);
            $this->assertArrayHasKey("newAccessToken", $newRefreshedSession);
            $this->assertIsArray($newRefreshedSession['newAccessToken']);
            $this->assertArrayHasKey("value", $newRefreshedSession['newAccessToken']);

            sleep(2);
            $newRefreshedSession2 = Session::refreshSession($newRefreshedSession['newRefreshToken']['value']);
            $this->assertIsArray($newRefreshedSession2);
            $this->assertArrayHasKey("newAccessToken", $newRefreshedSession2);
            $this->assertIsArray($newRefreshedSession2['newAccessToken']);
            $this->assertArrayHasKey("value", $newRefreshedSession2['newAccessToken']);

            sleep(2);
            $newRefreshedSession3 = Session::refreshSession($newRefreshedSession2['newRefreshToken']['value']);
            $this->assertIsArray($newRefreshedSession3);
            $this->assertArrayHasKey("newAccessToken", $newRefreshedSession3);
            $this->assertIsArray($newRefreshedSession3['newAccessToken']);
            $this->assertArrayHasKey("value", $newRefreshedSession3['newAccessToken']);
        }
    }

    /**
     * @throws SuperTokensAuthException | Exception
     */
    public function testRevokeAllSessionForUserWithoutBlacklisting() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new Session();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession1 = Session::createNewSession($userId, $jwtPayload, $sessionData);
        $newSession2 = Session::createNewSession($userId, $jwtPayload, $sessionData);
        $newSession3 = Session::createNewSession($userId, $jwtPayload, $sessionData);

        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 3);
        Session::revokeAllSessionsForUser($userId);
        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 0);

        $sessionInfo1 = Session::getSession($newSession1['accessToken']['value']);
        $this->assertIsArray($sessionInfo1);
        $this->assertArrayNotHasKey("newAccessToken", $sessionInfo1);
        $this->assertArrayHasKey("session", $sessionInfo1);
        $this->assertArrayHasKey("handle", $sessionInfo1['session']);
        $this->assertArrayHasKey("userId", $sessionInfo1['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo1['session']);
        $this->assertIsString($sessionInfo1['session']['handle']);
        $this->assertEquals($sessionInfo1['session']['userId'], $userId);
        $this->assertEquals($sessionInfo1['session']['jwtPayload'], $jwtPayload);

        $sessionInfo2 = Session::getSession($newSession2['accessToken']['value']);
        $this->assertIsArray($sessionInfo2);
        $this->assertArrayNotHasKey("newAccessToken", $sessionInfo2);
        $this->assertArrayHasKey("session", $sessionInfo2);
        $this->assertArrayHasKey("handle", $sessionInfo2['session']);
        $this->assertArrayHasKey("userId", $sessionInfo2['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo2['session']);
        $this->assertIsString($sessionInfo2['session']['handle']);
        $this->assertEquals($sessionInfo2['session']['userId'], $userId);
        $this->assertEquals($sessionInfo2['session']['jwtPayload'], $jwtPayload);

        $sessionInfo3 = Session::getSession($newSession3['accessToken']['value']);
        $this->assertIsArray($sessionInfo3);
        $this->assertArrayNotHasKey("newAccessToken", $sessionInfo3);
        $this->assertArrayHasKey("session", $sessionInfo3);
        $this->assertArrayHasKey("handle", $sessionInfo3['session']);
        $this->assertArrayHasKey("userId", $sessionInfo3['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo3['session']);
        $this->assertIsString($sessionInfo3['session']['handle']);
        $this->assertEquals($sessionInfo3['session']['userId'], $userId);
        $this->assertEquals($sessionInfo3['session']['jwtPayload'], $jwtPayload);
    }
}