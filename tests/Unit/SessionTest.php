<?php

namespace SuperTokens\Session\Tests;

use Exception;
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
     * @throws SuperTokensAuthException
     */
    public function testCreateAndGetSession() {
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
        $this->assertArrayHasKey("expires", $newSession['accessToken']);
        $this->assertIsString($newSession['accessToken']['value']);
        $this->assertIsInt($newSession['accessToken']['expires']);
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
}