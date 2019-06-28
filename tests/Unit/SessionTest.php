<?php

namespace SuperTokens\Session\Tests;

use Exception;
use SuperTokens\Session\Session;
use SuperTokens\Session\AccessToken;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use SuperTokens\Session\Helpers\AccessTokenSigningKey;
use SuperTokens\Session\Exceptions\SuperTokensAuthException;

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
    }
}