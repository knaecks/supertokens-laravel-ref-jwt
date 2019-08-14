<?php

namespace SuperTokens\Session\Tests;

use Exception;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensTokenTheftException;
use SuperTokens\Session\Exceptions\SuperTokensTryRefreshTokenException;
use SuperTokens\Session\Exceptions\SuperTokensUnauthorizedException;
use SuperTokens\Session\Helpers\RefreshTokenSigningKey;
use SuperTokens\Session\SessionHandlingFunctions;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use SuperTokens\Session\Helpers\AccessTokenSigningKey;
use SuperTokens\Session\Exceptions\SuperTokensException;
use SuperTokens\Session\Models\RefreshTokenModel;
use SuperTokens\Session\Db\RefreshTokenDb;

class SessionTest extends TestCase {
    use RefreshDatabase;

    /**
     * @throws SuperTokensException | Exception
     */
    public function testNumericUserId() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = 1;
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
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
        $this->assertIsString($newSession['antiCsrfToken']);
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testNumberAsStringUserId() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = "1";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
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
        $this->assertIsString($newSession['antiCsrfToken']);
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testValidJsonSingleFieldUserId() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = json_encode([
            "a" => "testing"
        ]);
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
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
        $this->assertIsString($newSession['antiCsrfToken']);
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testValidJsonMultipleFieldsUserId() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = json_encode([
            "a" => "testing",
            "i" => "supertokens"
        ]);
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
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
        $this->assertIsString($newSession['antiCsrfToken']);
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testInValidJsonUserId() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = json_encode([
            "i" => "supertokens"
        ]);
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        try {
            SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
            throw new Exception("test failed");
        } catch (SuperTokensGeneralException $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testCreateAndGetSessionWithAntiCsrf() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
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
        $this->assertIsString($newSession['antiCsrfToken']);
        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 1);

        $sessionInfo = SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
        $this->assertIsArray($sessionInfo);
        $this->assertArrayNotHasKey("newAccessToken", $sessionInfo);
        $this->assertArrayHasKey("session", $sessionInfo);
        $this->assertArrayHasKey("handle", $sessionInfo['session']);
        $this->assertArrayHasKey("userId", $sessionInfo['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo['session']);
        $this->assertIsString($sessionInfo['session']['handle']);
        $this->assertEquals($sessionInfo['session']['userId'], $userId);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);

        try {
            SessionHandlingFunctions::getSession($newSession['accessToken']['value'], "wrong-anti-csrf-token");
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testCreateAndGetSessionWithAntiCsrfDisabled() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.enableAntiCsrf', false);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("accessToken", $newSession);
        $this->assertArrayHasKey("idRefreshToken", $newSession);
        $this->assertArrayHasKey("refreshToken", $newSession);
        $this->assertArrayHasKey("session", $newSession);
        $this->assertArrayHasKey("antiCsrfToken", $newSession);
        $this->assertNull($newSession["antiCsrfToken"]);
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

        $sessionInfo = SessionHandlingFunctions::getSession($newSession['accessToken']['value']);
        $this->assertIsArray($sessionInfo);
        $this->assertArrayNotHasKey("newAccessToken", $sessionInfo);
        $this->assertArrayHasKey("session", $sessionInfo);
        $this->assertArrayHasKey("handle", $sessionInfo['session']);
        $this->assertArrayHasKey("userId", $sessionInfo['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo['session']);
        $this->assertIsString($sessionInfo['session']['handle']);
        $this->assertEquals($sessionInfo['session']['userId'], $userId);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
        SessionHandlingFunctions::getSession($newSession['accessToken']['value'], "wrong-anti-csrf-token");
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testCreateAndGetSessionWithDifferentPayloadTypes() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $sessionInfo = SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
        $this->assertEquals(SessionHandlingFunctions::getSessionData($sessionInfo['session']['handle']), $sessionData);

        $jwtPayload = 2;
        $sessionData = 123;

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $sessionInfo = SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
        $this->assertEquals(SessionHandlingFunctions::getSessionData($sessionInfo['session']['handle']), $sessionData);

        $jwtPayload = "hello";
        $sessionData = "bye";

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $sessionInfo = SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
        $this->assertEquals(SessionHandlingFunctions::getSessionData($sessionInfo['session']['handle']), $sessionData);

        $jwtPayload = true;
        $sessionData = false;

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $sessionInfo = SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
        $this->assertEquals(SessionHandlingFunctions::getSessionData($sessionInfo['session']['handle']), $sessionData);

        $jwtPayload = [1, 2, 3, "hi"];
        $sessionData = [true, 1, 2, "bye", [1, 3, "hi"]];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $sessionInfo = SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
        $this->assertEquals(SessionHandlingFunctions::getSessionData($sessionInfo['session']['handle']), $sessionData);

        $jwtPayload = null;
        $sessionData = null;

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $sessionInfo = SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
        $this->assertEquals(SessionHandlingFunctions::getSessionData($sessionInfo['session']['handle']), $sessionData);
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testCreateAndGetSessionWhereAccessTokenExpiresAfterOneSec() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.validity', 1);
        new SessionHandlingFunctions();
        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("accessToken", $newSession);
        $this->assertIsArray($newSession['accessToken']);
        $this->assertArrayHasKey("value", $newSession['accessToken']);
        $this->assertArrayHasKey("expires", $newSession['accessToken']);
        $this->assertIsString($newSession['accessToken']['value']);
        $this->assertIsInt($newSession['accessToken']['expires']);

        sleep(2);
        try {
            SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testCreateAndGetSessionWhereAccessTokenSigningKeyGetsUpdatedEveryTwoSec() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.updateInterval', 0.0005);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("accessToken", $newSession);
        $this->assertIsArray($newSession['accessToken']);
        $this->assertArrayHasKey("value", $newSession['accessToken']);
        $this->assertIsString($newSession['accessToken']['value']);

        sleep(2);
        try {
            SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }

        $newRefreshedSession = SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
        $this->assertIsArray($newRefreshedSession);
        $this->assertIsArray($newRefreshedSession['newAccessToken']);
        $this->assertArrayHasKey("value", $newRefreshedSession['newAccessToken']);
        $this->assertIsString($newRefreshedSession['newAccessToken']['value']);
        $this->assertNotEquals($newRefreshedSession['newAccessToken']['value'], $newSession['accessToken']['value']);

        $sessionInfo = SessionHandlingFunctions::getSession($newRefreshedSession['newAccessToken']['value'], $newRefreshedSession['newAntiCsrfToken']);
        $this->assertIsArray($sessionInfo);
        $this->assertArrayHasKey("session", $sessionInfo);
        $this->assertArrayHasKey("userId", $sessionInfo['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo['session']);
        $this->assertEquals($sessionInfo['session']['userId'], $userId);
        $this->assertEquals($sessionInfo['session']['jwtPayload'], $jwtPayload);
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testAlteringOfPayload() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];
        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("accessToken", $newSession);
        $this->assertIsArray($newSession['accessToken']);
        $this->assertArrayHasKey("value", $newSession['accessToken']);
        $this->assertIsString($newSession['accessToken']['value']);

        SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);

        $alteredPayload = base64_encode(json_encode(array_merge($jwtPayload, [ 'b' => "new field" ])));
        $alteredToken = explode(".", $newSession['accessToken']['value'])[0].$alteredPayload.explode(".", $newSession['accessToken']['value'])[2];

        try {
            SessionHandlingFunctions::getSession($alteredToken, $newSession['antiCsrfToken']);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testRefreshSessionWithAntiCsrf()
    {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.validity', 1);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
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
            SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }

        $newRefreshedSession = SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
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

        $sessionInfo = SessionHandlingFunctions::getSession($newRefreshedSession['newAccessToken']['value'], $newRefreshedSession['newAntiCsrfToken']);
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

        $newSessionInfo = SessionHandlingFunctions::getSession($sessionInfo['newAccessToken']['value'], $newRefreshedSession['newAntiCsrfToken']);
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
            SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newRefreshedSession['newAntiCsrfToken']);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }

        $newRefreshedSession2 = SessionHandlingFunctions::refreshSession($newRefreshedSession['newRefreshToken']['value']);
        $this->assertIsArray($newRefreshedSession2);
        $this->assertIsArray($newRefreshedSession2['newAccessToken']);
        $this->assertArrayHasKey("value", $newRefreshedSession2['newAccessToken']);
        $this->assertIsString($newRefreshedSession2['newAccessToken']['value']);
        $this->assertNotEquals($newRefreshedSession2['newAccessToken']['value'], $newSession['accessToken']['value']);
        $this->assertNotEquals($newRefreshedSession2['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);

        $sessionInfo2 = SessionHandlingFunctions::getSession($newRefreshedSession2['newAccessToken']['value'], $newRefreshedSession2['newAntiCsrfToken']);
        $this->assertIsArray($sessionInfo2);
        $this->assertArrayHasKey("session", $sessionInfo2);
        $this->assertArrayHasKey("newAccessToken", $sessionInfo2);
        $this->assertNotEquals($sessionInfo2['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);
    }


    /**
     * @throws SuperTokensException | Exception
     */
    public function testRefreshSessionWithAntiCsrfDisabled()
    {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.validity', 1);
        Config::set('supertokens.tokens.enableAntiCsrf', false);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
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
            SessionHandlingFunctions::getSession($newSession['accessToken']['value']);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }

        $newRefreshedSession = SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
        $this->assertIsArray($newRefreshedSession);
        $this->assertArrayHasKey("newAccessToken", $newRefreshedSession);
        $this->assertArrayHasKey("newIdRefreshToken", $newRefreshedSession);
        $this->assertArrayHasKey("newRefreshToken", $newRefreshedSession);
        $this->assertArrayHasKey("session", $newRefreshedSession);
        $this->assertIsArray($newRefreshedSession['newAccessToken']);
        $this->assertIsArray($newRefreshedSession['newIdRefreshToken']);
        $this->assertIsArray($newRefreshedSession['newRefreshToken']);
        $this->assertIsArray($newRefreshedSession['session']);
        $this->assertArrayHasKey("newAntiCsrfToken", $newRefreshedSession);
        $this->assertNull($newRefreshedSession["newAntiCsrfToken"]);
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

        $sessionInfo = SessionHandlingFunctions::getSession($newRefreshedSession['newAccessToken']['value']);
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

        $newSessionInfo = SessionHandlingFunctions::getSession($sessionInfo['newAccessToken']['value']);
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
            SessionHandlingFunctions::getSession($newSession['accessToken']['value']);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }

        $newRefreshedSession2 = SessionHandlingFunctions::refreshSession($newRefreshedSession['newRefreshToken']['value']);
        $this->assertIsArray($newRefreshedSession2);
        $this->assertIsArray($newRefreshedSession2['newAccessToken']);
        $this->assertArrayHasKey("value", $newRefreshedSession2['newAccessToken']);
        $this->assertIsString($newRefreshedSession2['newAccessToken']['value']);
        $this->assertNotEquals($newRefreshedSession2['newAccessToken']['value'], $newSession['accessToken']['value']);
        $this->assertNotEquals($newRefreshedSession2['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);

        $sessionInfo2 = SessionHandlingFunctions::getSession($newRefreshedSession2['newAccessToken']['value']);
        $this->assertIsArray($sessionInfo2);
        $this->assertArrayHasKey("session", $sessionInfo2);
        $this->assertArrayHasKey("newAccessToken", $sessionInfo2);
        $this->assertNotEquals($sessionInfo2['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testRefreshSessionWithRefreshTokenValidityLessThanThreeSec() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.refreshToken.validity', 0.0008);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        // Part 1
        {
            $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
            $this->assertIsArray($newSession);
            $this->assertArrayHasKey("refreshToken", $newSession);
            $this->assertIsArray($newSession['refreshToken']);
            $this->assertArrayHasKey("value", $newSession['refreshToken']);
            $this->assertIsString($newSession['refreshToken']['value']);

            $newRefreshedSession = SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
            $this->assertIsArray($newRefreshedSession);
            $this->assertArrayHasKey("newAccessToken", $newRefreshedSession);
            $this->assertIsArray($newRefreshedSession['newAccessToken']);
            $this->assertArrayHasKey("value", $newRefreshedSession['newAccessToken']);

            $sessionInfo = SessionHandlingFunctions::getSession($newRefreshedSession['newAccessToken']['value'], $newRefreshedSession['newAntiCsrfToken']);
            $this->assertIsArray($sessionInfo);
            $this->assertArrayHasKey("newAccessToken", $sessionInfo);
            $this->assertArrayHasKey("value", $sessionInfo['newAccessToken']);
            $this->assertIsString($sessionInfo['newAccessToken']['value']);
            $this->assertNotEquals($newRefreshedSession['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);

            sleep(4);
            try {
                SessionHandlingFunctions::refreshSession($newRefreshedSession['newRefreshToken']['value']);
                throw new Exception("test failed");
            } catch (SuperTokensUnauthorizedException $e) {
                $this->assertTrue(true);
            }
        }

        // Part 2
        {
            $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
            $this->assertIsArray($newSession);
            $this->assertArrayHasKey("refreshToken", $newSession);
            $this->assertIsArray($newSession['refreshToken']);
            $this->assertArrayHasKey("value", $newSession['refreshToken']);
            $this->assertIsString($newSession['refreshToken']['value']);

            $newRefreshedSession = SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
            $this->assertIsArray($newRefreshedSession);
            $this->assertArrayHasKey("newAccessToken", $newRefreshedSession);
            $this->assertIsArray($newRefreshedSession['newAccessToken']);
            $this->assertArrayHasKey("value", $newRefreshedSession['newAccessToken']);

            sleep(2);
            $newRefreshedSession2 = SessionHandlingFunctions::refreshSession($newRefreshedSession['newRefreshToken']['value']);
            $this->assertIsArray($newRefreshedSession2);
            $this->assertArrayHasKey("newAccessToken", $newRefreshedSession2);
            $this->assertIsArray($newRefreshedSession2['newAccessToken']);
            $this->assertArrayHasKey("value", $newRefreshedSession2['newAccessToken']);

            sleep(2);
            $newRefreshedSession3 = SessionHandlingFunctions::refreshSession($newRefreshedSession2['newRefreshToken']['value']);
            $this->assertIsArray($newRefreshedSession3);
            $this->assertArrayHasKey("newAccessToken", $newRefreshedSession3);
            $this->assertIsArray($newRefreshedSession3['newAccessToken']);
            $this->assertArrayHasKey("value", $newRefreshedSession3['newAccessToken']);
        }
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testRevokeAllSessionForUserWithoutBlacklisting() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession1 = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $newSession2 = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $newSession3 = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);

        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 3);
        SessionHandlingFunctions::revokeAllSessionsForUser($userId);
        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 0);

        $sessionInfo1 = SessionHandlingFunctions::getSession($newSession1['accessToken']['value'], $newSession1['antiCsrfToken']);
        $this->assertIsArray($sessionInfo1);
        $this->assertArrayNotHasKey("newAccessToken", $sessionInfo1);
        $this->assertArrayHasKey("session", $sessionInfo1);
        $this->assertArrayHasKey("handle", $sessionInfo1['session']);
        $this->assertArrayHasKey("userId", $sessionInfo1['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo1['session']);
        $this->assertIsString($sessionInfo1['session']['handle']);
        $this->assertEquals($sessionInfo1['session']['userId'], $userId);
        $this->assertEquals($sessionInfo1['session']['jwtPayload'], $jwtPayload);

        $sessionInfo2 = SessionHandlingFunctions::getSession($newSession2['accessToken']['value'], $newSession2['antiCsrfToken']);
        $this->assertIsArray($sessionInfo2);
        $this->assertArrayNotHasKey("newAccessToken", $sessionInfo2);
        $this->assertArrayHasKey("session", $sessionInfo2);
        $this->assertArrayHasKey("handle", $sessionInfo2['session']);
        $this->assertArrayHasKey("userId", $sessionInfo2['session']);
        $this->assertArrayHasKey("jwtPayload", $sessionInfo2['session']);
        $this->assertIsString($sessionInfo2['session']['handle']);
        $this->assertEquals($sessionInfo2['session']['userId'], $userId);
        $this->assertEquals($sessionInfo2['session']['jwtPayload'], $jwtPayload);

        $sessionInfo3 = SessionHandlingFunctions::getSession($newSession3['accessToken']['value'], $newSession3['antiCsrfToken']);
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

    /**
     * @throws SuperTokensException | Exception
     */
    public function testRevokeAllSessionForUserWithBlacklisting() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.blacklisting', true);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession1 = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $newSession2 = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $newSession3 = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);

        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 3);
        SessionHandlingFunctions::revokeAllSessionsForUser($userId);
        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 0);

        try {
            SessionHandlingFunctions::getSession($newSession1['accessToken']['value'], $newSession1['antiCsrfToken']);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        try {
            SessionHandlingFunctions::getSession($newSession2['accessToken']['value'], $newSession2['antiCsrfToken']);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        try {
            SessionHandlingFunctions::getSession($newSession3['accessToken']['value'], $newSession3['antiCsrfToken']);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testUpdateSessionInfo() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertIsArray($newSession['session']);
        $this->assertArrayHasKey("handle", $newSession['session']);
        $this->assertIsString($newSession['session']['handle']);

        $sessionDataBeforeUpdate = SessionHandlingFunctions::getSessionData($newSession['session']['handle']);
        $this->assertEquals($sessionDataBeforeUpdate, $sessionData);

        $newSessionData = 2;
        SessionHandlingFunctions::updateSessionData($newSession['session']['handle'], $newSessionData);

        $sessionDataPostUpdate = SessionHandlingFunctions::getSessionData($newSession['session']['handle']);
        $this->assertEquals($sessionDataPostUpdate, $newSessionData);
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testRevokeSessionWithoutBlacklisting() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertIsArray($newSession['session']);
        $this->assertArrayHasKey("handle", $newSession['session']);
        $this->assertIsString($newSession['session']['handle']);

        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 2);

        $this->assertEquals(SessionHandlingFunctions::revokeSessionUsingSessionHandle($newSession['session']['handle']), 1);
        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 1);

        try {
            SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        $sessionInfo = SessionHandlingFunctions::getSession($newSession['accessToken']['value'], $newSession['antiCsrfToken']);
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
     * @throws SuperTokensException  | Exception
     */
    public function testRevokeSessionWithBlacklisting() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.blacklisting', true);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession1 = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $newSession2 = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession1);
        $this->assertIsArray($newSession1['session']);
        $this->assertArrayHasKey("handle", $newSession1['session']);
        $this->assertIsString($newSession1['session']['handle']);

        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 2);

        $this->assertEquals(SessionHandlingFunctions::revokeSessionUsingSessionHandle($newSession1['session']['handle']), 1);
        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 1);

        try {
            SessionHandlingFunctions::refreshSession($newSession1['refreshToken']['value']);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        try {
            SessionHandlingFunctions::getSession($newSession1['accessToken']['value'], $newSession1['antiCsrfToken']);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        $sessionInfo = SessionHandlingFunctions::getSession($newSession2['accessToken']['value'], $newSession2['antiCsrfToken']);
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
     * @throws SuperTokensException | Exception
     */
    public function testTokenTheftS1_R1_S2_R1() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.blacklisting', true);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("refreshToken", $newSession);
        $this->assertIsArray($newSession['refreshToken']);
        $this->assertArrayHasKey("value", $newSession['refreshToken']);
        $this->assertIsString($newSession['refreshToken']['value']);
        $this->assertIsArray($newSession['session']);
        $this->assertArrayHasKey("handle", $newSession['session']);
        $this->assertIsString($newSession['session']['handle']);

        $newRefreshedSession = SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
        $this->assertIsArray($newRefreshedSession);
        $this->assertArrayHasKey("newAccessToken", $newRefreshedSession);
        $this->assertIsArray($newRefreshedSession['newAccessToken']);
        $this->assertArrayHasKey("value", $newRefreshedSession['newAccessToken']);

        $sessionInfo = SessionHandlingFunctions::getSession($newRefreshedSession['newAccessToken']['value'], $newRefreshedSession['newAntiCsrfToken']);
        $this->assertIsArray($sessionInfo);
        $this->assertArrayHasKey("newAccessToken", $sessionInfo);
        $this->assertArrayHasKey("value", $sessionInfo['newAccessToken']);
        $this->assertIsString($sessionInfo['newAccessToken']['value']);
        $this->assertNotEquals($newRefreshedSession['newAccessToken']['value'], $sessionInfo['newAccessToken']['value']);

        try {
            SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
            throw new Exception("test failed");
        } catch (SuperTokensTokenTheftException $e) {
            $this->assertEquals($e->getUserId(), $userId);
            $this->assertEquals($e->getSessionHandle(), $newSession['session']['handle']);
        }
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testTokenTheftS1_R1_R2_R1() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.blacklisting', true);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        $newSession = SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $this->assertIsArray($newSession);
        $this->assertArrayHasKey("refreshToken", $newSession);
        $this->assertIsArray($newSession['refreshToken']);
        $this->assertArrayHasKey("value", $newSession['refreshToken']);
        $this->assertIsString($newSession['refreshToken']['value']);
        $this->assertIsArray($newSession['session']);
        $this->assertArrayHasKey("handle", $newSession['session']);
        $this->assertIsString($newSession['session']['handle']);

        $newRefreshedSession = SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
        $this->assertIsArray($newRefreshedSession);
        $this->assertArrayHasKey("newRefreshToken", $newRefreshedSession);
        $this->assertIsArray($newRefreshedSession['newRefreshToken']);
        $this->assertArrayHasKey("value", $newRefreshedSession['newRefreshToken']);

        $newRefreshedSession2 = SessionHandlingFunctions::refreshSession($newRefreshedSession['newRefreshToken']['value']);
        $this->assertIsArray($newRefreshedSession2);
        $this->assertArrayHasKey("newRefreshToken", $newRefreshedSession2);
        $this->assertIsArray($newRefreshedSession2['newRefreshToken']);
        $this->assertArrayHasKey("value", $newRefreshedSession2['newRefreshToken']);
        $this->assertNotEquals($newRefreshedSession2['newRefreshToken']['value'], $newRefreshedSession['newRefreshToken']['value']);

        try {
            SessionHandlingFunctions::refreshSession($newSession['refreshToken']['value']);
            throw new Exception("test failed");
        } catch (SuperTokensTokenTheftException $e) {
            $this->assertEquals($e->getUserId(), $userId);
            $this->assertEquals($e->getSessionHandle(), $newSession['session']['handle']);
        }
    }

    /**
     * @throws SuperTokensException | Exception
     */
    public function testRemoveExpiredSessions() {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.refreshToken.validity', 0.0008);
        new SessionHandlingFunctions();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionData = [
            "s" => "session"
        ];

        SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 3);
        sleep(4);
        SessionHandlingFunctions::createNewSession($userId, $jwtPayload, $sessionData);
        RefreshTokenDb::removeOldSessions();
        $noOfRows = RefreshTokenModel::all()->count();
        $this->assertEquals($noOfRows, 1);
    }
}