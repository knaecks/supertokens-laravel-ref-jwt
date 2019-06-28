<?php

namespace SuperTokens\Session\Tests;

use SuperTokens\Session\Helpers\RefreshTokenSigningKey;
use SuperTokens\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Exception;
use SuperTokens\Session\RefreshToken;
use SuperTokens\Session\Exceptions\SuperTokensAuthException;

class RefreshTokenTest extends TestCase {
    use RefreshDatabase;

    /**
     * @throws SuperTokensAuthException | Exception
     */
    public function testCreateAndVerifyRefreshTokenSameSigningKey() {
        RefreshTokenSigningKey::resetInstance();
        new Session();

        $sessionHandle = "sessionHandle";
        $parentRefreshTokenHash1 = "parentRefreshTokenHash1";
        $userId = "superToken";

        $token = RefreshToken::createNewRefreshToken($sessionHandle, $userId, $parentRefreshTokenHash1);
        $infoFromToken = RefreshToken::getInfoFromRefreshToken($token['token']);

        $this->assertEquals($infoFromToken, [
            'sessionHandle' => "sessionHandle",
            'parentRefreshTokenHash1' => "parentRefreshTokenHash1",
            'userId' => "superToken"
        ]);
    }

    /**
     * @throws SuperTokensAuthException | Exception
     */
    public function testCreateAndVerifyRefreshTokenDifferentSigningKey() {
        RefreshTokenSigningKey::resetInstance();
        new Session();

        $sessionHandle = "sessionHandle";
        $parentRefreshTokenHash1 = "parentRefreshTokenHash1";
        $userId = "superToken";

        $token = RefreshToken::createNewRefreshToken($sessionHandle, $userId, $parentRefreshTokenHash1);

        RefreshTokenSigningKey::resetInstance();
        new Session();
        try {
            RefreshToken::getInfoFromRefreshToken($token['token']);
            throw new Exception("test failed");
        } catch (SuperTokensAuthException $e) {
            $this->assertEquals($e->getCode(), SuperTokensAuthException::$UnauthorizedException);
        }
    }
}
