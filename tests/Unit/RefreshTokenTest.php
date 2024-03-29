<?php

namespace SuperTokens\Session\Tests;

use SuperTokens\Session\Exceptions\SuperTokensUnauthorizedException;
use SuperTokens\Session\Helpers\RefreshTokenSigningKey;
use SuperTokens\Session\SessionHandlingFunctions;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Exception;
use SuperTokens\Session\Helpers\RefreshToken;
use SuperTokens\Session\Exceptions\SuperTokensException;

class RefreshTokenTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @throws SuperTokensException | Exception
     */
    public function testCreateAndVerifyRefreshTokenSameSigningKey()
    {
        RefreshTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

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
     * @throws SuperTokensException | Exception
     */
    public function testCreateAndVerifyRefreshTokenDifferentSigningKey()
    {
        RefreshTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        $sessionHandle = "sessionHandle";
        $parentRefreshTokenHash1 = "parentRefreshTokenHash1";
        $userId = "superToken";

        $token = RefreshToken::createNewRefreshToken($sessionHandle, $userId, $parentRefreshTokenHash1);

        RefreshTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();
        try {
            RefreshToken::getInfoFromRefreshToken($token['token']);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        } catch (Exception $e) {
            throw new Exception("test failed");
        }
    }
}
