<?php

namespace SuperTokens\Session\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Config;
use Exception;
use SuperTokens\Session\Exceptions\SuperTokensTokenTheftException;
use SuperTokens\Session\Exceptions\SuperTokensTryRefreshTokenException;
use SuperTokens\Session\Exceptions\SuperTokensUnauthorizedException;
use SuperTokens\Session\Helpers\AccessTokenSigningKey;
use SuperTokens\Session\Helpers\RefreshTokenSigningKey;
use SuperTokens\Session\SessionHandlingFunctions;
use SuperTokens\Session\SuperToken;
use SuperTokens\Session\Exceptions\SuperTokensException;

class SuperTokensTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @throws SuperTokensException
     * @throws Exception
     */
    public function testCreateGetAndRefreshSessionWithTokenTheftAndAntiCsrfAndCookiePath()
    {
        $accessTokenPath = "/testing";
        $refreshTokenPath = "/renew";
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.updateInterval', 0.0005);
        Config::set('supertokens.tokens.accessToken.accessTokenPath', "/testing");
        new SuperToken();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionInfo = [
            "s" => "session"
        ];

        $sAccessTokenCookie = null;
        $sRefreshTokenCookie = null;
        $sIdRefreshTokenCookie = null;

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $response = new Response();

        SuperToken::createNewSession($response, $userId, $jwtPayload, $sessionInfo);

        $cookies = $response->headers->getCookies();
        $antiCsrfToken = $response->headers->get('anti-csrf');
        $this->assertIsString($antiCsrfToken);
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();
            $cookiePath = $cookie->getPath();

            if ($cookieName === "sAccessToken") {
                $this->assertEquals($cookiePath, $accessTokenPath);
                $sAccessTokenCookie = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $this->assertEquals($cookiePath, $refreshTokenPath);
                $sRefreshTokenCookie = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $this->assertEquals($cookiePath, $accessTokenPath);
                $sIdRefreshTokenCookie = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken);
        $response = new Response();
        $session = SuperToken::getSession($request, $response, true);
        $this->assertEquals($session->getUserId(), $userId);

        sleep(2);
        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken);
        $response = new Response();
        try {
            SuperToken::getSession($request, $response, true);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie,
            'sRefreshToken' => $sRefreshTokenCookie
        ]);
        $response = new Response();
        SuperToken::refreshSession($request, $response);

        $sOldAccessTokenCookie = null;
        $sOldRefreshTokenCookie = null;
        $sOldIdRefreshTokenCookie = null;

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $cookies = $response->headers->getCookies();
        $antiCsrfToken = $response->headers->get('anti-csrf');
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();
            $cookiePath = $cookie->getPath();

            if ($cookieName === "sAccessToken") {
                $this->assertNotEquals($sAccessTokenCookie, $cookieValue);
                $this->assertEquals($cookiePath, $accessTokenPath);
                $sOldAccessTokenCookie = $sAccessTokenCookie;
                $sAccessTokenCookie = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $this->assertNotEquals($sRefreshTokenCookie, $cookieValue);
                $this->assertEquals($cookiePath, $refreshTokenPath);
                $sOldRefreshTokenCookie = $sRefreshTokenCookie;
                $sRefreshTokenCookie = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $this->assertNotEquals($sIdRefreshTokenCookie, $cookieValue);
                $this->assertEquals($cookiePath, $accessTokenPath);
                $sOldIdRefreshTokenCookie = $sIdRefreshTokenCookie;
                $sIdRefreshTokenCookie = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken);
        $response = new Response();
        SuperToken::getSession($request, $response, true);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $response = new Response();
        try {
            SuperToken::getSession($request, $response, true);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }

        $request = new Request([], [], [], [
            'sAccessToken' => $sOldAccessTokenCookie,
            'sIdRefreshToken' => $sOldIdRefreshTokenCookie,
            'sRefreshToken' => $sOldRefreshTokenCookie
        ]);
        $response = new Response();
        try {
            SuperToken::refreshSession($request, $response);
            throw new Exception("test failed");
        } catch (SuperTokensTokenTheftException $e) {
            $this->assertTrue(true);
        }

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $cookies = $response->headers->getCookies();
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();
            $cookieExpire = $cookie->getExpiresTime();
            $cookiePath = $cookie->getPath();

            if ($cookieName === "sAccessToken") {
                $this->assertEquals($cookiePath, $accessTokenPath);
                $this->assertEquals("", $cookieValue);
                $this->assertEquals(0, $cookieExpire);
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $this->assertEquals($cookiePath, $refreshTokenPath);
                $this->assertEquals("", $cookieValue);
                $this->assertEquals(0, $cookieExpire);
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $this->assertEquals($cookiePath, $accessTokenPath);
                $this->assertEquals("", $cookieValue);
                $this->assertEquals(0, $cookieExpire);
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);
    }

    /**
     * @throws SuperTokensException
     * @throws Exception
     */
    public function testCreateGetAndRefreshSessionWithAntiCsrfDisabled()
    {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.signingKey.updateInterval', 0.0005);
        Config::set('supertokens.tokens.enableAntiCsrf', false);
        new SuperToken();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionInfo = [
            "s" => "session"
        ];

        $sAccessTokenCookie = null;
        $sRefreshTokenCookie = null;
        $sIdRefreshTokenCookie = null;

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $response = new Response();

        SuperToken::createNewSession($response, $userId, $jwtPayload, $sessionInfo);

        $cookies = $response->headers->getCookies();
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();

            if ($cookieName === "sAccessToken") {
                $sAccessTokenCookie = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $sRefreshTokenCookie = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $sIdRefreshTokenCookie = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $response = new Response();
        $session = SuperToken::getSession($request, $response, true);
        $this->assertEquals($session->getUserId(), $userId);

        sleep(2);
        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $response = new Response();
        try {
            SuperToken::getSession($request, $response, true);
            throw new Exception("test failed");
        } catch (SuperTokensTryRefreshTokenException $e) {
            $this->assertTrue(true);
        }

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie,
            'sRefreshToken' => $sRefreshTokenCookie
        ]);
        $response = new Response();
        SuperToken::refreshSession($request, $response);

        $sOldAccessTokenCookie = null;
        $sOldRefreshTokenCookie = null;
        $sOldIdRefreshTokenCookie = null;

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $cookies = $response->headers->getCookies();
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();

            if ($cookieName === "sAccessToken") {
                $this->assertNotEquals($sAccessTokenCookie, $cookieValue);
                $sOldAccessTokenCookie = $sAccessTokenCookie;
                $sAccessTokenCookie = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $this->assertNotEquals($sRefreshTokenCookie, $cookieValue);
                $sOldRefreshTokenCookie = $sRefreshTokenCookie;
                $sRefreshTokenCookie = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $this->assertNotEquals($sIdRefreshTokenCookie, $cookieValue);
                $sOldIdRefreshTokenCookie = $sIdRefreshTokenCookie;
                $sIdRefreshTokenCookie = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $response = new Response();
        SuperToken::getSession($request, $response, true);

        $request = new Request([], [], [], [
            'sAccessToken' => $sOldAccessTokenCookie,
            'sIdRefreshToken' => $sOldIdRefreshTokenCookie,
            'sRefreshToken' => $sOldRefreshTokenCookie
        ]);
        $response = new Response();
        try {
            SuperToken::refreshSession($request, $response);
            throw new Exception("test failed");
        } catch (SuperTokensTokenTheftException $e) {
            $this->assertTrue(true);
        }

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $cookies = $response->headers->getCookies();
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();
            $cookieExpire = $cookie->getExpiresTime();

            if ($cookieName === "sAccessToken") {
                $this->assertEquals("", $cookieValue);
                $this->assertEquals(0, $cookieExpire);
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $this->assertEquals("", $cookieValue);
                $this->assertEquals(0, $cookieExpire);
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $this->assertEquals("", $cookieValue);
                $this->assertEquals(0, $cookieExpire);
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);
    }

    /**
     * @throws SuperTokensException
     * @throws Exception
     */
    public function testRevokeSessionWithoutBlacklisting()
    {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SuperToken();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionInfo = [
            "s" => "session"
        ];

        $sAccessTokenCookie = null;
        $sRefreshTokenCookie = null;
        $sIdRefreshTokenCookie = null;

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $response = new Response();

        SuperToken::createNewSession($response, $userId, $jwtPayload, $sessionInfo);

        $cookies = $response->headers->getCookies();
        $antiCsrfToken = $response->headers->get('anti-csrf');
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();

            if ($cookieName === "sAccessToken") {
                $sAccessTokenCookie = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $sRefreshTokenCookie = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $sIdRefreshTokenCookie = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken);
        $response = new Response();
        $session = SuperToken::getSession($request, $response, true);
        $this->assertEquals($session->getUserId(), $userId);

        $session->revokeSession();

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie,
                'sIdRefreshToken' => $sIdRefreshTokenCookie,
                'sRefreshToken' => $sRefreshTokenCookie
            ]);
            $response = new Response();
            SuperToken::refreshSession($request, $response);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken);
        $response = new Response();
        SuperToken::getSession($request, $response, true);
        $this->assertEquals($session->getUserId(), $userId);
    }

    /**
     * @throws SuperTokensException
     * @throws Exception
     */
    public function testRevokeSessionWithBlacklisting()
    {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.blacklisting', true);
        new SuperToken();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionInfo = [
            "s" => "session"
        ];

        $sAccessTokenCookie = null;
        $sRefreshTokenCookie = null;
        $sIdRefreshTokenCookie = null;

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $response = new Response();

        SuperToken::createNewSession($response, $userId, $jwtPayload, $sessionInfo);

        $cookies = $response->headers->getCookies();
        $antiCsrfToken = $response->headers->get('anti-csrf');
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();

            if ($cookieName === "sAccessToken") {
                $sAccessTokenCookie = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $sRefreshTokenCookie = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $sIdRefreshTokenCookie = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken);
        $response = new Response();
        $session = SuperToken::getSession($request, $response, true);
        $this->assertEquals($session->getUserId(), $userId);

        $session->revokeSession();

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie,
                'sIdRefreshToken' => $sIdRefreshTokenCookie,
                'sRefreshToken' => $sRefreshTokenCookie
            ]);
            $response = new Response();
            SuperToken::refreshSession($request, $response);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie,
                'sIdRefreshToken' => $sIdRefreshTokenCookie
            ]);
            $request->headers->set('anti-csrf', $antiCsrfToken);
            $response = new Response();
            SuperToken::getSession($request, $response, true);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }
    }

    /**
     * @throws SuperTokensException
     * @throws Exception
     */
    public function testRefreshTokenExpired()
    {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SuperToken();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionInfo = [
            "s" => "session"
        ];

        $sAccessTokenCookie = null;
        $sRefreshTokenCookie = null;
        $sIdRefreshTokenCookie = null;

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $response = new Response();

        SuperToken::createNewSession($response, $userId, $jwtPayload, $sessionInfo);

        $cookies = $response->headers->getCookies();
        $antiCsrfToken = $response->headers->get('anti-csrf');
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();

            if ($cookieName === "sAccessToken") {
                $sAccessTokenCookie = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $sRefreshTokenCookie = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $sIdRefreshTokenCookie = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie,
            'sIdRefreshToken' => $sIdRefreshTokenCookie
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken);
        $response = new Response();
        $session = SuperToken::getSession($request, $response, true);
        $this->assertEquals($session->getUserId(), $userId);

        RefreshTokenSigningKey::resetInstance();
        new SessionHandlingFunctions();

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie,
                'sIdRefreshToken' => $sIdRefreshTokenCookie,
                'sRefreshToken' => $sRefreshTokenCookie
            ]);
            $response = new Response();
            SuperToken::refreshSession($request, $response);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $cookies = $response->headers->getCookies();
        $this->assertEquals(count($cookies), 3);

        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();
            $cookieExpire = $cookie->getExpiresTime();

            if ($cookieName === "sAccessToken") {
                $this->assertEquals("", $cookieValue);
                $this->assertEquals(0, $cookieExpire);
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $this->assertEquals("", $cookieValue);
                $this->assertEquals(0, $cookieExpire);
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $this->assertEquals("", $cookieValue);
                $this->assertEquals(0, $cookieExpire);
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);
    }

    /**
     * @throws SuperTokensException
     * @throws Exception
     */
    public function testRevokeAllSessionsWithoutBlacklisting()
    {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        new SuperToken();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionInfo = [
            "s" => "session"
        ];

        $sAccessTokenCookie1 = null;
        $sRefreshTokenCookie1 = null;
        $sIdRefreshTokenCookie1 = null;

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $response = new Response();
        SuperToken::createNewSession($response, $userId, $jwtPayload, $sessionInfo);
        $cookies = $response->headers->getCookies();
        $antiCsrfToken1 = $response->headers->get('anti-csrf');
        $this->assertEquals(count($cookies), 3);
        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();

            if ($cookieName === "sAccessToken") {
                $sAccessTokenCookie1 = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $sRefreshTokenCookie1 = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $sIdRefreshTokenCookie1 = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $sAccessTokenCookie2 = null;
        $sRefreshTokenCookie2 = null;
        $sIdRefreshTokenCookie2 = null;

        $response = new Response();
        SuperToken::createNewSession($response, $userId, $jwtPayload, $sessionInfo);
        $cookies = $response->headers->getCookies();
        $antiCsrfToken2 = $response->headers->get('anti-csrf');
        $this->assertEquals(count($cookies), 3);
        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();

            if ($cookieName === "sAccessToken") {
                $sAccessTokenCookie2 = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $sRefreshTokenCookie2 = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $sIdRefreshTokenCookie2 = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie1,
            'sIdRefreshToken' => $sIdRefreshTokenCookie1
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken1);
        $response = new Response();
        $session1 = SuperToken::getSession($request, $response, true);
        $this->assertEquals($session1->getUserId(), $userId);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie2,
            'sIdRefreshToken' => $sIdRefreshTokenCookie2
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken2);
        $response = new Response();
        $session2 = SuperToken::getSession($request, $response, true);
        $this->assertEquals($session2->getUserId(), $userId);

        SuperToken::revokeAllSessionsForUser($userId);

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie1,
                'sIdRefreshToken' => $sIdRefreshTokenCookie1,
                'sRefreshToken' => $sRefreshTokenCookie1
            ]);
            $response = new Response();
            SuperToken::refreshSession($request, $response);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie1,
            'sIdRefreshToken' => $sIdRefreshTokenCookie1
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken1);
        $response = new Response();
        SuperToken::getSession($request, $response, true);
        $this->assertEquals($session1->getUserId(), $userId);

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie2,
                'sIdRefreshToken' => $sIdRefreshTokenCookie2,
                'sRefreshToken' => $sRefreshTokenCookie2
            ]);
            $response = new Response();
            SuperToken::refreshSession($request, $response);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie2,
            'sIdRefreshToken' => $sIdRefreshTokenCookie2
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken2);
        $response = new Response();
        SuperToken::getSession($request, $response, true);
        $this->assertEquals($session2->getUserId(), $userId);
    }

    /**
     * @throws SuperTokensException
     * @throws Exception
     */
    public function testRevokeAllSessionsWithBlacklisting()
    {
        RefreshTokenSigningKey::resetInstance();
        AccessTokenSigningKey::resetInstance();
        Config::set('supertokens.tokens.accessToken.blacklisting', true);
        new SuperToken();

        $userId = "testing";
        $jwtPayload = [
            "a" => "testing"
        ];
        $sessionInfo = [
            "s" => "session"
        ];

        $sAccessTokenCookie1 = null;
        $sRefreshTokenCookie1 = null;
        $sIdRefreshTokenCookie1 = null;

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $response = new Response();
        SuperToken::createNewSession($response, $userId, $jwtPayload, $sessionInfo);
        $cookies = $response->headers->getCookies();
        $antiCsrfToken1 = $response->headers->get('anti-csrf');
        $this->assertEquals(count($cookies), 3);
        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();

            if ($cookieName === "sAccessToken") {
                $sAccessTokenCookie1 = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $sRefreshTokenCookie1 = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $sIdRefreshTokenCookie1 = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $sAccessTokenCookieFound = false;
        $sRefreshTokenCookieFound = false;
        $sIdRefreshTokenCookieFound = false;

        $sAccessTokenCookie2 = null;
        $sRefreshTokenCookie2 = null;
        $sIdRefreshTokenCookie2 = null;

        $response = new Response();
        SuperToken::createNewSession($response, $userId, $jwtPayload, $sessionInfo);
        $cookies = $response->headers->getCookies();
        $antiCsrfToken2 = $response->headers->get('anti-csrf');
        $this->assertEquals(count($cookies), 3);
        for ($i = 0; $i < count($cookies); $i++) {
            $cookie = $cookies[$i];
            $cookieName = $cookie->getName();
            $cookieValue = $cookie->getValue();

            if ($cookieName === "sAccessToken") {
                $sAccessTokenCookie2 = $cookieValue;
                $sAccessTokenCookieFound = true;
            } elseif ($cookieName === "sRefreshToken") {
                $sRefreshTokenCookie2 = $cookieValue;
                $sRefreshTokenCookieFound = true;
            } elseif ($cookieName === "sIdRefreshToken") {
                $sIdRefreshTokenCookie2 = $cookieValue;
                $sIdRefreshTokenCookieFound = true;
            }
        }

        $this->assertTrue($sAccessTokenCookieFound);
        $this->assertTrue($sRefreshTokenCookieFound);
        $this->assertTrue($sIdRefreshTokenCookieFound);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie1,
            'sIdRefreshToken' => $sIdRefreshTokenCookie1
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken1);
        $response = new Response();
        $session1 = SuperToken::getSession($request, $response, true);
        $this->assertEquals($session1->getUserId(), $userId);

        $request = new Request([], [], [], [
            'sAccessToken' => $sAccessTokenCookie2,
            'sIdRefreshToken' => $sIdRefreshTokenCookie2
        ]);
        $request->headers->set('anti-csrf', $antiCsrfToken2);
        $response = new Response();
        $session2 = SuperToken::getSession($request, $response, true);
        $this->assertEquals($session2->getUserId(), $userId);

        SuperToken::revokeAllSessionsForUser($userId);

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie1,
                'sIdRefreshToken' => $sIdRefreshTokenCookie1,
                'sRefreshToken' => $sRefreshTokenCookie1
            ]);
            $request->headers->set('anti-csrf', $antiCsrfToken1);
            $response = new Response();
            SuperToken::refreshSession($request, $response);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie2,
                'sIdRefreshToken' => $sIdRefreshTokenCookie2,
                'sRefreshToken' => $sRefreshTokenCookie2
            ]);
            $request->headers->set('anti-csrf', $antiCsrfToken2);
            $response = new Response();
            SuperToken::refreshSession($request, $response);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie1,
                'sIdRefreshToken' => $sIdRefreshTokenCookie1
            ]);
            $request->headers->set('anti-csrf', $antiCsrfToken1);
            $response = new Response();
            SuperToken::getSession($request, $response, true);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }

        try {
            $request = new Request([], [], [], [
                'sAccessToken' => $sAccessTokenCookie2,
                'sIdRefreshToken' => $sIdRefreshTokenCookie2
            ]);
            $request->headers->set('anti-csrf', $antiCsrfToken2);
            $response = new Response();
            SuperToken::getSession($request, $response, true);
            throw new Exception("test failed");
        } catch (SuperTokensUnauthorizedException $e) {
            $this->assertTrue(true);
        }
    }
}
