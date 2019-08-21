<?php

namespace SuperTokens\Session\Tests;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use SuperTokens\Session\Helpers\CookieAndHeader;

class CookieTest extends TestCase
{
    public function testSetCookie()
    {
        $response = new Response();

        $key = 'test';
        $value = 'value';
        $domain = 'localhost';
        $secure = false;
        $httpOnly = false;
        $path = '/';
        $minutes = 10;

        CookieAndHeader::setCookie($response, $key, $value, $minutes, $path, $domain, $secure, $httpOnly);

        $this->assertIsObject($response->headers);
        $this->assertIsArray($response->headers->getCookies());
        $this->assertIsObject($response->headers->getCookies()[0]);
        $cookie = $response->headers->getCookies()[0];
        $this->assertEquals($cookie->getName(), $key);
        $this->assertEquals($cookie->getValue(), $value);
        $this->assertEquals($cookie->getDomain(), $domain);
        $this->assertEquals($cookie->getPath(), $path);
        $this->assertEquals($cookie->isSecure(), $secure);
        $this->assertEquals($cookie->isHttpOnly(), $httpOnly);
    }

    public function testGetCookie()
    {
        $key = 'test';
        $value = 'value';

        $request = new Request([], [], [], [$key => $value]);

        $cookieValue = CookieAndHeader::getCookie($request, $key);
        $this->assertEquals($cookieValue, $value);
    }
}
