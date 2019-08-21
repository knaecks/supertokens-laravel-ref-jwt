<?php

namespace SuperTokens\Session\Tests;

use SuperTokens\Session\Helpers\Utils;

class CryptoTest extends TestCase
{

    /**
     * @throws \Exception
     */
    public function testEncryptDecrypt()
    {
        $plainText = "testing";
        $masterKey = "master";

        $cipherText = Utils::encrypt($plainText, $masterKey);
        $decipheredText = Utils::decrypt($cipherText, $masterKey);

        $this->assertEquals($plainText, $decipheredText);
    }
}
