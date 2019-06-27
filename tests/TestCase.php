<?php

namespace SuperTokens\Session\Tests;

use SuperTokens\Session\Providers\SuperTokensServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase {

    /**
     * @param \Illuminate\Foundation\Application $app
     * @return array
     */
    public function getPackageProviders($app) {
        return [
            SuperTokensServiceProvider::class
        ];
    }
}