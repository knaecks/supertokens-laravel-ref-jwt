<?php

namespace SuperTokens\Session\Tests;

use SuperTokens\Session\Providers\SuperTokensServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase {

    /**
     * @param \Illuminate\Foundation\Application $app
     * @return array
     */
    protected function getPackageProviders($app) {
        return [
            SuperTokensServiceProvider::class
        ];
    }

    protected function getPackageAliases($app) {
        return [
            'SuperTokens' => 'SuperTokens\Session\Facades\SuperTokens'
        ];
    }

    protected function getEnvironmentSetUp($app) {
        parent::getEnvironmentSetUp($app); // TODO: Change the autogenerated stub

        $app['config']->set('supertokens',  [
            'tokens' => [
                'accessToken' => [
                    'signingKey' => [
                        'dynamic' => true,
                        'updateInterval' => 24,
                        'get' => null,
                    ],
                    'validity' => 3600,
                    'blacklisting' => false,
                ],
                'enableAntiCsrf' => true,
                'refreshToken' => [
                    'validity' => 2400,
                    'removalCronjobInterval' => '* * 1-31/7 * *',
                    'renewTokenPath' => '/renew',
                ],
            ],
            'cookie' => [
                'domain' => 'localhost',
                'secure' => false
            ]
        ]);
        $app['config']->set('env',  "testing");
    }
}