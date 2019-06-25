<?php

namespace SuperTokens\Laravel\Providers;

use Illuminate\Support\ServiceProvider;
use SuperTokens\Laravel\Session;

class SuperTokensServiceProvider extends ServiceProvider {
    /**
     * Register bindings in the container.
     *
     * @return void
     */
    public function register() {
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot() {
        $this->registerResources();
        $this->registerPublishing();
    }

    private function registerResources() {
        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations');
        $this->registerFacades();
    }

    private function registerPublishing() {
        $this->publishes([
            __DIR__.'/../../config/supertokens.php' => config_path('supertokens.php')
        ], 'supertokens-config');
    }

    private function registerFacades() {
        $this->app->singleton("SuperTokens", function ($app) {
            return new Session();
        });
    }
}