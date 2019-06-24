<?php

namespace SuperTokens\Laravel\Providers;

class SuperTokensServiceProvider {
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
        $this->publishes([__DIR__.'/config/supertokens.php' => config_path('supertokens.php')]);

        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
    }
}