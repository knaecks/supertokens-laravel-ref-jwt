<?php

namespace SuperTokens\Session\Providers;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;
use Illuminate\Console\Scheduling\Schedule;
use SuperTokens\Session\Helpers\Utils;
use SuperTokens\Session\Models\RefreshTokenModel;
use SuperTokens\Session\SuperToken;

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
        $this->registerScheduler();
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
            return new SuperToken();
        });
    }

    private function registerScheduler() {
        $this->app->booted(function () {
            $schedule = app(Schedule::class);
            $schedule->call(function () {
                $currentTimestamp = Utils::getDateTimeStamp();
                RefreshTokenModel::where('expires_at', '<=', $currentTimestamp)->delete();
            })->cron(Config::get('supertokens.tokens.refreshToken.removalCronjobInterval'));
        });
    }
}