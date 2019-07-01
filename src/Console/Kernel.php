<?php


namespace SuperTokens\Session\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use SuperTokens\Session\Helpers\Utils;
use SuperTokens\Session\Models\RefreshTokenModel;

class Kernel extends ConsoleKernel
{
    /**
     * The Artisan commands provided by your application.
     *
     * @var array
     */
    protected $commands = [
        //
    ];

    /**
     * Define the application's command schedule.
     *
     * @param Schedule $schedule
     * @return void
     */
    protected function schedule(Schedule $schedule) {
        $schedule->call(function () {
            $currentTimestamp = Utils::getDateTimeStamp();
            RefreshTokenModel::where('expires_at', '<=', $currentTimestamp)->delete();
        })->daily();
    }
}
