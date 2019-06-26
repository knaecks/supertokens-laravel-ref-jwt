<?php

namespace  SuperTokens\Session\Facades;

use Illuminate\Support\Facades\Facade;

class SuperTokens extends Facade {
    /**
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return "SuperTokens";
    }
}