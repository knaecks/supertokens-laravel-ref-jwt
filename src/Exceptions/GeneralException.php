<?php

namespace SuperTokens\Laravel\Exceptions;
use Exception;

class GeneralException extends SuperTokensAuthException {

    public function __construct($message = "") {
        $code = 1000;
        parent::__construct($message, $code);
    }
}