<?php

namespace SuperTokens\Session\Exceptions;
use Throwable;

class SuperTokensGeneralException extends SuperTokensException {

    public function __construct($message = "", Throwable $previous = null) {
        parent::__construct($message, $previous);
    }
}