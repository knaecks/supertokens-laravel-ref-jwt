<?php

namespace SuperTokens\Session\Exceptions;

/**
 * Class SuperTokensUnauthorizedException
 * @package SuperTokens\Laravel\Exceptions
 */
class SuperTokensUnauthorizedException extends SuperTokensException {

    /**
     * SuperTokensUnauthorizedException constructor.
     * @param string $message
     */
    public function __construct($message = "") {
        parent::__construct($message);
    }
}