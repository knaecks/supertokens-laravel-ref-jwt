<?php

namespace SuperTokens\Laravel\Exceptions;

/**
 * Class UnauthorizedException
 * @package SuperTokens\Laravel\Exceptions
 */
class UnauthorizedException extends SuperTokensAuthException {

    /**
     * UnauthorizedException constructor.
     * @param string $message
     */
    public function __construct($message = "") {
        $code = 2000;
        parent::__construct($message, $code);
    }
}