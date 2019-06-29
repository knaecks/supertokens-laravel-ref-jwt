<?php

namespace SuperTokens\Session\Exceptions;
use Exception;

/**
 * Class SuperTokensTryRefreshTokenException
 * @package SuperTokens\Laravel\Exceptions
 */
class SuperTokensTryRefreshTokenException extends SuperTokensException {

    /**
     * SuperTokensTryRefreshTokenException constructor.
     * @param string $message
     */
    public function __construct($message = "") {
        parent::__construct($message);
    }
}