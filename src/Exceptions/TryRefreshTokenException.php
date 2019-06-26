<?php

namespace SuperTokens\Session\Exceptions;
use Exception;

/**
 * Class TryRefreshTokenException
 * @package SuperTokens\Laravel\Exceptions
 */
class TryRefreshTokenException extends SuperTokensAuthException {

    /**
     * TryRefreshTokenException constructor.
     * @param string $message
     */
    public function __construct($message = "") {
        $code = 3000;
        parent::__construct($message, $code);
    }
}