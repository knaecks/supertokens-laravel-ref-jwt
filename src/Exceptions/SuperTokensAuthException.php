<?php

namespace SuperTokens\Laravel\Exceptions;
use Exception;

/**
 * Class SuperTokensAuthException
 * @package SuperTokens\Laravel\Exceptions
 */
class SuperTokensAuthException extends Exception {

    public static $generalException = 1000;
    public static $UnauthorizedException = 2000;
    public static $TryRefreshTokenException = 3000;
    /**
     * SuperTokensAuthException constructor.
     * @param string $message
     * @param int $code
     */
    public function __construct($message = "", $code = 0) {
        parent::__construct($message, $code);
    }

}