<?php

namespace SuperTokens\Session\Exceptions;
use Exception;
use Throwable;

/**
 * Class SuperTokensException
 * @package SuperTokens\Laravel\Exceptions
 */
abstract class SuperTokensException extends Exception {

    /**
     * SuperTokensException constructor.
     * @param string $message
     */
    protected function __construct($message = "", Throwable $previous = null) {
        parent::__construct($message, 0, $previous);
    }

    public static function generateGeneralException($anything, Throwable $previous = null) {
        if ($anything instanceof SuperTokensException) {
            return $anything;
        }
        return new SuperTokensGeneralException($anything, $previous);
    }

    public static function generateUnauthorisedException($anything) {
        if ($anything instanceof SuperTokensException) {
            return $anything;
        }
        return new SuperTokensUnauthorizedException($anything);
    }

    public static function generateTryRefreshTokenException($anything) {
        if ($anything instanceof SuperTokensException) {
            return $anything;
        }
        return new SuperTokensTryRefreshTokenException($anything);
    }

    public static function generateTokenTheftException($userId, $sessionHandle) {
        return new SuperTokensTokenTheftException($userId, $sessionHandle);
    }

}