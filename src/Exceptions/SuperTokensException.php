<?php

namespace SuperTokens\Session\Exceptions;
use Exception;
use Throwable;

/**
 * Class SuperTokensException
 * @package SuperTokens\Laravel\Exceptions
 */
class SuperTokensException extends Exception {

    /**
     * SuperTokensException constructor.
     * @param string $message
     */
    public function __construct($message = "", Throwable $previous = null) {
        parent::__construct($message, $previous);
    }

    public static function generateGeneralException($anything, Throwable $previous = null) {
        if (is_string($anything)) {
            return new SuperTokensGeneralException(@$anything, $previous);
        } else if ($anything instanceof SuperTokensException) {
            return $anything;
        } else if ($anything instanceof Exception) {
            if (!isset($previous)) {
                return new SuperTokensGeneralException("General error", anything);
            } else {
                return new SuperTokensGeneralException($anything->getMessage(), $previous);
            }
        }
        return new SuperTokensGeneralException("General error", $previous);
    }

    public static function generateUnauthorisedException($anything) {
        if (is_string($anything)) {
            return new SuperTokensUnauthorizedException(@message);
        } else if ($anything instanceof SuperTokensException) {
            return $anything;
        } else if ($anything instanceof Exception) {
            return new SuperTokensUnauthorizedException(@$anything->getMessage());
        }
        return new SuperTokensUnauthorizedException("Unauthorised");
    }

    public static function generateTryRefreshTokenException($anything) {
        if (is_string($anything)) {
            return new SuperTokensTryRefreshTokenException(@message);
        } else if ($anything instanceof SuperTokensException) {
            return $anything;
        } else if ($anything instanceof Exception) {
            return new SuperTokensTryRefreshTokenException(@$anything->getMessage());
        }
        return new SuperTokensTryRefreshTokenException("Try refresh token");
    }

}