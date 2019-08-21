<?php

namespace SuperTokens\Session\Exceptions;

use Exception;

/**
 * Class SuperTokensTryRefreshTokenException
 * @package SuperTokens\Laravel\Exceptions
 */
class SuperTokensTryRefreshTokenException extends SuperTokensException
{

    /**
     * SuperTokensTryRefreshTokenException constructor.
     * @param $anything
     */
    public function __construct($anything)
    {
        $message = "Try refresh token";
        $previous = null;
        if (is_string($anything)) {
            $message = $anything;
        } elseif ($anything instanceof Exception) {
            $message = $anything->getMessage();
        }
        parent::__construct($message, $previous);
    }
}
