<?php

namespace SuperTokens\Session\Exceptions;

use Exception;

/**
 * Class SuperTokensUnauthorizedException
 * @package SuperTokens\Laravel\Exceptions
 */
class SuperTokensUnauthorizedException extends SuperTokensException
{

    /**
     * SuperTokensUnauthorizedException constructor.
     * @param $anything
     */
    public function __construct($anything)
    {
        $message = "Unauthorised";
        $previous = null;
        if (is_string($anything)) {
            $message = $anything;
        } elseif ($anything instanceof SuperTokensException) {
            $message = $anything->getMessage();
            $previous = $anything->getPrevious();
        } elseif ($anything instanceof Exception) {
            $message = $anything->getMessage();
        }
        parent::__construct($message, $previous);
    }
}
