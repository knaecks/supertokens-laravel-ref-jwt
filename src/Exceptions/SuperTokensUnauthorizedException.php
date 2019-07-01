<?php

namespace SuperTokens\Session\Exceptions;

use Exception;

/**
 * Class SuperTokensUnauthorizedException
 * @package SuperTokens\Laravel\Exceptions
 */
class SuperTokensUnauthorizedException extends SuperTokensException {

    /**
     * SuperTokensUnauthorizedException constructor.
     * @param $anything
     */
    public function __construct($anything) {
        $message = "Unauthorised";
        $previous = null;
        if (is_string($anything)) {
            $message = $anything;
        } else if ($anything instanceof SuperTokensException) {
            $message = $anything->getMessage();
            $previous = $anything->getPrevious();
        } else if ($anything instanceof Exception) {
            $message = $anything->getMessage();
        }
        parent::__construct($message, $previous);
    }
}