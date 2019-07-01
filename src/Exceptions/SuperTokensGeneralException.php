<?php

namespace SuperTokens\Session\Exceptions;
use Exception;
use Throwable;

class SuperTokensGeneralException extends SuperTokensException {

    /**
     * SuperTokensGeneralException constructor.
     * @param $anything
     * @param Throwable|null $previous
     */
    protected function __construct($anything, Throwable $previous = null) {
        $message = "General error";
        if (is_string($anything)) {
            $message = $anything;
        } else if ($anything instanceof Exception) {
            if (!isset($previous)) {
                $previous = $anything;
            } else {
                $message = $anything->getMessage();
            }
        }
        parent::__construct($message, $previous);
    }
}