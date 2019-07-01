<?php

namespace SuperTokens\Session\Exceptions;
use Exception;

/**
 * Class SuperTokensTokenTheftException
 * @package SuperTokens\Laravel\Exceptions
 */
class SuperTokensTokenTheftException extends SuperTokensException {

    private $userId;

    private $sessionHandle;

    /**
     * SuperTokensTryRefreshTokenException constructor.
     * @param $anything
     */
    public function __construct($userId, $sessionHandle) {
        $message = "Token Theft Detected";
        parent::__construct($message);
        $this->userId = $userId;
        $this->sessionHandle = $sessionHandle;
    }

    public function getUserId() {
        return $this->userId;
    }

    public function getSessionHandle() {
        return $this->sessionHandle;
    }
}