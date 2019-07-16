<?php

namespace SuperTokens\Session;

use Illuminate\Http\Response;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensUnauthorizedException;
use SuperTokens\Session\Helpers\Cookie;

class Session {
    /**
     * @var
     */
    private $sessionHandle;

    /**
     * @var string
     */
    private $userId;

    /**
     * @var
     */
    private $jwtUserPayload;

    /**
     * @var Response
     */
    private $response;

    /**
     * SuperTokens constructor.
     * @param $sessionHandle
     * @param $userId
     * @param $jwtUserPayload
     * @param $response
     */
    public function __construct($sessionHandle, $userId, $jwtUserPayload, $response) {
        $this->sessionHandle = $sessionHandle;
        $this->userId = $userId;
        $this->jwtUserPayload = $jwtUserPayload;
        $this->response = $response;
    }

    /**
     * @throws SuperTokensGeneralException
     */
    public function revokeSession() {
        SuperToken::revokeSessionUsingSessionHandle($this->sessionHandle);
        Cookie::clearSessionFromCookie($this->response);
    }

    /**
     * @return mixed
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     */
    public function getSessionData() {
        try {
            return SessionHandlingFunctions::getSessionData($this->sessionHandle);
        } catch (SuperTokensUnauthorizedException $e) {
            Cookie::clearSessionFromCookie($this->response);
            throw $e;
        }
    }

    /**
     * @param $newSessionData
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     */
    public function updateSessionData($newSessionData) {
        try {
            SessionHandlingFunctions::updateSessionData($this->sessionHandle, $newSessionData);
        } catch (SuperTokensUnauthorizedException $e) {
            Cookie::clearSessionFromCookie($this->response);
            throw $e;
        }
    }

    /**
     * @return string
     */
    public function getUserId() {
        return $this->userId;
    }

    /**
     * @return mixed
     */
    public function getJWTPayload() {
        return $this->jwtUserPayload;
    }

}