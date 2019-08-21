<?php

namespace SuperTokens\Session;

use Illuminate\Http\Response;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensUnauthorizedException;
use SuperTokens\Session\Helpers\CookieAndHeader;

class Session
{
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
    public function __construct($sessionHandle, $userId, $jwtUserPayload, $response)
    {
        $this->sessionHandle = $sessionHandle;
        $this->userId = $userId;
        $this->jwtUserPayload = $jwtUserPayload;
        $this->response = $response;
    }

    /**
     * @throws SuperTokensGeneralException
     */
    public function revokeSession()
    {
        if (SuperToken::revokeSessionUsingSessionHandle($this->sessionHandle)) {
            CookieAndHeader::clearSessionFromCookie($this->response);
        }
    }

    /**
     * @return mixed
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     */
    public function getSessionInfo()
    {
        try {
            return SessionHandlingFunctions::getSessionInfo($this->sessionHandle);
        } catch (SuperTokensUnauthorizedException $e) {
            CookieAndHeader::clearSessionFromCookie($this->response);
            throw $e;
        }
    }

    /**
     * @param $newSessionInfo
     * @throws SuperTokensGeneralException
     * @throws SuperTokensUnauthorizedException
     */
    public function updateSessionInfo($newSessionInfo)
    {
        try {
            SessionHandlingFunctions::updateSessionInfo($this->sessionHandle, $newSessionInfo);
        } catch (SuperTokensUnauthorizedException $e) {
            CookieAndHeader::clearSessionFromCookie($this->response);
            throw $e;
        }
    }

    /**
     * @return string
     */
    public function getUserId()
    {
        return $this->userId;
    }

    /**
     * @return mixed
     */
    public function getJWTPayload()
    {
        return $this->jwtUserPayload;
    }
}
