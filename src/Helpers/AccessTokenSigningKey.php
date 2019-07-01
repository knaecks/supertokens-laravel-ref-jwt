<?php

namespace SuperTokens\Session\Helpers;

use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use SuperTokens\Session\Db\SigningKeyDb;
use SuperTokens\Session\Exceptions\GeneralException;
use SuperTokens\Session\Exceptions\SuperTokensAuthException;

define("ACCESS_TOKEN_SIGNING_KEY_NAME_IN_DB", "access_token_signing_key");

/**
 * Class AccessTokenSigningKey
 * @method userDefinedGet()
 */
class AccessTokenSigningKey {

    /**
     * @var AccessTokenSigningKey
     */
    private static $instance;

    /**
     * @var string
     */
    private $signingKey;

    /**
     * @var mixed
     */
    private $userDefinedGet;

    /**
     * @var boolean
     */
    private $isDynamic;

    /**
     * @var double
     */
    private $updateInterval;

    /**
     * @var integer
     */
    private $createdAtTime;

    /**
     * AccessTokenSigningKey constructor.
     */
    private function __construct() {
        $this->isDynamic = Config::get('supertokens.tokens.accessToken.signingKey.dynamic');
        $this->updateInterval = Config::get('supertokens.tokens.accessToken.signingKey.updateInterval') * 60 * 60;
        $this->userDefinedGet = Config::get('supertokens.tokens.accessToken.signingKey.get');
    }

    /**
     * @throws SuperTokensAuthException
     */
    public static function init() {
        if (!isset(AccessTokenSigningKey::$instance)) {
            AccessTokenSigningKey::$instance = new AccessTokenSigningKey();
            AccessTokenSigningKey::getKey();
        }
    }

    /**
     * @return string
     * @throws Exception
     */
    private function getKeyFromInstance() {
        try {
            if (isset($this->userDefinedGet)) {
                return call_user_func($this->userDefinedGet);
            }

            if (!isset($instance->signingKey)) {
                $this->signingKey = $this->maybeGenerateNewKeyAndUpdateInDb();
            }

            $currentTime = Utils::getDateTimeStamp();


            if ($this->isDynamic && $currentTime > ($this->createdAtTime + $this->updateInterval)) {
                // key has expired, we need to change it.
                $this->signingKey = $this->maybeGenerateNewKeyAndUpdateInDb();
            }

            return $this->signingKey;
        } catch (Exception $e) {
            throw $e;
        }
    }

    /**
     * @return string
     * @throws SuperTokensAuthException | Exception
     */
    public static function getKey() {
        if (!isset(AccessTokenSigningKey::$instance)) {
            throw new GeneralException("please call init function of access token signing key");
        }

        return AccessTokenSigningKey::$instance->getKeyFromInstance();
    }

    /**
     * @return string
     * @throws Exception
     */
    private function maybeGenerateNewKeyAndUpdateInDb() {
        DB::beginTransaction();
        $rollback = true;
        try {
            $key = SigningKeyDb::getKeyValueFromKeyName(ACCESS_TOKEN_SIGNING_KEY_NAME_IN_DB);
            $generateNewKey = false;

            if ($key !== null) {
                $currentTime = Utils::getDateTimeStamp();
                if ($this->isDynamic && $currentTime > ($key['createdAtTime'] + $this->updateInterval)) {
                    $generateNewKey = true;
                }
            }

            if ($key === null || $generateNewKey) {
                $keyValue = Utils::generateNewSigningKey();
                $currentTime = Utils::getDateTimeStamp();
                $key = [
                    'keyValue' => $keyValue,
                    'createdAtTime' => $currentTime
                ];
                SigningKeyDb::insertKeyValueForKeyName(ACCESS_TOKEN_SIGNING_KEY_NAME_IN_DB, $keyValue, $currentTime);
            }

            $this->createdAtTime = $key['createdAtTime'];
            $rollback = false;
            DB::commit();
            return $key['keyValue'];
        } catch (Exception $e) {
            if ($rollback) {
                DB::rollBack();
            }
            throw $e;
        }
    }

    /**
     * @throws SuperTokensAuthException
     */
    public static function removeKeyFromMemory() {
        if (!isset(AccessTokenSigningKey::$instance)) {
            throw new GeneralException("please call init function of access token signing key");
        }

        AccessTokenSigningKey::$instance->removeKeyFromMemoryInInstance();
    }

    private function removeKeyFromMemoryInInstance() {
        $this->signingKey = null;
        $this->createdAtTime = null;
    }

    public static function resetInstance() {
        AccessTokenSigningKey::$instance = null;
    }
}