<?php

namespace SuperTokens\Session\Helpers;

use Exception;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use SuperTokens\Session\Db\SigningKeyDb;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensException;

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
     * @throws SuperTokensGeneralException
     */
    public static function init() {
        if (!isset(AccessTokenSigningKey::$instance)) {
            AccessTokenSigningKey::$instance = new AccessTokenSigningKey();
            AccessTokenSigningKey::getKey();
        }
    }

    /**
     * @return string
     * @throws SuperTokensGeneralException
     */
    private function getKeyFromInstance() {
        if (isset($this->userDefinedGet)) {
            try {
                return call_user_func($this->userDefinedGet);
            } catch (Exception $e) {
                throw SuperTokensException::generateGeneralException("Exception thrown from user provided function to get access token signing key", $e);
            }
        }

        if (!isset($instance->signingKey)) {
            $newKey = $this->maybeGenerateNewKeyAndUpdateInDb();
            $this->signingKey = $newKey['keyValue'];
            $this->createdAtTime = $newKey['createdAtTime'];
        }

        $currentTime = Utils::getDateTimeStamp();

        if ($this->isDynamic && $currentTime > ($this->createdAtTime + $this->updateInterval)) {
            // key has expired, we need to change it.
            $newKey = $this->maybeGenerateNewKeyAndUpdateInDb();
            $this->signingKey = $newKey['keyValue'];
            $this->createdAtTime = $newKey['createdAtTime'];
        }

        return $this->signingKey;
    }

    /**
     * @return string
     * @throws SuperTokensGeneralException
     */
    public static function getKey() {
        if (!isset(AccessTokenSigningKey::$instance)) {
            throw SuperTokensException::generateGeneralException("please call init function of access token signing key");
        }

        return AccessTokenSigningKey::$instance->getKeyFromInstance();
    }

    /**
     * @return array
     * @throws SuperTokensGeneralException
     */
    private function maybeGenerateNewKeyAndUpdateInDb() {
        $rollback = false;
        try {
            DB::beginTransaction();
            $rollback = true;
            $key = SigningKeyDb::getKeyValueFromKeyNameForUpdate(ACCESS_TOKEN_SIGNING_KEY_NAME_IN_DB);
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
                SigningKeyDb::insertKeyValueForKeyName_Transaction(ACCESS_TOKEN_SIGNING_KEY_NAME_IN_DB, $keyValue, $currentTime);
            }

            $this->createdAtTime = $key['createdAtTime'];
            DB::commit();
            $rollback = false;
            return $key;
        } catch (Exception $e) {
            if ($rollback) {
                DB::rollBack();
            }
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @throws SuperTokensGeneralException
     */
    public static function removeKeyFromMemory() {
        if (!isset(AccessTokenSigningKey::$instance)) {
            throw SuperTokensException::generateGeneralException("please call init function of access token signing key");
        }

        AccessTokenSigningKey::$instance->removeKeyFromMemoryInInstance();
    }

    private function removeKeyFromMemoryInInstance() {
        $this->signingKey = null;
        $this->createdAtTime = null;
    }

    /**
     * @throws SuperTokensGeneralException
     */
    public static function resetInstance() {
        if (Config::get('env') !== "testing") {
            throw SuperTokensException::generateGeneralException("AccessToken reset should only be called during testing");
        }
        if (App::environment("testing")) {
            SigningKeyDb::removeKeyValueForKeyName(ACCESS_TOKEN_SIGNING_KEY_NAME_IN_DB);
            AccessTokenSigningKey::$instance = null;
        }
    }
}