<?php

namespace SuperTokens\Laravel\Helpers;

use Error;
use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use SuperTokens\Laravel\Db\SigningKeyDb;

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
        $this->updateInterval = Config::get('supertokens.tokens.accessToken.signingKey.updateInterval');
        $this->userDefinedGet = Config::get('supertokens.tokens.accessToken.signingKey.get');
    }

    /**
     * @throws Exception
     */
    public static function init() {
        if (!isset(AccessTokenSigningKey::$instance)) {
            AccessTokenSigningKey::$instance = new AccessTokenSigningKey();
            AccessTokenSigningKey::getKey();
        }
    }

    /**
     * @return mixed|string
     * @throws Exception
     */
    private function getKeyFromInstance() {
        // wrap around error
        if (isset($this->userDefinedGet)) {
            return $this->userDefinedGet();
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
    }

    /**
     * @return string
     * @throws Exception
     */
    public static function getKey() {
        if (!isset(AccessTokenSigningKey::$instance)) {
            throw new Error('');
        }

        return AccessTokenSigningKey::$instance->getKeyFromInstance();
    }

    /**
     * @return string
     * @throws Exception
     */
    private function maybeGenerateNewKeyAndUpdateInDb() {
        DB::beginTransaction();

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
                $this->createdAtTime = $currentTime;
            }

            DB::commit();
            return $key['keyValue'];
        } catch (Exception $e) {
            DB::rollBack();
            throw $e;
        }
    }

    /**
     *
     */
    public static function removeKeyFromMemory() {
        if (!isset(AccessTokenSigningKey::$instance)) {
            throw new Error('');
        }

        AccessTokenSigningKey::$instance->removeKeyFromMemoryInInstance();
    }

    /**
     *
     */
    private function removeKeyFromMemoryInInstance() {
        $this->signingKey = null;
        $this->createdAtTime = null;
    }
}