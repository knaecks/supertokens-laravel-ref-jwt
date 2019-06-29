<?php

namespace SuperTokens\Session\Helpers;

use Exception;
use Illuminate\Support\Facades\DB;
use SuperTokens\Session\Db\SigningKeyDb;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensException;

define("REFRESH_TOKEN_KEY_NAME_IN_DB", "refresh_token_key");

class RefreshTokenSigningKey {

    /**
     * @var string
     */
    private $key;

    /**
     * @var RefreshTokenSigningKey
     */
    private static $instance;

    /**
     * RefreshTokenSigningKey constructor.
     */
    private function __construct() {}

    /**
     * @throws SuperTokensGeneralException
     */
    public static function init() {
        if (!isset(RefreshTokenSigningKey::$instance)) {
            RefreshTokenSigningKey::$instance = new RefreshTokenSigningKey();
            RefreshTokenSigningKey::getKey();
        }
    }

    /**
     * @return string
     * @throws SuperTokensGeneralException
     */
    public static function getKey() {
        if (!isset(RefreshTokenSigningKey::$instance)) {
            throw SuperTokensException::generateGeneralException('please call init function of refresh token key');
        }

        return RefreshTokenSigningKey::$instance->getKeyFromInstance();
    }

    /**
     * @return string
     * @throws SuperTokensGeneralException
     */
    private function getKeyFromInstance() {
        if (!isset($instance->key)) {
            $this->key= $this->generateNewKeyAndUpdateInDb();
        }
        return $this->key;
    }

    /**
     * @return string
     * @throws SuperTokensGeneralException
     */
    private function generateNewKeyAndUpdateInDb() {
        try {
            DB::beginTransaction();
            $key = SigningKeyDb::getKeyValueFromKeyName(REFRESH_TOKEN_KEY_NAME_IN_DB);
            if ($key === null) {
                $keyValue = Utils::generateNewSigningKey();
                $currentTime = Utils::getDateTimeStamp();
                $key = [
                    'keyValue' => $keyValue,
                    'createdAtTime' => $currentTime
                ];
                SigningKeyDb::insertKeyValueForKeyName(REFRESH_TOKEN_KEY_NAME_IN_DB, $keyValue, $currentTime);
            }
            DB::commit();
            return $key['keyValue'];
        } catch (Exception $e) {
            DB::rollBack();
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @throws SuperTokensGeneralException
     */
    public static function resetInstance() {
        SigningKeyDb::removeKeyValueForKeyName(REFRESH_TOKEN_KEY_NAME_IN_DB);
        RefreshTokenSigningKey::$instance = null;
    }
}