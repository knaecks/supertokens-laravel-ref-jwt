<?php

namespace SuperTokens\Laravel\Helpers;

use Error;
use Exception;
use Illuminate\Support\Facades\DB;
use SuperTokens\Laravel\Db\SigningKeyDb;

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
     * @throws Exception
     */
    public static function init() {
        if (!isset(RefreshTokenSigningKey::$instance)) {
            RefreshTokenSigningKey::$instance = new RefreshTokenSigningKey();
            RefreshTokenSigningKey::getKey();
        }
    }

    /**
     * @return mixed|string
     * @throws Exception
     */
    public static function getKey() {
        if (!isset(RefreshTokenSigningKey::$instance)) {
            throw new Error('');
        }

        return RefreshTokenSigningKey::$instance->getKeyFromInstance();
    }

    /**
     * @return mixed|string
     * @throws Exception
     */
    private function getKeyFromInstance() {
        if (!isset($instance->key)) {
            $this->key= $this->generateNewKeyAndUpdateInDb();
        }
        return $this->key;
    }

    /**
     * @return string
     * @throws Exception
     */
    private function generateNewKeyAndUpdateInDb() {
        DB::beginTransaction();

        try {
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
            throw $e;
        }
    }
}