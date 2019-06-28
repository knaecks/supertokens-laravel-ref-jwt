<?php

namespace SuperTokens\Session\Db;

use Exception;
use SuperTokens\Session\Exceptions\GeneralException;
use SuperTokens\Session\Exceptions\SuperTokensAuthException;
use SuperTokens\Session\Models\SigningKeyModel;

class SigningKeyDb {

    /**
     * @param $keyName
     * @return array|null
     * @throws SuperTokensAuthException
     */
    public static function getKeyValueFromKeyName($keyName) {
        // check for transaction
        try {
            $result= SigningKeyModel::where('key_name', '=', $keyName)->lockForUpdate()->first();
            if ($result === null) {
                return null;
            }
            return [
                'keyValue' => $result->key_value,
                'createdAtTime' => $result->created_at_time
            ];
        } catch (Exception $e) {
            throw new GeneralException($e->getMessage());
        }
    }

    /**
     * @param $keyName
     * @param $keyValue
     * @param $createdAtTime
     * @throws SuperTokensAuthException
     */
    public static function insertKeyValueForKeyName($keyName, $keyValue, $createdAtTime) {
        try {
            $signingKey = new SigningKeyModel;
            $signingKey->updateOrInsert(
                ['key_name' => $keyName],
                ['key_name' => $keyName, 'key_value' => $keyValue, 'created_at_time' => $createdAtTime]
            );
        } catch (Exception $e) {
            throw new GeneralException($e->getMessage());
        }
    }

    /**
     * @param $keyName
     * @throws SuperTokensAuthException
     */
    public static function removeKeyValueForKeyName($keyName) {
        try {
            SigningKeyModel::where('key_name', '=', $keyName)->delete();
        } catch (Exception $e) {
            throw new GeneralException($e->getMessage());
        }
    }
}