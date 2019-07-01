<?php

namespace SuperTokens\Session\Db;

use Exception;
use SuperTokens\Session\Exceptions\SuperTokensGeneralException;
use SuperTokens\Session\Exceptions\SuperTokensException;
use SuperTokens\Session\Models\SigningKeyModel;

class SigningKeyDb {

    /**
     * @param $keyName
     * @return array|null
     * @throws SuperTokensGeneralException
     */
    public static function getKeyValueFromKeyNameForUpdate($keyName) {
        // check for transaction
        try {
            $result = SigningKeyModel::where('key_name', '=', $keyName)->lockForUpdate()->first();
            if ($result === null) {
                return null;
            }
            return [
                'keyValue' => $result->key_value,
                'createdAtTime' => $result->created_at_time
            ];
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $keyName
     * @param $keyValue
     * @param $createdAtTime
     * @throws SuperTokensGeneralException
     */
    public static function insertKeyValueForKeyName_Transaction($keyName, $keyValue, $createdAtTime) {
        try {
            SigningKeyModel::updateOrInsert(
                ['key_name' => $keyName],
                ['key_name' => $keyName, 'key_value' => $keyValue, 'created_at_time' => $createdAtTime]
            );
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }

    /**
     * @param $keyName
     * @throws SuperTokensGeneralException
     */
    public static function removeKeyValueForKeyName($keyName) {
        try {
            SigningKeyModel::where('key_name', '=', $keyName)->delete();
        } catch (Exception $e) {
            throw SuperTokensException::generateGeneralException($e);
        }
    }
}