<?php

namespace SuperTokens\Laravel\Db;

use SuperTokens\Laravel\Models\SigningKeyModel;

class SigningKeyDb {

    /**
     * @param $keyName
     * @return array|null
     */
    public static function getKeyValueFromKeyName($keyName) {
        // check for transaction
        $result= SigningKeyModel::where('key_name', '=', $keyName)->lockForUpdate()->first();
        if ($result === null) {
            return null;
        }
        return [
            'keyValue' => $result->key_value,
            'createdAtTime' => $result->created_at_time
        ];
    }

    /**
     * @param $keyName
     * @param $keyValue
     * @param $createdAtTime
     */
    public static function insertKeyValueForKeyName($keyName, $keyValue, $createdAtTime) {
        $signingKey = new SigningKeyModel;
        $signingKey->updateOrInsert(
            ['key_name', 'key_value', 'created_at_time'],
            [$keyName, $keyValue, $createdAtTime]
        );
        $signingKey->save();
    }

}