<?php

namespace SuperTokens\Laravel\Db;

use Exception;
use Illuminate\Support\Facades\DB;
use SuperTokens\Laravel\Exceptions\GeneralException;
use SuperTokens\Laravel\Exceptions\SuperTokensAuthException;
use SuperTokens\Laravel\Models\SigningKeyModel;

class SigningKeyDb {

    /**
     * @param $keyName
     * @return array|null
     * @throws SuperTokensAuthException
     */
    public static function getKeyValueFromKeyName($keyName) {
        // check for transaction
        try {
            DB::transactionLevel();
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
                ['key_name', 'key_value', 'created_at_time'],
                [$keyName, $keyValue, $createdAtTime]
            );
            $signingKey->save();
        } catch (Exception $e) {
            throw new GeneralException($e->getMessage());
        }
    }

}