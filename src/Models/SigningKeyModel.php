<?php
namespace SuperTokens\Session\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Class SigningKeyModel
 * @package SuperTokens\SessionHandlingFunctions\Models
 * @mixin Builder
 */
class SigningKeyModel extends Model {
    protected $table = "signing_key";

    protected $fillable = ['key_name', 'key_value', 'created_at_time'];

    public $timestamps = false;
}