<?php
namespace SuperTokens\Session\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Class RefreshTokenModel
 * @package SuperTokens\Laravel\Models
 * @mixin Builder
 */
class RefreshTokenModel extends Model
{
    protected $table = "refresh_token";

    protected $primaryKey = 'session_handle';

    public $incrementing = false;

    public $timestamps = false;
}
