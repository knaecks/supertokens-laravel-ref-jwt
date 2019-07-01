<?php
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;
class CreateRefreshTokenTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::defaultStringLength(191);
        Schema::create('refresh_token', function (Blueprint $table) {
            $table->string('session_handle', 255)->primary();
            $table->string('user_id', 128);
            $table->string('refresh_token_hash_2', 128);
            $table->text('session_info');
            $table->bigInteger('expires_at')->unsigned();
            $table->text('jwt_user_payload');
        });
    }
    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('refresh_token');
    }
}