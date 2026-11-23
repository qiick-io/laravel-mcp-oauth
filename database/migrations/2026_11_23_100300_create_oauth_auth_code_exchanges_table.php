<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Which grant an authorization code was first presented under (RFC 6749
 * §4.1.2, RFC 9700 §4.5). Passport does not link tokens to the code they
 * came from, and its tables are never altered, so a code presented again
 * finds here the grant whose tokens it must revoke. One row per code, written
 * once when the code is consumed.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_auth_code_exchanges', function (Blueprint $table): void {
            $table->string('auth_code_id', 100)->primary();
            $table->uuid('grant_id')->index();
            $table->timestamp('created_at')->useCurrent()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_auth_code_exchanges');
    }
};
