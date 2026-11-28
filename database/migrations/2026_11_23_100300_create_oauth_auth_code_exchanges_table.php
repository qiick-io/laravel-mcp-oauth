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
 * once when the code is consumed. Per-install grants bind the row at issue
 * time and keep its expiry until the code is consumed.
 *
 * M7 exception: keyed by Passport's code id, not a UUID. The row is technical,
 * never leaves the database and never appears on the wire, so a public id
 * would identify nothing anyone asks for.
 */
return new class extends Migration
{
    /**
     * Passport's connection, like Passport's own migrations: the model reads
     * and writes this table beside Passport's rows (UsesPassportConnectionTrait).
     */
    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }

    public function up(): void
    {
        Schema::create('oauth_auth_code_exchanges', function (Blueprint $table): void {
            $table->string('auth_code_id', 100)->primary();
            $table->uuid('grant_id')->index();
            $table->dateTime('expires_at')->nullable()->index();
            // Keep the exchange erasable after Passport prunes the original code.
            $table->string('user_identifier', 64)->nullable()->index();
            $table->json('metadata')->nullable();
            $table->unsignedSmallInteger('schema_version')->default(1);
            $table->timestamp('created_at')->useCurrent()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_auth_code_exchanges');
    }
};
