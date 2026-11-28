<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Append-only consent evidence (S4 / §2.4). Written on approve and deny; purged
 * with the 90-day retention rule. No updated_at: retention and erasure
 * are the only operations allowed to modify existing evidence.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_consent_records', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('client_id')->index();
            $table->string('user_identifier', 64)->nullable()->index();
            $table->uuid('grant_id')->nullable()->index();
            $table->string('decision', 16);
            $table->text('redirect_uri')->nullable();
            $table->string('redirect_host')->nullable();
            $table->string('resource', 512)->nullable();
            $table->json('resource_scopes')->nullable();
            $table->json('requested_scopes');
            $table->json('granted_scopes')->nullable();
            $table->string('role')->nullable();
            $table->json('resources')->nullable();
            $table->boolean('all_resources')->default(false);
            $table->json('attributes')->nullable();
            $table->string('consent_version', 32)->nullable();
            $table->string('locale', 16)->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->string('user_agent', 512)->nullable();
            $table->string('correlation_id', 64)->nullable();
            $table->dateTime('retention_until')->nullable()->index();
            $table->json('metadata')->nullable();
            $table->unsignedSmallInteger('schema_version')->default(1);
            $table->timestamp('created_at')->useCurrent()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_consent_records');
    }
};
