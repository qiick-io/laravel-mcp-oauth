<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Side table for RFC 7591 / 7592 client metadata, CIMD cache, and per-client
 * PAR/DPoP flags (standards review §2.2 / M3). One row per Passport client;
 * Passport's oauth_clients is never altered.
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
        Schema::create('oauth_client_metadata', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('client_id')->unique();
            $table->string('registration_source', 16)->index();
            $table->string('spec_revision', 16)->nullable();
            $table->string('application_type', 16)->nullable();
            $table->string('client_uri', 2048)->nullable();
            $table->string('logo_uri', 2048)->nullable();
            $table->string('tos_uri', 2048)->nullable();
            $table->string('policy_uri', 2048)->nullable();
            $table->json('contacts')->nullable();
            $table->string('software_id')->nullable();
            $table->string('software_version')->nullable();
            $table->text('software_statement')->nullable();
            // Nullable, no DB default: registration always writes the effective value (Resolved #2).
            $table->string('token_endpoint_auth_method', 64)->nullable();
            $table->string('jwks_uri', 2048)->nullable();
            $table->json('jwks')->nullable();
            $table->timestamp('client_id_issued_at')->nullable();
            $table->dateTime('client_secret_expires_at')->nullable();
            $table->char('registration_access_token_hash', 64)->nullable()->unique();
            $table->dateTime('registration_access_token_expires_at')->nullable();
            $table->text('metadata_document_url')->nullable();
            $table->char('metadata_document_url_sha256', 64)->nullable()->unique();
            $table->json('metadata_document')->nullable();
            $table->char('metadata_document_sha256', 64)->nullable();
            $table->string('metadata_document_etag')->nullable();
            $table->timestamp('metadata_document_fetched_at')->nullable();
            $table->dateTime('metadata_document_expires_at')->nullable()->index();
            $table->string('metadata_document_status', 16)->nullable();
            $table->string('metadata_document_error', 512)->nullable();
            $table->boolean('require_pushed_authorization_requests')->default(false);
            $table->boolean('dpop_bound_access_tokens')->default(false);
            $table->timestamp('revoked_at')->nullable()->index();
            $table->string('revocation_reason', 32)->nullable();
            $table->dateTime('retention_until')->nullable()->index();
            $table->json('metadata')->nullable();
            $table->unsignedSmallInteger('schema_version')->default(1);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_client_metadata');
    }
};
