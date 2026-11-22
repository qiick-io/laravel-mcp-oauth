<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Admin-blocked redirect hosts for DCR and authorize/token checks (M6 / §2.3).
 * Publish tag mcp-oauth-migrations; products that already have the table publish
 * nothing and add columns with their own additive migration.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oauth_blocked_redirect_hosts', function (Blueprint $table): void {
            $table->id();
            $table->uuid('public_id')->unique();
            $table->string('host')->unique();
            $table->string('host_original', 1024)->nullable();
            $table->string('match_mode', 24)->default('host_and_subdomains');
            $table->string('reason', 512)->nullable();
            $table->dateTime('expires_at')->nullable()->index();
            $table->json('metadata')->nullable();
            $table->unsignedSmallInteger('schema_version')->default(1);
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_blocked_redirect_hosts');
    }
};
