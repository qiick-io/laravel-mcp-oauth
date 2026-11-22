<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Admin-blocked redirect hosts for DCR and authorize/token checks (M6 / §2.3).
 * Loaded by the package; publish tag mcp-oauth-migrations is for apps that
 * customise the schema and add further columns with their own migrations.
 */
return new class extends Migration
{
    public function up(): void
    {
        $userModelClass = config('mcp-oauth.user_model') ?: config('auth.providers.users.model');
        $userTable = is_string($userModelClass) && is_a($userModelClass, Model::class, true)
            ? (new $userModelClass)->getTable()
            : 'users';

        Schema::create('oauth_blocked_redirect_hosts', function (Blueprint $table) use ($userTable): void {
            $table->id();
            $table->uuid('public_id')->unique();
            $table->string('host')->unique();
            $table->string('host_original', 1024)->nullable();
            $table->string('match_mode', 24)->default('host_and_subdomains');
            $table->string('reason', 512)->nullable();
            $table->dateTime('expires_at')->nullable()->index();
            $table->json('metadata')->nullable();
            $table->unsignedSmallInteger('schema_version')->default(1);
            $table->foreignId('created_by')->nullable()->constrained($userTable)->nullOnDelete();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oauth_blocked_redirect_hosts');
    }
};
