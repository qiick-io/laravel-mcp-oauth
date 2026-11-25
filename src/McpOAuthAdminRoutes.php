<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\Facades\Route;
use Qiick\McpOAuth\Http\Controllers\ClientAdminController;

/**
 * The admin routes for MCP clients and blocked hosts (design §5.2). The
 * product calls this inside its own admin group (`web`, `auth`, …) and names
 * the permission middleware every route also needs. They stay up while OAuth
 * is off, so an admin can still clean up.
 *
 * @api
 */
final class McpOAuthAdminRoutes
{
    public static function register(string $permissionMiddleware): void
    {
        Route::middleware($permissionMiddleware)->prefix('mcp-oauth-clients')->name('mcp-oauth.admin.')->group(static function (): void {
            Route::get('/', [ClientAdminController::class, 'index'])->name('index');
            Route::post('bulk-block', [ClientAdminController::class, 'bulkBlock'])->name('bulk-block');
            Route::post('blocked-hosts', [ClientAdminController::class, 'blockHost'])->name('blocked-hosts.store');
            Route::delete('blocked-hosts/{blockedHostId}', [ClientAdminController::class, 'unblockHost'])->name('blocked-hosts.destroy');
            Route::post('{clientId}/block', [ClientAdminController::class, 'block'])->name('block');
        });
    }
}
