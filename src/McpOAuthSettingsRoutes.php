<?php

declare(strict_types=1);

namespace Qiick\McpOAuth;

use Illuminate\Support\Facades\Route;
use Qiick\McpOAuth\Http\Controllers\ConnectedAppsController;

/**
 * The signed-in user's Connected apps routes (design §5.2). The product
 * calls this inside its own authenticated group (`web`, `auth`). They stay up
 * while OAuth is off (design §4.2), so leftover grants can still be revoked.
 *
 * @api
 */
final class McpOAuthSettingsRoutes
{
    public static function register(): void
    {
        Route::prefix('settings/connected-apps')->name('mcp-oauth.connected-apps.')->group(static function (): void {
            Route::get('/', [ConnectedAppsController::class, 'index'])->name('index');
            Route::delete('{grantId}', [ConnectedAppsController::class, 'destroy'])->name('destroy');
        });
    }
}
