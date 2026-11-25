<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Qiick\McpOAuth\Actions\DeleteClientAction;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\Contracts\GrantStore;
use Qiick\McpOAuth\Data\ClientInfo;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\ConsentOptions;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\HookedGrantStore;
use Qiick\McpOAuth\Tests\Support\TestUser;
use Symfony\Component\Process\Process;

uses(AuthorizeFlowTestCase::class);

/**
 * A user's first approval racing mcp-oauth:prune-unused-clients (review of
 * #45). Both take the client's metadata row lock: the approval before it
 * writes the grant, the prune before it deletes. Whichever commits first
 * wins, and the other sees it: a pruned client cannot be approved, and an
 * approved one is never pruned.
 */

/**
 * Shows the consent page, runs `$beforeApproval`, then posts the approval.
 */
function approveAfter(AuthorizeFlowTestCase $testCase, Client $client, TestUser $user, Closure $beforeApproval): TestResponse
{
    $consentPage = $testCase->actingAs($user)->get($testCase->authorizeUrl($client), ['X-Inertia' => 'true'])->assertOk();
    $beforeApproval();

    return $testCase->post('/oauth/authorize', [
        'auth_token' => $consentPage->json('props.authToken'),
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ]);
}

/**
 * The second session: the real prune, in its own process on the same server
 * database.
 */
function pruneInAnotherSession(string $signalFile = '', int $holdSeconds = 0): Process
{
    $process = new Process([PHP_BINARY, 'tests/Support/prune-unused-clients.php', $signalFile, (string) $holdSeconds], dirname(__DIR__, 2));
    $process->start();

    return $process;
}

function isServerDatabase(): bool
{
    return (getenv('DB_CONNECTION') ?: 'sqlite') !== 'sqlite';
}

beforeEach(function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
});

it('refuses an approval whose client was pruned after the consent page was read', function (): void {
    $client = $this->createClient();
    $hookedGrantStore = new HookedGrantStore($this->grantStore());
    app()->instance(GrantStore::class, $hookedGrantStore);
    // The prune commits between the approval's checks and its transaction.
    app()->instance(ConsentProvider::class, new class(AuthorizeFlowTestCase::defaultConsentOptions(), (string) $client->getKey()) implements ConsentProvider
    {
        public function __construct(private readonly ConsentOptions $consentOptions, private readonly string $clientId) {}

        public function options(Request $request, Authenticatable $user, ClientInfo $client): ConsentOptions
        {
            return $this->consentOptions;
        }

        public function validate(Request $request, Authenticatable $user, ConsentDecision $decision): void
        {
            app(DeleteClientAction::class)->execute($this->clientId);
        }
    });

    approveAfter($this, $client, $this->createUser(), static fn () => null)->assertForbidden();

    expect($this->grantStore()->replacedDecisions)->toBe([]);
});

it('makes an approval wait for a prune holding the client, then refuses it (two sessions)', function (): void {
    $client = $this->createClient();
    $client->forceFill(['created_at' => now()->subHours(25)])->save();
    $signalFile = sys_get_temp_dir().'/mcp-oauth-prune-race-'.bin2hex(random_bytes(6));

    $response = approveAfter($this, $client, $this->createUser(), static function () use ($signalFile): void {
        $prune = pruneInAnotherSession($signalFile, 3);
        $deadline = microtime(true) + 20;

        while (! is_file($signalFile)) {
            if (microtime(true) > $deadline || ! $prune->isRunning()) {
                throw new RuntimeException('The prune never locked the client: '.$prune->getErrorOutput());
            }

            usleep(50_000);
        }
    });
    @unlink($signalFile);

    $response->assertForbidden();

    expect($this->grantStore()->replacedDecisions)->toBe([])
        ->and(Client::query()->whereKey($client->getKey())->exists())->toBeFalse();
})->skip(fn (): bool => ! isServerDatabase(), 'two sessions need a server database (DB_CONNECTION pgsql, mysql or mariadb)');

it('makes a prune wait for an approval holding the client, then keeps it (two sessions)', function (): void {
    $client = $this->createClient();
    $client->forceFill(['created_at' => now()->subHours(25)])->save();
    $hookedGrantStore = new HookedGrantStore($this->grantStore());
    app()->instance(GrantStore::class, $hookedGrantStore);
    $prune = null;
    // Inside the approval's transaction: the prune starts, selects the
    // client as unused, and must then wait for this transaction.
    $hookedGrantStore->beforeNextReplace = static function () use (&$prune): void {
        $prune = pruneInAnotherSession();
        sleep(2);
    };

    approveAfter($this, $client, $this->createUser(), static fn () => null)->assertRedirect();
    $prune->wait();

    expect($prune->getOutput())->toBe('0')
        ->and(Client::query()->whereKey($client->getKey())->exists())->toBeTrue()
        ->and(OAuthClientMetadata::query()->where('client_id', $client->getKey())->value('first_authorized_at'))->not->toBeNull();
})->skip(fn (): bool => ! isServerDatabase(), 'two sessions need a server database (DB_CONNECTION pgsql, mysql or mariadb)');
