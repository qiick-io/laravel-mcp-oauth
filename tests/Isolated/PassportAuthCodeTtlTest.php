<?php

declare(strict_types=1);

use Carbon\CarbonInterval;
use Laravel\Passport\Passport;
use Laravel\Passport\PersonalAccessTokenFactory;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use Qiick\McpOAuth\Contracts\ConsentProvider;
use Qiick\McpOAuth\McpOAuthServiceProvider;
use Qiick\McpOAuth\Testing\FakeConsentProvider;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Qiick\McpOAuth\Tests\Support\PassportBootedTestCase;
use ReflectionProperty;

uses(PassportBootedTestCase::class);

/**
 * @return non-empty-string
 */
function passportTestKeyContents(string $basename): string
{
    $keyDirectory = sys_get_temp_dir().'/mcp-oauth-passport-keys';

    if (! is_dir($keyDirectory)) {
        mkdir($keyDirectory, 0700, true);
    }

    $keyPath = $keyDirectory.'/'.$basename;

    if (! is_file($keyPath)) {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($resource, $privateKey);
        file_put_contents($keyDirectory.'/oauth-private.key', $privateKey);
        chmod($keyDirectory.'/oauth-private.key', 0600);
        $details = openssl_pkey_get_details($resource);
        file_put_contents($keyDirectory.'/oauth-public.key', $details['key']);
        chmod($keyDirectory.'/oauth-public.key', 0600);
    }

    $contents = file_get_contents($keyDirectory.'/'.$basename);

    if ($contents === false || $contents === '') {
        throw new RuntimeException('Failed to load Passport test key '.$basename);
    }

    return $contents;
}

function authCodeTtlMinutesFromServer(AuthorizationServer $authorizationServer): ?float
{
    $enabledGrantTypesProperty = new ReflectionProperty($authorizationServer, 'enabledGrantTypes');
    /** @var array<string, object> $enabledGrantTypes */
    $enabledGrantTypes = $enabledGrantTypesProperty->getValue($authorizationServer);

    foreach ($enabledGrantTypes as $grant) {
        if (! $grant instanceof AuthCodeGrant) {
            continue;
        }

        $authCodeTtlProperty = new ReflectionProperty(AuthCodeGrant::class, 'authCodeTTL');
        /** @var DateInterval $interval */
        $interval = $authCodeTtlProperty->getValue($grant);

        return CarbonInterval::instance($interval)->totalMinutes;
    }

    return null;
}

it('applies auth_code_ttl_minutes onto the live AuthCodeGrant', function (): void {
    config([
        'passport.private_key' => passportTestKeyContents('oauth-private.key'),
        'passport.public_key' => passportTestKeyContents('oauth-public.key'),
        'mcp-oauth.access_token_ttl_minutes' => '60',
        'mcp-oauth.refresh_token_ttl_days' => '30',
        'mcp-oauth.auth_code_ttl_minutes' => '5',
    ]);

    (new McpOAuthServiceProvider($this->app))->boot();
    $this->app->forgetInstance(AuthorizationServer::class);

    expect(authCodeTtlMinutesFromServer($this->app->make(AuthorizationServer::class)))->toBe(5.0);
});

it('retrofits auth_code_ttl when AuthorizationServer was already resolved', function (): void {
    config([
        'passport.private_key' => passportTestKeyContents('oauth-private.key'),
        'passport.public_key' => passportTestKeyContents('oauth-public.key'),
        'mcp-oauth.access_token_ttl_minutes' => '60',
        'mcp-oauth.refresh_token_ttl_days' => '30',
        'mcp-oauth.auth_code_ttl_minutes' => '5',
    ]);

    (new McpOAuthServiceProvider($this->app))->boot();
    $this->app->forgetInstance(AuthorizationServer::class);
    $authorizationServer = $this->app->make(AuthorizationServer::class);
    expect(authCodeTtlMinutesFromServer($authorizationServer))->toBe(5.0);

    config(['mcp-oauth.auth_code_ttl_minutes' => '3']);
    (new McpOAuthServiceProvider($this->app))->boot();

    expect(authCodeTtlMinutesFromServer($authorizationServer))->toBe(3.0);
});

it('disables ClientCredentialsGrant with OAuth on so Passport star scope cannot be issued', function (): void {
    // OAuth on needs every adapter bound (S81).
    app()->instance(ConsentProvider::class, new FakeConsentProvider(AuthorizeFlowTestCase::defaultConsentOptions()));
    config([
        // Grants are stripped only while OAuth is on.
        'mcp-oauth.enabled' => true,
        'passport.private_key' => passportTestKeyContents('oauth-private.key'),
        'passport.public_key' => passportTestKeyContents('oauth-public.key'),
    ]);

    (new McpOAuthServiceProvider($this->app))->boot();
    $this->app->forgetInstance(AuthorizationServer::class);

    $enabledGrantTypesProperty = new ReflectionProperty(
        $this->app->make(AuthorizationServer::class),
        'enabledGrantTypes',
    );
    /** @var array<string, object> $enabledGrantTypes */
    $enabledGrantTypes = $enabledGrantTypesProperty->getValue($this->app->make(AuthorizationServer::class));
    $grantClasses = array_map(
        static fn (object $grant): string => $grant::class,
        $enabledGrantTypes,
    );

    expect($grantClasses)->not->toContain(ClientCredentialsGrant::class)
        ->and($grantClasses)->toContain(AuthCodeGrant::class)
        ->and($grantClasses)->toContain(RefreshTokenGrant::class)
        ->and(array_keys($enabledGrantTypes))->not->toContain('client_credentials');
});

it('keeps only the MCP grants on the server, and personal access on its own, whatever Passport enables', function (): void {
    // OAuth on needs every adapter bound (S81).
    app()->instance(ConsentProvider::class, new FakeConsentProvider(AuthorizeFlowTestCase::defaultConsentOptions()));
    config([
        // Grants are stripped only while OAuth is on.
        'mcp-oauth.enabled' => true,
        'passport.private_key' => passportTestKeyContents('oauth-private.key'),
        'passport.public_key' => passportTestKeyContents('oauth-public.key'),
    ]);
    Passport::enablePasswordGrant();
    Passport::enableImplicitGrant();

    try {
        (new McpOAuthServiceProvider($this->app))->boot();
        $this->app->forgetInstance(AuthorizationServer::class);
        $authorizationServer = $this->app->make(AuthorizationServer::class);
        $enabledGrantTypes = (new ReflectionProperty($authorizationServer, 'enabledGrantTypes'))->getValue($authorizationServer);
        // The product's createToken() runs on Passport's own personal access server.
        $personalAccessServer = (new ReflectionProperty(PersonalAccessTokenFactory::class, 'server'))
            ->getValue($this->app->make(PersonalAccessTokenFactory::class));
        $personalAccessGrantTypes = (new ReflectionProperty($personalAccessServer, 'enabledGrantTypes'))->getValue($personalAccessServer);
    } finally {
        Passport::$passwordGrantEnabled = false;
        Passport::$implicitGrantEnabled = false;
    }

    expect(array_keys($enabledGrantTypes))->toEqualCanonicalizing(['authorization_code', 'refresh_token'])
        ->and(array_keys($personalAccessGrantTypes))->toContain('personal_access')
        ->and(array_keys($personalAccessGrantTypes))->not->toContain('password');
});

it('leaves the product\'s Passport grants alone while OAuth is off', function (): void {
    config([
        'mcp-oauth.enabled' => false,
        'passport.private_key' => passportTestKeyContents('oauth-private.key'),
        'passport.public_key' => passportTestKeyContents('oauth-public.key'),
    ]);
    Passport::enablePasswordGrant();

    try {
        (new McpOAuthServiceProvider($this->app))->boot();
        $this->app->forgetInstance(AuthorizationServer::class);
        $authorizationServer = $this->app->make(AuthorizationServer::class);
        $enabledGrantTypes = (new ReflectionProperty($authorizationServer, 'enabledGrantTypes'))->getValue($authorizationServer);
    } finally {
        Passport::$passwordGrantEnabled = false;
    }

    expect(array_keys($enabledGrantTypes))->toContain('password')
        ->and(array_keys($enabledGrantTypes))->toContain('client_credentials');
});
