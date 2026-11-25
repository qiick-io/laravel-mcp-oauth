<?php

declare(strict_types=1);

use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;
use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

/**
 * S79: access tokens, refresh tokens, authorization codes and the PKCE
 * verifier never reach a log line or a package event, through every path
 * that logs or dispatches: exchange, rotation, refresh reuse, code replay
 * and revocation.
 */
it('never writes token material to a log line or a package event (S79)', function (): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    /** @var list<string> $captured every log line and package event, as text */
    $captured = [];
    $packageEventCount = 0;
    Event::listen(MessageLogged::class, static function (MessageLogged $logged) use (&$captured): void {
        $captured[] = $logged->message.' '.json_encode($logged->context, JSON_UNESCAPED_SLASHES);
    });
    Event::listen('Qiick\McpOAuth\Events\*', static function (string $eventName, array $payload) use (&$captured, &$packageEventCount): void {
        $packageEventCount++;
        $captured[] = $eventName.' '.json_encode($payload, JSON_UNESCAPED_SLASHES);
    });
    $json = ['Accept' => 'application/json'];
    $client = $this->createClient();

    ['code' => $code] = $this->obtainAuthorizationCode($client);
    $issued = $this->withHeaders($json)->post('/oauth/token', $this->codeExchange($client, $code))->assertOk();
    $rotated = $this->withHeaders($json)->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => (string) $client->getKey(),
        'refresh_token' => $issued->json('refresh_token'),
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ])->assertOk();
    // Reuse of the rotated-away refresh token, then a replay of the code: both log a warning.
    $this->withHeaders($json)->post('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => (string) $client->getKey(),
        'refresh_token' => $issued->json('refresh_token'),
        'resource' => AuthorizeFlowTestCase::RESOURCE,
    ])->assertStatus(400);
    $this->withHeaders($json)->post('/oauth/token', $this->codeExchange($client, $code))->assertStatus(400);
    $this->withHeaders($json)->post('/oauth/revoke', ['client_id' => (string) $client->getKey(), 'token' => $rotated->json('access_token')])->assertOk();

    $secrets = array_filter([
        $code,
        AuthorizeFlowTestCase::CODE_VERIFIER,
        $issued->json('access_token'),
        $issued->json('refresh_token'),
        $rotated->json('access_token'),
        $rotated->json('refresh_token'),
    ]);

    // The paths above did log and dispatch: the sweep has something to look at.
    expect($captured)->not->toBe([])
        ->and($packageEventCount)->toBeGreaterThan(0)
        ->and($secrets)->toHaveCount(6);

    foreach ($captured as $capturedText) {
        foreach ($secrets as $secret) {
            expect(str_contains($capturedText, (string) $secret))->toBeFalse();
        }
    }
});
