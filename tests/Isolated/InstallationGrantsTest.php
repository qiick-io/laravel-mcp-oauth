<?php

declare(strict_types=1);

use Qiick\McpOAuth\McpOAuthRoutes;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;

uses(AuthorizeFlowTestCase::class);

const FIRST_INSTALLATION = 'edb06dcc-75b5-4af4-b08e-25393e025fa2';
const FIRST_INSTALLATION_THUMBPRINT = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2ai4EcM';

it('refuses installation inputs from clients without trusted enrollment', function (array $installationParameters): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();

    $this->get($this->authorizeUrl($this->createClient(), $installationParameters))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_request')->assertHeaderMissing('Location');
})->with([
    'install identifier only' => [['install_id' => FIRST_INSTALLATION]],
    'thumbprint only' => [['companion_jkt' => FIRST_INSTALLATION_THUMBPRINT]],
    'both values' => [['install_id' => FIRST_INSTALLATION, 'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT]],
]);

it('requires an installation id and a correctly encoded key thumbprint for flagged clients', function (array $installationParameters): void {
    $this->enableOAuth();
    McpOAuthRoutes::register();
    $client = $this->createClient();
    OAuthClientMetadata::query()->where('client_id', $client->getKey())->update([
        'registration_source' => 'companion',
        'has_per_install_grants' => true,
    ]);

    $this->get($this->authorizeUrl($client, $installationParameters))
        ->assertBadRequest()->assertJsonPath('error', 'invalid_request')->assertHeaderMissing('Location');
})->with([
    'neither field' => [[]],
    'missing thumbprint' => [['install_id' => FIRST_INSTALLATION]],
    'invalid UUID' => [['install_id' => 'install-one', 'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT]],
    'padded thumbprint' => [['install_id' => FIRST_INSTALLATION, 'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT.'=']],
    'array' => [['install_id' => [FIRST_INSTALLATION], 'companion_jkt' => FIRST_INSTALLATION_THUMBPRINT]],
]);
