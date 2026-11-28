<?php

declare(strict_types=1);

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Promise\Utils;
use GuzzleHttp\Psr7\Request as HttpRequest;
use Psr\Http\Message\ResponseInterface;
use Qiick\McpOAuth\Tests\Http\Server\HttpFlowServiceProvider;
use Qiick\McpOAuth\Tests\Support\AuthorizeFlowTestCase;
use Symfony\Component\Process\Process;

/**
 * Design §11.1 and §11.2 over real HTTP: two `php -S` processes serve the
 * test product app (tests/Http/Server) from one database on the suite's
 * engine, and Guzzle drives them. No test kernel, no mocked PSR request: what
 * a real MCP client sees. Both servers answer for the first one's origin
 * (APP_URL), so S57 can send its two refreshes to two processes.
 *
 * Two single-process servers rather than PHP_CLI_SERVER_WORKERS: its forked
 * workers outlive Process::stop() and keep the test's output pipe open.
 */
uses()->group('http');

const HTTP_FLOW_REDIRECT_URI = 'http://127.0.0.1:9/callback';

/** @var array{processes: list<Process>, baseUrl: string, secondBaseUrl: string, storage: string, environment: array<string, string>}|null $httpFlowServer */
$httpFlowServer = null;

beforeAll(function () use (&$httpFlowServer): void {
    $storage = sys_get_temp_dir().'/mcp-oauth-http-'.bin2hex(random_bytes(6));
    mkdir($storage.'/cache', 0700, true);
    // Laravel's SQLite connector never creates the file; other engines ignore it.
    touch($storage.'/database.sqlite');
    writeHttpFlowPassportKeys($storage);

    $port = freeLocalPort();
    $baseUrl = "http://127.0.0.1:{$port}";
    $environment = ['MCP_HTTP_APP_URL' => $baseUrl, 'MCP_HTTP_STORAGE' => $storage];

    (new Process([PHP_BINARY, 'tests/Http/Server/prepare.php'], dirname(__DIR__, 2), $environment))->mustRun();

    // The second port is probed only once the first is taken.
    $firstServer = startHttpFlowServer($port, $environment);
    $secondPort = freeLocalPort();

    $httpFlowServer = [
        'processes' => [$firstServer, startHttpFlowServer($secondPort, $environment)],
        'baseUrl' => $baseUrl,
        'secondBaseUrl' => "http://127.0.0.1:{$secondPort}",
        'storage' => $storage,
        'environment' => $environment,
    ];
});

afterAll(function () use (&$httpFlowServer): void {
    foreach ($httpFlowServer['processes'] as $process) {
        $process->stop();
    }

    (new Process(['rm', '-rf', $httpFlowServer['storage']]))->run();
});

function freeLocalPort(): int
{
    $probe = stream_socket_server('tcp://127.0.0.1:0');
    assert($probe !== false);
    $port = (int) substr((string) stream_socket_get_name($probe, false), strlen('127.0.0.1:'));
    fclose($probe);

    return $port;
}

/**
 * @param  array<string, string>  $environment
 */
function startHttpFlowServer(int $port, array $environment): Process
{
    $process = new Process([PHP_BINARY, '-S', "127.0.0.1:{$port}", 'tests/Http/Server/index.php'], dirname(__DIR__, 2), $environment);
    $process->setTimeout(null);
    $process->start();
    $deadline = microtime(true) + 10;

    while (@fsockopen('127.0.0.1', $port) === false) {
        if (microtime(true) > $deadline || ! $process->isRunning()) {
            throw new RuntimeException('php -S did not start: '.$process->getErrorOutput());
        }

        usleep(50_000);
    }

    return $process;
}

function writeHttpFlowPassportKeys(string $storage): void
{
    $privateKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    assert($privateKey !== false);
    openssl_pkey_export($privateKey, $privatePem);
    $keyDetails = openssl_pkey_get_details($privateKey);
    assert(is_array($keyDetails) && is_string($privatePem));

    foreach (['oauth-private.key' => $privatePem, 'oauth-public.key' => (string) $keyDetails['key']] as $fileName => $pem) {
        file_put_contents("{$storage}/{$fileName}", $pem);
        chmod("{$storage}/{$fileName}", 0600);
    }
}

function httpFlowClient(string $baseUrl, ?CookieJar $cookieJar = null): HttpClient
{
    return new HttpClient([
        'base_uri' => $baseUrl,
        'http_errors' => false,
        'allow_redirects' => false,
        'cookies' => $cookieJar ?? new CookieJar,
        'timeout' => 20,
    ]);
}

/**
 * @return array<string, mixed>
 */
function jsonOf(ResponseInterface $response): array
{
    /** @var array<string, mixed> $decoded */
    $decoded = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);

    return $decoded;
}

function registerHttpFlowClient(HttpClient $client, string $redirectUri = HTTP_FLOW_REDIRECT_URI): string
{
    $registration = $client->post('/oauth/register', ['json' => ['client_name' => 'Real client', 'redirect_uris' => [$redirectUri]]]);

    expect($registration->getStatusCode())->toBe(201);

    return (string) jsonOf($registration)['client_id'];
}

/**
 * @param  list<string>  $additionalResources  Further resource indicators sent as separate query fields.
 */
function httpFlowAuthorizeUrl(string $baseUrl, string $clientId, string $redirectUri, array $additionalResources = [], string $scope = 'mcp:use'): string
{
    $authorizeUrl = '/oauth/authorize?'.http_build_query([
        'response_type' => 'code',
        'client_id' => $clientId,
        'redirect_uri' => $redirectUri,
        'state' => 'state-1234',
        'scope' => $scope,
        'code_challenge' => AuthorizeFlowTestCase::CODE_CHALLENGE,
        'code_challenge_method' => 'S256',
        'resource' => "{$baseUrl}/mcp",
    ]);

    foreach ($additionalResources as $resource) {
        $authorizeUrl .= '&resource='.rawurlencode($resource);
    }

    return $authorizeUrl;
}

/**
 * Authorize → login → consent → approve → token, as a browser and an MCP
 * client do it.
 *
 * @param  list<string>  $additionalResources
 * @return array{access_token: string, refresh_token: string, client_id: string, scope: string}
 */
function obtainHttpFlowTokens(string $baseUrl, string $redirectUri = HTTP_FLOW_REDIRECT_URI, ?string $clientId = null, array $additionalResources = []): array
{
    $client = httpFlowClient($baseUrl);
    $clientId ??= registerHttpFlowClient($client, $redirectUri);
    $authorizeUrl = httpFlowAuthorizeUrl($baseUrl, $clientId, $redirectUri, $additionalResources);
    $displayedResources = $additionalResources === [] ? [] : ["{$baseUrl}/mcp", ...$additionalResources];
    $approval = $client->post('/oauth/authorize', ['form_params' => prepareHttpFlowConsent($client, $authorizeUrl, $displayedResources)]);
    parse_str((string) parse_url($approval->getHeaderLine('Location'), PHP_URL_QUERY), $redirectParameters);

    expect($approval->getStatusCode())->toBe(302)
        ->and($redirectParameters)->toHaveKey('code')
        ->and($redirectParameters['iss'] ?? null)->toBe($baseUrl);

    $tokenResponse = httpFlowClient($baseUrl)->post('/oauth/token', ['form_params' => [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'redirect_uri' => $redirectUri,
        'code' => $redirectParameters['code'],
        'code_verifier' => AuthorizeFlowTestCase::CODE_VERIFIER,
        'resource' => "{$baseUrl}/mcp",
    ]]);

    expect($tokenResponse->getStatusCode())->toBe(200);

    /** @var array{access_token: string, refresh_token: string, scope: string} $tokenPair */
    $tokenPair = jsonOf($tokenResponse);

    return [...$tokenPair, 'client_id' => $clientId];
}

/**
 * @param  list<string>  $displayedResources
 * @return array{_token: string, auth_token: string, scopes: list<string>, role: string, resources: list<string>}
 */
function prepareHttpFlowConsent(HttpClient $client, string $authorizeUrl, array $displayedResources = []): array
{
    expect($client->get($authorizeUrl)->getHeaderLine('Location'))->toEndWith('/login');

    $loginCsrfToken = preg_replace('/^.*name="_token" value="([^"]+)".*$/s', '$1', (string) $client->get('/login')->getBody());
    $login = $client->post('/login', ['form_params' => ['_token' => $loginCsrfToken, 'user_id' => 1]]);

    $consentResponse = $client->get($login->getHeaderLine('Location'));
    expect($consentResponse->getStatusCode())->toBe(200);
    $consentPage = (string) $consentResponse->getBody();
    preg_match('/name="_token" value="([^"]+)".*name="auth_token" value="([^"]+)"/s', $consentPage, $tokens);

    expect($tokens)->toHaveCount(3);

    foreach ($displayedResources as $resource) {
        expect($consentPage)->toContain($resource);
    }

    return [
        '_token' => $tokens[1],
        'auth_token' => $tokens[2],
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ];
}

function listMcpTools(string $baseUrl, string $accessToken): ResponseInterface
{
    return httpFlowClient($baseUrl)->post('/mcp', [
        'headers' => ['Authorization' => "Bearer {$accessToken}", 'Accept' => 'application/json, text/event-stream'],
        'json' => ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'],
    ]);
}

function refreshHttpFlowTokens(HttpClient $client, string $baseUrl, string $clientId, string $refreshToken, ?string $resource = null): ResponseInterface
{
    return $client->post('/oauth/token', ['form_params' => [
        'grant_type' => 'refresh_token',
        'client_id' => $clientId,
        'refresh_token' => $refreshToken,
        'resource' => $resource ?? "{$baseUrl}/mcp",
    ]]);
}

it('builds the metadata from APP_URL under a hostile Host (step 1)', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    $metadata = httpFlowClient($baseUrl)->get('/.well-known/oauth-authorization-server', ['headers' => ['Host' => 'evil.example']]);
    $resourceMetadata = httpFlowClient($baseUrl)->get('/.well-known/oauth-protected-resource/mcp', ['headers' => ['Host' => 'evil.example']]);

    expect(jsonOf($metadata)['issuer'])->toBe($baseUrl)
        ->and(jsonOf($metadata)['token_endpoint'])->toBe("{$baseUrl}/oauth/token")
        ->and(jsonOf($resourceMetadata)['resource'])->toBe("{$baseUrl}/mcp");
});

it('registers loopback clients and refuses a public http redirect (step 2)', function () use (&$httpFlowServer): void {
    $client = httpFlowClient($httpFlowServer['baseUrl']);
    $register = static fn (string $redirectUri): ResponseInterface => $client->post('/oauth/register', ['json' => ['client_name' => 'Real client', 'redirect_uris' => [$redirectUri]]]);

    expect($register('http://127.0.0.1:9/callback')->getStatusCode())->toBe(201)
        ->and($register('http://[::1]:9/callback')->getStatusCode())->toBe(201)
        ->and($register('http://evil.example/callback')->getStatusCode())->toBe(400);
});

it('runs consent, code, token and tools/list end to end (step 3)', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    ['access_token' => $accessToken] = obtainHttpFlowTokens($baseUrl);

    $toolsList = listMcpTools($baseUrl, $accessToken);

    expect($toolsList->getStatusCode())->toBe(200)
        ->and((string) $toolsList->getBody())->toContain('list-news-tool');

    $unauthenticated = httpFlowClient($baseUrl)->post('/mcp', ['json' => ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list']]);

    expect($unauthenticated->getStatusCode())->toBe(401)
        ->and($unauthenticated->getHeaderLine('WWW-Authenticate'))->toContain("resource_metadata=\"{$baseUrl}/.well-known/oauth-protected-resource/mcp\"");
});

it('rotates a refresh token, then revokes the family on reuse (step 4)', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    $issued = obtainHttpFlowTokens($baseUrl);
    $client = httpFlowClient($baseUrl);

    $rotation = refreshHttpFlowTokens($client, $baseUrl, $issued['client_id'], $issued['refresh_token']);

    expect($rotation->getStatusCode())->toBe(200);

    $rotatedAccessToken = (string) jsonOf($rotation)['access_token'];

    expect(listMcpTools($baseUrl, $rotatedAccessToken)->getStatusCode())->toBe(200);

    $reuse = refreshHttpFlowTokens($client, $baseUrl, $issued['client_id'], $issued['refresh_token']);

    expect($reuse->getStatusCode())->toBe(400)
        ->and(jsonOf($reuse)['error'])->toBe('invalid_grant')
        ->and(listMcpTools($baseUrl, $rotatedAccessToken)->getStatusCode())->toBe(401);
});

it('S57: two parallel refreshes with one token yield at most one usable pair, then nothing works', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    $issued = obtainHttpFlowTokens($baseUrl);
    $refresh = ['form_params' => ['grant_type' => 'refresh_token', 'client_id' => $issued['client_id'], 'refresh_token' => $issued['refresh_token'], 'resource' => "{$baseUrl}/mcp"]];

    // One request per server process, both in flight together (curl_multi).
    $responses = Utils::unwrap([
        httpFlowClient($baseUrl)->postAsync('/oauth/token', $refresh),
        httpFlowClient($httpFlowServer['secondBaseUrl'])->postAsync('/oauth/token', $refresh),
    ]);
    $issuedAccessTokens = [$issued['access_token']];

    foreach ($responses as $response) {
        expect($response->getStatusCode())->toBeIn([200, 400]);

        if ($response->getStatusCode() === 200) {
            $issuedAccessTokens[] = (string) jsonOf($response)['access_token'];
        }
    }

    // At most one winner; the loser's reuse revoked the grant and the
    // whole family, the winner's fresh pair included.
    expect(count($issuedAccessTokens))->toBeLessThanOrEqual(2);

    foreach ($issuedAccessTokens as $accessToken) {
        expect(listMcpTools($baseUrl, $accessToken)->getStatusCode())->toBe(401);
    }
});

/**
 * Runs `$scenario` with the given state flags set on the running servers
 * (HttpFlowServiceProvider), and always clears them.
 *
 * @param  list<string>  $flags
 */
function withHttpFlowFlags(string $storage, array $flags, Closure $scenario): void
{
    foreach ($flags as $flag) {
        touch("{$storage}/{$flag}");
    }

    try {
        $scenario();
    } finally {
        foreach ($flags as $flag) {
            @unlink("{$storage}/{$flag}");
        }
    }
}

it('runs consent, token exchange, refresh and the bearer check using a CIMD URL over HTTP', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];

    withHttpFlowFlags($httpFlowServer['storage'], [HttpFlowServiceProvider::CIMD_ENABLED_FLAG], static function () use ($baseUrl): void {
        $client = httpFlowClient($baseUrl);
        $discovery = $client->get('/.well-known/oauth-authorization-server');
        expect($discovery->getStatusCode())->toBe(200);
        expect(jsonOf($discovery)['client_id_metadata_document_supported'])->toBeTrue();

        $tokens = obtainHttpFlowTokens($baseUrl, clientId: HttpFlowServiceProvider::CIMD_CLIENT_IDENTIFIER);
        $rotation = refreshHttpFlowTokens($client, $baseUrl, $tokens['client_id'], $tokens['refresh_token']);

        expect($rotation->getStatusCode())->toBe(200)
            ->and(listMcpTools($baseUrl, (string) jsonOf($rotation)['access_token'])->getStatusCode())->toBe(200);
    });
});

/**
 * @param  array{environment: array<string, string>}  $httpFlowServer
 */
function runHttpFlowCommand(array $httpFlowServer, string $action, string $subject): string
{
    return (new Process([PHP_BINARY, 'tests/Http/Server/command.php', $action, $subject], dirname(__DIR__, 2), $httpFlowServer['environment']))->mustRun()->getOutput();
}

function requestCompanion(HttpClient $client, string $accessToken): ResponseInterface
{
    return $client->get('/companion', ['headers' => ['Authorization' => "Bearer {$accessToken}"]]);
}

it('CMP3: consents to both resources and rotates only the selected audience', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    $resource = "{$baseUrl}/companion";

    withHttpFlowFlags($httpFlowServer['storage'], [HttpFlowServiceProvider::COMPANION_ENABLED_FLAG], function () use ($httpFlowServer, $baseUrl, $resource): void {
        $client = httpFlowClient($baseUrl);
        $clientId = registerHttpFlowClient($client);
        runHttpFlowCommand($httpFlowServer, 'classify-companion', $clientId);
        $mcp = obtainHttpFlowTokens($baseUrl, clientId: $clientId, additionalResources: [$resource]);

        $duplicateResource = $client->post('/oauth/token', [
            'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
            'body' => http_build_query([
                'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $mcp['refresh_token'], 'resource' => $resource,
            ]).'&resource='.rawurlencode("{$baseUrl}/mcp"),
        ]);
        expect($duplicateResource->getStatusCode())->toBe(400)
            ->and(jsonOf($duplicateResource)['error'])->toBe('invalid_target');

        $duplicateScope = $client->post('/oauth/token', [
            'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
            'body' => http_build_query([
                'grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $mcp['refresh_token'],
                'resource' => $resource, 'scope' => 'mcp:use',
            ]).'&scope=companion%3Adevice',
        ]);
        expect($duplicateScope->getStatusCode())->toBe(400)
            ->and(jsonOf($duplicateScope)['error'])->toBe('invalid_scope');

        $companion = refreshHttpFlowTokens($client, $baseUrl, $clientId, $mcp['refresh_token'], $resource);
        expect($companion->getStatusCode())->toBe(200);
        $companion = jsonOf($companion);
        expect($mcp['scope'])->toBe('mcp:use')
            ->and($companion['scope'])->toBe('companion:device')
            ->and(listMcpTools($baseUrl, $mcp['access_token'])->getStatusCode())->toBe(200)
            ->and(requestCompanion($client, $companion['access_token'])->getStatusCode())->toBe(200)
            ->and(listMcpTools($baseUrl, $companion['access_token'])->getStatusCode())->toBe(401)
            ->and(requestCompanion($client, $mcp['access_token'])->getStatusCode())->toBe(401);

        $rotatedMcp = refreshHttpFlowTokens($client, $baseUrl, $clientId, $companion['refresh_token']);
        expect($rotatedMcp->getStatusCode())->toBe(200)
            ->and(listMcpTools($baseUrl, $mcp['access_token'])->getStatusCode())->toBe(401)
            ->and(requestCompanion($client, $companion['access_token'])->getStatusCode())->toBe(200);

        withHttpFlowFlags($httpFlowServer['storage'], [HttpFlowServiceProvider::GRANT_DENIED_FLAG], static function () use ($client, $baseUrl, $companion, $rotatedMcp): void {
            expect(requestCompanion($client, $companion['access_token'])->getStatusCode())->toBe(403)
                ->and(listMcpTools($baseUrl, jsonOf($rotatedMcp)['access_token'])->getStatusCode())->toBe(403);
        });

        expect(refreshHttpFlowTokens($client, $baseUrl, $clientId, $mcp['refresh_token'], $resource)->getStatusCode())->toBe(400)
            ->and(requestCompanion($client, $companion['access_token'])->getStatusCode())->toBe(401)
            ->and(listMcpTools($baseUrl, jsonOf($rotatedMcp)['access_token'])->getStatusCode())->toBe(401);
    });
});

it('CMP4: refuses the restricted resource to DCR and fetched CIMD clients, API keys and a web session', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    $resource = "{$baseUrl}/companion";

    withHttpFlowFlags($httpFlowServer['storage'], [HttpFlowServiceProvider::COMPANION_ENABLED_FLAG, HttpFlowServiceProvider::CIMD_ENABLED_FLAG], static function () use ($baseUrl, $resource): void {
        $client = httpFlowClient($baseUrl);

        foreach ([registerHttpFlowClient($client), HttpFlowServiceProvider::CIMD_CLIENT_IDENTIFIER] as $clientId) {
            $authorize = $client->get(httpFlowAuthorizeUrl($baseUrl, $clientId, HTTP_FLOW_REDIRECT_URI, [$resource]));
            $scope = $client->get(httpFlowAuthorizeUrl($baseUrl, $clientId, HTTP_FLOW_REDIRECT_URI, scope: 'companion:device'));
            $token = refreshHttpFlowTokens($client, $baseUrl, $clientId, 'unused', $resource);
            expect($authorize->getStatusCode())->toBe(400)
                ->and(jsonOf($authorize)['error'])->toBe('invalid_target')
                ->and($scope->getStatusCode())->toBe(400)
                ->and(jsonOf($scope)['error'])->toBe('invalid_scope')
                ->and($token->getStatusCode())->toBe(400)
                ->and(jsonOf($token)['error'])->toBe('invalid_target');
        }

        $metadataClientTokens = obtainHttpFlowTokens($baseUrl, clientId: HttpFlowServiceProvider::CIMD_CLIENT_IDENTIFIER);
        expect($metadataClientTokens['scope'])->toBe('mcp:use')
            ->and(listMcpTools($baseUrl, $metadataClientTokens['access_token'])->getStatusCode())->toBe(200)
            ->and(requestCompanion($client, $metadataClientTokens['access_token'])->getStatusCode())->toBe(401);

        $loginCsrfToken = preg_replace('/^.*name="_token" value="([^"]+)".*$/s', '$1', (string) $client->get('/login')->getBody());
        expect($client->post('/login', ['form_params' => ['_token' => $loginCsrfToken, 'user_id' => 1]])->getStatusCode())->toBe(302)
            ->and($client->get('/companion')->getStatusCode())->toBe(401)
            ->and(requestCompanion($client, 'ak_valid')->getStatusCode())->toBe(401);
    });
});

it('CMP3: races one refresh on two database connections across both audiences', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    $storage = $httpFlowServer['storage'];
    $flags = [HttpFlowServiceProvider::COMPANION_ENABLED_FLAG, HttpFlowServiceProvider::REFRESH_RACE_FLAG];

    withHttpFlowFlags($storage, $flags, static function () use ($httpFlowServer, $baseUrl, $storage): void {
        $client = httpFlowClient($baseUrl);
        $clientId = registerHttpFlowClient($client);
        runHttpFlowCommand($httpFlowServer, 'classify-companion', $clientId);
        $mcp = obtainHttpFlowTokens($baseUrl, clientId: $clientId, additionalResources: ["{$baseUrl}/companion"]);
        $refresh = ['grant_type' => 'refresh_token', 'client_id' => $clientId, 'refresh_token' => $mcp['refresh_token']];

        // One curl_multi handler drives both requests. Each server has its own database connection.
        $responses = Utils::unwrap([
            $client->postAsync('/oauth/token', [
                'headers' => ['X-Refresh-Race' => 'mcp'],
                'form_params' => [...$refresh, 'resource' => "{$baseUrl}/mcp"],
            ]),
            $client->postAsync($httpFlowServer['secondBaseUrl'].'/oauth/token', [
                'headers' => ['X-Refresh-Race' => 'companion'],
                'form_params' => [...$refresh, 'resource' => "{$baseUrl}/companion"],
            ]),
        ]);
        expect(is_file($storage.'/refresh-arrived-mcp'))->toBeTrue()
            ->and(is_file($storage.'/refresh-arrived-companion'))->toBeTrue();
        $issued = [];

        foreach ($responses as $response) {
            expect($response->getStatusCode())->toBeIn([200, 400]);
            $result = jsonOf($response);

            if ($response->getStatusCode() === 200) {
                $issued[] = $result;
            } else {
                expect($result['error'])->toBe('invalid_grant');
            }
        }

        expect(count($issued))->toBeLessThanOrEqual(1)
            ->and(listMcpTools($baseUrl, $mcp['access_token'])->getStatusCode())->toBe(401);

        foreach ($issued as $result) {
            expect(listMcpTools($baseUrl, $result['access_token'])->getStatusCode())->toBe(401)
                ->and(requestCompanion($client, $result['access_token'])->getStatusCode())->toBe(401)
                ->and(refreshHttpFlowTokens($client, $baseUrl, $clientId, $result['refresh_token'])->getStatusCode())->toBe(400);
        }
    });
});

it('races two installation approvals on independent database connections', function (string $secondInstallId, int $expectedActive) use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    $storage = $httpFlowServer['storage'];
    $transport = httpFlowClient($baseUrl);
    $clientId = registerHttpFlowClient($transport);
    runHttpFlowCommand($httpFlowServer, 'classify-installation', $clientId);
    $flags = [HttpFlowServiceProvider::COMPANION_ENABLED_FLAG, HttpFlowServiceProvider::CONSENT_RACE_FLAG];

    withHttpFlowFlags($storage, $flags, static function () use ($httpFlowServer, $baseUrl, $storage, $transport, $clientId, $secondInstallId, $expectedActive): void {
        $companionResource = "{$baseUrl}/companion";
        $targets = [
            'first' => ['installId' => 'edb06dcc-75b5-4af4-b08e-25393e025fa2', 'origin' => $baseUrl],
            'second' => ['installId' => $secondInstallId, 'origin' => $httpFlowServer['secondBaseUrl']],
        ];
        $forms = [];

        foreach ($targets as $participant => $target) {
            $marker = $storage.'/consent-arrived-'.$participant;

            if (is_file($marker)) {
                unlink($marker);
            }

            $cookieJar = new CookieJar;
            $browser = httpFlowClient($baseUrl, $cookieJar);
            $authorizeUrl = httpFlowAuthorizeUrl($baseUrl, $clientId, HTTP_FLOW_REDIRECT_URI, [$companionResource]).'&'.http_build_query([
                'install_id' => $target['installId'],
                'companion_jkt' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2ai4EcM',
            ]);
            $approvalUrl = $target['origin'].'/oauth/authorize';
            $consentForm = prepareHttpFlowConsent($browser, $authorizeUrl, ["{$baseUrl}/mcp", $companionResource]);
            $cookieHeader = $cookieJar->withCookieHeader(new HttpRequest('POST', $approvalUrl))->getHeaderLine('Cookie');
            $forms[] = [$approvalUrl, [
                'cookies' => false,
                'headers' => ['Cookie' => $cookieHeader, 'X-Consent-Race' => $participant],
                'form_params' => $consentForm,
            ]];
        }

        // A single curl_multi handler sends both independent browser sessions together.
        $approvals = Utils::unwrap(array_map(
            static fn (array $form) => $transport->postAsync($form[0], $form[1]),
            $forms,
        ));
        expect(is_file($storage.'/consent-arrived-first'))->toBeTrue()
            ->and(is_file($storage.'/consent-arrived-second'))->toBeTrue()
            ->and(trim(runHttpFlowCommand($httpFlowServer, 'count-active-installations', $clientId)))->toBe((string) $expectedActive);
        $successfulExchanges = 0;

        foreach ($approvals as $approval) {
            expect($approval->getStatusCode())->toBe(302);
            parse_str((string) parse_url($approval->getHeaderLine('Location'), PHP_URL_QUERY), $redirect);
            expect($redirect)->toHaveKey('code');
            $exchange = $transport->post('/oauth/token', ['form_params' => [
                'grant_type' => 'authorization_code',
                'client_id' => $clientId,
                'redirect_uri' => HTTP_FLOW_REDIRECT_URI,
                'code' => $redirect['code'],
                'code_verifier' => AuthorizeFlowTestCase::CODE_VERIFIER,
                'resource' => "{$baseUrl}/mcp",
            ]]);

            if ($exchange->getStatusCode() === 200) {
                $mcpTokens = jsonOf($exchange);
                $companion = refreshHttpFlowTokens($transport, $baseUrl, $clientId, $mcpTokens['refresh_token'], $companionResource);
                expect($companion->getStatusCode())->toBe(200)
                    ->and(requestCompanion($transport, jsonOf($companion)['access_token'])->getStatusCode())->toBe(200)
                    ->and(listMcpTools($baseUrl, $mcpTokens['access_token'])->getStatusCode())->toBe(200);
                $successfulExchanges++;
            } else {
                expect($exchange->getStatusCode())->toBe(400)
                    ->and(jsonOf($exchange)['error'])->toBe('invalid_grant');
            }
        }

        expect($successfulExchanges)->toBe($expectedActive);
    });
})->with([
    'different installations' => ['f3add97d-af1e-4169-b778-65ad96ba090f', 2],
    'the same installation' => ['edb06dcc-75b5-4af4-b08e-25393e025fa2', 1],
]);

it('refuses an existing token once its redirect host is blocked (step 5)', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    ['access_token' => $accessToken] = obtainHttpFlowTokens($baseUrl);

    expect(listMcpTools($baseUrl, $accessToken)->getStatusCode())->toBe(200);

    runHttpFlowCommand($httpFlowServer, 'block-host', '127.0.0.1');

    try {
        $refused = listMcpTools($baseUrl, $accessToken);

        expect($refused->getStatusCode())->toBe(401)
            ->and($refused->getHeaderLine('WWW-Authenticate'))->toContain('error="invalid_token"');
    } finally {
        runHttpFlowCommand($httpFlowServer, 'unblock-host', '127.0.0.1');
    }
});

it('switched off by the admin or by config, answers 404 on OAuth and keeps API keys (step 6)', function (string $flag) use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];

    withHttpFlowFlags($httpFlowServer['storage'], [$flag], static function () use ($baseUrl): void {
        $client = httpFlowClient($baseUrl);

        expect($client->get('/.well-known/oauth-authorization-server')->getStatusCode())->toBe(404)
            ->and($client->get('/.well-known/oauth-protected-resource/mcp')->getStatusCode())->toBe(404)
            ->and($client->post('/oauth/register', ['json' => ['redirect_uris' => [HTTP_FLOW_REDIRECT_URI]]])->getStatusCode())->toBe(404)
            ->and($client->post('/oauth/token', ['form_params' => ['grant_type' => 'refresh_token']])->getStatusCode())->toBe(404)
            ->and(listMcpTools($baseUrl, 'ak_valid')->getStatusCode())->toBe(200);
    });
})->with([
    'the admin switch' => [HttpFlowServiceProvider::ADMIN_SWITCH_OFF_FLAG],
    'the config gate' => [HttpFlowServiceProvider::CONFIG_OFF_FLAG],
]);

it('with the Passport keys missing, answers 503 to OAuth and keeps API keys (step 7)', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    ['access_token' => $accessToken] = obtainHttpFlowTokens($baseUrl);

    withHttpFlowFlags($httpFlowServer['storage'], [HttpFlowServiceProvider::KEYS_MISSING_FLAG], static function () use ($baseUrl, $accessToken): void {
        $client = httpFlowClient($baseUrl);
        $registration = $client->post('/oauth/register', ['json' => ['redirect_uris' => [HTTP_FLOW_REDIRECT_URI]]]);
        $oauthCall = listMcpTools($baseUrl, $accessToken);

        expect($registration->getStatusCode())->toBe(503)
            ->and(jsonOf($registration)['error'])->toBe('temporarily_unavailable')
            ->and($client->post('/oauth/token', ['form_params' => ['grant_type' => 'refresh_token']])->getStatusCode())->toBe(503)
            ->and($oauthCall->getStatusCode())->toBe(503)
            ->and(jsonOf($oauthCall)['error'])->toBe('temporarily_unavailable')
            ->and(listMcpTools($baseUrl, 'ak_valid')->getStatusCode())->toBe(200);
    });

    // Keys back: the same token works again.
    expect(listMcpTools($baseUrl, $accessToken)->getStatusCode())->toBe(200);
});

it('runs the whole flow to tools/list with an IPv6 loopback callback (S24)', function () use (&$httpFlowServer): void {
    $baseUrl = $httpFlowServer['baseUrl'];
    ['access_token' => $accessToken] = obtainHttpFlowTokens($baseUrl, 'http://[::1]:9/callback');

    $toolsList = listMcpTools($baseUrl, $accessToken);

    expect($toolsList->getStatusCode())->toBe(200)
        ->and((string) $toolsList->getBody())->toContain('list-news-tool');
});
