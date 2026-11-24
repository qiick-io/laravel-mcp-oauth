<?php

declare(strict_types=1);

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Promise\Utils;
use Psr\Http\Message\ResponseInterface;
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

/** @var array{processes: list<Process>, baseUrl: string, secondBaseUrl: string, storage: string}|null $httpFlowServer */
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

function httpFlowClient(string $baseUrl): HttpClient
{
    return new HttpClient([
        'base_uri' => $baseUrl,
        'http_errors' => false,
        'allow_redirects' => false,
        'cookies' => new CookieJar,
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

function registerHttpFlowClient(HttpClient $client): string
{
    $registration = $client->post('/oauth/register', ['json' => ['client_name' => 'Real client', 'redirect_uris' => [HTTP_FLOW_REDIRECT_URI]]]);

    expect($registration->getStatusCode())->toBe(201);

    return (string) jsonOf($registration)['client_id'];
}

/**
 * Authorize → login → consent → approve → token, as a browser and an MCP
 * client do it.
 *
 * @return array{access_token: string, refresh_token: string, client_id: string}
 */
function obtainHttpFlowTokens(string $baseUrl): array
{
    $client = httpFlowClient($baseUrl);
    $clientId = registerHttpFlowClient($client);
    $authorizeUrl = '/oauth/authorize?'.http_build_query([
        'response_type' => 'code',
        'client_id' => $clientId,
        'redirect_uri' => HTTP_FLOW_REDIRECT_URI,
        'state' => 'state-1234',
        'scope' => 'mcp:use',
        'code_challenge' => AuthorizeFlowTestCase::CODE_CHALLENGE,
        'code_challenge_method' => 'S256',
        'resource' => "{$baseUrl}/mcp",
    ]);

    expect($client->get($authorizeUrl)->getHeaderLine('Location'))->toEndWith('/login');

    $loginCsrfToken = preg_replace('/^.*name="_token" value="([^"]+)".*$/s', '$1', (string) $client->get('/login')->getBody());
    $client->post('/login', ['form_params' => ['_token' => $loginCsrfToken, 'user_id' => 1]]);

    $consentPage = (string) $client->get($authorizeUrl)->getBody();
    preg_match('/name="_token" value="([^"]+)".*name="auth_token" value="([^"]+)"/s', $consentPage, $tokens);

    expect($tokens)->toHaveCount(3);

    $approval = $client->post('/oauth/authorize', ['form_params' => [
        '_token' => $tokens[1],
        'auth_token' => $tokens[2],
        'scopes' => ['mcp:read'],
        'role' => 'editor',
        'resources' => ['news'],
    ]]);
    parse_str((string) parse_url($approval->getHeaderLine('Location'), PHP_URL_QUERY), $redirectParameters);

    expect($approval->getStatusCode())->toBe(302)
        ->and($redirectParameters)->toHaveKey('code')
        ->and($redirectParameters['iss'] ?? null)->toBe($baseUrl);

    $tokenResponse = httpFlowClient($baseUrl)->post('/oauth/token', ['form_params' => [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'redirect_uri' => HTTP_FLOW_REDIRECT_URI,
        'code' => $redirectParameters['code'],
        'code_verifier' => AuthorizeFlowTestCase::CODE_VERIFIER,
        'resource' => "{$baseUrl}/mcp",
    ]]);

    expect($tokenResponse->getStatusCode())->toBe(200);

    /** @var array{access_token: string, refresh_token: string} $tokenPair */
    $tokenPair = jsonOf($tokenResponse);

    return [...$tokenPair, 'client_id' => $clientId];
}

function listMcpTools(string $baseUrl, string $accessToken): ResponseInterface
{
    return httpFlowClient($baseUrl)->post('/mcp', [
        'headers' => ['Authorization' => "Bearer {$accessToken}", 'Accept' => 'application/json, text/event-stream'],
        'json' => ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'],
    ]);
}

function refreshHttpFlowTokens(HttpClient $client, string $baseUrl, string $clientId, string $refreshToken): ResponseInterface
{
    return $client->post('/oauth/token', ['form_params' => [
        'grant_type' => 'refresh_token',
        'client_id' => $clientId,
        'refresh_token' => $refreshToken,
        'resource' => "{$baseUrl}/mcp",
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
