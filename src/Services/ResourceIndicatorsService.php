<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use Qiick\McpOAuth\Data\GrantRecord;
use Qiick\McpOAuth\McpOAuthServer;
use Qiick\McpOAuth\Models\OAuthClientMetadata;

/**
 * Resolves RFC 8707 indicators against registered resources and the server's
 * client classification. Only the authorization request can select several.
 *
 * @internal
 */
final readonly class ResourceIndicatorsService
{
    public const string REQUEST_ATTRIBUTE = 'mcp_oauth_resource_scopes';

    public function __construct(private McpOAuthServer $server) {}

    /**
     * PHP collapses repeated query and form fields. Read the wire representation
     * before the request bag, which is sufficient for a synthesized request.
     *
     * @return list<string> Empty for absent or ambiguous indicators.
     */
    public function parse(string $encodedParameters, mixed $parsedResource): array
    {
        if ($encodedParameters === '') {
            return is_string($parsedResource) ? [$parsedResource] : [];
        }

        $indicators = [];

        foreach (explode('&', $encodedParameters) as $parameter) {
            [$encodedName, $encodedValue] = array_pad(explode('=', $parameter, 2), 2, '');
            $name = urldecode($encodedName);

            if ($name === 'resource') {
                $indicators[] = urldecode($encodedValue);
            } elseif (str_starts_with(ltrim($name, ' '), 'resource[') || ltrim($name, ' ') === 'resource') {
                return [];
            }
        }

        return $indicators;
    }

    /**
     * @param  list<string>  $indicators
     * @return array<string, string> Resource identifiers keyed to their single wire scopes.
     */
    public function resolve(array $indicators, string $clientId): array
    {
        $registered = $this->server->registeredResources();
        $clientClass = OAuthClientMetadata::query()->where('client_id', $clientId)->value('registration_source');
        $resourceScopes = [];

        foreach ($indicators as $identifier) {
            if ($this->server->acceptsResource($identifier)) {
                $resource = $this->server->resourceIdentifier();
                $scope = McpOAuthServer::WIRE_SCOPE;
            } else {
                $definition = $registered[$identifier] ?? null;

                if ($definition === null || ! in_array($clientClass, $definition->allowedClientClasses, true)) {
                    return [];
                }

                $resource = $definition->identifier;
                $scope = $definition->scope;
            }

            if (isset($resourceScopes[$resource])) {
                return [];
            }

            $resourceScopes[$resource] = $scope;
        }

        return $resourceScopes;
    }

    /**
     * @param  array<string, string>  $resourceScopes
     */
    public function allowsRequestedScope(mixed $requestedScope, array $resourceScopes): bool
    {
        if ($requestedScope === null) {
            return true;
        }

        if (! is_string($requestedScope)) {
            return false;
        }

        $isLegacyAudience = $resourceScopes === [$this->server->resourceIdentifier() => McpOAuthServer::WIRE_SCOPE];
        $supportedScopes = $this->server->scopeDescriptions();

        foreach (explode(' ', $requestedScope) as $scope) {
            // The legacy audience still ignores scopes it never advertised.
            if (! in_array($scope, $resourceScopes, true) && (! $isLegacyAudience || isset($supportedScopes[$scope]))) {
                return false;
            }
        }

        return true;
    }

    public function scopeInGrant(GrantRecord $grant, string $resource): ?string
    {
        if ($grant->resourceScopes === [] && $resource === $this->server->resourceIdentifier()) {
            return McpOAuthServer::WIRE_SCOPE;
        }

        return $grant->resourceScopes[$resource] ?? null;
    }
}
