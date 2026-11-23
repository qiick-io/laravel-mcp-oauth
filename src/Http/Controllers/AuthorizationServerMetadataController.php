<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Qiick\McpOAuth\McpOAuthServer;

/**
 * RFC 8414 authorization server metadata (design §5.2, S13, S15; standards
 * review M1, M2, S1). Every URL comes from the issuer (APP_URL), never from
 * the request Host, and only what is switched on is advertised: client ID
 * metadata documents, PAR and DPoP join this document with their handlers.
 */
final class AuthorizationServerMetadataController
{
    public function __invoke(McpOAuthServer $mcpOAuthServer): JsonResponse
    {
        $issuer = $mcpOAuthServer->issuer();
        // Passport clients authenticate with a secret in Basic or the body; DCR clients with none.
        $clientAuthenticationMethods = ['none', 'client_secret_basic', 'client_secret_post'];

        return new JsonResponse([
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/oauth/authorize',
            'token_endpoint' => $issuer.'/oauth/token',
            'registration_endpoint' => $issuer.'/oauth/register',
            'revocation_endpoint' => $issuer.'/oauth/revoke',
            'scopes_supported' => [McpOAuthServer::WIRE_SCOPE],
            'response_types_supported' => ['code'],
            'grant_types_supported' => McpOAuthServer::SUPPORTED_GRANT_TYPES,
            'code_challenge_methods_supported' => McpOAuthServer::SUPPORTED_CODE_CHALLENGE_METHODS,
            'token_endpoint_auth_methods_supported' => $clientAuthenticationMethods,
            'revocation_endpoint_auth_methods_supported' => $clientAuthenticationMethods,
            'authorization_response_iss_parameter_supported' => true,
        ]);
    }
}
