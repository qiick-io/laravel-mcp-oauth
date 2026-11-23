<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Internal;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Qiick\McpOAuth\Exceptions\InvalidMcpOAuthConfigException;

/**
 * The `oauth_access_tokens` column that holds GrantStore::bindingKey()
 * (`mcp-oauth.grant_binding_column`, design §6). Read where a token is bound
 * and where the tokens of a grant are revoked, so both name the same column.
 *
 * @internal
 */
final class GrantBindingColumn
{
    /**
     * @throws InvalidMcpOAuthConfigException when the column is not a non-empty string
     */
    public static function from(ConfigRepository $config): string
    {
        $bindingColumn = $config->get('mcp-oauth.grant_binding_column');

        if (! is_string($bindingColumn) || $bindingColumn === '') {
            throw InvalidMcpOAuthConfigException::invalidGrantBindingColumn();
        }

        return $bindingColumn;
    }
}
