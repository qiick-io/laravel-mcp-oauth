<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Views;

use Inertia\Inertia;
use Qiick\McpOAuth\Contracts\ConsentView;
use Qiick\McpOAuth\Data\ConsentPage;
use Symfony\Component\HttpFoundation\Response;

/**
 * Default {@see ConsentView}: the Inertia page `oauth/authorize`, the app-ui
 * registry consent component (design Resolved #9). Bound only when
 * inertiajs/inertia-laravel is installed. The props mirror {@see ConsentPage}
 * one to one; docs/consent-page.md documents them and the form the page posts.
 *
 * @internal
 */
final class InertiaConsentView implements ConsentView
{
    public const string COMPONENT = 'oauth/authorize';

    public function render(array $parameters, ConsentPage $page): Response
    {
        // ConsentOptions and ConsentOption are readonly objects with public
        // properties: they serialise to exactly the documented props.
        $properties = [
            'client' => $page->client,
            'authToken' => $page->authToken,
            'options' => $page->options,
            'advanced' => $page->advanced,
        ];

        if ($page->resourceScopes !== []) {
            $properties['resourceScopes'] = $page->resourceScopes;
        }

        return Inertia::render(self::COMPONENT, $properties)->toResponse($parameters['request']);
    }
}
