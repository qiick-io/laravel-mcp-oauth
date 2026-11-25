<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Tests\Http\Server;

use Illuminate\Http\Response;
use Qiick\McpOAuth\Contracts\ConsentView;
use Qiick\McpOAuth\Data\ConsentPage;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * A plain HTML consent page: the two tokens an approval must post back (the
 * session's CSRF token and Passport's auth token). The test picks the
 * scopes, role and resources itself, as a user would on the real page.
 */
final class HtmlConsentView implements ConsentView
{
    public function render(array $parameters, ConsentPage $page): SymfonyResponse
    {
        return new Response(sprintf(
            '<form method="post" action="/oauth/authorize"><input name="_token" value="%s"><input name="auth_token" value="%s"></form>',
            e(csrf_token()),
            e($page->authToken),
        ));
    }
}
