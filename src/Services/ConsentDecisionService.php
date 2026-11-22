<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Services;

use Closure;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Qiick\McpOAuth\Data\ConsentDecision;
use Qiick\McpOAuth\Data\ConsentOption;
use Qiick\McpOAuth\Data\ConsentOptions;

/**
 * Turns the posted consent form into a {@see ConsentDecision}, judged against
 * the {@see ConsentOptions} the product offered for this user and client,
 * never against what the form claims (design §8.3 step 4, S46–S48):
 *
 * - `scopes[]`: at least one, each offered and grantable;
 * - `role`: required and grantable when roles are offered, refused otherwise;
 * - `resources[]` / `all_resources`: each offered and grantable; when the
 *   product requires a choice, an empty list counts only with an explicit
 *   `all_resources` (silence never means "all");
 * - `organisation`: with more than one organisation the user must pick a
 *   grantable one; with exactly one it is used without asking (instituta,
 *   decision 2026-11-22); with none it is refused. It reaches the grant as
 *   `attributes['organisation']`.
 *
 * The product's own checks run afterwards in ConsentProvider::validate().
 */
final class ConsentDecisionService
{
    public function __construct(
        private readonly ValidationFactory $validationFactory,
    ) {}

    /**
     * @throws ValidationException 422 field errors
     */
    public function fromRequest(Request $request, ConsentOptions $consentOptions, string $clientId, string $userIdentifier, string $redirectUri): ConsentDecision
    {
        $organisations = $consentOptions->organisations;
        // Closure rules compare strictly against the grantable values, so they
        // also refuse anything that is not one of those strings.
        $validator = $this->validationFactory->make($request->all(), [
            'scopes' => ['required', 'list'],
            'scopes.*' => ['distinct', $this->mustBeGrantable($consentOptions->scopes)],
            'role' => $consentOptions->roles === [] ? ['prohibited'] : ['required', $this->mustBeGrantable($consentOptions->roles)],
            'resources' => ['nullable', 'list'],
            'resources.*' => ['distinct', $this->mustBeGrantable($consentOptions->resources)],
            'all_resources' => ['boolean'],
            'organisation' => match (count($organisations)) {
                0 => ['prohibited'],
                1 => ['nullable', $this->mustBeGrantable($organisations)],
                default => ['required', $this->mustBeGrantable($organisations)],
            },
        ]);

        $validator->after(function (Validator $afterValidator) use ($request, $consentOptions, $organisations): void {
            $hasChosenResources = ! empty($request->input('resources'));

            if ($consentOptions->resourcesRequired && ! $request->boolean('all_resources') && ! $hasChosenResources) {
                $afterValidator->errors()->add('resources', 'Select at least one resource, or explicitly allow every resource.');
            }

            if (count($organisations) === 1 && ! $organisations[0]->grantable) {
                $afterValidator->errors()->add('organisation', 'You cannot grant access for this organisation.');
            }
        });

        /** @var array{scopes: list<string>, role?: string|null, resources?: list<string>|null, organisation?: string|null} $validated */
        $validated = $validator->validate();

        $isAllResources = $request->boolean('all_resources');
        $organisation = count($organisations) === 1 ? $organisations[0]->value : ($validated['organisation'] ?? null);

        return new ConsentDecision(
            clientId: $clientId,
            userIdentifier: $userIdentifier,
            redirectUri: $redirectUri,
            scopes: $validated['scopes'],
            role: $validated['role'] ?? null,
            resources: $isAllResources ? [] : ($validated['resources'] ?? []),
            allResources: $isAllResources,
            attributes: $organisation === null ? [] : ['organisation' => $organisation],
        );
    }

    /**
     * @param  list<ConsentOption>  $offeredOptions
     * @return Closure(string, mixed, Closure(string): mixed): void
     */
    private function mustBeGrantable(array $offeredOptions): Closure
    {
        $grantableValues = array_map(
            static fn (ConsentOption $consentOption): string => $consentOption->value,
            array_filter($offeredOptions, static fn (ConsentOption $consentOption): bool => $consentOption->grantable),
        );

        return static function (string $attribute, mixed $value, Closure $fail) use ($grantableValues): void {
            if (! in_array($value, $grantableValues, true)) {
                $fail('The selected :attribute was not offered or cannot be granted by you.');
            }
        };
    }
}
