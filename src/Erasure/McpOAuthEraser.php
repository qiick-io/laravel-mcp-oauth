<?php

declare(strict_types=1);

namespace Qiick\McpOAuth\Erasure;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Laravel\Passport\Passport;
use LogicException;
use Qiick\McpOAuth\Events\SubjectErasedEvent;
use Qiick\McpOAuth\Internal\BoundedPositiveInt;
use Qiick\McpOAuth\Models\OAuthAuthCodeExchange;
use Qiick\McpOAuth\Models\OAuthBlockedRedirectHost;
use Qiick\McpOAuth\Models\OAuthClientMetadata;
use Qiick\McpOAuth\Models\OAuthConsentRecord;
use RuntimeException;
use SensitiveParameter;

/**
 * Erases subject data the package owns while preserving consent evidence and
 * keeping a host block in force after its author has been unlinked.
 *
 * @api
 */
final class McpOAuthEraser
{
    public const string DELETE = 'delete';

    public const string ANONYMISE = 'anonymise';

    public function __construct(private readonly ConfigRepository $config, private readonly Dispatcher $events) {}

    /**
     * The product locks out the subject and revokes its grants before invoking
     * the package eraser. A real run dispatches SubjectErasedEvent after commit.
     *
     * @param  list<string>  $publicIds
     * @param  list<string>  $identifiers
     *
     * @throws InvalidArgumentException if the input fails validation
     * @throws OrganisationScopeUnsupportedException if an organisation is supplied
     * @throws LogicException if the stores cannot share a transaction
     */
    public function erase(
        #[SensitiveParameter] string $userId,
        #[SensitiveParameter] string $userPublicId,
        #[SensitiveParameter] string $mode,
        #[SensitiveParameter] array $publicIds = [],
        #[SensitiveParameter] array $identifiers = [],
        #[SensitiveParameter] ?string $organisationId = null,
        bool $dryRun = false,
    ): ErasureReport {
        $this->validate($userPublicId, $mode, $publicIds, $identifiers);

        if ($organisationId !== null) {
            throw new OrganisationScopeUnsupportedException;
        }

        $consent = new OAuthConsentRecord;
        $blockedHost = new OAuthBlockedRedirectHost;
        $exchange = new OAuthAuthCodeExchange;
        $clientMetadata = new OAuthClientMetadata;
        $authCode = Passport::authCode();
        $accessToken = Passport::token();
        $refreshToken = Passport::refreshToken();
        $connection = $consent->getConnection();

        foreach ([$blockedHost, $exchange, $clientMetadata, $authCode, $accessToken, $refreshToken] as $store) {
            if ($store->getConnection() !== $connection) {
                throw new LogicException('MCP OAuth erasure requires its stores to share a database connection.');
            }
        }

        $subjectConsent = $connection->table($consent->getTable())->useWritePdo()->where(function (Builder $query) use ($userId, $publicIds): void {
            $query->where('user_identifier', $userId)->orWhereIn('grant_id', $publicIds);
        });
        $subjectBlocks = $connection->table($blockedHost->getTable())->useWritePdo();
        $driver = $connection->getDriverName();
        $this->whereUserKey($subjectBlocks, 'created_by', $userId, $driver);

        $clientIds = $connection->table($clientMetadata->getTable())->select('client_id');
        $subjectCodes = $connection->table($authCode->getTable())->useWritePdo()->whereIn('client_id', $clientIds);
        $this->whereUserKey($subjectCodes, 'user_id', $userId, $driver);
        $subjectTokens = $connection->table($accessToken->getTable())->useWritePdo()->whereIn('client_id', $clientIds);
        $this->whereUserKey($subjectTokens, 'user_id', $userId, $driver);
        $subjectRefreshTokens = $connection->table($refreshToken->getTable())->useWritePdo()
            ->whereIn('access_token_id', (clone $subjectTokens)->select('id'));
        $subjectExchanges = $connection->table($exchange->getTable())->useWritePdo()
            ->where('user_identifier', $userId)
            ->orWhereIn('auth_code_id', (clone $subjectCodes)->select('id'))
            ->orWhereIn('grant_id', (clone $subjectConsent)->select('grant_id'))
            ->orWhereIn('grant_id', $publicIds);

        // Delete credentials and replay keys in dependency order. They have no anonymous form.
        $subjectCredentials = [
            $exchange->getTable() => $subjectExchanges,
            $refreshToken->getTable() => $subjectRefreshTokens,
            $authCode->getTable() => $subjectCodes,
            $accessToken->getTable() => $subjectTokens,
        ];

        try {
            return $connection->transaction(function () use ($connection, $mode, $dryRun, $subjectConsent, $subjectBlocks, $subjectCredentials, $blockedHost, $consent): ErasureReport {
                $stores = [];

                foreach ($subjectCredentials as $table => $query) {
                    $stores[$table] = self::counts(deleted: $dryRun ? $query->count() : $query->delete());
                }

                $stores[$blockedHost->getTable()] = self::counts(anonymised: $dryRun ? $subjectBlocks->count() : $subjectBlocks->update([
                    'created_by' => null,
                    'reason' => null,
                    'metadata' => null,
                ]));
                $scrubbedConsent = $this->scrubConsent($subjectConsent, $dryRun);
                $stores[$consent->getTable()] = self::counts(anonymised: $scrubbedConsent, kept: $scrubbedConsent);
                $report = new ErasureReport('qiick/laravel-mcp-oauth', $mode, $dryRun, $stores);

                if (! $dryRun) {
                    $connection->afterCommit(fn () => $this->events->dispatch(new SubjectErasedEvent($report)));
                }

                return $report;
            });
        } catch (QueryException) {
            // The framework includes bound subject values in QueryException messages.
            throw new RuntimeException('MCP OAuth erasure could not access its data stores.');
        }
    }

    /**
     * @param  array<array-key, mixed>  $publicIds
     * @param  array<array-key, mixed>  $identifiers
     */
    private function validate(#[SensitiveParameter] string $userPublicId, #[SensitiveParameter] string $mode, #[SensitiveParameter] array $publicIds, #[SensitiveParameter] array $identifiers): void
    {
        if (! in_array($mode, [self::DELETE, self::ANONYMISE], true) || ! Str::isUuid($userPublicId)) {
            throw new InvalidArgumentException('Invalid MCP OAuth erasure mode or user public identifier.');
        }

        foreach ($publicIds as $publicId) {
            if (! is_string($publicId) || ! Str::isUuid($publicId)) {
                throw new InvalidArgumentException('Invalid MCP OAuth erasure public identifier.');
            }
        }

        foreach ($identifiers as $identifier) {
            if (! is_string($identifier) || trim($identifier) === '') {
                throw new InvalidArgumentException('Invalid MCP OAuth erasure identifier.');
            }
        }
    }

    /**
     * A textual comparison prevents MySQL from coercing a key to an unrelated integer.
     *
     * @param  'created_by'|'user_id'  $column
     */
    private function whereUserKey(Builder $query, string $column, #[SensitiveParameter] string $userId, string $driver): void
    {
        if (ctype_digit($userId) && (string) (int) $userId === $userId) {
            // Allow the engine to use the normal lookup index for bigint keys.
            $query->where($column, $userId);
        }

        $sqlType = in_array($driver, ['mysql', 'mariadb'], true) ? 'char' : 'text';
        $query->whereRaw("cast({$column} as {$sqlType}) = ?", [$userId]);
    }

    /** Preserve the existing deadline, or start it when erasure unlinks an active grant. */
    private function scrubConsent(#[SensitiveParameter] Builder $consent, bool $dryRun): int
    {
        if ($dryRun) {
            return $consent->count();
        }

        $retentionDays = BoundedPositiveInt::require(
            $this->config->get('mcp-oauth.revoked_retention_days'),
            'revoked_retention_days',
            BoundedPositiveInt::REVOKED_RETENTION_DAYS_MAX,
        );
        (clone $consent)->whereNull('retention_until')->update(['retention_until' => Date::now()->addDays($retentionDays)]);

        return $consent->update([
            'user_identifier' => null,
            'grant_id' => null,
            'redirect_uri' => null,
            'redirect_host' => null,
            'resource' => null,
            'resource_scopes' => null,
            'requested_scopes' => '[]',
            'granted_scopes' => null,
            'role' => null,
            'resources' => null,
            'all_resources' => false,
            'attributes' => null,
            'consent_version' => null,
            'locale' => null,
            'ip_address' => null,
            'user_agent' => null,
            'correlation_id' => null,
            'metadata' => null,
        ]);
    }

    /** @return array{deleted: int, anonymised: int, kept: int, reason: ?string} */
    private static function counts(int $deleted = 0, int $anonymised = 0, int $kept = 0): array
    {
        return ['deleted' => $deleted, 'anonymised' => $anonymised, 'kept' => $kept, 'reason' => $kept > 0 ? 'consent_evidence' : null];
    }
}
