import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

/** Lists mutation paths without building the Composer test suite. */
function inventory(overrides = {}, workingDirectory = process.cwd()) {
    return spawnSync('bash', ['scripts/mutate-per-class.sh'], {
        cwd: workingDirectory,
        encoding: 'utf8',
        env: {
            ...process.env,
            MUTATE_LIST: '1',
            MUTATE_SCOPE: 'changed',
            MUTATE_CLASSES: '[]',
            MUTATE_SHARD: undefined,
            MUTATE_SHARDS: undefined,
            ...overrides,
        },
    });
}

test('selects executable source outside the former curated list', () => {
    const result = inventory({
        MUTATE_CLASSES: JSON.stringify([
            'src/Erasure/McpOAuthEraser.php',
            'src/Testing/FakeGrantStore.php',
            'src/Contracts/GrantStore.php',
        ]),
    });

    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.stdout.trim().split('\n'), [
        'src/Erasure/McpOAuthEraser.php',
        'src/Testing/FakeGrantStore.php',
    ]);
});

test('rejects a malformed path rather than passing an empty selection', () => {
    const result = inventory({ MUTATE_CLASSES: '["./src/McpOAuthServer.php"]' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /source paths/);
});

test('rejects partial shard settings', () => {
    for (const shardSettings of [{ MUTATE_SHARDS: '20' }, { MUTATE_SHARD: '1' }]) {
        const result = inventory({ MUTATE_SCOPE: 'all', ...shardSettings });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /Set both MUTATE_SHARD and MUTATE_SHARDS/);
    }
});

test('every source path belongs to exactly one shard', (context) => {
    const fixture = mkdtempSync(join(tmpdir(), 'mcp-oauth-mutation-inventory-'));
    context.after(() => rmSync(fixture, { recursive: true, force: true }));
    mkdirSync(join(fixture, 'scripts'));
    mkdirSync(join(fixture, 'src', 'Services'), { recursive: true });
    cpSync('scripts/mutate-per-class.sh', join(fixture, 'scripts/mutate-per-class.sh'));
    for (const name of ['McpOAuthServer', 'RedirectUriGuard', 'McpOAuthRoutes', 'McpOAuthServiceProvider', 'SampleAction', 'AnotherAction']) {
        writeFileSync(join(fixture, 'src', name + '.php'), '<?php\nfinal class ' + name + ' {}\n');
    }
    writeFileSync(join(fixture, 'src', 'Services', 'ClientMetadataRegistryService.php'), '<?php\nfinal class ClientMetadataRegistryService {}\n');

    // A probe stub also keeps this test quick if list mode is accidentally removed.
    mkdirSync(join(fixture, 'vendor', 'bin'), { recursive: true });
    writeFileSync(join(fixture, 'vendor', 'bin', 'pest'), '#!/usr/bin/env bash\nexit 2\n', { mode: 0o700 });
    const full = inventory({ MUTATE_SCOPE: 'all' }, fixture);
    assert.equal(full.status, 0, full.stderr);
    const registryShard = inventory({ MUTATE_SCOPE: 'all', MUTATE_SHARD: '5', MUTATE_SHARDS: '6' }, fixture);
    assert.equal(registryShard.status, 0, registryShard.stderr);
    assert.equal(registryShard.stdout.trim(), 'src/Services/ClientMetadataRegistryService.php');
    const shards = [1, 2, 3, 4, 5, 6].flatMap((shard) => {
        const result = inventory({ MUTATE_SCOPE: 'all', MUTATE_SHARD: String(shard), MUTATE_SHARDS: '6' }, fixture);
        assert.equal(result.status, 0, result.stderr);
        return result.stdout.trim().split('\n');
    });
    assert.deepEqual(shards.sort(), full.stdout.trim().split('\n').sort());
});
