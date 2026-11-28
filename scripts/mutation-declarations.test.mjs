import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

/** Runs the declaration lint on one source fixture with the package's PHP parser. */
function lintDeclaration(context, members) {
    const fixture = mkdtempSync(join(tmpdir(), 'mcp-oauth-declaration-lint-'));
    context.after(() => rmSync(fixture, { recursive: true, force: true }));
    mkdirSync(join(fixture, 'src'));
    writeFileSync(join(fixture, 'src', 'Policy.php'), '<?php\nnamespace Fixture;\nfinal class Policy {\n' + members + '\n}\n');

    return spawnSync('php', ['scripts/mutate-declarations.php', '--lint', fixture], { encoding: 'utf8' });
}

test('allows a reasoned directive on a literal constant', (context) => {
    const result = lintDeclaration(context, `
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int MAXIMUM = 10;
`);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /2 declaration mutations/);
});

for (const [name, members] of Object.entries({
    'an executable statement': `
    public function maximum(): int {
        // PCOV has no line coverage for a class constant initializer.
        // @pest-mutate-ignore: IncrementInteger,DecrementInteger
        return 10;
    }
`,
    'a directive without a reason': `
    // @pest-mutate-ignore: IncrementInteger,DecrementInteger
    public const int MAXIMUM = 10;
`,
    'a blanket directive': `
    // PCOV has no line coverage for a class constant initializer.
    // @pest-mutate-ignore
    public const int MAXIMUM = 10;
`,
    'a directive written in a string': `
    public function description(): string {
        return '@pest-mutate-ignore: IncrementInteger';
    }
`,
    'a directive on a property with executable hooks': `
    // PCOV has no line coverage for a static property initializer.
    // @pest-mutate-ignore: FalseToTrue
    public bool $isEnabled = false {
        get => $this->isEnabled && false;
    }
`,
})) {
    test('rejects ' + name, (context) => {
        const result = lintDeclaration(context, members);

        assert.equal(result.status, 1, result.stdout);
        assert.match(result.stderr, /src\/Policy\.php:\d+.*directive/i);
    });
}
