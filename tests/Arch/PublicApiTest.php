<?php

declare(strict_types=1);

/*
 * docs/public-api.md is the frozen 1.0 surface: every class, interface and enum in
 * src/ says whether it belongs to it (@api) or not (@internal), and the page lists
 * every @api one (fleet convention F12).
 *
 * Copied from qiick/laravel-http-basics tests/Arch/PublicApiTest.php (develop,
 * 2026-11-26), with one change: a declaration is found first and its docblock
 * after, so a class with no docblock at all fails instead of being skipped.
 */

/**
 * The docblock right above the first declaration in a source file, past any
 * attributes, or '' when there is none.
 *
 * @return array{0: string, 1: string}|null [short name, docblock], null for a file with no declaration
 */
function declarationDocblock(string $source): ?array
{
    if (preg_match('/^(?:final |abstract )?(?:readonly )?(?:class|interface|enum|trait) (\w+)/m', $source, $declaration, PREG_OFFSET_CAPTURE) !== 1) {
        return null;
    }

    $sourceBefore = substr($source, 0, $declaration[0][1]);
    $docblock = preg_match('/(\/\*\*(?:(?!\*\/).)*\*\/)\s*(?:#\[[^\n]*\]\s*)*$/s', $sourceBefore, $match) === 1 ? $match[1] : '';

    return [$declaration[1][0], $docblock];
}

/**
 * @return array<string, string> class short name => the docblock right above it
 */
function sourceClassDocblocks(): array
{
    $docblocks = [];
    $sourceFiles = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__, 2).'/src', FilesystemIterator::SKIP_DOTS));

    foreach ($sourceFiles as $sourceFile) {
        $declaration = declarationDocblock((string) file_get_contents((string) $sourceFile));

        if ($declaration !== null) {
            $docblocks[$declaration[0]] = $declaration[1];
        }
    }

    ksort($docblocks);

    return $docblocks;
}

it('marks every class in src as @api or @internal, never both', function (): void {
    foreach (sourceClassDocblocks() as $class => $docblock) {
        $isApi = str_contains($docblock, '@api');
        $isInternal = str_contains($docblock, '@internal');

        expect($isApi xor $isInternal)->toBeTrue("{$class} must be marked either @api or @internal.");
    }
});

it('lists every @api class in docs/public-api.md, and nothing else', function (): void {
    $page = (string) file_get_contents(dirname(__DIR__, 2).'/docs/public-api.md');
    preg_match_all('/^- `(\w+)` \((?:class|interface|enum)\)$/m', $page, $listed);

    $apiClasses = array_keys(array_filter(sourceClassDocblocks(), static fn (string $docblock): bool => str_contains($docblock, '@api')));
    $listedClasses = $listed[1];
    sort($listedClasses);

    expect($listedClasses)->toBe($apiClasses);
});

it('finds a declaration that has no docblock, so the marks check fails on it (Codex review of #64)', function (): void {
    expect(declarationDocblock("<?php\n\nfinal class Undocumented\n{\n}\n"))->toBe(['Undocumented', ''])
        ->and(declarationDocblock("<?php\n\n/**\n * Kept.\n *\n * @api\n */\n#[Attribute]\nfinal class Documented\n{\n}\n"))
        ->toBe(['Documented', "/**\n * Kept.\n *\n * @api\n */"]);
});
