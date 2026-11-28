<?php

declare(strict_types=1);

use PhpParser\Node\Expr;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\Int_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\ClassConst;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\Namespace_;
use PhpParser\Node\Stmt\Property;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;
use Symfony\Component\Process\Process;

require dirname(__DIR__).'/vendor/autoload.php';

/**
 * Find the literal initializers PCOV cannot attribute when PHP loads a class.
 *
 * @return array{Expr, list<Expr>, list<string>}
 */
function declarationVariants(ClassConst|Property $declaration): array
{
    if ($declaration instanceof ClassConst && $declaration->attrGroups === [] && count($declaration->consts) === 1) {
        $value = $declaration->consts[0]->value;

        if ($value instanceof Int_) {
            return [$value, [new Int_($value->value - 1), new Int_($value->value + 1)], ['IncrementInteger', 'DecrementInteger']];
        }
    }

    if ($declaration instanceof Property && $declaration->attrGroups === [] && $declaration->hooks === [] && count($declaration->props) === 1) {
        $value = $declaration->props[0]->default;

        if ($value instanceof Expr\ConstFetch && $value->name->toLowerString() === 'false') {
            return [$value, [new Expr\ConstFetch(new Name('true'))], ['FalseToTrue']];
        }

        if ($value instanceof Expr\Array_ && $value->items !== []) {
            $replacements = [];

            foreach ($value->items as $index => $item) {
                if ($item->byRef || $item->unpack || ! $item->value instanceof String_ || ($item->key !== null && ! $item->key instanceof String_)) {
                    throw new RuntimeException('A directive on a property array requires literal string items and keys.');
                }

                $items = $value->items;
                unset($items[$index]);
                $replacements[] = new Expr\Array_(array_values($items));
            }

            return [$value, $replacements, ['RemoveArrayItem']];
        }
    }

    throw new RuntimeException('The directive requires a supported literal initializer.');
}

/**
 * Every directive must be attached to a top-level type member, with its reason
 * on the preceding comment line. Checking raw occurrences also catches strings
 * because Pest scans the source text for directives before traversing the AST.
 *
 * @return list<array{path: string, source: string, line: int, isConstant: bool}>
 */
function declarationMutations(string $packageRoot): array
{
    $parser = (new ParserFactory)->createForNewestSupportedVersion();
    $printer = new Standard;
    $paths = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($packageRoot.'/src', FilesystemIterator::SKIP_DOTS));
    $mutations = [];

    foreach ($paths as $path) {
        if ($path->getExtension() !== 'php') {
            continue;
        }

        $relativePath = substr($path->getPathname(), strlen($packageRoot) + 1);
        $source = file_get_contents($path->getPathname());
        preg_match_all('/@pest-mutate-ignore/', $source, $occurrences, PREG_OFFSET_CAPTURE);

        if ($occurrences[0] === []) {
            continue;
        }

        $types = [];
        foreach ($parser->parse($source) ?? [] as $statement) {
            $types = [...$types, ...($statement instanceof Namespace_ ? $statement->stmts : [$statement])];
        }

        $declarations = [];
        foreach ($types as $type) {
            if (! $type instanceof ClassLike) {
                continue;
            }

            foreach ($type->stmts as $member) {
                if (! $member instanceof ClassConst && ! $member instanceof Property) {
                    continue;
                }

                foreach ($member->getComments() as $comment) {
                    $offset = strpos($comment->getText(), '@pest-mutate-ignore');

                    if ($offset !== false) {
                        $declarations[$comment->getStartFilePos() + $offset] = $member;
                    }
                }
            }
        }

        $handledMembers = [];
        foreach ($occurrences[0] as [, $offset]) {
            $precedingSource = substr($source, 0, $offset);
            $line = substr_count($precedingSource, "\n") + 1;
            $member = $declarations[$offset] ?? null;

            try {
                if ($member === null || isset($handledMembers[$member->getStartFilePos()])) {
                    throw new RuntimeException('A directive must belong to a single constant or property declaration.');
                }

                if (! preg_match('~(?:^|\R)\h*(?://|\*)\h+PCOV [^\r\n]+\R\h*(?://|\*)\h*$~D', $precedingSource)) {
                    throw new RuntimeException('A directive needs a one-line PCOV reason in the preceding comment.');
                }

                [$initializer, $replacements, $expectedMutators] = declarationVariants($member);
                $directive = substr($source, $offset, strcspn($source, "\r\n", $offset));
                $declaredMutators = str_starts_with($directive, '@pest-mutate-ignore:')
                    ? array_map('trim', explode(',', substr($directive, strlen('@pest-mutate-ignore:'))))
                    : [];
                sort($declaredMutators);
                sort($expectedMutators);

                if ($declaredMutators !== $expectedMutators) {
                    throw new RuntimeException('A directive must name exactly '.implode(', ', $expectedMutators).'.');
                }
            } catch (RuntimeException $exception) {
                throw new RuntimeException($relativePath.':'.$line.' '.$exception->getMessage(), previous: $exception);
            }

            $handledMembers[$member->getStartFilePos()] = true;
            $start = $initializer->getStartFilePos();
            $length = $initializer->getEndFilePos() - $start + 1;

            foreach ($replacements as $replacement) {
                $mutations[] = [
                    'path' => $relativePath,
                    'source' => substr_replace($source, $printer->prettyPrintExpr($replacement), $start, $length),
                    'line' => $initializer->getStartLine(),
                    'isConstant' => $member instanceof ClassConst,
                ];
            }
        }
    }

    return $mutations;
}

/** The low code TTL lets both off-by-one variants reach the boundary assertion. */
function declarationContract(string $snapshot, bool $isConstant): Process
{
    if (file_exists($snapshot.'/.env') || is_link($snapshot.'/.env')) {
        throw new RuntimeException('The declaration test workspace must use the isolated SQLite database.');
    }

    $file = $isConstant ? 'tests/Feature/IntegerConfigBootTest.php' : 'tests/Feature/Schema/PackageMigrationsTest.php';
    $filter = $isConstant ? 'published upper limit' : 'package model insert fields';

    return new Process(
        [
            PHP_BINARY, '-d', 'memory_limit=1G', 'vendor/bin/pest',
            '--compact', '--colors=never', '--fail-on-empty-test-suite', $file, '--filter='.$filter,
        ],
        $snapshot,
        ['DB_CONNECTION' => 'sqlite', 'DB_DATABASE' => ':memory:', 'MCP_OAUTH_AUTH_CODE_TTL_MINUTES' => '1'],
    );
}

try {
    $packageRoot = dirname(__DIR__);
    $isLintOnly = ($argv[1] ?? null) === '--lint';
    $mutations = declarationMutations($isLintOnly ? ($argv[2] ?? $packageRoot) : $packageRoot);

    if ($isLintOnly) {
        fwrite(STDOUT, count($mutations)." declaration mutations validated.\n");
        exit(0);
    }

    $snapshot = sys_get_temp_dir().'/mcp-oauth-declarations-'.bin2hex(random_bytes(8));

    if (! mkdir($snapshot, 0700)) {
        throw new RuntimeException('Could not create a declaration test workspace.');
    }

    try {
        (new Process(['cp', '-R', 'composer.json', 'config', 'database', 'phpunit.xml', 'src', 'tests', 'vendor', $snapshot], $packageRoot))->mustRun();
        declarationContract($snapshot, true)->mustRun();
        declarationContract($snapshot, false)->mustRun();
        $isolatedRoot = realpath($snapshot);

        foreach ($mutations as $mutation) {
            $path = realpath($snapshot.'/'.$mutation['path']);

            if ($isolatedRoot === false || $path === false || ! str_starts_with($path, $isolatedRoot.'/src/')) {
                throw new RuntimeException($mutation['path'].' is outside the isolated source tree.');
            }

            $original = file_get_contents($path);
            file_put_contents($path, $mutation['source']);

            try {
                $test = declarationContract($snapshot, $mutation['isConstant']);
                $status = $test->run();
                $output = $test->getOutput();

                if (! in_array($status, [1, 2], true) || ! preg_match('/^\s*Tests:\s+1 failed\b/m', $output)) {
                    throw new RuntimeException($mutation['path'].':'.$mutation['line']." declaration mutation was not detected by its contract test.\n".$output.$test->getErrorOutput());
                }
            } finally {
                file_put_contents($path, $original);
            }
        }
    } finally {
        (new Process(['rm', '-rf', $snapshot]))->mustRun();
    }

    fwrite(STDOUT, count($mutations)." declaration mutations detected by contract tests.\n");
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage().PHP_EOL);
    exit(1);
}
