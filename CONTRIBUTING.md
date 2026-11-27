# Contributing to laravel-mcp-oauth

Thanks for helping. A few rules keep the codebase consistent:

1. Open or pick an issue first. One cohesive area per pull request.
2. Branch from `develop` as `<type>/<kebab-slug>` (types: feat, fix, refactor,
   chore, docs, test, perf, ci, build, security).
3. Use Conventional Commits; PR titles follow the same format. Body lines ≤ 100
   characters. Git identity for bots: Luca Giardi
   `<62483245+LucaGiardi20@users.noreply.github.com>`.
4. Open the PR against `develop`. PRs are squash-merged. Never push to
   `develop` or `main` directly; never tag from a contributor branch; never
   touch Packagist.
5. Before pushing run `composer test` (Pest), `composer lint` (Pint) and
   `composer analyse` (PHPStan level max). Security-critical classes also need
   `pest --mutate` coverage (design §11.4; per-class MSI ≥ 95%, one invocation
   per class, pcov, no `--covered-only`, no `|| true`).
6. Red-first: every design §9 security checklist row is a failing test before
   the code that makes it pass. Real HTTP tests use `php -S` without a shell
   wrapper and kill the server in tearDown; the CI `http` group job fails if
   empty once tests exist.
7. Code style: strict types, `final` by default, English docblocks that explain
   *why*, no `parse_url` in `src/`, no Signaculum symbols, no
   `Illuminate\Foundation\` in `src/`. Only `@api` types are SemVer BC.
8. Security checks are never weakened. Fixtures represent real formats and are
   never edited to make code pass.
9. Do not commit `composer.lock`, secrets, or `graphify-out/`. Never read
   `.env` files in agent workflows.
10. Releases and Packagist: maintainer / orchestrator only under the package
    release policy (see SECURITY.md and the qiick release standard).
