# Changelog

All notable changes to **laravel-mcp-oauth** (`qiick/laravel-mcp-oauth`) are
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Core runtime services: `McpOAuthServer` (three gates, Passport key usability
  including half-set env and world-readable files), `RedirectUriGuard` (League
  Uri, ASCII hosts, scheme allowlist, host block), `ClientThrottleKey`,
  `McpOAuthReadiness`, and `MissingPassportKeysException`. Mutation targets
  registered for these classes.

- Design §3 / §5.5 public contracts (`AdminSwitch`, `GrantStore`, …), data
  objects (`GrantRecord`, `AuthorizationDecision`, …), `RevocationReason`, and
  immutable audit events. Ids on the wire stay UUID strings (S80).

- Package scaffold: auto-discovered `McpOAuthServiceProvider`, publishable
  `config/mcp-oauth.php` (tag `mcp-oauth-config`), Pest + Testbench, Pint,
  PHPStan level max, qiick standards pack pinned to app-ui `v0.12.0`
  (`f613af9febfce3b6d7f7f41785e9845a610080c7`), CI matrix (PHP 8.3/8.4/8.5 ×
  Laravel 12/13 × lowest/stable) with `composer validate --strict`,
  `composer audit`, SHA-pinned Actions, PostgreSQL/MySQL/MariaDB/SQLite job
  shape, real-HTTP and no-dev boot cells, and README header banners.
