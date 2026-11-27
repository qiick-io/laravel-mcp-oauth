# Security Policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| Untagged `develop` / pre-`0.1.0` | Best effort while the package is in development. |
| Tagged `0.x` / `1.x` (once published) | Documented here when the first tag lands. |

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting
("Report a vulnerability" on the Security tab of
`qiick-io/laravel-mcp-oauth`). We aim to acknowledge reports within 72 hours.

This package is the OAuth authorization server for every qiick `/mcp` endpoint.
Reports about DCR / redirect URI bypass, host-header discovery poisoning,
refresh-token family races, consent widening, missing-key 500s, dual-door
selection mistakes, or token material in logs/events/audit are treated as
critical.

Every security PR needs an independent adversarial review before merge, with
mutation scores read from the CI log (design §15).

Coordinate disclosure with `qiick/laravel-api-keys` and `qiick/laravel-access`
when a finding spans packages.

## Trusted release path

Tagged releases are cut from `main` with GitHub attestations / build provenance
where available. Packagist publish happens only after Luca’s explicit go. Never
trust an untagged `develop` commit as a production dependency.
