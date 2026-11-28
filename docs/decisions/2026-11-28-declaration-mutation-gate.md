# 2026-11-28: Whole-source mutation gate

The package measures executable code with Pest and PCOV at a minimum of 95%
per source path. The source inventory includes erasure and shipped test fakes.
Interfaces declare contracts and types with no generated mutants have their
own result. Uncovered executable mutants count against the score.

PHP loads class constants and literal property initializers as declarations.
PCOV provides no line attribution for these initializers, so Pest reports
their mutants as uncovered. The affected contracts include configuration
ceilings, Eloquent mass assignment, timestamp handling and key generation.

An eligible declaration carries a one-line PCOV reason and names its exact
mutators. The lint matches each directive against the PHP syntax tree.
Directives on methods, property hooks, executable statements and strings
fail the lint. Adding support for another initializer requires a contract
test that detects its mutations.

The declaration runner makes a disposable copy of the package and runs its
contracts on SQLite in memory. It changes one literal or removes one
property array item per run. The baseline must pass and each changed version
must fail its contract. The initial inventory has 101 declaration mutants.

`Mutation (per-class ≥95%)` requires both the Pest shards and the declaration
job. A release preparation PR runs the complete inventory at its head.

The [app-ui standards proposal](https://github.com/qiick-io/app-ui/issues/300)
tracks adoption across packages.
