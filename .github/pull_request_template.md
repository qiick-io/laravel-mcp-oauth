## Summary

-

## Test plan

- [ ] `composer validate --strict`
- [ ] `composer test`
- [ ] `composer lint` (stable)
- [ ] `composer analyse` (stable)
- [ ] Mutation targets touched by this PR: one `pest --mutate` per class
      (pcov, no `--covered-only`); copy the per-class table from the CI log
      into this body when security-critical classes change
