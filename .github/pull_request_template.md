## Summary

<!-- What does this change and why? Link the issue it addresses, e.g. "Closes #12". -->

## Testing

<!-- How you checked it: DRYRUN daemon run, ES replay, installed build, shellcheck... -->

## Checklist

- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] New checks take a baseline on first run, throttle repeats and mask secrets
- [ ] No new forks or heavy work on the daemon's or helper's hot path, or the CPU impact is described above
- [ ] Documentation and `CHANGELOG.md` (Unreleased) are updated
