# Contributing to MacSentry

Thank you for taking the time to help. Bug reports, false positive reports, detection ideas, documentation,
translations and code are all welcome.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security vulnerabilities go
through [SECURITY.md](SECURITY.md), never through public issues.

## Reporting issues

Use the [issue forms](https://github.com/vuminhhoa/macsentry/issues/new/choose):

- **Bug report**: something crashes, does not install, or behaves wrongly.
- **False positive**: an alert that fired for normal activity. Include the alert text and what you were doing.
- **Detection request**: a technique or event MacSentry should report.

Logs and alerts can contain host names, user names, IPs and command lines. Remove anything you would not want to
publish, and never post your bot token or chat ID.

## Development setup

You need macOS 26 or later and Xcode 26 or later (Swift 6). There are no third-party dependencies.

```sh
git clone https://github.com/vuminhhoa/macsentry.git
cd MacSentry
./build.sh --no-install        # build app, daemon and helper into build/
```

`./build.sh` without flags also installs and starts the app in `~/Applications`. Install the daemon with
`sudo ./daemon/install.sh` when you need to test it as root.

### Testing changes

There is no automated test suite yet; contributions toward one are very welcome. Until then, please check
changes by hand:

- **Daemon** without root and without sending anything:

  ```sh
  mkdir -p state pub && printf 'TOKEN=\nCHAT=\n' > test.conf
  DRYRUN=1 CONF=./test.conf LOG=./test.log STATE=./state PUB_DIR=./pub build/macsentryd
  ```

  Then watch `test.log`. `sudo build/macsentryd --check` prints what the readers see without sending anything.
- **Endpoint Security helper** against recorded events:

  ```sh
  STATE=./state build/macsentry-es --replay < events.jsonl
  ```

  Real samples are saved in `/var/db/macsentry/es_samples/` on a machine running the helper, and
  `python3 es/schema.py` prints their structure.
- **App**: install with `./build.sh` and exercise the pages you changed.
- **Shell scripts**: run `shellcheck build.sh uninstall.sh daemon/*.sh` (CI uses ShellCheck 0.11).

### CI

CI builds every pull request for Apple silicon and Intel, runs ShellCheck and actionlint, and runs CodeQL.

The CodeQL analysis of the Swift code is the slow part: it has to watch a real build on a macOS runner, and
it took about 25 minutes with the release build. There is no build-free mode for Swift, and cached or
incremental builds don't help, because CodeQL only analyzes the files it sees being compiled in that run. To
keep it reasonable, `.github/workflows/codeql.yml`:

- runs on push and pull requests only when Swift or Python code, `build.sh` or a workflow changes, and the
  weekly scheduled run still covers everything;
- builds with `SWIFT_OPT=-Onone`, which the analysis doesn't need. This is our own choice, not something GitHub
  documents, and the gain is small: the build step went from about 26 to 22 minutes. Under the CodeQL tracer
  the build reports `x86_64` on the arm64 runner, so it most likely runs under Rosetta; that, not the
  optimization level, seems to be where most of the time goes;
- builds only the runner's own architecture (no `ARCHS`).

In both workflows, a new push to the same branch or pull request cancels the run still in progress. The
scheduled CodeQL run has its own concurrency group, so pushes never cancel it.

Keep these when you change the workflow. GitHub's advice is in
[Code scanning analysis takes too long](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/analysis-takes-too-long)
and [CodeQL code scanning for compiled languages](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/codeql-code-scanning-for-compiled-languages).

## Pull requests

1. For anything larger than a small fix, open an issue first so we can agree on the approach.
2. Create a branch from `main` and keep the change focused on one thing.
3. Match the style of the surrounding code: small free functions in the daemon, comments that explain *why*,
   APIs instead of spawning commands where an API exists, and nothing on the hot 2-second path that forks.
   Existing comments are mostly in Vietnamese; new comments may be in English or Vietnamese.
4. New checks should take a baseline on first run (`diffState`), throttle repeats (`throttle`), and mask secrets
   in anything they send (`maskSecrets` / `redact`).
5. Mention the CPU impact if your change touches the daemon's or the helper's main loop.
6. Update the documentation (`README.md`, `docs/`) and `CHANGELOG.md` under **Unreleased**.
7. Write commit messages in English following [Conventional Commits](https://www.conventionalcommits.org/), for
   example `feat(daemon): report new DNS resolvers` or `fix(es): ignore xpcproxy in the parent chain`. Common
   scopes are `app`, `daemon`, `es`, `install`, `docs` and `ci`.

## Translations

The app is available in Vietnamese and English. Vietnamese is the development language: strings in the source
are Vietnamese and double as lookup keys for `L(...)` and `Lplural(...)` (see `Sources/Localization.swift`).
English translations live in `Resources/en.lproj/Localizable.strings`, and `build.sh` checks them with
`plutil -lint` before bundling them. For a string with a count, add the singular form under `"<key>#one"`.

To add a language, create `Resources/<code>.lproj/Localizable.strings`, add the code to `Lang.supported`, to
`AppLanguage` and to `CFBundleLocalizations` in `build.sh`. Telegram alerts from the daemon are still in
Vietnamese only; please open an issue before translating them so the work can be split sensibly.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
