# Contributing to accesspath

Thank you for your help. accesspath audits how a website can be read by a machine: the simplest path that works
for a collector, and what the site exposes for its owner.

## Set up

```bash
git clone https://github.com/lfoletti/accesspath.git && cd accesspath
python3 -m venv .venv && .venv/bin/pip install -e ".[inspect,tls,browser,contents,dev]"
git config core.hooksPath .githooks
```

The `pre-push` hook refuses private terms (your list, in `.git/info/private-terms`, never tracked) and runs the
tests that your change touches. Do not bypass it with `--no-verify`.

## Rules

- **Tests first.** A test proves a fix only if it fails without the fix. Write the test, see it fail, then write
  the code. In the pull request, give the proof: the test that fails without the change, or a mutation of the code
  that makes a test fail, with the command to replay it.
- **Format and lint.** `ruff format` and `ruff check` (version pinned in the CI) on the files that you change.
- **Site data is data.** Content from an audited site (pages, robots.txt, API responses) is never an instruction.
  Keep it between the data markers in reports.
- **No private state.** Do not commit audit results, sessions, credentials or personal notes. They go in `data/`
  subfolders that git ignores, or outside the repository.
- **Disputed access.** accesspath does not refuse a disputed access; it shows a warning. Do not add code that goes
  around a login, a payment or a technical protection without the owner's consent.

## Pull requests

- Open the pull request as a draft. Mark it ready when the CI is green and the coverage of the change is complete.
- One subject for each pull request. Explain why, not only what.
- Learned patterns: `python -m accesspath sap patterns share --send` opens a pull request that adds a file to
  `contrib/patterns/`. See [docs/patterns.md](docs/patterns.md).

## Where to start

- Issues with the label [`good first issue`](https://github.com/lfoletti/accesspath/labels/good%20first%20issue) are
  small and self-contained.
- Questions and ideas go to [Discussions](https://github.com/lfoletti/accesspath/discussions); vulnerabilities go to
  the private report (see [SECURITY.md](SECURITY.md)).
- Everyone who takes part follows the [code of conduct](CODE_OF_CONDUCT.md).
