# accesspath reference

This document gives the details that the README does not give.

## Installation

### Extras

The dependencies are in `pyproject.toml`. The core uses `httpx` and `PyYAML`. The extras are:

| Extra | Packages | Use |
|---|---|---|
| `inspect` | `nodriver` | `sap inspect` (browser) |
| `tls` | `curl_cffi>=0.15`, `brotli>=1.2.1` | Chrome TLS fingerprint |
| `browser` | `playwright` | human steps and Chrome profiles (`warmup`, `gestes`) |
| `contents` | `beautifulsoup4` | content pages (`sap batch --mode contents`) |
| `dev` | `pytest`, `pytest-cov`, `ruff` (pinned), `mypy`, `types-PyYAML`, `pip-audit` | tests and checks |

The lower limits of `curl_cffi` and `brotli` are the versions that correct known vulnerabilities.

On macOS 13, the `curl_cffi` 0.15 and 0.16 wheels need CoreFoundation before the import. If CoreFoundation is not loaded, `import curl_cffi` fails with `symbol not found in flat namespace`. An import of `accesspath` loads CoreFoundation through `httpx`. Linux and the CI do not have this problem.

### Manual installation

```bash
git clone https://github.com/lfoletti/accesspath.git && cd accesspath
python3 -m venv .venv
.venv/bin/pip install -e ".[inspect,tls]"                    # audit engine
.venv/bin/pip install -e ".[inspect,tls,browser,contents,dev]"   # all functions, tests, tools
```

The installation also makes the command `accesspath`. This command is the same as `python -m accesspath`.

### Installation from the lock files

The lock files have fixed versions and hashes, for Python 3.11 and later.

```bash
.venv/bin/pip install --require-hashes -r requirements.lock        # engine, inspect, tls
.venv/bin/pip install --require-hashes -r requirements-dev.lock    # all extras
.venv/bin/pip install --no-deps -e .
```

After a change to `pyproject.toml`, make the lock files again for Python 3.11 with `uv`:

```bash
uv pip compile pyproject.toml --generate-hashes --python-version 3.11 --extra inspect --extra tls -o requirements.lock
uv pip compile pyproject.toml --generate-hashes --python-version 3.11 --extra inspect --extra tls --extra browser --extra contents --extra dev -o requirements-dev.lock
```

## How the audit works

```
URL ──► probe (HTTP only)                        ──► recommended tier + report
          tier 1: declared doors, platform doors, then 20+ known paths
          tier 2: static HTML (WordPress? Next.js? SPA? inline data?)
          TLS:    one Chrome request if the home page refuses Python
          rate:   burst of 20 requests, 429 and Retry-After
          schema: sample of 100 items if an API answers

URL ──► inspect (Chrome through nodriver, 6 phases, stop at the first failure)
          A reachability   B anti-bot (Cloudflare, Akamai, PerimeterX, DataDome…)
          C framework      D network capture with bodies   E JSON islands
          F synthesis: difficulty (rules and nearest neighbours), tier, legal frame

URL ──► owner (probe + inspect, read for the site owner)

profile ──► verify / diff / show / rehearse
```

| File | Function |
|---|---|
| `accesspath/probe.py` | HTTP probe, without a browser |
| `accesspath/sap_inspect.py` | browser audit; nearest-neighbour classification on an optional annotated corpus (`ACCESSPATH_CORPUS`); legal frame of Krotov and Tennyson |
| `accesspath/owner.py` | owner report: findings, states and actions for the site owner |
| `accesspath/sap.py` | profiles, live audits, comparison |
| `accesspath/ghost.py` | ghost mode: HAR analysis and replay |
| `accesspath/human_gate.py`, `accesspath/gestures.py` | human steps and their queue |
| `accesspath/_http.py` | bounded HTTP, SSRF guard, Chrome imitation |
| `accesspath/stealth.py` | consistent browser headers |
| `accesspath/acquisition/` | content pages, known platforms, site patterns, learned patterns |

A profile in four files (`--emit-yaml`) has this order:

1. `01_identification`: what the site is.
2. `02_technical`: rendering, API, anti-bot.
3. `03_ethics`: `robots.txt`, terms of use, legal assessment.
4. `04_strategy`: difficulty, recommended tier, fallbacks, rehearsal status.

## Command options

| Option | Function |
|---|---|
| `--save` | Keeps the report and the profile entry. Without it, accesspath writes nothing. |
| `--name` | Site name. The default is the host. |
| `--headless` | Runs `inspect` without a window. The window mode is the default because it passes anti-bot checks better. |
| `--purpose research\|commercial\|personal\|journalism` | Changes the legal assessment. |
| `--emit-yaml` | Writes the profile in four files. |
| `--skeleton` | With `probe`, writes a collector skeleton in `sites/<name>.py` of the current folder. |
| `--copies` | With `probe`, always asks the Wayback Machine and Common Crawl. |
| `--timeout` | Capture time of `inspect`. |

## Batch audit

```bash
python -m accesspath sap batch sites.txt [--mode probe|inspect|history|contents] [--concurrency N] [--per-host-block N] [--deadline S] [--limit N] [--copies] [--resume]
```

- **Input.** A text file with one URL on each line (`#` starts a comment), or a CSV file with a `url` column. A `name` column is optional. The other columns go into the results. accesspath removes duplicate URLs and records the incorrect lines.
- **Shared hosting.** accesspath groups the sites by address block (IPv4 /24, IPv6 /48) and audits one site of a block at a time (`--per-host-block N` to change it). A site that waits for its block does not take a place in `--concurrency`. Without this limit, a shared host (for example Strato) cuts the connections of the batch address, and its sites come out as unreachable. Each line gives its `host_block`.
- **Mode `probe`** (default). The HTTP probe runs in the same process. The default is 8 sites at the same time, 32 at most. Each probe has a time limit of 180 seconds.
- **Mode `inspect`.** Each site runs in its own process group. The default is 4 sites at the same time, 8 at most. At the time limit (90 seconds), accesspath kills the full group, Chrome included.
- **Mode `history`.** The history of `robots.txt` in the Wayback Machine since 2020. accesspath reads a sample of 16 archived versions, then bisects between two versions that differ, to find the first changed version. For each AI crawler, the result gives the date of the first block and of a reopening. A date `≤YYYY-MM-DD` means that the crawler was already blocked in the first version read. The dates are capture dates: the change happened between the previous capture and this one. The default is 2 sites at the same time, 4 at most, with a pause of one second between two requests. After a 429, 5xx or refused connection, accesspath waits 10, 30, then 60 seconds. Some domains refuse the archive index (403); accesspath records the error.
- **Mode `contents`** (old name `projects`, still accepted). The content pages of a site (projects, works, articles, product sheets): where they are, how many, and how their images load. Sources in this order: the WordPress REST API (project content type, `X-WP-Total`), the index page of the site recipe (`accesspath/acquisition/websites.yaml`), the sitemap, a list page found from the home page (its name may carry `.html`, `.php` or a number: `projekte.html`, `work2`), and last the sitemap of a flat site (`/seefeld`, at least three pages that are not service pages). When the home page cannot be read, the line gives the reason (`home_error`: certificate refused, unreachable, HTTP status). On three content pages: images (tags, `srcset` width, lazy loading, direct links, CSS backgrounds, Open Graph), image hosts, and one image read without and with a `Referer`, if `robots.txt` allows it. With `ACCESSPATH_CONTENTS_ROOT`, the gap is the content pages online minus the pages already collected on disk. The default is 8 sites at the same time, 16 at most.
- **Known platforms.** A probe compares the site with `accesspath/acquisition/platforms.yaml`: the software platforms that the studies found (commercial registers: chregister, hrc-internet, Zefix; communes: i-web; site CMS: WordPress, Squarespace, TYPO3, Imaginator). A known platform gives its access recipe in the report, so a new instance does not need a new investigation.
- **Learned patterns.** At the end of a batch, signals that at least three sites share without a known platform (the declared generator, a host that the home page loads from) and project URL templates that only the depth heuristic found become candidates. accesspath adds the new ones to a local dataset (`~/.accesspath/patterns.local.yaml`, or `ACCESSPATH_PATTERNS_LOCAL`), outside the repository, and says how many. The detection uses them at once. `python -m accesspath sap patterns` lists them. `sap patterns share` shows the contribution report in English, without the campaign and site names (`--include-sites` adds the sites). `--send` opens a pull request that adds the patterns as a YAML file to `contrib/patterns/` (from a fork, as a draft, for a contributor).
- **Usage preferences.** In mode `probe`, each line also gives the blocked AI crawlers, `Content-Usage`, the TDM reservation, `llms.txt` and the paid access.
- **Output.** `data/batch/<list name>/results.jsonl` gets one line for each site when the site is done. `summary.md` gives the counts: status, tier, platform, TLS verdict, anti-bot vendor, doors.
- **Resume.** If `results.jsonl` exists, accesspath stops. Use `--resume` to continue the batch without the sites that are done.

## Ghost mode

1. Open the site in your browser. Do the steps that show the data.
2. In the developer tools, open the Network tab. Save the session as HAR.
3. Analyse the session:

   ```bash
   python -m accesspath ghost <site> --har session.har [--visible visible_text.txt] [--save]
   ```

4. Replay the calls:

   ```bash
   python -m accesspath ghost <site> --replay [--call 0] [--pages 3] [--delay 1] [--har fresh_session.har] [--save]
   ```

- **Analysis.** `ghost` removes static files, analytics and advertising. It sorts the data calls by the quantity of their JSON that shows on the page. It gives each parameter a role: pagination, cursor, constant or secret.
- **Replay.** The pagination moves by its step. The cursor comes from the previous response. The replay stops at the page limit, at an error, at an empty page, at a missing cursor or at a repeated response.
- **Secrets.** accesspath reads secrets from the variables `ACCESSPATH_SECRET_<NAME>` or from a fresh HAR. It never writes them to disk. If a secret is missing, no request goes out.
- **Warning.** A replay with a logged-in session is a disputed access. accesspath does not refuse it, but the output shows a warning.

## Human steps

Some sites need a person: an anti-bot challenge, a login or a consent page. `inspect` shows "✋ Geste humain requis" at the top of the report, with the machine name and the command `warmup <site> --at <url>`.

- With `--save`, the step goes into the queue `data/gestures.jsonl` (not tracked).
- A collector project can add tickets to the same queue (`accesspath.gestures.add`).
- `gestes` lists the queue. `gestes --faire` opens each page in Chrome. The ticket closes when the profile is ready.
- From a conversation with an agent, each step is a command that returns at once:
  - `gestes --ouvrir <site>` opens Chrome on the site's profile and leaves it open;
  - the person does the step, then answers: done, skip or useless;
  - `gestes --verifier <site>` reads the page again. If the page is served, the profile is marked ready and the ticket closes. If a challenge, a block page, an empty page or (for a consent ticket) a visible consent banner is still there, the window stays open;
  - `gestes --passer <site>` closes the window and keeps the ticket;
  - `gestes --ecarter <site> --motif "…"` closes the ticket with its reason.
- Chrome always starts with `--use-mock-keychain`. Without a graphical session (SSH, launchd), the macOS keychain is locked and Chrome saves no cookie: a warmed profile would keep nothing.
- `gestes --revoir [<site>…]` audits the tickets again with the current code and closes those without a step.
- Without a graphical session on the Mac (login screen, person over SSH), `--ouvrir` starts Chrome without a window. Over SSH, the window is on the Mac's screen, or there is none. Set `ACCESSPATH_CDP_PORT` (for example 9333), forward that port (`ssh -N -L 9333:127.0.0.1:9333 <mac>`), then open `chrome://inspect` on your own machine, add `localhost:9333` and click "inspect": DevTools shows the page live and you can click in it.
- Do the step on the machine that collects. A challenge that you pass on one machine is not valid on a different machine.

The audit finds the access that the site gives. It does not force a restricted access (login, payment, personal data).

## Collector projects

accesspath audits; a collector project collects. The project installs accesspath (`pip install -e ../accesspath`) and connects to it in three ways:

- **Data.** With `--save`, accesspath writes into `data/` of the current folder, or into `ACCESSPATH_DATA`.
- **Collectors.** `ACCESSPATH_SITES` names a Python package with a `REGISTRY` (name → configuration) and one module for each site. `sap verify <site>` then calls the `sap_verify()` function of the site module, and `warmup <site>` without `--at` uses the site home page.
- **Commands.** `accesspath.cli.build_parser()` and `accesspath.cli.DISPATCH` can be extended with the project's own sub-commands (`run`, `sanity`…).

`ACCESSPATH_PATTERNS` points to the full patterns file of the project (with its sites). The file in this repository is a public view: no site names and no addresses, and only the patterns that at least two sites share.

## Configuration

| Variable | Function |
|---|---|
| `ACCESSPATH_DIR` | repository folder for the skill; default `~/Documents/accesspath` |
| `ACCESSPATH_DATA` | folder for the data written with `--save`; default `./data` |
| `ACCESSPATH_SITES` | Python package of a collector project (see above) |
| `ACCESSPATH_PATTERNS` | full site patterns file; default the public view in the package |
| `ACCESSPATH_PATTERNS_LOCAL` | local learned patterns; default `~/.accesspath/patterns.local.yaml` |
| `ACCESSPATH_CORPUS` | annotated corpus for the nearest-neighbour prior of `inspect`; optional |
| `ACCESSPATH_CONTENTS_ROOT` | earlier collection on disk, compared by `sap batch --mode contents` |
| `ACCESSPATH_SECRET_<NAME>` | secrets for the ghost replay |
| `ACCESSPATH_ALLOW_PRIVATE` | `1` lets requests go to internal addresses (tests only) |
| `ACCESSPATH_INSECURE_HOSTS` | hosts without TLS certificate check, separated by commas |
| `ACCESSPATH_CHROME_PATH` | Chrome binary |
| `ACCESSPATH_CDP_PORT` | CDP port of Chrome for human steps; default: a random free port |
| `ACCESSPATH_CHROME_LOG_DIR` | folder of the Chrome stderr log (random file name, mode 0600) |

- **Credentials.** For a login step, `data/credentials.json` (not tracked) can give the login of a site; the collector module does the login.
- **TLS certificates.** accesspath always checks the certificate. It does not change to `verify=False` or to `http://`. To accept one host, add it to `ACCESSPATH_INSECURE_HOSTS` or to `data/insecure_hosts.txt` (one host per line). accesspath logs each accepted host.

## Safety

- **Site data.** accesspath removes control characters from site data. The data stays between `DATA_BEGIN` and `DATA_END`. `skill/SKILL.md` tells the agent to obey no instruction in this data.
- **Destinations.** accesspath refuses internal addresses (loopback, private networks, link-local, reserved) for the target, each redirect and each sitemap. The Chrome imitation follows the same rule. `--allow-private` removes this guard.
- **Bounded reads.** 10 MiB on the wire, 50 MiB decoded, a time limit for each request and for the full probe.
- **Politeness.** accesspath reads `robots.txt` first. It stops a burst at the first 429 or 503. It obeys `Retry-After`. It sends 4 parallel requests at most.
- **Writes.** accesspath validates site names and URLs. Each file stays in its folder.
- **Browser.** Each audit uses a temporary profile. Chrome stops and accesspath deletes the profile, also after an error.
- **Known limits.** DNS resolution and connection are two steps (DNS rebinding is possible). In `inspect`, accesspath checks the target only, not the sub-resources that Chrome loads.

## Data

Nothing is written without `--save`. With `--save`, in `data/` (or `ACCESSPATH_DATA`):

- `site_architecture_profiles.json`: one profile for each site;
- `sap_audits.jsonl`: audit history;
- `probes/`: `probe` and `inspect` reports; `sap/`: four-file profiles;
- `gestures.jsonl`: the queue of human steps; `profiles/`: Chrome profiles of the human steps;
- `batch/<list>/`: batch results.

## Tests and CI

```bash
.venv/bin/python -m pytest tests/test_sap_inspect.py   # SAP engine
.venv/bin/python -m pytest -m "not network"            # full suite, as in the CI
.venv/bin/python -m pytest --cov=accesspath               # with coverage
.venv/bin/ruff check .                                 # lint
```

A test that uses the network must have the marker `network`.

The CI (`.github/workflows/ci.yml`) runs on each pull request and on `main`:

- lint: `ruff check`, `ruff format --check`, and `mypy` on the engine (not blocking);
- tests on Python 3.11 and 3.13;
- `pip-audit` on the two lock files;
- `gitleaks` on the full history. `.gitleaksignore` lists the false positives that we examined.

pre-commit runs `ruff`, `gitleaks` and basic checks:

```bash
pip install pre-commit && pre-commit install
```

## Technology watch

The facts that change without notice (anti-bot signatures, platform APIs, machine-access standards) and the code lines that hold them are listed in [VEILLE.md](VEILLE.md).
