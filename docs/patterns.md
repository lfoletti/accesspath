# Patterns, templates and platforms

Each audit and each collector teaches accesspath something about how sites are built: where the content is, how
the pages are named, how the images load, which software runs the site. This knowledge is kept in machine-readable
files, so the next site does not start from zero. This page explains the three layers and how the project uses them.

| Layer | File | What it holds | Who writes it |
|---|---|---|---|
| Site patterns and templates | `accesspath/acquisition/websites.yaml` | URL families, CMS profiles, ranked templates (public view: no site names) | a collector project, from its collectors |
| Known platforms | `accesspath/acquisition/platforms.yaml` | Software platforms that several sites share, with their access recipe | By hand, from the studies |
| Learned patterns | `~/.accesspath/patterns.local.yaml` | Candidates found after a campaign | `sap batch`, at the end of a batch |

## Site patterns

accesspath is a general tool, not a crawler for one kind of site. A collector project keeps one module for each site.
Its extraction reads these modules as text (it does not import them) and keeps only the values that differ from the
defaults:

- **CMS profiles.** WordPress, TYPO3, Drupal, Squarespace, Imaginator: body scope, project URL patterns, image paths,
  thumbnail suffixes to remove.
- **Families.** Values that several sites share: project URL patterns, lazy-loading attributes, image paths, body
  scopes, labels of the information table.
- **Recipes.** For each site: base URL, CMS, sitemap, index page, and whether the site needs the TLS fingerprint
  of Chrome.

The file in this repository is the **public view** of that knowledge (`patterns.public_view`): each family gives the
number of its sites (`n_sites`), never their names; recipes, index pages and template examples are removed; a pattern
that only one site carries is removed, because it would point to that site. A collector project uses its full file
with `ACCESSPATH_PATTERNS`.

## Templates: winning combinations

A template is a combination of choices that collects a site. The extraction describes each site by its signature:

| Choice | Values |
|---|---|
| `cms` | wordpress, typo3, … or `aucun` (none) |
| `url_pattern` | the default of the CMS, or an override |
| `discovery` | sitemap, index page, or both |
| `chrome_tls` | the site needs the TLS fingerprint of Chrome |
| `image_paths`, `thumb_strip` | the default of the CMS, or an override |

Sites with the same signature form a combination. A combination is a success on a site when the collection on
disk has projects and an image archive. The combinations are ranked by the **lower bound of the Wilson interval** of
their success rate, not by the raw rate: 3 successes out of 3 rank below 72 out of 85, because three sites prove
less. For each CMS, the template gives the **best** combination and its **variants**, in rank order, with the median
number of projects and of images per project.

Current result (October 2026):

| CMS | Best combination | Successes |
|---|---|---:|
| WordPress | defaults, sitemap | 72 / 85 |
| none (custom site) | defaults, sitemap | 253 / 324 |
| TYPO3 | defaults, sitemap | 3 / 3 |

What the ranking shows: the sitemap wins for every CMS. On custom sites, an index page alone works less often
(104 / 163). The Chrome-TLS variant collects (12 / 16) but gives only 0.5 images per project.

**How to use a template.** Before you write a collector for a new site, detect its CMS, start from the best
combination of that CMS, and try the variants in rank order when it fails.

## Where the project uses the patterns

- **Contents profile** (`sap batch --mode contents`, `accesspath/acquisition/contents.py`). A URL is a content page
  when a pattern matches it, from the general to the specific: generic patterns, CMS profiles, site families, learned
  patterns. The report gives the label of the pattern (`matched_by`): `famille:<n>` (or `site:<name>` with a full
  file) means that a family was decisive. With a full file, the recipe of a site gives its index page and sitemap.
- **Probe** (`sap probe`). The home page is compared with the known platforms. A match adds a "Plateforme connue"
  section to the report, with the recipe and the source of the knowledge. The batch row gets `known_platform`.
- **Collectors.** `match_project(doc, url)` and `site_for_url(doc, url)` in `accesspath/acquisition/patterns.py`
  give the pattern and the known site for any URL.

## Known platforms

Many sites run the same software. A known platform gives its recipe at once to a new instance. The base holds:

- **Commercial registers.** `chregister` (25 cantonal registers, JSF with a `ViewState`), `hrc-internet` (NE, VD, GE,
  FR, REST API with an `XSRF-TOKEN` cookie), `zefix` (national index).
- **Communes.** `i-web` (CMS of Swiss communes; its login form is not a login wall).
- **Site CMS.** WordPress, Squarespace, TYPO3, Imaginator.

Each entry has a detection (host patterns, instances on a shared host, HTML markers, headers, cookies), a recipe
(tier, discovery, endpoints, access, format), its instances, and its source. A marker that several platforms share,
such as an `XSRF-TOKEN` cookie alone, is not enough.

## Learned patterns

At the end of a batch, accesspath looks for signals that at least three sites share and that no known platform
explains: the declared generator (`<meta name="generator">`) and the hosts that the home page loads from (without
trackers, common resources and error-monitoring tools). Signals that live on the same sites form one pattern: the
generator "Wix.com" and the Wix hosts are one candidate, not three. Content URL templates that only the depth
heuristic found also become candidates.

```
3 nouveaux motifs ont été identifiés et ajoutés au dataset local (~/.accesspath/patterns.local.yaml)
  Share with the tool's creators: python -m accesspath sap patterns share
```

- The detection uses the new patterns at once.
- `python -m accesspath sap patterns` lists them, with their campaign and whether they were shared.
- `sap patterns share` shows the contribution in English, without the campaign and site names. `--include-sites`
  adds the sites. `--send` opens a pull request that adds a YAML file to `contrib/patterns/` in the tool
  repository: from a fork and as a draft for a contributor, from a branch for the maintainer. Nothing leaves before
  `--send`. The CI checks the format of each file; the maintainer promotes the good patterns to `platforms.yaml`.
- `sap batch <list> --relearn --out <dir>` learns again from a finished batch, and replaces its patterns that were
  not shared.

A learned pattern is a candidate. To make it a known platform, add its recipe to `platforms.yaml` with its source.
