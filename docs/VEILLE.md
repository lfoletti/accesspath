# Technology watch: what must go into the code

accesspath uses facts that change without notice: anti-bot rules, platform APIs, machine-access standards, case law. The code keeps fixed copies of these facts. The watch keeps them current. A watch result is useful only when it gives a tested code change.

## Sources

The maintainer follows these sources:

- RSS feeds: IETF AIPREF and Web Bot Auth, Cloudflare, DataDome, the Shopify and WordPress change logs, Common Crawl, Internet Archive, the blog of Eric Goldman, EFF, Zyte, Apify, The Web Scraping Club, Reddit (webscraping forum);
- OpenAlex and arXiv for the research.

A report of a change is welcome as an issue, with its source.

## From a theme to the code

When a watch result touches one of these lines, change the code. Write the test first and make sure that it fails before the change.

| Watch theme | Code to change | Test that must fail before the change |
|---|---|---|
| Anti-bot vendors: new cookie, header or challenge page title | `ANTI_BOT_SIGS`, `_COOKIE_FINGERPRINTS` (`accesspath/sap_inspect.py`), `CHALLENGE_MARKERS` (`accesspath/probe.py`) | `tests/test_sap_inspect.py`, `tests/test_tls_fingerprint.py` |
| Challenges and walls: vendor order, duration of a human step | `VENDOR_PRIORITY`, `EST_SECONDS` (`accesspath/human_gate.py`) | `tests/test_human_gate.py` |
| TLS fingerprint: new Chrome target, new refusal status | `IMPERSONATE_TARGET` (`accesspath/_http.py`), `TLS_REFUSAL_STATUSES` (`accesspath/probe.py`) | `tests/test_tls_fingerprint.py` |
| Platform APIs: new access point, new signature, deprecation | `PLATFORM_SIGNS`, `PLATFORM_DOORS` (`accesspath/probe.py`) | `tests/test_sap_probe_doors.py` |
| Machine-access standards: new declared link type, bot signature | `_DECLARED_TYPES`, `declared_doors`, robots (`accesspath/probe.py`) | `tests/test_sap_probe_doors.py`, `tests/test_sap_probe_polite.py` |
| Usage preferences and AI crawlers: AIPREF `Content-Usage`, TDMRep, `llms.txt`, new AI crawler name, Pay Per Crawl headers | `AI_CRAWLERS`, `TDM_FIELDS`, `parse_content_usage`, `pay_per_crawl` (`accesspath/usage_prefs.py`), `discover_usage` (`accesspath/probe.py`) | `tests/test_usage_prefs.py` |
| Third-party trackers: new ad network, analytics, consent manager | `TRACKERS`, `PATH_TRACKERS`, `HTML_SIGNATURES` (`accesspath/trackers.py`) | `tests/test_trackers.py` |
| Archives and crawl indexes: Wayback CDX or Common Crawl API change | `WAYBACK_CDX`, `CC_COLLINFO`, `wayback_copies`, `commoncrawl_copies` (`accesspath/probe.py`) | `tests/test_sap_probe_copies.py` |
| Collection law: court decision, standard terms of use, text and data mining opt-out | `THIRD_PARTY_LEGAL` (`accesspath/probe.py`), `_ethics_check` and the legal frame (`accesspath/sap_inspect.py`) | `tests/test_sap_inspect.py` |
| Subscriptions: new form of alert or newsletter | `_SUB_WORDS`, `find_subscriptions` (`accesspath/probe.py`) | `tests/test_sap_probe_suivi.py` |
| API reverse engineering: call shape, cursor name, secret header | `SECRET_NAME`, `PAGE_NAME`, `BROWSER_HEADERS`, `NOISE` (`accesspath/ghost.py`) | `tests/test_ghost.py`, `tests/test_ghost_replay.py` |

## Disputed access

accesspath does not refuse an access that is legally disputed or that can be against the terms of a site. The report and the SAP entry show an explicit **warning**, in the same form as the "third-party copy" flag of `probe`. The watch documents these accesses like the other topics.

## Schedule

Each month, or when an audit cannot get through a site, review the lines of the table above against the sources. Then make the change, with a test that fails first.
