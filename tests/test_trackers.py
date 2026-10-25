"""Traceurs tiers : fournisseur et catégorie (régie, audience, enregistrement, réseau
social, balises, consentement, intégration), par domaine appelé et par signature HTML.
Les hôtes du site lui-même ne comptent pas ; un suffixe ne vaut qu'à une frontière de
label (« evil-doubleclick.net » n'est pas DoubleClick)."""

from __future__ import annotations

from accesspath.trackers import detect_trackers, site_domain

SITE = "https://www.example-commune.ch/"


def test_regie_par_domaine_appele():
    t = detect_trackers(["https://securepubads.g.doubleclick.net/tag/js/gpt.js"], "", SITE)
    assert t["vendors"]["Google Ad Manager"]["category"] == "régie"
    assert t["regies"] == ["Google Ad Manager"]
    assert t["categories"] == {"régie": 1}


def test_suffixe_a_une_frontiere_de_label():
    t = detect_trackers(["https://evil-doubleclick.net/x.js", "https://doubleclick.net.attacker.io/"], "", SITE)
    assert t["vendors"] == {}


def test_hotes_du_site_ignores_et_tiers_comptes():
    urls = [
        "https://www.example-commune.ch/app.js",
        "https://cdn.example-commune.ch/a.css",
        "https://www.google-analytics.com/g/collect?v=2",
        "https://unknown-cdn.net/lib.js",
    ]
    t = detect_trackers(urls, "", SITE)
    assert t["third_party_domains"] == ["google-analytics.com", "unknown-cdn.net"]
    assert t["vendors"]["Google Analytics"]["hosts"] == ["www.google-analytics.com"]
    assert t["vendors"]["Google Analytics"]["source"] == "réseau"


def test_signatures_html_et_scripts_du_html():
    html = (
        '<script>var _paq = window._paq || []; _paq.push(["trackPageView"]);</script>'
        '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-X"></script>'
    )
    t = detect_trackers([], html, SITE)
    assert t["vendors"]["Matomo (auto-hébergé)"]["category"] == "audience"
    assert t["vendors"]["Matomo (auto-hébergé)"]["source"] == "html"
    assert t["vendors"]["Google Tag Manager"]["category"] == "balises"
    assert t["vendors"]["Google Tag Manager"]["source"] == "html"


def test_matomo_auto_heberge_absent_si_matomo_cloud():
    html = '<script>_paq.push(["x"])</script>'
    t = detect_trackers(["https://example.matomo.cloud/matomo.js"], html, SITE)
    assert "Matomo Cloud" in t["vendors"] and "Matomo (auto-hébergé)" not in t["vendors"]


def test_regie_malgre_consentement():
    urls = ["https://consent.cookiebot.com/uc.js", "https://ib.adnxs.com/ut/v3"]
    t = detect_trackers(urls, "", SITE)
    assert t["consent_manager"] == ["Cookiebot"]
    assert t["regies"] == ["Xandr"]


def test_ordre_stable_et_categories_comptees():
    urls = [
        "https://connect.facebook.net/en_US/fbevents.js",
        "https://www.youtube-nocookie.com/embed/x",
        "https://fonts.gstatic.com/s/a.woff2",
        "https://static.hotjar.com/c/hotjar-1.js",
    ]
    t = detect_trackers(urls, "", SITE)
    assert list(t["vendors"]) == sorted(t["vendors"])
    assert t["categories"] == {"enregistrement": 1, "intégration": 2, "réseau social": 1}


def test_domaine_du_site():
    assert site_domain("https://www.gemeinde.example.ch/de/") == "example.ch"
    assert site_domain("https://news.bbc.co.uk/") == "bbc.co.uk"
    assert site_domain("https://example.ch") == "example.ch"


def test_recaptcha_par_chemin():
    urls = ["https://www.google.com/recaptcha/api2/anchor?k=x", "https://www.gstatic.com/recaptcha/releases/x/r.js"]
    t = detect_trackers(urls, "", SITE)
    assert t["vendors"]["reCAPTCHA"]["hosts"] == ["www.google.com", "www.gstatic.com"]
    assert t["unclassified"] == []


def test_google_hors_chemin_non_classe():
    t = detect_trackers(["https://www.google.com/search?q=x", "https://cdn.unknown.net/a.js"], "", SITE)
    assert t["vendors"] == {}
    assert t["unclassified"] == ["google.com", "unknown.net"]


def test_un_lien_n_est_pas_un_traceur():
    html = (
        '<a href="https://www.facebook.com/commune">Facebook</a>'
        '<a href="https://www.instagram.com/commune">Instagram</a>'
        '<link rel="canonical" href="https://other.example.net/x">'
        '<link rel="alternate" href="https://feeds.example.org/rss">'
    )
    t = detect_trackers([], html, SITE)
    assert t["vendors"] == {} and t["third_party_domains"] == []


def test_balises_qui_chargent_sont_lues():
    html = (
        '<iframe width="560" src="https://www.youtube-nocookie.com/embed/x"></iframe>'
        '<img alt="" src="//ct.pinterest.com/v3/?tid=1">'
        '<link href="https://fonts.googleapis.com/css2?family=X" rel="stylesheet">'
        "<link rel='preconnect' href='https://cdn.unknown.net'>"
        '<SCRIPT async SRC="https://static.hotjar.com/c/hotjar-1.js"></SCRIPT>'
    )
    t = detect_trackers([], html, SITE)
    assert sorted(t["vendors"]) == ["Google Fonts", "Hotjar", "Pinterest Tag", "YouTube"]
    assert t["unclassified"] == ["unknown.net"]


def test_ressources_non_http_ignorees():
    urls = ["data:image/png;base64,AAAA", "blob:https://x.ch/123", "about:blank", "chrome-extension://abc/x.js"]
    t = detect_trackers(urls, '<img src="data:image/gif;base64,R0">', SITE)
    assert t["third_party_domains"] == [] and t["unclassified"] == []


def test_adobe_fonts():
    t = detect_trackers(["https://use.typekit.net/abc.css"], "", SITE)
    assert t["vendors"]["Adobe Fonts"]["category"] == "intégration"
