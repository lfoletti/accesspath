"""Apprentissage de motifs après une campagne : candidats, dataset local, partage."""

from __future__ import annotations

import pytest
import yaml

from accesspath.acquisition import learn
from accesspath.acquisition import platforms as pf


@pytest.fixture(autouse=True)
def local(tmp_path, monkeypatch):
    path = tmp_path / "patterns.local.yaml"
    monkeypatch.setattr(learn, "LOCAL_FILE", path)
    monkeypatch.setattr(pf, "_DOC", None)
    return path


def _row(name, generator=None, hosts=(), known=()):
    return {
        "name": name,
        "url": f"https://{name}.ch/",
        "status": "ok",
        "generator": generator,
        "asset_hosts": list(hosts),
        "known_platform": list(known),
    }


def test_empreinte_de_l_accueil():
    html = (
        '<meta name="generator" content="Joomla! 4.2 - Open Source">'
        '<script src="https://cdn.example-cms.net/app.js"></script>'
        '<script src="https://www.googletagmanager.com/gtm.js"></script>'
        '<img src="/local.jpg"><link href="https://fonts.googleapis.com/css">'
    )
    fp = learn.fingerprint(html, "https://bureau.ch/")
    assert fp == {"generator": "Joomla! 4.2 - Open Source", "asset_hosts": ["cdn.example-cms.net"]}


def test_candidats_de_plateforme():
    rows = [_row(f"s{i}", generator=f"Joomla! {i}", hosts=["cdn.example-cms.net"]) for i in range(3)]
    rows += [_row("s9", generator="Joomla! 5", hosts=["cdn.example-cms.net"], known=["wordpress"])]
    rows += [_row("t1", generator="Rare"), _row("t2", hosts=["solo.example"])]
    cands = learn.platform_candidates(rows)
    assert [(c["name"], c["sites"]) for c in cands] == [("joomla!", 3)]
    assert cands[0]["markers"] == [
        {"kind": "generator", "marker": "joomla!"},
        {"kind": "asset_host", "marker": "cdn.example-cms.net"},
    ]


def test_signaux_des_memes_sites_forment_un_seul_motif():
    wix = [
        _row(f"w{i}", generator="Fabrik.io Builder", hosts=["assets.fabrik-cdn.example", "media.fabrik-cdn.example"])
        for i in range(4)
    ]
    wix.append(_row("w9", hosts=["media.fabrik-cdn.example"]))  # sans générateur : même plateforme
    other = [_row(f"o{i}", generator="Kirby 4") for i in range(3)]
    cands = learn.platform_candidates(wix + other)
    assert [(c["name"], c["sites"], len(c["markers"])) for c in cands] == [("fabrik.io", 5, 3), ("kirby", 3, 1)]


def test_outils_de_suivi_d_erreurs_exclus():
    html = '<script src="https://browser.sentry-cdn.com/7/b.js"></script><script src="https://js-agent.newrelic.com/n.js"></script>'
    assert learn.fingerprint(html, "https://b.ch/")["asset_hosts"] == []


def test_un_marqueur_deja_connu_n_est_pas_candidat():
    rows = [_row(f"s{i}", hosts=["static1.squarespace.com"]) for i in range(3)]
    assert learn.platform_candidates(rows) == []


def test_candidats_de_projets():
    rows = [
        {
            "name": f"b{i}",
            "status": "ok",
            "matched_by": "profondeur",
            "content_samples": [f"/batiments/{i}a/", f"/batiments/{i}b/"],
        }
        for i in range(2)
    ]
    rows.append({"name": "c", "status": "ok", "matched_by": "générique", "content_samples": ["/projekte/x/"]})
    cands = learn.content_candidates(rows)
    assert [(c["regex"], c["sites"]) for c in cands] == [("^/batiments/[^/]+/?$", 2)]


def test_enregistrement_et_annonce(local):
    rows = [_row(f"s{i}", generator="Joomla! 4", hosts=["cdn.example-cms.net"]) for i in range(3)]
    added = learn.learn_from_batch(rows, campaign="bureaux_2026-10")
    assert len(added) == 1
    assert learn.announce(added) == (
        f"1 nouveau motif a été identifié et ajouté au dataset local ({local})\n"
        "  Share with the tool's creators: python -m accesspath sap patterns share"
    )
    doc = yaml.safe_load(local.read_text())
    entry = doc["candidates"][0]
    assert entry["campaign"] == "bureaux_2026-10" and entry["examples"] == ["s0.ch", "s1.ch", "s2.ch"]
    assert learn.learn_from_batch(rows, campaign="encore") == []  # déjà connus
    assert learn.announce([]) == ""


def test_le_motif_local_sert_a_la_detection(local):
    rows = [_row(f"s{i}", hosts=["cdn.example-cms.net"]) for i in range(3)]
    learn.learn_from_batch(rows, campaign="c")
    pf._DOC = None
    hit = pf.detect("https://neuf.ch/", html='<script src="https://cdn.example-cms.net/a.js">')
    assert hit[0]["platform"] == "local:cdn.example-cms.net" and hit[0]["source"] == "dataset local (campagne c)"


def test_generateur_appris_reconnu():
    learn.learn_from_batch([_row(f"s{i}", generator="Joomla! 4") for i in range(3)], campaign="c")
    hit = pf.detect("https://neuf.ch/", html='<meta name="generator" content="Joomla! 5 - Open Source">')
    assert hit[0]["platform"] == "local:joomla!"


def test_reapprendre_remplace_les_motifs_non_partages_de_la_campagne(local):
    import yaml as y

    local.write_text(
        y.safe_dump(
            {
                "version": 1,
                "candidates": [
                    {
                        "kind": "generator",
                        "marker": "fabrik.io",
                        "sites": 3,
                        "examples": [],
                        "campaign": "c",
                        "shared": None,
                    },
                    {
                        "kind": "generator",
                        "marker": "x",
                        "sites": 3,
                        "examples": [],
                        "campaign": "autre",
                        "shared": None,
                    },
                    {
                        "kind": "generator",
                        "marker": "y",
                        "sites": 3,
                        "examples": [],
                        "campaign": "c",
                        "shared": "2026-10-25",
                    },
                ],
            }
        )
    )
    rows = [_row(f"w{i}", generator="Fabrik.io", hosts=["media.fabrik-cdn.example"]) for i in range(3)]
    added = learn.relearn(rows, campaign="c")
    kept = [(c["kind"], c.get("marker") or c.get("name")) for c in learn.load_local()["candidates"]]
    assert kept == [("generator", "x"), ("generator", "y"), ("platform", "fabrik.io")]
    assert len(added) == 1


def test_motif_de_projet_local_reconnu(local):
    from accesspath.acquisition import contents as pp

    rows = [
        {"name": f"b{i}", "status": "ok", "matched_by": "profondeur", "content_samples": [f"/batiments/{i}/"]}
        for i in range(2)
    ]
    learn.learn_from_batch(rows, campaign="c")
    doc = learn.with_local(pp._patterns(None))
    assert pp.content_label("https://x.ch/batiments/maison/", doc) == "local"


def test_partage_en_anglais_sans_les_sites(local):
    rows = [_row(f"s{i}", generator="Joomla! 4") for i in range(3)]
    learn.learn_from_batch(rows, campaign="bureaux_2026-10")
    text = learn.share_report()
    assert text.startswith("# accesspath pattern contribution: 1 new pattern")
    assert "generator `joomla!`" in text and "3 sites" in text
    assert "s0.ch" not in text and "bureaux_2026-10" not in text
    assert "s0.ch" in learn.share_report(include_sites=True)


class FakeGh:
    """Enregistre les appels à gh ; `login` est le compte qui partage."""

    def __init__(self, login):
        self.login, self.calls = login, []

    def __call__(self, args):
        self.calls.append(args)
        if args[:2] == ["api", "user"]:
            return self.login
        if args[0] == "api" and "git/ref/heads/main" in args[1]:
            return "abc123"
        if args[:2] == ["pr", "create"]:
            return "https://github.com/lfoletti/accesspath/pull/7"
        return ""


def test_fichier_de_contribution(local):
    learn.learn_from_batch([_row(f"s{i}", generator="Joomla! 4") for i in range(3)], campaign="camp")
    path, text = learn.contribution_file()
    assert path.startswith("contrib/patterns/") and path.endswith(".yaml")
    doc = yaml.safe_load(text)
    assert learn.validate_contribution(doc) == []
    assert doc["patterns"][0]["name"] == "joomla!" and doc["patterns"][0]["sites"] == 3
    assert "camp" not in text and "s0.ch" not in text
    assert "s0.ch" in learn.contribution_file(include_sites=True)[1]


def test_validation_de_contribution():
    bad = {"version": 1, "patterns": [{"kind": "platform", "sites": 2}, {"kind": "autre"}]}
    errors = learn.validate_contribution(bad)
    assert any("markers" in e for e in errors) and any("autre" in e for e in errors)
    regex = learn.validate_contribution(
        {"version": 1, "patterns": [{"kind": "content_url", "regex": "^/(", "sites": 2}]}
    )
    assert regex and "regex" in regex[0]


def test_partage_par_pull_request_depuis_un_fork(local, monkeypatch):
    learn.learn_from_batch([_row(f"s{i}", generator="Joomla! 4") for i in range(3)], campaign="c")
    gh = FakeGh("contributrice")
    monkeypatch.setattr(learn, "_gh", gh)
    assert learn.share(send=True) == "https://github.com/lfoletti/accesspath/pull/7"
    flat = [" ".join(c) for c in gh.calls]
    assert any(c.startswith("repo fork lfoletti/accesspath") for c in flat)
    assert any("repos/contributrice/accesspath/git/refs" in c for c in flat)
    put = next(c for c in gh.calls if c[:3] == ["api", "-X", "PUT"])
    assert put[3].startswith("repos/contributrice/accesspath/contents/contrib/patterns/")
    pr = next(c for c in gh.calls if c[:2] == ["pr", "create"])
    assert "--draft" in pr and "contributrice:patterns/" in " ".join(pr)
    assert learn.share_report().startswith("# accesspath pattern contribution: 0 new patterns")


def test_partage_par_le_mainteneur_sans_fork(local, monkeypatch):
    learn.learn_from_batch([_row(f"s{i}", generator="Joomla! 4") for i in range(3)], campaign="c")
    gh = FakeGh("lfoletti")
    monkeypatch.setattr(learn, "_gh", gh)
    learn.share(send=True)
    assert not any(c[:2] == ["repo", "fork"] for c in gh.calls)
    pr = next(c for c in gh.calls if c[:2] == ["pr", "create"])
    assert "--draft" not in pr and pr[pr.index("--head") + 1].startswith("patterns/")


def test_rien_a_partager(local, monkeypatch):
    gh = FakeGh("x")
    monkeypatch.setattr(learn, "_gh", gh)
    assert learn.share(send=True) == "nothing to share"
    assert gh.calls == []


def test_ligne_de_sonde():
    from accesspath import batch, probe

    r = probe.ProbeReport(url="https://x.ch/", timestamp="t")
    r.fingerprint = {"generator": "Joomla! 4", "asset_hosts": ["cdn.example-cms.net"]}
    row = batch.probe_row(r)
    assert row["generator"] == "Joomla! 4" and row["asset_hosts"] == ["cdn.example-cms.net"]


def test_ligne_de_projets_garde_les_chemins_d_exemple():
    from accesspath.acquisition import contents as pp

    p = {
        "source": "sitemap", "count": 2, "image_mode": None, "images_per_page": None, "max_width": None,
        "image_hosts": [], "image_check": None, "robots_images_allowed": None, "disk_contents": None, "gap": None,
        "matched_by": "profondeur", "sample": ["https://x.ch/batiments/a/", "https://x.ch/batiments/b/"],
    }  # fmt: skip
    row = pp.contents_row(p)
    assert row["matched_by"] == "profondeur" and row["content_samples"] == ["/batiments/a/", "/batiments/b/"]


def test_fin_de_lot_annonce_les_motifs(tmp_path, monkeypatch, capsys, local):
    import asyncio

    from accesspath import batch, cli

    def fake_runner(**kw):
        async def run(t):
            await asyncio.sleep(0)
            return {"status": "ok", "generator": "Joomla! 4", "asset_hosts": [], "known_platform": []}

        return run

    monkeypatch.setattr(batch, "probe_runner", fake_runner)
    f = tmp_path / "bureaux.csv"
    f.write_text("url,name\nhttps://a.ch,a\nhttps://b.ch,b\nhttps://c.ch,c\n")
    out = tmp_path / "lot"
    assert cli.main(["sap", "batch", str(f), "--out", str(out)]) == 0
    said = capsys.readouterr().out
    assert "1 nouveau motif a été identifié et ajouté au dataset local" in said
    assert "Share with the tool's creators" in said
    assert "## Motifs appris" in (out / "summary.md").read_text()
    assert learn.load_local()["candidates"][0]["campaign"] == "bureaux"


def test_commande_patterns(capsys, monkeypatch, local):
    from accesspath import cli

    learn.learn_from_batch([_row(f"s{i}", generator="Joomla! 4") for i in range(3)], campaign="c")
    assert cli.main(["sap", "patterns"]) == 0
    assert "joomla!" in capsys.readouterr().out
    assert cli.main(["sap", "patterns", "share"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# accesspath pattern contribution: 1 new pattern") and "--send" in out
    monkeypatch.setattr(learn, "_open_pr", lambda path, text, title, body: "https://github.com/x/2")
    assert cli.main(["sap", "patterns", "share", "--send"]) == 0
    assert "https://github.com/x/2" in capsys.readouterr().out


def test_commande_relearn(tmp_path, capsys, local):
    import json

    from accesspath import cli

    out = tmp_path / "lot"
    out.mkdir()
    rows = [{"url": f"https://w{i}.ch/", "name": f"w{i}", **_row(f"w{i}", generator="Fabrik.io")} for i in range(3)]
    (out / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    f = tmp_path / "bureaux.csv"
    f.write_text("url,name\nhttps://w0.ch,w0\n")
    assert cli.main(["sap", "batch", str(f), "--relearn", "--out", str(out)]) == 0
    assert "1 nouveau motif" in capsys.readouterr().out
    assert [c["name"] for c in learn.load_local()["candidates"]] == ["fabrik.io"]


@pytest.mark.parametrize(
    "generator", ["2018.1.1.386", "BBEdit 14.6", "Adobe Dreamweaver CS6", "Microsoft FrontPage 4.0"]
)
def test_generateurs_qui_ne_signent_pas_une_plateforme(generator):
    rows = [_row(f"s{i}", generator=generator) for i in range(3)]
    assert learn.platform_candidates(rows) == []


def test_generateur_d_extension_nomme_son_cms():
    rows = [_row(f"s{i}", generator="SEOmatic") for i in range(3)]
    assert [c["name"] for c in learn.platform_candidates(rows)] == ["craft"]


def test_bibliotheques_banales_exclues():
    html = "".join(
        f'<script src="https://{h}/x.js"></script>'
        for h in ("fast.fonts.net", "oss.maxcdn.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com")
    )
    assert learn.fingerprint(html, "https://b.ch/")["asset_hosts"] == []


def _content_rows(*paths):
    return [
        {
            "name": f"b{i}",
            "url": f"https://b{i}.ch/",
            "status": "ok",
            "matched_by": "profondeur",
            "content_samples": [p],
        }
        for i, p in enumerate(paths)
    ]


def test_gabarit_deja_reconnu_n_est_pas_candidat():
    assert learn.content_candidates(_content_rows("/projekte/a/", "/projekte/b/")) == []


@pytest.mark.parametrize("prefix", ["category", "tag", "portfolio_category", "kategorie", "de", "fr"])
def test_taxonomies_et_langues_seules_ne_sont_pas_des_gabarits(prefix):
    assert learn.content_candidates(_content_rows(f"/{prefix}/a/", f"/{prefix}/b/")) == []


def test_gabarit_neuf_retenu():
    cands = learn.content_candidates(_content_rows("/werkliste/a/", "/werkliste/b/"))
    assert [c["regex"] for c in cands] == ["^/werkliste/[^/]+/?$"]
