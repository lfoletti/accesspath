"""CLI : accesspath <sub-command>.

Sous-commandes :
  sap <action> ...           audit : probe, inspect, owner, batch, verify, diff, show, rehearse, patterns
  warmup <site> [--at URL]   lance Chrome avec fenêtre, attend l'humain, marque le profil prêt
  gestes [--faire|--ouvrir|--verifier|--passer|--ecarter SITE|--revoir]  file des gestes humains
  ghost <site> --har F       mode fantôme : une session HAR devient des appels rejouables

Un projet de collecte étend ce parseur (`build_parser`) et `DISPATCH` avec ses propres
sous-commandes.

Exit codes :
  0  succès
  1  erreur d'extraction / sanity cassée
  2  warmup nécessaire en mode unattended
  3  usage invalide
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

# Imports lourds (registre des ~1 240 sites, pipeline, Playwright, profils
# navigateur, statut) faits dans les cmd_* qui s'en servent : `sap probe` et
# `sap inspect` n'en ont pas besoin.

log = logging.getLogger("accesspath.sap")


# ── Sub-commands ──────────────────────────────────────────────────────────
def cmd_warmup(args: argparse.Namespace) -> int:
    """Prépare le profil Chrome d'un site : --at donne l'adresse ; sans --at, le collecteur
    branché (ACCESSPATH_SITES) la fournit."""
    from . import human
    from ._safe import UnsafeInput, normalize_target_url, validate_site_name
    from .config import sites_registry

    try:
        validate_site_name(args.site)
        at = normalize_target_url(args.at) if args.at else None
    except UnsafeInput as e:
        print(f"  ✗ {e}", file=sys.stderr)
        return 3
    site = sites_registry().get(args.site)
    if site is None:
        if at is None:
            print(f"  ✗ site {args.site!r} sans collecteur : donner l'adresse avec --at <url>", file=sys.stderr)
            return 3
        return 0 if asyncio.run(human.warmup_at(args.site, at)) else 2
    return 0 if asyncio.run(human.warmup(site, at)) else 2


def cmd_ghost(args: argparse.Namespace) -> int:
    """Mode fantôme : lit un HAR, imprime les gabarits d'appels, les écrit avec --save."""
    from . import ghost
    from ._safe import UnsafeInput, validate_site_name
    from .sap_inspect import DATA_BEGIN, DATA_END, neutralize

    try:
        name = validate_site_name(args.site)
    except UnsafeInput as e:
        print(f"refusé : {e}", file=sys.stderr)
        return 3
    if args.replay:
        return _ghost_replay(name, args)
    if args.openapi:
        return _ghost_openapi(name)
    if not args.har:
        print("--har est requis hors rejeu", file=sys.stderr)
        return 2
    visible = Path(args.visible).read_text(encoding="utf-8", errors="replace") if args.visible else None
    spec = ghost.build_spec(name, ghost.load_har(args.har), visible)
    print(f"Mode fantôme — {len(spec['calls'])} gabarit(s) d'appel de données")
    print(DATA_BEGIN)
    for line in ghost.summary_lines(spec):
        print(neutralize(line, max_len=300))
    print(DATA_END)
    if args.save:
        print(f"écrit : {ghost.save_spec(spec)}")
    return 0


def _ghost_openapi(name: str) -> int:
    """Écrit data/sap/<site>/openapi.json depuis ghost_spec.yaml. 4 : pas de spécification."""
    import yaml

    from . import ghost

    spec_file = ghost.SAP_DIR / name / "ghost_spec.yaml"
    if not spec_file.exists():
        print(f"pas de spécification : {spec_file} (python -m accesspath ghost {name} --har … --save)", file=sys.stderr)
        return 4
    spec = yaml.safe_load(spec_file.read_text(encoding="utf-8")) or {}
    spec.setdefault("site", name)
    spec.setdefault("calls", [])
    print(f"écrit : {ghost.save_openapi(spec)}")
    return 0


def _ghost_replay(name: str, args: argparse.Namespace) -> int:
    """Rejoue un gabarit. 4 : pas de spécification ; 5 : secrets manquants ; 1 : première page en échec."""
    import json

    import yaml

    from . import _http, ghost
    from .sap_inspect import DATA_BEGIN, DATA_END, neutralize

    spec_file = ghost.SAP_DIR / name / "ghost_spec.yaml"
    if not spec_file.exists():
        print(f"pas de spécification : {spec_file} (python -m accesspath ghost {name} --har … --save)", file=sys.stderr)
        return 4
    calls = yaml.safe_load(spec_file.read_text(encoding="utf-8")).get("calls") or []
    if not 0 <= args.call < len(calls):
        print(f"gabarit {args.call} absent ({len(calls)} gabarit(s))", file=sys.stderr)
        return 4
    t = calls[args.call]
    secrets, missing = ghost.resolve_secrets(t, ghost.load_har(args.har) if args.har else None)
    if missing:
        names = ", ".join(ghost.env_name(m) for m in missing)
        print(
            f"secrets manquants : {names} (variables d'environnement, ou --har d'une session fraîche)", file=sys.stderr
        )
        return 5
    print(f"Rejeu fantôme — {t['method']} {neutralize(t['url'], max_len=200)}")
    if secrets:
        print(
            "⚠ voie litigieuse : rejeu d'une session authentifiée (cookies ou jetons du porteur) ; "
            "les conditions d'utilisation du site peuvent l'interdire."
        )
    with _http.client() as c:
        pages = ghost.replay(t, c, secrets, pages=args.pages, delay=args.delay)
    print(DATA_BEGIN)
    for p in pages:
        flag = " (réponse répétée)" if p["repeated"] else ""
        print(f"page {p['page']} : statut {p['status']}, {p['items']} élément(s){flag}")
    print(DATA_END)
    if args.save:
        out = ghost.SAP_DIR / name / "ghost_replay.jsonl"
        with out.open("w", encoding="utf-8") as f:
            for p in pages:
                f.write(json.dumps(p, ensure_ascii=False) + "\n")
        print(f"écrit : {out}")
    return 0 if pages and 200 <= pages[0]["status"] < 300 else 1


def _sap_batch(args: argparse.Namespace) -> int:
    """sap batch <fichier> : audite chaque site de la liste ; 3 si la liste ou les bornes sont refusées."""
    from . import _http, batch
    from ._safe import UnsafeInput

    mode = "contents" if args.mode == "projects" else args.mode  # ancien nom du mode contents
    concurrency = batch.DEFAULT_CONCURRENCY[mode] if args.concurrency is None else args.concurrency
    if not 1 <= concurrency <= batch.MAX_CONCURRENCY[mode]:
        print(f"  ✗ --concurrency : de 1 à {batch.MAX_CONCURRENCY[mode]} en mode {mode}", file=sys.stderr)
        return 3
    if not args.target or not Path(args.target).is_file():
        print(f"  ✗ liste de sites introuvable : {args.target}", file=sys.stderr)
        return 3
    try:
        name = batch.batch_name(args.target)
    except UnsafeInput as e:
        print(f"  ✗ {e}", file=sys.stderr)
        return 3
    out_dir = Path(args.out) if args.out else batch.BATCH_DIR / name
    if args.relearn:
        if not (out_dir / "results.jsonl").exists():
            print(f"  ✗ pas de lot à réapprendre : {out_dir / 'results.jsonl'}", file=sys.stderr)
            return 3
        from .acquisition import learn

        added = learn.relearn(batch.read_results(out_dir / "results.jsonl"), campaign=name)
        print("  " + (learn.announce(added) or "aucun motif nouveau"))
        return 0
    if args.retrackers:
        if not (out_dir / "results.jsonl").exists():
            print(f"  ✗ pas de lot à reclasser : {out_dir / 'results.jsonl'}", file=sys.stderr)
            return 3
        n = batch.refresh_trackers(out_dir)
        rows = batch.read_results(out_dir / "results.jsonl")
        (out_dir / "summary.md").write_text(batch.summarize(name, rows), encoding="utf-8")
        print(f"  {n} site(s) reclassé(s) ; écrit : {out_dir / 'summary.md'}")
        return 0
    if (out_dir / "results.jsonl").exists() and not args.resume:
        print(f"  ✗ {out_dir / 'results.jsonl'} existe déjà : --resume pour reprendre", file=sys.stderr)
        return 3
    targets, invalid = batch.read_targets(args.target)
    if args.limit:
        targets = targets[: args.limit]
    _http.set_allow_private(bool(args.allow_private))
    deadline = args.deadline or batch.SITE_DEADLINE_S[mode]
    if mode == "probe":
        runner = batch.probe_runner(deadline=deadline, copies=bool(args.copies))
    elif mode == "history":
        runner = batch.history_runner(deadline=deadline)
    elif mode == "contents":
        runner = batch.contents_runner(deadline=deadline)
    else:
        configs = (",".join(batch.DEFAULT_ROTATION) if args.configs is None else args.configs).split(",")
        if not configs or any(c not in batch.INSPECT_CONFIGS for c in configs):
            print(f"  ✗ --configs : parmi {', '.join(batch.INSPECT_CONFIGS)}", file=sys.stderr)
            return 3
        runner = batch.inspect_runner(
            configs=configs,
            deadline=deadline,
            allow_private=bool(args.allow_private),
            browser=bool(args.browser),
            profiles_dir=out_dir / "profils",
        )
    print(
        f"  batch {name} : {len(targets)} site(s), mode {mode}, {concurrency} à la fois, "
        f"au plus {max(1, args.per_host_block)} par hébergeur, {len(invalid)} ligne(s) refusée(s)"
    )
    import asyncio

    t0 = batch.clock()
    asyncio.run(
        batch.run_batch(
            targets,
            runner=runner,
            concurrency=concurrency,
            out_dir=out_dir,
            resume=args.resume,
            per_block=max(1, args.per_host_block),
        )
    )
    elapsed = batch.clock() - t0
    rows = batch.read_results(out_dir / "results.jsonl")
    summary = out_dir / "summary.md"
    text = batch.summarize(name, rows, invalid=invalid, elapsed_s=elapsed)
    from .acquisition import learn

    added = learn.learn_from_batch(rows, campaign=name)
    if added:
        text += (
            "\n## Motifs appris\n\n" + "\n".join(f"- {learn.describe(c)} : {c['sites']} sites" for c in added) + "\n"
        )
    summary.write_text(text, encoding="utf-8")
    print(f"  écrit : {out_dir / 'results.jsonl'}")
    print(f"  écrit : {summary}")
    if added:
        print("  " + learn.announce(added))
    return 0


def _sap_patterns(args: argparse.Namespace) -> int:
    """Motifs appris : liste du dataset local ; share prépare (ou, avec --send, envoie) le partage."""
    from .acquisition import learn

    if args.target == "share":
        result = learn.share(send=args.send, include_sites=args.include_sites)
        print(result)
        if not args.send:
            print(
                f"Send to the tool's creators ({learn.UPSTREAM_REPO}): python -m accesspath sap patterns share --send"
            )
        return 0
    doc = learn.load_local()
    print(f"  dataset local : {learn.LOCAL_FILE} ; {len(doc['candidates'])} motif(s)")
    for c in doc["candidates"]:
        state = f"partagé le {c['shared']}" if c.get("shared") else "non partagé"
        print(f"  - {learn.describe(c)} : {c['sites']} sites ({c['campaign']}, {state})")
    return 0


def cmd_gestes(args: argparse.Namespace) -> int:
    """Liste la file de gestes humains ; --faire les ouvre un par un au terminal. Depuis la
    conversation : --ouvrir, puis --verifier, --passer ou --ecarter ; --revoir réaudite."""
    from . import gestures, human
    from ._safe import UnsafeInput, validate_site_name

    one = args.ouvrir or args.verifier or args.passer or args.ecarter
    if one or args.revoir:
        try:
            for name in [one] if one else args.revoir:
                validate_site_name(name)
        except UnsafeInput as e:
            print(f"  ✗ {e}", file=sys.stderr)
            return 3
    if one:
        return _geste_un_site(args, one)
    if args.revoir is not None:
        return asyncio.run(_revoir_gestes(args.revoir))
    todo = gestures.pending()
    if not todo:
        print("  ✓ aucun geste en attente")
        return 0
    print(f"  ✋ {len(todo)} gestes en attente" if len(todo) > 1 else "  ✋ 1 geste en attente")
    for g in todo:
        print(f"     - {g.site:24s} {g.kind:10s} {g.open_url}  ({g.reason}, {g.at})")
    if not args.faire:
        print("  → python -m accesspath gestes --faire  (ouvre chaque page dans Chrome, Entrée quand c'est fait)")
        return 0
    if human.detect_policy() == human.HumanPolicy.UNATTENDED:
        print("  ✗ gestes --faire demande un humain au terminal", file=sys.stderr)
        return 2
    worst = 0
    for g in todo:
        if not asyncio.run(human.warmup_at(g.site, g.open_url)):
            worst = 2
    return worst


def _geste_un_site(args: argparse.Namespace, name: str) -> int:
    from . import gestures, human

    ticket = next((g for g in gestures.pending() if g.site == name), None)
    if args.ouvrir or args.ecarter:
        if ticket is None:
            print(f"  ✗ aucun geste en attente pour {name}", file=sys.stderr)
            return 3
    if args.ouvrir:
        st, launched = asyncio.run(human.open_gesture(ticket))
        print(
            f"  🪟 [{name}] Chrome {'ouvert' if launched else 'déjà ouvert'} : {st['url']} ({ticket.kind}, {ticket.reason})"
        )
        print(
            f"     à distance : ssh -N -L {st['port']}:127.0.0.1:{st['port']} <mac>, puis chrome://inspect, localhost:{st['port']}"
        )
        print(f"     fait    : python -m accesspath gestes --verifier {name}")
        print(f"     passer  : python -m accesspath gestes --passer {name}")
        print(f'     inutile : python -m accesspath gestes --ecarter {name} --motif "…"')
        return 0
    if args.verifier:
        res = asyncio.run(human.check_gesture(name))
        if res is None:
            print(
                f"  ✗ aucune fenêtre ouverte pour {name} : python -m accesspath gestes --ouvrir {name}", file=sys.stderr
            )
            return 3
        ok, why = res
        print(f"  {'✅' if ok else '✗'} [{name}] {why}" + ("" if ok else " ; la fenêtre reste ouverte"))
        return 0 if ok else 2
    if args.passer:
        closed = asyncio.run(human.pass_gesture(name))
        print(f"  ↷ [{name}] {'fenêtre fermée, ' if closed else ''}ticket gardé")
        return 0
    asyncio.run(human.drop_gesture(name, args.motif or ""))
    print(f"  ✗ [{name}] ticket fermé : inutile{' : ' + args.motif if args.motif else ''}")
    return 0


async def _revoir_gestes(names: list[str]) -> int:
    """Réaudite chaque ticket (défi, connexion, consentement) avec le code actuel ; ferme
    ceux où l'audit n'annonce plus de geste. Les profils froids (warmup) ne s'auditent pas."""
    from . import gestures, sap_inspect

    todo = [g for g in gestures.pending() if g.kind != "warmup" and (not names or g.site in names)]
    for g in todo:
        try:
            rep = await sap_inspect.inspect(g.open_url, g.site, headless=True)
        except Exception as e:
            print(f"  ? [{g.site}] audit impossible : {e}")
            continue
        if rep.human_gate is not None:
            print(f"  ✋ [{g.site}] geste toujours requis : {rep.human_gate.kind}")
            continue
        reach = rep.reachability
        parts = (["refus net"] if reach.hard_block else []) + (
            [f"redirige vers {reach.redirected_to}"] if reach.redirected_to else []
        )
        why = "revu : " + (", ".join(parts) or "voie libre")
        gestures.resolve(g.site, why=why)
        print(f"  ✓ [{g.site}] ticket fermé ({why})")
    return 0


def cmd_sap(args: argparse.Namespace) -> int:
    from ._safe import (
        UnsafeInput,
        name_from_url,
        normalize_target_url,
        validate_site_name,
    )
    from .sap import (
        diff_results,
        load_audits,
        load_profiles,
        print_result,
        save_audit,
        verify_site,
    )

    # Validation centrale : URL (probe/inspect) ou nom de site (autres actions),
    # et --name, avant toute requête ou écriture.
    if args.action == "batch":
        return _sap_batch(args)
    if args.action == "patterns":
        return _sap_patterns(args)
    try:
        if args.action in ("probe", "inspect", "owner"):
            if args.target:
                args.target = normalize_target_url(args.target)
        elif args.target:
            validate_site_name(args.target)
        if args.name:
            validate_site_name(args.name)
    except UnsafeInput as e:
        print(f"  ✗ {e}", file=sys.stderr)
        return 3

    from . import _http

    _http.set_allow_private(bool(getattr(args, "allow_private", False)))

    if args.action == "show":
        profiles = load_profiles()
        if args.all:
            for name in sorted(profiles):
                print(f"\n=== {name} ===")
                print(json.dumps(profiles[name], indent=2, ensure_ascii=False)[:2000])
        elif args.target:
            audits = load_audits(args.target)
            if args.target not in profiles and not audits:
                print(f"  ✗ {args.target} absent de site_architecture_profiles.json et sans audit")
                return 1
            if args.target in profiles:
                print(json.dumps(profiles[args.target], indent=2, ensure_ascii=False))
            else:
                print(f"  (pas de profil pour {args.target} dans site_architecture_profiles.json)")
            if audits:
                last = audits[-1]
                print(f"\n  Dernier audit : {last.timestamp[:19]} — {last.overall.upper()}")
                print_result(last)
            else:
                print("\n  Dernier audit : aucun (lancer `sap verify <site> --save`)")
        else:
            print(f"  Sites profilés ({len(profiles)}) : {', '.join(sorted(profiles))}")
        return 0

    if args.action == "verify":
        from .config import sites_registry

        registry = sites_registry()
        sites = sorted(registry) if args.all else [args.target] if args.target else []
        if not sites:
            print("  ✗ specifie un site ou --all")
            return 3
        unknown = [s for s in sites if s not in registry]
        if unknown:
            print(
                f"  ✗ sans collecteur branché (ACCESSPATH_SITES) : {', '.join(unknown)}",
                file=sys.stderr,
            )
            return 3
        worst = "pass"
        for s in sites:
            result = asyncio.run(verify_site(s))
            print_result(result)
            if args.save:
                save_audit(result)
            if result.overall == "fail":
                worst = "fail"
            elif result.overall == "warn" and worst == "pass":
                worst = "warn"
        return 0 if worst == "pass" else (1 if worst == "fail" else 0)

    if args.action == "diff":
        if not args.target:
            print("  ✗ specifie un site")
            return 3
        audits = load_audits(args.target)
        if len(audits) < 2:
            print(f"  ✗ {args.target} : besoin de ≥2 audits (trouvé {len(audits)})")
            return 1
        print(diff_results(audits[-2], audits[-1]))
        return 0

    if args.action == "probe":
        from .probe import emit_markdown, probe, save_findings

        if not args.target:
            print("  ✗ probe : specifie une URL (ex: https://www.designboom.com)")
            return 3
        url = args.target  # déjà validée et normalisée
        try:
            name = args.name or name_from_url(url)
        except UnsafeInput:
            print(
                "  ✗ probe : impossible de déduire le nom — utilise --name",
                file=sys.stderr,
            )
            return 3

        try:
            report = asyncio.run(probe(url, copies=True if args.copies else None))
        except Exception as e:  # échéance, destination refusée, panne réseau…
            log.error("  ✗ probe : %s: %s", type(e).__name__, e)
            return 1
        from .probe import door_changes

        report.door_changes = door_changes(load_profiles().get(name, {}), report)
        print(emit_markdown(report, name))
        subs = report.tier1.get("subscriptions") or []
        if args.save and subs:
            from . import gestures

            if gestures.add(name, "subscribe", subs[0]["url"], f"s'inscrire ({subs[0]['kind']}) avec l'adresse dédiée"):
                log.info("  ✋ abonnement ajouté à la file : python -m accesspath gestes")

        if args.save or args.skeleton:
            written = save_findings(report, name, save_skeleton=args.skeleton)
            log.info("  📝 Findings écrits :")
            for k, v in written.items():
                log.info("     %-10s: %s", k, v)
        else:
            log.info(
                "  ℹ️  Pour persister : ajoute --save (ou --skeleton pour aussi générer sites/%s.py)",
                name,
            )
        reached = bool(report.tier1.get("found")) or bool(report.tier2.get("fetched"))
        if not reached:
            log.error("  ✗ probe : aucune réponse exploitable du site")
            return 1
        return 0

    if args.action == "owner":
        from . import owner

        if not args.target:
            print("  ✗ owner : specifie une URL", file=sys.stderr)
            return 3
        try:
            name = args.name or name_from_url(args.target)
        except UnsafeInput:
            print("  ✗ owner : impossible de déduire le nom — utilise --name", file=sys.stderr)
            return 3
        p, i = asyncio.run(
            owner.audit(
                args.target,
                name,
                headless=bool(getattr(args, "headless", False)),
                timeout=float(getattr(args, "timeout", None) or 30.0),
            )
        )
        if p is None and i is None:
            return 1
        print(owner.to_markdown(args.target, owner.findings(p, i)))
        return 0

    if args.action == "inspect":
        from .sap_inspect import emit_yaml_shards, inspect, save_report, to_markdown

        if not args.target:
            print("  ✗ inspect : specifie une URL")
            return 3
        if getattr(args, "emit_yaml", False) and not args.save:
            print(
                "  ✗ inspect : --emit-yaml écrit data/sap/<site>/ et exige --save",
                file=sys.stderr,
            )
            return 3
        url = args.target  # déjà validée et normalisée
        try:
            name = args.name or name_from_url(url)
        except UnsafeInput:
            print(
                "  ✗ inspect : impossible de déduire le nom — utilise --name",
                file=sys.stderr,
            )
            return 3

        timeout = float(getattr(args, "timeout", None) or 30.0)
        headless = bool(getattr(args, "headless", False))
        purpose = getattr(args, "purpose", None) or "research"

        try:
            report = asyncio.run(
                inspect(
                    url,
                    name,
                    headless=headless,
                    timeout=timeout,
                    purpose=purpose,
                    save_partial=bool(args.save),
                    force_browser=bool(getattr(args, "browser", False)),
                )
            )
        except Exception as e:
            log.error("  ✗ inspect : %s: %s", type(e).__name__, e)
            return 1
        print(to_markdown(report))
        if args.save:
            written = save_report(report)
            if report.human_gate:
                from . import gestures

                g = report.human_gate
                why = "; ".join([f"{g.kind} {g.vendor}".strip(), *g.evidence])
                if gestures.add(name, g.kind, g.open_url, why):
                    log.info("  ✋ geste ajouté à la file : python -m accesspath gestes")
            log.info("  📝 Inspect findings écrits :")
            for k, v in written.items():
                log.info("     %-10s: %s", k, v)
        else:
            log.info("  ℹ️  Pour persister : ajoute --save")
        if getattr(args, "emit_yaml", False):
            shards = emit_yaml_shards(report)
            log.info("  🧩 SAP V2 shards émis :")
            for k, v in shards.items():
                log.info("     %-28s: %s", k, v)
        if report.reachability.status == "error":
            log.error("  ✗ inspect : site injoignable (%s)", report.reachability.evidence)
            return 1
        return 0

    if args.action == "rehearse":
        from .sap_inspect import rehearse_strategy

        if not args.target:
            print("  ✗ rehearse : specifie un nom de site (ex: dezeen)")
            return 3
        name = args.target
        log.info("  🎬 Rehearsal strategy for %s…", name)
        result = rehearse_strategy(name, save=bool(args.save))
        status = result.get("status", "FAIL")
        emoji = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "DEFERRED": "⏭️"}.get(status, "?")
        print(f"\n  {emoji} {status} — Tier {result.get('tier')}")
        for ev in result.get("evidence", []):
            print(f"     · {ev}")
        # Pretty-print key fields if present
        for k in (
            "endpoint",
            "sample_url",
            "sample_title",
            "n_items",
            "n_og_tags",
            "n_jsonld_blocks",
            "fields_present",
            "fields_missing",
        ):
            if k in result:
                print(f"     {k:<18}: {result[k]}")
        return 1 if status == "FAIL" else 0

    return 3


# ── Parser ────────────────────────────────────────────────────────────────
def build_parser(extend=None, prog: str = "accesspath") -> argparse.ArgumentParser:
    """Parseur du moteur ; `extend(sub)` ajoute les sous-commandes d'un projet de collecte."""
    p = argparse.ArgumentParser(prog=prog)
    sub = p.add_subparsers(dest="cmd", required=True)

    warm = sub.add_parser("warmup", help="lance Chrome headed, warmup interactif")
    warm.add_argument("site")
    warm.add_argument("--at", default=None, help="URL à ouvrir ; permet un site sans collecteur")

    ges = sub.add_parser("gestes", help="file des gestes humains en attente (défi, connexion, consentement)")
    ges_do = ges.add_mutually_exclusive_group()
    ges_do.add_argument("--faire", action="store_true", help="ouvre chaque geste dans Chrome, un par un (terminal)")
    ges_do.add_argument("--ouvrir", metavar="SITE", help="ouvre Chrome sur le geste du site et rend la main")
    ges_do.add_argument("--verifier", metavar="SITE", help="relit la page ouverte ; servie : profil prêt, ticket fermé")
    ges_do.add_argument("--passer", metavar="SITE", help="ferme la fenêtre, garde le ticket")
    ges_do.add_argument("--ecarter", metavar="SITE", help="ferme le ticket : geste inutile")
    ges_do.add_argument("--revoir", nargs="*", metavar="SITE", help="réaudite les tickets, ferme ceux sans geste")
    ges.add_argument("--motif", default="", help="avec --ecarter : pourquoi le geste est inutile")

    gho = sub.add_parser("ghost", help="mode fantôme : un HAR de navigation devient des appels rejouables")
    gho.add_argument("site")
    gho.add_argument(
        "--har",
        default=None,
        help="session exportée du navigateur (onglet Réseau, format HAR) ; au rejeu, source facultative des secrets",
    )
    gho.add_argument("--visible", default=None, help="texte affiché à l'écran, pour reconnaître les appels de données")
    gho.add_argument(
        "--save", action="store_true", help="écrit data/sap/<site>/ghost_spec.yaml (au rejeu : ghost_replay.jsonl)"
    )
    gho.add_argument("--replay", action="store_true", help="rejoue un gabarit de ghost_spec.yaml sans navigateur")
    gho.add_argument("--openapi", action="store_true", help="écrit data/sap/<site>/openapi.json depuis ghost_spec.yaml")
    gho.add_argument("--call", type=int, default=0, help="rang du gabarit à rejouer (0 : le plus probant)")
    gho.add_argument("--pages", type=int, default=3, help="pages rejouées au plus")
    gho.add_argument("--delay", type=float, default=1.0, help="secondes entre deux requêtes")

    p_sap = sub.add_parser(
        "sap",
        help="Site Architecture Profile : verify/diff/show/probe/inspect/owner/rehearse",
    )
    p_sap.add_argument(
        "action", choices=["verify", "show", "diff", "probe", "inspect", "owner", "rehearse", "batch", "patterns"]
    )
    p_sap.add_argument(
        "target",
        nargs="?",
        help="nom du site (verify/show/diff), URL (probe/inspect), fichier de sites (batch) ou share (patterns)",
    )
    p_sap.add_argument(
        "--send", action="store_true", help="patterns share : ouvre la pull request sur le dépôt de l'outil"
    )
    p_sap.add_argument(
        "--include-sites", action="store_true", help="patterns share : joint les sites d'exemple au partage"
    )
    p_sap.add_argument(
        "--relearn",
        action="store_true",
        help="batch : réapprend les motifs d'un lot fini depuis ses résultats (remplace ses motifs non partagés)",
    )
    p_sap.add_argument(
        "--retrackers",
        action="store_true",
        help="batch : reclasse les traceurs d'un lot inspecté depuis ses profils, sans relancer Chrome",
    )
    p_sap.add_argument(
        "--mode",
        choices=["probe", "inspect", "history", "contents", "projects"],
        default="probe",
        help="batch : audit lancé par site (history : robots.txt archivé et robots d'IA ; contents : pages de contenu d'un site et leurs images ; projects, ancien nom)",
    )
    p_sap.add_argument("--concurrency", type=int, default=None, help="batch : sites audités à la fois")
    p_sap.add_argument("--deadline", type=float, default=None, help="batch : secondes au plus par site")
    p_sap.add_argument(
        "--per-host-block",
        type=int,
        default=1,
        help="batch : sites d'un même bloc d'adresses (hébergeur mutualisé) audités à la fois",
    )
    p_sap.add_argument("--limit", type=int, default=None, help="batch : premiers sites de la liste seulement")
    p_sap.add_argument("--resume", action="store_true", help="batch : reprendre un lot, sans refaire les sites faits")
    p_sap.add_argument(
        "--configs",
        type=str,
        default=None,
        help="batch inspect : configurations essayées dans l'ordre (headless-30,headless-12 ; visible-30 ouvre des fenêtres)",
    )
    p_sap.add_argument("--out", type=str, default=None, help="batch : dossier de sortie (défaut data/batch/<liste>)")
    p_sap.add_argument("--all", action="store_true", help="appliquer à tous les sites")
    p_sap.add_argument(
        "--save",
        action="store_true",
        help="probe/inspect/verify/rehearse : persiste (rapport, entrée SAP, audit, "
        "04_strategy.yaml). Sans --save, rien n'est écrit.",
    )
    p_sap.add_argument(
        "--copies",
        action="store_true",
        help="probe : interroge aussi les copies tierces (Wayback CDX, Common Crawl) ; "
        "sans l'option, seulement quand le site ne laisse passer aucune porte",
    )
    p_sap.add_argument(
        "--skeleton",
        action="store_true",
        help="probe : génère sites/{name}.py squelette (impl --save)",
    )
    p_sap.add_argument(
        "--name",
        type=str,
        default=None,
        help="probe/inspect : nom du site (défaut : déduit du host)",
    )
    p_sap.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="inspect : durée de capture en secondes (défaut 30)",
    )
    p_sap.add_argument(
        "--browser",
        action="store_true",
        help="inspect : ouvre Chrome même si HTTP suffit (traceurs chargés en JavaScript)",
    )
    p_sap.add_argument(
        "--headless",
        action="store_true",
        help="inspect : force headless (défaut headed = mieux contre anti-bot)",
    )
    p_sap.add_argument(
        "--purpose",
        type=str,
        default="research",
        choices=["research", "commercial", "personal", "journalism"],
        help="inspect : purpose pour scoring legal_check (Krotov framework)",
    )
    p_sap.add_argument(
        "--allow-private",
        action="store_true",
        help="probe/inspect/rehearse : autorise les adresses internes (127.0.0.1, 10/8, "
        "192.168/16, link-local…). Refusées par défaut.",
    )
    p_sap.add_argument(
        "--emit-yaml",
        action="store_true",
        help="inspect : émet aussi data/sap/<name>/{01..04}_*.yaml (V2 sharded profile) ; exige --save",
    )

    if extend is not None:
        extend(sub)
    return p


def _setup_logging() -> None:
    """Progression sur stderr ; stdout reste réservé au rapport."""
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


DISPATCH = {
    "warmup": cmd_warmup,
    "gestes": cmd_gestes,
    "ghost": cmd_ghost,
    "sap": cmd_sap,
}


def main(argv: list[str] | None = None, *, extend=None, dispatch: dict | None = None, prog: str = "accesspath") -> int:
    """Point d'entrée ; un projet de collecte passe ses sous-commandes (`extend`, `dispatch`)."""
    parser = build_parser(extend, prog)
    args = parser.parse_args(argv)
    _setup_logging()
    return {**DISPATCH, **(dispatch or {})}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
