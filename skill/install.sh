#!/usr/bin/env bash
# Installe le skill /sap pour Claude Code sur cette machine, depuis ce dépôt (accesspath).
#
#   skill/install.sh
#
# Ce que fait le script, et rien d'autre :
#   1. ~/.claude/skills/sap devient un lien vers le dossier skill/ de ce dépôt (un `git pull` met à jour
#      le moteur et le skill ensemble) ; un sap déjà présent et différent est rangé dans
#      ~/.claude/skills.retires/ (hors du dossier que Claude Code lit), jamais effacé ;
#   2. l'environnement .venv du dépôt est créé s'il manque : dépendances de l'audit installées depuis
#      requirements.lock avec vérification des empreintes (--require-hashes), puis le dépôt en mode
#      éditable sans dépendances ;
#   3. la commande sap est vérifiée.
# If the repository is not in ~/Documents/accesspath, export ACCESSPATH_DIR (SKILL.md reads it).
set -euo pipefail

ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPOT="$(cd "$ICI/.." && pwd)"
SKILLS="$HOME/.claude/skills"

dire() { printf '\n== %s\n' "$*"; }

dire "Skill"
mkdir -p "$SKILLS"
if [[ -L "$SKILLS/sap" && "$(readlink "$SKILLS/sap")" == "$ICI" ]]; then
  echo "déjà en place : $SKILLS/sap → $ICI"
else
  if [[ -e "$SKILLS/sap" || -L "$SKILLS/sap" ]]; then
    mkdir -p "$HOME/.claude/skills.retires"
    mis_de_cote="$HOME/.claude/skills.retires/sap.avant-$(date +%Y%m%d-%H%M%S)"
    mv "$SKILLS/sap" "$mis_de_cote"
    echo "ancien skill mis de côté : $mis_de_cote"
  fi
  ln -s "$ICI" "$SKILLS/sap"
  echo "installé : $SKILLS/sap → $ICI"
fi

dire "Environnement Python ($DEPOT/.venv)"
if [[ ! -x "$DEPOT/.venv/bin/python" ]]; then
  python3 -m venv "$DEPOT/.venv"
  "$DEPOT/.venv/bin/pip" install -q --upgrade pip
  "$DEPOT/.venv/bin/pip" install -q --require-hashes -r "$DEPOT/requirements.lock"
  "$DEPOT/.venv/bin/pip" install -q --no-deps -e "$DEPOT"
else
  echo "présent"
fi

dire "Vérification"
( cd "$DEPOT" && .venv/bin/python -m accesspath sap --help >/dev/null 2>&1 ) \
  && echo "ok : /sap est prêt (Claude Code le voit à la prochaine session, ou tout de suite s'il recharge ses skills)" \
  || { echo "la commande sap ne répond pas : voir $DEPOT" >&2; exit 1; }
if [[ "$DEPOT" != "$HOME/Documents/accesspath" ]]; then
  echo "dépôt hors de ~/Documents/accesspath : exporter ACCESSPATH_DIR=$DEPOT dans votre shell"
fi
exit 0
