#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SOC Automation Pipeline — Pré-téléchargement des images d'analyseurs Cortex
#
#  Cortex lance chaque analyseur dans un conteneur Docker (« neuron »).
#  Si l'image n'est pas présente et que l'auto-pull échoue (registre
#  momentanément injoignable, rate-limit Docker Hub…), TOUS les jobs
#  finissent en « Failure » avec un errorMessage vide.
#
#  Ce script interroge Cortex pour la liste EXACTE des images des
#  analyseurs activés (registre + tag corrects) et les tire une par une.
#
#  À LANCER SUR L'HÔTE DOCKER qui fait tourner Cortex.
#
#  Usage :
#      CORTEX_URL=http://127.0.0.1:9001 CORTEX_APIKEY=xxxxx \
#          bash scripts/pull-cortex-analyzers.sh
#
#  (les valeurs par défaut ci-dessous conviennent si Cortex écoute en local)
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

CORTEX_URL="${CORTEX_URL:-http://127.0.0.1:9001}"
CORTEX_APIKEY="${CORTEX_APIKEY:?Définir CORTEX_APIKEY (Cortex > Organization > Users > API key)}"

echo ">> Cortex : $CORTEX_URL"
IMAGES="$(curl -sf -H "Authorization: Bearer $CORTEX_APIKEY" \
            "$CORTEX_URL/api/analyzer" \
          | grep -oE '"dockerImage":"[^"]*"' | cut -d'"' -f4 | sort -u)"

if [ -z "$IMAGES" ]; then
  echo "!! Aucun analyseur activé (ou clé API invalide)."
  echo "   Active d'abord des analyseurs : Cortex > Organization > Analyzers."
  exit 1
fi

echo ">> Images à tirer :"
echo "$IMAGES" | sed 's/^/   /'
echo

FAIL=0
while read -r img; do
  [ -n "$img" ] || continue
  echo "== docker pull $img"
  docker pull "$img" || { echo "!! échec : $img"; FAIL=1; }
done <<< "$IMAGES"

echo
if [ "$FAIL" -eq 0 ]; then
  echo ">> Toutes les images sont présentes. Relance une analyse dans Cortex."
else
  echo "!! Certaines images ont échoué — vérifier le DNS/registre de l'hôte :"
  echo "   docker run --rm alpine nslookup ghcr.io"
  exit 1
fi
