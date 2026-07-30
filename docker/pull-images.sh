#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SOC Automation Pipeline — téléchargement robuste des images
#
#  « docker compose up -d » abandonne tout dès qu'une seule image
#  échoue : sur une connexion instable, on repart de zéro à chaque
#  fois. Ce script tire les images une par une et retente jusqu'à
#  réussite. Les couches déjà téléchargées ne le sont pas deux fois.
#
#  Usage :
#      cd docker
#      ./pull-images.sh          # 5 tentatives par image (défaut)
#      ./pull-images.sh 20       # 20 tentatives par image
#      docker compose up -d      # une fois tout téléchargé
# ══════════════════════════════════════════════════════════════════
set -u

MAX_TRIES="${1:-5}"
COMPOSE_FILE="$(dirname "$0")/docker-compose.yml"

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "docker-compose.yml introuvable à côté de ce script." >&2
    exit 1
fi

# Images du compose, en résolvant les valeurs par défaut ${VAR:-valeur}
IMAGES=$(grep -oE '^[[:space:]]+image:[[:space:]]*[^[:space:]]+' "$COMPOSE_FILE" \
         | sed -E 's/^[[:space:]]*image:[[:space:]]*//' \
         | sed -E 's/^\$\{[A-Za-z_][A-Za-z0-9_]*:-(.+)\}$/\1/' \
         | sort -u)

TOTAL=$(echo "$IMAGES" | grep -c .)
echo "═══════════════════════════════════════════════════════════"
echo "  Téléchargement de $TOTAL images — $MAX_TRIES tentatives max chacune"
echo "═══════════════════════════════════════════════════════════"

FAILED=""
INDEX=0

for IMAGE in $IMAGES; do
    INDEX=$((INDEX + 1))
    echo ""
    echo "── [$INDEX/$TOTAL] $IMAGE"

    TRY=1
    while [ "$TRY" -le "$MAX_TRIES" ]; do
        if docker pull "$IMAGE"; then
            echo "   ✅ $IMAGE"
            break
        fi
        if [ "$TRY" -eq "$MAX_TRIES" ]; then
            echo "   ❌ abandon après $MAX_TRIES tentatives"
            FAILED="$FAILED $IMAGE"
            break
        fi
        WAIT=$((TRY * 5))
        echo "   ⚠️  échec (tentative $TRY/$MAX_TRIES) — nouvel essai dans ${WAIT}s"
        sleep "$WAIT"
        TRY=$((TRY + 1))
    done
done

echo ""
echo "═══════════════════════════════════════════════════════════"
if [ -z "$FAILED" ]; then
    echo "  ✅ Toutes les images sont disponibles localement."
    echo "     Lancer maintenant : docker compose up -d"
    exit 0
fi

echo "  ❌ Images non téléchargées :"
for IMAGE in $FAILED; do
    echo "       - $IMAGE"
done
echo ""
echo "  Pistes :"
echo "    • relancer ce script, les couches déjà tirées sont conservées"
echo "    • « network is unreachable » sur une adresse IPv6 : désactiver"
echo "      IPv6 sur le conteneur (voir INSTALL.md, section Dépannage)"
echo "    • « i/o timeout » sur un nom de registre : régler le DNS de"
echo "      Docker dans /etc/docker/daemon.json"
echo "═══════════════════════════════════════════════════════════"
exit 1
