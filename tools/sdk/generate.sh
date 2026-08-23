#!/usr/bin/env bash
# Генерация тонких клиентов из api/openapi.yaml через openapi-generator (Docker).
#
#   tools/sdk/generate.sh                    # все языки в dist/sdk/<lang>
#   tools/sdk/generate.sh php python         # только указанные
#   SDK_VERSION=1.2.3 tools/sdk/generate.sh  # версия пакетов (по умолчанию из git)
#
# Спецификация генерируется из Go-типов (make openapi), поэтому клиенты не могут
# разъехаться с сервером: дрейф ловит make check-generated ещё до генерации.
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO="$(pwd)"
SPEC="api/openapi.yaml"
OUT="dist/sdk"
IMAGE="${SDK_IMAGE:-openapitools/openapi-generator-cli:v7.10.0}"

# Версия пакетов: явная, иначе ближайший тег, иначе 0.0.0-dev.
VERSION="${SDK_VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0-dev)}"
VERSION="${VERSION#v}"

# Все поддерживаемые языки. Ассоциативные массивы не используются намеренно:
# на macOS системный bash — 3.2, где их нет, а скрипт должен работать и локально.
ALL_LANGS="php python typescript csharp java go ruby kotlin dart rust"

# generator_for отображает язык на генератор openapi-generator (обычно совпадает).
generator_for() {
	case "$1" in
	typescript) echo "typescript-axios" ;;
	php | python | csharp | java | go | ruby | kotlin | dart | rust) echo "$1" ;;
	*) echo "" ;;
	esac
}

LANGS="$*"
if [[ -z "$LANGS" ]]; then
	LANGS="$ALL_LANGS"
fi

[[ -f "$SPEC" ]] || { echo "нет $SPEC — сначала make openapi" >&2; exit 1; }

for lang in $LANGS; do
	gen="$(generator_for "$lang")"
	if [[ -z "$gen" ]]; then
		echo "неизвестный язык '$lang' (есть: $ALL_LANGS)" >&2
		exit 2
	fi
	echo ">>> $lang ($gen) v$VERSION"
	rm -rf "${OUT:?}/$lang"
	mkdir -p "$OUT/$lang"
	docker run --rm -u "$(id -u):$(id -g)" -v "$REPO":/local "$IMAGE" generate \
		-i "/local/$SPEC" \
		-g "$gen" \
		-o "/local/$OUT/$lang" \
		--additional-properties="packageName=qoltanba,packageVersion=$VERSION,projectName=qoltanba,artifactId=qoltanba,groupId=kz.qoltanba,gemName=qoltanba,npmName=@qoltanba/client,npmVersion=$VERSION,invokerPackage=Qoltanba,packageDescription=Qoltanba digital-signature service client (RK ЭЦП)" \
		--git-user-id uelnur --git-repo-id qoltanba >/dev/null
done

echo "готово: $OUT/ ($LANGS)"
