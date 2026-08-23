#!/usr/bin/env python3
"""Генератор справочника OID НУЦ/КУЦ РК из официального источника.

Источник (официальный, КУЦ РК): https://root.gov.kz/oid/
Страница — HTML-дерево арки 1.2.398 (Казахстан) с актуальными именами ролей,
политик, TSA-политик и зарегистрированных информационных систем. Прямого
JSON/CSV нет, поэтому парсим дерево и выпускаем машиночитаемый JSON.

Использование:
    python3 fetch_oids.py            # скачать и записать oids-nuc.json
    python3 fetch_oids.py file.html  # распарсить локально сохранённый HTML

Выход: internal/pki/oids-nuc.json — полный плоский список {oid: name} +
курируемые подмножества (roles/policies/tsaPolicies) для маппинга keyUser.
"""
import json
import re
import sys
import os
import urllib.request
from html import unescape

SOURCE_URL = "https://root.gov.kz/oid/"
OUT = os.path.join(os.path.dirname(__file__), "..", "..", "internal", "pki", "oids-nuc.json")

# Курируемые ветки для прикладного маппинга (EKU-роли и политики).
ROLE_ARC = "1.2.398.3.3.4"       # Пользователи / роли / полномочия / идентификация
POLICY_ARC = "1.2.398.3.3.2"     # Политики применения (вкл. TSA .6)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def parse_tree(h: str) -> dict:
    """Извлекает пары OID(1.2.398...) -> имя из текста дерева."""
    txt = re.sub(r"<[^>]+>", " ", h)
    txt = unescape(re.sub(r"\s+", " ", txt))
    toks = list(re.finditer(r"(?<![\d.])(1\.2\.398(?:\.\d+)*)\b", txt))
    result: dict[str, str] = {}
    for i, t in enumerate(toks):
        oid = t.group(1)
        end = toks[i + 1].start() if i + 1 < len(toks) else t.end() + 200
        name = txt[t.end():end].strip(" .|")
        name = re.sub(r"\s+", " ", name).strip()
        # обрезаем возможный хвост следующего узла, если имя слишком длинное
        if oid not in result and name:
            result[oid] = name
    return result


def subset(oids: dict, arc: str) -> dict:
    return {o: n for o, n in oids.items() if o == arc or o.startswith(arc + ".")}


def main():
    if len(sys.argv) > 1:
        h = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    else:
        h = fetch(SOURCE_URL)

    oids = parse_tree(h)
    if not oids:
        print("ОШИБКА: OID не извлечены — изменилась разметка источника?", file=sys.stderr)
        sys.exit(1)

    doc = {
        "source": SOURCE_URL,
        "arc": "1.2.398 (Казахстан, iso.member-body.kz)",
        "note": "Официальный справочник КУЦ РК. Имена обновляются (новые ИС добавляются часто).",
        "count": len(oids),
        "roles": subset(oids, ROLE_ARC),
        "policies": subset(oids, POLICY_ARC),
        "all": dict(sorted(oids.items(), key=lambda kv: [int(x) for x in kv[0].split(".")])),
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"Записано {len(oids)} OID в {os.path.relpath(OUT)}")


if __name__ == "__main__":
    main()
