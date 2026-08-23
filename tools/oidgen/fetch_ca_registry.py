#!/usr/bin/env python3
"""Генератор списка CA-сертификатов и корневых CRL РК (trust-store).

Источник (официальный, КУЦ РК): https://root.gov.kz/registr/
«Регистр регистрационных свидетельств» — перечень всех CA-сертификатов
(корни КУЦ, НУЦ, УЦ ГО, аккредитованные УЦ) и корневых CRL.

Использование:
    python3 fetch_ca_registry.py             # скачать и записать ca-registry.json
    python3 fetch_ca_registry.py file.html   # распарсить локальный HTML

Выход: internal/pki/ca-registry.json — список {label,url,kind,algo,test} + rootCrls.
Это источник CA-набора для построения/валидации цепочки (см. DESIGN §8).
"""
import json
import os
import re
import sys
import urllib.request
from collections import Counter

SOURCE_URL = "https://root.gov.kz/registr/"
OUT = os.path.join(os.path.dirname(__file__), "..", "..", "internal", "pki", "ca-registry.json")

# Manually seeded CA certificates the official registr page does not link, but that
# real end-entity certificates reference via AIA (the per-year issuing NUC
# intermediates). Without these, a chain from a 2022 NUC leaf cannot anchor. Merged
# with the scraped set; verified reachable (HTTP 200).
EXTRA_CERTS = [
    "https://pki.gov.kz/cert/nca_gost_2022.cer",  # НУЦ GOST 2022 — issues GOST-2015 leaves
    "https://pki.gov.kz/cert/nca_rsa_2022.cer",   # НУЦ RSA 2022 — issues RSA leaves
]


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def classify(u: str) -> dict:
    name = u.rsplit("/", 1)[-1]
    low = name.lower()
    test = "test" in low
    if "/uc/" in u:
        kind = "accredited_ca"
    elif "nca_" in low:
        kind = "nca_intermediate"
    elif "ucgo" in u:
        kind = "ucgo"
    elif "root" in low or "kuc" in low:
        kind = "root"
    else:
        kind = "other"
    if "gost2015" in low or "gost_2020" in low:
        algo = "gost2015"
    elif "gost" in low:
        algo = "gost"
    elif "rsa" in low:
        algo = "rsa"
    else:
        algo = "unknown"
    return {"label": name.rsplit(".", 1)[0], "url": u, "kind": kind, "algo": algo, "test": test}


def main():
    if len(sys.argv) > 1:
        h = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    else:
        h = fetch(SOURCE_URL)

    scraped = set(re.findall(r"https?://[^\s\"'<>]+\.(?:cer|crt|pem|p7b)", h))
    certs = sorted(scraped | set(EXTRA_CERTS))
    crls = sorted(set(re.findall(r"https?://[^\s\"'<>]+\.crl", h)))
    if not certs:
        print("ОШИБКА: сертификаты не извлечены — изменилась разметка?", file=sys.stderr)
        sys.exit(1)

    doc = {
        "source": SOURCE_URL,
        "title": "Регистр регистрационных свидетельств (КУЦ РК) — trust-store",
        "note": "Официальный список CA-сертификатов и корневых CRL РК. Источник CA-набора для валидации цепочки.",
        "certificates": [classify(c) for c in certs],
        "rootCrls": crls,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"Записано {len(certs)} сертов, {len(crls)} CRL в {os.path.relpath(OUT)}")
    print("по видам:", dict(Counter(c["kind"] for c in doc["certificates"])))


if __name__ == "__main__":
    main()
