# Разбор сертификата: форматы, профили, производные поля

Часть фичи `signature-service` — сначала [`index.md`](index.md).
Что и в каком виде отдаёт `X509CertificateGetInfo` и что мы вычисляем сами.
Таблицы OID/DN/ролей — в [`nuc-pki-reference.md`](../../nuc-pki-reference.md);
механика C-API (сигнатуры, флаги, форматы) — в
[`../../kalkan-api/certificates.md`](../../kalkan-api/certificates.md).

## Форматы значений

- Все поля — **UTF-8 строки** `имя=значение`, NUL-терминированные в дополненных
  буферах. Префикс `имя=` **срезать**, резать по первому `\x00`. Кириллица — как есть.
- **Отсутствие поля** → `0x08F00038` (`KCR_GETCERTPROPERR`) → `null`, не ошибка.

| Поле | Пример | Формат |
|------|--------|--------|
| `SUBJECT_DN` | `CN = ТЕСТОВ ТЕСТ, SN = …, serialNumber = IIN…, C = KZ, GN = …` | агрегат RDN, разделитель `, `, пробелы вокруг `=` |
| `SUBJECT_SERIALNUMBER` | `serialNumber=IIN123456789011` | ИИН как `IIN<12 цифр>` |
| `SUBJECT_ORGUNIT_NAME` | `OU=BIN123456789021` | у ЮЛ несёт **БИН** как `BIN<12>` |
| `SUBJECT_ORG_NAME` | `O=АО "ТЕСТ"` | название организации (ЮЛ) |
| `SUBJECT_BC` | `businessCategory=KS1234` | только некоторые профили (Казначейство) |
| `NOTBEFORE`/`NOTAFTER` | `notBefore=08.05.2026 06:45:13 +00:00` | **`DD.MM.YYYY HH:MM:SS ±HH:MM`** → нормализуем в RFC3339 |
| `CERT_SN` | `certificateSerialNumber=6C4256…` | HEX (верхний регистр) |
| `AUTH_KEY_ID`/`SUBJ_KEY_ID` | `authorityKeyIdentifier=FAD24B…` | HEX |
| `KEY_USAGE` | `keyUsage=digitalSignature nonRepudiation keyAgreement` | список через пробел |
| `EXT_KEY_USAGE` | `extendedKeyUsage=E-mail Protection (…); 1.2.398.3.3.4.1.2 (…)` | человекочит.+OID, разделитель `; ` |
| `SIGNATURE_ALG` | `signatureAlgorithm=GOST R 34.10-2015 … (…OID)` | текст + OID |
| `PUBKEY` | `MIGsMCMG…` | **base64** DER (SubjectPublicKeyInfo) |
| `POLICIES_ID` | `certificatePolicies=1.2.398.3.3.2` | OID(ы) политик |

## Различия по профилям

Наличие полей задаёт тип владельца (`+` присутствует, `.` — `KCR_GETCERTPROPERR`):

| Свойство | Физлицо | ЮЛ-персона¹ | Инфосистема | Казначейство |
|----------|:-------:|:-----------:|:-----------:|:------------:|
| ФИО + ИИН (`SUBJECT_SERIALNUMBER`) | + | + | . | + |
| ORG + OU(БИН) | . | + | + | + |
| `businessCategory` / `DC` | . | . | . | + |

¹ первый рук. / сотрудник / право подписи. DN, серийники, KU/EKU, даты, алгоритм,
pubkey, policies — есть у всех.

## Производные поля (вычисляем сами)

- **`ownerType`** по наличию полей:
  - нет `OU(BIN)` → **физлицо**;
  - есть `OU(BIN)` + ФИО/ИИН → **сотрудник ЮЛ**;
  - есть `OU(BIN)`, нет ФИО/ИИН → **информационная система** (не человек).
- **`iin`** ← срез `IIN` из `SUBJECT_SERIALNUMBER`; **`bin`** ← срез `BIN` из `OU`.
- **`roles`** ← OID в `EXT_KEY_USAGE` (маппинг → см.
  [`nuc-pki-reference.md`](../../nuc-pki-reference.md)). По `certificatePolicies` роль
  не различить — у тестовых профилей она одна.
- **`gender`** ← 7-я цифра ИИН (формула в справочнике).
- **OIDC-claims** (`core.ClaimsFromCertificate`, `internal/core/claims.go`) — готовый
  claim-set поверх производных полей (не сырой DN): стандартные `sub`/`name`/
  `given_name`/`family_name`/`email` + РК-специфичные `iin`/`bin`/`organization`/
  `roles`/`owner_type`/`gender` (плоские snake_case). `sub` = ИИН, иначе БИН (ИС);
  `gender` → OIDC-стиль `male|female` (NONE опускается). Отдаётся **по флагу**
  запроса `claims`: на каждом `signers[].claims` в verify и на `claims` в cert-info
  (строительный блок будущего OIDC-провайдера — [`roadmap.md`](../../roadmap.md)).
- **`keyAlgorithm`** ← `signatureAlgorithm`/OID (RSA / ГОСТ-2004 / ГОСТ-2015 + длина).
- **Упрощённый `keyUsage` (SIGN/AUTH/UNKNOWN)** — для паритета с эталоном, из бит
  `keyUsage` (`2.5.29.15`): **SIGN** = `digitalSignature` **и** `nonRepudiation`;
  **AUTH** = `digitalSignature` **и** `keyEncipherment`; проверять SIGN первым (при
  совпадении обоих → SIGN), иначе `UNKNOWN`. Полный список бит отдаём отдельно.

## Признак CA-уровня

У промежуточного (НУЦ) и корневого (КУЦ) — `keyUsage=keyCertSign cRLSign` и **нет
`extendedKeyUsage`** (`0x08F00038`); у листа — `digitalSignature nonRepudiation
keyAgreement` + EKU с роль-OID. Это надёжный признак «это CA» при разборе цепочки
(см. [`validation.md`](validation.md)).
