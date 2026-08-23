# NCANode — эталон-конкурент (единственная дока с упоминанием)

> **Это единственное место, где проект ссылается на NCANode.** В остальных доках
> поведение описывается на своих условиях (эмпирика Kalkan + стандарты РК), без
> отсылок к чужой реализации. Сюда приходят, когда нужен паритет по полям, разбор
> чужих правил или обоснование «мы отдаём больше».

**Что это.** NCANode v3 (`ncanode-kz/NCANode`, Java/Spring) — популярный
open-source сервис ЭЦП РК. Это **обёртка над тем же криптоядром Kalkan** (через
Java JCE `knca_provider_jce_kalkan`), что и наш сервис (у нас — нативный
`libkalkancryptwr` / C-API). Отсюда следствие: доступ к данным у нас **тот же или
шире** — всё, что отдаёт NCANode, мы либо уже извлекли эмпирически, либо выводим из
тех же байтов.

## Ключевые выводы

- **Паритет полей — полный.** Все поля схем NCANode (`CertificateSubject`,
  `CertificateInfo`, `CmsSignerInfo`, `TspInfo`, revocation, verify-ответы)
  воспроизводимы.
- **Мы отдаём больше:** полный `keyUsage`/`extendedKeyUsage` списком, AKI/SKI,
  `certificatePolicies`, BC/DC, сырой OCSP-ответ и `verifyInfo`, AIA/CRL-URL,
  признак CAdES-уровня и detached, восстановленное содержимое, **полную цепочку**
  (NCANode кладёт в ответ только лист), несколько транспортов, batch, async.
- **Их слабые места, которые мы закрываем:** NCANode **не проверяет** подпись
  OCSP-ответа и `thisUpdate/nextUpdate`, не валидирует подпись CRL, **не вычисляет**
  `gender` (всегда null), не строит полную цепочку в ответе. Мы — проверяем/строим.
- **Вне Kalkan-C-API у NCANode только два эндпоинта:** PDF (отдельный слой на
  PDFBox, подпись — всё равно detached-CMS через Kalkan) и JWT (GOST). Реализуемы
  нами, но требуют доп. кода, не самого Kalkan. PDF — единственный реально
  трудозатратный пункт.

## Где лежат детали (уже разнесено по нашим докам)

Разбор исходников NCANode распределён по темам — ходить в чужой код за этим не надо:

- **Паритет полей и «сверх»-поля** — этот док (выше) + черновик формы
  `qoltanba/api/qoltanba-draft.proto`.
- **Сертификат / DN / роли / алгоритмы** — [`nuc-pki-reference.md`](nuc-pki-reference.md)
  (OID, DN→поля, gender, таблицы алгоритмов) и
  [`features/signature-service/certificates.md`](features/signature-service/certificates.md)
  (форматы полей, вывод `keyUsage` SIGN/AUTH).
- **CMS + TSP** (imprint от **SignatureValue** подписанта, unsigned-attr OID
  `1.2.840.113549.1.9.16.2.14`, структура TSTInfo), **XML/WSSE** (transforms,
  C14N-URI, LIFO-проверка, namespace WSSE) —
  [`features/signature-service/signing-verify.md`](features/signature-service/signing-verify.md).
- **OCSP/CRL/цепочка** (SHA-256 CertID, AIA-нюанс, delta-раньше-full, выбор
  издателя) — [`features/signature-service/validation.md`](features/signature-service/validation.md).
- **PDF / JWT** (подход, лицензионный нюанс, `x5c` не используется) —
  [`features/signature-service/pdf-jwt.md`](features/signature-service/pdf-jwt.md).
