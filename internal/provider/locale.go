package provider

import "strings"

// Locale identifies the language an explanation is rendered in. English is the
// source of truth: keys and English text live with the catalog, translations are
// tables keyed by the same stable Key, so adding a language never touches call
// sites or the wire contract.
type Locale string

const (
	LocaleEN Locale = "en"
	LocaleRU Locale = "ru"
	LocaleKK Locale = "kk"
)

// ParseLocale resolves a language tag (an Accept-Language value, a config
// setting) to a supported locale, falling back to English. Only the primary
// subtag matters: "ru-KZ" and "ru" render the same text.
func ParseLocale(tag string) Locale {
	tag = strings.TrimSpace(strings.ToLower(tag))
	if tag == "" {
		return LocaleEN
	}
	// An Accept-Language header may list several tags with q-values; the first
	// supported one wins, which is the common case and keeps this dependency-free.
	for _, part := range strings.Split(tag, ",") {
		primary := strings.TrimSpace(part)
		if i := strings.IndexAny(primary, ";"); i >= 0 {
			primary = strings.TrimSpace(primary[:i])
		}
		if i := strings.IndexAny(primary, "-_"); i >= 0 {
			primary = primary[:i]
		}
		switch Locale(primary) {
		case LocaleRU:
			return LocaleRU
		case LocaleKK:
			return LocaleKK
		case LocaleEN:
			return LocaleEN
		}
	}
	return LocaleEN
}

// localized is a translated message/action pair.
type localized struct {
	message string
	action  string
}

// translations maps a catalog Key to its rendering per locale. A missing key or
// locale falls back to the English text in the catalog, so a partial translation
// degrades to English rather than to an empty message.
var translations = map[Locale]map[string]localized{
	LocaleRU: {
		"container.password.invalid": {
			"Неверный пароль контейнера закрытого ключа.",
			"Проверьте пароль контейнера (PKCS#12/PFX) и повторите попытку."},
		"key.not_found": {
			"В контейнере не найден закрытый ключ.",
			"Убедитесь, что контейнер содержит ключ подписи и выбран правильный алиас."},
		"cert.not_found": {
			"Сертификат не найден.",
			"Передайте сертификат подписанта или проверьте, что он есть в контейнере ключа."},
		"cert.expired": {
			"Срок действия сертификата истёк.",
			"Перевыпустите сертификат или используйте действующий."},
		"cert.time_invalid": {
			"Сертификат недействителен на указанный момент времени.",
			"Используйте сертификат, действующий на момент подписания/проверки, или измените проверяемое время."},
		"cert.parse_error": {
			"Не удалось разобрать сертификат.",
			"Проверьте кодировку (PEM/DER/Base64) и то, что байты являются корректным сертификатом X.509."},
		"sign.format_mismatch": {
			"Флаг формата подписи не соответствует данным.",
			"Убедитесь, что формат (CMS/XML/WSSE) и признак detached совпадают с тем, как данные подписывались."},
		"signature.invalid": {
			"Подпись криптографически недействительна.",
			"Данные изменены или подписаны другим ключом — подпишите заново либо проверьте против исходного документа."},
		"signature.absent": {
			"Во входных данных не найдена подпись.",
			"Передайте подписанный контейнер и проверьте, что флаг формата ему соответствует."},
		"chain.invalid": {
			"Не удалось построить или проверить цепочку сертификатов.",
			"Добавьте сертификаты выпустившего УЦ в хранилище доверия."},
		"ca.required": {
			"Требуется доверенный сертификат УЦ, но он недоступен.",
			"Загрузите сертификаты НУЦ РК в хранилище доверия."},
		"ocsp.request_failed": {
			"Проверка отзыва по OCSP не удалась.",
			"Проверьте сетевой доступ к OCSP-респондеру или повторите позже."},
		"xml.parse_error": {
			"Не удалось разобрать XML-документ.",
			"Убедитесь, что на вход подан корректный XML."},
		"output.empty": {
			"Криптобиблиотека вернула успех, но пустой результат.",
			"Это сочетание опций библиотека не поддерживает — чаще всего метка времени вместе с отключённой проверкой времени сертификата. Повторите с включённой проверкой времени."},
		"cms.format_unknown": {
			"Формат контейнера CMS/PKCS#7 не распознан.",
			"Проверьте, что на вход подана корректная структура CMS/PKCS#7 и что признак detached ей соответствует."},
		"request.invalid_parameter": {
			"Библиотека отклонила параметр запроса.",
			"Проверьте флаги операции и кодировку входных данных."},
		"buffer.too_small": {
			"Выходной буфер библиотеки оказался мал.",
			"Повторите операцию; если повторяется — сообщите сопровождающим размер входных данных."},
		"operation.unsupported": {
			"Загруженная версия библиотеки не поддерживает эту операцию.",
			"Обновите библиотеку Kalkan или используйте поддерживаемую операцию."},
		"service.not_ready": {
			"Сервис не готов — нативная библиотека не инициализирована.",
			"Дождитесь готовности (/readyz) или проверьте настройки нативной библиотеки."},
		"service.closed": {
			"Провайдер закрыт.",
			"Перезапустите сервис."},
		"library.error": {
			"Криптографическая библиотека вернула ошибку.",
			"Изучите код и текст ошибки; обратитесь к каталогу ошибок или к сопровождающим."},
	},
	LocaleKK: {
		"container.password.invalid": {
			"Жабық кілт контейнерінің құпия сөзі дұрыс емес.",
			"Контейнердің (PKCS#12/PFX) құпия сөзін тексеріп, қайта көріңіз."},
		"key.not_found": {
			"Контейнерден жабық кілт табылмады.",
			"Контейнерде қол қою кілті бар екенін және дұрыс алиас таңдалғанын тексеріңіз."},
		"cert.not_found": {
			"Сертификат табылмады.",
			"Қол қоюшының сертификатын беріңіз немесе оның кілт контейнерінде бар-жоғын тексеріңіз."},
		"cert.expired": {
			"Сертификаттың қолданылу мерзімі өтіп кеткен.",
			"Сертификатты қайта шығарыңыз немесе қолданыстағысын пайдаланыңыз."},
		"cert.time_invalid": {
			"Сертификат көрсетілген уақытта жарамсыз.",
			"Қол қою/тексеру сәтінде жарамды сертификатты пайдаланыңыз немесе тексеру уақытын өзгертіңіз."},
		"cert.parse_error": {
			"Сертификатты талдау мүмкін болмады.",
			"Кодтауды (PEM/DER/Base64) және байттардың жарамды X.509 сертификаты екенін тексеріңіз."},
		"sign.format_mismatch": {
			"Қол қою пішімінің жалаушасы деректерге сәйкес келмейді.",
			"Пішім (CMS/XML/WSSE) мен detached белгісі деректерге қол қою тәсіліне сай екенін тексеріңіз."},
		"signature.invalid": {
			"Қол криптографиялық тұрғыдан жарамсыз.",
			"Деректер өзгертілген немесе басқа кілтпен қол қойылған — қайта қол қойыңыз не бастапқы құжатпен салыстырыңыз."},
		"signature.absent": {
			"Кіріс деректерінде қол табылмады.",
			"Қол қойылған контейнерді беріңіз және пішім жалаушасының оған сәйкестігін тексеріңіз."},
		"chain.invalid": {
			"Сертификаттар тізбегін құру немесе тексеру мүмкін болмады.",
			"Сертификатты шығарған КО сертификаттарын сенім қоймасына қосыңыз."},
		"ca.required": {
			"Сенімді КО сертификаты қажет, бірақ қолжетімсіз.",
			"ҚР ҰКО сертификаттарын сенім қоймасына жүктеңіз."},
		"ocsp.request_failed": {
			"OCSP арқылы кері қайтарып алуды тексеру сәтсіз аяқталды.",
			"OCSP серверіне желілік қолжетімділікті тексеріңіз немесе кейінірек қайталаңыз."},
		"xml.parse_error": {
			"XML құжатын талдау мүмкін болмады.",
			"Кірісте жарамды XML бар екеніне көз жеткізіңіз."},
		"output.empty": {
			"Криптокітапхана сәттілік туралы хабарлады, бірақ нәтиже бос.",
			"Опциялардың бұл тіркесімін кітапхана қолдамайды — көбінесе бұл уақыт белгісі мен өшірілген сертификат уақытын тексеру. Сертификат уақытын тексеруді қосып қайталаңыз."},
		"cms.format_unknown": {
			"CMS/PKCS#7 контейнерінің пішімі танылмады.",
			"Кірісте жарамды CMS/PKCS#7 құрылымы бар екенін және detached белгісінің сәйкестігін тексеріңіз."},
		"request.invalid_parameter": {
			"Кітапхана сұраныс параметрін қабылдамады.",
			"Операция жалаушаларын және кіріс деректерінің кодтауын тексеріңіз."},
		"buffer.too_small": {
			"Кітапхананың шығыс буфері тым кіші болды.",
			"Операцияны қайталаңыз; қайталанса — кіріс деректерінің көлемін әзірлеушілерге хабарлаңыз."},
		"operation.unsupported": {
			"Жүктелген кітапхана нұсқасы бұл операцияны қолдамайды.",
			"Kalkan кітапханасын жаңартыңыз немесе қолдау көрсетілетін операцияны пайдаланыңыз."},
		"service.not_ready": {
			"Қызмет дайын емес — нативті кітапхана іске қосылмаған.",
			"Дайындықты күтіңіз (/readyz) немесе нативті кітапхана баптауларын тексеріңіз."},
		"service.closed": {
			"Провайдер жабылған.",
			"Қызметті қайта іске қосыңыз."},
		"library.error": {
			"Криптографиялық кітапхана қате қайтарды.",
			"Қате кодын және мәтінін қараңыз; қателер каталогына немесе әзірлеушілерге жүгініңіз."},
	},
}

// Localize renders exp in the given locale, leaving the English text in place for
// an untranslated key. Code and Key never change: they are the stable contract.
func Localize(exp Explanation, loc Locale) Explanation {
	table, ok := translations[loc]
	if !ok {
		return exp
	}
	t, ok := table[exp.Key]
	if !ok {
		return exp
	}
	exp.Message, exp.Action = t.message, t.action
	return exp
}

// ExplainIn renders err into an Explanation in the given locale.
func ExplainIn(err error, loc Locale) Explanation { return Localize(Explain(err), loc) }
