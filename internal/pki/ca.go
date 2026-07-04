package pki

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// Официальный реестр CA-сертификатов и корневых CRL РК (КУЦ РК,
// https://root.gov.kz/registr/). Источник trust-store для валидации цепочки
// (см. DESIGN §8, CA-источник). Снимок регенерируется tools/oidgen/fetch_ca_registry.py.

//go:embed ca-registry.json
var caRegistryJSON []byte

// CACertRef — ссылка на CA-сертификат в официальном реестре.
type CACertRef struct {
	Label string `json:"label"` // имя файла без расширения (напр. root_gost2015_2022)
	URL   string `json:"url"`
	Kind  string `json:"kind"` // root | nca_intermediate | ucgo | accredited_ca | other
	Algo  string `json:"algo"` // gost | gost2015 | rsa | unknown
	Test  bool   `json:"test"` // тестовый корень/цепочка
}

type caRegistry struct {
	Source       string      `json:"source"`
	Title        string      `json:"title"`
	Certificates []CACertRef `json:"certificates"`
	RootCrls     []string    `json:"rootCrls"`
}

var (
	caOnce sync.Once
	caReg  caRegistry
)

func caRegistryData() *caRegistry {
	caOnce.Do(func() { _ = json.Unmarshal(caRegistryJSON, &caReg) })
	return &caReg
}

// CACertificates возвращает все CA-сертификаты из официального реестра.
func CACertificates() []CACertRef { return caRegistryData().Certificates }

// RootCRLs возвращает URL корневых CRL КУЦ.
func RootCRLs() []string { return caRegistryData().RootCrls }

// CACertificatesFor фильтрует CA по продакшн/тест (test=false → только боевые).
func CACertificatesFor(test bool) []CACertRef {
	var out []CACertRef
	for _, c := range caRegistryData().Certificates {
		if c.Test == test {
			out = append(out, c)
		}
	}
	return out
}

// CARegistrySource — URL официального источника trust-store.
func CARegistrySource() string { return caRegistryData().Source }
