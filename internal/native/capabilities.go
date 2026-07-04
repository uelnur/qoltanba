package native

import (
	"regexp"

	"github.com/uelnur/qoltanba/internal/provider"
)

// Capability identifiers for kc_has. These MUST match the KC_CAP_* macros in
// shim.h. A separate Go copy keeps the capability logic free of cgo so it can be
// tested with a fake.
const (
	capSignData   = 1
	capVerifyData = 2
	capSignXML    = 3
	capVerifyXML  = 4
	capCertInfo   = 5
	capValidate   = 6
	capTSA        = 7
	capZipSign    = 8
	capWSSE       = 9
	capHashData   = 10
	capSignHash   = 11
	capExportCert = 12
)

// detectCaps builds the capability map from the methods actually present in the
// function table (the table grows between versions, so some methods may be
// missing).
func detectCaps(inst kalkanInstance, cfg Config) provider.Capabilities {
	ver := cfg.Version
	if ver == "" {
		ver = versionFromPath(cfg.WrapperPath)
	}
	return provider.Capabilities{
		Version:    ver,
		SignCMS:    inst.has(capSignData),
		VerifyCMS:  inst.has(capVerifyData),
		SignXML:    inst.has(capSignXML),
		VerifyXML:  inst.has(capVerifyXML),
		CertInfo:   inst.has(capCertInfo),
		Validate:   inst.has(capValidate),
		Timestamp:  inst.has(capTSA),
		ZipSign:    inst.has(capZipSign),
		WSSE:       inst.has(capWSSE),
		Hash:       inst.has(capHashData) && inst.has(capSignHash),
		ExportCert: inst.has(capExportCert),
	}
}

var versionRe = regexp.MustCompile(`(\d+\.\d+\.\d+)`)

// versionFromPath extracts the version from the wrapper file name
// (e.g. libkalkancryptwr-64.so.2.0.13 -> "2.0.13"). The C-API has no version call.
func versionFromPath(path string) string {
	if m := versionRe.FindString(path); m != "" {
		return m
	}
	return "unknown"
}
