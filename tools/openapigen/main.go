// Command openapigen generates api/openapi.yaml and the Postman collection from
// the Go request/response types, so the schemas never drift from the code. The
// drift-prone part — the component schemas — is reflected from internal/transport/dto
// (requests) and internal/core (responses); the stable part — paths, info, enums —
// is declared here. Run via `make openapi`; a CI diff-gate fails if the committed
// files are stale.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/invopop/jsonschema"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/uelnur/qoltanba/internal/audit"
	"github.com/uelnur/qoltanba/internal/challenge"
	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/multisign"
	"github.com/uelnur/qoltanba/internal/oidc"
	"github.com/uelnur/qoltanba/internal/qr"
	"github.com/uelnur/qoltanba/internal/signedqr"
	"github.com/uelnur/qoltanba/internal/transport/dto"
)

// ErrorEnvelope is the hard-failure JSON shape (mirrors rest.errorBody). Declared
// here because the transport type is unexported; it is part of the wire contract.
type ErrorEnvelope struct {
	Error struct {
		Kind    string `json:"kind"`
		Code    string `json:"code,omitempty"`
		Message string `json:"message"`
		Action  string `json:"action,omitempty"`
	} `json:"error"`
}

// schemaType binds a component name to the Go type reflected into it.
type schemaType struct {
	name string
	typ  any
}

// The top-level types. Nested types (Subject, Certificate, KeySpec, TrustedCert,
// LibError, Warning, Timestamp, RevocationStatus, Signer, Claims) are pulled in
// automatically by reflection and named after their Go type.
var topTypes = []schemaType{
	{"SignRequest", &dto.SignRequest{}},
	{"VerifyRequest", &dto.VerifyRequest{}},
	{"VerifyAtRequest", &dto.VerifyAtRequest{}},
	{"ExtractRequest", &dto.ExtractRequest{}},
	{"CertInfoRequest", &dto.CertInfoRequest{}},
	{"ValidateRequest", &dto.ValidateRequest{}},
	{"SignResponse", &core.SignOutput{}},
	{"VerifyResponse", &core.VerifyOutput{}},
	{"VerifyAtResponse", &core.VerifyAtOutput{}},
	{"ExtractResponse", &core.ExtractOutput{}},
	{"CertInfoResponse", &core.CertInfoOutput{}},
	{"ValidateResponse", &core.ValidateOutput{}},
	{"ErrorEnvelope", &ErrorEnvelope{}},
	// Batch and async-job wire types. The batch request/response wrappers are
	// generic, so they are composed by hand in addBatchSchemas from these leaves;
	// the job status view and the per-item error reflect cleanly.
	{"BatchItemError", &core.BatchItemError{}},
	{"JobStatus", &jobs.View{}},
	// OIDC "login with ЭЦП" wire types. JWK is pulled in by reflection from JWKSet.
	{"OIDCChallengeRequest", &oidc.ChallengeRequest{}},
	{"OIDCChallengeResponse", &oidc.ChallengeResponse{}},
	{"OIDCVerifyRequest", &oidc.VerifyRequest{}},
	{"OIDCTokenResponse", &oidc.TokenResponse{}},
	{"OIDCDiscovery", &oidc.DiscoveryDoc{}},
	{"OIDCJWKS", &oidc.JWKSet{}},
	// eGov Mobile QR wire types. QRView is hand-authored (its result is polymorphic)
	// in addQRSchemas; Document is pulled in by reflection from QRCreateRequest.
	{"QRCreateRequest", &qr.CreateRequest{}},
	{"QRCreateResponse", &qr.CreateResponse{}},
	// Long-term validation and the register view over a batch.
	{"ArchiveRequest", &dto.ArchiveRequest{}},
	{"ArchiveResponse", &core.ArchiveOutput{}},
	{"RegistryItemRequest", &dto.RegistryItemRequest{}},
	{"RegistryResponse", &core.RegistryOutput{}},
	// Standalone challenge–response (the same handshake OIDC uses internally).
	{"ChallengeIssueRequest", &challenge.IssueRequest{}},
	{"ChallengeIssueResponse", &challenge.IssueResponse{}},
	{"ChallengeConfirmRequest", &challenge.ConfirmRequest{}},
	{"ChallengeConfirmResponse", &challenge.ConfirmResponse{}},
	// Multi-signature sessions.
	{"MultisignCreateRequest", &multisign.CreateRequest{}},
	{"MultisignSession", &multisign.Session{}},
	// Audit journal.
	{"AuditVerifyResult", &audit.VerifyResult{}},
	// Service-signed documents carried in a QR.
	{"SignedQRIssueRequest", &signedqr.IssueRequest{}},
	{"SignedQRIssueResponse", &signedqr.IssueResponse{}},
	{"SignedQRVerifyResult", &signedqr.VerifyResult{}},
}

// nestedRenames disambiguates nested types whose bare Go name would be too
// generic once every package's types share one component namespace.
var nestedRenames = map[string]string{
	"Signature": "MultisignSignature",   // multisign.Signature — one collected signature
	"Required":  "MultisignRequirement", // multisign.Required — one required signer
}

// enums enriches specific properties the reflector cannot infer (Go string types
// carry no value set). Keyed by "Schema.property".
var enums = map[string][]string{
	"SignRequest.format":        {"cms", "xml", "wsse"},
	"VerifyRequest.format":      {"cms", "xml", "wsse"},
	"VerifyAtRequest.format":    {"cms", "xml", "wsse"},
	"VerifyAtRequest.method":    {"ocsp", "crl"},
	"ExtractRequest.format":     {"cms", "xml", "wsse"},
	"SignResponse.format":       {"cms", "xml", "wsse"},
	"VerifyResponse.format":     {"cms", "xml", "wsse"},
	"VerifyAtResponse.format":   {"cms", "xml", "wsse"},
	"PointInTimeVerdict.method": {"ocsp", "crl"},
	"DiagnosisStep.status":      {"pass", "fail", "warn", "skipped", "unknown"},
	"CertInfoRequest.encoding":  {"pem", "der", "base64"},
	"ValidateRequest.encoding":  {"pem", "der", "base64"},
	"CertInfoRequest.method":    {"ocsp", "crl"},
	"ValidateRequest.method":    {"ocsp", "crl"},
	"RevocationStatus.method":   {"ocsp", "crl"},
	"Certificate.ownerType":     {"INDIVIDUAL", "LEGAL_PERSON", "INFOSYSTEM", "UNKNOWN"},
	"Claims.owner_type":         {"INDIVIDUAL", "LEGAL_PERSON", "INFOSYSTEM", "UNKNOWN"},
	"Subject.gender":            {"MALE", "FEMALE", "NONE"},
	"Claims.gender":             {"male", "female"},
	"Signer.cadesLevel":         {"BES", "T"},
	"SignResponse.cadesLevel":   {"BES", "T"},
	"QRCreateRequest.mode":      {"sign", "auth"},
	"QRCreateRequest.profile":   {"agnostic", "egov", "relay"},
	"QRCreateRequest.format":    {"cms", "xml", "wsse"},

	"VerificationReport.verdict":    {"valid", "invalid", "indeterminate"},
	"RegistryRow.verdict":           {"valid", "invalid", "indeterminate"},
	"ArchiveResponse.level":         {"LT"},
	"MultisignCreateRequest.format": {"cms", "xml"},
	"MultisignSession.format":       {"cms", "xml"},
	"MultisignSession.status":       {"pending", "complete", "expired"},
	"RegistryItemRequest.format":    {"cms", "xml", "wsse"},
}

func main() {
	root, err := os.Getwd()
	must(err)

	schemas := reflectSchemas()
	applyEnums(schemas)
	addQRSchemas(schemas)
	addBatchSchemas(schemas)
	addAppSchemas(schemas)
	addOIDCSchemas(schemas)

	doc := buildDoc(schemas)
	writeOpenAPI(filepath.Join(root, "api", "openapi.yaml"), doc)
	writePostman(filepath.Join(root, "deploy", "postman", "qoltanba.postman_collection.json"))
	fmt.Println("generated api/openapi.yaml and deploy/postman/qoltanba.postman_collection.json")
}

// reflectSchemas reflects every top type and merges all named definitions into one
// component map, renaming top types and rewriting $ref to the components path.
func reflectSchemas() map[string]any {
	r := &jsonschema.Reflector{ExpandedStruct: false}
	out := map[string]any{}
	for _, st := range topTypes {
		s := r.Reflect(st.typ)
		raw, err := json.Marshal(s)
		must(err)
		var m map[string]any
		must(json.Unmarshal(raw, &m))
		defs, _ := m["$defs"].(map[string]any)
		// The Go type name invopop assigned to the reflected root.
		goName := reflect.TypeOf(st.typ).Elem().Name()
		// A root's own rename overrides the shared map: two packages can export the
		// same type name (audit.VerifyResult, signedqr.VerifyResult), and only the
		// pass that is reflecting one of them knows which is meant.
		renames := map[string]string{}
		for k, v := range rootRenames() {
			renames[k] = v
		}
		for k, v := range nestedRenames {
			renames[k] = v
		}
		renames[goName] = st.name // rename the root (e.g. SignOutput → SignResponse)
		for name, def := range defs {
			target := name
			if r, ok := renames[name]; ok {
				target = r
			}
			cleaned := cleanSchema(def, renames)
			if prev, ok := out[target]; ok && !sameSchema(prev, cleaned) {
				panic("component name collision: " + target + " (add a nestedRenames entry)")
			}
			out[target] = cleaned
		}
	}
	return out
}

// rootRenames maps every unambiguously-named top type's Go name to its component
// name, so a $ref reaching one from another root's schema still resolves. Go
// names claimed by more than one top type are left out — the per-pass override
// resolves those, since a shared map cannot say which package is meant.
func rootRenames() map[string]string {
	claimed := map[string]int{}
	for _, st := range topTypes {
		claimed[reflect.TypeOf(st.typ).Elem().Name()]++
	}
	out := map[string]string{}
	for _, st := range topTypes {
		if goName := reflect.TypeOf(st.typ).Elem().Name(); claimed[goName] == 1 {
			out[goName] = st.name
		}
	}
	return out
}

// sameSchema reports whether two reflected definitions are identical, so a type
// reached from several roots is not mistaken for a name collision.
func sameSchema(a, b any) bool {
	x, err := json.Marshal(a)
	must(err)
	y, err := json.Marshal(b)
	must(err)
	return bytes.Equal(x, y)
}

// cleanSchema strips reflector bookkeeping keys and rewrites $ref recursively.
func cleanSchema(v any, renames map[string]string) any {
	switch t := v.(type) {
	case map[string]any:
		delete(t, "$schema")
		delete(t, "$id")
		delete(t, "additionalProperties")
		for k, val := range t {
			if k == "$ref" {
				if s, ok := val.(string); ok {
					t[k] = rewriteRef(s, renames)
				}
				continue
			}
			t[k] = cleanSchema(val, renames)
		}
		return t
	case []any:
		for i := range t {
			t[i] = cleanSchema(t[i], renames)
		}
		return t
	default:
		return v
	}
}

func rewriteRef(ref string, renames map[string]string) string {
	const p = "#/$defs/"
	if len(ref) > len(p) && ref[:len(p)] == p {
		name := ref[len(p):]
		if r, ok := renames[name]; ok {
			name = r
		}
		return "#/components/schemas/" + name
	}
	return ref
}

// applyEnums injects enum lists onto the named schema properties.
func applyEnums(schemas map[string]any) {
	for key, vals := range enums {
		schema, prop := splitKey(key)
		s, ok := schemas[schema].(map[string]any)
		if !ok {
			panic("enum target schema missing: " + schema)
		}
		props, ok := s["properties"].(map[string]any)
		if !ok {
			panic("enum target has no properties: " + schema)
		}
		p, ok := props[prop].(map[string]any)
		if !ok {
			panic("enum target property missing: " + key)
		}
		arr := make([]any, len(vals))
		for i, v := range vals {
			arr[i] = v
		}
		p["enum"] = arr
	}
}

func splitKey(key string) (schema, prop string) {
	for i := 0; i < len(key); i++ {
		if key[i] == '.' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func writeOpenAPI(path string, doc map[string]any) {
	out, err := sigsyaml.Marshal(doc)
	must(err)
	banner := []byte("# Code generated by tools/openapigen; DO NOT EDIT.\n# Regenerate with `make openapi`.\n")
	must(os.WriteFile(path, append(banner, out...), 0o644))
}
