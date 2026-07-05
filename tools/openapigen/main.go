// Command openapigen generates api/openapi.yaml and the Postman collection from
// the Go request/response types, so the schemas never drift from the code. The
// drift-prone part — the component schemas — is reflected from internal/transport/dto
// (requests) and internal/core (responses); the stable part — paths, info, enums —
// is declared here. Run via `make openapi`; a CI diff-gate fails if the committed
// files are stale.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/invopop/jsonschema"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/jobs"
	"github.com/uelnur/qoltanba/internal/oidc"
	"github.com/uelnur/qoltanba/internal/qr"
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
	{"ExtractRequest", &dto.ExtractRequest{}},
	{"CertInfoRequest", &dto.CertInfoRequest{}},
	{"ValidateRequest", &dto.ValidateRequest{}},
	{"SignResponse", &core.SignOutput{}},
	{"VerifyResponse", &core.VerifyOutput{}},
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
}

// enums enriches specific properties the reflector cannot infer (Go string types
// carry no value set). Keyed by "Schema.property".
var enums = map[string][]string{
	"SignRequest.format":       {"cms", "xml", "wsse"},
	"VerifyRequest.format":     {"cms", "xml", "wsse"},
	"ExtractRequest.format":    {"cms", "xml", "wsse"},
	"SignResponse.format":      {"cms", "xml", "wsse"},
	"VerifyResponse.format":    {"cms", "xml", "wsse"},
	"CertInfoRequest.encoding": {"pem", "der", "base64"},
	"ValidateRequest.encoding": {"pem", "der", "base64"},
	"CertInfoRequest.method":   {"ocsp", "crl"},
	"ValidateRequest.method":   {"ocsp", "crl"},
	"RevocationStatus.method":  {"ocsp", "crl"},
	"Certificate.ownerType":    {"INDIVIDUAL", "LEGAL_PERSON", "INFOSYSTEM", "UNKNOWN"},
	"Claims.owner_type":        {"INDIVIDUAL", "LEGAL_PERSON", "INFOSYSTEM", "UNKNOWN"},
	"Subject.gender":           {"MALE", "FEMALE", "NONE"},
	"Claims.gender":            {"male", "female"},
	"Signer.cadesLevel":        {"BES", "T"},
	"SignResponse.cadesLevel":  {"BES", "T"},
	"QRCreateRequest.mode":     {"sign", "auth"},
	"QRCreateRequest.profile":  {"agnostic", "egov", "relay"},
	"QRCreateRequest.format":   {"cms", "xml", "wsse"},
}

func main() {
	root, err := os.Getwd()
	must(err)

	schemas := reflectSchemas()
	applyEnums(schemas)
	addQRSchemas(schemas)
	addBatchSchemas(schemas)
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
		for name, def := range defs {
			target := name
			if name == goName {
				target = st.name // rename the root (e.g. SignOutput → SignResponse)
			}
			out[target] = cleanSchema(def)
		}
	}
	return out
}

// cleanSchema strips reflector bookkeeping keys and rewrites $ref recursively.
func cleanSchema(v any) any {
	switch t := v.(type) {
	case map[string]any:
		delete(t, "$schema")
		delete(t, "$id")
		delete(t, "additionalProperties")
		for k, val := range t {
			if k == "$ref" {
				if s, ok := val.(string); ok {
					t[k] = rewriteRef(s)
				}
				continue
			}
			t[k] = cleanSchema(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = cleanSchema(t[i])
		}
		return t
	default:
		return v
	}
}

func rewriteRef(ref string) string {
	const p = "#/$defs/"
	if len(ref) > len(p) && ref[:len(p)] == p {
		name := ref[len(p):]
		// Rename any renamed root types in refs too.
		for _, st := range topTypes {
			if goName := reflect.TypeOf(st.typ).Elem().Name(); name == goName {
				name = st.name
			}
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
