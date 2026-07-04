package main

import (
	"encoding/json"
	"os"
	"strings"
)

// endpoint drives both the OpenAPI paths and the Postman collection from one
// declaration. reqSchema/respSchema are component names ("" for none); body is an
// example request body for Postman (with {{variables}}).
type endpoint struct {
	method, path, opID, tag, summary string
	reqSchema, respSchema, respDesc  string
	body                             string
}

var endpoints = []endpoint{
	{"POST", "/sign", "sign", "signature", "Sign data (CMS / XML / WSSE)",
		"SignRequest", "SignResponse", "Signature produced (check libError for a crypto-core failure)",
		`{"format":"cms","data":"{{dataBase64}}","key":{"path":{"path":"/keys/signer.p12","password":"{{keyPassword}}"}},"detached":false,"withTimestamp":false}`},
	{"POST", "/sign/add", "signAdd", "signature", "Co-sign — add a signer to an already-signed container",
		"SignRequest", "SignResponse", "Signature produced",
		`{"format":"cms","data":"{{dataBase64}}","key":{"path":{"path":"/keys/signer2.p12","password":"{{keyPassword}}"}},"existingSignature":"{{signatureBase64}}"}`},
	{"POST", "/verify", "verify", "signature", "Verify a signature and extract everything available",
		"VerifyRequest", "VerifyResponse", "Verification outcome (an invalid signature is valid=false + libError, still HTTP 200)",
		`{"format":"cms","signature":"{{signatureBase64}}","checkCertTime":true,"extractContent":true,"claims":true}`},
	{"POST", "/extract", "extract", "signature", "Recover the original content from an attached signature",
		"ExtractRequest", "ExtractResponse", "Recovered content",
		`{"format":"cms","signature":"{{signatureBase64}}"}`},
	{"POST", "/cert/info", "certInfo", "certificate", "Fully parse a certificate (optionally build/validate the chain, add claims)",
		"CertInfoRequest", "CertInfoResponse", "Parsed certificate plus optional chain and claims",
		`{"cert":"{{certBase64}}","encoding":"der","buildChain":true,"claims":true}`},
	{"POST", "/cert/validate", "certValidate", "certificate", "Check a certificate's revocation status (OCSP / CRL)",
		"ValidateRequest", "ValidateResponse", "Revocation-status outcome",
		`{"cert":"{{certBase64}}","encoding":"der","method":"ocsp","wantOcsp":true}`},
}

var obsEndpoints = []endpoint{
	{"GET", "/healthz", "healthz", "observability", "Liveness — the process is up", "", "", "ok", ""},
	{"GET", "/readyz", "readyz", "observability", "Readiness — library loaded and self-tested", "", "", "ready", ""},
	{"GET", "/statusz", "statusz", "observability", "Non-sensitive service status (no secrets)", "", "", "Status info", ""},
	{"GET", "/metrics", "metrics", "observability", "Prometheus metrics", "", "", "Prometheus text exposition", ""},
}

func buildDoc(schemas map[string]any) map[string]any {
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "qoltanba REST API",
			"version": "v1",
			"description": "REST/JSON transport for the qoltanba digital-signature service (RK / Kalkan). " +
				"One call handles one item. Binary fields are base64-encoded strings; times are RFC 3339. " +
				"All request and response keys are lowerCamelCase. Generated from the Go types — do not edit by hand.",
			"license": map[string]any{
				"name": "Proprietary Kalkan library is BYOL; this service is separate.",
			},
		},
		"servers": []any{
			map[string]any{"url": "http://localhost:8080", "description": "Default REST work port (-http :8080)"},
		},
		"tags": []any{
			map[string]any{"name": "signature", "description": "Sign, verify, extract"},
			map[string]any{"name": "certificate", "description": "Certificate parsing and revocation"},
			map[string]any{"name": "observability", "description": "Health, status, metrics"},
		},
		"paths": buildPaths(),
		"components": map[string]any{
			"schemas": schemas,
			"responses": map[string]any{
				"Error": map[string]any{
					"description": "Hard failure envelope (friendly message from the error catalog)",
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": ref("ErrorEnvelope"),
						},
					},
				},
			},
		},
	}
}

func buildPaths() map[string]any {
	paths := map[string]any{}
	for _, e := range endpoints {
		op := map[string]any{
			"tags":        []any{e.tag},
			"summary":     e.summary,
			"operationId": e.opID,
			"responses": map[string]any{
				"200": jsonResponse(e.respDesc, e.respSchema),
				"400": ref2("responses", "Error"),
				"500": ref2("responses", "Error"),
				"503": ref2("responses", "Error"),
			},
		}
		if e.reqSchema != "" {
			op["requestBody"] = map[string]any{
				"required": true,
				"content": map[string]any{
					"application/json": map[string]any{"schema": ref(e.reqSchema)},
				},
			}
		}
		paths[e.path] = map[string]any{"post": op}
	}
	for _, e := range obsEndpoints {
		paths[e.path] = map[string]any{
			"get": map[string]any{
				"tags":        []any{e.tag},
				"summary":     e.summary,
				"operationId": e.opID,
				"responses": map[string]any{
					"200": map[string]any{"description": e.respDesc},
				},
			},
		}
	}
	return paths
}

func jsonResponse(desc, schema string) map[string]any {
	r := map[string]any{"description": desc}
	if schema != "" {
		r["content"] = map[string]any{
			"application/json": map[string]any{"schema": ref(schema)},
		}
	}
	return r
}

func ref(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}

func ref2(kind, name string) map[string]any {
	return map[string]any{"$ref": "#/components/" + kind + "/" + name}
}

// --- Postman (v2.1), derived from the same endpoint table ---

type pmCollection struct {
	Info     pmInfo   `json:"info"`
	Variable []pmVar  `json:"variable"`
	Item     []pmItem `json:"item"`
}
type pmInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Schema      string `json:"schema"`
}
type pmVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type pmItem struct {
	Name    string     `json:"name"`
	Item    []pmItem   `json:"item,omitempty"`
	Request *pmRequest `json:"request,omitempty"`
}
type pmRequest struct {
	Method string  `json:"method"`
	Header []pmHdr `json:"header,omitempty"`
	Body   *pmBody `json:"body,omitempty"`
	URL    pmURL   `json:"url"`
}
type pmHdr struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type pmBody struct {
	Mode string `json:"mode"`
	Raw  string `json:"raw"`
}
type pmURL struct {
	Raw  string   `json:"raw"`
	Host []string `json:"host"`
	Path []string `json:"path"`
}

func writePostman(path string) {
	col := pmCollection{
		Info: pmInfo{
			Name: "qoltanba REST API",
			Description: "Generated from the Go types (tools/openapigen). Set {{baseUrl}} and the " +
				"base64/secret variables. All keys are lowerCamelCase.",
			Schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
		},
		Variable: []pmVar{{Key: "baseUrl", Value: "http://localhost:8080"}},
	}
	folders := map[string]int{} // tag → index in col.Item
	add := func(tag string, it pmItem) {
		idx, ok := folders[tag]
		if !ok {
			col.Item = append(col.Item, pmItem{Name: title(tag)})
			idx = len(col.Item) - 1
			folders[tag] = idx
		}
		col.Item[idx].Item = append(col.Item[idx].Item, it)
	}
	for _, e := range append(append([]endpoint{}, endpoints...), obsEndpoints...) {
		add(e.tag, pmItem{Name: e.summary, Request: pmRequestFor(e)})
	}

	b, err := json.MarshalIndent(col, "", "  ")
	must(err)
	must(os.WriteFile(path, append(b, '\n'), 0o644))
}

func pmRequestFor(e endpoint) *pmRequest {
	req := &pmRequest{
		Method: e.method,
		URL:    pmURL{Raw: "{{baseUrl}}" + e.path, Host: []string{"{{baseUrl}}"}, Path: splitPath(e.path)},
	}
	if e.body != "" {
		req.Header = []pmHdr{{Key: "Content-Type", Value: "application/json"}}
		req.Body = &pmBody{Mode: "raw", Raw: e.body}
	}
	return req
}

func splitPath(p string) []string {
	out := []string{}
	seg := ""
	for i := 1; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			if seg != "" {
				out = append(out, seg)
			}
			seg = ""
			continue
		}
		seg += string(p[i])
	}
	return out
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
