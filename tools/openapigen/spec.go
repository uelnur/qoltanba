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
	{"POST", "/sign/batch", "signBatch", "batch", "Sign many items (aggregated JSON, or NDJSON stream with Accept: application/x-ndjson)",
		"SignBatchRequest", "SignBatchResponse", "Per-item results in request order, plus a summary",
		`{"items":[{"format":"cms","data":"{{dataBase64}}","key":{"path":{"path":"/keys/signer.p12","password":"{{keyPassword}}"}}}],"policy":"continue-on-error"}`},
	{"POST", "/verify/batch", "verifyBatch", "batch", "Verify many signatures",
		"VerifyBatchRequest", "VerifyBatchResponse", "Per-item results in request order, plus a summary",
		`{"items":[{"format":"cms","signature":"{{signatureBase64}}"}],"policy":"continue-on-error"}`},
	{"POST", "/extract/batch", "extractBatch", "batch", "Recover content from many attached signatures",
		"ExtractBatchRequest", "ExtractBatchResponse", "Per-item results in request order, plus a summary",
		`{"items":[{"format":"cms","signature":"{{signatureBase64}}"}]}`},
	{"POST", "/cert/info/batch", "certInfoBatch", "batch", "Parse many certificates",
		"CertInfoBatchRequest", "CertInfoBatchResponse", "Per-item results in request order, plus a summary",
		`{"items":[{"cert":"{{certBase64}}","encoding":"der"}]}`},
	{"POST", "/cert/validate/batch", "certValidateBatch", "batch", "Check revocation for many certificates",
		"CertValidateBatchRequest", "CertValidateBatchResponse", "Per-item results in request order, plus a summary",
		`{"items":[{"cert":"{{certBase64}}","encoding":"der","method":"ocsp"}]}`},
}

// batchOps maps each batch endpoint to the single-call request/response schemas
// its items and results reuse, so addBatchSchemas composes the generic wrappers
// without reflecting Go generics (whose names carry full import paths).
var batchOps = []struct{ title, reqSchema, respSchema string }{
	{"Sign", "SignRequest", "SignResponse"},
	{"Verify", "VerifyRequest", "VerifyResponse"},
	{"Extract", "ExtractRequest", "ExtractResponse"},
	{"CertInfo", "CertInfoRequest", "CertInfoResponse"},
	{"CertValidate", "ValidateRequest", "ValidateResponse"},
}

// addBatchSchemas composes the batch request/item/response components for every
// operation from the existing single-call schemas.
func addBatchSchemas(schemas map[string]any) {
	for _, b := range batchOps {
		schemas[b.title+"BatchRequest"] = map[string]any{
			"type":        "object",
			"description": "A batch of " + b.reqSchema + " items with batch-wide controls.",
			"properties": map[string]any{
				"items":       map[string]any{"type": "array", "items": ref(b.reqSchema)},
				"policy":      map[string]any{"type": "string", "enum": []any{"continue-on-error", "fail-fast"}, "description": "error policy (default continue-on-error)"},
				"concurrency": map[string]any{"type": "integer", "description": "max items in parallel (0 = driver pool size)"},
			},
			"required": []any{"items"},
		}
		schemas[b.title+"BatchItem"] = map[string]any{
			"type": "object",
			"properties": map[string]any{
				"index":  map[string]any{"type": "integer", "description": "position in the request"},
				"status": map[string]any{"type": "string", "enum": []any{"ok", "error", "skipped"}},
				"output": ref(b.respSchema),
				"error":  ref("BatchItemError"),
			},
		}
		schemas[b.title+"BatchResponse"] = map[string]any{
			"type": "object",
			"properties": map[string]any{
				"total":     map[string]any{"type": "integer"},
				"succeeded": map[string]any{"type": "integer"},
				"failed":    map[string]any{"type": "integer"},
				"results":   map[string]any{"type": "array", "items": ref(b.title + "BatchItem")},
			},
		}
	}
	schemas["JobSubmitRequest"] = map[string]any{
		"type":        "object",
		"description": "Submit an operation to run as an async job. request is the op payload (the same JSON as the sync endpoint, single or batch).",
		"properties": map[string]any{
			"op":          map[string]any{"type": "string", "description": "operation name, e.g. sign, verify, sign-batch"},
			"request":     map[string]any{"type": "object", "description": "the op payload"},
			"callbackUrl": map[string]any{"type": "string", "description": "optional webhook POSTed the job status view on completion"},
		},
		"required": []any{"op", "request"},
	}
}

// oidcEndpoints drive the Postman collection for the OIDC flow. Their OpenAPI
// paths are authored in addOIDCPaths (they mix GET/POST and use the OAuth2 error
// shape), but the summaries and example bodies live here so Postman stays in sync.
var oidcEndpoints = []endpoint{
	{"GET", "/.well-known/openid-configuration", "oidcDiscovery", "oidc", "OpenID Connect discovery document", "", "OIDCDiscovery", "Discovery metadata", ""},
	{"GET", "/oidc/jwks.json", "oidcJWKS", "oidc", "JSON Web Key Set for token verification", "", "OIDCJWKS", "Public signing keys", ""},
	{"POST", "/oidc/challenge", "oidcChallenge", "oidc", "Issue a challenge nonce to sign with ЭЦП",
		"OIDCChallengeRequest", "OIDCChallengeResponse", "Challenge to sign (detached CMS over the nonce)",
		`{"nonce":"{{rpNonce}}","state":"{{rpState}}"}`},
	{"POST", "/oidc/verify", "oidcVerify", "oidc", "Verify the signed challenge and issue OIDC tokens",
		"OIDCVerifyRequest", "OIDCTokenResponse", "Token set (id_token, access_token)",
		`{"challengeId":"{{challengeId}}","signature":"{{signatureBase64}}","clientId":"{{clientId}}"}`},
	{"GET", "/oidc/userinfo", "oidcUserInfo", "oidc", "Claims for a bearer access token", "", "", "Claim set for the token subject", ""},
}

// addOIDCSchemas declares the OAuth2 error envelope used by the OIDC endpoints
// (distinct from the service's generic ErrorEnvelope, per the OIDC contract).
func addOIDCSchemas(schemas map[string]any) {
	schemas["OAuthError"] = map[string]any{
		"type":        "object",
		"description": "OAuth2/OIDC error response.",
		"properties": map[string]any{
			"error":             map[string]any{"type": "string", "enum": []any{"invalid_request", "invalid_grant", "access_denied", "invalid_token", "server_error"}},
			"error_description": map[string]any{"type": "string"},
		},
		"required": []any{"error"},
	}
}

// addOIDCPaths declares the OIDC endpoints. They mix methods and use the OAuth2
// error envelope, so they are authored here rather than via the POST-only table.
func addOIDCPaths(paths map[string]any) {
	oauthErr := func(codes ...string) map[string]any {
		r := map[string]any{}
		for _, c := range codes {
			r[c] = map[string]any{
				"description": "OAuth2 error",
				"content":     map[string]any{"application/json": map[string]any{"schema": ref("OAuthError")}},
			}
		}
		return r
	}
	paths["/.well-known/openid-configuration"] = map[string]any{
		"get": oidcGet("oidcDiscovery", "OpenID Connect discovery document", "Discovery metadata", "OIDCDiscovery"),
	}
	paths["/oidc/jwks.json"] = map[string]any{
		"get": oidcGet("oidcJWKS", "JSON Web Key Set for token verification", "Public signing keys", "OIDCJWKS"),
	}
	paths["/oidc/userinfo"] = map[string]any{
		"get": func() map[string]any {
			op := oidcGet("oidcUserInfo", "Claims for a bearer access token (Authorization: Bearer <access_token>)", "Claim set for the token subject", "")
			resp := op["responses"].(map[string]any)
			for k, v := range oauthErr("401") {
				resp[k] = v
			}
			return op
		}(),
	}
	post := func(opID, summary, req, resp, respDesc string, errCodes ...string) map[string]any {
		responses := map[string]any{"200": jsonResponse(respDesc, resp)}
		for k, v := range oauthErr(errCodes...) {
			responses[k] = v
		}
		return map[string]any{
			"tags":        []any{"oidc"},
			"summary":     summary,
			"operationId": opID,
			"requestBody": map[string]any{
				"required": true,
				"content":  map[string]any{"application/json": map[string]any{"schema": ref(req)}},
			},
			"responses": responses,
		}
	}
	paths["/oidc/challenge"] = map[string]any{
		"post": post("oidcChallenge", "Issue a challenge nonce to sign with ЭЦП", "OIDCChallengeRequest", "OIDCChallengeResponse", "Challenge to sign (detached CMS over the nonce)", "400"),
	}
	paths["/oidc/verify"] = map[string]any{
		"post": post("oidcVerify", "Verify the signed challenge and issue OIDC tokens", "OIDCVerifyRequest", "OIDCTokenResponse", "Token set (id_token, access_token)", "400", "401"),
	}
}

// oidcGet builds a GET operation with a single JSON 200 response.
func oidcGet(opID, summary, respDesc, schema string) map[string]any {
	return map[string]any{
		"tags":        []any{"oidc"},
		"summary":     summary,
		"operationId": opID,
		"responses":   map[string]any{"200": jsonResponse(respDesc, schema)},
	}
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
			map[string]any{"name": "batch", "description": "Batched operations (aggregated or NDJSON stream)"},
			map[string]any{"name": "jobs", "description": "Async jobs for large/slow work (submit, poll, cancel)"},
			map[string]any{"name": "oidc", "description": "Login with ЭЦП: OpenID Connect discovery, challenge/verify, tokens"},
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
	addJobPaths(paths)
	addOIDCPaths(paths)
	return paths
}

// idParam is the {id} path parameter shared by the per-job endpoints.
var idParam = []any{map[string]any{
	"name": "id", "in": "path", "required": true,
	"schema": map[string]any{"type": "string"}, "description": "job id",
}}

// addJobPaths declares the async-job endpoints. They vary by method, path
// parameter and status codes, so they are authored here rather than via the
// POST-only endpoint table.
func addJobPaths(paths map[string]any) {
	paths["/jobs"] = map[string]any{
		"post": map[string]any{
			"tags":        []any{"jobs"},
			"summary":     "Submit an operation as an async job",
			"operationId": "submitJob",
			"requestBody": map[string]any{
				"required": true,
				"content":  map[string]any{"application/json": map[string]any{"schema": ref("JobSubmitRequest")}},
			},
			"responses": map[string]any{
				"202": jsonResponse("Job accepted; poll /jobs/{id}. The Location header points at the job.", "JobStatus"),
				"400": ref2("responses", "Error"),
				"413": ref2("responses", "Error"),
				"503": ref2("responses", "Error"),
			},
		},
	}
	paths["/jobs/{id}"] = map[string]any{
		"get": map[string]any{
			"tags":        []any{"jobs"},
			"summary":     "Job status (no request payload or result — poll until terminal)",
			"operationId": "getJob",
			"parameters":  idParam,
			"responses": map[string]any{
				"200": jsonResponse("Job status view", "JobStatus"),
				"404": ref2("responses", "Error"),
			},
		},
		"delete": map[string]any{
			"tags":        []any{"jobs"},
			"summary":     "Cancel a job (idempotent)",
			"operationId": "cancelJob",
			"parameters":  idParam,
			"responses": map[string]any{
				"200": jsonResponse("Job status after cancellation", "JobStatus"),
				"404": ref2("responses", "Error"),
			},
		},
	}
	paths["/jobs/{id}/result"] = map[string]any{
		"get": map[string]any{
			"tags":        []any{"jobs"},
			"summary":     "Job result — the operation output once the job succeeded",
			"operationId": "getJobResult",
			"parameters":  idParam,
			"responses": map[string]any{
				"200": map[string]any{"description": "The operation output (shape depends on the job's op)"},
				"404": ref2("responses", "Error"),
				"409": jsonResponse("Job not finished yet — keep polling", "JobStatus"),
				"422": jsonResponse("Job failed or was canceled (see error in the view)", "JobStatus"),
			},
		},
	}
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
	all := append([]endpoint{}, endpoints...)
	all = append(all, oidcEndpoints...)
	all = append(all, obsEndpoints...)
	for _, e := range all {
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
