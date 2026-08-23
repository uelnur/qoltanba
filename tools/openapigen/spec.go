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
		`{"format":"cms","signature":"{{signatureBase64}}","checkCertTime":true,"extractContent":true,"claims":true,"explain":true}`},
	{"POST", "/verify/at", "verifyAt", "signature", "Historical (point-in-time) verify: was the signature valid at a past instant, reconstructing certificate validity and revocation status as of that time",
		"VerifyAtRequest", "VerifyAtResponse", "Point-in-time outcome per signer (validAt + determinate; a not-valid-then signature is validAt=false, still HTTP 200)",
		`{"format":"cms","signature":"{{signatureBase64}}","at":"2022-06-01T00:00:00Z","method":"ocsp"}`},
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
	{"POST", "/sign/archive", "archive", "signature", "Embed long-term validation evidence (CAdES-LT) into an existing signature, so it stays verifiable after the certificate expires",
		"ArchiveRequest", "ArchiveResponse", "Container with evidence embedded (an unreachable responder is a warning, not a failure)",
		`{"signature":"{{signatureBase64}}","outputPem":false}`},
	{"POST", "/verify/registry", "verifyRegistry", "batch", "Verify a set of documents and return the auditor's register: counts plus one row per document with its verdict, signers and first failing check",
		"VerifyRegistryRequest", "RegistryResponse", "Register over the whole set",
		`{"items":[{"ref":"contract-2024-11.p7s","format":"cms","signature":"{{signatureBase64}}"}],"policy":"continue-on-error"}`},
	{"POST", "/challenge", "challengeIssue", "challenge", "Issue a single-use nonce bound to a purpose (the anti-replay handshake as a standalone primitive)",
		"ChallengeIssueRequest", "ChallengeIssueResponse", "Nonce to sign as a detached CMS",
		`{"purpose":"payment.approve","meta":{"orderId":"1042"}}`},
	{"POST", "/challenge/confirm", "challengeConfirm", "challenge", "Confirm a challenge with the user's detached signature and report who signed it",
		"ChallengeConfirmRequest", "ChallengeConfirmResponse", "Who signed the challenge, and for what",
		`{"challengeId":"{{challengeId}}","signature":"{{signatureBase64}}"}`},
	{"POST", "/qr/documents", "signedQRIssue", "signed-qr", "Issue a QR carrying a short statement signed with the service key (verifiable offline, no ЭЦП needed to check it)",
		"SignedQRIssueRequest", "SignedQRIssueResponse", "Compact JWS payload plus a rendered PNG",
		`{"subject":"{{iin}}","data":{"permit":"A-142"},"ttlSeconds":86400}`},
	{"POST", "/qr/documents/verify", "signedQRVerify", "signed-qr", "Check a scanned document QR against the service key",
		"SignedQRVerifyRequest", "SignedQRVerifyResult", "Verification result (a forged or expired code is valid=false, still HTTP 200)",
		`{"payload":"{{qrPayload}}"}`},
	{"POST", "/sandbox/sign", "sandboxSign", "sandbox", "Sign with the operator's demo key, so the service can be evaluated without an ЭЦП of one's own (off unless a sandbox key is configured)",
		"SandboxSignRequest", "SignResponse", "Signature produced with the demo key",
		`{"data":"{{dataBase64}}","format":"cms"}`},
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

// addAppSchemas declares the small request bodies the handlers read as anonymous
// structs (they have no named Go type to reflect), plus the register's batch
// wrapper, which reuses the batch controls over registry items.
func addAppSchemas(schemas map[string]any) {
	schemas["VerifyRegistryRequest"] = map[string]any{
		"type":        "object",
		"description": "A set of documents to check, each optionally labeled with the caller's own reference.",
		"properties": map[string]any{
			"items":       map[string]any{"type": "array", "items": ref("RegistryItemRequest")},
			"policy":      map[string]any{"type": "string", "enum": []any{"continue-on-error", "fail-fast"}, "description": "error policy (default continue-on-error)"},
			"concurrency": map[string]any{"type": "integer", "description": "max items in parallel (0 = driver pool size)"},
		},
		"required": []any{"items"},
	}
	schemas["MultisignSubmitRequest"] = map[string]any{
		"type":        "object",
		"description": "The container as it stands after a participant co-signed it elsewhere. The service verifies it and counts the new signer; it never signs here.",
		"properties": map[string]any{
			"container": map[string]any{"type": "string", "format": "byte", "description": "base64 co-signed container"},
		},
		"required": []any{"container"},
	}
	schemas["SignedQRVerifyRequest"] = map[string]any{
		"type":        "object",
		"description": "A scanned QR payload (the compact JWS the code encodes).",
		"properties": map[string]any{
			"payload": map[string]any{"type": "string"},
		},
		"required": []any{"payload"},
	}
	schemas["SandboxSignRequest"] = map[string]any{
		"type":        "object",
		"description": "Bytes to sign with the operator's demo key. Certificate-time checking is off: a demo container is usually expired or issued by a test CA.",
		"properties": map[string]any{
			"data":   map[string]any{"type": "string", "format": "byte", "description": "base64 content to sign"},
			"format": map[string]any{"type": "string", "enum": []any{"cms", "xml", "wsse"}, "description": "default cms"},
		},
		"required": []any{"data"},
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

// qrEndpoints drive the Postman collection for the QR flow. The app-facing pair
// (/qr/a/{id}) is hit by eGov Mobile, not the consumer, so it is documented but
// carries no Postman example body beyond a placeholder.
var qrEndpoints = []endpoint{
	{"POST", "/qr/sessions", "qrCreate", "qr", "Start an eGov Mobile QR signing/auth session",
		"QRCreateRequest", "QRCreateResponse", "Session created (render qr as a PNG; poll the session)",
		`{"mode":"sign","profile":"agnostic","data":"{{dataBase64}}","callbackUrl":"{{callbackUrl}}"}`},
	{"GET", "/qr/sessions/{id}", "qrGet", "qr", "Poll a QR session for the verified result or tokens", "", "QRView", "Session view", ""},
	{"GET", "/qr/a/{id}", "qrAppData", "qr", "App-facing: eGov Mobile fetches the data-to-sign", "", "", "Data-to-sign", ""},
	{"POST", "/qr/a/{id}", "qrAppSubmit", "qr", "App-facing: eGov Mobile returns the signature", "", "", "Accepted", `{"signature":"{{signatureBase64}}"}`},
}

// addQRSchemas hand-authors the QR session view (its result is polymorphic — a
// SignResult or an OIDC token set — so it does not reflect cleanly).
func addQRSchemas(schemas map[string]any) {
	schemas["QRView"] = map[string]any{
		"type":        "object",
		"description": "Client-safe QR session view (no data-to-sign or callback).",
		"properties": map[string]any{
			"id":        map[string]any{"type": "string"},
			"mode":      map[string]any{"type": "string", "enum": []any{"sign", "auth"}},
			"profile":   map[string]any{"type": "string", "enum": []any{"agnostic", "egov", "relay"}},
			"status":    map[string]any{"type": "string", "enum": []any{"pending", "verified", "failed", "expired"}},
			"expiresAt": map[string]any{"type": "string", "format": "date-time"},
			"result":    map[string]any{"type": "object", "description": "SignResult (sign mode) or OIDC token set (auth mode)"},
			"error":     ref("BatchItemError"),
		},
	}
}

// addQRPaths declares the QR endpoints (mixed methods with path params).
func addQRPaths(paths map[string]any) {
	idParam := []any{map[string]any{
		"name": "id", "in": "path", "required": true,
		"schema": map[string]any{"type": "string"},
	}}
	errs := map[string]any{"400": ref2("responses", "Error"), "404": ref2("responses", "Error"), "500": ref2("responses", "Error")}
	withErrs := func(m map[string]any) map[string]any {
		for k, v := range errs {
			m[k] = v
		}
		return m
	}
	paths["/qr/sessions"] = map[string]any{"post": map[string]any{
		"tags": []any{"qr"}, "summary": "Start an eGov Mobile QR signing/auth session", "operationId": "qrCreate",
		"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": ref("QRCreateRequest")}}},
		"responses":   withErrs(map[string]any{"201": jsonResponse("Session created", "QRCreateResponse")}),
	}}
	paths["/qr/sessions/{id}"] = map[string]any{"get": map[string]any{
		"tags": []any{"qr"}, "summary": "Poll a QR session for the verified result or tokens", "operationId": "qrGet",
		"parameters": idParam,
		"responses":  withErrs(map[string]any{"200": jsonResponse("Session view", "QRView")}),
	}}
	paths["/qr/a/{id}"] = map[string]any{
		"get": map[string]any{
			"tags": []any{"qr"}, "summary": "App-facing: eGov Mobile fetches the data-to-sign", "operationId": "qrAppData",
			"parameters": idParam,
			"responses":  withErrs(map[string]any{"200": map[string]any{"description": "Data-to-sign (profile-specific)"}}),
		},
		"post": map[string]any{
			"tags": []any{"qr"}, "summary": "App-facing: eGov Mobile returns the signature", "operationId": "qrAppSubmit",
			"parameters": idParam,
			"responses":  withErrs(map[string]any{"200": map[string]any{"description": "Signature accepted"}}),
		},
	}
}

// multisignEndpoints drive the Postman collection for the multi-signature flow.
// Their OpenAPI paths are authored in addMultisignPaths (mixed methods, 201/204).
var multisignEndpoints = []endpoint{
	{"POST", "/multisign/sessions", "multisignCreate", "multisign", "Open a session for a document that needs several signatures",
		"MultisignCreateRequest", "MultisignSession", "Session opened",
		`{"format":"cms","document":"{{dataBase64}}","required":[{"iin":"{{iin}}","label":"Директор"},{"role":"CEO"}],"subject":"Договор №42","ttlSeconds":604800}`},
	{"GET", "/multisign/sessions/{id}", "multisignGet", "multisign", "Session state: who has signed, who is still owed, and the container as it stands", "", "MultisignSession", "Session view", ""},
	{"POST", "/multisign/sessions/{id}/signatures", "multisignSubmit", "multisign", "Submit the container after a participant co-signed it",
		"MultisignSubmitRequest", "MultisignSession", "Session after counting the new signer",
		`{"container":"{{signatureBase64}}"}`},
	{"DELETE", "/multisign/sessions/{id}", "multisignCancel", "multisign", "Cancel a session", "", "", "Canceled", ""},
}

// addMultisignPaths declares the session endpoints (mixed methods, path param).
func addMultisignPaths(paths map[string]any) {
	sessionID := []any{map[string]any{
		"name": "id", "in": "path", "required": true,
		"schema": map[string]any{"type": "string"}, "description": "session id",
	}}
	op := func(e endpoint, okCode string, okDesc string, params []any) map[string]any {
		responses := map[string]any{
			okCode: jsonResponse(okDesc, e.respSchema),
			"400":  ref2("responses", "Error"),
			"404":  ref2("responses", "Error"),
			"500":  ref2("responses", "Error"),
		}
		o := map[string]any{
			"tags": []any{e.tag}, "summary": e.summary, "operationId": e.opID,
			"responses": responses,
		}
		if params != nil {
			o["parameters"] = params
		}
		if e.reqSchema != "" {
			o["requestBody"] = map[string]any{
				"required": true,
				"content":  map[string]any{"application/json": map[string]any{"schema": ref(e.reqSchema)}},
			}
		}
		return o
	}
	paths["/multisign/sessions"] = map[string]any{
		"post": op(multisignEndpoints[0], "201", "Session opened", nil),
	}
	paths["/multisign/sessions/{id}"] = map[string]any{
		"get":    op(multisignEndpoints[1], "200", "Session view", sessionID),
		"delete": op(multisignEndpoints[3], "204", "Session canceled (no body)", sessionID),
	}
	paths["/multisign/sessions/{id}/signatures"] = map[string]any{
		"post": op(multisignEndpoints[2], "200", "Session after counting the new signer", sessionID),
	}
}

// auditEndpoints drive the Postman collection for the audit journal. Both are
// GETs whose interesting part is the status code and the media type, so their
// paths are authored in addAuditPaths.
var auditEndpoints = []endpoint{
	{"GET", "/audit/verify", "auditVerify", "audit", "Walk the journal's hash chain and report whether — and where — it was altered", "", "AuditVerifyResult", "Chain intact", ""},
	{"GET", "/audit/export", "auditExport", "audit", "Stream the journal as NDJSON for a SIEM (supports range requests and conditional fetches)", "", "", "The journal", ""},
}

func addAuditPaths(paths map[string]any) {
	paths["/audit/verify"] = map[string]any{
		"get": map[string]any{
			"tags": []any{"audit"}, "summary": auditEndpoints[0].summary, "operationId": "auditVerify",
			"responses": map[string]any{
				"200": jsonResponse("Chain intact", "AuditVerifyResult"),
				// A broken chain is a finding about the journal, not a server fault.
				"409": jsonResponse("Chain broken — brokenAt names the first altered entry", "AuditVerifyResult"),
				"503": ref2("responses", "Error"),
			},
		},
	}
	paths["/audit/export"] = map[string]any{
		"get": map[string]any{
			"tags": []any{"audit"}, "summary": auditEndpoints[1].summary, "operationId": "auditExport",
			"responses": map[string]any{
				"200": map[string]any{
					"description": "The journal, one signed entry per line",
					"content":     map[string]any{"application/x-ndjson": map[string]any{"schema": map[string]any{"type": "string"}}},
				},
				"206": map[string]any{"description": "Partial content (range request)"},
				"503": ref2("responses", "Error"),
			},
		},
	}
}

// authEndpoints drive the Postman collection for the browser-redirect leg of
// OIDC plus the service's own JWKS. Their paths are authored in addAuthPaths:
// they speak form-encoding, HTML and redirects rather than JSON request bodies.
var authEndpoints = []endpoint{
	{"GET", "/jwks.json", "serviceJWKS", "oidc", "Public keys the service signs with — verification receipts, signed-document QR and OIDC tokens (served even when OIDC is off)", "", "OIDCJWKS", "Public signing keys", ""},
	{"GET", "/oidc/authorize", "oidcAuthorize", "oidc", "Authorization endpoint: renders the hosted login page that collects a signature (authorization code + PKCE)", "", "", "Login page", ""},
	{"POST", "/oidc/authorize", "oidcAuthorizeSubmit", "oidc", "Submit the collected signature and redirect back to the relying party with an authorization code", "", "", "Redirect to redirect_uri", ""},
	{"POST", "/oidc/token", "oidcToken", "oidc", "Token endpoint: exchange an authorization code for tokens (client credentials in the body or HTTP Basic)", "", "OIDCTokenResponse", "Token set", ""},
}

func addAuthPaths(paths map[string]any) {
	authorizeParams := func(in string) []any {
		p := []any{}
		for _, q := range []struct{ name, desc string }{
			{"client_id", "registered client id"},
			{"redirect_uri", "must match one registered for the client"},
			{"response_type", "code"},
			{"scope", "openid plus any extra scopes"},
			{"state", "opaque value echoed back to the client"},
			{"nonce", "bound into the id_token"},
			{"code_challenge", "PKCE challenge (required for public clients)"},
			{"code_challenge_method", "S256 (plain is refused for public clients)"},
		} {
			p = append(p, map[string]any{
				"name": q.name, "in": in, "required": false,
				"schema": map[string]any{"type": "string"}, "description": q.desc,
			})
		}
		return p
	}
	htmlResponse := func(desc string) map[string]any {
		return map[string]any{
			"description": desc,
			"content":     map[string]any{"text/html": map[string]any{"schema": map[string]any{"type": "string"}}},
		}
	}
	paths["/jwks.json"] = map[string]any{
		"get": oidcGet("serviceJWKS", authEndpoints[0].summary, "Public signing keys", "OIDCJWKS"),
	}
	paths["/oidc/authorize"] = map[string]any{
		"get": map[string]any{
			"tags": []any{"oidc"}, "summary": authEndpoints[1].summary, "operationId": "oidcAuthorize",
			"parameters": authorizeParams("query"),
			"responses": map[string]any{
				"200": htmlResponse("Hosted login page (NCALayer widget, plus the eGov QR option when the QR orchestrator is on)"),
				// An unverified redirect target is exactly what must not be redirected to.
				"400": htmlResponse("Client or redirect_uri rejected — rendered here rather than redirected"),
			},
		},
		"post": map[string]any{
			"tags": []any{"oidc"}, "summary": authEndpoints[2].summary, "operationId": "oidcAuthorizeSubmit",
			"requestBody": map[string]any{
				"required": true,
				"content": map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": map[string]any{
					"type":        "object",
					"description": "The authorize parameters as posted back by the login page, plus the collected signature.",
					"properties": map[string]any{
						"client_id":             map[string]any{"type": "string"},
						"redirect_uri":          map[string]any{"type": "string"},
						"response_type":         map[string]any{"type": "string"},
						"scope":                 map[string]any{"type": "string"},
						"state":                 map[string]any{"type": "string"},
						"nonce":                 map[string]any{"type": "string"},
						"code_challenge":        map[string]any{"type": "string"},
						"code_challenge_method": map[string]any{"type": "string"},
						"challengeId":           map[string]any{"type": "string", "description": "id of the challenge the page was issued"},
						"signature":             map[string]any{"type": "string", "description": "detached CMS over the challenge nonce"},
					},
					"required": []any{"challengeId", "signature"},
				}}},
			},
			"responses": map[string]any{
				"303": map[string]any{"description": "Redirect to redirect_uri with code and state"},
				"400": htmlResponse("Authorization refused (bad client, redirect_uri or signature)"),
			},
		},
	}
	paths["/oidc/token"] = map[string]any{
		"post": map[string]any{
			"tags": []any{"oidc"}, "summary": authEndpoints[3].summary, "operationId": "oidcToken",
			"requestBody": map[string]any{
				"required": true,
				"content": map[string]any{"application/x-www-form-urlencoded": map[string]any{"schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"grant_type":    map[string]any{"type": "string", "enum": []any{"authorization_code"}},
						"code":          map[string]any{"type": "string", "description": "single-use, 60 s"},
						"redirect_uri":  map[string]any{"type": "string"},
						"client_id":     map[string]any{"type": "string", "description": "or HTTP Basic"},
						"client_secret": map[string]any{"type": "string", "description": "confidential clients only"},
						"code_verifier": map[string]any{"type": "string", "description": "PKCE verifier"},
					},
					"required": []any{"grant_type", "code"},
				}}},
			},
			"responses": map[string]any{
				"200": jsonResponse("Token set (id_token, access_token)", "OIDCTokenResponse"),
				"400": map[string]any{"description": "OAuth2 error", "content": map[string]any{"application/json": map[string]any{"schema": ref("OAuthError")}}},
				"401": map[string]any{"description": "OAuth2 error", "content": map[string]any{"application/json": map[string]any{"schema": ref("OAuthError")}}},
			},
		},
	}
}

// pageEndpoints are the human-facing surfaces. They are documented so the spec
// stays a complete map of what the service serves, even though a generated SDK
// has nothing to do with an HTML page.
var pageEndpoints = []endpoint{
	{"GET", "/verify/portal", "verifyPortal", "portal", "Upload form for checking a signature (off by default — it accepts uploads from anyone who can reach it)", "", "", "The upload page", ""},
	{"POST", "/verify/portal", "verifyPortalSubmit", "portal", "Check an uploaded container and render the verification card", "", "", "The verification card", ""},
	{"GET", "/console", "console", "sandbox", "Built-in test console: pick an operation, edit the body, see the raw response (off by default)", "", "", "The console page", ""},
}

func addPagePaths(paths map[string]any) {
	html := func(desc string) map[string]any {
		return map[string]any{
			"description": desc,
			"content":     map[string]any{"text/html": map[string]any{"schema": map[string]any{"type": "string"}}},
		}
	}
	page := func(e endpoint, responses map[string]any) map[string]any {
		return map[string]any{
			"tags": []any{e.tag}, "summary": e.summary, "operationId": e.opID, "responses": responses,
		}
	}
	portalSubmit := page(pageEndpoints[1], map[string]any{
		"200": html("The verification card for the uploaded container"),
		// A check that could not run is said so on the page, not rendered as "invalid".
		"400": html("Nothing to check, or the check could not be run — the page says which"),
	})
	portalSubmit["requestBody"] = map[string]any{
		"required": true,
		"content": map[string]any{"multipart/form-data": map[string]any{"schema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"signature": map[string]any{"type": "string", "format": "binary", "description": "the signed container (.p7s, .cms, .xml); format is detected from the bytes"},
				"document":  map[string]any{"type": "string", "format": "binary", "description": "the original file — only a detached signature needs it"},
			},
			"required": []any{"signature"},
		}}},
	}
	paths["/verify/portal"] = map[string]any{
		"get":  page(pageEndpoints[0], map[string]any{"200": html("The upload page")}),
		"post": portalSubmit,
	}
	paths["/console"] = map[string]any{
		"get": page(pageEndpoints[2], map[string]any{"200": html("The console page (self-contained, no external resources)")}),
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
				"All request and response keys are lowerCamelCase. Generated from the Go types — do not edit by hand. " +
				"The proprietary Kalkan library is bring-your-own (BYOL) and is not part of this service.",
		},
		"servers": []any{
			map[string]any{"url": "http://localhost:8080", "description": "Default REST work port (-http :8080)"},
		},
		"tags": []any{
			map[string]any{"name": "signature", "description": "Sign, verify, extract"},
			map[string]any{"name": "certificate", "description": "Certificate parsing and revocation"},
			map[string]any{"name": "batch", "description": "Batched operations (aggregated or NDJSON stream)"},
			map[string]any{"name": "jobs", "description": "Async jobs for large/slow work (submit, poll, cancel)"},
			map[string]any{"name": "oidc", "description": "Login with ЭЦП: OpenID Connect discovery, challenge/verify, hosted login, tokens"},
			map[string]any{"name": "qr", "description": "eGov Mobile QR signing/authorization sessions"},
			map[string]any{"name": "challenge", "description": "Standalone challenge–response: a single-use nonce, signed and confirmed"},
			map[string]any{"name": "multisign", "description": "Sessions collecting several signatures on one document"},
			map[string]any{"name": "signed-qr", "description": "Short statements signed with the service key and carried in a QR"},
			map[string]any{"name": "audit", "description": "Tamper-evident journal of what was signed and verified"},
			map[string]any{"name": "portal", "description": "Human-facing verification page (HTML, off by default)"},
			map[string]any{"name": "sandbox", "description": "Evaluation aids: demo signing key and the built-in test console (off by default)"},
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
	addQRPaths(paths)
	addMultisignPaths(paths)
	addAuditPaths(paths)
	addAuthPaths(paths)
	addPagePaths(paths)
	addBatchNegotiation(paths)
	addReportNegotiation(paths)
	addCrossCutting(paths)
	return paths
}

// idempotentPaths are the mutating endpoints wrapped in the Idempotency-Key
// middleware. Kept as data so the spec_test can hold it against the routes the
// transport actually wraps — a new endpoint that opts in silently would
// otherwise ship an undocumented header.
var idempotentPaths = []string{
	"/sign", "/sign/add", "/verify", "/verify/at", "/extract",
	"/cert/info", "/cert/validate",
	"/sign/batch", "/verify/batch", "/verify/registry", "/sign/archive",
	"/extract/batch", "/cert/info/batch", "/cert/validate/batch",
}

// batchStreamPaths are the endpoints that also emit an NDJSON stream.
var batchStreamPaths = []string{
	"/sign/batch", "/verify/batch", "/extract/batch",
	"/cert/info/batch", "/cert/validate/batch",
}

// addBatchNegotiation records the streaming form of the batch endpoints: the same
// call returns one NDJSON line per result (plus a summary line) when the caller
// asks for it, which is the only way a large batch avoids buffering in memory.
func addBatchNegotiation(paths map[string]any) {
	for _, p := range batchStreamPaths {
		op := paths[p].(map[string]any)["post"].(map[string]any)
		addParam(op, map[string]any{
			"name": "stream", "in": "query", "required": false,
			"schema":      map[string]any{"type": "string", "enum": []any{"1", "true", "yes"}},
			"description": "stream results as NDJSON instead of one aggregated object (same as Accept: application/x-ndjson)",
		})
		addParam(op, headerParam("Accept", "application/x-ndjson streams per-item results as they complete"))
		ok := op["responses"].(map[string]any)["200"].(map[string]any)
		ok["content"].(map[string]any)["application/x-ndjson"] = map[string]any{
			"schema": map[string]any{
				"type":        "string",
				"description": "one JSON object per line: each result tagged with its index, then a final {total, succeeded, failed} summary line",
			},
		}
	}
}

// addReportNegotiation records that /verify also renders the human card: the same
// call returns the verification report as a self-contained page when the caller
// prefers HTML (which implies report=true).
func addReportNegotiation(paths map[string]any) {
	op := paths["/verify"].(map[string]any)["post"].(map[string]any)
	addParam(op, headerParam("Accept", "text/html returns the verification card as a page instead of JSON (implies report=true)"))
	ok := op["responses"].(map[string]any)["200"].(map[string]any)
	ok["content"].(map[string]any)["text/html"] = map[string]any{
		"schema": map[string]any{
			"type":        "string",
			"description": "the verification card, self-contained (no external CSS or fonts) so it can be saved or printed as an audit artifact",
		},
	}
}

// addCrossCutting applies the two headers that are not per-endpoint features:
// Accept-Language (error messages are localized wherever an error envelope can
// come back) and Idempotency-Key on the mutating endpoints that honor it.
func addCrossCutting(paths map[string]any) {
	idem := map[string]bool{}
	for _, p := range idempotentPaths {
		idem[p] = true
	}
	for path, item := range paths {
		for method, raw := range item.(map[string]any) {
			op, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if returnsErrorEnvelope(op) {
				addParam(op, headerParam("Accept-Language",
					"preferred language for error messages (ru, kk; anything else renders English)"))
			}
			if method == "post" && idem[path] {
				addParam(op, headerParam("Idempotency-Key",
					"replay the first successful response for this key instead of re-executing, so a retry does not produce a second signature"))
				ok := op["responses"].(map[string]any)["200"].(map[string]any)
				ok["headers"] = map[string]any{
					"Idempotency-Replayed": map[string]any{
						"description": "present as true when this response was replayed from an earlier identical call",
						"schema":      map[string]any{"type": "string", "enum": []any{"true"}},
					},
				}
			}
		}
	}
}

// returnsErrorEnvelope reports whether an operation can answer with a localized
// error body — the only place Accept-Language changes anything.
func returnsErrorEnvelope(op map[string]any) bool {
	responses, ok := op["responses"].(map[string]any)
	if !ok {
		return false
	}
	for code, resp := range responses {
		if code < "400" {
			continue
		}
		blob, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		if strings.Contains(string(blob), "ErrorEnvelope") || strings.Contains(string(blob), "responses/Error") {
			return true
		}
	}
	return false
}

// headerParam builds a non-required header parameter.
func headerParam(name, desc string) map[string]any {
	return map[string]any{
		"name": name, "in": "header", "required": false,
		"schema": map[string]any{"type": "string"}, "description": desc,
	}
}

// addParam appends a parameter, keeping whatever the operation already declared.
func addParam(op map[string]any, p map[string]any) {
	existing, _ := op["parameters"].([]any)
	op["parameters"] = append(existing, p)
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
	all = append(all, authEndpoints...)
	all = append(all, qrEndpoints...)
	all = append(all, multisignEndpoints...)
	all = append(all, auditEndpoints...)
	all = append(all, pageEndpoints...)
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
