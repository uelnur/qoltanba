package rest

import (
	"bytes"
	"strings"
	"testing"
)

// TestLoginPageRenders covers what the page must contain to work at all: the
// challenge to sign, the parameters that carry the authorization request through
// the POST, and nothing pulled from a third-party origin.
func TestLoginPageRenders(t *testing.T) {
	var buf bytes.Buffer
	err := loginTemplate.Execute(&buf, loginPage{
		ClientID: "spa", RedirectURI: "https://spa.kz/cb", State: "st", Nonce: "n",
		CodeChallenge: "cc", CodeChallengeMethod: "S256",
		ChallengeID: "chid", Data: "ZGF0YQ==", ExpiresIn: 300, QREnabled: true,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	page := buf.String()
	for _, want := range []string{
		`name="client_id" value="spa"`,
		`name="redirect_uri" value="https://spa.kz/cb"`,
		`name="code_challenge" value="cc"`,
		`name="challengeId" value="chid"`,
		"ZGF0YQ==",
		"wss://127.0.0.1:13579/", // NCALayer runs on the user's own machine
		"/qr/sessions",           // eGov Mobile path is offered
	} {
		if !strings.Contains(page, want) {
			t.Errorf("login page is missing %q", want)
		}
	}
	// No third-party origins: the page must work on a closed network and must not
	// leak the challenge to anyone else.
	for _, forbidden := range []string{"https://cdn", "http://cdn", "googleapis", "unpkg"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("login page pulls in %q", forbidden)
		}
	}
}

// TestLoginPageHidesQRWhenDisabled keeps the page honest about what the service
// can actually do.
func TestLoginPageHidesQRWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	if err := loginTemplate.Execute(&buf, loginPage{ClientID: "spa", QREnabled: false}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(buf.String(), "/qr/sessions") {
		t.Error("the eGov Mobile option is offered while the QR orchestrator is off")
	}
}

// TestAuthorizeErrorPageRenders keeps the failure path presentable — it is what a
// user sees when a client is misconfigured.
func TestAuthorizeErrorPageRenders(t *testing.T) {
	var buf bytes.Buffer
	if err := authorizeErrorTemplate.Execute(&buf, map[string]string{
		"code": "invalid_request", "detail": "redirect_uri is not registered",
	}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(buf.String(), "invalid_request") {
		t.Error("error page does not name the error")
	}
}
