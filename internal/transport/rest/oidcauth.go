package rest

import (
	"errors"
	"html/template"
	"net/http"

	"github.com/uelnur/qoltanba/internal/core"
	"github.com/uelnur/qoltanba/internal/oidc"
)

// The browser-redirect leg of OIDC: GET /oidc/authorize renders a login page that
// collects a signature, POST /oidc/authorize turns that signature into an
// authorization code and redirects back to the relying party, and POST
// /oidc/token exchanges the code for tokens. Together with discovery and JWKS
// this is what an off-the-shelf OIDC client needs — no custom driver.
//
// The page is the one piece of UI the service hosts, and it is deliberately
// minimal glue: it asks NCALayer (or the user's own tooling) for a signature and
// posts it back. The private key never leaves the user's machine — the service
// never sees it, only the signature.

func (s *Server) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	req := authorizeRequestFrom(r)
	client, err := s.oidc.ValidateAuthorize(req)
	if err != nil {
		// Errors about the client or the redirect target are shown here rather than
		// redirected: sending an error to an unverified destination is the very
		// thing the check prevents.
		writeAuthorizeError(w, err)
		return
	}
	challenge, err := s.oidc.Challenge(r.Context(), oidc.ChallengeRequest{Nonce: req.Nonce, State: req.State})
	if err != nil {
		writeError(w, r, &core.Error{Kind: core.KindInternal, Op: "Authorize"}, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page carries a one-time challenge and must never be cached by a proxy or
	// the browser's back button.
	w.Header().Set("Cache-Control", "no-store")
	_ = loginTemplate.Execute(w, loginPage{
		ClientID:            client.ID,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		Nonce:               req.Nonce,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ChallengeID:         challenge.ChallengeID,
		Data:                challenge.Data,
		ExpiresIn:           challenge.ExpiresIn,
		// The eGov Mobile option is offered only when the QR orchestrator is on:
		// the page drives the existing /qr endpoints, it does not host its own.
		QREnabled: s.qr != nil,
	})
}

// handleOIDCAuthorizeSubmit receives the signature the page collected and
// redirects back to the relying party with an authorization code.
func (s *Server) handleOIDCAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeAuthorizeError(w, err)
		return
	}
	req := authorizeRequestFrom(r)
	redirect, err := s.oidc.CompleteAuthorization(r.Context(), req,
		r.FormValue("challengeId"), []byte(r.FormValue("signature")))
	if err != nil {
		writeAuthorizeError(w, err)
		return
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (s *Server) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// Client credentials may arrive in the body or as HTTP Basic; both are standard
	// and libraries differ in which they use.
	clientID, clientSecret := r.FormValue("client_id"), r.FormValue("client_secret")
	if id, secret, ok := r.BasicAuth(); ok {
		clientID, clientSecret = id, secret
	}
	tokens, err := s.oidc.Exchange(r.Context(), oidc.TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CodeVerifier: r.FormValue("code_verifier"),
	})
	if err != nil {
		status, code := oauthErrorFor(err)
		writeOAuthError(w, status, code, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, tokens)
}

func authorizeRequestFrom(r *http.Request) oidc.AuthorizeRequest {
	get := r.URL.Query().Get
	if r.Method == http.MethodPost {
		get = r.FormValue
	}
	return oidc.AuthorizeRequest{
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		ResponseType:        get("response_type"),
		Scope:               get("scope"),
		State:               get("state"),
		Nonce:               get("nonce"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
	}
}

// oauthErrorFor maps a flow error to the OAuth2 error code and HTTP status a
// relying party expects.
func oauthErrorFor(err error) (int, string) {
	switch {
	case errors.Is(err, oidc.ErrUnknownClient), errors.Is(err, oidc.ErrClientAuth):
		return http.StatusUnauthorized, "invalid_client"
	case errors.Is(err, oidc.ErrCodeInvalid), errors.Is(err, oidc.ErrPKCEFailed):
		return http.StatusBadRequest, "invalid_grant"
	case errors.Is(err, oidc.ErrUnsupportedFlow):
		return http.StatusBadRequest, "unsupported_grant_type"
	case errors.Is(err, oidc.ErrPKCERequired), errors.Is(err, oidc.ErrRedirectMismatch):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, oidc.ErrSignatureRejected), errors.Is(err, oidc.ErrCertRevoked):
		return http.StatusForbidden, "access_denied"
	default:
		return http.StatusInternalServerError, "server_error"
	}
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// writeAuthorizeError renders an authorization failure as a page: at this point
// there is no verified redirect target to send the error to.
func writeAuthorizeError(w http.ResponseWriter, err error) {
	status, code := oauthErrorFor(err)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = authorizeErrorTemplate.Execute(w, map[string]string{"code": code, "detail": err.Error()})
}

// loginPage is what the login template renders.
type loginPage struct {
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	ChallengeID         string
	Data                string
	ExpiresIn           int
	QREnabled           bool
}

var authorizeErrorTemplate = template.Must(template.New("authorize-error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign-in error</title>
<style>body{font:15px/1.5 system-ui,sans-serif;margin:0;padding:3rem 1rem;text-align:center}
h1{font-size:1.2rem}code{font-family:ui-monospace,Menlo,monospace}</style></head>
<body><h1>Sign-in cannot continue</h1><p><code>{{.code}}</code></p><p>{{.detail}}</p></body></html>
`))

// loginTemplate is the hosted login page. It talks to NCALayer over its local
// WebSocket — the standard desktop signer in RK — and falls back to pasting a
// signature produced by other tooling, so the page stays usable where NCALayer is
// not installed.
var loginTemplate = template.Must(template.New("oidc-login").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Вход по ЭЦП</title>
<style>
:root{color-scheme:light dark;--line:#d0d7de;--accent:#1a56db;--bad:#c5221f}
body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;padding:3rem 1rem}
main{max-width:26rem;margin:0 auto}
h1{font-size:1.25rem;margin:0 0 .3rem}
p.sub{margin:.2rem 0 1.6rem;opacity:.75}
button{font:inherit;padding:.6rem 1rem;border:0;border-radius:.4rem;background:var(--accent);color:#fff;cursor:pointer;width:100%}
button[disabled]{opacity:.6;cursor:progress}
button.secondary{background:transparent;color:var(--accent);border:1px solid var(--accent);margin-top:.6rem}
#qrbox{margin-top:1rem;text-align:center}
#qrimg{image-rendering:pixelated;border:1px solid var(--line);border-radius:.4rem}
details{margin-top:1.4rem;border-top:1px solid var(--line);padding-top:1rem}
textarea{width:100%;min-height:7rem;font-family:ui-monospace,Menlo,monospace;font-size:.8rem}
.status{margin-top:1rem;min-height:1.4rem}
.err{color:var(--bad)}
small{opacity:.7}
</style></head><body><main>
<h1>Вход по ЭЦП</h1>
<p class="sub">Приложение <strong>{{.ClientID}}</strong> запрашивает подтверждение личности.</p>

<form id="f" method="post" action="/oidc/authorize">
  <input type="hidden" name="client_id" value="{{.ClientID}}">
  <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
  <input type="hidden" name="response_type" value="code">
  <input type="hidden" name="state" value="{{.State}}">
  <input type="hidden" name="nonce" value="{{.Nonce}}">
  <input type="hidden" name="scope" value="{{.Scope}}">
  <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
  <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
  <input type="hidden" name="challengeId" value="{{.ChallengeID}}">
  <input type="hidden" id="signature" name="signature" value="">
  <button type="button" id="go">Подписать через NCALayer</button>
{{if .QREnabled}}  <button type="button" id="qr" class="secondary">Подписать через eGov Mobile</button>
  <div id="qrbox" hidden>
    <img id="qrimg" alt="QR для eGov Mobile" width="220" height="220">
    <p><small>Отсканируйте QR в приложении eGov Mobile и подпишите запрос.</small></p>
  </div>
{{end}}  <div class="status" id="status"></div>
  <details>
    <summary>Подписать другим способом</summary>
    <p><small>Подпишите эту строку (base64) как отсоединённый CMS и вставьте результат:</small></p>
    <textarea readonly id="data">{{.Data}}</textarea>
    <textarea id="manual" placeholder="CMS в base64 или PEM"></textarea>
    <button type="button" id="send">Отправить подпись</button>
  </details>
</form>

<script>
(function () {
  var DATA = {{.Data}};
  var status = document.getElementById('status');
  var form = document.getElementById('f');
  var sigField = document.getElementById('signature');

  function fail(msg) { status.className = 'status err'; status.textContent = msg; }
  function say(msg) { status.className = 'status'; status.textContent = msg; }

  function submit(signature) {
    if (!signature) { fail('Пустая подпись.'); return; }
    sigField.value = signature;
    form.submit();
  }

  document.getElementById('send').addEventListener('click', function () {
    submit(document.getElementById('manual').value.trim());
  });

{{if .QREnabled}}  var qrBtn = document.getElementById('qr');
  if (qrBtn) {
    // eGov Mobile signs the same challenge nonce through the service's own QR
    // session endpoints, so this page needs no server code of its own.
    qrBtn.addEventListener('click', function () {
      qrBtn.disabled = true;
      say('Создаём сессию eGov Mobile…');
      fetch('/qr/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'sign', format: 'cms', detached: true, data: DATA,
                               description: 'Вход в {{.ClientID}}' })
      }).then(function (r) {
        if (!r.ok) { throw new Error('HTTP ' + r.status); }
        return r.json();
      }).then(function (s) {
        var box = document.getElementById('qrbox');
        document.getElementById('qrimg').src = 'data:image/png;base64,' + s.qr;
        box.hidden = false;
        say('Ожидаем подпись в eGov Mobile…');
        poll(s.sessionId, Date.now() + (s.expiresIn || 300) * 1000);
      }).catch(function (e) {
        qrBtn.disabled = false;
        fail('Не удалось создать QR-сессию: ' + e.message);
      });
    });
  }

  function poll(id, deadline) {
    if (Date.now() > deadline) { qrBtn.disabled = false; fail('Время сессии истекло.'); return; }
    fetch('/qr/sessions/' + encodeURIComponent(id)).then(function (r) { return r.json(); })
      .then(function (v) {
        if (v.status === 'verified' && v.result && v.result.signature) { submit(v.result.signature); return; }
        if (v.status === 'failed' || v.status === 'expired') {
          qrBtn.disabled = false;
          fail(v.error && v.error.message ? v.error.message : 'Подписание не завершено.');
          return;
        }
        setTimeout(function () { poll(id, deadline); }, 1500);
      }).catch(function () { setTimeout(function () { poll(id, deadline); }, 3000); });
  }
{{end}}

  // NCALayer listens on a fixed local WebSocket. It is the user's own software:
  // the key stays there, and only the produced signature reaches this page.
  document.getElementById('go').addEventListener('click', function () {
    var btn = this;
    btn.disabled = true;
    say('Открываем NCALayer…');
    var ws;
    try { ws = new WebSocket('wss://127.0.0.1:13579/'); }
    catch (e) { btn.disabled = false; fail('NCALayer недоступен. Используйте ручной способ ниже.'); return; }

    var timer = setTimeout(function () {
      try { ws.close(); } catch (e) {}
      btn.disabled = false;
      fail('NCALayer не отвечает. Запустите его или используйте ручной способ ниже.');
    }, 10000);

    ws.onopen = function () {
      say('Выберите ключ в окне NCALayer…');
      ws.send(JSON.stringify({
        module: 'kz.gov.pki.knca.commonUtils',
        method: 'createCMSSignatureFromBase64',
        args: ['PKCS12', 'AUTHENTICATION', DATA, true]
      }));
    };
    ws.onmessage = function (ev) {
      clearTimeout(timer);
      var res;
      try { res = JSON.parse(ev.data); } catch (e) { btn.disabled = false; fail('Некорректный ответ NCALayer.'); return; }
      try { ws.close(); } catch (e) {}
      if (res && res.code === '200' && res.responseObject) { submit(res.responseObject); return; }
      btn.disabled = false;
      fail((res && (res.message || res.code)) ? 'NCALayer: ' + (res.message || res.code) : 'Подписание отменено.');
    };
    ws.onerror = function () {
      clearTimeout(timer);
      btn.disabled = false;
      fail('Не удалось соединиться с NCALayer. Используйте ручной способ ниже.');
    };
  });
})();
</script>
</main></body></html>
`))
