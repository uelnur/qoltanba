package rest

import (
	"html/template"
	"net/http"
)

// The console is a "try it here" page: the endpoints, an editable request body
// and the raw response. It exists for the first hour with the service — deciding
// whether it fits, checking that a container verifies — when writing a client
// first is friction, not diligence.
//
// It is a client of the public API and nothing more: no privileged path, no
// separate logic, so what it shows is exactly what a caller would get. Off by
// default, since it is a UI on an otherwise headless service.

func (s *Server) handleConsole(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consoleTemplate.Execute(w, consolePage{
		SandboxKey: s.sandboxKey != "",
		Portal:     s.portal,
	})
}

type consolePage struct {
	SandboxKey bool
	Portal     bool
}

var consoleTemplate = template.Must(template.New("console").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>qoltanba console</title>
<style>
:root{color-scheme:light dark;--line:#d0d7de;--accent:#1a56db;--bad:#c5221f;--ok:#137333}
body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;padding:2rem 1rem}
main{max-width:60rem;margin:0 auto}
h1{font-size:1.3rem;margin:0 0 .2rem}
p.sub{margin:.2rem 0 1.5rem;opacity:.75}
.row{display:flex;gap:1rem;flex-wrap:wrap}
.col{flex:1 1 24rem;min-width:20rem}
label{display:block;font-weight:600;margin:.8rem 0 .3rem}
select,textarea,input{width:100%;font:inherit}
textarea{min-height:16rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem}
pre{background:rgba(127,127,127,.09);padding:.8rem;border-radius:.4rem;overflow:auto;max-height:28rem;font-size:.82rem}
button{font:inherit;margin-top:.9rem;padding:.55rem 1rem;border:0;border-radius:.4rem;background:var(--accent);color:#fff;cursor:pointer}
button.secondary{background:transparent;color:var(--accent);border:1px solid var(--accent)}
.status{margin-top:.6rem;font-weight:600}
.ok{color:var(--ok)}.err{color:var(--bad)}
small{opacity:.7}
</style></head><body><main>
<h1>qoltanba console</h1>
<p class="sub">Пробные запросы к этому же REST API. Ничего привилегированного — то же, что увидит ваш клиент.
{{if .Portal}} Для проверки файлом есть <a href="/verify/portal">портал</a>.{{end}}</p>

<div class="row">
  <div class="col">
    <label for="op">Операция</label>
    <select id="op">
      <option value="/verify">POST /verify</option>
      <option value="/sign">POST /sign</option>
      <option value="/extract">POST /extract</option>
      <option value="/cert/info">POST /cert/info</option>
      <option value="/cert/validate">POST /cert/validate</option>
      <option value="/verify/at">POST /verify/at</option>
      <option value="/verify/registry">POST /verify/registry</option>
      <option value="/challenge">POST /challenge</option>
      <option value="/statusz" data-get="1">GET /statusz</option>
      <option value="/readyz" data-get="1">GET /readyz</option>
    </select>

    <label for="body">Тело запроса (JSON)</label>
    <textarea id="body" spellcheck="false"></textarea>
    <small>Двоичные поля — base64. Времена — RFC 3339.</small>

    <div>
      <button id="send">Отправить</button>
      <button id="sample" class="secondary" type="button">Пример</button>
{{if .SandboxKey}}      <button id="demo" class="secondary" type="button">Подписать тестовым ключом</button>{{end}}
    </div>
    <div class="status" id="status"></div>
  </div>

  <div class="col">
    <label>Ответ</label>
    <pre id="out">—</pre>
  </div>
</div>

<script>
(function () {
  var SAMPLES = {
    '/verify': { format: 'cms', signature: '<base64 CMS>', detached: false, claims: true, report: true, explain: true },
    '/sign': { policy: 'cades-t', data: btoa('hello'), key: { path: '/path/to/key.p12', password: '***' } },
    '/extract': { format: 'cms', signature: '<base64 CMS>' },
    '/cert/info': { cert: '<base64 cert>', format: 'pem', claims: true, buildChain: true },
    '/cert/validate': { cert: '<base64 cert>', format: 'pem', method: 'ocsp', wantOcsp: true },
    '/verify/at': { format: 'cms', signature: '<base64 CMS>', at: new Date().toISOString() },
    '/verify/registry': { items: [{ ref: 'doc-1', format: 'cms', signature: '<base64 CMS>' }] },
    '/challenge': { purpose: 'payment.confirm', meta: { orderId: '42' } }
  };

  var op = document.getElementById('op');
  var body = document.getElementById('body');
  var out = document.getElementById('out');
  var status = document.getElementById('status');

  function isGet() { return op.options[op.selectedIndex].dataset.get === '1'; }
  function fillSample() {
    var s = SAMPLES[op.value];
    body.value = s ? JSON.stringify(s, null, 2) : '';
    body.disabled = isGet();
  }
  op.addEventListener('change', fillSample);
  document.getElementById('sample').addEventListener('click', fillSample);
  fillSample();

  function show(ok, text, label) {
    out.textContent = text;
    status.className = 'status ' + (ok ? 'ok' : 'err');
    status.textContent = label;
  }

  document.getElementById('send').addEventListener('click', function () {
    var started = performance.now();
    var init = isGet() ? { method: 'GET' }
      : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body.value };
    fetch(op.value, init).then(function (r) {
      return r.text().then(function (t) {
        var pretty = t;
        try { pretty = JSON.stringify(JSON.parse(t), null, 2); } catch (e) {}
        var ms = Math.round(performance.now() - started);
        show(r.ok, pretty, r.status + ' ' + r.statusText + ' · ' + ms + ' ms');
      });
    }).catch(function (e) { show(false, String(e), 'запрос не отправлен'); });
  });

{{if .SandboxKey}}  // The sandbox key lives on the service; the console never sees key material.
  document.getElementById('demo').addEventListener('click', function () {
    show(true, '…', 'подписываем тестовым ключом');
    fetch('/sandbox/sign', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: btoa('hello from the console') })
    }).then(function (r) { return r.text(); }).then(function (t) {
      var parsed; try { parsed = JSON.parse(t); } catch (e) {}
      out.textContent = parsed ? JSON.stringify(parsed, null, 2) : t;
      if (parsed && parsed.signature) {
        op.value = '/verify';
        body.disabled = false;
        body.value = JSON.stringify({ format: 'cms', signature: parsed.signature,
                                      inputPem: true, claims: true, report: true }, null, 2);
        show(true, out.textContent, 'подписано — нажмите «Отправить», чтобы проверить');
      } else {
        show(false, out.textContent, 'не удалось подписать');
      }
    }).catch(function (e) { show(false, String(e), 'запрос не отправлен'); });
  });
{{end}}})();
</script>
</main></body></html>
`))
