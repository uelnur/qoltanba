package rest

import (
	"bytes"
	"html/template"
	"io"
	"net/http"

	"github.com/uelnur/qoltanba/internal/core"
)

// The verification portal is the "check this signature" page: a person uploads a
// signed container (and the original file for a detached signature) and gets the
// verification card back. It exists because the people who need to check a
// signature — a clerk, a counterparty, an auditor — are not the people who will
// POST JSON, and telling them to install NCALayer to *verify* something is
// backwards: verification needs no key at all.
//
// It is off by default: the page accepts uploads from anyone who can reach it, so
// exposing it is a deliberate decision, not a side effect of enabling REST.

// portalMaxUpload caps one upload. Signature containers are kilobytes; the
// original document can be larger, but a portal is not a bulk channel — a big
// batch belongs on /verify/registry.
const portalMaxUpload = 16 << 20

func (s *Server) handlePortal(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = portalTemplate.Execute(w, nil)
}

func (s *Server) handlePortalVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(portalMaxUpload); err != nil {
		renderPortalError(w, "Не удалось прочитать загруженные файлы: "+err.Error())
		return
	}
	signature, err := formFile(r, "signature")
	if err != nil || len(signature) == 0 {
		renderPortalError(w, "Выберите файл подписи (.p7s, .cms, .xml).")
		return
	}
	document, _ := formFile(r, "document") // optional: only a detached signature needs it

	in := core.VerifyInput{
		Format:         formatOf(signature),
		Signature:      signature,
		Data:           document,
		Detached:       len(document) > 0,
		InputPEM:       bytes.HasPrefix(signature, []byte("-----BEGIN")),
		ExtractContent: len(document) == 0,
		ExtractClaims:  true,
		Report:         true,
	}
	out, err := s.svc.Verify(r.Context(), in)
	if err != nil {
		// A failed check is not a bad signature: say so plainly rather than
		// rendering an "invalid" verdict the service did not reach.
		renderPortalError(w, "Проверка не выполнена: "+core.ExplainIn(r.Context(), err).Message)
		return
	}
	if writeReportHTML(w, out) {
		return
	}
	renderPortalError(w, "Проверка не вернула результат.")
}

// formatOf guesses the container format from the bytes: XML signatures start with
// a document prolog or an element, everything else is treated as CMS.
func formatOf(b []byte) core.SignatureFormat {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '<':
			return core.FormatXML
		default:
			return core.FormatCMS
		}
	}
	return core.FormatCMS
}

func formFile(r *http.Request, field string) ([]byte, error) {
	f, _, err := r.FormFile(field)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, portalMaxUpload))
}

func renderPortalError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = portalTemplate.Execute(w, map[string]string{"error": msg})
}

var portalTemplate = template.Must(template.New("portal").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Проверка электронной подписи</title>
<style>
:root{color-scheme:light dark;--line:#d0d7de;--accent:#1a56db;--bad:#c5221f}
body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;padding:3rem 1rem}
main{max-width:30rem;margin:0 auto}
h1{font-size:1.3rem;margin:0 0 .3rem}
p.sub{margin:.2rem 0 1.6rem;opacity:.75}
label{display:block;margin:1rem 0 .3rem;font-weight:600}
input[type=file]{width:100%}
button{font:inherit;margin-top:1.6rem;padding:.6rem 1rem;border:0;border-radius:.4rem;background:var(--accent);color:#fff;cursor:pointer;width:100%}
.err{color:var(--bad);margin-top:1rem}
small{opacity:.7}
</style></head><body><main>
<h1>Проверка электронной подписи</h1>
<p class="sub">Загрузите подпись — сервис покажет, кто и когда подписал документ. Ключ ЭЦП для проверки не нужен.</p>
{{with .error}}<p class="err">{{.}}</p>{{end}}
<form method="post" action="/verify/portal" enctype="multipart/form-data">
  <label for="signature">Файл подписи</label>
  <input id="signature" type="file" name="signature" required>
  <small>CMS/PKCS#7 (.p7s, .cms) или подписанный XML.</small>

  <label for="document">Исходный документ</label>
  <input id="document" type="file" name="document">
  <small>Нужен только для отсоединённой подписи — когда подпись лежит отдельным файлом.</small>

  <button type="submit">Проверить</button>
</form>
</main></body></html>
`))
