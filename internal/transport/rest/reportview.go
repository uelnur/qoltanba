package rest

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/uelnur/qoltanba/internal/core"
)

// The verification card can be rendered as a page instead of JSON: POST /verify
// with Accept: text/html returns the human view of the same report. It is a
// presentation concern, so it lives in the transport — the domain builds the
// report, this only renders it.
//
// The page is self-contained (no external CSS or fonts) so it works on an
// air-gapped network and can be saved or printed as an audit artifact.

// wantsHTML reports whether the caller asked for the page rather than JSON.
// JSON stays the default: a client that sends no preference, or prefers JSON,
// must keep getting it.
func wantsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" || strings.Contains(accept, "application/json") {
		return false
	}
	return strings.Contains(accept, "text/html")
}

// writeReportHTML renders the card. A verification without a report (the caller
// did not ask for one) falls back to JSON rather than an empty page.
func writeReportHTML(w http.ResponseWriter, out core.VerifyOutput) bool {
	if out.Report == nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := reportTemplate.Execute(w, out.Report); err != nil {
		// The status line is already written, so the only honest thing left is to
		// stop; the client sees a truncated body and its own read error.
		return true
	}
	return true
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"fmtTime": func(t *time.Time) string {
		if t == nil {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"fmtAt": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"join":  func(v []string) string { return strings.Join(v, ", ") },
	"yesno": func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	},
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signature verification — {{.Verdict}}</title>
<style>
:root { color-scheme: light dark; --ok:#137333; --bad:#c5221f; --warn:#b06000; --line:#d0d7de; }
body { font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 2rem 1rem; }
main { max-width: 46rem; margin: 0 auto; }
.verdict { display:inline-block; padding:.25rem .6rem; border-radius:.4rem; color:#fff; font-weight:600; text-transform:uppercase; letter-spacing:.03em; font-size:.8rem; }
.valid { background: var(--ok); } .invalid { background: var(--bad); } .indeterminate { background: var(--warn); }
h1 { font-size:1.3rem; margin:.6rem 0 .2rem; } .summary { margin:.2rem 0 1.4rem; }
table { border-collapse: collapse; width:100%; margin:.4rem 0 1.4rem; }
th, td { text-align:left; padding:.4rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
th { width:12rem; font-weight:600; }
.step { display:flex; gap:.6rem; padding:.35rem 0; border-bottom:1px solid var(--line); }
.badge { flex:0 0 5.5rem; font-size:.78rem; text-transform:uppercase; letter-spacing:.03em; }
.pass { color: var(--ok); } .fail { color: var(--bad); } .warn, .unknown { color: var(--warn); } .skipped { opacity:.6; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.85em; word-break:break-all; }
h2 { font-size:1rem; margin:1.6rem 0 .3rem; }
</style></head><body><main>
<span class="verdict {{.Verdict}}">{{.Verdict}}</span>
<h1>Signature verification</h1>
<p class="summary">{{.Summary}}</p>

<h2>Document</h2>
<table>
<tr><th>Format</th><td>{{with .Document.Format}}{{.}}{{else}}—{{end}}{{if .Document.Detached}} (detached){{end}}</td></tr>
<tr><th>Signature SHA-256</th><td><code>{{with .Document.SignatureSHA256}}{{.}}{{else}}—{{end}}</code></td></tr>
{{if .Document.ContentSHA256}}<tr><th>Content SHA-256</th><td><code>{{.Document.ContentSHA256}}</code></td></tr>{{end}}
<tr><th>Checked at</th><td>{{fmtAt .CheckedAt}}</td></tr>
</table>

{{range .Signers}}
<h2>Signer: {{with .Name}}{{.}}{{else}}(unnamed){{end}}</h2>
<table>
{{if .IIN}}<tr><th>IIN</th><td>{{.IIN}}</td></tr>{{end}}
{{if .BIN}}<tr><th>BIN</th><td>{{.BIN}}</td></tr>{{end}}
{{if .Organization}}<tr><th>Organization</th><td>{{.Organization}}</td></tr>{{end}}
{{if .Roles}}<tr><th>Roles</th><td>{{join .Roles}}</td></tr>{{end}}
<tr><th>Signed at</th><td>{{fmtTime .SignedAt}}{{if .SignedAtSource}} <small>({{.SignedAtSource}})</small>{{end}}</td></tr>
<tr><th>Algorithm</th><td>{{with .SignatureAlgorithm}}{{.}}{{else}}—{{end}}{{if .CAdESLevel}} · CAdES-{{.CAdESLevel}}{{end}}
{{if .Algorithm.Generation}}<br><span class="{{if eq .Algorithm.Generation "current"}}pass{{else}}warn{{end}}">{{.Algorithm.Generation}}</span>{{end}}
{{if .Algorithm.Advice}}<br><small>{{.Algorithm.Advice}}</small>{{end}}</td></tr>
<tr><th>Certificate</th><td>serial <code>{{with .Certificate.SerialNumber}}{{.}}{{else}}—{{end}}</code><br>
issuer {{with .Certificate.Issuer}}{{.}}{{else}}—{{end}}<br>
valid {{fmtTime .Certificate.NotBefore}} — {{fmtTime .Certificate.NotAfter}}{{if .Certificate.Expired}} <strong class="fail">(expired)</strong>{{end}}</td></tr>
<tr><th>Chain</th><td>complete: {{yesno .Chain.Complete}} · anchored in trust: {{yesno .Chain.AnchoredInTrust}} · signatures verified: {{yesno .Chain.SignaturesVerified}}</td></tr>
</table>
{{end}}

<h2>Checks</h2>
{{range .Steps}}<div class="step"><span class="badge {{.Status}}">{{.Status}}</span><span>{{.Summary}}{{if .Action}}<br><small>{{.Action}}</small>{{end}}</span></div>{{end}}

{{if .Warnings}}<h2>Warnings</h2><ul>{{range .Warnings}}<li>{{.}}</li>{{end}}</ul>{{end}}
</main></body></html>
`))
