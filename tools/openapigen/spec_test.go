package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The spec's paths are declared by hand while the routes are registered in the
// transport, so `make check-generated` — which only re-runs this generator and
// diffs its output — cannot notice an endpoint that was never declared here.
// These tests close that gap by reading the routes out of the transport source:
// a new handler with no spec entry fails the build, which is how the spec fell
// nineteen endpoints behind in the first place.

// restPackage is the transport whose routes must appear in the spec.
const restPackage = "../../internal/transport/rest"

// externallyMounted are documented paths served by a handler mounted outside the
// rest package (cmd/qoltanba puts the metrics handler on the same work mux), so
// the source scan below cannot see them.
var externallyMounted = map[string]bool{"GET /metrics": true}

func TestEveryRouteIsDocumented(t *testing.T) {
	routes := restRoutes(t)
	documented := specRoutes()

	var missing []string
	for r := range routes {
		if !documented[r] {
			missing = append(missing, r)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("routes registered but absent from the OpenAPI spec:\n\t%s\n"+
			"declare them in spec.go (and give them a Postman example) so generated SDKs and the collection cover them",
			strings.Join(missing, "\n\t"))
	}
}

func TestEveryDocumentedPathIsRouted(t *testing.T) {
	routes := restRoutes(t)
	var stale []string
	for r := range specRoutes() {
		if !routes[r] && !externallyMounted[r] {
			stale = append(stale, r)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("documented but not served by the rest transport:\n\t%s\n"+
			"either the route was removed (drop it from spec.go) or it is mounted elsewhere (add it to externallyMounted)",
			strings.Join(stale, "\n\t"))
	}
}

// TestIdempotentPathsMatchTheMiddleware keeps the documented Idempotency-Key
// header aligned with the handlers actually wrapped in it: a documented header
// the endpoint ignores is worse than none, and an undocumented one that works is
// a feature nobody can find.
func TestIdempotentPathsMatchTheMiddleware(t *testing.T) {
	wrapped := map[string]bool{}
	forEachRoute(t, func(method, path string, idempotent bool) {
		if idempotent {
			wrapped[path] = true
		}
	})
	declared := map[string]bool{}
	for _, p := range idempotentPaths {
		declared[p] = true
	}
	for p := range wrapped {
		if !declared[p] {
			t.Errorf("%s is wrapped in the idempotency middleware but not listed in idempotentPaths", p)
		}
	}
	for p := range declared {
		if !wrapped[p] {
			t.Errorf("%s is listed in idempotentPaths but the handler is not wrapped in the middleware", p)
		}
	}
}

// restRoutes returns the "METHOD /path" set the rest transport registers.
func restRoutes(t *testing.T) map[string]bool {
	out := map[string]bool{}
	forEachRoute(t, func(method, path string, _ bool) {
		out[method+" "+path] = true
	})
	return out
}

// specRoutes returns the "METHOD /path" set the generated document declares.
func specRoutes() map[string]bool {
	out := map[string]bool{}
	for path, item := range buildPaths() {
		for method := range item.(map[string]any) {
			out[strings.ToUpper(method)+" "+path] = true
		}
	}
	return out
}

// forEachRoute parses the transport package and reports every mux registration,
// flagging the ones wrapped in the idempotency middleware. Reading the source
// rather than the built mux is deliberate: net/http's ServeMux does not expose
// its patterns, and half the routes only register when a subsystem is enabled.
func forEachRoute(t *testing.T, fn func(method, path string, idempotent bool)) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(restPackage)
	if err != nil {
		t.Fatalf("read %s: %v", restPackage, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(restPackage, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
				return true
			}
			if recv, ok := sel.X.(*ast.Ident); !ok || recv.Name != "mux" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: route pattern is not a literal — the spec gate cannot read it",
					filepath.Base(fset.Position(call.Pos()).String()))
				return true
			}
			pattern, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("unquote route pattern: %v", err)
			}
			method, path, found := strings.Cut(pattern, " ")
			if !found {
				t.Errorf("route %q has no method — the spec needs one", pattern)
				return true
			}
			fn(method, path, wrapsIdempotency(call))
			return true
		})
	}
}

// wrapsIdempotency reports whether the handler argument is s.idempotent(...).
func wrapsIdempotency(call *ast.CallExpr) bool {
	if len(call.Args) < 2 {
		return false
	}
	inner, ok := call.Args[1].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := inner.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "idempotent"
}
