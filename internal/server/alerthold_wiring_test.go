package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// A ROUTER EDIT REACHES THE LIVE ALERT HOLD (2026-10-22).
//
// `reconfigureLiveSession` runs on every router save, so it is where the
// router's Offline threshold is handed to its running CPU and ping-loss rules.
// A session held for alerting is never rebuilt, so without this a changed
// threshold would wait for a restart.
func TestARouterEditReachesTheLiveAlertHold(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "routers_api.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "reconfigureLiveSession" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("routers_api.go has no reconfigureLiveSession: this check reads nothing")
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ApplyAlertHold" {
				found = true
			}
		}
		return true
	})
	if !found {
		t.Error("reconfigureLiveSession does not hand the router's Offline threshold to its live " +
			"session (sessions.ApplyAlertHold), so changing it does not change how long CPU and " +
			"ping loss must persist until a restart")
	}
}

// THE FLEET'S ONE-SECOND TICKER JUDGES HELD READINGS (2026-10-22).
//
// Ping is emitted only when it changes, so steady loss is one reading and then
// silence; without `tickAlerts` on the clock, the hold could never be reached on
// a real router while every unit test of the evaluator still passed.
func TestTheFleetTickerJudgesHeldReadings(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "startConnTicker" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "tickAlerts" {
					found = true
				}
			}
			return true
		})
	}
	if !found {
		t.Error("startConnTicker does not call tickAlerts, so a held CPU or ping-loss reading " +
			"that does not repeat can never reach the router's hold")
	}
}
