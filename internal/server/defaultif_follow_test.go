package server

// A ROUTER EDIT'S WAN INTERFACE REACHES THE LIVE SESSION AND ITS VIEWERS
// (issue #158).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"testing"

	"mikrodash/internal/collect"
	"mikrodash/internal/hub"
	"mikrodash/internal/routeros"
	"mikrodash/internal/session"
)

// reconfigureLiveSession runs on every router save, so it is where the WAN
// interface has to be handed to the running session, as the ping target is.
func TestARouterEditReachesTheLiveWanInterface(t *testing.T) {
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
	applies, follows := false, false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "ApplyDefaultIf":
				applies = true
			case "followDefaultIf":
				follows = true
			}
		}
		return true
	})
	if !applies {
		t.Error("reconfigureLiveSession does not hand the record's WAN interface to the live " +
			"session (sessions.ApplyDefaultIf), so a changed WAN keeps the badge and the default " +
			"graph on the old interface until a restart")
	}
	if !follows {
		t.Error("reconfigureLiveSession does not move the viewers on the old default (followDefaultIf), " +
			"so an open dashboard keeps graphing the old WAN")
	}
}

type idleReader struct{}

func (idleReader) Do(routeros.Cmd) ([]routeros.Reply, error) { return nil, nil }
func (idleReader) Connected() bool                           { return false }

// followDefaultIf moves the viewers still on the old default and nobody else.
func TestViewersOnTheOldWanFollowTheNewOne(t *testing.T) {
	h := hub.New()
	s := &Server{hub: h, conns: map[*hub.Client]*conn{}}

	tr := collect.NewTraffic(idleReader{}, hub.Relay{}, "ether2", 1)
	sn := session.NewForTest(h, "r1")
	sn.SetTrafficForTest(tr)
	other := session.NewForTest(h, "r2")
	other.SetTrafficForTest(collect.NewTraffic(idleReader{}, hub.Relay{}, "ether2", 1))

	viewer := func(id, routerID string, rs *session.Session) *conn {
		c := hub.NewClient(id, 64)
		h.Add(c)
		cn := &conn{c: c, srv: s, routerID: routerID, rsession: rs}
		s.conns[c] = cn
		cn.trafficSelectDefault(rs.Traffic().DefaultIf())
		return cn
	}
	onWan := viewer("on-wan", "r1", sn)
	picked := viewer("picked", "r1", sn)
	picked.dropTraffic()
	picked.trafficIf = ""
	picked.trafficSelectDefault("ether5") // stands in for a viewer's own pick
	elsewhere := viewer("other-router", "r2", other)

	if !tr.SetDefaultIf("pppoe-out1") {
		t.Fatal("the WAN did not move")
	}
	s.followDefaultIf("r1", "ether2")

	newRoom := session.RoomFor("r1", collect.TrafficSub("pppoe-out1"))
	oldRoom := session.RoomFor("r1", collect.TrafficSub("ether2"))
	if onWan.trafficIf != "pppoe-out1" {
		t.Errorf("the viewer on the old WAN is on %q, want pppoe-out1", onWan.trafficIf)
	}
	if rooms := onWan.c.Rooms(); !slices.Contains(rooms, newRoom) || slices.Contains(rooms, oldRoom) {
		t.Errorf("the moved viewer is in rooms %v, want %s and not %s", rooms, newRoom, oldRoom)
	}
	if picked.trafficIf != "ether5" {
		t.Errorf("a viewer on another interface was moved to %q", picked.trafficIf)
	}
	if elsewhere.trafficIf != "ether2" {
		t.Errorf("a viewer of another router was moved to %q", elsewhere.trafficIf)
	}
}
