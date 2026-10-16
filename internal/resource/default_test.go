package resource

import "testing"

// A PROPERTY THE ROUTER OMITS AT ITS DEFAULT reads as that default. Measured on
// the CHR (7.24.3): /ip/dhcp-server leaves out conflict-detection until it is
// set, and its default is yes; read as "absent, so off", the next save of any
// field wrote `no`. The control is the same field reported explicitly, which
// must win over the default.
func TestAnOmittedPropertyReadsAsItsDocumentedDefault(t *testing.T) {
	row := map[string]string{"name": "dhcp1", "interface": "bridge"}
	if got := DHCPServer.RowValues(row)["conflictDetection"]; got != true {
		t.Errorf("an unreported conflict-detection reads %v, want its default true", got)
	}
	if got := DHCPServer.RowValues(row)["authoritative"]; got != "yes" {
		t.Errorf("an unreported authoritative reads %v, want its default yes", got)
	}
	row["conflict-detection"] = "false"
	if got := DHCPServer.RowValues(row)["conflictDetection"]; got != false {
		t.Errorf("a reported conflict-detection=false reads %v; the router's word must win", got)
	}
}

// THE FORM IS TOLD THE DEFAULT. An Add form has no row to read it from, so
// Describe carries it; without it a checkbox opened unticked and a new DHCP
// server went out with `conflict-detection=no`. The browser half, that an Add
// starts from it, is web/test/resource-add-defaults.test.ts.
func TestTheSchemaCarriesEachFieldsDefault(t *testing.T) {
	got := map[string]any{}
	for _, f := range DHCPServer.Describe()["fields"].([]map[string]any) {
		got[f["name"].(string)] = f["default"]
	}
	if got["conflictDetection"] != "yes" || got["addArp"] != "no" {
		t.Errorf("schema defaults conflictDetection=%v addArp=%v, want yes and no",
			got["conflictDetection"], got["addArp"])
	}
	if got["comment"] != "" {
		t.Errorf("a field with no default sends %v, want empty", got["comment"])
	}
}
