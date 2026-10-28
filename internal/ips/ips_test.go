package ips

import (
	"strings"
	"testing"
)

// A line as dpi-sensor/ writes it, replayed from a real run over nDPI's
// netflix.pcap (addresses moved into the documentation ranges).
const netflixLine = `{"type":"flow","ts":1793140197936,"l4":"tcp","client":"192.168.1.7","clientPort":53214,` +
	`"server":"198.51.100.40","serverPort":443,"name":"TLS.NetFlix","app":"NetFlix","master":"TLS",` +
	`"category":"Video","breed":"Fun","host":"www.netflix.com","risks":[],"guessed":false,"packets":6,"bytes":2210}`

func flowOf(t *testing.T, line string) Flow {
	t.Helper()
	l, err := ParseLine([]byte(line))
	if err != nil || l.Flow == nil {
		t.Fatalf("ParseLine: %v %+v", err, l)
	}
	return *l.Flow
}

func TestParseLineReadsEveryKindTheSensorSends(t *testing.T) {
	f := flowOf(t, netflixLine)
	if f.App != "NetFlix" || f.Master != "TLS" || f.Host != "www.netflix.com" || f.ServerPort != 443 {
		t.Errorf("flow: %+v", f)
	}
	if l, _ := ParseLine([]byte(`{"type":"hello","version":"1","ndpi":"4.14"}`)); l.Hello == nil || l.Hello.NDPI != "4.14" {
		t.Errorf("hello: %+v", l)
	}
	if l, _ := ParseLine([]byte(`{"type":"stats","packets":4214,"droppedEvents":2}`)); l.Stats == nil || l.Stats.DroppedEvents != 2 {
		t.Errorf("stats: %+v", l)
	}
	if l, _ := ParseLine([]byte(`{"type":"error","message":"bad token"}`)); l.Error != "bad token" {
		t.Errorf("error: %+v", l)
	}
	if l, _ := ParseLine([]byte(strings.Replace(netflixLine, `"risks":[]`, `"risks":null`, 1))); l.Flow.Risks == nil {
		t.Error("a null risk list must arrive as an empty one")
	}
}

func TestParseLineRefusesWhatCannotBeActedOn(t *testing.T) {
	for _, bad := range []string{
		strings.Replace(netflixLine, `"198.51.100.40"`, `"no-address"`, 1),
		strings.Replace(netflixLine, `"192.168.1.7"`, `""`, 1),
		`{"type":"surprise"}`,
		`not json`,
	} {
		if _, err := ParseLine([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestARuleMatchesWhenEveryCriterionDoes(t *testing.T) {
	f := flowOf(t, netflixLine)
	for name, tc := range map[string]struct {
		r    Rule
		want bool
	}{
		"the application":              {Rule{Apps: []string{"netflix"}}, true},
		"the master":                   {Rule{Apps: []string{"TLS"}}, true},
		"the dotted name":              {Rule{Apps: []string{"TLS.NetFlix"}}, true},
		"another application":          {Rule{Apps: []string{"YouTube"}}, false},
		"the category":                 {Rule{Categories: []string{"video"}}, true},
		"the breed":                    {Rule{Breeds: []string{"Fun"}}, true},
		"a parent of the host":         {Rule{Hosts: []string{"netflix.com"}}, true},
		"a suffix that is not a label": {Rule{Hosts: []string{"flix.com"}}, false},
		"any risk, with none":          {Rule{Risks: []string{"*"}}, false},
		"the client's prefix":          {Rule{Apps: []string{"NetFlix"}, Clients: []string{"192.168.1.0/24"}}, true},
		"another client":               {Rule{Apps: []string{"NetFlix"}, Clients: []string{"192.168.1.8"}}, false},
		"one of two values":            {Rule{Apps: []string{"YouTube", "NetFlix"}}, true},
		"one criterion of two fails":   {Rule{Apps: []string{"NetFlix"}, Categories: []string{"Game"}}, false},
	} {
		if got := tc.r.Matches(f); got != tc.want {
			t.Errorf("%s: Matches = %v, want %v", name, got, tc.want)
		}
	}
	risky := f
	risky.Risks = []string{"Known Proto on Non Std Port"}
	if !(Rule{Risks: []string{"*"}}).Matches(risky) || !(Rule{Risks: []string{"known proto on non std port"}}).Matches(risky) {
		t.Error("a flow with a risk must match * and its own risk")
	}
}

func TestTheFirstEnabledMatchDecides(t *testing.T) {
	f := flowOf(t, netflixLine)
	rules := []Rule{
		{ID: 1, Name: "off", Enabled: false, Apps: []string{"NetFlix"}, Action: ActionQuarantine},
		{ID: 2, Name: "other", Enabled: true, Apps: []string{"YouTube"}, Action: ActionBlock},
		{ID: 3, Name: "netflix", Enabled: true, Apps: []string{"NetFlix"}, Action: ActionBlock, TimeoutMin: 30},
		{ID: 4, Name: "video", Enabled: true, Categories: []string{"Video"}, Action: ActionLog},
	}
	d := Decide(rules, f)
	if d.RuleID != 3 || d.Action != ActionBlock || d.Target != "198.51.100.40" || d.List != BlockList || d.TimeoutMin != 30 {
		t.Errorf("block: %+v", d)
	}
	rules[2].Action = ActionQuarantine
	if d := Decide(rules, f); d.Target != "192.168.1.7" || d.List != QuarantineList {
		t.Errorf("quarantine lists the client: %+v", d)
	}
	rules[2].Action = ActionAllow
	if d := Decide(rules, f); d.Action != ActionAllow || d.Target != "" {
		t.Errorf("allow stops evaluation and lists nothing: %+v", d)
	}
	if d := Decide(rules[:2], f); d.RuleID != 0 || d.Action != "" {
		t.Errorf("no match: %+v", d)
	}
}

func TestValidateNormalisesAndRefuses(t *testing.T) {
	r := Rule{Name: " Block P2P ", Apps: []string{" BitTorrent ", "", "BitTorrent"}, Hosts: []string{"*.Example.COM."},
		Action: ActionBlock}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Name != "Block P2P" || len(r.Apps) != 1 || r.Hosts[0] != "example.com" || r.TimeoutMin != DefaultTimeout {
		t.Errorf("normalised: %+v", r)
	}
	logged := Rule{Name: "watch", Categories: []string{"Game"}, Action: ActionLog, TimeoutMin: 99}
	if err := logged.Validate(); err != nil || logged.TimeoutMin != 0 {
		t.Errorf("a log rule has no timeout: %v %+v", err, logged)
	}
	for name, bad := range map[string]Rule{
		"no name":            {Apps: []string{"X"}, Action: ActionLog},
		"unknown action":     {Name: "x", Apps: []string{"X"}, Action: "drop"},
		"clients alone":      {Name: "x", Clients: []string{"192.168.1.0/24"}, Action: ActionBlock},
		"a bad client":       {Name: "x", Apps: []string{"X"}, Clients: []string{"192.168.1.0/33"}, Action: ActionLog},
		"a host with a path": {Name: "x", Hosts: []string{"example.com/x"}, Action: ActionLog},
		"a week and a day":   {Name: "x", Apps: []string{"X"}, Action: ActionBlock, TimeoutMin: MaxTimeout + 1},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, bad)
		}
	}
}

func TestTheCatalogNamesWhatTheSensorSends(t *testing.T) {
	c := TheCatalog()
	if len(c.Apps) < 300 || len(c.Categories) < 30 || len(c.Breeds) != 8 || len(c.Risks) < 40 {
		t.Fatalf("a short catalogue: %d apps, %d categories, %d breeds, %d risks",
			len(c.Apps), len(c.Categories), len(c.Breeds), len(c.Risks))
	}
	// Names as a real sensor run reported them (netflixLine, the BitTorrent
	// replay): the catalogue must spell them the same, letter for letter.
	f := flowOf(t, netflixLine)
	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	apps := []string{}
	for _, a := range c.Apps {
		apps = append(apps, a.Name)
	}
	for _, v := range []string{f.App, f.Master, "BitTorrent", "DNS", "QUIC"} {
		if !has(apps, v) {
			t.Errorf("the catalogue has no app %q", v)
		}
	}
	if !has(c.Categories, f.Category) || !has(c.Breeds, f.Breed) {
		t.Errorf("category %q or breed %q is missing", f.Category, f.Breed)
	}
	for _, r := range c.Risks {
		if SeverityRank(r.Severity) == 0 {
			t.Errorf("risk %q has a severity outside nDPI's: %q", r.Name, r.Severity)
		}
	}
	// Both risks the BitTorrent replay raised, with their severities.
	if s := RiskSeverity("Known Proto on Non Std Port"); s == "" {
		t.Error("a risk the sensor sent has no severity")
	}
	if w := WorstSeverity([]string{"Known Proto on Non Std Port", "Unidirectional Traffic", "not a risk"}); SeverityRank(w) == 0 {
		t.Errorf("worst of two known risks: %q", w)
	}
	if WorstSeverity(nil) != "" || WorstSeverity([]string{"not a risk"}) != "" {
		t.Error("no known risk has no severity")
	}
}

func TestCountriesMatchTheRemotePartyAndBlockListsIt(t *testing.T) {
	out := flowOf(t, netflixLine)
	out.ServerCountry = "US"
	// A connection that came in through a dst-nat: the client is on the
	// internet, the server is at home.
	in := out
	in.Client, in.ClientCountry, in.Server, in.ServerCountry = "203.0.113.9", "CN", "192.168.11.182", ""

	if a, c, inbound := out.Remote(); a != "198.51.100.40" || c != "US" || inbound {
		t.Errorf("outbound remote: %s %s %v", a, c, inbound)
	}
	if a, c, inbound := in.Remote(); a != "203.0.113.9" || c != "CN" || !inbound {
		t.Errorf("inbound remote: %s %s %v", a, c, inbound)
	}
	lan := out
	lan.Server = "192.168.11.5"
	if a, _, _ := lan.Remote(); a != "" {
		t.Errorf("a flow inside the LAN has no remote party: %s", a)
	}

	geo := []Rule{{ID: 7, Name: "geo", Enabled: true, Countries: []string{"CN", "RU"}, Action: ActionBlock, TimeoutMin: 60}}
	if d := Decide(geo, out); d.RuleID != 0 {
		t.Errorf("a US server matched CN/RU: %+v", d)
	}
	d := Decide(geo, in)
	if d.RuleID != 7 || d.Target != "203.0.113.9" || d.List != BlockList {
		t.Errorf("an inbound connection from CN blocks the client, never the server at home: %+v", d)
	}
	geo[0].Action = ActionQuarantine
	if d := Decide(geo, in); d.Target != "192.168.11.182" || d.List != QuarantineList {
		t.Errorf("quarantine on an inbound connection lists the device at home: %+v", d)
	}

	r := Rule{Name: "geo", Countries: []string{" cn ", "ru"}, Action: ActionLog}
	if err := r.Validate(); err != nil || r.Countries[0] != "CN" || r.Countries[1] != "RU" {
		t.Errorf("countries normalised: %v %+v", err, r.Countries)
	}
	if err := (&Rule{Name: "geo", Countries: []string{"France"}, Action: ActionLog}).Validate(); err == nil {
		t.Error("a country name is not a code")
	}
	for addr, want := range map[string]bool{"8.8.8.8": true, "192.168.1.1": false, "100.64.1.1": false, "127.0.0.1": false, "x": false} {
		if Public(addr) != want {
			t.Errorf("Public(%s) != %v", addr, want)
		}
	}
}
