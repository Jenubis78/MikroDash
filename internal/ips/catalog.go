package ips

// The names a rule can match, as nDPI writes them: the rule editor's lists.
//
// ndpi_catalog.json is PRINTED by dpi-sensor/tools/catalog.c from the nDPI the
// sensor links, never typed: a rule matches the exact strings the sensor sends,
// and one letter of difference ("Netflix" for "NetFlix") is a rule that never
// matches. Regenerate it whenever the sensor's Dockerfile moves NDPI_REF.

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed ndpi_catalog.json
var catalogJSON []byte

// CatalogApp is one protocol nDPI can name.
type CatalogApp struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Breed    string `json:"breed"`
}

// CatalogRisk is one risk nDPI can raise, with the severity nDPI gives it.
type CatalogRisk struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// Catalog is everything the rule editor offers.
type Catalog struct {
	NDPI       string        `json:"ndpi"`
	Apps       []CatalogApp  `json:"apps"`
	Categories []string      `json:"categories"`
	Breeds     []string      `json:"breeds"`
	Risks      []CatalogRisk `json:"risks"`
}

var (
	catalogOnce sync.Once
	catalog     Catalog
	severityOf  map[string]string
)

// TheCatalog is the embedded catalogue, read once.
func TheCatalog() Catalog {
	catalogOnce.Do(func() {
		if err := json.Unmarshal(catalogJSON, &catalog); err != nil {
			panic("ips: ndpi_catalog.json: " + err.Error())
		}
		severityOf = map[string]string{}
		for _, r := range catalog.Risks {
			severityOf[r.Name] = r.Severity
		}
	})
	return catalog
}

// Severities in nDPI's order, least first.
var severities = []string{"Low", "Medium", "High", "Severe", "Critical", "Emergency"}

// SeverityRank orders severities: 0 for none or unknown, 1 for Low, and so on.
func SeverityRank(s string) int {
	for i, v := range severities {
		if v == s {
			return i + 1
		}
	}
	return 0
}

// RiskSeverity is nDPI's severity for a risk name, or "" for one the catalogue
// does not know.
func RiskSeverity(name string) string {
	TheCatalog()
	return severityOf[name]
}

// WorstSeverity is the highest severity among a flow's risks, or "".
func WorstSeverity(risks []string) string {
	worst := ""
	for _, r := range risks {
		if s := RiskSeverity(r); SeverityRank(s) > SeverityRank(worst) {
			worst = s
		}
	}
	return worst
}
