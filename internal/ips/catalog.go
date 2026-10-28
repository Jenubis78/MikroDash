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

// Catalog is everything the rule editor offers.
type Catalog struct {
	NDPI       string       `json:"ndpi"`
	Apps       []CatalogApp `json:"apps"`
	Categories []string     `json:"categories"`
	Breeds     []string     `json:"breeds"`
	Risks      []string     `json:"risks"`
}

var (
	catalogOnce sync.Once
	catalog     Catalog
)

// TheCatalog is the embedded catalogue, read once.
func TheCatalog() Catalog {
	catalogOnce.Do(func() {
		if err := json.Unmarshal(catalogJSON, &catalog); err != nil {
			panic("ips: ndpi_catalog.json: " + err.Error())
		}
	})
	return catalog
}
