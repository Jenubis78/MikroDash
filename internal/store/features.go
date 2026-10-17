package store

// The optional features, Settings -> Features. Each is off until the operator
// switches it on: off, its controls are not drawn, its endpoints answer 403 and
// nothing of it runs in the background or reads a router.
const (
	FeatureDNSBulk      = "dnsBulkEnabled"      // select many static entries; export them
	FeatureDNSCache     = "dnsCacheEnabled"     // browse the resolver's cache on demand
	FeatureDNSFleetSync = "dnsFleetSyncEnabled" // make routers' static tables match a reference
	FeatureDNSLists     = "dnsListsEnabled"     // FWD entries kept in step with a domain list
	FeatureDNSTrace     = "dnsTraceEnabled"     // why a domain does or does not take its route
)

// FeatureOn reports whether an optional feature is switched on.
func FeatureOn(s Settings, key string) bool { v, _ := s[key].(bool); return v }
