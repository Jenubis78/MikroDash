package server

import (
	"reflect"
	"testing"

	"mikrodash/internal/routeros"
)

// TestASharedAddressDoesNotIdentifyARouter. The page decides a peer IS the
// router on screen when one address is in both lists, and every RouterOS 7
// loopback answers 00:00:00:00:00:00, so every peer matched and the merge did
// nothing. A VRRP group's virtual MAC is the same on both of its routers.
func TestASharedAddressDoesNotIdentifyARouter(t *testing.T) {
	got := macsOf([]routeros.Reply{
		{"name": "lo", "mac-address": "00:00:00:00:00:00"},
		{"name": "ether1", "mac-address": "02:aa:bb:cc:dd:01"},
		{"name": "bridge", "mac-address": "02:AA:BB:CC:DD:01"},
		{"name": "vrrp1", "mac-address": "00:00:5E:00:01:0A"},
		{"name": "vrrp6", "mac-address": "00:00:5e:00:02:0a"},
		{"name": "wg0"},
	})
	if want := []string{"02:AA:BB:CC:DD:01"}; !reflect.DeepEqual(got, want) {
		t.Errorf("macsOf = %v, want %v", got, want)
	}
}
