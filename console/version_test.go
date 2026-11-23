package main

import "testing"

func TestMarkOutdated(t *testing.T) {
	devs := []Device{
		{ID: "a", Info: SysInfo{Version: "1.5.3"}},
		{ID: "b", Info: SysInfo{Version: "1.5.3-fd2"}},
		{ID: "c", Info: SysInfo{Version: "1.5.3-fd10"}},
		{ID: "d", Info: SysInfo{Version: ""}},
	}
	if got := markOutdated(devs); got != "1.5.3-fd10" {
		t.Fatalf("newest = %q", got)
	}
	want := map[string]bool{"a": true, "b": true, "c": false, "d": false}
	for _, d := range devs {
		if d.Outdated != want[d.ID] {
			t.Errorf("%s (%q): outdated = %v", d.ID, d.Info.Version, d.Outdated)
		}
	}
	for _, bad := range []string{"1.5", "x.y.z", "1.5.3-fdx", "1.5.3.4"} {
		if _, ok := fdVersion(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
