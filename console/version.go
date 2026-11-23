package main

import (
	"strconv"
	"strings"
)

// fdVersion turns an app version ("1.5.3-fd3", or "1.5.3" from builds before
// fd2) into a comparable key. ok is false for anything else.
func fdVersion(v string) (key [4]int, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	base, build, hasBuild := strings.Cut(v, "-fd")
	parts := strings.Split(base, ".")
	if len(parts) != 3 {
		return key, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" {
			return key, false
		}
		key[i] = n
	}
	if hasBuild {
		n, err := strconv.Atoi(build)
		if err != nil || n < 0 {
			return key, false
		}
		key[3] = n
	}
	return key, true
}

func versionLess(a, b [4]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// markOutdated flags devices whose reported app is older than the newest
// version any device reports, and returns that version.
func markOutdated(devs []Device) string {
	var newest [4]int
	newestStr, found := "", false
	for _, d := range devs {
		if k, ok := fdVersion(d.Info.Version); ok && (!found || versionLess(newest, k)) {
			newest, newestStr, found = k, d.Info.Version, true
		}
	}
	for i := range devs {
		if k, ok := fdVersion(devs[i].Info.Version); ok && versionLess(k, newest) {
			devs[i].Outdated = true
		}
	}
	return newestStr
}
