package network

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// MatchDownloadsForRust applies rust-specific heuristics to map downloads to a package
func MatchDownloadsForRust(p *pkg.Package, downloads []DownloadEntry) []DownloadEntry {
	var matched []DownloadEntry
	lname := strings.ToLower(p.Name)

	for _, d := range downloads {
		// crates.io special handling
		if strings.Contains(d.Host, "crates.io") || strings.Contains(d.URL, "/crates/") {
			// prefer explicit project/version extracted from path
			if d.Project != "" && strings.EqualFold(d.Project, lname) {
				if p.Version == "" || d.Version == "" || strings.EqualFold(d.Version, p.Version) {
					matched = append(matched, d)
					continue
				}
			}
			// filename-based fallback
			if d.Filename != "" && strings.Contains(strings.ToLower(d.Filename), lname) {
				matched = append(matched, d)
				continue
			}
		}
	}

	// fall back to generic heuristics if none found
	if len(matched) == 0 {
		matched = genericMatch(p, downloads)
	}
	return matched
}
