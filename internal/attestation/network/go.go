package network

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// MatchDownloadsForGo applies Go-specific heuristics to map downloads to a package
func MatchDownloadsForGo(p *pkg.Package, downloads []DownloadEntry) []DownloadEntry {
	// Prefer modules served by common Go proxies
	var matched []DownloadEntry
	lname := strings.ToLower(p.Name)

	for _, d := range downloads {
		if strings.Contains(d.Host, "proxy.golang.org") || strings.Contains(d.Host, "sum.golang.org") {
			if d.Filename != "" && strings.Contains(strings.ToLower(d.Filename), lname) {
				matched = append(matched, d)
				continue
			}
		}
	}

	if len(matched) == 0 {
		matched = genericMatch(p, downloads)
	}
	return matched
}
