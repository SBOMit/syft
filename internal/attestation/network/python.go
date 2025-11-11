package network

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// MatchDownloadsForPython applies python-specific heuristics to map downloads to a package
func MatchDownloadsForPython(p *pkg.Package, downloads []DownloadEntry) []DownloadEntry {
	// start with the generic match
	matched := genericMatch(p, downloads)

	// Python-specific: prefer files.pythonhosted.org artifacts that contain the package name
	lname := strings.ToLower(p.Name)
	for _, d := range downloads {
		if strings.Contains(d.Host, "files.pythonhosted.org") {
			if d.Filename != "" && strings.Contains(strings.ToLower(d.Filename), lname) {
				// ensure not already included
				already := false
				for _, ex := range matched {
					if ex.URL == d.URL {
						already = true
						break
					}
				}
				if !already {
					matched = append(matched, d)
				}
			}
		}
	}

	return matched
}
