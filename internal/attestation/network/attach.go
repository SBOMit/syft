package network

import (
	"net/url"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// AttachDownloadsToPackages attempts to map discovered downloads to attestation-discovered packages
// It returns a modified slice of packages with package.Metadata["attestation.downloads"] populated
// and, when appropriate, a download_url qualifier added to the package PURL (only if it exists).
func AttachDownloadsToPackages(pkgs []pkg.Package, downloads []DownloadEntry) []pkg.Package {
	for i := range pkgs {
		p := &pkgs[i]
		var matched []DownloadEntry

		// Choose matcher by language when available
		switch p.Language {
		case pkg.Python:
			matched = MatchDownloadsForPython(p, downloads)
		case pkg.Rust:
			matched = MatchDownloadsForRust(p, downloads)
		case pkg.Go:
			matched = MatchDownloadsForGo(p, downloads)
		default:
			matched = genericMatch(p, downloads)
		}

		if len(matched) == 0 {
			continue
		}

		// build metadata entries
		var entries []map[string]interface{}
		var primary string
		for _, m := range matched {
			e := map[string]interface{}{
				"url":  m.URL,
				"host": m.Host,
				"kind": m.Kind,
			}
			if m.Bytes != nil {
				e["bytes"] = *m.Bytes
			}
			if m.Hash != "" {
				e["hash"] = m.Hash
			}
			if m.Filename != "" {
				e["filename"] = m.Filename
			}
			entries = append(entries, e)
			if primary == "" && m.Kind == "artifact" {
				primary = m.URL
			}
		}

		// ensure Metadata is a map[string]interface{}
		var metaMap map[string]interface{}
		if p.Metadata == nil {
			metaMap = map[string]interface{}{}
		} else {
			if mm, ok := p.Metadata.(map[string]interface{}); ok {
				metaMap = mm
			} else {
				// not the expected shape: preserve original under "original" and create a new map
				metaMap = map[string]interface{}{"original": p.Metadata}
			}
		}
		// attach full list for auditability
		metaMap["attestation"] = map[string]interface{}{"downloads": entries}
		p.Metadata = metaMap

		// If there is a primary artifact URL and the package already has a PURL, append a download_url qualifier.
		if primary != "" && p.PURL != "" {
			if !strings.Contains(p.PURL, "?download_url=") {
				enc := url.QueryEscape(primary)
				p.PURL = p.PURL + "?download_url=" + enc
			}
		}
	}

	return pkgs
}
