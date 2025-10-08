package attestation

import (
	"regexp"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// ResolvePathsToPythonPackages accepts a list of file paths (e.g., opened files from attestations)
// and returns resolved Python packages and file.Metadata for unresolved files.
func ResolvePathsToPythonPackages(paths []string) ([]pkg.Package, []file.Metadata) {
	var pkgs []pkg.Package
	var files []file.Metadata

	// track chosen package per name, prefer site-packages over dist-packages
	type chosen struct {
		name    string
		version string
		src     string // "site-packages" | "dist-packages" | ""
	}

	chosenByName := map[string]chosen{}
	seenFiles := map[string]struct{}{}

	libRe := regexp.MustCompile(`(?:((?:dist-packages|site-packages))/)?([^/]+)-([\d\.\+\w]+)\.(dist-info|egg-info)(?:/[^/]*)?$`)

	for _, filePath := range paths {
		// Ignore non-pkg files
		if strings.Contains(filePath, "__pycache__") ||
			strings.Contains(filePath, "/locale/") ||
			strings.HasSuffix(filePath, ".mo") {
			continue
		}

		if m := libRe.FindStringSubmatch(filePath); len(m) == 5 {
			src := m[1] // may be "site-packages" or "dist-packages" or ""
			name := m[2]
			version := m[3]

			cur, exists := chosenByName[strings.ToLower(name)]
			// decide whether to replace current chosen entry
			replace := false
			if !exists {
				replace = true
			} else {
				// if existing source is dist and new source is site, prefer site
				if cur.src == "dist-packages" && src == "site-packages" {
					replace = true
				}
				// if both same source, keep existing (first seen)
			}

			if replace {
				chosenByName[strings.ToLower(name)] = chosen{name: name, version: version, src: src}
			}
			continue
		}

		if _, exists := seenFiles[filePath]; !exists {
			seenFiles[filePath] = struct{}{}
			files = append(files, file.Metadata{
				Path: filePath,
				Type: stereoscopeFile.TypeRegular,
			})
		}
	}

	// build pkgs list from chosenByName
	for _, c := range chosenByName {
		p := pkg.Package{
			Name:    c.name,
			Version: c.version,
			Type:    pkg.PythonPkg,
			FoundBy: "attestation",
		}
		p.SetID()
		pkgs = append(pkgs, p)
	}

	return pkgs, files
}
