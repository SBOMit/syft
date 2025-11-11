package files

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func ResolvePathsToPythonPackagesFiles(paths []string) ([]pkg.Package, []file.Metadata) {
	var pkgs []pkg.Package
	var filesFound []file.Metadata

	// Examples matched: "site-packages/foo-1.2.3.dist-info" or "dist-packages/foo-1.2.3.egg-info"
	re := regexp.MustCompile(`((dist-packages|site-packages)/)?([^/]+)-([0-9A-Za-z\.\+\-_]+)\.(dist-info|egg-info)`) // simplified capture

	seenMeta := map[string]struct{}{}

	for _, p := range paths {
		// normalize
		np := path.Clean(p)
		if strings.Contains(np, "site-packages") || strings.Contains(np, "dist-packages") || strings.Contains(np, "egg-info") || strings.Contains(np, "dist-info") {
			m := re.FindStringSubmatch(np)
			if len(m) > 0 {
				name := m[3]
				version := m[4]
				key := name + "@" + version
				if _, ok := seenMeta[key]; ok {
					continue
				}
				seenMeta[key] = struct{}{}

				purl := "pkg:pypi/" + name + "@" + version
				pkgObj := pkg.Package{
					Name:    name,
					Version: version,
					Type:    pkg.PythonPkg,
					PURL:    purl,
					FoundBy: "attestation:python",
				}
				pkgs = append(pkgs, pkgObj)
				filesFound = append(filesFound, file.Metadata{Path: filepath.ToSlash(np)})
			}
		}
	}

	return pkgs, filesFound
}
