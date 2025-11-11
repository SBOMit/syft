package files

import (
	"regexp"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// ResolvePathsToGoPackagesFiles attempts to resolve attestation file paths into Go module packages
// and returns discovered packages plus leftover file metadata. It matches typical module cache
// paths like /pkg/mod/github.com/foo/bar@v1.2.3/... and vendor paths like /vendor/github.com/foo/bar/...
func ResolvePathsToGoPackagesFiles(paths []string) ([]pkg.Package, []file.Metadata) {
	var pkgs []pkg.Package
	var files []file.Metadata

	// match module cache entries: .../pkg/mod/<module>@<version>/...
	modRe := regexp.MustCompile(`(?:/pkg/mod/)?((?:[^/@]+/)*[^/@]+)@([^/]+)(?:/|$)`) // group1=module, group2=version
	// match vendor paths: .../vendor/<module>/...
	vendorRe := regexp.MustCompile(`(?:/|^)vendor/((?:[^/]+/)*[^/]+)(?:/|$)`) // group1=module

	chosenByModule := map[string]struct{ module, version string }{}
	seenFiles := map[string]struct{}{}

	// first pass: discover modules with versions
	for _, p := range paths {
		if m := modRe.FindStringSubmatch(p); len(m) == 3 {
			module := m[1]
			version := m[2]
			key := strings.ToLower(module)
			if _, ok := chosenByModule[key]; !ok {
				chosenByModule[key] = struct{ module, version string }{module: module, version: version}
			}
		}
	}

	// vendor-only modules (no version); add if not already present
	for _, p := range paths {
		if m := vendorRe.FindStringSubmatch(p); len(m) == 2 {
			module := m[1]
			key := strings.ToLower(module)
			if _, ok := chosenByModule[key]; !ok {
				chosenByModule[key] = struct{ module, version string }{module: module, version: ""}
			}
		}
	}

	// second pass: collect leftover file paths, skipping module-owned files (unless binary .so)
	for _, p := range paths {
		// ignore common caches
		if strings.Contains(p, "/.cache/") || strings.Contains(p, "__pycache__") {
			continue
		}

		// skip files that are inside discovered module dirs (unless .so)
		owned := false
		lp := strings.ToLower(p)
		for _, entry := range chosenByModule {
			module := strings.ToLower(entry.module)
			// check likely module prefixes
			if strings.Contains(lp, "/pkg/mod/"+module+"@") || strings.Contains(lp, "/vendor/"+module+"/") || strings.Contains(lp, "/vendor/"+module) {
				if strings.HasSuffix(lp, ".so") || strings.Contains(lp, ".so.") {
					// keep shared libraries
					break
				}
				owned = true
				break
			}
		}
		if owned {
			continue
		}

		if _, ok := seenFiles[p]; !ok {
			seenFiles[p] = struct{}{}
			files = append(files, file.Metadata{Path: p, Type: stereoscopeFile.TypeRegular})
		}
	}

	// build packages list
	for _, e := range chosenByModule {
		pa := pkg.Package{
			Name:    e.module,
			Version: e.version,
			Type:    pkg.GoModulePkg,
			FoundBy: "attestation",
		}
		// purl: pkg:golang/<module>@<version>
		if pa.Name != "" {
			if pa.Version != "" {
				pa.PURL = "pkg:golang/" + strings.ToLower(pa.Name) + "@" + pa.Version
			} else {
				pa.PURL = "pkg:golang/" + strings.ToLower(pa.Name)
			}
		}
		pa.SetID()
		pkgs = append(pkgs, pa)
	}

	return pkgs, files
}
