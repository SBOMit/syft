package files

import (
	"regexp"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func ResolvePathsToRustPackagesFiles(paths []string) ([]pkg.Package, []file.Metadata) {
	var pkgs []pkg.Package
	var files []file.Metadata

	chosenByName := map[string]string{}

	// patterns to detect crate names and versions from common maturin/cargo paths
	// examples:
	// /.../registry/src/index.crates.io-.../cfg-if-1.0.4/src/lib.rs
	// /.../registry/cache/.../serde-1.0.228.crate
	fingerprintRe := regexp.MustCompile(`\.fingerprint/([^-/]+)-[a-f0-9]+/`)
	// crate dir or file with version: name-version/ or name-version.crate
	// Use a pragmatic approach: capture everything before the LAST '-' as the name
	// and require the version to start with a digit (to avoid matching other hyphenated dirs).
	crateDirWithVerRe := regexp.MustCompile(`([^/]+)-([0-9][0-9A-Za-z\.\-\+]*)(?:/|$)`)
	crateFileWithVerRe := regexp.MustCompile(`([^/]+)-([0-9][0-9A-Za-z\.\-\+]*)\.crate$`)

	for _, p := range paths {
		pp := strings.TrimSpace(p)

		if m := crateFileWithVerRe.FindStringSubmatch(pp); len(m) == 3 {
			if strings.Contains(pp, "/registry/cache/") || strings.Contains(pp, "index.crates.io") {
				chosenByName[m[1]] = m[2]
			}
			continue
		}
		if m := crateDirWithVerRe.FindStringSubmatch(pp); len(m) == 3 {
			// indicators that this is cargo-related
			// NOTE: do NOT treat paths under /.fingerprint/ or /target/ as authoritative
			// sources of crate versions: those directories contain build fingerprints
			// (hash-like identifiers), not the crate semver. Only accept the name-version
			// pattern when it appears in known cargo registry/cache/index or crate files.
			if strings.Contains(pp, "/registry/cache") || strings.Contains(pp, ".crate") || strings.Contains(pp, "/crates/") || (strings.Contains(pp, "/registry/src/") && strings.Contains(pp, "index.crates.io")) {
				chosenByName[m[1]] = m[2]
				continue
			}
			continue
		}

		if m := fingerprintRe.FindStringSubmatch(pp); len(m) == 2 {
			if vm := crateDirWithVerRe.FindStringSubmatch(pp); len(vm) == 3 {
				if strings.Contains(pp, "/registry/src/") && strings.Contains(pp, "index.crates.io") {
					chosenByName[vm[1]] = vm[2]
				}
			}
			continue
		}
	}

	seen := map[string]struct{}{}
	for _, p := range paths {
		norm := strings.TrimSpace(p)

		// ignore some common build noise
		if strings.Contains(norm, "/.fingerprint/") || strings.Contains(norm, "/target/") {
			continue
		}

		// skip compiled artifacts; they are not useful as independent file entries here
		if strings.HasSuffix(norm, ".d") || strings.HasSuffix(norm, ".rlib") || strings.HasSuffix(norm, ".rmeta") || strings.HasSuffix(norm, ".so") {
			owned := false
			for c := range chosenByName {
				if strings.HasPrefix(norm, c+"/") || strings.Contains(norm, "/"+c+"/") || strings.Contains(norm, "/"+c+"-") {
					owned = true
					break
				}
			}
			if owned {
				continue
			}
		}

		if _, ok := seen[norm]; !ok {
			seen[norm] = struct{}{}
			files = append(files, file.Metadata{Path: norm, Type: stereoscopeFile.TypeRegular})
		}
	}

	// build packages list from chosen crate names (only those with versions)
	for name, ver := range chosenByName {
		if name == "" || ver == "" {
			continue
		}
		p := pkg.Package{
			Name:    name,
			Version: ver,
			Type:    pkg.RustPkg,
			FoundBy: "attestation",
		}
		// include a purl with version
		p.PURL = "pkg:cargo/" + strings.ToLower(p.Name) + "@" + p.Version
		p.SetID()
		pkgs = append(pkgs, p)
	}

	return pkgs, files
}
