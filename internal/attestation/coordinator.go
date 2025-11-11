package attestation

import (
	"fmt"
	"strings"

	attfiles "github.com/anchore/syft/internal/attestation/files"
	"github.com/anchore/syft/internal/attestation/network"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// ResolveAttestationEvidence coordinates per-ecosystem path resolution and download mapping.
// - paths: attestation-reported file paths
// - downloads: parsed network download entries
// - forcedEcosystem: if non-empty, only use that ecosystem's resolver/mapper
// Returns: discovered packages and leftover file metadata
func ResolveAttestationEvidence(paths []string, downloads []network.DownloadEntry, forcedEcosystem string) ([]pkg.Package, []file.Metadata) {
	// populate default registries (one-time, idempotent): delegate to existing top-level functions
	// so this change is refactor-only and preserves current behavior.
	if len(pathResolvers) == 0 {
		// adapters that call the per-ecosystem files package implementations (refactor-safe)
		RegisterPathResolver("python", pathResolverFunc(func(p []string) ([]pkg.Package, []file.Metadata) {
			return attfiles.ResolvePathsToPythonPackagesFiles(p)
		}))
		RegisterPathResolver("go", pathResolverFunc(func(p []string) ([]pkg.Package, []file.Metadata) { return attfiles.ResolvePathsToGoPackagesFiles(p) }))
		RegisterPathResolver("rust", pathResolverFunc(func(p []string) ([]pkg.Package, []file.Metadata) { return attfiles.ResolvePathsToRustPackagesFiles(p) }))

		// default download mapper uses the network package AttachDownloadsToPackages implementation
		RegisterDownloadMapper("default", downloadMapperFunc(func(pkgs []pkg.Package, d []network.DownloadEntry) []pkg.Package {
			return network.AttachDownloadsToPackages(pkgs, d)
		}))
	}

	var allPkgs []pkg.Package
	var allFiles []file.Metadata
	seenPkgKeys := map[string]struct{}{}

	// helper to dedupe packages by name+type+version
	dedupeKey := func(p pkg.Package) string {
		return strings.ToLower(fmt.Sprintf("%s|%v|%s", p.Name, p.Type, p.Version))
	}

	// choose which resolvers to run
	if forcedEcosystem != "" {
		if r, ok := pathResolvers[forcedEcosystem]; ok {
			pkgs, files := r.Resolve(paths)
			for _, f := range files {
				allFiles = append(allFiles, f)
			}
			for _, p := range pkgs {
				k := dedupeKey(p)
				if _, ok := seenPkgKeys[k]; ok {
					continue
				}
				seenPkgKeys[k] = struct{}{}
				allPkgs = append(allPkgs, p)
			}
		}
	} else {
		// run all registered path resolvers and merge results
		for _, r := range pathResolvers {
			pkgs, files := r.Resolve(paths)
			for _, f := range files {
				allFiles = append(allFiles, f)
			}
			for _, p := range pkgs {
				k := dedupeKey(p)
				if _, ok := seenPkgKeys[k]; ok {
					continue
				}
				seenPkgKeys[k] = struct{}{}
				allPkgs = append(allPkgs, p)
			}
		}
	}

	// Attach downloads as enrichment using the default mapper
	if mapper, ok := downloadMappers["default"]; ok && len(downloads) > 0 {
		allPkgs = mapper.MapDownloads(allPkgs, downloads)
	}

	return allPkgs, allFiles
}

// small function adapters to implement interfaces from plain functions
type pathResolverFunc func([]string) ([]pkg.Package, []file.Metadata)

func (f pathResolverFunc) Resolve(p []string) ([]pkg.Package, []file.Metadata) { return f(p) }

type downloadMapperFunc func([]pkg.Package, []network.DownloadEntry) []pkg.Package

func (f downloadMapperFunc) MapDownloads(pkgs []pkg.Package, d []network.DownloadEntry) []pkg.Package {
	return f(pkgs, d)
}
