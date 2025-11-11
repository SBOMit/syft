package attestation

import (
	"github.com/anchore/syft/internal/attestation/network"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// PathResolver resolves a set of attestation-reported file paths into packages and leftover files.
type PathResolver interface {
	Resolve(paths []string) ([]pkg.Package, []file.Metadata)
}

// DownloadMapper maps discovered downloads to packages (enrichment) and may modify package PURLs/metadata.
type DownloadMapper interface {
	MapDownloads(pkgs []pkg.Package, downloads []network.DownloadEntry) []pkg.Package
}

// registries for per-ecosystem implementations. These are populated with defaults that
// delegate to the existing top-level attestation functions so behavior remains unchanged.
var (
	pathResolvers   = map[string]PathResolver{}
	downloadMappers = map[string]DownloadMapper{}
)

// RegisterPathResolver registers a PathResolver for an ecosystem name.
func RegisterPathResolver(name string, r PathResolver) {
	pathResolvers[name] = r
}

// RegisterDownloadMapper registers a DownloadMapper for an ecosystem name.
func RegisterDownloadMapper(name string, m DownloadMapper) {
	downloadMappers[name] = m
}
