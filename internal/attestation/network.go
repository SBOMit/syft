package attestation

import (
	"github.com/anchore/syft/internal/attestation/network"
	"github.com/anchore/syft/syft/pkg"
)

// ParseNetworkDownloads is a thin wrapper that converts a slice of TypedAttestation
// into the raw data maps expected by the network parser and returns network.DownloadEntry.
func ParseNetworkDownloads(typed []TypedAttestation) []network.DownloadEntry {
	var typedData []map[string]interface{}
	for _, t := range typed {
		typedData = append(typedData, t.Data)
	}
	return network.ParseNetworkDownloads(typedData)
}

// AttachDownloadsToPackages delegates to the network package implementation.
func AttachDownloadsToPackages(pkgs []pkg.Package, downloads []network.DownloadEntry) []pkg.Package {
	return network.AttachDownloadsToPackages(pkgs, downloads)
}
