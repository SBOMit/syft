package attestation

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// rustAttestationParser parses Rust witness/in-toto attestations
// and extracts Rust package info.
type rustAttestationParser struct{}

func (p *rustAttestationParser) ParseAttestation(path string) ([]pkg.Package, []file.Metadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var att map[string]interface{}
	if err := json.Unmarshal(data, &att); err != nil {
		return nil, nil, err
	}

	var pkgs []pkg.Package
	var files []file.Metadata
	seenPkgs := map[string]struct{}{}
	seenFiles := map[string]struct{}{}

	crateRe := regexp.MustCompile(`crate-sources/([^/]+)-([\d\.\w\+]+)(/.*)?`)

	// Get materials and products from signed section if present
	// might change if format for attestation changes
	signed, ok := att["signed"].(map[string]interface{})
	if ok {
		materials := map[string]interface{}{}
		products := map[string]interface{}{}
		if m, ok := signed["materials"].(map[string]interface{}); ok {
			materials = m
		}
		if p, ok := signed["products"].(map[string]interface{}); ok {
			products = p
		}
		allFiles := make(map[string]interface{})
		for k, v := range materials {
			allFiles[k] = v
		}
		for k, v := range products {
			allFiles[k] = v
		}

		for filePath, metaRaw := range allFiles {
			if m := crateRe.FindStringSubmatch(filePath); len(m) >= 3 {
				name := m[1]
				version := m[2]
				key := strings.ToLower(name) + "@" + version
				if _, exists := seenPkgs[key]; !exists {
					seenPkgs[key] = struct{}{}
					p := pkg.Package{
						Name:    name,
						Version: version,
						Type:    pkg.RustPkg,
						FoundBy: "attestation",
					}
					p.SetID()
					pkgs = append(pkgs, p)
				}
				continue
			}
			// Add file metadata for non-crate-sources files
			if _, exists := seenFiles[filePath]; !exists {
				seenFiles[filePath] = struct{}{}
				fmeta := file.Metadata{
					Path: filePath,
					Type: stereoscopeFile.TypeRegular,
				}
				if meta, ok := metaRaw.(map[string]interface{}); ok {
					if sha256, ok := meta["sha256"].(string); ok && sha256 != "" {
						// Add hash to fmeta if supported
						// fmeta.Digest = sha256
					}
				}
				files = append(files, fmeta)
			}
		}
	}

	return pkgs, files, nil
}

func init() {
	RegisterParser("rust", &rustAttestationParser{})
}
