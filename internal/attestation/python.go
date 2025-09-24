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

// PythonAttestationParser parses witness/in-toto attestations for Python ecosystems.
type PythonAttestationParser struct{}

// ParseAttestation implements the AttestationParser interface.
func (p PythonAttestationParser) ParseAttestation(path string) ([]pkg.Package, []file.Metadata, error) {
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
	seen := map[string]struct{}{}

	predicate, ok := att["predicate"].(map[string]interface{})
	if !ok {
		return pkgs, files, nil
	}
	attestations, ok := predicate["attestations"].([]interface{})
	if !ok {
		return pkgs, files, nil
	}
	for _, attRaw := range attestations {
		attMap, ok := attRaw.(map[string]interface{})
		if !ok {
			continue
		}
		attestation, ok := attMap["attestation"].(map[string]interface{})
		if !ok {
			continue
		}
		processes, ok := attestation["processes"].([]interface{})
		if !ok {
			continue
		}
		for _, procRaw := range processes {
			proc, ok := procRaw.(map[string]interface{})
			if !ok {
				continue
			}
			openedfiles, ok := proc["openedfiles"].(map[string]interface{})
			if !ok {
				continue
			}
			for filePath := range openedfiles {

				// Ignore non-pkg files
				if strings.Contains(filePath, "__pycache__") ||
					strings.Contains(filePath, "/locale/") ||
					strings.HasSuffix(filePath, ".mo") {
					continue
				}

				// Promote .dist-info/ or .egg-info/ → library
				libRe := regexp.MustCompile(`(?:dist-packages/|site-packages/)?([^/]+)-([\d\.\+\w]+)\.(dist-info|egg-info)(?:/[^/]*)?$`)
				if m := libRe.FindStringSubmatch(filePath); len(m) == 4 {
					name := m[1]
					version := m[2]
					key := strings.ToLower(name) + "@" + version
					if _, exists := seen[key]; !exists {
						seen[key] = struct{}{}
						p := pkg.Package{
							Name:    name,
							Version: version,
							Type:    pkg.PythonPkg,
							FoundBy: "attestation",
						}
						p.SetID()
						pkgs = append(pkgs, p)
					}
					continue
				}

				// Otherwise → file metadata
				if _, exists := seen[filePath]; !exists {
					seen[filePath] = struct{}{}
					files = append(files, file.Metadata{
						Path: filePath,
						Type: stereoscopeFile.TypeRegular,
					})
				}
			}
		}
	}
	return pkgs, files, nil
}

func init() {
	RegisterParser("python", PythonAttestationParser{})
}
