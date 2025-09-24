package attestation

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// AttestationParser defines the interface for language/ecosystem-specific attestation handlers.
type AttestationParser interface {
	ParseAttestation(path string) ([]pkg.Package, []file.Metadata, error)
}

// Registry for available attestation parsers by ecosystem/language.
var parserRegistry = map[string]AttestationParser{}

// RegisterParser allows adding a parser for a given language/ecosystem.
func RegisterParser(lang string, parser AttestationParser) {
	parserRegistry[lang] = parser
}

// GetParser returns the parser for a given language/ecosystem, if available.
func GetParser(lang string) AttestationParser {
	return parserRegistry[lang]
}
