package attestation

import (
	"strings"

	"github.com/anchore/syft/syft/file"
)

// ExtractAttestationFileDigests walks typed attestations and extracts any reported
// file digests for materials/openedfiles. Returns a map[path] -> []file.Digest
func ExtractAttestationFileDigests(typed []TypedAttestation) map[string][]file.Digest {
	out := make(map[string][]file.Digest)

	for _, ta := range typed {
		// materials
		if m, ok := ta.Data["materials"].(map[string]interface{}); ok {
			for p, v := range m {
				if dig := parsePossibleDigest(v); len(dig) > 0 {
					out[p] = append(out[p], dig...)
				}
			}
		}

		// openedfiles
		if of, ok := ta.Data["openedfiles"].(map[string]interface{}); ok {
			for p, v := range of {
				if dig := parsePossibleDigest(v); len(dig) > 0 {
					out[p] = append(out[p], dig...)
				}
			}
		}

		// some attestations may include a flat map of files at top-level
		for k, v := range ta.Data {
			if strings.HasPrefix(k, "/") {
				if dig := parsePossibleDigest(v); len(dig) > 0 {
					out[k] = append(out[k], dig...)
				}
			}
		}
	}

	return out
}

// parsePossibleDigest accepts an arbitrary attestation value and attempts to extract
// file.Digest entries from common layouts (hash, hashes map, digest map).
func parsePossibleDigest(v interface{}) []file.Digest {
	var ret []file.Digest
	if v == nil {
		return ret
	}

	if m, ok := v.(map[string]interface{}); ok {
		// common: {"hash": "..."}
		if h, ok := m["hash"].(string); ok && h != "" {
			algo := guessAlgorithm(h)
			ret = append(ret, file.Digest{Algorithm: algo, Value: h})
			return ret
		}

		// common: {"hashes": {"sha256":"..."}}
		if hm, ok := m["hashes"].(map[string]interface{}); ok {
			for k, val := range hm {
				if s, ok := val.(string); ok && s != "" {
					ret = append(ret, file.Digest{Algorithm: strings.ToLower(k), Value: s})
				}
			}
			return ret
		}

		// common: {"digests": [{"algorithm":"sha256","value":"..."}]}
		if dm, ok := m["digests"].([]interface{}); ok {
			for _, e := range dm {
				if em, ok := e.(map[string]interface{}); ok {
					alg, _ := em["algorithm"].(string)
					val, _ := em["value"].(string)
					if val != "" {
						if alg == "" {
							alg = guessAlgorithm(val)
						}
						ret = append(ret, file.Digest{Algorithm: strings.ToLower(alg), Value: val})
					}
				}
			}
			return ret
		}

		// sometimes the map is just algo->value like {"sha256":"..."}
		for k, val := range m {
			if s, ok := val.(string); ok && s != "" {
				lk := strings.ToLower(k)
				if lk == "sha1" || lk == "sha256" || lk == "md5" || lk == "sha512" {
					ret = append(ret, file.Digest{Algorithm: lk, Value: s})
				}
			}
		}
	}

	// fallback: if v is a string and looks like a hex digest, guess algorithm
	if s, ok := v.(string); ok && s != "" {
		ret = append(ret, file.Digest{Algorithm: guessAlgorithm(s), Value: s})
	}

	return ret
}

// guessAlgorithm makes a best-effort guess at digest algorithm by length
func guessAlgorithm(d string) string {
	l := len(d)
	switch l {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	case 128:
		return "sha512"
	default:
		return "sha256"
	}
}
