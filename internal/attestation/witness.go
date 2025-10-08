package attestation

import (
	"encoding/json"
	"os"
)

// TypedAttestation is a normalized representation of an attestation entry
// after type-specific parsing.
type TypedAttestation struct {
	Type string                 // the attestation type URI
	Data map[string]interface{} // extracted, type-specific info
}

// handler signature for type-specific parsers.
type attHandler func(map[string]interface{}) map[string]interface{}

// registry of handlers for known attestation types.
var attHandlers = map[string]attHandler{
	"https://witness.dev/attestations/environment/v0.1": handleEnvironment,
	"https://witness.dev/attestations/git/v0.1":         handleGit,
	"https://witness.dev/attestations/material/v0.1":    handleMaterial,
	"https://witness.dev/attestations/command-run/v0.1": handleCommandRun,
	"https://witness.dev/attestations/product/v0.1":     handleProduct,
	"https://witness.dev/attestations/network/v0.1":     handleNetwork,
}

// ParseWitnessFile reads a witness document (the attestation collection)
// and returns a slice of typed attestations with extracted info.
func ParseWitnessFile(path string) ([]TypedAttestation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	predicate, _ := doc["predicate"].(map[string]interface{})
	attestations, _ := predicate["attestations"].([]interface{})
	if attestations == nil {
		// support older/alternate layout: top-level "attestations"
		if a, ok := doc["attestations"].([]interface{}); ok {
			attestations = a
		}
	}

	var out []TypedAttestation
	for _, a := range attestations {
		attMap, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		attType, _ := attMap["type"].(string)
		attBody, _ := attMap["attestation"].(map[string]interface{})
		// if attestation body is missing, use the whole map as fallback
		if attBody == nil {
			// sometimes the attestation entry is nested differently; try "payload" or the entry itself
			if p, ok := attMap["payload"].(map[string]interface{}); ok {
				attBody = p
			} else {
				attBody = attMap
			}
		}

		handler := attHandlers[attType]
		var info map[string]interface{}
		if handler != nil {
			info = handler(attBody)
		} else {
			// unknown type: keep raw body under "raw"
			info = map[string]interface{}{"raw": attBody}
		}

		// Normalize type to a short form for easier CLI usage
		short := attType
		switch attType {
		case "https://witness.dev/attestations/environment/v0.1":
			short = "environment"
		case "https://witness.dev/attestations/git/v0.1":
			short = "git"
		case "https://witness.dev/attestations/material/v0.1":
			short = "material"
		case "https://witness.dev/attestations/command-run/v0.1":
			short = "command-run"
		case "https://witness.dev/attestations/product/v0.1":
			short = "product"
		case "https://witness.dev/attestations/network/v0.1":
			short = "network"
		}

		// include original type URI in the parsed data for reference
		info["type_uri"] = attType

		out = append(out, TypedAttestation{
			Type: short,
			Data: info,
		})
	}

	return out, nil
}

// --- handlers ---

func handleEnvironment(att map[string]interface{}) map[string]interface{} {
	// extract variables / env keys if present
	if v, ok := att["variables"].(map[string]interface{}); ok {
		return map[string]interface{}{"variables": v}
	}
	if v, ok := att["env"].(map[string]interface{}); ok {
		return map[string]interface{}{"variables": v}
	}
	// fallback: return att body
	return map[string]interface{}{"raw": att}
}

func handleGit(att map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	// common git fields: remote, url, commit, ref, branch, tag
	// copy any of these if present
	for _, k := range []string{"remote", "url", "commit", "ref", "branch", "tag", "repository"} {
		if v, ok := att[k]; ok {
			out[k] = v
		}
	}
	// if there's a nested "git" or "repo" object, copy it
	if g, ok := att["git"].(map[string]interface{}); ok {
		out["git"] = g
	}
	if len(out) == 0 {
		return map[string]interface{}{"raw": att}
	}
	return out
}

func handleMaterial(att map[string]interface{}) map[string]interface{} {
	// materials commonly are a map[path] -> metadata (hashes)
	if m, ok := att["materials"].(map[string]interface{}); ok {
		return map[string]interface{}{"materials": m}
	}
	// some witness formats put the file map at the top-level
	// detect map[string]{sha256,...}
	candidate := map[string]interface{}{}
	for k, v := range att {
		if _, ok := v.(map[string]interface{}); ok {
			candidate[k] = v
		}
	}
	if len(candidate) > 0 {
		return map[string]interface{}{"materials": candidate}
	}
	return map[string]interface{}{"raw": att}
}

func handleCommandRun(att map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	if cmd, ok := att["command"].([]interface{}); ok {
		out["command"] = cmd
	}
	// processes / openedfiles
	if procs, ok := att["processes"].([]interface{}); ok {
		out["processes"] = procs
	} else if p, ok := att["process"].([]interface{}); ok {
		out["processes"] = p
	}
	// opened files often appear per-process or at top-level as "openedfiles"
	if of, ok := att["openedfiles"].(map[string]interface{}); ok {
		out["openedfiles"] = of
	} else {
		// try to gather openedfiles from processes
		filesAgg := map[string]interface{}{}
		if procs, ok := out["processes"].([]interface{}); ok {
			for _, pr := range procs {
				if prm, ok := pr.(map[string]interface{}); ok {
					if ofm, ok := prm["openedfiles"].(map[string]interface{}); ok {
						for k, v := range ofm {
							filesAgg[k] = v
						}
					}
				}
			}
		}
		if len(filesAgg) > 0 {
			out["openedfiles"] = filesAgg
		}
	}
	if len(out) == 0 {
		return map[string]interface{}{"raw": att}
	}
	return out
}

func handleProduct(att map[string]interface{}) map[string]interface{} {
	// placeholder/todo parser; capture "products" if present
	if p, ok := att["products"].(map[string]interface{}); ok {
		return map[string]interface{}{"products": p}
	}
	return map[string]interface{}{"todo": "product parser not implemented", "raw": att}
}

func handleNetwork(att map[string]interface{}) map[string]interface{} {
	// extract URL-like fields: urls, endpoints, network
	if u, ok := att["urls"].([]interface{}); ok {
		return map[string]interface{}{"urls": u}
	}
	if e, ok := att["endpoints"].([]interface{}); ok {
		return map[string]interface{}{"endpoints": e}
	}
	// fallback to raw
	return map[string]interface{}{"raw": att}
}
