package network

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// DownloadEntry represents a discovered network download endpoint from an attestation
type DownloadEntry struct {
	URL      string
	Host     string
	Kind     string // artifact | index | other
	Bytes    *int64
	Hash     string
	Headers  map[string][]string
	Filename string
	Project  string
	Version  string
}

var filenameRe = regexp.MustCompile(`([^/]+?)-([0-9]+[A-Za-z0-9\.\+\-_]*)`) // name-version-ish

// ParseNetworkDownloads extracts download-related URLs and some metadata from a slice of attestation data maps
// Each entry in the slice should be the attestation Data map (map[string]interface{}) from a typed attestation.
func ParseNetworkDownloads(typedData []map[string]interface{}) []DownloadEntry {
	var out []DownloadEntry

	for _, data := range typedData {
		// if handler already produced a top-level urls/endpoints list, prefer that
		if ulist, ok := data["urls"].([]interface{}); ok {
			for _, ui := range ulist {
				if us, ok := ui.(string); ok {
					out = append(out, analyzeURL(us, nil))
				}
			}
		}

		if endpoints, ok := data["endpoints"].([]interface{}); ok {
			for _, ei := range endpoints {
				if es, ok := ei.(string); ok {
					out = append(out, analyzeURL(es, nil))
				}
			}
		}

		// some attestations embed processes -> networkcalls -> dst_addr
		if procs, ok := data["processes"].([]interface{}); ok {
			for _, pr := range procs {
				if prm, ok := pr.(map[string]interface{}); ok {
					if ncs, ok := prm["networkcalls"].([]interface{}); ok {
						for _, nc := range ncs {
							if ncm, ok := nc.(map[string]interface{}); ok {
								// dst_addr
								if dst, ok := ncm["dst_addr"].(string); ok {
									// try to pull response metadata if present
									var headers map[string][]string
									var bytesPtr *int64
									var hash string
									if dataObj, ok := ncm["data"].(map[string]interface{}); ok {
										if resp, ok := dataObj["response"].(map[string]interface{}); ok {
											if b, ok := resp["bytes"]; ok {
												// JSON numbers are float64
												switch v := b.(type) {
												case float64:
													iv := int64(v)
													bytesPtr = &iv
												case int64:
													bytesPtr = &v
												case string:
													if iv, err := strconv.ParseInt(v, 10, 64); err == nil {
														bytesPtr = &iv
													}
												}
											}
											if h, ok := resp["hash"].(string); ok {
												hash = h
											}
											if hdrs, ok := resp["headers"].(map[string]interface{}); ok {
												headers = map[string][]string{}
												for hk, hv := range hdrs {
													switch vt := hv.(type) {
													case []interface{}:
														for _, el := range vt {
															if s, ok := el.(string); ok {
																headers[hk] = append(headers[hk], s)
															}
														}
													case string:
														headers[hk] = append(headers[hk], vt)
													}
												}
											}
										}
									}

									meta := &optionalMeta{headers: headers, bytes: bytesPtr, hash: hash}
									out = append(out, analyzeURL(dst, meta))
								}
							}
						}
					}
				}
			}
		}
	}

	return out
}

// internal small holder for passing some optional metadata
type optionalMeta struct {
	headers map[string][]string
	bytes   *int64
	hash    string
}

func analyzeURL(u string, opt *optionalMeta) DownloadEntry {
	d := DownloadEntry{URL: u, Headers: map[string][]string{}}
	if opt != nil {
		d.Headers = opt.headers
		d.Bytes = opt.bytes
		d.Hash = opt.hash
	}

	parsed, err := url.Parse(u)
	if err == nil {
		d.Host = parsed.Hostname()
		// classify
		if strings.Contains(d.Host, "files.pythonhosted.org") {
			d.Kind = "artifact"
		} else if strings.Contains(d.Host, "pypi.org") {
			d.Kind = "index"
		} else if strings.Contains(d.Host, "crates.io") || strings.Contains(d.Host, "static.crates.io") {
			d.Kind = "artifact"
		} else {
			d.Kind = "other"
		}
		// try to extract filename
		p := parsed.Path
		parts := strings.Split(p, "/")
		if len(parts) > 0 {
			fname := parts[len(parts)-1]
			d.Filename = fname
			if m := filenameRe.FindStringSubmatch(fname); len(m) >= 3 {
				d.Project = strings.ToLower(m[1])
				d.Version = m[2]
			}
			// special-case crates.io download paths: /crates/<name>/<version>/download
			if len(parts) >= 4 && parts[1] == "crates" {
				// parts: ["", "crates", "<name>", "<version>", "download"]
				proj := parts[2]
				ver := parts[3]
				if proj != "" {
					d.Project = strings.ToLower(proj)
				}
				if ver != "" {
					d.Version = ver
				}
			}
		}
	}

	// if headers include X-Pypi-File-Project/Version, prefer those
	if h, ok := d.Headers["X-Pypi-File-Project"]; ok && len(h) > 0 {
		d.Project = strings.ToLower(h[0])
	}
	if hv, ok := d.Headers["X-Pypi-File-Version"]; ok && len(hv) > 0 {
		d.Version = hv[0]
	}

	return d
}

// genericMatch performs the default matching heuristics between a package and downloads
func genericMatch(p *pkg.Package, downloads []DownloadEntry) []DownloadEntry {
	var matched []DownloadEntry
	lname := strings.ToLower(p.Name)
	for _, d := range downloads {
		// match by explicit project header first
		if d.Project != "" {
			if strings.EqualFold(d.Project, lname) {
				matched = append(matched, d)
				continue
			}
		}

		// match by filename name/version
		if d.Filename != "" && p.Version != "" {
			// cheap contains check (case-insensitive)
			if strings.Contains(strings.ToLower(d.Filename), lname) && strings.Contains(strings.ToLower(d.Filename), strings.ToLower(p.Version)) {
				matched = append(matched, d)
				continue
			}
		}

		// match by index URL like /simple/<name>/
		if d.Kind == "index" {
			if strings.Contains(strings.ToLower(d.URL), "/simple/"+lname) || strings.Contains(strings.ToLower(d.URL), "/simple/"+strings.ToLower(p.Name)) {
				matched = append(matched, d)
				continue
			}
		}
	}
	return matched
}
