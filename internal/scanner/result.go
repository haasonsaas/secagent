package scanner

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/result"

	lsimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
)

// Result wraps a SCALIBR ScanResult with convenience accessors.
type Result struct {
	ScanResult *result.ScanResult
}

// Packages returns all discovered software packages.
func (r *Result) Packages() []*extractor.Package {
	if r.ScanResult == nil {
		return nil
	}
	return r.ScanResult.Inventory.Packages
}

// Vulns returns all package vulnerabilities found.
func (r *Result) Vulns() []*inventory.PackageVuln {
	if r.ScanResult == nil {
		return nil
	}
	return r.ScanResult.Inventory.PackageVulns
}

// Secrets returns all secrets found.
func (r *Result) Secrets() []*inventory.Secret {
	if r.ScanResult == nil {
		return nil
	}
	return r.ScanResult.Inventory.Secrets
}

// Findings returns all generic findings.
func (r *Result) Findings() []*inventory.GenericFinding {
	if r.ScanResult == nil {
		return nil
	}
	return r.ScanResult.Inventory.GenericFindings
}

// HasVulns returns true if any vulnerabilities were found.
func (r *Result) HasVulns() bool {
	return len(r.Vulns()) > 0
}

// HasSecrets returns true if any secrets were found.
func (r *Result) HasSecrets() bool {
	return len(r.Secrets()) > 0
}

// HasFindings returns true if any generic findings were found.
func (r *Result) HasFindings() bool {
	return len(r.Findings()) > 0
}

// ImageResult wraps Result with container image metadata.
type ImageResult struct {
	Result
	Image *lsimage.Image
}
