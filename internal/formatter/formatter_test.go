package formatter

import (
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/result"
	"github.com/google/osv-scalibr/veles"

	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"

	"secagent/internal/scanner"
)

func makeResult(pkgs []*extractor.Package, vulns []*inventory.PackageVuln, secrets []*inventory.Secret) *scanner.Result {
	return &scanner.Result{
		ScanResult: &result.ScanResult{
			Version:   "1.0",
			StartTime: time.Now(),
			EndTime:   time.Now(),
			Status:    &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
			Inventory: inventory.Inventory{
				Packages:     pkgs,
				PackageVulns: vulns,
				Secrets:      secrets,
			},
		},
	}
}

func TestFormatForClaude_Empty(t *testing.T) {
	r := makeResult(nil, nil, nil)
	out := FormatForClaude(r)

	if !strings.Contains(out, "# Security Scan Results") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "**Packages found:** 0") {
		t.Error("should show 0 packages")
	}
	if !strings.Contains(out, "**Vulnerabilities found:** 0") {
		t.Error("should show 0 vulns")
	}
	if !strings.Contains(out, "**Secrets found:** 0") {
		t.Error("should show 0 secrets")
	}
	// Should not contain vuln or secret sections
	if strings.Contains(out, "## Vulnerabilities") {
		t.Error("should not have vuln section with no vulns")
	}
	if strings.Contains(out, "## Secrets Detected") {
		t.Error("should not have secrets section with no secrets")
	}
}

func TestFormatForClaude_WithPackages(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "lodash", Version: "4.17.20", PURLType: "npm", Locations: []string{"package-lock.json"}},
		{Name: "requests", Version: "2.28.0", PURLType: "pypi", Locations: []string{"requirements.txt"}},
	}
	r := makeResult(pkgs, nil, nil)
	out := FormatForClaude(r)

	if !strings.Contains(out, "**Packages found:** 2") {
		t.Error("should show 2 packages")
	}
	if !strings.Contains(out, "lodash") {
		t.Error("should contain lodash")
	}
	if !strings.Contains(out, "4.17.20") {
		t.Error("should contain version")
	}
	if !strings.Contains(out, "package-lock.json") {
		t.Error("should contain location")
	}
}

func TestFormatVulnsOnly(t *testing.T) {
	vulns := []*inventory.PackageVuln{
		{
			Vulnerability: &osvpb.Vulnerability{
				Id: "CVE-2023-1234",
				Severity: []*osvpb.Severity{
					{Score: "9.8"},
				},
				Affected: []*osvpb.Affected{
					{
						Ranges: []*osvpb.Range{
							{
								Events: []*osvpb.Event{
									{Introduced: "0"},
									{Fixed: "2.0.0"},
								},
							},
						},
					},
				},
			},
			Package: &extractor.Package{Name: "dangerous-lib", Version: "1.0.0"},
		},
	}

	out := FormatVulnsOnly(vulns)

	if !strings.Contains(out, "CVE-2023-1234") {
		t.Error("should contain CVE ID")
	}
	if !strings.Contains(out, "9.8") {
		t.Error("should contain severity score")
	}
	if !strings.Contains(out, "dangerous-lib") {
		t.Error("should contain package name")
	}
	if !strings.Contains(out, "1.0.0") {
		t.Error("should contain current version")
	}
	if !strings.Contains(out, "2.0.0") {
		t.Error("should contain fixed version")
	}
}

func TestFormatVulnsOnly_NoFixedVersion(t *testing.T) {
	vulns := []*inventory.PackageVuln{
		{
			Vulnerability: &osvpb.Vulnerability{
				Id: "CVE-2023-9999",
			},
			Package: &extractor.Package{Name: "eol-lib", Version: "1.0.0"},
		},
	}

	out := FormatVulnsOnly(vulns)
	if !strings.Contains(out, "CVE-2023-9999") {
		t.Error("should contain CVE ID")
	}
	if !strings.Contains(out, "eol-lib") {
		t.Error("should contain package name")
	}
}

func TestFormatSecretsOnly(t *testing.T) {
	secrets := []*inventory.Secret{
		{
			Secret:   veles.Secret("test-secret-value"),
			Location: "config/settings.py:42",
		},
		{
			Secret:   veles.Secret("another-secret"),
			Location: ".env:3",
			Validation: inventory.SecretValidationResult{
				At:     time.Now(),
				Status: veles.ValidationValid,
			},
		},
	}

	out := FormatSecretsOnly(secrets)

	if !strings.Contains(out, "## Secrets Detected") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "config/settings.py:42") {
		t.Error("should contain first location")
	}
	if !strings.Contains(out, ".env:3") {
		t.Error("should contain second location")
	}
	if !strings.Contains(out, "not validated") {
		t.Error("first secret should show not validated")
	}
}

func TestFormatImageLayers(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:    "musl",
			Version: "1.2.4",
			LayerMetadata: &extractor.LayerMetadata{
				Index:   0,
				Command: "ADD file:abc123 /",
			},
		},
		{
			Name:    "curl",
			Version: "8.1.0",
			LayerMetadata: &extractor.LayerMetadata{
				Index:   1,
				Command: "RUN apk add curl",
			},
		},
	}

	r := &scanner.ImageResult{
		Result: scanner.Result{
			ScanResult: &result.ScanResult{
				Version:   "1.0",
				StartTime: time.Now(),
				EndTime:   time.Now(),
				Status:    &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded},
				Inventory: inventory.Inventory{Packages: pkgs},
			},
		},
	}

	out := FormatImageLayers(r)

	if !strings.Contains(out, "# Container Image Scan Results") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "Layer 0") {
		t.Error("should contain layer 0")
	}
	if !strings.Contains(out, "Layer 1") {
		t.Error("should contain layer 1")
	}
	if !strings.Contains(out, "ADD file:abc123") {
		t.Error("should contain layer command")
	}
	if !strings.Contains(out, "RUN apk add curl") {
		t.Error("should contain layer command")
	}
	if !strings.Contains(out, "musl") {
		t.Error("should contain musl package")
	}
	if !strings.Contains(out, "curl") {
		t.Error("should contain curl package")
	}
}

func TestTruncation(t *testing.T) {
	long := strings.Repeat("x", maxChars+100)
	result := truncate(long)
	if len(result) > maxChars+50 { // allow for the truncation message
		t.Errorf("truncated string too long: %d", len(result))
	}
	if !strings.Contains(result, "truncated") {
		t.Error("should contain truncation notice")
	}
}

func TestTruncation_Short(t *testing.T) {
	short := "hello world"
	result := truncate(short)
	if result != short {
		t.Error("should not truncate short strings")
	}
}

func TestFormatForClaude_NilResult(t *testing.T) {
	r := &scanner.Result{ScanResult: nil}
	// Should not panic
	out := FormatForClaude(r)
	if !strings.Contains(out, "**Packages found:** 0") {
		t.Error("nil result should show 0 packages")
	}
}
