package scanner

import (
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/result"

	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

func makeTestResult(pkgs []*extractor.Package, vulns []*inventory.PackageVuln, secrets []*inventory.Secret) *Result {
	return &Result{
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

func TestResult_NilScanResult(t *testing.T) {
	r := &Result{ScanResult: nil}

	if r.Packages() != nil {
		t.Error("Packages() should return nil for nil ScanResult")
	}
	if r.Vulns() != nil {
		t.Error("Vulns() should return nil for nil ScanResult")
	}
	if r.Secrets() != nil {
		t.Error("Secrets() should return nil for nil ScanResult")
	}
	if r.Findings() != nil {
		t.Error("Findings() should return nil for nil ScanResult")
	}
	if r.HasVulns() {
		t.Error("HasVulns() should return false for nil ScanResult")
	}
	if r.HasSecrets() {
		t.Error("HasSecrets() should return false for nil ScanResult")
	}
}

func TestResult_WithPackages(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "foo", Version: "1.0"},
		{Name: "bar", Version: "2.0"},
	}
	r := makeTestResult(pkgs, nil, nil)

	if len(r.Packages()) != 2 {
		t.Errorf("expected 2 packages, got %d", len(r.Packages()))
	}
	if r.HasVulns() {
		t.Error("should not have vulns")
	}
	if r.HasSecrets() {
		t.Error("should not have secrets")
	}
}

func TestResult_WithVulns(t *testing.T) {
	vulns := []*inventory.PackageVuln{
		{
			Vulnerability: &osvpb.Vulnerability{Id: "CVE-2023-0001"},
			Package:       &extractor.Package{Name: "vuln-pkg", Version: "1.0"},
		},
	}
	r := makeTestResult(nil, vulns, nil)

	if !r.HasVulns() {
		t.Error("should have vulns")
	}
	if len(r.Vulns()) != 1 {
		t.Errorf("expected 1 vuln, got %d", len(r.Vulns()))
	}
}

func TestResult_WithSecrets(t *testing.T) {
	secrets := []*inventory.Secret{
		{Location: "file.py:10"},
	}
	r := makeTestResult(nil, nil, secrets)

	if !r.HasSecrets() {
		t.Error("should have secrets")
	}
	if len(r.Secrets()) != 1 {
		t.Errorf("expected 1 secret, got %d", len(r.Secrets()))
	}
}

func TestScanMode_PluginNames(t *testing.T) {
	sca := pluginNamesForMode(ModeSCA)
	if len(sca) == 0 {
		t.Error("SCA mode should have plugins")
	}

	sec := pluginNamesForMode(ModeSecrets)
	if len(sec) != 1 || sec[0] != "secrets" {
		t.Error("Secrets mode should have exactly 'secrets' plugin")
	}

	full := pluginNamesForMode(ModeFull)
	if len(full) != len(sca)+len(sec) {
		t.Errorf("Full mode should combine SCA + secrets, got %d", len(full))
	}
}
