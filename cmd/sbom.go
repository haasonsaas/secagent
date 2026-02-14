package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/converter/spdx"

	"secagent/internal/scanner"
)

// RunSBOM generates an SBOM in the specified format for the target.
func RunSBOM(ctx context.Context, target string, format string) error {
	fmt.Println("Scanning", target, "for packages...")

	result, err := scanner.Scan(ctx, scanner.ScanOptions{
		Target: target,
		Mode:   scanner.ModeSCA,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	inv := result.ScanResult.Inventory

	switch format {
	case "cdx", "cyclonedx":
		bom := converter.ToCDX(inv, converter.CDXConfig{
			ComponentName: target,
			ComponentType: "application",
		})
		var buf bytes.Buffer
		encoder := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
		encoder.SetPretty(true)
		if err := encoder.Encode(bom); err != nil {
			return fmt.Errorf("encoding CycloneDX: %w", err)
		}
		fmt.Print(buf.String())

	default: // spdx
		doc := converter.ToSPDX23(inv, spdx.Config{
			DocumentName:      "secagent-sbom",
			DocumentNamespace: "https://secagent.dev/sbom/" + target,
		})
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding SPDX: %w", err)
		}
		fmt.Println(string(out))
	}

	return nil
}
