package mcptools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/converter/spdx"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// BuildAllTools returns MCP tool definitions for SCALIBR scanning capabilities.
func BuildAllTools() []*claudecode.McpTool {
	return []*claudecode.McpTool{
		scanPathTool(),
		scanSecretsTool(),
		scanImageTool(),
		scanHardenTool(),
		generateSBOMTool(),
	}
}

func scanPathTool() *claudecode.McpTool {
	return claudecode.NewTool(
		"scan_path",
		"Scan a filesystem path for software packages and known vulnerabilities (CVEs). Returns a formatted report of all packages found and any associated vulnerabilities.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "The filesystem path to scan (absolute or relative)",
				},
				"osv_match": map[string]any{
					"type":        "boolean",
					"description": "Whether to match packages against the OSV vulnerability database (default: true)",
				},
			},
			"required": []string{"path"},
		},
		func(ctx context.Context, args map[string]any) (*claudecode.McpToolResult, error) {
			path, _ := args["path"].(string)
			if path == "" {
				path = "."
			}

			osvMatch := true
			if v, ok := args["osv_match"].(bool); ok {
				osvMatch = v
			}

			result, err := scanner.Scan(ctx, scanner.ScanOptions{
				Target:       path,
				Mode:         scanner.ModeSCA,
				WithOSVMatch: osvMatch,
			})
			if err != nil {
				return &claudecode.McpToolResult{
					Content: []claudecode.McpContent{{Type: "text", Text: fmt.Sprintf("Scan error: %v", err)}},
					IsError: true,
				}, nil
			}

			report := formatter.FormatForClaude(result)
			return &claudecode.McpToolResult{
				Content: []claudecode.McpContent{{Type: "text", Text: report}},
			}, nil
		},
	)
}

func scanSecretsTool() *claudecode.McpTool {
	return claudecode.NewTool(
		"scan_secrets",
		"Scan a filesystem path for secrets, credentials, and API keys. Returns a report of all detected secrets with their locations.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "The filesystem path to scan for secrets",
				},
			},
			"required": []string{"path"},
		},
		func(ctx context.Context, args map[string]any) (*claudecode.McpToolResult, error) {
			path, _ := args["path"].(string)
			if path == "" {
				path = "."
			}

			result, err := scanner.Scan(ctx, scanner.ScanOptions{
				Target: path,
				Mode:   scanner.ModeSecrets,
			})
			if err != nil {
				return &claudecode.McpToolResult{
					Content: []claudecode.McpContent{{Type: "text", Text: fmt.Sprintf("Scan error: %v", err)}},
					IsError: true,
				}, nil
			}

			report := formatter.FormatSecretsOnly(result.Secrets())
			if !result.HasSecrets() {
				report = "No secrets detected in the scanned path."
			}
			return &claudecode.McpToolResult{
				Content: []claudecode.McpContent{{Type: "text", Text: report}},
			}, nil
		},
	)
}

func scanImageTool() *claudecode.McpTool {
	return claudecode.NewTool(
		"scan_image",
		"Scan a container image for software packages and vulnerabilities. Supports remote registry images, local Docker images, and tarballs.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"image_ref": map[string]any{
					"type":        "string",
					"description": "The image reference (e.g. 'alpine:latest', 'gcr.io/project/image:tag', or '/path/to/image.tar')",
				},
			},
			"required": []string{"image_ref"},
		},
		func(ctx context.Context, args map[string]any) (*claudecode.McpToolResult, error) {
			ref, _ := args["image_ref"].(string)
			if ref == "" {
				return &claudecode.McpToolResult{
					Content: []claudecode.McpContent{{Type: "text", Text: "image_ref is required"}},
					IsError: true,
				}, nil
			}

			result, err := scanner.ScanImage(ctx, scanner.ImageScanOptions{
				ImageRef:     ref,
				WithOSVMatch: true,
			})
			if err != nil {
				return &claudecode.McpToolResult{
					Content: []claudecode.McpContent{{Type: "text", Text: fmt.Sprintf("Image scan error: %v", err)}},
					IsError: true,
				}, nil
			}
			defer result.Image.CleanUp()

			report := formatter.FormatImageLayers(result)
			return &claudecode.McpToolResult{
				Content: []claudecode.McpContent{{Type: "text", Text: report}},
			}, nil
		},
	)
}

func scanHardenTool() *claudecode.McpTool {
	return claudecode.NewTool(
		"scan_harden",
		"Scan a filesystem path for security misconfigurations (CIS benchmarks, weak credentials, privilege escalation, end-of-life software).",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "The filesystem path to scan for misconfigurations",
				},
			},
			"required": []string{"path"},
		},
		func(ctx context.Context, args map[string]any) (*claudecode.McpToolResult, error) {
			path, _ := args["path"].(string)
			if path == "" {
				path = "."
			}

			result, err := scanner.Scan(ctx, scanner.ScanOptions{
				Target: path,
				Mode:   scanner.ModeHarden,
			})
			if err != nil {
				return &claudecode.McpToolResult{
					Content: []claudecode.McpContent{{Type: "text", Text: fmt.Sprintf("Scan error: %v", err)}},
					IsError: true,
				}, nil
			}

			if !result.HasFindings() {
				return &claudecode.McpToolResult{
					Content: []claudecode.McpContent{{Type: "text", Text: "No security misconfigurations detected."}},
				}, nil
			}

			report := formatter.FormatFindings(result.Findings())
			return &claudecode.McpToolResult{
				Content: []claudecode.McpContent{{Type: "text", Text: report}},
			}, nil
		},
	)
}

func generateSBOMTool() *claudecode.McpTool {
	return claudecode.NewTool(
		"generate_sbom",
		"Generate a Software Bill of Materials (SBOM) for a filesystem path in SPDX or CycloneDX format.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{
					"type":        "string",
					"description": "The filesystem path to scan for packages",
				},
				"format": map[string]any{
					"type":        "string",
					"description": "SBOM format: 'spdx' (default) or 'cdx' (CycloneDX)",
					"enum":        []string{"spdx", "cdx"},
				},
			},
			"required": []string{"path"},
		},
		func(ctx context.Context, args map[string]any) (*claudecode.McpToolResult, error) {
			path, _ := args["path"].(string)
			if path == "" {
				path = "."
			}

			sbomFormat, _ := args["format"].(string)
			if sbomFormat == "" {
				sbomFormat = "spdx"
			}

			result, err := scanner.Scan(ctx, scanner.ScanOptions{
				Target: path,
				Mode:   scanner.ModeSCA,
			})
			if err != nil {
				return &claudecode.McpToolResult{
					Content: []claudecode.McpContent{{Type: "text", Text: fmt.Sprintf("Scan error: %v", err)}},
					IsError: true,
				}, nil
			}

			inv := result.ScanResult.Inventory
			var output string

			switch sbomFormat {
			case "cdx":
				bom := converter.ToCDX(inv, converter.CDXConfig{
					ComponentName: path,
					ComponentType: "application",
				})
				var buf bytes.Buffer
				encoder := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
				encoder.SetPretty(true)
				if err := encoder.Encode(bom); err != nil {
					return &claudecode.McpToolResult{
						Content: []claudecode.McpContent{{Type: "text", Text: fmt.Sprintf("Encoding error: %v", err)}},
						IsError: true,
					}, nil
				}
				output = buf.String()

			default: // spdx
				doc := converter.ToSPDX23(inv, spdx.Config{
					DocumentName:      "secagent-sbom",
					DocumentNamespace: "https://secagent.dev/sbom/" + path,
				})
				out, err := json.MarshalIndent(doc, "", "  ")
				if err != nil {
					return &claudecode.McpToolResult{
						Content: []claudecode.McpContent{{Type: "text", Text: fmt.Sprintf("Encoding error: %v", err)}},
						IsError: true,
					}, nil
				}
				output = string(out)
			}

			return &claudecode.McpToolResult{
				Content: []claudecode.McpContent{{Type: "text", Text: output}},
			}, nil
		},
	)
}
