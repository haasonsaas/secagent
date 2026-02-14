package cmd

import (
	"context"
	"fmt"
	"strings"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/agent"
	"secagent/internal/formatter"
	"secagent/internal/scanner"
)

// dangerousPatterns are command patterns blocked during remediation.
var dangerousPatterns = []string{
	"rm -rf",
	"git push",
	"git reset --hard",
	"chmod 777",
	"git clean -f",
	"git checkout .",
}

// blockDangerousCommands is a pre-tool-use hook that prevents dangerous shell commands.
func blockDangerousCommands(_ context.Context, input any, _ *string, _ claudecode.HookContext) (claudecode.HookJSONOutput, error) {
	inputMap, ok := input.(map[string]any)
	if !ok {
		return claudecode.HookJSONOutput{}, nil
	}

	command, _ := inputMap["command"].(string)
	if command == "" {
		return claudecode.HookJSONOutput{}, nil
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(command, pattern) {
			reason := fmt.Sprintf("Blocked dangerous command containing %q", pattern)
			decision := "block"
			return claudecode.HookJSONOutput{
				Decision: &decision,
				Reason:   &reason,
			}, nil
		}
	}

	return claudecode.HookJSONOutput{}, nil
}

// RunRemediate scans for vulnerabilities and uses Claude to apply fixes.
func RunRemediate(ctx context.Context, target string, reachableOnly bool, model string) error {
	fmt.Println("Scanning", target, "for vulnerabilities...")

	result, err := scanner.Scan(ctx, scanner.ScanOptions{
		Target:           target,
		Mode:             scanner.ModeSCA,
		WithOSVMatch:     true,
		WithReachability: reachableOnly,
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if !result.HasVulns() {
		fmt.Println("No vulnerabilities found — nothing to remediate.")
		return nil
	}

	report := formatter.FormatVulnsOnly(result.Vulns())
	prompt := "Remediate the following vulnerabilities by updating dependency files in this project. Verify changes compile and pass tests before finishing:\n\n" + report

	fmt.Println("Claude is remediating", len(result.Vulns()), "vulnerabilities...")

	opts := []claudecode.Option{
		claudecode.WithSystemPrompt(agent.RemediatePrompt),
		claudecode.WithAllowedTools("Read", "Write", "Edit", "Bash", "Glob", "Grep"),
		claudecode.WithCwd(target),
		claudecode.WithPermissionMode(claudecode.PermissionModeAcceptEdits),
		claudecode.WithMaxTurns(20),
		claudecode.WithFileCheckpointing(),
		claudecode.WithPreToolUseHook("Bash", blockDangerousCommands),
	}
	if model != "" {
		opts = append(opts, claudecode.WithModel(model))
	}

	return claudecode.WithClient(ctx, func(client claudecode.Client) error {
		if err := client.Query(ctx, prompt); err != nil {
			return err
		}
		return agent.StreamToStdout(ctx, client)
	}, opts...)
}
