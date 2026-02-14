package cmd

import (
	"context"
	"fmt"

	claudecode "github.com/severity1/claude-agent-sdk-go"

	"secagent/internal/mcptools"
)

// RunServe starts a long-running session exposing SCALIBR tools for external Claude sessions.
func RunServe(ctx context.Context) error {
	tools := mcptools.BuildAllTools()
	server := claudecode.CreateSDKMcpServer("scalibr", "1.0.0", tools...)

	allowedTools := make([]string, 0, len(tools))
	for _, t := range tools {
		allowedTools = append(allowedTools, "mcp__scalibr__"+t.Name())
	}

	fmt.Println("secagent serve mode — SCALIBR tools available for external Claude sessions")
	fmt.Println("Press Ctrl+C to stop.")

	return claudecode.WithClient(ctx, func(client claudecode.Client) error {
		<-ctx.Done()
		return ctx.Err()
	},
		claudecode.WithSdkMcpServer("scalibr", server),
		claudecode.WithAllowedTools(allowedTools...),
	)
}
