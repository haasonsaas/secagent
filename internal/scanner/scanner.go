package scanner

import (
	"context"
	"fmt"
	"strings"

	scalibr "github.com/google/osv-scalibr"
	scalibrfs "github.com/google/osv-scalibr/fs"
	pl "github.com/google/osv-scalibr/plugin/list"
)

// ScanMode determines which plugin sets to load.
type ScanMode int

const (
	ModeSCA     ScanMode = iota // Software composition analysis only
	ModeSecrets                 // Secret detection only
	ModeFull                    // Both SCA and secrets
)

// scaPlugins are the plugin names used for software composition analysis.
var scaPlugins = []string{"os", "python", "javascript", "java", "go", "ruby", "rust"}

// secretPlugins are the plugin names used for secret detection.
var secretPlugins = []string{"secrets"}

// ScanOptions configures a filesystem scan.
type ScanOptions struct {
	Target       string
	Mode         ScanMode
	ExtraPlugins []string
	WithOSVMatch bool
	MaxFileSize  int
}

func pluginNamesForMode(mode ScanMode) []string {
	switch mode {
	case ModeSCA:
		return scaPlugins
	case ModeSecrets:
		return secretPlugins
	case ModeFull:
		return append(append([]string{}, scaPlugins...), secretPlugins...)
	default:
		return scaPlugins
	}
}

// Scan runs SCALIBR against the given filesystem target.
func Scan(ctx context.Context, opts ScanOptions) (*Result, error) {
	names := pluginNamesForMode(opts.Mode)
	if len(opts.ExtraPlugins) > 0 {
		names = append(names, opts.ExtraPlugins...)
	}

	// If OSV matching is requested, add the vulnmatch enricher.
	if opts.WithOSVMatch {
		names = append(names, "vulnmatch")
	}

	plugins, err := pl.FromNames(names, nil)
	if err != nil {
		return nil, fmt.Errorf("loading plugins %v: %w", names, err)
	}

	target := opts.Target
	if target == "" {
		target = "."
	}
	if !strings.HasPrefix(target, "/") {
		// Resolve relative paths — SCALIBR needs absolute paths for scan roots.
		// We accept relative paths for UX convenience.
	}

	cfg := &scalibr.ScanConfig{
		ScanRoots:  scalibrfs.RealFSScanRoots(target),
		Plugins:    plugins,
		MaxFileSize: opts.MaxFileSize,
	}

	sr := scalibr.New().Scan(ctx, cfg)
	return &Result{ScanResult: sr}, nil
}
