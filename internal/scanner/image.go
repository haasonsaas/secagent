package scanner

import (
	"context"
	"fmt"
	"strings"

	scalibr "github.com/google/osv-scalibr"
	lsimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	pl "github.com/google/osv-scalibr/plugin/list"
)

// ImageScanOptions configures a container image scan.
type ImageScanOptions struct {
	ImageRef     string
	ExtraPlugins []string
	WithOSVMatch bool
}

// ScanImage scans a container image for packages and vulnerabilities.
// The caller must call result.Image.CleanUp() when done.
func ScanImage(ctx context.Context, opts ImageScanOptions) (*ImageResult, error) {
	img, err := loadImage(opts.ImageRef)
	if err != nil {
		return nil, fmt.Errorf("loading image %q: %w", opts.ImageRef, err)
	}

	names := append([]string{}, scaPlugins...)
	if len(opts.ExtraPlugins) > 0 {
		names = append(names, opts.ExtraPlugins...)
	}
	if opts.WithOSVMatch {
		names = append(names, "vulnmatch")
	}

	plugins, err := pl.FromNames(names, nil)
	if err != nil {
		img.CleanUp()
		return nil, fmt.Errorf("loading plugins: %w", err)
	}

	cfg := &scalibr.ScanConfig{
		Plugins: plugins,
	}

	sr, err := scalibr.New().ScanContainer(ctx, img, cfg)
	if err != nil {
		img.CleanUp()
		return nil, fmt.Errorf("scanning container: %w", err)
	}

	return &ImageResult{
		Result: Result{ScanResult: sr},
		Image:  img,
	}, nil
}

// loadImage determines the image source format and loads it.
func loadImage(ref string) (*lsimage.Image, error) {
	config := lsimage.DefaultConfig()

	switch {
	case strings.HasSuffix(ref, ".tar") || strings.HasSuffix(ref, ".tar.gz"):
		return lsimage.FromTarball(ref, config)
	case strings.Contains(ref, "/") || strings.Contains(ref, "."):
		// Looks like a remote registry reference (e.g. alpine:latest, gcr.io/foo/bar)
		return lsimage.FromRemoteName(ref, config)
	default:
		// Try local Docker daemon first, fall back to remote.
		img, err := lsimage.FromLocalDockerImage(ref, config)
		if err != nil {
			return lsimage.FromRemoteName(ref, config)
		}
		return img, nil
	}
}
