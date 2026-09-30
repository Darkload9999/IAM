// Package ui holds the built dashboard (npm run build writes ui/dist), so
// the Hub ships as one binary.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Files is the built dashboard: index.html at its root.
func Files() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
