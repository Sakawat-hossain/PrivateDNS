package portal

import (
	"io/fs"
)

// fsSub narrows the embedded filesystem to a subdirectory, so URLs do not
// carry the "static/" prefix twice.
func fsSub(f fs.FS, dir string) (fs.FS, error) {
	return fs.Sub(f, dir)
}
