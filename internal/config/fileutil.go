package config

import (
	"os"

	"github.com/binn/ccproxy/internal/fileutil"
)

// atomicWriteFile delegates to the shared fileutil package.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	return fileutil.AtomicWriteFile(path, data, perm)
}
