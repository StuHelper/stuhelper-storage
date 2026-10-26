//go:build !linux

package storage

import "os"

// A target without a verified cross-process lock must not clean shared staging.
func lockStaging(*os.File) error { return ErrUnavailable }
