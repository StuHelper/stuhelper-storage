package bhpan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	storage "github.com/StuHelper/stuhelper-storage"
)

const rootPrefix = "【严禁自行删除！StuHelper贡献空间 严禁自行删除！】"

// NewRootName creates a warning label independent of the contribution quota.
func NewRootName() (string, error) {
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", storage.ErrUnavailable
	}
	return rootPrefix + hex.EncodeToString(nonce[:]), nil
}

// IsManagedRootName validates the whole persisted provisioning intent.
func IsManagedRootName(name string) bool {
	suffix, ok := strings.CutPrefix(name, rootPrefix)
	if !ok || len(suffix) != 8 {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil && suffix == strings.ToLower(suffix)
}

// CheckRootAvailable examines the library before a new root is issued. A
// matching warning label is a conflict and never sufficient proof of ownership.
func CheckRootAvailable(ctx context.Context, client Client, library string) error {
	listing, err := client.List(ctx, library)
	if err != nil {
		return storage.ErrUnavailable
	}
	for _, entry := range listing.Directories {
		if IsManagedRootName(entry.Name) {
			return storage.ErrConflict
		}
	}
	return nil
}
