package storage_test

import (
	"context"
	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
	"github.com/StuHelper/stuhelper-storage/drivers/bhpan"
	"regexp"
	"testing"
	"time"
)

type migrationClient struct {
	*statefulBHpanClient
	renames int
}

func (c *migrationClient) Rename(_ context.Context, id, name string) error {
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	c.renames++
	for other, existing := range c.acc.directories {
		if other != id && existing == name {
			return protocol.ErrConflict
		}
	}
	c.acc.directories[id] = name
	return nil
}

func TestLegacyContributionRootMigrationAndReceipt(t *testing.T) {
	h := harnessFor(t)
	pool := bhpan.NewPool()
	defer pool.Close()
	cfg := h.cfg
	cfg.TemporaryDirectory = t.TempDir()
	svc, err := storage.New(h.repo, h.auth, pool, pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close(h.ctx)
	acc := newStatefulBHpanAccount("migration", 0, 0)
	client := &migrationClient{statefulBHpanClient: &statefulBHpanClient{acc: acc}}
	i, err := pool.Provision(h.ctx, "migration", 1, client, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "【严禁自行删除！StuHelper贡献空间 严禁自行删除！】"
	if !regexp.MustCompile("^" + prefix + "[a-f0-9]{8}$").MatchString(acc.directories[i.Root]) {
		t.Fatal("wrong new root format")
	}
	i.ID, i.OwnerDomain, i.Ownership, i.State, i.Authorized = "migration", "owner", "contributor", "paused", true
	i, err = svc.Register(h.ctx, h.actor, "register", i)
	if err != nil {
		t.Fatal(err)
	}
	const old = "stuhelper-storage-1234567800112233445566778899aabb"
	const target = prefix + "12345678"
	acc.directories[i.Root] = old
	other := acc.libraryID + "/old-sibling"
	acc.directories[other] = target
	check := func(wantName, status string, calls int) {
		t.Helper()
		if err := svc.RefreshInstance(h.ctx, h.actor, i.ID); err != nil {
			t.Fatal("directory maintenance disrupted quota", err)
		}
		rows, err := svc.Instances(h.ctx, h.actor, 1, "")
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		row := rows[0]
		if row.Root != i.Root || row.RootNameReceipt.Status != status || row.RootNameReceipt.CheckedAt.IsZero() || acc.directories[i.Root] != wantName || client.renames != calls {
			t.Fatal("incorrect root or migration receipt", row.RootNameReceipt, calls, client.renames)
		}
	}
	check(old, "storage_conflict", 1)
	if acc.directories[other] != target {
		t.Fatal("modified a sibling")
	}
	acc.directories[other] = "personal"
	check(target, "confirmed", 2)
	check(target, "confirmed", 2)
	i.Ownership = "platform"
	acc.directories[i.Root] = old
	if err := pool.MigrateRootName(h.ctx, i); err != storage.ErrDenied || client.renames != 2 {
		t.Fatal("platform-owned root migrated", err)
	}
}
