package storage

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type gateDriver struct {
	Driver
	started chan string
	release chan struct{}
}

func (d *gateDriver) Read(ctx context.Context, i Instance, _ Locator, _ io.Writer) (int64, error) {
	d.started <- i.AccountDomain
	select {
	case <-d.release:
		return 0, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

type gateResolver struct{ driver Driver }

func (r gateResolver) Resolve(context.Context, Instance) (Driver, error) { return r.driver, nil }
func TestAccountConcurrencyDoesNotBlockOtherAccounts(t *testing.T) {
	gate := &gateDriver{started: make(chan string, 3), release: make(chan struct{})}
	r := &limitedResolver{inner: gateResolver{gate}, parallel: 1, global: newPacer(1024), accountRate: 1024, accounts: map[string]*accountLimit{}}
	a := Instance{AccountDomain: "a"}
	b := Instance{AccountDomain: "b"}
	first, _ := r.Resolve(context.Background(), a)
	second, _ := r.Resolve(context.Background(), a)
	other, _ := r.Resolve(context.Background(), b)
	done := make(chan error, 3)
	go func() { _, err := first.Read(context.Background(), a, Locator{}, io.Discard); done <- err }()
	select {
	case id := <-gate.started:
		if id != "a" {
			t.Fatal(id)
		}
	case <-time.After(time.Second):
		t.Fatal("first account blocked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, err := second.Read(ctx, a, Locator{}, io.Discard); done <- err }()
	go func() { _, err := other.Read(context.Background(), b, Locator{}, io.Discard); done <- err }()
	select {
	case id := <-gate.started:
		if id != "b" {
			t.Fatal("single-account limit exceeded")
		}
	case <-time.After(time.Second):
		t.Fatal("other account blocked")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued account did not cancel: %v", err)
	}
	close(gate.release)
	for n := 0; n < 2; n++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
