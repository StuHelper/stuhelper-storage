package storage

import (
	"context"
	"io"
	"sync"
	"time"
)

// pacer permits a bounded chunk then spaces subsequent chunks. The aggregate
// limiter is shared by all accounts in this execution process.
type pacer struct {
	mu   sync.Mutex
	rate int64
	next time.Time
}

func newPacer(rate int64) *pacer { return &pacer{rate: rate} }
func (p *pacer) wait(ctx context.Context, n int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil {
		return nil
	}
	p.mu.Lock()
	now := time.Now()
	start := p.next
	if start.Before(now) {
		start = now
	}
	p.next = start.Add(time.Duration(float64(n) / float64(p.rate) * float64(time.Second)))
	p.mu.Unlock()
	if delay := time.Until(start); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

type accountLimit struct {
	slots chan struct{}
	pacer *pacer
}
type limitedResolver struct {
	inner       Resolver
	mu          sync.Mutex
	accounts    map[string]*accountLimit
	parallel    int
	global      *pacer
	accountRate int64
}

func (r *limitedResolver) Resolve(ctx context.Context, i Instance) (Driver, error) {
	d, err := r.inner.Resolve(ctx, i)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.accounts[i.AccountDomain]
	if a == nil {
		if len(r.accounts) >= 100 {
			return nil, ErrCapacity
		}
		a = &accountLimit{slots: make(chan struct{}, r.parallel), pacer: newPacer(r.accountRate)}
		r.accounts[i.AccountDomain] = a
	}
	return &limitedDriver{inner: d, account: a, global: r.global}, nil
}

type limitedDriver struct {
	inner   Driver
	account *accountLimit
	global  *pacer
}

func (d *limitedDriver) slot(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case d.account.slots <- struct{}{}:
		return func() { <-d.account.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (d *limitedDriver) Find(ctx context.Context, i Instance, intent string, l Locator) (Locator, error) {
	release, err := d.slot(ctx)
	if err != nil {
		return Locator{}, err
	}
	defer release()
	return d.inner.Find(ctx, i, intent, l)
}
func (d *limitedDriver) Remove(ctx context.Context, i Instance, l Locator) error {
	release, err := d.slot(ctx)
	if err != nil {
		return err
	}
	defer release()
	return d.inner.Remove(ctx, i, l)
}
func (d *limitedDriver) Write(ctx context.Context, i Instance, intent string, size int64, src io.Reader, checkpoint func(Locator) error) (Locator, error) {
	release, err := d.slot(ctx)
	if err != nil {
		return Locator{}, err
	}
	defer release()
	return d.inner.Write(ctx, i, intent, size, &pacedReader{ctx: ctx, src: src, global: d.global, account: d.account.pacer}, checkpoint)
}
func (d *limitedDriver) Read(ctx context.Context, i Instance, l Locator, dst io.Writer) (int64, error) {
	release, err := d.slot(ctx)
	if err != nil {
		return 0, err
	}
	defer release()
	return d.inner.Read(ctx, i, l, &pacedWriter{ctx: ctx, dst: dst, global: d.global, account: d.account.pacer})
}

type pacedReader struct {
	ctx             context.Context
	src             io.Reader
	global, account *pacer
}

func (p *pacedReader) Read(b []byte) (int, error) {
	if err := p.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := p.src.Read(b[:min(len(b), 32<<10)])
	if n > 0 {
		if e := p.global.wait(p.ctx, n); e != nil {
			return 0, e
		}
		if e := p.account.wait(p.ctx, n); e != nil {
			return 0, e
		}
	}
	return n, err
}

type pacedWriter struct {
	ctx             context.Context
	dst             io.Writer
	global, account *pacer
}

func (p *pacedWriter) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n := min(len(b), 32<<10)
		if err := p.global.wait(p.ctx, n); err != nil {
			return total, err
		}
		if err := p.account.wait(p.ctx, n); err != nil {
			return total, err
		}
		written, err := p.dst.Write(b[:n])
		total += written
		b = b[written:]
		if err != nil {
			return total, err
		}
		if written != n {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
