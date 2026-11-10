package storage

import "context"

// begin admits a bounded operation without an unbounded in-memory wait queue.
func (s *Service) begin(ctx context.Context) (context.Context, func(), error) {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.stopping || ctx.Err() != nil {
		return nil, nil, ErrUnavailable
	}
	select {
	case s.slots <- struct{}{}:
	default:
		return nil, nil, ErrCapacity
	}
	s.active++
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.stopCtx, cancel)
	return work, func() {
		stop()
		cancel()
		s.lifecycle.Lock()
		defer s.lifecycle.Unlock()
		<-s.slots
		s.active--
		if s.stopping && s.active == 0 {
			s.closeErr = s.staging.close()
			close(s.closed)
		}
	}, nil
}

// Close rejects new transfers, cancels active I/O and waits for cleanup. The
// directory stays locked until the last operation actually exits, even on timeout.
func (s *Service) Close(ctx context.Context) error {
	s.lifecycle.Lock()
	if !s.stopping {
		s.stopping = true
		s.cancel()
		if s.active == 0 {
			s.closeErr = s.staging.close()
			close(s.closed)
		}
	}
	s.lifecycle.Unlock()
	select {
	case <-s.closed:
		s.lifecycle.Lock()
		defer s.lifecycle.Unlock()
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
