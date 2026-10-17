package server

// The background half of the optional features (Settings -> Features): one
// goroutine, once a minute, and each feature reads its switch on every pass, so
// turning one off stops it at the next minute without a restart.
//
//	domain lists   a list whose interval has passed, synced
//
// ── ONE LIFETIME FOR EVERYTHING IT STARTS ───────────────────────────────────
//
// `ctx` is cancelled by Stop, and everything the features run in the
// background takes it: the pass in progress, a list's sync and a bulk job
// waiting for the write limit. A Server that is shut down leaves none of them
// running.

import (
	"context"
	"sync"
	"time"

	"mikrodash/internal/store"
)

type featureLoop struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex
	// listsRunning is the domain lists being synced now, by id.
	listsRunning map[int64]bool
}

func (s *Server) buildFeatureLoop() *featureLoop {
	ctx, cancel := context.WithCancel(context.Background())
	f := &featureLoop{ctx: ctx, cancel: cancel, listsRunning: map[int64]bool{}}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				s.featureTick(ctx, now)
			}
		}
	}()
	return f
}

// Stop ends the loop and everything it started.
func (f *featureLoop) Stop() { f.cancel() }

// featuresDone is closed when the server stops; nil, never closed, for a
// Server a test built without the loop.
func (s *Server) featuresDone() <-chan struct{} {
	if s.features == nil {
		return nil
	}
	return s.features.ctx.Done()
}

func (s *Server) featureTick(ctx context.Context, now time.Time) {
	if s.auditDB != nil && s.featureOn(store.FeatureDNSLists) {
		s.syncDueLists(ctx, now)
	}
}
