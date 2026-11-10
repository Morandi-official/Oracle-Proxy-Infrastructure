package main

import (
	"errors"
	"testing"
	"time"
)

func TestAdapterPreparationOverlapsAndJoinsEveryExit(t *testing.T) {
	for _, failure := range []error{nil, errors.New("creation failed")} {
		entered, release, cleaned := make(chan struct{}), make(chan struct{}), make(chan bool, 1)
		go func() {
			created := false
			defer func() { cleaned <- created }()
			join := beginAdapterPreparation(func() error { close(entered); <-release; created = true; return failure })
			defer join()
			// An unrelated startup failure returns before the preparation completes.
			// Its deferred join MUST finish before ownership cleanup is allowed.
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("not started")
		}
		select {
		case <-cleaned:
			t.Fatal("cleanup raced late creation")
		default:
		}
		close(release)
		select {
		case ready := <-cleaned:
			if !ready {
				t.Fatal("creation not joined")
			}
		case <-time.After(time.Second):
			t.Fatal("join did not finish")
		}
		joined := beginAdapterPreparation(func() error { return failure })
		if joined() != failure || joined() != failure {
			t.Fatal("join lost result")
		}
	}
}
