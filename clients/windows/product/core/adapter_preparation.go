package main

// The join is idempotent and must finish before the caller's ownership cleanup,
// including when another independent startup stage fails before it needs READY.
func beginAdapterPreparation(prepare func() error) func() error {
	done := make(chan struct{})
	var result error
	go func() { defer close(done); result = prepare() }()
	return func() error { <-done; return result }
}
