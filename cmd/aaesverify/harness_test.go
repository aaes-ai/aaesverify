package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func captureRun(t *testing.T, args []string) (string, int) {
	t.Helper()
	return captureWith(t, args, run)
}

// captureWith runs entry with stdout and stderr captured together.
func captureWith(t *testing.T, args []string, entry func([]string) int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Drain concurrently: Windows pipe buffers are smaller than some results.
	type read struct {
		raw []byte
		err error
	}
	done := make(chan read, 1)
	go func() {
		raw, err := io.ReadAll(r)
		done <- read{raw, err}
	}()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	code := entry(args)
	_ = w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	got := <-done
	_ = r.Close()
	if got.err != nil {
		t.Fatal(got.err)
	}
	return string(got.raw), code
}

func moduleDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Dir(file)
}
