//go:build amd64 && gc && !purego

package siv

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"testing"
)

const failClosedChildEnv = "SIV_FAIL_CLOSED_CHILD"

// TestFailClosedGODEBUG re-runs the test binary with AES-NI or
// PCLMULQDQ hidden through GODEBUG and checks that NewGCM fails
// closed in the child process.
func TestFailClosedGODEBUG(t *testing.T) {
	if os.Getenv(failClosedChildEnv) != "" {
		t.Skip("running as child")
	}
	if !haveAsm {
		t.Skip("CPU lacks AES-NI or PCLMULQDQ")
	}
	for _, feature := range []string{"aes", "pclmulqdq"} {
		t.Run(feature, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestFailClosedChild$", "-test.v")
			cmd.Env = append(os.Environ(),
				failClosedChildEnv+"=1",
				"GODEBUG=cpu."+feature+"=off",
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child failed: %v\n%s", err, out)
			}
			if !bytes.Contains(out, []byte("--- PASS: TestFailClosedChild")) {
				t.Fatalf("child did not run:\n%s", out)
			}
		})
	}
}

// TestFailClosedChild is the child half of TestFailClosedGODEBUG.
func TestFailClosedChild(t *testing.T) {
	if os.Getenv(failClosedChildEnv) == "" {
		t.Skip("only runs as a child of TestFailClosedGODEBUG")
	}
	if haveAsm {
		t.Fatal("GODEBUG did not hide the CPU feature")
	}
	for _, n := range []int{16, 32} {
		if _, err := NewGCM(make([]byte, n)); !errors.Is(err, ErrUnsupportedCPU) {
			t.Fatalf("%d: expected %v, got %v", n, ErrUnsupportedCPU, err)
		}
	}
}
