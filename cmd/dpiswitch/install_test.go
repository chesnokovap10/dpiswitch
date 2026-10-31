package main

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSetupArgs(t *testing.T) {
	args := setupArgs("reinstall", "S-1-5-21-1-2-3-1001")
	for _, part := range []string{"reinstall --owner S-1-5-21-1-2-3-1001", "--quiet", fmt.Sprintf("--keep %d", windows.GetCurrentProcessId())} {
		if !strings.Contains(args, part) {
			t.Fatalf("missing %s: %s", part, args)
		}
	}
}
