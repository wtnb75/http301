package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func runcmd_test(t *testing.T, args []string, rval int) (string, string) {
	t.Helper()
	oldargs := os.Args
	oldstdout := os.Stdout
	oldstderr := os.Stderr
	oldglobalopts := globalOption
	defer func() {
		os.Args = oldargs
		os.Stdout = oldstdout
		os.Stderr = oldstderr
		globalOption = oldglobalopts
	}()
	stdio_r, stdio_w, err := os.Pipe()
	if err != nil {
		t.Error("pipe")
		return "", ""
	}
	stderr_r, stderr_w, err := os.Pipe()
	if err != nil {
		t.Error("pipe")
		return "", ""
	}
	os.Stdout = stdio_w
	os.Stderr = stderr_w
	os.Args = args
	res := realMain()
	if res != rval {
		t.Error("return value", "expected", rval, "actual", res)
	}
	if err = stdio_w.Close(); err != nil {
		t.Error("write close(stdout)")
	}
	if err = stderr_w.Close(); err != nil {
		t.Error("write close(stderr)")
	}
	stdout_output, err := io.ReadAll(stdio_r)
	if err != nil {
		t.Error("read(stdout)")
	}
	stderr_output, err := io.ReadAll(stderr_r)
	if err != nil {
		t.Error("read(stderr)")
	}
	return string(stdout_output), string(stderr_output)
}

func TestVersionCommand(t *testing.T) {
	stdout, _ := runcmd_test(t, []string{"http301", "version"}, 0)
	if !strings.Contains(stdout, "http301") {
		t.Error("missing command name")
	}
	if !strings.Contains(stdout, version) {
		t.Error("missing version", stdout)
	}
}

func TestVersionCommandFull(t *testing.T) {
	stdout, _ := runcmd_test(t, []string{"http301", "version", "--full-version"}, 0)
	if !strings.Contains(stdout, "hash") {
		t.Error("missing hash", stdout)
	}
	if !strings.Contains(stdout, commit) {
		t.Error("missing commit", stdout)
	}
	if !strings.Contains(stdout, date) {
		t.Error("missing date", stdout)
	}
}
