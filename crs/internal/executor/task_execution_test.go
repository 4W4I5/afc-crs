package executor

import (
	"errors"
	"testing"
)

func TestExecuteFuzzingTaskReturnsErrNoFuzzersInLocalTestMode(t *testing.T) {
	t.Setenv("LOCAL_TEST", "1")

	err := ExecuteFuzzingTask(TaskExecutionParams{
		AllFuzzers: []string{},
	})
	if !errors.Is(err, ErrNoFuzzers) {
		t.Fatalf("expected ErrNoFuzzers, got %v", err)
	}
}

func TestExecuteFuzzingTaskReturnsErrNoFuzzersInNormalMode(t *testing.T) {
	t.Setenv("LOCAL_TEST", "")

	err := ExecuteFuzzingTask(TaskExecutionParams{
		Fuzzer:     "",
		AllFuzzers: []string{},
	})
	if !errors.Is(err, ErrNoFuzzers) {
		t.Fatalf("expected ErrNoFuzzers, got %v", err)
	}
}
