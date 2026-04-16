package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGeneratedFuzzerResultJSONSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "generated_fuzzer.cc")
	binaryPath := filepath.Join(tmpDir, "generated_fuzzer")

	require.NoError(t, os.WriteFile(srcPath, []byte("int main() { return 0; }"), 0o644))
	require.NoError(t, os.WriteFile(binaryPath, []byte("bin"), 0o755))

	payload, err := json.Marshal(generatedFuzzerPayload{
		Status:     "success",
		SourcePath: srcPath,
		BinaryPath: binaryPath,
	})
	require.NoError(t, err)

	output := "generator log\nGEN_FUZZER_JSON:" + string(payload) + "\n"
	gotSrc, gotBinary, parseErr := parseGeneratedFuzzerResult(output)
	require.NoError(t, parseErr)
	assert.Equal(t, srcPath, gotSrc)
	assert.Equal(t, binaryPath, gotBinary)
}

func TestParseGeneratedFuzzerResultJSONError(t *testing.T) {
	payload, err := json.Marshal(generatedFuzzerPayload{
		Status:      "error",
		Reason:      "no_existing_fuzzers",
		Message:     "No existing fuzzers found",
		Diagnostics: "checked main_repo and oss-fuzz",
	})
	require.NoError(t, err)

	output := "GEN_FUZZER_JSON:" + string(payload)
	_, _, parseErr := parseGeneratedFuzzerResult(output)
	require.Error(t, parseErr)
	assert.ErrorContains(t, parseErr, "no_existing_fuzzers")
	assert.ErrorContains(t, parseErr, "No existing fuzzers found")
}

func TestParseGeneratedFuzzerResultLegacyFallback(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "legacy_fuzzer.cc")
	binaryPath := filepath.Join(tmpDir, "legacy_fuzzer")

	require.NoError(t, os.WriteFile(srcPath, []byte("int main() { return 0; }"), 0o644))
	require.NoError(t, os.WriteFile(binaryPath, []byte("bin"), 0o755))

	output := "some log\n" + srcPath + "\n" + binaryPath + "\n"
	gotSrc, gotBinary, parseErr := parseGeneratedFuzzerResult(output)
	require.NoError(t, parseErr)
	assert.Equal(t, srcPath, gotSrc)
	assert.Equal(t, binaryPath, gotBinary)
}

func TestBaseServiceSetters(t *testing.T) {
	b := &baseService{workDir: "/tmp/work"}

	b.SetSubmissionEndpoint("http://submit")
	b.SetAnalysisServiceUrl("http://analysis")

	assert.Equal(t, "/tmp/work", b.GetWorkDir())
	assert.Equal(t, "http://submit", b.submissionEndpoint)
	assert.Equal(t, "http://analysis", b.analysisServiceUrl)
}

func TestInitializeWorkDirUsesEnv(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	dir := initializeWorkDir()
	assert.Equal(t, os.Getenv("CRS_WORKDIR"), dir)
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestInitializeWorkDirFallback(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "not_a_dir")
	require.NoError(t, os.WriteFile(tempFile, []byte("x"), 0o644))

	t.Setenv("CRS_WORKDIR", tempFile)

	dir := initializeWorkDir()
	assert.NotEqual(t, tempFile, dir)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestShouldUseSubmissionService(t *testing.T) {
	t.Setenv("CRS_DISABLE_SUBMISSION_SERVICE", "true")
	assert.False(t, shouldUseSubmissionService("http://submission"))

	t.Setenv("CRS_DISABLE_SUBMISSION_SERVICE", "false")
	assert.True(t, shouldUseSubmissionService("http://submission"))
	assert.False(t, shouldUseSubmissionService(""))
}

func TestGetAverageCPUUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CPU usage test in short mode (takes 2s)")
	}
	value, err := getAverageCPUUsage()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, value, 0.0)
	assert.LessOrEqual(t, value, 100.0)
}
