package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"crs/internal/competition"
	"crs/internal/models"
	"crs/internal/utils/helpers"
	"github.com/shirou/gopsutil/v3/cpu"
)

// Common errors
var (
	errNotSupportedInLocalMode  = errors.New("operation not supported in local mode")
	errNotSupportedInWebMode    = errors.New("operation not supported in web mode")
	errNotSupportedInWorkerMode = errors.New("operation not supported in worker mode")
)

// baseService contains fields and methods shared by all service implementations
type baseService struct {
	workDir            string
	competitionClient  *competition.Client
	submissionEndpoint string
	analysisServiceUrl string
	model              string

	// POV metadata directories (used by Local and Worker services)
	povMetadataDir          string
	povMetadataDir0         string
	povAdvcancedMetadataDir string
	patchWorkDir            string
}

// GetWorkDir returns the working directory path
func (b *baseService) GetWorkDir() string {
	return b.workDir
}

// SetSubmissionEndpoint sets the submission endpoint URL
func (b *baseService) SetSubmissionEndpoint(endpoint string) {
	b.submissionEndpoint = endpoint
}

// SetAnalysisServiceUrl sets the analysis service URL
func (b *baseService) SetAnalysisServiceUrl(url string) {
	b.analysisServiceUrl = url
}

// initializeWorkDir initializes and returns the working directory
func initializeWorkDir() string {
	workDir := "/crs-workdir"

	if envWorkDir := os.Getenv("CRS_WORKDIR"); envWorkDir != "" {
		workDir = envWorkDir
	}

	if err := helpers.EnsureWorkDir(workDir); err != nil {
		log.Printf("Warning: Could not create work directory at %s: %v", workDir, err)

		homeDir, err := os.UserHomeDir()
		if err == nil {
			workDir = filepath.Join(homeDir, "crs-workdir")
			log.Printf("Trying fallback work directory: %s", workDir)

			if err := helpers.EnsureWorkDir(workDir); err != nil {
				log.Printf("Warning: Could not create fallback work directory: %v", err)
				tempDir, err := os.MkdirTemp("", "crs-workdir-")
				if err == nil {
					workDir = tempDir
					log.Printf("Using temporary directory as work directory: %s", workDir)
				} else {
					workDir = "."
					log.Printf("Warning: Using current directory as work directory")
				}
			}
		} else {
			workDir = "."
			log.Printf("Warning: Using current directory as work directory")
		}
	}

	return workDir
}

// initializeCompetitionAPI initializes competition API credentials
func initializeCompetitionAPI() (endpoint, keyID, token string) {
	endpoint = os.Getenv("COMPETITION_API_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:7081"
	}

	keyID = os.Getenv("CRS_KEY_ID")
	token = os.Getenv("CRS_KEY_TOKEN")

	if keyID == "" || token == "" {
		log.Printf("Warning: CRS_KEY_ID or CRS_KEY_TOKEN not set")
	}

	return endpoint, keyID, token
}

// initializeCompetitionClient creates a new competition client
func initializeCompetitionClient(endpoint, keyID, token string) *competition.Client {
	return competition.NewClient(endpoint, keyID, token)
}

// ============================================================================
// Shared Types (migrated from crs_services.go)
// ============================================================================

// WorkerFuzzerPair represents a fuzzer assigned to a worker
type WorkerFuzzerPair struct {
	Worker int
	Fuzzer string
}

// WorkerStatus tracks the status of a worker node
type WorkerStatus struct {
	LastAssignedTime time.Time
	FailureCount     int
	BlacklistedUntil time.Time
	AssignedTasks    int
}

// ============================================================================
// System Utilities (migrated from crs_services.go)
// ============================================================================

// getAverageCPUUsage returns the average CPU usage percentage
func getAverageCPUUsage() (float64, error) {
	// cpu.Percent returns percent used per CPU, over the interval
	percents, err := cpu.Percent(2*time.Second, true)
	if err != nil {
		return 0, err
	}
	var sum float64
	for _, p := range percents {
		sum += p
	}
	return sum / float64(len(percents)), nil
}

// ============================================================================
// Service Interface (migrated from crs_services.go)
// ============================================================================

// CRSService defines the interface for CRS service operations
type CRSService interface {
	GetStatus() models.Status
	SubmitTask(task models.Task) error
	SubmitLocalTask(taskPath string) error
	SubmitWorkerTask(task models.WorkerTask) error
	CancelTask(taskID string) error
	CancelAllTasks() error
	SubmitSarif(sarifBroadcast models.SARIFBroadcast) error
	HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error
	SetWorkerIndex(index string)
	SetSubmissionEndpoint(endpoint string)
	SetAnalysisServiceUrl(url string)
	GetWorkDir() string
}

// ============================================================================
// Constants (migrated from crs_services.go)
// ============================================================================

const (
	UNHARNESSED = "UNHARNESSED"
)

// ============================================================================
// Package-level variables (migrated from crs_services.go)
// ============================================================================

var (
	workerTaskMutex   sync.RWMutex
	activeWorkerTasks = make(map[string]bool)
)

// ============================================================================
// Unharnessed Task Functions
// ============================================================================

func prepareUnharnessedTaskAssets(taskDir string) error {
	if taskDir == "" {
		return fmt.Errorf("task directory is empty")
	}
	if err := os.MkdirAll(taskDir, 0755); err != nil {
		return fmt.Errorf("failed to create task directory %s: %w", taskDir, err)
	}
	return nil
}

func resolveGenerateFuzzerScriptPath() (string, error) {
	baseDir := os.Getenv("STRATEGY_BASE_DIR")
	if baseDir == "" {
		baseDir = "/app/strategy"
	}

	strategyDir := os.Getenv("STRATEGY_NEW_DIR")
	if strategyDir == "" {
		strategyDir = "jeff"
	}

	candidates := []string{
		filepath.Join(baseDir, strategyDir, "generate_fuzzer.py"),
		filepath.Join(baseDir, "jeff", "generate_fuzzer.py"),
		"/app/strategy/jeff/generate_fuzzer.py",
	}

	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "strategy", "jeff", "generate_fuzzer.py"),
			filepath.Join(cwd, "crs", "strategy", "jeff", "generate_fuzzer.py"),
		)
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("generate_fuzzer.py not found; checked: %s", strings.Join(candidates, ", "))
}

func parseGenerateFuzzerOutput(stdout, stderr string) (string, string, error) {
	lines := strings.Split(stdout+"\n"+stderr, "\n")
	paths := make([]string, 0, 2)
	seen := make(map[string]struct{})

	for _, line := range lines {
		candidate := strings.TrimSpace(line)
		if candidate == "" || !filepath.IsAbs(candidate) {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			seen[candidate] = struct{}{}
			paths = append(paths, candidate)
		}
	}

	if len(paths) < 2 {
		return "", "", fmt.Errorf("unable to parse generated fuzzer paths from output")
	}

	newFuzzerSrcPath := ""
	newFuzzerPath := ""

	for _, p := range paths {
		ext := strings.ToLower(filepath.Ext(p))
		if newFuzzerSrcPath == "" && (ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx" || ext == ".java") {
			newFuzzerSrcPath = p
			continue
		}
		if newFuzzerPath == "" {
			newFuzzerPath = p
		}
	}

	if newFuzzerSrcPath == "" {
		newFuzzerSrcPath = paths[0]
	}
	if newFuzzerPath == "" || newFuzzerPath == newFuzzerSrcPath {
		for _, p := range paths {
			if p != newFuzzerSrcPath {
				newFuzzerPath = p
				break
			}
		}
	}

	if newFuzzerSrcPath == "" || newFuzzerPath == "" {
		return "", "", fmt.Errorf("missing generated fuzzer source/binary paths")
	}

	return newFuzzerSrcPath, newFuzzerPath, nil
}

func tailString(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[len(s)-limit:]
}

func generateHarnessForUnharnessedTask(taskDir, focus, sanitizerDir, projectName, sanitizer string) (string, string, error) {
	if err := prepareUnharnessedTaskAssets(taskDir); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(sanitizerDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create sanitizer directory %s: %w", sanitizerDir, err)
	}

	scriptPath, err := resolveGenerateFuzzerScriptPath()
	if err != nil {
		return "", "", err
	}

	pythonPath := "/tmp/crs_venv/bin/python3"
	if _, err := os.Stat(pythonPath); err != nil {
		pythonPath = "python3"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	args := []string{
		scriptPath,
		"--task_dir", taskDir,
		"--focus", focus,
		"--sanitizer_dir", sanitizerDir,
		"--project_name", projectName,
		"--sanitizer", sanitizer,
	}

	cmd := exec.CommandContext(ctx, pythonPath, args...)
	cmd.Dir = taskDir
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("Generating harness for unharnessed task via %s", scriptPath)
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", "", fmt.Errorf("generate_fuzzer.py timed out")
	}
	if err != nil {
		return "", "", fmt.Errorf("generate_fuzzer.py failed: %w (stderr tail: %s)", err, tailString(stderr.String(), 3000))
	}

	newFuzzerSrcPath, newFuzzerPath, parseErr := parseGenerateFuzzerOutput(stdout.String(), stderr.String())
	if parseErr != nil {
		return "", "", fmt.Errorf("failed to parse generated fuzzer output: %w (stdout tail: %s)", parseErr, tailString(stdout.String(), 3000))
	}

	log.Printf("Generated unharnessed fuzzer source: %s", newFuzzerSrcPath)
	log.Printf("Generated unharnessed fuzzer binary: %s", newFuzzerPath)
	return newFuzzerSrcPath, newFuzzerPath, nil
}
