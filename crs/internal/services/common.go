package services

import (
	"bufio"
	"encoding/json"
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
	"gopkg.in/yaml.v3"
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
		endpoint = "http://localhost:4141"
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
	workerTaskMutex     sync.RWMutex
	activeWorkerTasks   = make(map[string]bool)
	taskDirCloningLocks = make(map[string]*sync.Mutex)
	taskDirLocksMu      sync.Mutex
)

type unharnessedProjectConfig struct {
	MainRepo string `yaml:"main_repo"`
}

type generatedFuzzerPayload struct {
	Status          string `json:"status"`
	SourcePath      string `json:"source_path"`
	BinaryPath      string `json:"binary_path"`
	BuildScriptPath string `json:"build_script_path,omitempty"`
	Model           string `json:"model,omitempty"`
	Reason          string `json:"reason,omitempty"`
	Message         string `json:"message,omitempty"`
	Diagnostics     string `json:"diagnostics,omitempty"`
	LogFile         string `json:"log_file,omitempty"`
}

func isDeltaTask(taskDetail models.TaskDetail) bool {
	return taskDetail.Type == models.TaskTypeDelta
}

func ensureDeltaDiffReady(taskDir string) error {
	diffPath := filepath.Join(taskDir, "diff", "ref.diff")
	stat, err := os.Stat(diffPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("delta unharnessed generation requires %s", diffPath)
		}
		return fmt.Errorf("failed to stat %s: %w", diffPath, err)
	}
	if stat.IsDir() {
		return fmt.Errorf("expected diff file but found directory: %s", diffPath)
	}
	if stat.Size() == 0 {
		return fmt.Errorf("delta diff file is empty: %s", diffPath)
	}
	return nil
}

func getCloningLockForTaskDir(taskDir string) *sync.Mutex {
	taskDirLocksMu.Lock()
	defer taskDirLocksMu.Unlock()

	lock, exists := taskDirCloningLocks[taskDir]
	if !exists {
		lock = &sync.Mutex{}
		taskDirCloningLocks[taskDir] = lock
	}
	return lock
}

func runCommandAndStreamOutput(cmd *exec.Cmd, commandDesc string) error {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe for %s: %w", commandDesc, err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe for %s: %w", commandDesc, err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %w", commandDesc, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			log.Printf("[%s stdout] %s", commandDesc, scanner.Text())
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[%s stderr] %s", commandDesc, scanner.Text())
		}
	}()

	err = cmd.Wait()
	wg.Wait()
	if err != nil {
		return fmt.Errorf("%s failed: %w", commandDesc, err)
	}
	return nil
}

func commandOutputTail(out string, maxLines int) string {
	if maxLines <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-maxLines:], "\n")
}

func resolveGenerateFuzzerScriptPath(taskDir string) (string, error) {
	candidates := []string{}
	if strategyBaseDir := os.Getenv("STRATEGY_BASE_DIR"); strategyBaseDir != "" {
		candidates = append(candidates, filepath.Join(strategyBaseDir, "jeff", "generate_fuzzer.py"))
	}

	candidates = append(candidates,
		filepath.Join(".", "strategy", "jeff", "generate_fuzzer.py"),
		filepath.Join(taskDir, "strategy", "jeff", "generate_fuzzer.py"),
		filepath.Join("/app", "strategy", "jeff", "generate_fuzzer.py"),
	)

	for _, candidate := range candidates {
		if stat, err := os.Stat(candidate); err == nil && !stat.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("could not locate generate_fuzzer.py; checked: %s", strings.Join(candidates, ", "))
}

func pickPythonInterpreter() string {
	if stat, err := os.Stat("/tmp/crs_venv/bin/python3"); err == nil && !stat.IsDir() {
		return "/tmp/crs_venv/bin/python3"
	}
	return "python3"
}

func parseGeneratedFuzzerResult(output string) (string, string, error) {
	const payloadPrefix = "GEN_FUZZER_JSON:"

	var payload *generatedFuzzerPayload
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || !strings.HasPrefix(line, payloadPrefix) {
			continue
		}

		candidate := &generatedFuzzerPayload{}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, payloadPrefix)), candidate); err != nil {
			continue
		}
		payload = candidate
	}

	if payload != nil {
		if strings.EqualFold(payload.Status, "success") {
			srcPath := strings.TrimSpace(payload.SourcePath)
			binaryPath := strings.TrimSpace(payload.BinaryPath)
			if srcPath == "" || binaryPath == "" {
				return "", "", fmt.Errorf("generator returned success payload without source/binary paths")
			}
			if srcPath == binaryPath {
				return "", "", fmt.Errorf("generator returned identical source and binary path: %s", srcPath)
			}

			srcStat, srcErr := os.Stat(srcPath)
			binStat, binErr := os.Stat(binaryPath)
			if srcErr != nil || srcStat.IsDir() {
				return "", "", fmt.Errorf("generated source path invalid: %s", srcPath)
			}
			if binErr != nil || binStat.IsDir() {
				return "", "", fmt.Errorf("generated binary path invalid: %s", binaryPath)
			}
			return srcPath, binaryPath, nil
		}

		reason := strings.TrimSpace(payload.Reason)
		message := strings.TrimSpace(payload.Message)
		diagnostics := strings.TrimSpace(payload.Diagnostics)
		if reason == "" {
			reason = "unknown"
		}
		if message == "" {
			message = "generator reported an error"
		}
		if diagnostics != "" {
			return "", "", fmt.Errorf("generator failed (%s): %s | %s", reason, message, diagnostics)
		}
		return "", "", fmt.Errorf("generator failed (%s): %s", reason, message)
	}

	return parseGeneratedFuzzerPathsLegacy(output)
}

func parseGeneratedFuzzerPathsLegacy(output string) (string, string, error) {
	lines := strings.Split(output, "\n")
	paths := make([]string, 0, 4)
	seen := map[string]struct{}{}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || !filepath.IsAbs(line) {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		if stat, err := os.Stat(line); err == nil && !stat.IsDir() {
			seen[line] = struct{}{}
			paths = append(paths, line)
		}
	}

	if len(paths) < 2 {
		return "", "", fmt.Errorf("failed to parse generated fuzzer paths from output")
	}

	srcPath := paths[len(paths)-2]
	binaryPath := paths[len(paths)-1]
	if srcPath == binaryPath {
		return "", "", fmt.Errorf("generator returned identical source and binary path: %s", srcPath)
	}

	return srcPath, binaryPath, nil
}

// ============================================================================
// Unharnessed Task Functions (temporary stubs - need full migration)
// ============================================================================

// cloneOssFuzzAndMainRepoOnce - TODO: migrate full implementation from deleted crs_services.go
func cloneOssFuzzAndMainRepoOnce(taskDir, projectName, sanitizerDir string) error {
	cloningLock := getCloningLockForTaskDir(taskDir)
	cloningLock.Lock()
	defer cloningLock.Unlock()

	if err := os.MkdirAll(sanitizerDir, 0o755); err != nil {
		return fmt.Errorf("failed to create sanitizer directory %s: %w", sanitizerDir, err)
	}

	ossFuzzDir := filepath.Join(taskDir, "oss-fuzz")
	mainRepoDir := filepath.Join(taskDir, "main_repo")

	if _, err := os.Stat(ossFuzzDir); os.IsNotExist(err) {
		log.Printf("Cloning OSS-Fuzz for unharnessed generation into %s", ossFuzzDir)
		cmd := exec.Command("git", "clone", "--depth", "1", "https://github.com/google/oss-fuzz", ossFuzzDir)
		if err := runCommandAndStreamOutput(cmd, "git-clone-oss-fuzz"); err != nil {
			return fmt.Errorf("failed to clone OSS-Fuzz: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat OSS-Fuzz directory %s: %w", ossFuzzDir, err)
	}

	projectYAMLPath := filepath.Join(ossFuzzDir, "projects", projectName, "project.yaml")
	var cfg unharnessedProjectConfig
	var mainRepoURL string

	const maxYAMLAttempts = 3
	const yamlAttemptDelay = 5 * time.Second

	for attempt := 1; attempt <= maxYAMLAttempts; attempt++ {
		if _, err := os.Stat(projectYAMLPath); err == nil {
			data, readErr := os.ReadFile(projectYAMLPath)
			if readErr != nil {
				return fmt.Errorf("failed to read %s on attempt %d: %w", projectYAMLPath, attempt, readErr)
			}
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return fmt.Errorf("failed to parse %s on attempt %d: %w", projectYAMLPath, attempt, err)
			}
			mainRepoURL = strings.TrimSpace(cfg.MainRepo)
			if mainRepoURL == "" {
				return fmt.Errorf("main_repo is empty in %s", projectYAMLPath)
			}
			break
		}

		if attempt == maxYAMLAttempts {
			return fmt.Errorf("failed to find %s after %d attempts", projectYAMLPath, maxYAMLAttempts)
		}

		log.Printf("Waiting for %s (attempt %d/%d)", projectYAMLPath, attempt, maxYAMLAttempts)
		time.Sleep(yamlAttemptDelay)
	}

	if mainRepoURL == "" {
		return fmt.Errorf("could not determine main_repo URL from %s", projectYAMLPath)
	}

	if stat, err := os.Stat(mainRepoDir); err == nil && stat.IsDir() {
		entries, readErr := os.ReadDir(mainRepoDir)
		if readErr == nil && len(entries) > 0 {
			log.Printf("Reusing existing main repository at %s", mainRepoDir)
			return nil
		}
		_ = os.RemoveAll(mainRepoDir)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat main repository directory %s: %w", mainRepoDir, err)
	}

	log.Printf("Cloning main repository for unharnessed generation from %s", mainRepoURL)
	cmd := exec.Command("git", "clone", "--depth", "1", mainRepoURL, mainRepoDir)
	if err := runCommandAndStreamOutput(cmd, "git-clone-main-repo"); err != nil {
		return fmt.Errorf("failed to clone main repository: %w", err)
	}

	return nil
}

// generateFuzzerForUnharnessedTask - TODO: migrate full implementation from deleted crs_services.go
func generateFuzzerForUnharnessedTask(taskDir, focus, sanitizerDir, projectName, sanitizer string) (string, string, error) {
	if err := ensureDeltaDiffReady(taskDir); err != nil {
		return "", "", err
	}

	scriptPath, err := resolveGenerateFuzzerScriptPath(taskDir)
	if err != nil {
		return "", "", err
	}

	pythonInterpreter := pickPythonInterpreter()
	cmd := exec.Command(
		pythonInterpreter,
		scriptPath,
		"--task_dir", taskDir,
		"--focus", focus,
		"--sanitizer_dir", sanitizerDir,
		"--project_name", projectName,
		"--sanitizer", sanitizer,
		"--output-format", "json",
		"--source-mode", "diff",
		"--diff-path", filepath.Join(taskDir, "diff", "ref.diff"),
	)
	cmd.Dir = taskDir
	cmd.Env = os.Environ()

	log.Printf(
		"Running unharnessed fuzzer generator: %s --task_dir %s --focus %s --sanitizer_dir %s --project_name %s --sanitizer %s",
		pythonInterpreter,
		taskDir,
		focus,
		sanitizerDir,
		projectName,
		sanitizer,
	)

	outBytes, err := cmd.CombinedOutput()
	out := string(outBytes)
	if err != nil {
		return "", "", fmt.Errorf(
			"generate_fuzzer.py failed: %w\nOutput tail:\n%s",
			err,
			commandOutputTail(out, 30),
		)
	}

	newFuzzerSrcPath, newFuzzerBinaryPath, parseErr := parseGeneratedFuzzerResult(out)
	if parseErr != nil {
		return "", "", fmt.Errorf(
			"failed to parse generated fuzzer paths: %w\nOutput tail:\n%s",
			parseErr,
			commandOutputTail(out, 30),
		)
	}

	log.Printf("Generated unharnessed fuzzer source: %s", newFuzzerSrcPath)
	log.Printf("Generated unharnessed fuzzer binary: %s", newFuzzerBinaryPath)

	return newFuzzerSrcPath, newFuzzerBinaryPath, nil
}
