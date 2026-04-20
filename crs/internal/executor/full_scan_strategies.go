package executor

import (
	"context"
	"crs/internal/config"
	"crs/internal/models"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

// FullScanStrategyConfig holds configuration for full scan strategy execution
type FullScanStrategyConfig struct {
	Model              string
	POVMetadataDir     string
	SubmissionEndpoint string
	WorkerIndex        string
	AnalysisServiceUrl string
	StrategyConfig     *config.StrategyConfig
	Sanitizer          string
}

// runFullScanStrategy executes the full scan workflow
//
// Full Scan Workflow:
// 1. Call Analysis Service to get reachable functions
// 2. For each function, identify suspicious points using LLM
// 3. Store suspicious points in PostgreSQL database
// 4. Run Python strategy (as0_full.py) which reads from database
//
// This is different from delta scan which analyzes git diffs.
// Full scan analyzes the entire codebase to find vulnerabilities.
func runFullScanStrategy(fuzzer, taskDir, projectDir, fuzzDir, language string,
	taskDetail models.TaskDetail, task models.Task, fullScanConfig FullScanStrategyConfig) bool {

	log.Printf("========== FULL SCAN STRATEGY ==========")
	log.Printf("TaskID: %s", taskDetail.TaskID)
	log.Printf("TaskType: %s", taskDetail.Type)
	log.Printf("Project: %s", taskDetail.ProjectName)
	log.Printf("Focus: %s", taskDetail.Focus)
	log.Printf("Language: %s", language)
	log.Printf("Sanitizer: %s", fullScanConfig.Sanitizer)
	log.Printf("Fuzzer: %s", fuzzer)
	log.Printf("FuzzerName: %s", filepath.Base(fuzzer))
	log.Printf("Deadline: %d (timestamp: %s)", taskDetail.Deadline, time.Unix(taskDetail.Deadline/1000, 0).Format(time.RFC3339))
	log.Printf("Analysis Service URL: %s", fullScanConfig.AnalysisServiceUrl)
	log.Printf("Metadata: %v", taskDetail.Metadata)
	log.Printf("=========================================")

	return runFullScanStrategies(fuzzer, taskDir, projectDir, fuzzDir,
		language, taskDetail, task, fullScanConfig)
}

// runFullScanStrategies discovers and executes configured full-scan strategies.
func runFullScanStrategies(fuzzer, taskDir, projectDir, fuzzDir, language string,
	taskDetail models.TaskDetail, task models.Task, fullScanConfig FullScanStrategyConfig) bool {

	strategyConfig := fullScanConfig.StrategyConfig
	if strategyConfig == nil {
		log.Printf("StrategyConfig is nil, using defaults")
		strategyConfig = &config.StrategyConfig{
			BaseDir:        "/app/strategy",
			NewStrategyDir: "jeff",
			POV: config.POVStrategyConfig{
				AdvancedFullPattern: "as*_full.py",
			},
		}
	}

	strategyDir := strategyConfig.GetStrategyDir()
	strategyFilePattern := strategyConfig.GetAdvancedStrategyPattern(string(models.TaskTypeFull))
	strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, strategyFilePattern))
	if err != nil {
		log.Printf("Failed to discover full scan strategy files with pattern %s: %v", strategyFilePattern, err)
		return false
	}

	if len(strategyFiles) == 0 {
		log.Printf("No full scan strategy files found in %s with pattern %s", strategyDir, strategyFilePattern)
		return false
	}

	sort.Strings(strategyFiles)
	var filteredStrategies []string
	for _, strategyPath := range strategyFiles {
		strategyName := filepath.Base(strategyPath)
		if strategyConfig.ShouldRunAdvancedStrategy(strategyName) {
			filteredStrategies = append(filteredStrategies, strategyPath)
		} else {
			log.Printf("Skipping full scan strategy %s (not selected)", strategyName)
		}
	}

	if len(filteredStrategies) == 0 {
		log.Printf("No full scan strategies to run after filtering (selected: %s)", strategyConfig.POV.SelectedAdvancedStrategy)
		return false
	}

	log.Printf("Running %d full scan strategies: %v", len(filteredStrategies), filteredStrategies)

	povSuccess := false
	for _, strategyPath := range filteredStrategies {
		log.Printf("Running full scan strategy: %s", strategyPath)

		if _, err := os.Stat(strategyPath); os.IsNotExist(err) {
			log.Printf("Strategy file disappeared before execution: %s", strategyPath)
			continue
		}

		if runSingleFullScanStrategy(
			strategyPath,
			fuzzer,
			projectDir,
			taskDetail.ProjectName,
			taskDetail.Focus,
			language,
			fullScanConfig.Model,
			fullScanConfig.POVMetadataDir,
			fullScanConfig.SubmissionEndpoint,
			taskDetail.TaskID.String(),
			fullScanConfig.WorkerIndex,
		) {
			povSuccess = true
			log.Printf("✓ Full scan strategy succeeded: %s", filepath.Base(strategyPath))
			break
		}

		log.Printf("✗ Full scan strategy did not find POV: %s", filepath.Base(strategyPath))
	}

	if povSuccess {
		log.Printf("✓ Full scan strategy execution succeeded")
	} else {
		log.Printf("✗ Full scan strategy execution did not find POV")
	}

	return povSuccess
}

// runSingleFullScanStrategy executes a single full scan Python strategy
func runSingleFullScanStrategy(
	strategyPath string,
	fuzzer string,
	projectDir string,
	projectName string,
	focus string,
	language string,
	model string,
	povMetadataDir string,
	submissionEndpoint string,
	taskID string,
	workerIndex string,
) bool {

	// Get Python interpreter path
	pythonInterpreter := "/tmp/crs_venv/bin/python3"
	if _, err := os.Stat(pythonInterpreter); os.IsNotExist(err) {
		pythonInterpreter = "python3"
	}

	// Build command arguments
	args := []string{
		strategyPath,
		fuzzer,
		projectName,
		focus,
		language,
		"--model", model,
		"--pov-metadata-dir", povMetadataDir,
		"--fuzzing-timeout", "45",
		"--max-iterations", "5",
	}

	// Set up environment variables
	env := os.Environ()
	env = append(env, "SUBMISSION_ENDPOINT="+submissionEndpoint)
	env = append(env, "TASK_ID="+taskID)
	env = append(env, "WORKER_INDEX="+workerIndex)
	env = append(env, "PYTHONUNBUFFERED=1")
	env = append(env, "VIRTUAL_ENV=/tmp/crs_venv")

	// Create context with timeout (1 hour)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	// Create command
	cmd := exec.CommandContext(ctx, pythonInterpreter, args...)
	cmd.Dir = projectDir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("Executing: %s %v", pythonInterpreter, args)

	// Run strategy
	err := cmd.Run()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 0 {
				log.Printf("Strategy completed successfully")
				return true
			}
			log.Printf("Strategy exited with code %d", exitErr.ExitCode())
		} else {
			log.Printf("Strategy execution error: %v", err)
		}
		return false
	}

	log.Printf("Strategy completed successfully")
	return true
}
