#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${CRS_LOG_DIR:-$SCRIPT_DIR/logs}"
mkdir -p "$LOG_DIR"

# Setup Python virtual environment
VENV_DIR="/tmp/crs_venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment at $VENV_DIR..."
    if ! python3 -m venv "$VENV_DIR"; then
        echo "ERROR: Failed to create Python virtual environment at $VENV_DIR"
        echo "Hint: install python3-venv (or python3.12-venv) and retry"
        exit 1
    fi
fi

if [ ! -f "$VENV_DIR/bin/activate" ]; then
    echo "WARN: Detected broken virtual environment at $VENV_DIR, recreating..."
    rm -rf "$VENV_DIR"
    if ! python3 -m venv "$VENV_DIR"; then
        echo "ERROR: Failed to recreate Python virtual environment at $VENV_DIR"
        exit 1
    fi
fi

# Activate venv and install dependencies
if [ ! -f "$VENV_DIR/bin/activate" ]; then
    echo "ERROR: Virtual environment activation script is missing: $VENV_DIR/bin/activate"
    exit 1
fi
source "$VENV_DIR/bin/activate"

if ! "$VENV_DIR/bin/python3" -m ensurepip --upgrade >/dev/null 2>&1; then
    echo "WARN: ensurepip failed; continuing with existing pip setup"
fi

# Python 3.12+ venv may not include setuptools by default; openlit transitively imports pkg_resources.
if ! "$VENV_DIR/bin/python3" -m pip install -q --upgrade pip wheel "setuptools<81"; then
    echo "ERROR: Failed to bootstrap pip/wheel/setuptools<81 in virtual environment"
    exit 1
fi

if [ -f "$SCRIPT_DIR/strategy/requirements.txt" ]; then
    if ! "$VENV_DIR/bin/python3" -m pip install -q -r "$SCRIPT_DIR/strategy/requirements.txt"; then
        echo "ERROR: Failed to install strategy Python dependencies"
        exit 1
    fi
fi

# Preserve explicit caller overrides for key fuzzer controls.
_HAS_FUZZER_SELECTED="${FUZZER_SELECTED+1}"
_OVERRIDE_FUZZER_SELECTED="$FUZZER_SELECTED"
_HAS_FUZZER_DISCOVERY_MODE="${FUZZER_DISCOVERY_MODE+1}"
_OVERRIDE_FUZZER_DISCOVERY_MODE="$FUZZER_DISCOVERY_MODE"
_HAS_FUZZER_PER_TIMEOUT="${FUZZER_PER_FUZZER_TIMEOUT_MINUTES+1}"
_OVERRIDE_FUZZER_PER_TIMEOUT="$FUZZER_PER_FUZZER_TIMEOUT_MINUTES"
_HAS_AI_MODEL="${AI_MODEL+1}"
_OVERRIDE_AI_MODEL="$AI_MODEL"
_HAS_STRATEGY_ENABLE_PATCHING="${STRATEGY_ENABLE_PATCHING+1}"
_OVERRIDE_STRATEGY_ENABLE_PATCHING="$STRATEGY_ENABLE_PATCHING"

# Load and export .env variables for Python strategies
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

if [ -n "$_HAS_FUZZER_SELECTED" ]; then
    export FUZZER_SELECTED="$_OVERRIDE_FUZZER_SELECTED"
fi
if [ -n "$_HAS_FUZZER_DISCOVERY_MODE" ]; then
    export FUZZER_DISCOVERY_MODE="$_OVERRIDE_FUZZER_DISCOVERY_MODE"
fi
if [ -n "$_HAS_FUZZER_PER_TIMEOUT" ]; then
    export FUZZER_PER_FUZZER_TIMEOUT_MINUTES="$_OVERRIDE_FUZZER_PER_TIMEOUT"
fi
if [ -n "$_HAS_AI_MODEL" ]; then
    export AI_MODEL="$_OVERRIDE_AI_MODEL"
fi
if [ -n "$_HAS_STRATEGY_ENABLE_PATCHING" ]; then
    export STRATEGY_ENABLE_PATCHING="$_OVERRIDE_STRATEGY_ENABLE_PATCHING"
fi

DATE=$(date +"%Y%m%d_%H%M%S")
IN_PLACE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --in-place)
            IN_PLACE=true
            shift
            ;;
        -*)
            echo "Unknown option $1"
            exit 1
            ;;
        *)
            if [ -z "$ORIGINAL_DATASET" ]; then
                ORIGINAL_DATASET="$1"
            elif [ -z "$LOG_NAME" ]; then
                LOG_NAME="$1"
            else
                echo "Too many arguments"
                exit 1
            fi
            shift
            ;;
    esac
done

# Check if path argument is provided
if [ -z "$ORIGINAL_DATASET" ]; then
    echo "Usage: $0 [--in-place] <dataset_path> [log_name]"
    echo "Options:"
    echo "  --in-place    Run directly in the provided path without copying to a new workspace"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/dataset                      # Creates a new workspace copy"
    echo "  $0 /path/to/dataset my_test_run          # With custom log name"
    echo "  $0 --in-place /path/to/dataset           # Run directly without copying"
    exit 1
fi

# Set log file name
if [ -n "$LOG_NAME" ]; then
    SAFE_LOG_NAME="$(basename "$LOG_NAME")"
    LOG_FILE="$LOG_DIR/${SAFE_LOG_NAME}.log"
else
    LOG_FILE="$LOG_DIR/${DATE}.log"
fi

# Check if the dataset path exists
if [ ! -d "$ORIGINAL_DATASET" ]; then
    echo "Error: Dataset directory '$ORIGINAL_DATASET' does not exist!"
    exit 1
fi

# Determine workspace to use
if [ "$IN_PLACE" = true ]; then
    WORKSPACE="$ORIGINAL_DATASET"
    echo "Starting CRS local run at $(date)" | tee "$LOG_FILE"
    echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
    echo "Using existing dataset directly: $WORKSPACE" | tee -a "$LOG_FILE"
else
    # Extract project name from the dataset path
    PROJECT_NAME=$(basename "$ORIGINAL_DATASET")

    # create new workspace directory
    WORKSPACE="/crs-workdir/workspace_${PROJECT_NAME}_${DATE}"

    echo "Starting CRS local run at $(date)" | tee "$LOG_FILE"
    echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
    echo "Original dataset: $ORIGINAL_DATASET" | tee -a "$LOG_FILE"
    echo "New workspace: $WORKSPACE" | tee -a "$LOG_FILE"

    # create new workspace directory
    echo "Creating new workspace directory..." | tee -a "$LOG_FILE"
    mkdir -p "$WORKSPACE"

    # copy original dataset to new workspace
    echo "Copying original dataset to new workspace..." | tee -a "$LOG_FILE"
    cp -r "$ORIGINAL_DATASET"/* "$WORKSPACE/"
fi

# Set strategy base directory for local runs
export STRATEGY_BASE_DIR="$(pwd)/strategy"

# use the workspace directory
echo "Command: go run ./cmd/local/main.go $WORKSPACE" | tee -a "$LOG_FILE"
echo "Strategy directory: $STRATEGY_BASE_DIR" | tee -a "$LOG_FILE"
echo "===========================================" | tee -a "$LOG_FILE"

go run ./cmd/local/main.go "$WORKSPACE" 2>&1 | tee -a "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}
echo "===========================================" | tee -a "$LOG_FILE"
echo "Process finished at $(date) with exit code: $EXIT_CODE" | tee -a "$LOG_FILE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "SUCCESS: CRS local run completed successfully" | tee -a "$LOG_FILE"
else
    echo "ERROR: CRS local run failed with exit code $EXIT_CODE" | tee -a "$LOG_FILE"
fi

echo "===========================================" | tee -a "$LOG_FILE"
if [ "$IN_PLACE" = true ]; then
    echo "Ran directly in: $WORKSPACE" | tee -a "$LOG_FILE"
else
    echo "Workspace created at: $WORKSPACE" | tee -a "$LOG_FILE"
fi
echo "Full log saved to: $LOG_FILE" | tee -a "$LOG_FILE"

exit "$EXIT_CODE"