#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRS_DIR="$SCRIPT_DIR/crs"

# Local runs often use endpoints that don't implement submission-service APIs.
# Allow override by setting CRS_DISABLE_SUBMISSION_SERVICE=false.
export CRS_DISABLE_SUBMISSION_SERVICE="${CRS_DISABLE_SUBMISSION_SERVICE:-true}"

# Default LLM proxy endpoint for OpenAI-compatible model lookup/completions.
# Allow override by setting COPILOT_API_BASE_URL before running.
export COPILOT_API_BASE_URL="${COPILOT_API_BASE_URL:-http://localhost:4141}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Prepare workspace repo before local CRS build.
# This is especially important for projects like Skia that rely on
# tools/git-sync-deps to populate third_party/externals.
prepare_repo_for_build() {
    local repo_dir="$1"
    local target_commit="$2"

    if [ ! -d "$repo_dir/.git" ]; then
        print_warn "Skipping repo preparation: not a git repo ($repo_dir)"
        return 0
    fi

    if [ -n "$target_commit" ]; then
        print_info "Checking out target commit: $target_commit"
        if ! git -C "$repo_dir" checkout --quiet "$target_commit"; then
            print_error "Failed to checkout commit $target_commit in $repo_dir"
            return 1
        fi
    fi

    if [ -f "$repo_dir/tools/git-sync-deps" ]; then
        local max_sync_attempts="${GIT_SYNC_DEPS_MAX_ATTEMPTS:-5}"
        local sync_attempt=1
        local sync_ok=false
        local sync_output=""
        local fallback_output=""
        local sync_status=0
        local empty_repo_count=0
        local externals_populated=false
        local rate_limit_count=0
        local thread_failure_count=0
        local lock_conflict_count=0
        local transport_error_count=0
        local transient_error_count=0
        local mirror_ref_miss_count=0
        local backoff_seconds=0
        local jitter_seconds=0
        local git_http_connect_timeout="${GIT_HTTP_CONNECT_TIMEOUT:-30}"
        local git_http_low_speed_time="${GIT_HTTP_LOW_SPEED_TIME:-300}"
        local git_http_low_speed_limit="${GIT_HTTP_LOW_SPEED_LIMIT:-1024}"
        local sync_lock_fd=""
        local sync_lock_file="$repo_dir/.git-sync-deps.lock"

        if ! [[ "$max_sync_attempts" =~ ^[0-9]+$ ]] || [ "$max_sync_attempts" -lt 1 ]; then
            max_sync_attempts=5
        fi

        if command -v flock >/dev/null 2>&1; then
            exec {sync_lock_fd}> "$sync_lock_file" || {
                print_error "Failed to open dependency sync lock file: $sync_lock_file"
                return 1
            }
            print_info "Waiting for dependency sync lock: $sync_lock_file"
            if ! flock -w 900 "$sync_lock_fd"; then
                print_error "Timed out waiting for dependency sync lock"
                exec {sync_lock_fd}>&-
                return 1
            fi
        fi

        while [ "$sync_attempt" -le "$max_sync_attempts" ]; do
            print_info "Running dependency sync: tools/git-sync-deps (attempt $sync_attempt/$max_sync_attempts)"

            if [ -d "$repo_dir/third_party/externals" ]; then
                local active_git_processes=""
                local stale_lock_count=0
                active_git_processes="$(pgrep -af "git .*${repo_dir}/third_party/externals" | grep -v "pgrep -af" || true)"
                if [ -z "$active_git_processes" ]; then
                    stale_lock_count=$(find "$repo_dir/third_party/externals" -type f -name '*.lock' -mmin +10 -print -delete 2>/dev/null | wc -l)
                    if [ "$stale_lock_count" -gt 0 ]; then
                        print_warn "Removed $stale_lock_count stale git lock file(s) before sync"
                    fi
                else
                    print_warn "Active git processes detected under externals; skipping stale lock cleanup"
                fi
            fi

            sync_output="$({
                cd "$repo_dir" && \
                GIT_CONFIG_COUNT=4 \
                GIT_CONFIG_KEY_0=url.https://github.com/.insteadof \
                GIT_CONFIG_VALUE_0=https://chromium.googlesource.com/external/github.com/ \
                GIT_CONFIG_KEY_1=url.https://github.com/.insteadof \
                GIT_CONFIG_VALUE_1=https://skia.googlesource.com/external/github.com/ \
                GIT_CONFIG_KEY_2=url.https://gitlab.com/.insteadof \
                GIT_CONFIG_VALUE_2=https://chromium.googlesource.com/external/gitlab.com/ \
                GIT_CONFIG_KEY_3=url.https://gitlab.com/.insteadof \
                GIT_CONFIG_VALUE_3=https://skia.googlesource.com/external/gitlab.com/ \
                GIT_HTTP_CONNECT_TIMEOUT="$git_http_connect_timeout" \
                GIT_HTTP_LOW_SPEED_TIME="$git_http_low_speed_time" \
                GIT_HTTP_LOW_SPEED_LIMIT="$git_http_low_speed_limit" \
                GIT_SYNC_DEPS_SKIP_EMSDK=1 \
                GIT_SYNC_DEPS_SHALLOW_CLONE=1 \
                GIT_SYNC_DEPS_QUIET=0 \
                python3 tools/git-sync-deps
            } 2>&1)"
            sync_status=$?

            mirror_ref_miss_count=$(printf "%s\n" "$sync_output" | grep -icE "not our ref|couldn't find remote ref|unadvertised object|reference is not a tree|unable to find.*in upstream" || true)
            if [ "$sync_status" -ne 0 ] && [ "$mirror_ref_miss_count" -gt 0 ]; then
                print_warn "Mirror source missing commit hash; retrying this attempt with original dependency URLs"
                fallback_output="$({
                    cd "$repo_dir" && \
                    GIT_HTTP_CONNECT_TIMEOUT="$git_http_connect_timeout" \
                    GIT_HTTP_LOW_SPEED_TIME="$git_http_low_speed_time" \
                    GIT_HTTP_LOW_SPEED_LIMIT="$git_http_low_speed_limit" \
                    GIT_SYNC_DEPS_SKIP_EMSDK=1 \
                    GIT_SYNC_DEPS_SHALLOW_CLONE=1 \
                    GIT_SYNC_DEPS_QUIET=0 \
                    python3 tools/git-sync-deps
                } 2>&1)"
                sync_status=$?
                sync_output="${sync_output}"$'\n'"${fallback_output}"
            fi

            printf "%s\n" "$sync_output"

            empty_repo_count=$(printf "%s\n" "$sync_output" | grep -ic "You appear to have cloned an empty repository" || true)
            rate_limit_count=$(printf "%s\n" "$sync_output" | grep -icE "resource_exhausted|error: 429|http 429|rate limit|too many requests|quotafailure" || true)
            thread_failure_count=$(printf "%s\n" "$sync_output" | grep -icE "thread failure detected|traceback \(most recent call last\)" || true)
            lock_conflict_count=$(printf "%s\n" "$sync_output" | grep -icE "\.lock': File exists|unable to create '.*\.lock'" || true)
            transport_error_count=$(printf "%s\n" "$sync_output" | grep -icE "expected flush after ref listing|expected 'acknowledgments'|connection reset|connection timed out|temporary failure|eof occurred|fatal: early EOF|RPC failed" || true)
            transient_error_count=$((rate_limit_count + thread_failure_count + lock_conflict_count + transport_error_count))

            externals_populated=false
            if [ -d "$repo_dir/third_party/externals" ] && [ -n "$(find "$repo_dir/third_party/externals" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
                externals_populated=true
            fi

            if [ "$empty_repo_count" -gt 0 ]; then
                print_warn "Dependency sync produced empty-repository warnings ($empty_repo_count)"
            fi
            if [ "$rate_limit_count" -gt 0 ]; then
                print_warn "Dependency sync detected rate-limit errors ($rate_limit_count)"
            fi
            if [ "$thread_failure_count" -gt 0 ]; then
                print_warn "Dependency sync detected thread failure signatures ($thread_failure_count)"
            fi
            if [ "$lock_conflict_count" -gt 0 ]; then
                print_warn "Dependency sync detected lock-file conflicts ($lock_conflict_count)"
            fi
            if [ "$transport_error_count" -gt 0 ]; then
                print_warn "Dependency sync detected transport/protocol errors ($transport_error_count)"
            fi

            if [ "$sync_status" -eq 0 ] && [ "$externals_populated" = true ] && [ "$transient_error_count" -eq 0 ]; then
                sync_ok=true
                print_info "Dependency sync completed successfully"
                break
            fi

            if [ "$sync_status" -ne 0 ]; then
                print_warn "Dependency sync exited with code $sync_status"
            fi
            if [ "$externals_populated" != true ]; then
                print_warn "Dependency sync did not populate third_party/externals"
            fi

            if [ "$sync_attempt" -lt "$max_sync_attempts" ]; then
                print_warn "Preparing dependency cache for retry"
                if [ -d "$repo_dir/third_party/externals" ]; then
                    local cleaned_repo_count=0
                    while IFS= read -r dep_dir; do
                        if [ -z "$dep_dir" ]; then
                            continue
                        fi
                        if [ -d "$dep_dir/.git" ] && ! git -C "$dep_dir" rev-parse HEAD >/dev/null 2>&1; then
                            rm -rf "$dep_dir"
                            cleaned_repo_count=$((cleaned_repo_count + 1))
                        fi
                    done < <(find "$repo_dir/third_party/externals" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)

                    if [ "$cleaned_repo_count" -gt 0 ]; then
                        print_warn "Removed $cleaned_repo_count incomplete dependency repo(s) before retry"
                    fi
                fi

                if [ "$sync_attempt" -eq $((max_sync_attempts - 1)) ]; then
                    print_warn "Final retry path: resetting third_party/externals for a clean sync"
                    rm -rf "$repo_dir/third_party/externals"
                fi

                backoff_seconds=$((20 * (2 ** (sync_attempt - 1))))
                if [ "$backoff_seconds" -gt 240 ]; then
                    backoff_seconds=240
                fi
                jitter_seconds=$((RANDOM % 11))
                backoff_seconds=$((backoff_seconds + jitter_seconds))
                print_warn "Retrying dependency sync after ${backoff_seconds}s backoff"
                sleep "$backoff_seconds"
            fi

            sync_attempt=$((sync_attempt + 1))
        done

        if [ -n "$sync_lock_fd" ]; then
            flock -u "$sync_lock_fd" 2>/dev/null || true
            exec {sync_lock_fd}>&-
        fi

        if [ "$sync_ok" != true ]; then
            print_error "Dependency sync failed after $max_sync_attempts attempts; aborting run"
            return 1
        fi
    fi

    return 0
}

# Check if argument looks like a git URL
is_git_url() {
    [[ "$1" =~ ^git@ ]] || [[ "$1" =~ ^https?://.*\.git$ ]] || [[ "$1" =~ ^https?://github\.com/ ]] || [[ "$1" =~ ^https?://gitlab\.com/ ]]
}

# Check if argument is a simple project name (no slashes, not a URL)
is_project_name() {
    local input="$1"
    # Not a URL and doesn't contain slashes
    if ! is_git_url "$input" && [[ ! "$input" =~ / ]]; then
        return 0
    fi
    return 1
}

# Extract repo name from git URL
# git@github.com:libexpat/libexpat.git -> libexpat
# https://github.com/libexpat/libexpat.git -> libexpat
get_repo_name() {
    local url="$1"
    local name
    # Remove .git suffix and get basename
    name=$(basename "$url" .git)
    echo "$name"
}

# Try to find matching oss-fuzz project
# Returns project name if found, empty string otherwise
find_ossfuzz_project() {
    local repo_name="$1"
    local ossfuzz_dir="$2"

    # Direct match
    if [ -d "$ossfuzz_dir/projects/$repo_name" ]; then
        echo "$repo_name"
        return
    fi

    # Try lowercase
    local lower_name=$(echo "$repo_name" | tr '[:upper:]' '[:lower:]')
    if [ -d "$ossfuzz_dir/projects/$lower_name" ]; then
        echo "$lower_name"
        return
    fi

    # Try removing common prefixes/suffixes
    local stripped_name=$(echo "$repo_name" | sed -E 's/^(lib|py|go|rust)-?//i' | sed -E 's/-?(lib|py|go|rust)$//i')
    if [ -d "$ossfuzz_dir/projects/$stripped_name" ]; then
        echo "$stripped_name"
        return
    fi

    echo ""
}

# Validate that workspace contains required fuzz-tooling assets.
validate_workspace_fuzz_tooling() {
    local workspace_dir="$1"
    local helper_path="$workspace_dir/fuzz-tooling/infra/helper.py"
    local projects_dir="$workspace_dir/fuzz-tooling/projects"
    local dockerfile_path=""

    if [ ! -f "$helper_path" ]; then
        print_error "Missing required OSS-Fuzz helper: $helper_path"
        print_error "This workspace cannot build fuzzers without fuzz-tooling infrastructure."
        print_info "Use --with-oss-fuzz (optionally with --project NAME) or provide a workspace with fuzz-tooling/infra."
        return 1
    fi

    dockerfile_path="$(find "$projects_dir" -mindepth 2 -maxdepth 2 -type f -name 'Dockerfile' -print -quit 2>/dev/null || true)"
    if [ -z "$dockerfile_path" ]; then
        print_error "No project Dockerfile found under $projects_dir"
        print_error "Unable to determine project build configuration."
        print_info "Use --with-oss-fuzz (optionally with --project NAME) or populate fuzz-tooling/projects manually."
        return 1
    fi

    print_info "Validated fuzz-tooling assets: $(dirname "$dockerfile_path")"
    return 0
}

# Prompt user for API keys
prompt_api_key() {
    local env_file="$CRS_DIR/.env"
    local env_example="$CRS_DIR/.env.example"

    echo ""
    print_info "No API key configured. Let's set them up!"
    echo ""
    print_info "Press SPACE or ENTER to skip any key you don't have"
    echo ""

    # Create .env from example if it doesn't exist
    if [ ! -f "$env_file" ]; then
        if [ -f "$env_example" ]; then
            cp "$env_example" "$env_file"
            print_info "Created $env_file from example"
        else
            touch "$env_file"
        fi
    fi

    local keys_added=0

    # Prompt for each API key
    declare -A api_keys=(
        ["ANTHROPIC_API_KEY"]="Anthropic (Claude)"
        ["OPENAI_API_KEY"]="OpenAI (GPT)"
        ["GEMINI_API_KEY"]="Google (Gemini)"
        ["XAI_API_KEY"]="xAI (Grok)"
    )

    for key_name in "ANTHROPIC_API_KEY" "OPENAI_API_KEY" "GEMINI_API_KEY" "XAI_API_KEY"; do
        local key_display="${api_keys[$key_name]}"
        echo ""
        read -p "Enter your $key_display API key (or press ENTER to skip): " key_value

        # Skip if empty or just whitespace
        if [ -z "$key_value" ] || [ "$key_value" = " " ]; then
            print_warn "Skipped $key_display"
            continue
        fi

        # Update or append the API key
        if grep -q "^${key_name}=" "$env_file" 2>/dev/null; then
            # Update existing key
            sed -i "s|^${key_name}=.*|${key_name}=${key_value}|" "$env_file"
        else
            # Append new key
            echo "${key_name}=${key_value}" >> "$env_file"
        fi

        print_info "$key_display API key saved"
        export "$key_name=$key_value"
        keys_added=$((keys_added + 1))
    done

    echo ""
    if [ $keys_added -eq 0 ]; then
        print_error "No API keys were added. At least one API key is required."
        exit 1
    fi

    print_info "Successfully configured $keys_added API key(s)"
}

# Check if Docker is running
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed!"
        print_error "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker is not running!"
        print_error "Please start Docker daemon and try again."
        exit 1
    fi

    print_info "Docker is running"
}

# Function to compare version numbers
version_ge() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# Install Go
install_go() {
    local GO_VERSION="1.22.2"
    local OS="$(uname -s)"
    local ARCH="$(uname -m)"
    local GO_ARCH=""

    print_info "Installing Go ${GO_VERSION}..."

    # Determine architecture
    case "$ARCH" in
        x86_64)
            GO_ARCH="amd64"
            ;;
        aarch64|arm64)
            GO_ARCH="arm64"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            return 1
            ;;
    esac

    case "$OS" in
        Linux)
            local GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
            local DOWNLOAD_URL="https://go.dev/dl/${GO_TARBALL}"

            print_info "Downloading Go for Linux ${GO_ARCH}..."
            if ! wget -q "$DOWNLOAD_URL" -O "/tmp/${GO_TARBALL}"; then
                print_error "Failed to download Go"
                return 1
            fi

            print_info "Installing Go to /usr/local/go (requires sudo)..."
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
            rm "/tmp/${GO_TARBALL}"

            # Add to PATH
            if ! grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
            fi
            if ! grep -q '/usr/local/go/bin' ~/.profile 2>/dev/null; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
            fi

            export PATH=$PATH:/usr/local/go/bin
            print_info "Go ${GO_VERSION} installed successfully"
            ;;

        Darwin)
            local GO_PKG="go${GO_VERSION}.darwin-${GO_ARCH}.pkg"
            local DOWNLOAD_URL="https://go.dev/dl/${GO_PKG}"

            print_info "Downloading Go for macOS ${GO_ARCH}..."
            if ! curl -L "$DOWNLOAD_URL" -o "/tmp/${GO_PKG}"; then
                print_error "Failed to download Go"
                return 1
            fi

            print_info "Installing Go (requires sudo)..."
            sudo installer -pkg "/tmp/${GO_PKG}" -target /
            rm "/tmp/${GO_PKG}"

            # Add to PATH
            if ! grep -q '/usr/local/go/bin' ~/.zshrc 2>/dev/null; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
            fi
            if ! grep -q '/usr/local/go/bin' ~/.bash_profile 2>/dev/null; then
                echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bash_profile
            fi

            export PATH=$PATH:/usr/local/go/bin
            print_info "Go ${GO_VERSION} installed successfully"
            ;;

        *)
            print_error "Unsupported OS: $OS"
            return 1
            ;;
    esac

    return 0
}

# Check and install Go
check_go() {
    local REQUIRED_GO_VERSION="1.21"
    local need_install=false

    if command -v go &> /dev/null; then
        local CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_info "Go $CURRENT_GO_VERSION is installed"

        if version_ge "$CURRENT_GO_VERSION" "$REQUIRED_GO_VERSION"; then
            print_info "Go version is sufficient (>= $REQUIRED_GO_VERSION)"
            return 0
        else
            print_warn "Go version $CURRENT_GO_VERSION is too old (required >= $REQUIRED_GO_VERSION)"
            need_install=true
        fi
    else
        print_error "Go is not installed (required >= $REQUIRED_GO_VERSION)"
        need_install=true
    fi

    if [ "$need_install" = true ]; then
        echo ""
        read -p "Would you like to install Go 1.22.2? (yes/no): " install_choice

        if [ "$install_choice" = "yes" ]; then
            if install_go; then
                print_info "Go installation completed"
                return 0
            else
                print_error "Go installation failed"
                exit 1
            fi
        else
            print_error "Go >= $REQUIRED_GO_VERSION is required. Exiting."
            print_error "Manual installation: https://go.dev/doc/install"
            exit 1
        fi
    fi
}

# Check environment configuration
check_environment() {
    local env_file="$CRS_DIR/.env"
    local env_example="$CRS_DIR/.env.example"

    # Check Docker and Go first
    check_docker
    check_go

    # Check if .env exists
    if [ ! -f "$env_file" ]; then
        print_warn ".env file not found at $env_file"
        prompt_api_key
        return
    fi

    # Preserve explicit caller overrides for fuzzer controls.
    local _HAS_FUZZER_SELECTED="${FUZZER_SELECTED+1}"
    local _OVERRIDE_FUZZER_SELECTED="$FUZZER_SELECTED"
    local _HAS_FUZZER_DISCOVERY_MODE="${FUZZER_DISCOVERY_MODE+1}"
    local _OVERRIDE_FUZZER_DISCOVERY_MODE="$FUZZER_DISCOVERY_MODE"
    local _HAS_FUZZER_PER_TIMEOUT="${FUZZER_PER_FUZZER_TIMEOUT_MINUTES+1}"
    local _OVERRIDE_FUZZER_PER_TIMEOUT="$FUZZER_PER_FUZZER_TIMEOUT_MINUTES"
    local _HAS_AI_MODEL="${AI_MODEL+1}"
    local _OVERRIDE_AI_MODEL="$AI_MODEL"
    local _HAS_STRATEGY_ENABLE_PATCHING="${STRATEGY_ENABLE_PATCHING+1}"
    local _OVERRIDE_STRATEGY_ENABLE_PATCHING="$STRATEGY_ENABLE_PATCHING"

    # Load .env file
    set -a
    source "$env_file"
    set +a

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

    # Check if at least one API key is set
    local has_api_key=false

    if [ -n "$ANTHROPIC_API_KEY" ] && [ "$ANTHROPIC_API_KEY" != "your-anthropic-api-key" ]; then
        has_api_key=true
    fi

    if [ -n "$OPENAI_API_KEY" ] && [ "$OPENAI_API_KEY" != "your-openai-api-key" ]; then
        has_api_key=true
    fi

    if [ -n "$GEMINI_API_KEY" ] && [ "$GEMINI_API_KEY" != "your-gemini-api-key" ]; then
        has_api_key=true
    fi

    if [ "$has_api_key" = false ]; then
        print_warn "No valid API key found in $env_file"
        prompt_api_key
        return
    fi

    print_info "Environment check passed"
}

show_usage() {
    echo "Usage: $0 [OPTIONS] <git_url|workspace_path|project_name>"
    echo ""
    echo "Arguments:"
    echo "  git_url         Git repository URL (e.g., git@github.com:libexpat/libexpat.git)"
    echo "  workspace_path  Local workspace directory path"
    echo "  project_name    Existing project name under workspace/ directory"
    echo ""
    echo "Options:"
    echo "  --in-place      Run directly without copying workspace"
    echo "  --pov-only      Disable patch generation and run POV/ASAN-focused flow"
    echo "  --with-oss-fuzz Enable OSS-Fuzz project clone/bootstrap for new workspace"
    echo "  --project NAME  Specify OSS-Fuzz project name (if different from repo name)"
    echo "  -b COMMIT       Base commit ID (for delta scan)"
    echo "  -d COMMIT       Delta commit ID (for delta scan, requires -b)"
    echo ""
    echo "Examples:"
    echo "  $0 git@github.com:libexpat/libexpat.git                                # Full scan from git"
    echo "  $0 --with-oss-fuzz git@github.com:libexpat/libexpat.git                # Full scan + OSS-Fuzz bootstrap"
    echo "  $0 -b abc123 -d def456 git@github.com:libexpat/libexpat.git           # Delta scan (runs BASE commit with BASE..DELTA diff context)"
    echo "  $0 --pov-only -b abc123 -d def456 git@github.com:libexpat/libexpat.git # Delta scan with POV-only (no patching)"
    echo "  $0 --with-oss-fuzz --project expat git@github.com:libexpat/libexpat.git # Specify OSS-Fuzz project"
    echo "  $0 /path/to/workspace                                                  # Use existing workspace"
    echo "  $0 --in-place /path/to/workspace                                       # Run in-place"
    echo "  $0 libexpat                                                            # Continue fuzzing existing project"
    exit 1
}

# Parse arguments
IN_PLACE=false
POV_ONLY=false
WITH_OSS_FUZZ=false
OSS_FUZZ_PROJECT=""
BASE_COMMIT=""
DELTA_COMMIT=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --in-place)
            IN_PLACE=true
            shift
            ;;
        --pov-only)
            POV_ONLY=true
            shift
            ;;
        --with-oss-fuzz)
            WITH_OSS_FUZZ=true
            shift
            ;;
        --project)
            OSS_FUZZ_PROJECT="$2"
            shift 2
            ;;
        -b)
            BASE_COMMIT="$2"
            shift 2
            ;;
        -d)
            DELTA_COMMIT="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            ;;
        -*)
            print_error "Unknown option: $1"
            show_usage
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Restore positional arguments
set -- "${POSITIONAL_ARGS[@]}"

if [ $# -lt 1 ]; then
    show_usage
fi

TARGET="$1"

# Validate delta scan arguments
if [ -n "$DELTA_COMMIT" ] && [ -z "$BASE_COMMIT" ]; then
    print_error "Delta commit (-d) requires base commit (-b)"
    show_usage
fi

if [ "$POV_ONLY" = true ]; then
    export STRATEGY_ENABLE_PATCHING=false
    print_warn "POV-only mode enabled: patch generation disabled"
fi

# ============================================
# CASE 1: Project Name - Continue fuzzing existing project
# ============================================
if is_project_name "$TARGET"; then
    PROJECT_NAME="$TARGET"
    WORKSPACE="$SCRIPT_DIR/workspace/${PROJECT_NAME}"

    # Check if project exists under workspace
    if [ ! -d "$WORKSPACE" ]; then
        print_error "Project '$PROJECT_NAME' not found under workspace/"
        print_error "Expected workspace at: $WORKSPACE"
        echo ""
        print_info "Available projects:"
        if [ -d "$SCRIPT_DIR/workspace" ] && [ -n "$(ls -A "$SCRIPT_DIR/workspace" 2>/dev/null)" ]; then
            ls -1 "$SCRIPT_DIR/workspace"
        else
            echo "  (none)"
        fi
        echo ""
        print_info "To create a new project, use a git URL instead:"
        print_info "  $0 git@github.com:user/repo.git"
        exit 1
    fi

    # Verify workspace structure
    if [ ! -d "$WORKSPACE/repo" ]; then
        print_error "Invalid workspace structure: missing 'repo' directory"
        print_error "Workspace at $WORKSPACE does not appear to be a valid fuzzing workspace"
        exit 1
    fi

    print_info "Found existing project: $PROJECT_NAME"
    print_info "Workspace: $WORKSPACE"
    echo ""

    if ! validate_workspace_fuzz_tooling "$WORKSPACE"; then
        exit 1
    fi

    if ! prepare_repo_for_build "$WORKSPACE/repo" "$BASE_COMMIT"; then
        exit 1
    fi

    # Check environment before running
    check_environment

    # Continue fuzzing with existing workspace (always in-place)
    cd "$CRS_DIR" && sudo --preserve-env=FUZZER_SELECTED,FUZZER_DISCOVERY_MODE,FUZZER_PER_FUZZER_TIMEOUT_MINUTES,AI_MODEL,STRATEGY_ENABLE_PATCHING ./run_crs.sh --in-place "$WORKSPACE"

# ============================================
# CASE 2: Git URL - Create workspace from scratch
# ============================================
elif is_git_url "$TARGET"; then
    GIT_URL="$TARGET"
    REPO_NAME=$(get_repo_name "$GIT_URL")

    print_info "Detected git URL: $GIT_URL"
    print_info "Repository name: $REPO_NAME"

    # Set workspace directory (without timestamp to allow reuse)
    WORKSPACE="$SCRIPT_DIR/workspace/${REPO_NAME}"

    # Check if workspace already exists
    if [ -d "$WORKSPACE/repo" ] && [ -d "$WORKSPACE/repo/.git" ]; then
        print_info "Found existing workspace: $WORKSPACE"
        print_info "Reusing existing repository (pulling latest changes)..."

        cd "$WORKSPACE/repo"
        current_branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
        if [ -n "$current_branch" ]; then
            if git pull --ff-only; then
                print_info "Repository updated successfully on branch '$current_branch'"
            else
                print_warn "Failed to pull updates on branch '$current_branch', continuing with existing repository"
            fi
        else
            print_warn "Repository is in detached HEAD; skipping git pull and fetching remote refs instead"
            if git fetch --all --tags --prune; then
                print_info "Fetched latest remote refs (detached HEAD preserved)"
            else
                print_warn "Failed to fetch remote refs, continuing with existing repository"
            fi
        fi
        cd "$SCRIPT_DIR"
    else
        print_info "Creating new workspace: $WORKSPACE"
        mkdir -p "$WORKSPACE/repo"
        mkdir -p "$WORKSPACE/fuzz-tooling"

        # Clone target repository
        print_info "Cloning target repository..."
        if ! git clone "$GIT_URL" "$WORKSPACE/repo"; then
            print_error "Failed to clone repository: $GIT_URL"
            exit 1
        fi
    fi

    # Check if fuzz-tooling already exists and is complete enough to reuse.
    has_fuzz_tooling_projects=false
    has_fuzz_tooling_helper=false
    if [ -d "$WORKSPACE/fuzz-tooling/projects" ] && [ -n "$(ls -A "$WORKSPACE/fuzz-tooling/projects" 2>/dev/null)" ]; then
        has_fuzz_tooling_projects=true
    fi
    if [ -f "$WORKSPACE/fuzz-tooling/infra/helper.py" ]; then
        has_fuzz_tooling_helper=true
    fi

    if [ "$has_fuzz_tooling_projects" = true ] && [ "$has_fuzz_tooling_helper" = true ]; then
        print_info "Reusing existing fuzz-tooling from workspace"
    elif [ "$WITH_OSS_FUZZ" = true ]; then
        # Clone oss-fuzz to temp directory
        OSSFUZZ_TMP="/tmp/oss-fuzz-$$"
        print_info "Cloning oss-fuzz (this may take a moment)..."
        if ! git clone --depth 1 https://github.com/google/oss-fuzz.git "$OSSFUZZ_TMP" 2>/dev/null; then
            print_error "Failed to clone oss-fuzz"
            rm -rf "$OSSFUZZ_TMP"
            exit 1
        fi

        # Find matching oss-fuzz project
        if [ -z "$OSS_FUZZ_PROJECT" ]; then
            OSS_FUZZ_PROJECT=$(find_ossfuzz_project "$REPO_NAME" "$OSSFUZZ_TMP")
        fi

        if [ -z "$OSS_FUZZ_PROJECT" ]; then
            print_warn "No matching OSS-Fuzz project found for '$REPO_NAME'"
            print_warn "Available projects can be found at: https://github.com/google/oss-fuzz/tree/master/projects"
            print_warn "Use --project NAME to specify the correct project name"
            print_warn "Continuing without fuzz-tooling (you'll need to set it up manually)"
            rm -rf "$OSSFUZZ_TMP"
        else
            print_info "Found OSS-Fuzz project: $OSS_FUZZ_PROJECT"

            # Copy only the matching project (replace stale copy if present)
            mkdir -p "$WORKSPACE/fuzz-tooling/projects"
            rm -rf "$WORKSPACE/fuzz-tooling/projects/$OSS_FUZZ_PROJECT"
            if ! cp -r "$OSSFUZZ_TMP/projects/$OSS_FUZZ_PROJECT" "$WORKSPACE/fuzz-tooling/projects/"; then
                print_error "Failed to copy OSS-Fuzz project '$OSS_FUZZ_PROJECT' into workspace"
                rm -rf "$OSSFUZZ_TMP"
                exit 1
            fi

            # Copy necessary oss-fuzz infrastructure (replace stale/missing infra)
            rm -rf "$WORKSPACE/fuzz-tooling/infra"
            if ! cp -r "$OSSFUZZ_TMP/infra" "$WORKSPACE/fuzz-tooling/"; then
                print_error "Failed to copy OSS-Fuzz infra into workspace"
                rm -rf "$OSSFUZZ_TMP"
                exit 1
            fi

            # Cleanup
            rm -rf "$OSSFUZZ_TMP"
            print_info "OSS-Fuzz project copied to workspace"
        fi
    else
        if [ "$has_fuzz_tooling_projects" = true ] && [ "$has_fuzz_tooling_helper" = false ]; then
            print_warn "Detected incomplete fuzz-tooling in workspace (missing infra/helper.py)"
        fi
        if [ -n "$OSS_FUZZ_PROJECT" ]; then
            print_warn "Ignoring --project because --with-oss-fuzz was not provided"
        fi
        print_info "Skipping OSS-Fuzz clone/bootstrap (enable with --with-oss-fuzz)"
    fi

    if ! validate_workspace_fuzz_tooling "$WORKSPACE"; then
        exit 1
    fi

    # Handle delta scan (generate ref.diff from base and delta commits)
    if [ -n "$BASE_COMMIT" ]; then
        print_info "Delta scan mode: generating diff between base ($BASE_COMMIT) and delta ($DELTA_COMMIT)"
        mkdir -p "$WORKSPACE/diff"

        cd "$WORKSPACE/repo"

        # Verify both commits exist
        if ! git cat-file -t "$BASE_COMMIT" >/dev/null 2>&1; then
            print_error "Base commit $BASE_COMMIT not found in repository"
            print_warn "Continuing without diff (full scan mode)"
            rm -rf "$WORKSPACE/diff"
            cd "$SCRIPT_DIR"
        elif [ -n "$DELTA_COMMIT" ] && ! git cat-file -t "$DELTA_COMMIT" >/dev/null 2>&1; then
            print_error "Delta commit $DELTA_COMMIT not found in repository"
            print_warn "Continuing without diff (full scan mode)"
            rm -rf "$WORKSPACE/diff"
            cd "$SCRIPT_DIR"
        else
            # Generate diff between base and delta (or HEAD if delta not specified)
            target_commit="${DELTA_COMMIT:-HEAD}"
            git diff "$BASE_COMMIT..$target_commit" > "$WORKSPACE/diff/ref.diff"

            if [ -s "$WORKSPACE/diff/ref.diff" ]; then
                print_info "Generated ref.diff from $BASE_COMMIT to $target_commit"
            else
                print_warn "Diff between $BASE_COMMIT and $target_commit is empty"
            fi
            cd "$SCRIPT_DIR"
        fi
    fi

    if [ -f "$SCRIPT_DIR/vuln.diff" ]; then
        mkdir -p "$WORKSPACE/diff"
        if cp "$SCRIPT_DIR/vuln.diff" "$WORKSPACE/diff/vuln.diff"; then
            print_info "Staged supplemental vulnerability diff: $WORKSPACE/diff/vuln.diff"
        else
            print_warn "Failed to stage supplemental vulnerability diff from $SCRIPT_DIR/vuln.diff"
        fi
    fi

    # Ensure workspace repo is at base commit (if provided) and dependencies are synced.
    target_commit="${BASE_COMMIT:-}"
    if ! prepare_repo_for_build "$WORKSPACE/repo" "$target_commit"; then
        exit 1
    fi

    print_info "Workspace created successfully: $WORKSPACE"
    echo ""

    # Check environment before running
    check_environment

    # Run CRS with the new workspace (always in-place since we just created it)
    cd "$CRS_DIR" && sudo --preserve-env=FUZZER_SELECTED,FUZZER_DISCOVERY_MODE,FUZZER_PER_FUZZER_TIMEOUT_MINUTES,AI_MODEL,STRATEGY_ENABLE_PATCHING ./run_crs.sh --in-place "$WORKSPACE"

# ============================================
# CASE 3: Local path - Use existing workspace
# ============================================
else
    if [ ! -d "$TARGET" ]; then
        print_error "Directory does not exist: $TARGET"
        exit 1
    fi

    # If TARGET follows workspace layout, run the same repo preparation.
    if [ -d "$TARGET/repo" ]; then
        if ! validate_workspace_fuzz_tooling "$TARGET"; then
            exit 1
        fi

        if ! prepare_repo_for_build "$TARGET/repo" "$BASE_COMMIT"; then
            exit 1
        fi
    fi

    # Check environment before running
    check_environment

    # Pass through to original run_crs.sh
    if [ "$IN_PLACE" = true ]; then
        cd "$CRS_DIR" && sudo --preserve-env=FUZZER_SELECTED,FUZZER_DISCOVERY_MODE,FUZZER_PER_FUZZER_TIMEOUT_MINUTES,AI_MODEL,STRATEGY_ENABLE_PATCHING ./run_crs.sh --in-place "$TARGET"
    else
        cd "$CRS_DIR" && sudo --preserve-env=FUZZER_SELECTED,FUZZER_DISCOVERY_MODE,FUZZER_PER_FUZZER_TIMEOUT_MINUTES,AI_MODEL,STRATEGY_ENABLE_PATCHING ./run_crs.sh "$TARGET"
    fi
fi
