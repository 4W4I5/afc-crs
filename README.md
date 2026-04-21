<!-- markdownlint-disable MD001 MD041 -->
<h1 align="center">
All You Need Is A Fuzzing Brain
</h1>

<h3 align="center">
Autonomous Cyber Reasoning System for Vulnerability Discovery
</h3>



## About

**FuzzingBrain** is an AI-driven automated vulnerability detection and remediation framework built upon the OSS-Fuzz infrastructure. Developed by the team "all_you_need_is_a_fuzzing_brain" for the **2025 DARPA AIxCC (Artificial Intelligence Cyber Challenge) finals**.

### Key Features

- **LLM-Powered Analysis**: Leverages multiple LLM providers (OpenAI, Anthropic, Google, xAI) for intelligent vulnerability detection
- **Multi-Strategy Framework**: 23+ specialized strategies for POV generation and patch synthesis
- **Automated Patch Generation**: Generates and validates patches automatically
- **OSS-Fuzz Integration**: Seamless integration with Google's fuzzing infrastructure
- **Multi-Language Support**: C/C++ and Java vulnerability detection

### Supported Task Types

- **Delta Scan**: Analyze specific commits for introduced vulnerabilities
- **Full Scan**: Comprehensive repository-wide vulnerability analysis
- **SARIF Analysis**: Validate and patch vulnerabilities from static analysis reports

---

## Getting Started

### 1. Clone Repository

```bash
git clone https://github.com/aixcc-sc/afc-crs-all-you-need-is-a-fuzzing-brain.git
cd afc-crs-all-you-need-is-a-fuzzing-brain
```

### 2. Configure API Keys

```bash
cd crs && cp .env.example .env
```

Edit `crs/.env` and add your API keys (at least one required):

```bash
OPENAI_API_KEY=sk-proj-your-key-here
ANTHROPIC_API_KEY=sk-ant-your-key-here
GEMINI_API_KEY=your-key-here
XAI_API_KEY=xai-your-key-here
```

### 3. Run a Scan

```bash
# Delta Scan - analyze BASE..DELTA diff while executing BASE commit (unpatched)
./FuzzingBrain.sh -b <base_commit> -d <delta_commit> <repo_url>

# Delta Scan (POV-only) - skip patch generation, focus on ASAN/POV evidence
./FuzzingBrain.sh --pov-only -b <base_commit> -d <delta_commit> <repo_url>

# Delta Scan + OSS-Fuzz bootstrap (opt-in)
./FuzzingBrain.sh --with-oss-fuzz -b <base_commit> -d <delta_commit> <repo_url>

# Delta Scan + OSS-Fuzz bootstrap + POV-only
./FuzzingBrain.sh --with-oss-fuzz --pov-only -b <base_commit> -d <delta_commit> <repo_url>

# Full Scan - analyze entire repository
./FuzzingBrain.sh <repo_url>

# Full Scan + OSS-Fuzz bootstrap (opt-in)
./FuzzingBrain.sh --with-oss-fuzz <repo_url>

# Specify OSS-Fuzz project name (requires --with-oss-fuzz)
./FuzzingBrain.sh --with-oss-fuzz --project <oss_fuzz_project> <repo_url>
```


