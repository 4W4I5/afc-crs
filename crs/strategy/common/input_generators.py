"""
Input generator abstraction used by POV strategies.
"""

import os
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import List


class InputGenerator(ABC):
    """Interface for generating blob files from LLM-produced code."""

    @abstractmethod
    def generate(self, code: str, output_dir: str) -> List[str]:
        """Generate one or more blob files in output_dir and return their paths."""


class PythonExecutorInputGenerator(InputGenerator):
    """Default input generator that executes Python code to produce x.bin."""

    def __init__(self, timeout_seconds: int = 30, blob_name: str = "x.bin") -> None:
        self.timeout_seconds = timeout_seconds
        self.blob_name = blob_name

    def generate(self, code: str, output_dir: str) -> List[str]:
        code_file = os.path.join(output_dir, "generate_blob.py")
        with open(code_file, "w", encoding="utf-8") as f:
            f.write(code)

        try:
            result = subprocess.run(
                [sys.executable, code_file],
                cwd=output_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Code execution timed out") from exc
        except Exception as exc:  # pragma: no cover - defensive wrapper
            raise RuntimeError(f"Code execution error: {str(exc)}") from exc

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            diagnostics = stderr or stdout or "no output"
            raise RuntimeError(f"Code execution failed: {diagnostics}")

        blob_path = os.path.join(output_dir, self.blob_name)
        if not os.path.exists(blob_path):
            raise RuntimeError(f"Code did not create {self.blob_name}")

        return [blob_path]


def build_input_generator(name: str) -> InputGenerator:
    """Create an input generator by symbolic name."""
    normalized = (name or "python_executor").strip().lower()

    if normalized in {"python", "python_executor", "python-executor", "script"}:
        return PythonExecutorInputGenerator()

    raise ValueError(f"Unsupported input generator: {name}")
