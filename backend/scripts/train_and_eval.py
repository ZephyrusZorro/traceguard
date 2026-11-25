"""CLI entrypoint to train all TraceGuard ML models and run the full benchmark suite."""
from __future__ import annotations

import json
from traceguard.ml.evaluation import run_full_benchmark


def main() -> None:
    report = run_full_benchmark(seed=42)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
