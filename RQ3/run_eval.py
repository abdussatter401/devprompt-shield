import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE         = Path(__file__).parent
DATASET_PATH = HERE / "self_executable_code_repair_dataset.json"
RESULTS_PATH = HERE / "eval_results.json"

sys.path.insert(0, str(HERE))
from sanitizer import sanitize

MODEL        = "qwen2.5-coder:32b"
OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_TIMEOUT = 360
RUN_TIMEOUT    = 15

def call_ollama(prompt: str) -> str:
    payload = json.dumps({
        "model":   MODEL,
        "prompt":  prompt,
        "stream":  False,
        "options": {"temperature": 0.0},
    }).encode()
    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
        return json.loads(resp.read())["response"]

def extract_code(response: str) -> str:
    m = re.search(r"```(?:python)?\s*\n(.*?)```", response, re.DOTALL)
    return m.group(1).strip() if m else response.strip()

def restore(code: str, detections) -> str:
    for d in detections:
        if d.redacted:
            code = code.replace(d.redacted, d.original)
    return code

def run_code(code: str, expected: str) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        src = os.path.join(tmpdir, "solution.py")
        with open(src, "w") as fh:
            fh.write(code)
        try:
            proc = subprocess.run(
                [sys.executable, src],
                capture_output=True, text=True,
                timeout=RUN_TIMEOUT, cwd=tmpdir,
            )
            actual = proc.stdout.strip()
            return {
                "passed": actual == expected.strip(),
                "actual": actual,
                "stderr": proc.stderr.strip()[:300],
            }
        except subprocess.TimeoutExpired:
            return {"passed": False, "actual": "", "stderr": "TIMEOUT"}
        except Exception as e:
            return {"passed": False, "actual": "", "stderr": str(e)}

def main():
    with open(DATASET_PATH) as fh:
        dataset = json.load(fh)

    programs = dataset["programs"]
    results  = []

    print(f"Model  : {MODEL}")
    print(f"Dataset: {DATASET_PATH.name}  ({len(programs)} programs)\n")
    print(f"{'ID':>3}  {'Pattern':<45}  {'Original':>8}  {'Sanitized':>9}")
    print("─" * 72)

    for prog in programs:
        pid      = prog["id"]
        expected = prog["expected_output"]
        prompt   = prog["instruction"] + "\n\n" + prog["buggy_code"]

        san_result       = sanitize(prompt)
        sanitized_prompt = san_result.sanitized
        detections       = san_result.detections

        print(f"  [{pid:02d}] querying original  …", end="", flush=True)
        t0           = time.time()
        orig_code    = extract_code(call_ollama(prompt))
        orig_run     = run_code(orig_code, expected)
        orig_elapsed = round(time.time() - t0, 1)
        print(f"\r", end="")

        print(f"  [{pid:02d}] querying sanitized …", end="", flush=True)
        t0           = time.time()
        san_code_raw = extract_code(call_ollama(sanitized_prompt))
        san_code     = restore(san_code_raw, detections)
        san_run      = run_code(san_code, expected)
        san_elapsed  = round(time.time() - t0, 1)
        print(f"\r", end="")

        o = "PASS" if orig_run["passed"] else "FAIL"
        s = "PASS" if san_run["passed"]  else "FAIL"
        print(f"{pid:>3}  {prog['pattern']:<45}  {o:>8}  {s:>9}")

        results.append({
            "id":        pid,
            "pattern":   prog["pattern"],
            "category":  prog["category"],
            "original":  {
                "passed":  orig_run["passed"],
                "actual":  orig_run["actual"],
                "stderr":  orig_run["stderr"],
                "elapsed": orig_elapsed,
            },
            "sanitized": {
                "passed":  san_run["passed"],
                "actual":  san_run["actual"],
                "stderr":  san_run["stderr"],
                "elapsed": san_elapsed,
            },
        })

    n          = len(results)
    orig_pass  = sum(r["original"]["passed"]  for r in results)
    san_pass   = sum(r["sanitized"]["passed"] for r in results)

    print("─" * 72)
    print(f"\nOriginal  pass rate : {orig_pass}/{n}  ({orig_pass/n:.0%})")
    print(f"Sanitized pass rate : {san_pass}/{n}  ({san_pass/n:.0%})")

    with open(RESULTS_PATH, "w") as fh:
        json.dump({
            "model":   MODEL,
            "dataset": DATASET_PATH.name,
            "summary": {
                "total":               n,
                "original_pass":       orig_pass,
                "sanitized_pass":      san_pass,
                "original_pass_rate":  round(orig_pass / n, 4),
                "sanitized_pass_rate": round(san_pass  / n, 4),
            },
            "results": results,
        }, fh, indent=2)

    print(f"\nSaved → {RESULTS_PATH}")

if __name__ == "__main__":
    main()
